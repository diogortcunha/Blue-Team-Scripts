#!/usr/bin/env python3

"""Find processes running from deleted files, memory (fileless) or temporary folders.

Linux: /proc/<pid>/exe pointing to "(deleted)" or memfd:, or into /tmp, /dev/shm, ...
Windows: executables in Temp/Public/Recycle Bin, or whose file no longer exists.
"""

from __future__ import annotations

import os

from btcommon import IS_LINUX, IS_WINDOWS, Report, compile_patterns, first_match, is_file, list_processes, load_rules, make_parser, read_text


def linux_exe_findings(dirs: list) -> list[tuple[str, int, str, str, str]]:
    """Return (severity, pid, name, exe, reason)."""
    results = []
    for pid_text in os.listdir("/proc"):
        if not pid_text.isdigit():
            continue
        try:
            exe = os.readlink(f"/proc/{pid_text}/exe")
        except OSError:
            continue
        name = (read_text(f"/proc/{pid_text}/comm") or "?").strip()
        pid = int(pid_text)
        if exe.startswith("/memfd:"):
            results.append(("high", pid, name, exe, "running from an anonymous memory file (fileless)"))
        elif exe.endswith(" (deleted)"):
            path = exe[: -len(" (deleted)")]
            # package upgrades replace binaries under running daemons; still worth a look
            severity = "high" if first_match(path, dirs) else "medium"
            results.append((severity, pid, name, exe, "binary was deleted after the process started"))
        else:
            matched = first_match(exe, dirs)
            if matched:
                results.append(("high", pid, name, exe, "running from a temporary/world-writable folder"))
    return results


def main() -> int:
    parser = make_parser("Find processes running from deleted, in-memory or temporary locations.")
    args = parser.parse_args()
    report = Report("deleted_binary_check", args, needs_admin=True)
    dirs = compile_patterns(load_rules("deleted_binary_check", args.rules).get("suspicious_dirs", []))

    if IS_LINUX:
        findings = linux_exe_findings(dirs)
        for severity, pid, name, exe, reason in sorted(findings, key=lambda f: f[1]):
            cmdline = (read_text(f"/proc/{pid}/cmdline") or "").replace("\0", " ").strip()
            report.add("processes", severity, f"pid {pid} ({name}) {exe}: {reason} :: {cmdline[:150]}", pid=pid, process=name, exe=exe, reason=reason)
        report.info("summary", f"checked {sum(1 for p in os.listdir('/proc') if p.isdigit())} processes")
    elif IS_WINDOWS:
        procs, error = list_processes()
        if error:
            report.error(error)
        for proc in procs:
            if not proc.exe:
                continue
            if first_match(proc.exe, dirs):
                report.add("processes", "high", f"pid {proc.pid} ({proc.name}) runs from {proc.exe}", pid=proc.pid, exe=proc.exe)
            elif not is_file(proc.exe):
                report.add("processes", "high", f"pid {proc.pid} ({proc.name}) executable no longer exists: {proc.exe}", pid=proc.pid, exe=proc.exe)
        report.info("summary", f"checked {len(procs)} processes")
    else:
        report.fail("deleted_binary_check supports Linux and Windows")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
