#!/usr/bin/env python3

"""Look for common user-land and kernel rootkit indicators on Linux.

- /etc/ld.so.preload entries and LD_PRELOAD/LD_LIBRARY_PATH in running processes
- kernel modules visible in /sys/module but missing from /proc/modules (hidden modules)
- out-of-tree/unsigned modules and the kernel taint flags
- PIDs that answer in /proc but are missing from the directory listing (hidden processes)
Run as root: other users' process environments are unreadable otherwise.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from btcommon import Report, make_parser, read_text

TAINT_FLAGS = {
    0: "proprietary module loaded",
    1: "module force-loaded",
    12: "out-of-tree module loaded",
    13: "unsigned module loaded",
    15: "kernel live-patched",
}


def taint_reasons(value: int) -> list[str]:
    return [reason for bit, reason in TAINT_FLAGS.items() if value & (1 << bit)]


def proc_modules() -> dict[str, str]:
    """{module: flags} from /proc/modules; flags such as (OE) mark out-of-tree/unsigned."""
    modules = {}
    for line in (read_text("/proc/modules") or "").splitlines():
        parts = line.split()
        if parts:
            flags = parts[-1] if parts[-1].startswith("(") else ""
            modules[parts[0]] = flags
    return modules


def sys_loaded_modules() -> set[str]:
    """Loadable modules according to sysfs (built-ins have no initstate file)."""
    names = set()
    try:
        for entry in Path("/sys/module").iterdir():
            if (entry / "initstate").exists():
                names.add(entry.name)
    except OSError:
        pass
    return names


def hidden_pids(max_pid: int = 4194304, quick: bool = False) -> list[int]:
    """PIDs that exist (stat works) but are not listed by readdir(/proc).

    The full scan checks every PID up to pid_max (a few seconds); ``quick`` stops 5000
    above the highest listed PID.
    """
    listed = {int(p) for p in os.listdir("/proc") if p.isdigit()}
    try:
        max_pid = int((read_text("/proc/sys/kernel/pid_max") or str(max_pid)).strip())
    except ValueError:
        pass
    hidden = []
    upper = min(max_pid, max(listed, default=0) + 5000) if quick else max_pid + 1
    for pid in range(1, upper):
        if pid in listed:
            continue
        try:
            os.stat(f"/proc/{pid}")
        except OSError:
            continue
        # threads are reachable by stat but not listed; only count thread-group leaders
        status = read_text(f"/proc/{pid}/status") or ""
        tgid = next((line.split()[1] for line in status.splitlines() if line.startswith("Tgid:")), "")
        if tgid == str(pid):
            hidden.append(pid)
    # Confirm twice: short-lived processes that started or exited during the scan would
    # otherwise look hidden. A hidden process must still exist and still be unlisted.
    for _ in range(2):
        time.sleep(0.5)
        relisted = {int(p) for p in os.listdir("/proc") if p.isdigit()}
        hidden = [pid for pid in hidden if pid not in relisted and os.path.exists(f"/proc/{pid}/status")]
    return hidden


def main() -> int:
    parser = make_parser("Check for LD_PRELOAD, hidden module and hidden process rootkit indicators.")
    parser.add_argument("--skip-pid-scan", action="store_true", help="Skip the hidden process brute-force scan")
    parser.add_argument("--quick-pid-scan", action="store_true", help="Only scan up to 5000 above the highest visible PID")
    args = parser.parse_args()
    report = Report("ld_preload_check", args, needs_admin=True)
    if not report.require("Linux"):
        return report.emit()

    preload = (read_text("/etc/ld.so.preload") or "").strip()
    if preload:
        report.add("preload", "high", f"/etc/ld.so.preload loads into every process: {preload}", libraries=preload.split())
    else:
        report.info("preload", "/etc/ld.so.preload is absent or empty")

    unreadable = 0
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        try:
            with open(f"/proc/{pid}/environ", "rb") as handle:
                env = handle.read().split(b"\0")
        except OSError:
            unreadable += 1
            continue
        for var in env:
            if var.startswith((b"LD_PRELOAD=", b"LD_AUDIT=")) and var.split(b"=", 1)[1]:
                comm = (read_text(f"/proc/{pid}/comm") or "?").strip()
                value = var.decode(errors="replace")
                report.add("preload", "high", f"pid {pid} ({comm}) runs with {value}", pid=int(pid), process=comm, variable=value)
    if unreadable:
        report.info("preload", f"{unreadable} process environment(s) unreadable (run as root)")

    listed = proc_modules()
    loaded = sys_loaded_modules()
    for name in sorted(loaded - set(listed)):
        report.add("kernel modules", "high", f"module {name} is in /sys/module but hidden from /proc/modules", module=name)
    for name, flags in sorted(listed.items()):
        if "O" in flags or "E" in flags:
            report.add("kernel modules", "low", f"module {name} is out-of-tree/unsigned {flags}", module=name, flags=flags)
    try:
        taint = int((read_text("/proc/sys/kernel/tainted") or "0").strip())
    except ValueError:
        taint = 0
    reasons = taint_reasons(taint)
    if reasons:
        report.add("kernel modules", "low", f"kernel taint {taint}: {', '.join(reasons)}", taint=taint)
    report.info("kernel modules", f"{len(listed)} loadable module(s) listed")

    if not args.skip_pid_scan:
        for pid in hidden_pids(quick=args.quick_pid_scan):
            comm = (read_text(f"/proc/{pid}/comm") or "?").strip()
            report.add("hidden processes", "high", f"pid {pid} ({comm}) exists but is hidden from /proc listing", pid=pid, process=comm)
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
