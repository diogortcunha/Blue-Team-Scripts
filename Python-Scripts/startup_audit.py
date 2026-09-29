#!/usr/bin/env python3

"""Audit (and optionally diff) common autorun and persistence locations.

Linux: rc.local, enabled systemd services, admin/user unit files, XDG autostart, profile
scripts, per-user shell rc files, ld.so.preload, udev RUN rules and boot-time modules.
Windows: Run/RunOnce keys, Startup folders of every user and auto-start services.
Cron jobs and scheduled tasks are covered by scheduled_task_audit.py; WMI, IFEO and
Winlogon persistence by wmi_persistence_audit.py.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from btcommon import (
    IS_WINDOWS,
    Report,
    compile_patterns,
    first_match,
    handle_baseline,
    home_dirs,
    is_file,
    load_rules,
    make_parser,
    powershell_json,
    read_text,
    reg_query,
    run,
    sha256_file,
)


class Collector:
    def __init__(self) -> None:
        self.items: dict[str, str] = {}
        self.bodies: dict[str, str] = {}

    def add(self, key: str, value: str = "", body: str | None = None) -> None:
        self.items[key] = value
        if body:
            self.bodies[key] = body

    def add_file(self, path: Path) -> None:
        text = read_text(path, max_bytes=1_000_000)
        if text is None:
            return
        self.add(str(path), sha256_file(path) or "", text)


def _files(directory: Path, pattern: str = "*") -> list[Path]:
    try:
        return sorted(p for p in directory.glob(pattern) if is_file(p))
    except OSError:
        return []


def unit_exec_lines(text: str) -> str:
    return " ; ".join(line.strip() for line in text.splitlines() if re.match(r"\s*Exec(Start|StartPre|StartPost|Stop)=", line))


def linux_collect(rc_files: list[str]) -> Collector:
    c = Collector()
    for path in [Path("/etc/rc.local"), Path("/etc/profile"), Path("/etc/bash.bashrc"), Path("/etc/environment")]:
        if is_file(path):
            c.add_file(path)
    for path in _files(Path("/etc/profile.d")):
        c.add_file(path)

    enabled = run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager", "--plain"])
    for line in enabled.lines():
        if line.split():
            c.add(f"systemd enabled: {line.split()[0]}")

    unit_dirs = [Path("/etc/systemd/system")] + [home / ".config/systemd/user" for home in home_dirs()]
    for directory in unit_dirs:
        for path in _files(directory, "*.service") + _files(directory, "*.timer"):
            text = read_text(path) or ""
            c.add(str(path), unit_exec_lines(text), text)

    autostart_dirs = [Path("/etc/xdg/autostart")] + [home / ".config/autostart" for home in home_dirs()]
    for directory in autostart_dirs:
        for path in _files(directory, "*.desktop"):
            text = read_text(path) or ""
            exec_line = next((line for line in text.splitlines() if line.startswith("Exec=")), "")
            c.add(str(path), exec_line, text)

    for home in home_dirs():
        for name in rc_files:
            path = home / name
            if is_file(path):
                c.add_file(path)

    preload = Path("/etc/ld.so.preload")
    if preload.exists():
        c.add(str(preload), (read_text(preload) or "").strip())

    for path in _files(Path("/etc/udev/rules.d"), "*.rules"):
        for line in (read_text(path) or "").splitlines():
            if "RUN" in line and not line.lstrip().startswith("#"):
                c.add(f"{path}: {line.strip()}", "", line)

    for path in [Path("/etc/modules")] + _files(Path("/etc/modules-load.d"), "*.conf"):
        for line in (read_text(path) or "").splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                c.add(f"boot module ({path}): {line.strip()}")
    return c


def windows_collect(run_keys: list[str], report: Report) -> Collector:
    c = Collector()
    for key in run_keys:
        for subkey, values in reg_query(key).items():
            for name, data in values.items():
                c.add(f"{subkey}\\{name}", data, data)

    folders = [Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\Startup"]
    folders += [home / r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" for home in home_dirs()]
    for folder in folders:
        for path in _files(folder):
            if path.name.lower() != "desktop.ini":
                c.add(str(path), sha256_file(path) or "", path.name)

    rows, error = powershell_json(
        "Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } | Select-Object Name,PathName,StartName"
    )
    if error:
        report.error(f"services: {error}")
    for row in rows:
        path_name = row.get("PathName") or ""
        c.add(f"service: {row.get('Name')}", path_name, path_name)
    return c


def unquoted_service_path(path_name: str) -> bool:
    """True for an unquoted executable path with spaces, e.g. C:\\Program Files\\A B\\svc.exe."""
    if not path_name or path_name.startswith('"'):
        return False
    exe = re.split(r"\.exe\b", path_name, maxsplit=1, flags=re.IGNORECASE)[0]
    return " " in exe and not exe.lower().startswith(r"c:\windows\system32")


def main() -> int:
    parser = make_parser("Inspect (and diff) common persistence locations.", baseline=True)
    parser.add_argument("--quiet", action="store_true", help="Only show flagged entries, not the full inventory")
    args = parser.parse_args()
    report = Report("startup_audit", args, needs_admin=True)
    rules = load_rules("startup_audit", args.rules)
    patterns = compile_patterns(load_rules("commands", args.rules).get("patterns", []))

    if IS_WINDOWS:
        collector = windows_collect(rules.get("windows_run_keys", []), report)
    else:
        collector = linux_collect(rules.get("linux_rc_files", []))

    for key, value in sorted(collector.items.items()):
        body = collector.bodies.get(key, "")
        matched = first_match(body, patterns) or first_match(value, patterns)
        if key == "/etc/ld.so.preload" and value:
            report.add("persistence", "high", f"{key} preloads libraries into every process: {value}", path=key, value=value)
        elif matched:
            line = next((ln.strip() for ln in body.splitlines() if re.search(matched, ln, re.IGNORECASE)), value)
            report.add("persistence", "high", f"{key}: {line[:200]}  <- matches {matched!r}", path=key, value=value, pattern=matched)
        elif IS_WINDOWS and key.startswith("service: ") and unquoted_service_path(value):
            report.add("persistence", "low", f"{key}: unquoted service path with spaces: {value}", path=key, value=value)
        elif not args.quiet:
            shown = value if len(value) < 100 else value[:97] + "..."
            report.info("inventory", f"{key}  {shown}".rstrip(), path=key, value=value)

    handle_baseline(report, collector.items, check="changes since baseline")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
