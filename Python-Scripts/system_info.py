#!/usr/bin/env python3

"""Collect a system and security snapshot of the host for triage.

The report is written to ``<ip>_<timestamp>.txt`` (or ``.json`` with ``--json``) with
owner-only permissions, or to stdout with ``--output -``. Each section is collected on its
own, so one failing command never loses the rest of the report. Shell history can contain
secrets and is only collected with ``--include-history``.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from btcommon import (
    IS_WINDOWS,
    SYSTEM,
    Report,
    file_mtime,
    fmt_endpoint,
    home_dirs,
    is_dir,
    list_sockets,
    load_rules,
    make_parser,
    read_text,
    run,
    run_first,
    run_powershell,
    walk_files,
    windows_events,
)

Section = Callable[[], str]


def get_ip() -> str:
    """First non-loopback IPv4 address (no packet is sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def cmd(*commands: list[str]) -> Section:
    """Section that runs the first available command."""
    return lambda: run_first(*commands).output


def ps_table(script: str) -> Section:
    return lambda: run_powershell(f"{script} | Format-Table -AutoSize | Out-String -Width 250").output


def sockets_section(listening: bool) -> Section:
    def collect() -> str:
        sockets, error = list_sockets()
        if error:
            return error
        lines = []
        for sock in sockets:
            if sock.listening != listening:
                continue
            remote = "" if listening else f" -> {fmt_endpoint(sock.remote_addr, sock.remote_port)} {sock.state}"
            lines.append(f"{sock.proto:<4} {fmt_endpoint(sock.local_addr, sock.local_port)}{remote} {sock.process or ''} {sock.pid or ''}".rstrip())
        return "\n".join(sorted(lines))
    return collect


def recent_files(dirs: list[Path], days: int = 7, limit: int = 300) -> Section:
    def collect() -> str:
        cutoff = datetime.now() - timedelta(days=days)
        lines = []
        for path in walk_files([d for d in dirs if is_dir(d)]):
            changed = file_mtime(path)
            if changed and changed >= cutoff:
                lines.append(f"{changed:%Y-%m-%d %H:%M}  {path}")
        lines.sort(reverse=True)
        extra = [f"... {len(lines) - limit} more"] if len(lines) > limit else []
        return "\n".join(lines[:limit] + extra) or f"no files changed in the last {days} days"
    return collect


def web_shells() -> str:
    import re

    from suspicious_web_root_scan import scan_file

    rules = load_rules("suspicious_web_root_scan")
    rules["script_extensions"] = set(rules.get("script_extensions", []))
    rules["image_extensions"] = set(rules.get("image_extensions", []))
    markers = [(re.compile(m["pattern"], re.IGNORECASE), m["severity"]) for m in rules.get("markers", [])]
    cutoff = datetime.now() - timedelta(days=7)
    roots = [Path(r) for r in rules.get("roots", []) if is_dir(r)]
    lines = []
    for path in walk_files(roots):
        hit = scan_file(path, rules, markers, cutoff)
        if hit:
            lines.append(f"[{hit[0].upper()}] {path}: {hit[1]}")
    return "\n".join(lines) or ("no web roots found" if not roots else "nothing suspicious")


def shell_history(lines_per_file: int) -> Section:
    names = [".bash_history", ".zsh_history", ".sh_history", ".history", ".python_history", ".mysql_history", ".psql_history"]
    win = [r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"]

    def collect() -> str:
        out = []
        for home in home_dirs():
            for name in (win if IS_WINDOWS else names):
                text = read_text(home / name)
                if text:
                    tail = text.splitlines()[-lines_per_file:]
                    out.append(f"--- {home / name} (last {len(tail)} lines)\n" + "\n".join(tail))
        return "\n".join(out) or "no readable history files"
    return collect


def proxy_env() -> str:
    lines = [f"{k}={v}" for k, v in os.environ.items() if k.lower() in {"http_proxy", "https_proxy", "ftp_proxy", "all_proxy", "no_proxy"}]
    for line in (read_text("/etc/environment") or "").splitlines():
        if "proxy" in line.lower():
            lines.append(f"/etc/environment: {line}")
    return "\n".join(lines) or "no proxy configured"


def users_linux() -> str:
    shells = set(load_rules("account_audit").get("nologin_shells", []))
    out = ["Accounts with a login shell:"]
    for line in (read_text("/etc/passwd") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[6] not in shells:
            out.append(f"  {parts[0]} uid={parts[2]} home={parts[5]} shell={parts[6]}")
    out.append("Groups with members:")
    for line in (read_text("/etc/group") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[3]:
            out.append(f"  {parts[0]}: {parts[3]}")
    return "\n".join(out)


def windows_security_policy() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "secedit.inf"
        result = run(["secedit", "/export", "/cfg", str(cfg), "/quiet"])
        try:
            return cfg.read_text(encoding="utf-16")
        except OSError as exc:
            return f"could not export security policy: {result.stderr or exc}"


def windows_account_events() -> str:
    events, error = windows_events("Security", [4720, 4722, 4725, 4726, 4738, 4732, 4728], days=7)
    if error:
        return error
    return "\n".join(f"{e.time} [{e.id}] {e.summary} target={e.field('TargetUserName')} by={e.field('SubjectUserName')}" for e in events) or "none in the last 7 days"


def windows_sections(args) -> list[tuple[str, Section]]:
    temp = Path(os.environ.get("TEMP", tempfile.gettempdir()))
    sections: list[tuple[str, Section]] = [
        ("System Information", cmd(["systeminfo"])),
        ("Installed Software", ps_table(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
            "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | "
            "Where-Object DisplayName | Sort-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate")),
        ("Running Services", ps_table("Get-CimInstance Win32_Service | Where-Object State -eq 'Running' | Sort-Object Name | Select-Object Name,StartMode,StartName,PathName")),
        ("Listening Ports", sockets_section(True)),
        ("Active Connections", sockets_section(False)),
        ("Network Configuration", cmd(["ipconfig", "/all"])),
        ("Routes", cmd(["route", "print"])),
        ("Local Users", ps_table("Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordExpires")),
        ("Administrators", cmd(["net", "localgroup", "administrators"])),
        ("Account Policy", cmd(["net", "accounts"])),
        ("Security Policy", windows_security_policy),
        ("Firewall Profiles", cmd(["netsh", "advfirewall", "show", "allprofiles"])),
        ("Firewall Rules", cmd(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])),
        ("Recent Account Changes (7 days)", windows_account_events),
        ("Recent Files (Downloads, Temp)", recent_files([h / "Downloads" for h in home_dirs()] + [temp])),
        ("Potential Web Shells", web_shells),
        ("SMB Sessions", cmd(["net", "session"])),
        ("SMB Shares", cmd(["net", "share"])),
        ("Proxy Settings", lambda: run(["netsh", "winhttp", "show", "proxy"]).output + "\n" + proxy_env()),
    ]
    if args.include_history:
        sections.append(("PowerShell History", shell_history(args.history_lines)))
    return sections


def linux_sections(args) -> list[tuple[str, Section]]:
    downloads = [h / "Downloads" for h in home_dirs()]
    sections: list[tuple[str, Section]] = [
        ("System Information", lambda: "\n".join(filter(None, [
            f"Hostname: {socket.gethostname()}",
            run(["uname", "-a"]).output,
            (read_text("/etc/os-release") or "").strip(),
            "Uptime: " + run_first(["uptime", "-p"], ["uptime"]).output,
        ]))),
        ("Logged-in Users", cmd(["who", "-a"])),
        ("Installed Software", cmd(["dpkg-query", "-W", "-f", "${Package} ${Version}\\n"], ["rpm", "-qa"], ["pacman", "-Q"], ["apk", "info", "-v"])),
        ("Running Services", cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain", "--no-legend"])),
        ("Listening Ports", sockets_section(True)),
        ("Active Connections", sockets_section(False)),
        ("Network Configuration", cmd(["ip", "addr", "show"], ["ifconfig", "-a"])),
        ("Routes", cmd(["ip", "route"], ["netstat", "-rn"])),
        ("Users and Groups", users_linux),
        ("Mandatory Access Control", cmd(["sestatus"], ["aa-status"])),
        ("Firewall", cmd(["nft", "list", "ruleset"], ["iptables", "-S"], ["ufw", "status", "verbose"], ["firewall-cmd", "--list-all"])),
        ("Recent Logins", cmd(["last", "-n", "30", "-w"])),
        ("Recent Files (/tmp, /var/tmp, /dev/shm, Downloads)", recent_files([Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")] + downloads)),
        ("Potential Web Shells", web_shells),
        ("SMB Sessions", cmd(["smbstatus", "-b"])),
        ("Proxy Settings", proxy_env),
    ]
    if args.include_history:
        sections.append(("Shell History", shell_history(args.history_lines)))
    return sections


def freebsd_sections(args) -> list[tuple[str, Section]]:
    sections: list[tuple[str, Section]] = [
        ("System Information", cmd(["uname", "-a"])),
        ("Installed Software", cmd(["pkg", "info"])),
        ("Enabled Services", cmd(["service", "-e"])),
        ("Listening Ports", cmd(["sockstat", "-46l"])),
        ("Active Connections", cmd(["sockstat", "-46c"])),
        ("Network Configuration", cmd(["ifconfig", "-a"])),
        ("Users and Groups", users_linux),
        ("Security Settings", cmd(["sysctl", "security"])),
        ("Firewall", cmd(["pfctl", "-sr"], ["ipfw", "list"])),
        ("Recent Logins", cmd(["last", "-n", "30"])),
        ("Recent Files (/tmp, /var/tmp)", recent_files([Path("/tmp"), Path("/var/tmp")] + [h / "Downloads" for h in home_dirs()])),
        ("Potential Web Shells", web_shells),
        ("SMB Sessions", cmd(["smbstatus", "-b"])),
        ("Proxy Settings", proxy_env),
    ]
    if args.include_history:
        sections.append(("Shell History", shell_history(args.history_lines)))
    return sections


def write_private(path: Path, text: str) -> None:
    """Write a file readable only by its owner (the report can contain sensitive data)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def main() -> int:
    parser = make_parser("Collect a system and security snapshot.")
    parser.add_argument("--output", help="Output file, or '-' for stdout (default: <ip>_<timestamp>.txt/.json)")
    parser.add_argument("--include-history", action="store_true", help="Include shell/PowerShell history (may contain secrets)")
    parser.add_argument("--history-lines", type=int, default=100, help="History lines per file (default: 100)")
    parser.add_argument("--section", action="append", help="Only collect sections whose title contains this text (repeatable)")
    args = parser.parse_args()
    report = Report("system_info", args, needs_admin=True)

    if IS_WINDOWS:
        sections = windows_sections(args)
    elif SYSTEM == "FreeBSD":
        sections = freebsd_sections(args)
    else:
        sections = linux_sections(args)
    if args.section:
        wanted = [s.lower() for s in args.section]
        sections = [(title, fn) for title, fn in sections if any(w in title.lower() for w in wanted)]

    for title, collect in sections:
        print(f"collecting: {title}", file=sys.stderr)
        try:
            text = collect() or "(no output)"
        except Exception as exc:  # one broken section must not lose the whole report
            text = f"section failed: {type(exc).__name__}: {exc}"
            report.error(f"{title}: {text}")
        report.info(title, text.rstrip())

    output = args.output or f"{get_ip().replace('.', '_')}_{datetime.now():%Y%m%d-%H%M%S}.{'json' if args.json else 'txt'}"
    if output == "-":
        return report.emit()

    from contextlib import redirect_stdout
    from io import StringIO

    buffer = StringIO()
    with redirect_stdout(buffer):
        code = report.emit()
    write_private(Path(output), buffer.getvalue())
    print(f"System information saved to {output}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
