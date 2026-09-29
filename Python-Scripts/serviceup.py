#!/usr/bin/env python3

"""Watch service states and alert (and optionally restart) when a running service stops.

Linux uses systemd, Windows uses ``sc``. Only transitions from running to stopped/failed
raise an alert, so one-shot units that finish normally are not reported as stopped.
``--restart ask`` prompts on a terminal, ``auto`` restarts immediately and ``never``
only reports. With ``--once`` the current failed/stopped auto-start services are listed.
"""

from __future__ import annotations

import json
import re
import sys
import time
from fnmatch import fnmatch

from btcommon import IS_LINUX, IS_WINDOWS, Allowlist, Report, hostname, make_parser, now_iso, powershell_json, run

RUNNING = {"active", "running", "reloading", "activating"}
STOPPED = {"inactive", "failed", "stopped", "stop_pending", "paused", "deactivating"}


def parse_systemctl_units(output: str) -> dict[str, str]:
    """Parse ``systemctl list-units --plain --no-legend`` into {unit: ACTIVE state}."""
    services: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.replace("●", " ").split()
        if len(parts) >= 3 and parts[0].endswith(".service"):
            services[parts[0]] = parts[2].lower()
    return services


def parse_sc_query(output: str) -> dict[str, str]:
    services: dict[str, str] = {}
    name = ""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("STATE") and name:
            parts = line.split(":", 1)[1].split()
            if len(parts) >= 2:
                services[name] = parts[1].lower()
    return services


def get_services() -> dict[str, str]:
    if IS_WINDOWS:
        return parse_sc_query(run(["sc", "query", "type=", "service", "state=", "all"]).stdout)
    result = run(["systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager"])
    return parse_systemctl_units(result.stdout)


def start_service(name: str) -> tuple[bool, str]:
    result = run(["sc", "start", name]) if IS_WINDOWS else run(["systemctl", "start", name])
    return result.ok, result.stderr or result.stdout


def who_stopped(name: str) -> str:
    """Best effort: find a recent sudo/systemctl/sc command that stopped this service."""
    if IS_LINUX:
        unit = name.removesuffix(".service")
        result = run(["journalctl", "--no-pager", "-q", "-o", "cat", "--since", "-10min", "_COMM=sudo"])
        for line in reversed(result.stdout.splitlines()):
            if "COMMAND=" in line and re.search(rf"\b(stop|kill|disable|mask)\b.*\b{re.escape(unit)}\b", line):
                user = line.split(":", 1)[0].strip()
                return f"{user} ({line.split('COMMAND=', 1)[1].strip()})"
        return "unknown (enable auditd or check journalctl -u " + name + ")"
    if IS_WINDOWS:
        rows, _ = powershell_json(
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036,7040; StartTime=(Get-Date).AddMinutes(-10)} "
            "-MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object Id,UserId,Message"
        )
        for row in rows:
            if name.lower() in (row.get("Message") or "").lower() and row.get("UserId"):
                return str(row["UserId"])
    return "unknown"


def selected(name: str, only: list[str], ignore: list[str]) -> bool:
    if only and not any(fnmatch(name, pattern) for pattern in only):
        return False
    return not any(fnmatch(name, pattern) for pattern in ignore)


_allowlist: Allowlist | None = None


def alert(args, severity: str, message: str, **data) -> None:
    global _allowlist
    if _allowlist is None:
        _allowlist = Allowlist.load(getattr(args, "allowlist", None) or [])
    reason = _allowlist.match("serviceup", "services", message) if severity != "info" else None
    if reason:
        severity, message, data = "info", f"{message}  (allowlisted: {reason})", {**data, "allowlisted": reason}
    if args.json:
        print(json.dumps({"tool": "serviceup", "host": hostname(), "timestamp": now_iso(), "severity": severity, "message": message, **data}), flush=True)
    else:
        print(f"{now_iso()} [{severity.upper()}] {message}", flush=True)


def handle_stop(args, name: str, old: str, new: str) -> None:
    culprit = who_stopped(name)
    alert(args, "medium", f"service {name} went from {old} to {new} (stopped by: {culprit})", service=name, old=old, new=new, stopped_by=culprit)
    mode = args.restart
    if mode == "ask":
        if not sys.stdin.isatty():
            return
        answer = input(f"Restart {name}? [y/N] ").strip().lower()
        if answer not in {"y", "yes", "s", "sim"}:
            return
    elif mode == "never":
        return
    ok, output = start_service(name)
    alert(args, "info" if ok else "high", f"restart of {name} {'succeeded' if ok else 'FAILED: ' + output}", service=name, restarted=ok)


def main() -> int:
    parser = make_parser("Monitor services and alert when running services stop.")
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between checks (default: 5)")
    parser.add_argument("--restart", choices=["ask", "auto", "never"], default="ask", help="What to do when a service stops (default: ask)")
    parser.add_argument("--only", action="append", default=[], metavar="GLOB", help="Only watch matching services (repeatable)")
    parser.add_argument("--ignore", action="append", default=[], metavar="GLOB", help="Ignore matching services (repeatable)")
    parser.add_argument("--once", action="store_true", help="List failed services once and exit")
    args = parser.parse_args()

    if not (IS_LINUX or IS_WINDOWS):
        print("error: serviceup supports Linux (systemd) and Windows only", file=sys.stderr)
        return 2

    previous = {n: s for n, s in get_services().items() if selected(n, args.only, args.ignore)}
    if not previous:
        print("error: no services found (is systemd running?)", file=sys.stderr)
        return 2

    if args.once:
        report = Report("serviceup", args)
        for name, state in sorted(previous.items()):
            if state == "failed":
                report.add("failed services", "medium", f"{name} is {state}", service=name, state=state)
        report.info("services", f"{len(previous)} service(s), {sum(1 for s in previous.values() if s in RUNNING)} running")
        return report.emit()

    print(f"Watching {len(previous)} services every {args.interval}s (restart={args.restart}). Ctrl-C to stop.", file=sys.stderr)
    try:
        while True:
            time.sleep(args.interval)
            current = {n: s for n, s in get_services().items() if selected(n, args.only, args.ignore)}
            for name, state in sorted(current.items()):
                old = previous.get(name)
                if old is None or old == state:
                    continue
                if old in RUNNING and state in STOPPED:
                    handle_stop(args, name, old, state)
                    state = get_services().get(name, state)
                elif state == "failed":
                    alert(args, "medium", f"service {name} failed (was {old})", service=name, old=old, new=state)
                current[name] = state
            for name in sorted(set(previous) - set(current)):
                if previous[name] in RUNNING:
                    alert(args, "low", f"service {name} disappeared", service=name)
            previous = current
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
