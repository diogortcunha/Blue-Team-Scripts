#!/usr/bin/env python3

"""Triage authentication, account and security log activity.

Linux/BSD: auth.log / secure (including rotated and .gz files) or journald.
Windows: Security and System event logs via Get-WinEvent.
Flags brute force per source IP, successful logins from brute-forcing IPs, account and
group changes, sudo failures, root logins, cleared logs and new services.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from btcommon import IS_WINDOWS, SEVERITY_RANK, Report, WinEvent, auth_log_lines, load_rules, make_parser, run, windows_events

_IP = re.compile(r"(?:from|rhost=)\s*([0-9a-fA-F:.]{3,})")
_USER = re.compile(r"(?:for (?:invalid user )?|user[= ])([^\s;:(]+)")


@dataclass
class Event:
    category: str
    severity: str
    text: str
    ip: str = ""
    user: str = ""
    time: str = ""


@dataclass
class Triage:
    events: list[Event] = field(default_factory=list)
    unmatched: int = 0


def classify_linux(lines: list[str], patterns: list[dict], ignore: list[str] = ()) -> Triage:
    compiled = [(re.compile(p["pattern"], re.IGNORECASE), p["category"], p["severity"]) for p in patterns]
    ignored = [re.compile(p, re.IGNORECASE) for p in ignore]
    triage = Triage()
    for line in lines:
        if any(regex.search(line) for regex in ignored):
            continue
        for regex, category, severity in compiled:
            if regex.search(line):
                ip = _IP.search(line)
                user = _USER.search(line)
                triage.events.append(Event(category, severity, line, ip.group(1) if ip else "", user.group(1) if user else ""))
                break
        else:
            triage.unmatched += 1
    return triage


# EventData fields worth showing, in display order (names are language independent).
WINDOWS_FIELDS = [
    ("TargetUserName", "user"), ("TargetDomainName", "domain"), ("IpAddress", "from"), ("LogonType", "logon_type"),
    ("SubjectUserName", "by"), ("MemberName", "member"), ("ServiceName", "service"), ("ImagePath", "image"),
    ("ServiceFileName", "image"), ("TaskName", "task"), ("TargetServerName", "server"), ("Channel", "log"),
]
SYSTEM_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}


def describe_windows_event(event: WinEvent, description: str) -> str:
    parts = [f"{event.time} [{event.id}] {description}"]
    seen = set()
    for field_name, label in WINDOWS_FIELDS:
        value = event.field(field_name)
        if value and label not in seen and value not in {"::1", "127.0.0.1"}:
            seen.add(label)
            parts.append(f"{label}={value}")
    return " ".join(parts)


def classify_windows(days: int, rules: dict, report: Report) -> Triage:
    triage = Triage()
    logon_types = set(rules.get("interesting_logon_types", []))
    for log, ids in rules.get("windows_events", {}).items():
        events, error = windows_events(log, [int(i) for i in ids], days)
        if error:
            report.error(f"{log} log: {error}")
        for event in events:
            meta = ids.get(str(event.id), {})
            user = event.field("TargetUserName") or event.field("SubjectUserName")
            if event.id == 4624 and logon_types and event.field("LogonType") not in logon_types:
                continue
            if event.id in (4624, 4672) and (user.endswith("$") or user.upper() in SYSTEM_ACCOUNTS or user.upper().startswith(("DWM-", "UMFD-"))):
                continue
            ip = event.field("IpAddress")
            ip = "" if ip in {"::1", "127.0.0.1"} else ip
            text = describe_windows_event(event, meta.get("description") or event.summary)
            triage.events.append(Event(meta.get("category", "other"), meta.get("severity", "info"), text, ip, user, event.time))
    return triage


def summarize(report: Report, triage: Triage, threshold: int, limit: int) -> None:
    counts = Counter(event.category for event in triage.events)
    for category, count in counts.most_common():
        report.info("summary", f"{category}: {count}", category=category, count=count)

    failures_by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in triage.events:
        if event.category == "auth_failure":
            failures_by_ip[event.ip or "unknown source"].append(event)
    brute_ips = {ip for ip, events in failures_by_ip.items() if len(events) >= threshold and ip != "unknown source"}

    for ip, events in sorted(failures_by_ip.items(), key=lambda item: -len(item[1])):
        users = Counter(e.user for e in events if e.user)
        top_users = ", ".join(f"{u} ({n})" for u, n in users.most_common(5))
        severity = "high" if ip in brute_ips else "low"
        label = "possible brute force" if ip in brute_ips else "failed logins"
        report.add("authentication failures", severity, f"{label}: {len(events)} from {ip} (users: {top_users or '?'})", ip=ip, count=len(events), users=dict(users))

    for event in triage.events:
        if event.category in {"login", "root_login"} and event.ip in brute_ips:
            report.add("compromise indicators", "high", f"successful login from brute-forcing IP {event.ip}: {event.text}", ip=event.ip, user=event.user)

    flagged: dict[str, list[Event]] = defaultdict(list)
    for event in triage.events:
        if event.category != "auth_failure" and SEVERITY_RANK[event.severity] > 0:
            flagged[event.category].append(event)
    for category, events in flagged.items():
        for event in events[-limit:][::-1]:
            report.add(category, event.severity, event.text, user=event.user, ip=event.ip)
        if len(events) > limit:
            report.info(category, f"... {len(events) - limit} older {category} event(s) not shown")

    logins = [e for e in triage.events if e.category in {"login", "sudo", "su", "privileged_logon", "explicit_credentials"}]
    for event in logins[-limit:][::-1]:
        report.info("recent activity", event.text, category=event.category)


def main() -> int:
    parser = make_parser("Summarize suspicious authentication and security log activity.")
    parser.add_argument("--days", type=int, default=7, help="Look back this many days (default: 7)")
    parser.add_argument("--limit", type=int, default=25, help="Max events to show per category (default: 25)")
    args = parser.parse_args()
    report = Report("log_triage", args, needs_admin=True)
    rules = load_rules("log_triage", args.rules)
    threshold = int(rules.get("bruteforce_threshold", 10))

    if IS_WINDOWS:
        triage = classify_windows(args.days, rules, report)
        if not triage.events and report.errors:
            report.fail("no readable event log data")
            return report.emit()
        report.info("source", f"Windows event logs, last {args.days} day(s)")
    else:
        lines, source = auth_log_lines(args.days)
        if not lines:
            report.fail("no readable authentication log (auth.log, secure or journald)")
            return report.emit()
        report.info("source", f"{source}: {len(lines)} line(s) from the last {args.days} day(s)")
        triage = classify_linux(lines, rules.get("linux_patterns", []), rules.get("linux_ignore", []))
        last = run(["last", "-n", str(args.limit), "-w"])
        for line in last.lines():
            if line.strip() and not line.startswith("wtmp"):
                report.info("last logins (wtmp)", line)

    summarize(report, triage, threshold, args.limit)
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
