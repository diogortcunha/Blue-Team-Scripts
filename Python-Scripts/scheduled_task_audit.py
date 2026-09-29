#!/usr/bin/env python3

"""Audit cron jobs, at jobs, systemd timers and Windows scheduled tasks.

Flags suspicious commands and, with --baseline, shows jobs that were added, removed or
changed. Run times (next/last run, last result) are left out so diffs stay stable.
"""

from __future__ import annotations

from pathlib import Path

from btcommon import (
    IS_WINDOWS,
    Report,
    compile_patterns,
    first_match,
    handle_baseline,
    is_file,
    load_rules,
    make_parser,
    powershell_json,
    read_text,
    run,
    sha256_file,
)

CRON_FILES = [Path("/etc/crontab"), Path("/etc/anacrontab")]
CRON_DIRS = [Path("/etc/cron.d"), Path("/var/spool/cron/crontabs"), Path("/var/spool/cron")]
CRON_SCRIPT_DIRS = [Path(f"/etc/cron.{period}") for period in ("hourly", "daily", "weekly", "monthly")]


def cron_lines(text: str) -> list[str]:
    """Job lines of a crontab, without comments, blank lines and variable assignments."""
    jobs = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        head = stripped.split(None, 1)[0]
        if "=" in head and not head.startswith(("*", "@")) and not head[0].isdigit():
            continue
        jobs.append(" ".join(stripped.split()))
    return jobs


def linux_jobs(report: Report, bodies: dict[str, str]) -> dict[str, str]:
    """Return {stable key: value}; the value is what a CHANGED diff compares.

    ``bodies`` receives the content of cron scripts so it can be scanned too.
    """
    items: dict[str, str] = {}
    user_cron = run(["crontab", "-l"])
    for line in cron_lines(user_cron.stdout if user_cron.ok else ""):
        items[f"crontab -l: {line}"] = ""

    files = [p for p in CRON_FILES if is_file(p)]
    for directory in CRON_DIRS:
        try:
            files.extend(sorted(p for p in directory.iterdir() if is_file(p)))
        except PermissionError:
            report.error(f"{directory}: permission denied (run as root to read other users' crontabs)")
        except OSError:
            pass
    for path in files:
        text = read_text(path)
        if text is None:
            report.error(f"{path}: unreadable")
            continue
        for line in cron_lines(text):
            items[f"{path}: {line}"] = ""

    for directory in CRON_SCRIPT_DIRS:
        try:
            scripts = sorted(p for p in directory.iterdir() if is_file(p))
        except OSError:
            continue
        for path in scripts:
            items[f"{path}"] = sha256_file(path) or "unreadable"
            bodies[f"{path}"] = read_text(path, max_bytes=500_000) or ""

    at_jobs = run(["atq"])
    for line in at_jobs.lines():
        job_id = line.split()[0] if line.split() else ""
        body = run(["at", "-c", job_id]).stdout if job_id else ""
        command = body.strip().splitlines()[-1] if body.strip() else line
        items[f"at job {job_id}: {command}"] = ""

    timers = run(["systemctl", "list-unit-files", "--type=timer", "--no-legend", "--no-pager", "--plain"])
    for line in timers.lines():
        parts = line.split()
        if len(parts) >= 2:
            items[f"systemd timer: {parts[0]}"] = parts[1]
    return items


def windows_jobs(report: Report) -> dict[str, str]:
    rows, error = powershell_json(
        "Get-ScheduledTask | ForEach-Object { [pscustomobject]@{ "
        "Path = $_.TaskPath + $_.TaskName; Author = $_.Author; "
        "Actions = (($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' ; ') } }"
    )
    if error:
        report.error(error)
    items: dict[str, str] = {}
    for row in rows:
        path = row.get("Path") or "?"
        items[path] = (row.get("Actions") or "").strip()
    return items


def main() -> int:
    parser = make_parser("Audit scheduled tasks and cron entries.", baseline=True)
    parser.add_argument("--all", action="store_true", help="List every job, not only suspicious ones")
    parser.add_argument("--include-microsoft", action="store_true", help="Windows: also flag tasks under \\Microsoft\\")
    args = parser.parse_args()
    report = Report("scheduled_task_audit", args, needs_admin=True)
    patterns = compile_patterns(load_rules("commands", args.rules).get("patterns", []))

    bodies: dict[str, str] = {}
    items = windows_jobs(report) if IS_WINDOWS else linux_jobs(report, bodies)
    if not items and report.errors:
        report.fail("no scheduled job data could be collected")
        return report.emit()

    for key, value in sorted(items.items()):
        text = f"{key} {value}".strip()
        if IS_WINDOWS:
            text = f"{key} -> {value}"
        matched = first_match(text, patterns) or first_match(bodies.get(key, ""), patterns)
        if IS_WINDOWS and key.startswith("\\Microsoft\\") and not args.include_microsoft:
            matched = None if matched is None or "\\appdata\\" not in text.lower() else matched
        if matched:
            report.add("suspicious jobs", "high", f"{text}  <- matches {matched!r}", job=key, action=value, pattern=matched)
        elif args.all:
            report.info("jobs", text, job=key, action=value)
    report.info("jobs", f"{len(items)} scheduled job(s) collected (use --all to list them)")

    handle_baseline(report, items, check="changes since baseline")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
