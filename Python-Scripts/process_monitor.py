#!/usr/bin/env python3

"""Quick process snapshot and suspicious process triage."""

from __future__ import annotations

from btcommon import Process, Report, compile_patterns, first_match, list_processes, load_rules, make_parser, normalize_name


def classify(proc: Process, names: set[str], patterns: list) -> tuple[str, str] | None:
    """Return (severity, reason) when the process looks suspicious."""
    matched = first_match(proc.cmdline, patterns) if proc.cmdline else None
    if matched:
        return "high", f"command line matches {matched!r}"
    if normalize_name(proc.name) in names:
        return "medium", "tool often abused by attackers"
    return None


def main() -> int:
    parser = make_parser("List running processes and flag suspicious names and command lines.")
    parser.add_argument("--limit", type=int, default=25, help="Number of top processes to list (default: 25)")
    args = parser.parse_args()
    report = Report("process_monitor", args)

    rules = load_rules("process_monitor", args.rules)
    names = {n.lower() for n in rules.get("suspicious_names", [])}
    patterns = compile_patterns(load_rules("commands", args.rules).get("patterns", []))

    procs, error = list_processes()
    if error:
        report.error(error)
    if not procs:
        report.fail("could not list processes")
        return report.emit()

    procs.sort(key=lambda p: (p.cpu or 0, p.mem or 0), reverse=True)
    for proc in procs[: args.limit]:
        report.info(
            "top processes",
            f"{proc.pid:<7} {proc.ppid if proc.ppid is not None else '':<7} {proc.user[:16]:<16} "
            f"cpu={proc.cpu if proc.cpu is not None else '-':<5} mem={proc.mem if proc.mem is not None else '-':<6} "
            f"{proc.cmdline[:120] or proc.name}",
            pid=proc.pid,
            name=proc.name,
        )

    for proc in procs:
        hit = classify(proc, names, patterns)
        if hit:
            severity, reason = hit
            report.add(
                "suspicious processes",
                severity,
                f"pid {proc.pid} ({proc.name}) user={proc.user or '?'}: {reason}: {proc.cmdline[:200]}",
                pid=proc.pid,
                ppid=proc.ppid,
                name=proc.name,
                user=proc.user,
                cmdline=proc.cmdline,
                exe=proc.exe,
                reason=reason,
            )
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
