#!/usr/bin/env python3

"""Flag suspicious parent -> child process relationships and print process trees.

Examples: winword.exe -> powershell.exe (malicious macro), w3wp.exe/nginx -> sh (web shell),
lsass.exe with a parent other than wininit.exe (masquerading). Rules live in rules.json.
"""

from __future__ import annotations

from btcommon import IS_WINDOWS, Process, Report, list_processes, load_rules, make_parser, normalize_name


def check_pairs(procs: list[Process], rules: list[dict]) -> list[tuple[dict, Process, Process]]:
    by_pid = {p.pid: p for p in procs}
    hits = []
    compiled = [(rule, set(rule["parents"]), set(rule["children"])) for rule in rules]
    for child in procs:
        parent = by_pid.get(child.ppid) if child.ppid is not None else None
        if parent is None or parent.pid == child.pid:
            continue
        pname, cname = normalize_name(parent.name), normalize_name(child.name)
        for rule, parents, children in compiled:
            if pname in parents and cname in children:
                hits.append((rule, parent, child))
                break
    return hits


def check_expected_parents(procs: list[Process], expected: dict[str, list[str]]) -> list[tuple[Process, str]]:
    by_pid = {p.pid: p for p in procs}
    hits = []
    for proc in procs:
        name = normalize_name(proc.name)
        allowed = expected.get(name)
        if not allowed or isinstance(allowed, str):
            continue
        parent = by_pid.get(proc.ppid) if proc.ppid is not None else None
        # A missing parent is normal for processes started by smss.exe, which exits.
        if parent is not None and normalize_name(parent.name) not in allowed:
            hits.append((proc, parent.name))
    return hits


def render_tree(procs: list[Process], root_pid: int) -> list[str]:
    children: dict[int, list[Process]] = {}
    for proc in procs:
        if proc.ppid is not None and proc.ppid != proc.pid:
            children.setdefault(proc.ppid, []).append(proc)
    by_pid = {p.pid: p for p in procs}
    lines: list[str] = []

    def walk(proc: Process, depth: int) -> None:
        lines.append(f"{'  ' * depth}{proc.pid} {proc.name} {proc.cmdline[:120]}".rstrip())
        for child in sorted(children.get(proc.pid, []), key=lambda p: p.pid):
            if depth < 50:
                walk(child, depth + 1)

    if root_pid in by_pid:
        walk(by_pid[root_pid], 0)
    return lines


def ancestry(procs: list[Process], pid: int) -> str:
    by_pid = {p.pid: p for p in procs}
    chain, seen = [], set()
    current = by_pid.get(pid)
    while current and current.pid not in seen and len(chain) < 20:
        seen.add(current.pid)
        chain.append(f"{current.name}({current.pid})")
        current = by_pid.get(current.ppid) if current.ppid is not None else None
    return " <- ".join(chain)


def main() -> int:
    parser = make_parser("Audit parent/child process relationships.")
    parser.add_argument("--tree", type=int, metavar="PID", help="Print the process tree below PID")
    args = parser.parse_args()
    report = Report("process_tree_audit", args, needs_admin=IS_WINDOWS)
    rules = load_rules("process_tree_audit", args.rules)

    procs, error = list_processes()
    if error:
        report.error(error)
    if not procs:
        report.fail("could not list processes")
        return report.emit()

    for rule, parent, child in check_pairs(procs, rules.get("rules", [])):
        report.add(
            "suspicious parent/child",
            rule.get("severity", "medium"),
            f"{rule['name']}: {ancestry(procs, child.pid)} :: {child.cmdline[:200]}",
            parent=parent.name, parent_pid=parent.pid, child=child.name, child_pid=child.pid, cmdline=child.cmdline,
        )
    if IS_WINDOWS:
        expected = {k: v for k, v in rules.get("expected_parents", {}).items() if not k.startswith("_")}
        for proc, parent_name in check_expected_parents(procs, expected):
            report.add("unexpected parent", "high", f"{proc.name} ({proc.pid}) has parent {parent_name}; expected {', '.join(expected[normalize_name(proc.name)])}", pid=proc.pid, exe=proc.exe)

    if args.tree is not None:
        for line in render_tree(procs, args.tree) or [f"pid {args.tree} not found"]:
            report.info("process tree", line)
    report.info("summary", f"{len(procs)} process(es) checked")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
