#!/usr/bin/env python3

"""Run every applicable check with --json and build one Markdown or HTML triage report.

    python3 triage_all.py                      # Markdown report in the current directory
    python3 triage_all.py --format html -o report.html
    python3 triage_all.py --only log_triage --only port_watch

Checks that need arguments (paths, IOC lists, API keys) or run forever are not included;
see README.md for those.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from btcommon import PRIV_WARNING, SEVERITIES, SEVERITY_RANK, SYSTEM, hostname, is_admin, now_iso

HERE = Path(__file__).resolve().parent  # the .pyz file itself when running from the archive
ANY = {"Linux", "Windows", "FreeBSD", "Darwin"}
POSIX = {"Linux", "FreeBSD"}

# script -> (supported systems, extra arguments)
CHECKS: dict[str, tuple[set[str], list[str]]] = {
    "tool_integrity_check": ({"Linux", "Windows"}, []),  # runs first; see TRUST_CHECK
    "process_monitor": ({"Linux", "Windows", "FreeBSD", "Darwin"}, ["--limit", "15"]),
    "process_tree_audit": ({"Linux", "Windows", "FreeBSD", "Darwin"}, []),
    "deleted_binary_check": ({"Linux", "Windows"}, []),
    "port_watch": ({"Linux", "Windows"}, []),
    "network_beacon_watch": ({"Linux", "Windows"}, []),
    "log_triage": ({"Linux", "Windows", "FreeBSD"}, []),
    "account_audit": ({"Linux", "Windows", "FreeBSD"}, []),
    "ssh_key_audit": (ANY, []),
    "startup_audit": ({"Linux", "Windows"}, ["--quiet"]),
    "scheduled_task_audit": ({"Linux", "Windows", "FreeBSD"}, []),
    "suid_audit": (POSIX, []),
    "ld_preload_check": ({"Linux"}, []),
    "wmi_persistence_audit": ({"Windows"}, []),
    "defender_status": ({"Windows"}, []),
    "powershell_logging_audit": ({"Windows"}, []),
    "dns_cache_audit": ({"Linux", "Windows"}, []),
    "suspicious_web_root_scan": (ANY, []),
    "browser_download_audit": (ANY, ["--risky-only"]),
    "usb_device_audit": ({"Linux", "Windows"}, []),
    "serviceup": ({"Linux", "Windows"}, ["--once"]),
}


TRUST_CHECK = "tool_integrity_check"


def script_command(name: str) -> list[str]:
    """Command that runs one check, from the scripts folder or from the .pyz archive."""
    if HERE.is_file():
        return [sys.executable, str(HERE), name]
    return [sys.executable, str(HERE / f"{name}.py")]


def run_check(name: str, extra: list[str], timeout: int, min_severity: str, allowlists: list[str] = ()) -> dict:
    allow_args = [arg for path in allowlists for arg in ("--allowlist", path)]
    cmd = [*script_command(name), "--json", "--min-severity", min_severity, *allow_args, *extra]
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"tool": name, "findings": [], "errors": [f"timed out after {timeout}s"], "exit_code": 2, "duration": timeout}
    duration = round(time.monotonic() - started, 1)
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
        return {"tool": name, "findings": [], "errors": [f"no JSON output (exit {proc.returncode}): {' | '.join(tail)}"], "exit_code": 2, "duration": duration}
    doc["duration"] = duration
    # the privilege warning is shown once in the report header instead of per check
    doc["errors"] = [e for e in doc.get("errors", []) if e != PRIV_WARNING]
    return doc


def counts(doc: dict) -> dict[str, int]:
    return doc.get("summary") or {sev: sum(1 for f in doc.get("findings", []) if f.get("severity") == sev) for sev in SEVERITIES}


def status_of(doc: dict) -> str:
    return {0: "clean", 1: "findings", 2: "error"}.get(doc.get("exit_code", 2), "error")


def trust_warning(results: list[dict]) -> str:
    """Warning text when the system tools every other check relies on look tampered with."""
    doc = next((d for d in results if d.get("tool") == TRUST_CHECK), None)
    if doc is None:
        return ""
    c = counts(doc)
    if c.get("high", 0) or c.get("medium", 0):
        return (
            "System tools failed the integrity check (see tool_integrity_check below): results of the "
            "other checks may be manipulated by a rootkit. Re-run from a trusted live system."
        )
    return ""


def render_markdown(results: list[dict], meta: dict) -> str:
    lines = [f"# Triage report: {meta['host']}", "", f"- Generated: {meta['timestamp']}", f"- OS: {meta['os']}", f"- Privileged: {meta['privileged']}" + ("" if meta["privileged"] else " (run as root/Administrator for complete results)"), ""]
    if meta.get("trust_warning"):
        lines += [f"> **WARNING:** {meta['trust_warning']}", ""]
    lines += ["## Summary", "", "| Check | Status | High | Medium | Low | Time (s) |", "|---|---|---|---|---|---|"]
    for doc in results:
        c = counts(doc)
        lines.append(f"| {doc['tool']} | {status_of(doc)} | {c.get('high', 0)} | {c.get('medium', 0)} | {c.get('low', 0)} | {doc.get('duration', '')} |")
    lines.append("")
    for severity in ("high", "medium", "low"):
        rows = [(doc["tool"], f) for doc in results for f in doc.get("findings", []) if f.get("severity") == severity]
        if rows:
            lines += [f"## {severity.capitalize()} findings ({len(rows)})", ""]
            lines += [f"- **{tool}** / {f.get('check')}: {f.get('message', '').replace(chr(10), ' ')}" for tool, f in rows]
            lines.append("")
    errors = [(doc["tool"], e) for doc in results for e in doc.get("errors", [])]
    if errors:
        lines += ["## Errors and gaps", ""] + [f"- **{tool}**: {e}" for tool, e in errors] + [""]
    return "\n".join(lines)


def render_html(results: list[dict], meta: dict) -> str:
    esc = html.escape
    rows = "".join(
        f"<tr class='{status_of(d)}'><td>{esc(d['tool'])}</td><td>{status_of(d)}</td>"
        + "".join(f"<td>{counts(d).get(s, 0)}</td>" for s in ("high", "medium", "low"))
        + f"<td>{d.get('duration', '')}</td></tr>"
        for d in results
    )
    sections = []
    for severity in ("high", "medium", "low"):
        items = [(d["tool"], f) for d in results for f in d.get("findings", []) if f.get("severity") == severity]
        if items:
            lis = "".join(f"<li><b>{esc(t)}</b> / {esc(str(f.get('check')))}: <code>{esc(f.get('message', ''))}</code></li>" for t, f in items)
            sections.append(f"<h2 class='{severity}'>{severity.capitalize()} findings ({len(items)})</h2><ul>{lis}</ul>")
    errors = "".join(f"<li><b>{esc(d['tool'])}</b>: {esc(e)}</li>" for d in results for e in d.get("errors", []))
    if errors:
        sections.append(f"<h2>Errors and gaps</h2><ul>{errors}</ul>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Triage report {esc(meta['host'])}</title>
<style>
:root {{ --bg:#fff; --fg:#1b1f24; --muted:#5b6470; --line:#d8dee4; --high:#b42318; --medium:#b54708; --low:#175cd3; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1115; --fg:#e6e8eb; --muted:#9aa4af; --line:#2b313a; --high:#f97066; --medium:#fdb022; --low:#84adff; }} }}
body {{ background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; max-width:1100px; margin:0 auto; padding:24px 16px; }}
table {{ border-collapse:collapse; width:100%; }} th, td {{ border-bottom:1px solid var(--line); padding:6px 8px; text-align:left; }}
td:nth-child(n+3) {{ text-align:right; font-variant-numeric:tabular-nums; }}
tr.error td:nth-child(2) {{ color:var(--high); }} tr.findings td:nth-child(2) {{ color:var(--medium); }}
h2.high {{ color:var(--high); }} h2.medium {{ color:var(--medium); }} h2.low {{ color:var(--low); }}
code {{ white-space:pre-wrap; word-break:break-word; }} .meta {{ color:var(--muted); }}
.warning {{ border-left:4px solid var(--high); padding:8px 12px; }}
</style></head><body>
<h1>Triage report: {esc(meta['host'])}</h1>
<p class="meta">{esc(meta['timestamp'])} &middot; {esc(meta['os'])} &middot; privileged: {meta['privileged']}</p>
{f"<p class='warning'><b>WARNING:</b> {esc(meta['trust_warning'])}</p>" if meta.get('trust_warning') else ''}
<table><thead><tr><th>Check</th><th>Status</th><th>High</th><th>Medium</th><th>Low</th><th>Time (s)</th></tr></thead><tbody>{rows}</tbody></table>
{''.join(sections)}
</body></html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all applicable checks and build one report.")
    parser.add_argument("--format", choices=["md", "html", "json"], default="md", help="Report format (default: md)")
    parser.add_argument("-o", "--output", help="Output file, or '-' for stdout (default: triage_<host>_<time>.<ext>)")
    parser.add_argument("--only", action="append", default=[], help="Run only this check (repeatable)")
    parser.add_argument("--skip", action="append", default=[], help="Skip this check (repeatable)")
    parser.add_argument("--timeout", type=int, default=600, help="Per-check timeout in seconds (default: 600)")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="low", help="Lowest severity to include (default: low)")
    parser.add_argument("--list", action="store_true", help="List the checks that would run and exit")
    parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1), help="Checks to run in parallel (default: up to 4)")
    parser.add_argument("--allowlist", action="append", default=[], metavar="FILE", help="Allowlist file passed to every check (repeatable)")
    args = parser.parse_args()

    unknown = [n for n in args.only + args.skip if n not in CHECKS]
    if unknown:
        parser.error(f"unknown check(s): {', '.join(unknown)}; choose from {', '.join(CHECKS)}")
    selected = [
        (name, extra) for name, (systems, extra) in CHECKS.items()
        if SYSTEM in systems and (not args.only or name in args.only) and name not in args.skip
    ]
    if args.list:
        print("\n".join(name for name, _ in selected))
        return 0
    if not is_admin():
        print("warning: not running as root/Administrator; many checks will be incomplete", file=sys.stderr)

    def progress(doc: dict) -> None:
        c = counts(doc)
        print(f"{doc['tool']:<26} {status_of(doc):<9} high={c.get('high', 0)} medium={c.get('medium', 0)} low={c.get('low', 0)} ({doc.get('duration')}s)", file=sys.stderr, flush=True)

    results = []
    # The integrity check runs alone and first, so a warning shows up before anything else.
    first = [(n, e) for n, e in selected if n == TRUST_CHECK]
    rest = [(n, e) for n, e in selected if n != TRUST_CHECK]
    for name, extra in first:
        doc = run_check(name, extra, args.timeout, args.min_severity, args.allowlist)
        progress(doc)
        results.append(doc)
        if trust_warning([doc]):
            print(f"WARNING: {trust_warning([doc])}", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = [pool.submit(run_check, name, extra, args.timeout, args.min_severity, args.allowlist) for name, extra in rest]
        for future in as_completed(futures):
            doc = future.result()
            progress(doc)
            results.append(doc)

    import platform

    meta = {"host": hostname(), "timestamp": now_iso(), "os": platform.platform(), "privileged": is_admin(), "trust_warning": trust_warning(results)}
    results.sort(key=lambda d: (-counts(d).get("high", 0), -counts(d).get("medium", 0), d["tool"]))
    if args.format == "json":
        text = json.dumps({**meta, "results": results}, indent=2, default=str)
    elif args.format == "html":
        text = render_html(results, meta)
    else:
        text = render_markdown(results, meta)

    output = args.output or f"triage_{meta['host']}_{datetime.now():%Y%m%d-%H%M%S}.{args.format}"
    if output == "-":
        print(text)
    else:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"report written to {output}", file=sys.stderr)
    worst = max((SEVERITY_RANK.get(f.get("severity", "info"), 0) for d in results for f in d.get("findings", [])), default=0)
    return 1 if worst > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
