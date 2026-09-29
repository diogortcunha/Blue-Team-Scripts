#!/usr/bin/env python3

"""Continuously watch files for content, permission and ownership changes.

Only files whose size/mtime/ctime/inode changed are re-hashed on each pass, so short
intervals are cheap. With ``--json`` each change is printed as one JSON object per line.
"""

from __future__ import annotations

import json
import sys
import time

from btcommon import EXIT_ERROR, EXIT_FINDINGS, Allowlist, Report, hostname, load_baseline, make_parser, now_iso
from file_hash_audit import SEVERITY, compare, snapshot

_allowlist: Allowlist | None = None


def emit_change(args, status: str, path: str, detail: str) -> bool:
    """Print one change; returns False when it was allowlisted."""
    global _allowlist
    if _allowlist is None:
        _allowlist = Allowlist.load(getattr(args, "allowlist", None) or [])
    severity = SEVERITY[status]
    suffix = f" ({detail})" if detail else ""
    reason = _allowlist.match("hashwatch_daemon", "integrity", f"{status} {path}{suffix}")
    if reason:
        severity, suffix = "info", f"{suffix}  (allowlisted: {reason})"
    if args.json:
        print(json.dumps({
            "tool": "hashwatch_daemon", "host": hostname(), "timestamp": now_iso(),
            "severity": severity, "status": status, "path": path, "detail": detail, "allowlisted": reason,
        }), flush=True)
    else:
        print(f"{now_iso()} [{severity.upper()}] {status} {path}{suffix}", flush=True)
    return reason is None


def main() -> int:
    parser = make_parser("Watch files for changes.")
    parser.add_argument("paths", nargs="+", help="Files or directories to watch")
    parser.add_argument("--interval", type=int, default=30, help="Polling interval in seconds (default: 30)")
    parser.add_argument("--once", action="store_true", help="Compare once (against --baseline if given) and exit")
    parser.add_argument("--baseline", metavar="FILE", help="Start from a file_hash_audit baseline instead of the current state")
    args = parser.parse_args()

    cache: dict = {}
    errors: list[str] = []
    current = snapshot(args.paths, errors, cache)
    for error in errors:
        print(f"warning: {error}", file=sys.stderr)

    if args.baseline:
        try:
            previous = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read baseline {args.baseline}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        flagged = [emit_change(args, status, path, detail) for status, path, detail in compare(previous, current)]
        if args.once:
            return EXIT_FINDINGS if any(flagged) else 0
    elif args.once:
        report = Report("hashwatch_daemon", args)
        for path, entry in sorted(current.items()):
            report.info("hashes", f"{entry.get('sha256') or '-> ' + entry.get('link', '')}  {path}", path=path)
        return report.emit()

    if not args.json:
        print(f"Watching {len(current)} files every {args.interval}s. Ctrl-C to stop.", file=sys.stderr)
    previous = current
    try:
        while True:
            time.sleep(args.interval)
            errors = []
            current = snapshot(args.paths, errors, cache)
            for status, path, detail in compare(previous, current):
                emit_change(args, status, path, detail)
            previous = current
    except KeyboardInterrupt:
        if not args.json:
            print("Stopped.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
