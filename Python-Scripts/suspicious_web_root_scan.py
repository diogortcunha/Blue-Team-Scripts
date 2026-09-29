#!/usr/bin/env python3

"""Scan web roots for web shells and recently changed server-side scripts.

Every server-side script is checked for web-shell markers regardless of age; recent
scripts without markers are listed as low severity; images that contain code (polyglots)
and scripts inside upload folders are flagged too. "Recent" uses the newer of mtime and
ctime on POSIX systems, since ctime cannot be faked with ``touch``.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

from btcommon import Report, file_mtime, is_dir, load_rules, make_parser, read_text, walk_files

_CODE_IN_IMAGE = re.compile(r"<\?php|<%@|<%\s|<script\s+runat", re.IGNORECASE)


def scan_file(path: Path, rules: dict, markers: list[tuple[re.Pattern[str], str]], cutoff: datetime) -> tuple[str, str] | None:
    """Return (severity, reason) for a file, or None when it is not interesting."""
    suffix = path.suffix.lower()
    max_bytes = int(rules.get("max_read_bytes", 2_000_000))
    changed = file_mtime(path)
    recent = changed is not None and changed >= cutoff
    in_upload_dir = any(part.lower() in {"upload", "uploads", "files", "images", "img", "media"} for part in path.parts[:-1])

    if suffix in rules["image_extensions"]:
        head = read_text(path, max_bytes=65536) or ""
        if _CODE_IN_IMAGE.search(head):
            return "high", "image file contains server-side code (polyglot web shell)"
        return None
    if suffix not in rules["script_extensions"]:
        return None

    text = read_text(path, max_bytes=max_bytes)
    if text is None:
        return "medium", "script could not be read (locked, or quarantined by antivirus - check its detection history)"
    for regex, severity in markers:
        if regex.search(text):
            return severity, f"web-shell marker {regex.pattern!r}"
    if in_upload_dir:
        return "medium", "server-side script inside an upload/media folder"
    if recent:
        return "low", f"script changed recently ({changed:%Y-%m-%d %H:%M})"
    return None


def main() -> int:
    parser = make_parser("Scan web roots for web shells and suspicious files.")
    parser.add_argument("--days", type=int, default=7, help="Scripts changed within N days are listed (default: 7)")
    parser.add_argument("roots", nargs="*", help="Web roots to scan (default: common locations)")
    args = parser.parse_args()
    report = Report("suspicious_web_root_scan", args)
    rules = load_rules("suspicious_web_root_scan", args.rules)
    rules["script_extensions"] = set(rules.get("script_extensions", []))
    rules["image_extensions"] = set(rules.get("image_extensions", []))
    markers = [(re.compile(m["pattern"], re.IGNORECASE), m["severity"]) for m in rules.get("markers", [])]
    cutoff = datetime.now() - timedelta(days=args.days)

    roots = [Path(r) for r in (args.roots or rules.get("roots", []))]
    existing = [r for r in roots if is_dir(r)]
    if not existing:
        if args.roots:
            report.fail(f"web root(s) not found: {', '.join(args.roots)}")
        else:
            report.info("summary", "no common web root on this host; pass the path(s) to scan")
        return report.emit()

    errors: list[str] = []
    scanned = 0
    for path in walk_files(existing, errors):
        scanned += 1
        hit = scan_file(path, rules, markers, cutoff)
        if hit:
            severity, reason = hit
            report.add("web roots", severity, f"{path}: {reason}", path=str(path), reason=reason)
    for error in errors[:20]:
        report.error(error)
    report.info("summary", f"scanned {scanned} file(s) under {', '.join(str(r) for r in existing)}")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
