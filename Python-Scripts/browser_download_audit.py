#!/usr/bin/env python3

"""Review recent downloads for risky files.

Flags risky extensions, double extensions (``invoice.pdf.exe``) and reports the source
URL when the browser recorded it: the Mark-of-the-Web ``Zone.Identifier`` stream on
Windows, or the ``user.xdg.origin.url`` extended attribute on Linux.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

from btcommon import IS_WINDOWS, Report, dedupe_paths, file_mtime, home_dirs, is_dir, load_rules, make_parser, read_text, walk_files


def download_roots(all_users: bool) -> list[Path]:
    homes = home_dirs() if all_users else [Path.home()]
    return [root for root in dedupe_paths(home / "Downloads" for home in homes) if is_dir(root)]


def double_extension(name: str, decoys: set[str], executables: set[str]) -> bool:
    parts = name.lower().rsplit(".", 2)
    return len(parts) == 3 and f".{parts[1]}" in decoys and f".{parts[2]}" in executables


def origin(path: Path) -> dict[str, str]:
    """Download source recorded by the browser, if any."""
    if IS_WINDOWS:
        text = read_text(f"{path}:Zone.Identifier") or ""
        info = {}
        for line in text.splitlines():
            key, _, value = line.partition("=")
            if key in {"ZoneId", "HostUrl", "ReferrerUrl"}:
                info[key] = value.strip()
        return info
    if hasattr(os, "getxattr"):
        for attr in ("user.xdg.origin.url", "user.xdg.referrer.url"):
            try:
                return {"HostUrl": os.getxattr(path, attr).decode(errors="replace")}
            except OSError:
                continue
    return {}


def main() -> int:
    parser = make_parser("Audit recent downloads.")
    parser.add_argument("--days", type=int, default=7, help="Only show files changed in the last N days (default: 7)")
    parser.add_argument("--all-users", action="store_true", help="Scan every user's Downloads folder (needs admin/root)")
    parser.add_argument("--risky-only", action="store_true", help="Hide recent files that are not risky")
    args = parser.parse_args()
    report = Report("browser_download_audit", args, needs_admin=args.all_users)
    rules = load_rules("browser_download_audit", args.rules)
    risky = set(rules.get("risky_extensions", []))
    decoys = set(rules.get("decoy_extensions", []))
    executables = set(rules.get("executable_extensions", []))
    cutoff = datetime.now() - timedelta(days=args.days)

    roots = download_roots(args.all_users)
    if not roots:
        report.info("downloads", "no Downloads folder found")
        return report.emit()

    errors: list[str] = []
    for path in walk_files(roots, errors):
        changed = file_mtime(path)
        if changed is None or changed < cutoff:
            continue
        src = origin(path)
        source = f" from {src['HostUrl']}" if src.get("HostUrl") else ""
        data = {"path": str(path), "modified": changed.isoformat(timespec="seconds"), **src}
        if double_extension(path.name, decoys, executables):
            report.add("downloads", "high", f"{path}: double extension disguises an executable{source}", **data)
        elif path.suffix.lower() in risky:
            report.add("downloads", "medium", f"{path}: risky file type {path.suffix.lower()}{source}", **data)
        elif not args.risky_only:
            report.info("downloads", f"{path} ({changed:%Y-%m-%d %H:%M}){source}", **data)
    for error in errors[:20]:
        report.error(error)
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
