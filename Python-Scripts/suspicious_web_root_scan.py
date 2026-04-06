#!/usr/bin/env python3

"""Scan common web roots for recent or suspicious files."""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta
from pathlib import Path


DEFAULT_ROOTS = [
    Path("/var/www/html"),
    Path("/srv/www"),
    Path("C:/inetpub/wwwroot"),
    Path("C:/xampp/htdocs"),
]

SUSPICIOUS_MARKERS = ("eval(", "base64_decode", "system(", "shell_exec", "passthru", "cmd.exe", "powershell", "exec(")
SUSPICIOUS_EXTS = {".php", ".phtml", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".py"}


def scan(root: Path, days: int) -> list[str]:
    findings: list[str] = []
    cutoff = datetime.now() - timedelta(days=days)
    if not root.exists():
        return findings
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
            if mtime < cutoff:
                continue
            if path.suffix.lower() in SUSPICIOUS_EXTS:
                text = path.read_text(errors="ignore").lower()
                if any(marker in text for marker in SUSPICIOUS_MARKERS):
                    findings.append(f"{path} [suspicious content]")
                else:
                    findings.append(f"{path} [recent script]")
            else:
                findings.append(f"{path} [recent file]")
        except OSError:
            continue
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan web roots for suspicious files.")
    parser.add_argument("--days", type=int, default=7, help="Only show files modified in the last N days")
    parser.add_argument("roots", nargs="*", help="Custom web roots to scan")
    args = parser.parse_args()

    roots = [Path(root) for root in args.roots] if args.roots else DEFAULT_ROOTS
    for root in roots:
        for finding in scan(root, args.days):
            print(finding)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
