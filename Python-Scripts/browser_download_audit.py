#!/usr/bin/env python3

"""Review recent browser download locations for risky files."""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta
from pathlib import Path


RISKY_EXTS = {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".hta", ".lnk", ".zip", ".rar", ".7z"}


def download_roots() -> list[Path]:
    roots = [Path.home() / "Downloads"]
    if os.name == "nt":
        roots.append(Path(os.environ.get("USERPROFILE", "")) / "Downloads")
    return [root for root in roots if root.exists()]


def scan(root: Path, days: int) -> list[str]:
    cutoff = datetime.now() - timedelta(days=days)
    findings: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
        except OSError:
            continue
        if mtime < cutoff:
            continue
        mark = "risk" if path.suffix.lower() in RISKY_EXTS else "recent"
        findings.append(f"{path} [{mark}] {mtime}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit recent downloads.")
    parser.add_argument("--days", type=int, default=7, help="Only show files modified in the last N days")
    args = parser.parse_args()

    roots = download_roots()
    if not roots:
        print("No download folders found.")
        return 1

    for root in roots:
        print(f"{root}:")
        for line in scan(root, args.days):
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
