#!/usr/bin/env python3

"""Continuously watch files for hash changes."""

from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path


def iter_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(p for p in path.rglob("*") if p.is_file())
    return sorted(set(files))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot(paths: list[str]) -> dict[str, str]:
    data: dict[str, str] = {}
    for path in iter_files(paths):
        try:
            data[str(path)] = sha256(path)
        except OSError:
            continue
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch files for content changes.")
    parser.add_argument("paths", nargs="+", help="Files or directories to watch")
    parser.add_argument("--interval", type=int, default=30, help="Polling interval in seconds")
    parser.add_argument("--once", action="store_true", help="Run a single check and exit")
    args = parser.parse_args()

    previous = snapshot(args.paths)
    if args.once:
        for path, digest in sorted(previous.items()):
            print(f"{digest}  {path}")
        return 0

    print(f"Watching {len(previous)} files every {args.interval}s. Ctrl-C to stop.")
    try:
        while True:
            time.sleep(args.interval)
            current = snapshot(args.paths)
            for path, digest in sorted(current.items()):
                if previous.get(path) != digest:
                    print(f"CHANGED {path}")
            for path in sorted(set(previous) - set(current)):
                print(f"MISSING {path}")
            previous = current
    except KeyboardInterrupt:
        print("Stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
