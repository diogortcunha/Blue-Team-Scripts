#!/usr/bin/env python3

"""Create or compare SHA-256 hashes for files and directories."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def iter_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for value in paths:
        path = Path(value)
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


def build_snapshot(paths: list[str]) -> dict[str, str]:
    return {str(path): sha256(path) for path in iter_files(paths)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Hash files for integrity checks.")
    parser.add_argument("paths", nargs="+", help="Files or directories to hash")
    parser.add_argument("--baseline", help="Baseline JSON file to compare against")
    parser.add_argument("--write-baseline", help="Write snapshot to this JSON file")
    args = parser.parse_args()

    snapshot = build_snapshot(args.paths)

    if args.write_baseline:
        Path(args.write_baseline).write_text(json.dumps(snapshot, indent=2, sort_keys=True))
        print(f"Wrote {len(snapshot)} hashes to {args.write_baseline}")

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text())
        for path, digest in sorted(snapshot.items()):
            if baseline.get(path) != digest:
                print(f"CHANGED {path}")
        for path in sorted(set(baseline) - set(snapshot)):
            print(f"MISSING {path}")
    else:
        for path, digest in sorted(snapshot.items()):
            print(f"{digest}  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
