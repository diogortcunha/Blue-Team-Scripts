#!/usr/bin/env python3

"""Snapshot and diff scheduled jobs and cron entries."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
from pathlib import Path


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def linux_snapshot() -> list[str]:
    items: list[str] = []
    cron = run(["crontab", "-l"])
    if cron:
        items.extend(f"crontab:{line}" for line in cron.splitlines())
    for path in (Path("/etc/crontab"), Path("/etc/cron.d")):
        if path.exists():
            if path.is_dir():
                for child in sorted(path.iterdir()):
                    text = child.read_text(errors="ignore")
                    items.extend(f"{child}:{line}" for line in text.splitlines())
            else:
                text = path.read_text(errors="ignore")
                items.extend(f"{path}:{line}" for line in text.splitlines())
    systemd = run(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"])
    if systemd:
        items.extend(f"timer:{line}" for line in systemd.splitlines())
    return sorted(set(items))


def windows_snapshot() -> list[str]:
    text = run(["schtasks", "/query", "/fo", "CSV", "/v"])
    return sorted(set(text.splitlines())) if text else []


def load_json(path: str) -> list[str]:
    return json.loads(Path(path).read_text())


def save_json(path: str, data: list[str]) -> None:
    Path(path).write_text(json.dumps(data, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description="Diff scheduled tasks against a baseline.")
    parser.add_argument("--baseline", help="Baseline JSON file")
    parser.add_argument("--write-baseline", help="Write current snapshot to JSON")
    args = parser.parse_args()

    snapshot = windows_snapshot() if platform.system() == "Windows" else linux_snapshot()

    if args.write_baseline:
        save_json(args.write_baseline, snapshot)
        print(f"Wrote {len(snapshot)} entries to {args.write_baseline}")

    if args.baseline:
        baseline = set(load_json(args.baseline))
        current = set(snapshot)
        for item in sorted(current - baseline):
            print(f"ADDED {item}")
        for item in sorted(baseline - current):
            print(f"REMOVED {item}")
    else:
        for item in snapshot:
            print(item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
