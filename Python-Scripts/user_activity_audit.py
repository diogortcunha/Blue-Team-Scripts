#!/usr/bin/env python3

"""Summarize recent user and authentication activity."""

from __future__ import annotations

import argparse
import platform
import subprocess
from collections import Counter
from pathlib import Path


PATTERNS = (
    "failed password",
    "authentication failure",
    "session opened for user",
    "session closed for user",
    "sudo:",
    "new user",
    "useradd",
    "adduser",
    "event id 4624",
    "event id 4625",
    "event id 4672",
    "event id 4720",
    "event id 4722",
    "event id 4726",
)


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def linux_lines() -> list[str]:
    for path in (Path("/var/log/auth.log"), Path("/var/log/secure")):
        if path.exists():
            return path.read_text(errors="ignore").splitlines()
    output = run(["last", "-n", "20"])
    return output.splitlines() if output else []


def windows_lines() -> list[str]:
    output = run(["wevtutil", "qe", "Security", "/f:text", "/c:300"])
    return output.splitlines()


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit recent user activity.")
    parser.add_argument("--limit", type=int, default=40, help="Max matching lines to print")
    args = parser.parse_args()

    lines = windows_lines() if platform.system() == "Windows" else linux_lines()
    if not lines:
        print("No activity data found.")
        return 1

    matches = []
    counts = Counter()
    for line in lines:
        lowered = line.lower()
        for pattern in PATTERNS:
            if pattern in lowered:
                matches.append(line)
                counts[pattern] += 1
                break

    print(f"Matched lines: {len(matches)}")
    for pattern, count in counts.most_common():
        print(f"{pattern}: {count}")
    print("\nSamples:")
    for line in matches[: args.limit]:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
