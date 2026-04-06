#!/usr/bin/env python3

"""Triage authentication and security-related log entries."""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
from collections import Counter
from pathlib import Path


PATTERNS = [
    "failed password",
    "invalid user",
    "authentication failure",
    "sudo:",
    "new user",
    "useradd",
    "adduser",
    "logon failure",
    "event id 4625",
    "event id 4720",
    "event id 4722",
]


def read_linux_logs() -> list[str]:
    candidates = [Path("/var/log/auth.log"), Path("/var/log/secure")]
    for path in candidates:
        if path.exists():
            return path.read_text(errors="ignore").splitlines()
    return []


def read_windows_logs() -> list[str]:
    cmd = ["wevtutil", "qe", "Security", "/f:text", "/c:200"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return (result.stdout or result.stderr).splitlines()


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize suspicious log activity.")
    parser.add_argument("--limit", type=int, default=50, help="Max matching lines to print")
    args = parser.parse_args()

    lines = read_windows_logs() if platform.system() == "Windows" else read_linux_logs()
    if not lines:
        print("No readable log source found.")
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
