#!/usr/bin/env python3

"""Summarize outbound connections and flag repeated destinations."""

from __future__ import annotations

import argparse
import platform
import re
import subprocess
from collections import Counter


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def connections_windows() -> list[str]:
    return run(["netstat", "-ano"]).splitlines()


def connections_linux() -> list[str]:
    output = run(["ss", "-H", "-tun"])
    if output.startswith("[Errno") or "not found" in output.lower():
        output = run(["netstat", "-tun"])
    return output.splitlines()


def extract_remote(line: str) -> str | None:
    tokens = line.split()
    if not tokens:
        return None
    if tokens[0].upper() in {"TCP", "UDP"} and len(tokens) >= 4:
        remote = tokens[2] if tokens[0].upper() == "TCP" else tokens[1]
        if remote not in {"*", "0.0.0.0:*", "[::]:*"}:
            return remote
    if tokens[0].upper() in {"ESTAB", "SYN-SENT", "SYN-RECV", "TIME-WAIT"} and len(tokens) >= 5:
        return tokens[4]
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\]):\d+\b", line)
    if match:
        return match.group(1)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch for repeated outbound network destinations.")
    parser.add_argument("--limit", type=int, default=25, help="Max destinations to show")
    args = parser.parse_args()

    lines = connections_windows() if platform.system() == "Windows" else connections_linux()
    remotes = [remote for line in lines if (remote := extract_remote(line))]
    counts = Counter(remotes)

    print("Top remote destinations:")
    for remote, count in counts.most_common(args.limit):
        mark = " suspicious" if count >= 5 else ""
        print(f"{remote}: {count}{mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
