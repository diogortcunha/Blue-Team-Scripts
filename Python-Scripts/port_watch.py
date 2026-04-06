#!/usr/bin/env python3

"""Show listening ports and active connections."""

from __future__ import annotations

import argparse
import platform
import subprocess


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect ports and connections.")
    args = parser.parse_args()
    _ = args

    if platform.system() == "Windows":
        output = run(["netstat", "-ano"])
    else:
        output = run(["ss", "-tulpen"])
        if output.startswith("[Errno") or "not found" in output.lower():
            output = run(["netstat", "-tulpen"])

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
