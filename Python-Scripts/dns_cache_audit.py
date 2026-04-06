#!/usr/bin/env python3

"""Inspect local DNS cache or resolver state."""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def windows_report() -> str:
    return run(["ipconfig", "/displaydns"])


def linux_report() -> str:
    parts = []
    for cmd in (["resolvectl", "statistics"], ["systemd-resolve", "--statistics"], ["nscd", "-g"]):
        if shutil.which(cmd[0]):
            parts.append(f"$ {' '.join(cmd)}")
            parts.append(run(cmd))
    try:
        parts.append("/etc/resolv.conf:")
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as handle:
            parts.append(handle.read().strip())
    except OSError:
        pass
    return "\n".join(part for part in parts if part)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit DNS cache and resolver state.")
    args = parser.parse_args()
    _ = args

    report = windows_report() if platform.system() == "Windows" else linux_report()
    print(report or "No DNS cache data available on this system.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
