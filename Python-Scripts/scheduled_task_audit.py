#!/usr/bin/env python3

"""List scheduled tasks and cron jobs for persistence review."""

from __future__ import annotations

import argparse
import platform
import subprocess
from pathlib import Path


SUSPICIOUS_HINTS = ("curl", "wget", "bash -c", "sh -c", "python -c", "powershell", "cmd /c", "nc ")


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def windows_tasks() -> list[str]:
    return run(["schtasks", "/query", "/fo", "LIST", "/v"]).splitlines()


def linux_tasks() -> list[str]:
    lines = ["User crontab:", run(["crontab", "-l"])]
    for path in [Path("/etc/crontab"), Path("/etc/cron.d")]:
        if path.exists():
            lines.append(str(path))
            if path.is_dir():
                for item in path.iterdir():
                    lines.append(item.read_text(errors="ignore"))
            else:
                lines.append(path.read_text(errors="ignore"))
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit scheduled tasks and cron entries.")
    args = parser.parse_args()
    _ = args

    lines = windows_tasks() if platform.system() == "Windows" else linux_tasks()
    for line in lines:
        lowered = line.lower()
        mark = " [suspicious]" if any(hint in lowered for hint in SUSPICIOUS_HINTS) else ""
        print(f"{line}{mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
