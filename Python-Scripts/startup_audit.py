#!/usr/bin/env python3

"""Audit common persistence and startup locations."""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
from pathlib import Path


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def windows_report() -> list[str]:
    items = []
    items.append("Registry Run keys:")
    items.append(run(["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"]))
    items.append(run(["reg", "query", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"]))
    items.append("Startup folders:")
    for folder in [Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup", Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"]:
        if folder.exists():
            items.append(str(folder))
            items.extend(str(p) for p in folder.iterdir())
    return items


def linux_report() -> list[str]:
    items = ["User crontab:", run(["crontab", "-l"])]
    for path in [Path("/etc/crontab"), Path("/etc/cron.d")]:
        if path.exists():
            items.append(str(path))
            if path.is_dir():
                items.extend(str(p) for p in path.iterdir())
            else:
                items.append(path.read_text(errors="ignore"))
    for path in [Path("/etc/rc.local"), Path.home() / ".bashrc", Path.home() / ".profile"]:
        if path.exists():
            items.append(str(path))
            items.append(path.read_text(errors="ignore"))
    items.append("Enabled services:")
    items.append(run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager"]))
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect common persistence locations.")
    args = parser.parse_args()
    _ = args

    report = windows_report() if platform.system() == "Windows" else linux_report()
    for item in report:
        if item:
            print(item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
