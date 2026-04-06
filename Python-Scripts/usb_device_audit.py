#!/usr/bin/env python3

"""Inspect removable media activity and device inventory."""

from __future__ import annotations

import argparse
import platform
import subprocess


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit USB/removable devices.")
    args = parser.parse_args()
    _ = args

    if platform.system() == "Windows":
        print(run(["wmic", "logicaldisk", "get", "Caption,DriveType,FileSystem,VolumeName"]))
    else:
        print(run(["lsblk", "-o", "NAME,TRAN,SIZE,MODEL,MOUNTPOINT"]))
        print("\nRecent kernel USB messages:")
        messages = run(["dmesg"]).splitlines()
        for line in messages:
            if "usb" in line.lower():
                print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
