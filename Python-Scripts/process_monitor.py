#!/usr/bin/env python3

"""Quick process snapshot and suspicious process triage."""

from __future__ import annotations

import argparse
import csv
import platform
import subprocess
from dataclasses import dataclass


SUSPICIOUS_NAMES = {
    "powershell",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "python",
    "python3",
}


@dataclass
class ProcessRow:
    pid: str
    ppid: str
    user: str
    name: str
    cpu: str
    mem: str


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip() or result.stderr.strip()


def linux_processes() -> list[ProcessRow]:
    output = run(["ps", "-eo", "pid=,ppid=,user=,comm=,%cpu=,%mem=", "--sort=-%cpu"])
    rows: list[ProcessRow] = []
    for line in output.splitlines():
        parts = line.split(None, 5)
        if len(parts) == 6:
            rows.append(ProcessRow(*parts))
    return rows


def windows_processes() -> list[ProcessRow]:
    output = run(["tasklist", "/fo", "csv", "/v"])
    rows: list[ProcessRow] = []
    for row in csv.DictReader(output.splitlines()):
        rows.append(
            ProcessRow(
                pid=row.get("PID", ""),
                ppid="",
                user=row.get("User Name", ""),
                name=row.get("Image Name", ""),
                cpu=row.get("CPU Time", ""),
                mem=row.get("Mem Usage", ""),
            )
        )
    return rows


def suspicious(row: ProcessRow) -> bool:
    name = row.name.lower()
    return any(token in name for token in SUSPICIOUS_NAMES)


def main() -> int:
    parser = argparse.ArgumentParser(description="List running processes and flag suspicious names.")
    parser.add_argument("--limit", type=int, default=25, help="Number of rows to print")
    args = parser.parse_args()

    rows = windows_processes() if platform.system() == "Windows" else linux_processes()
    print(f"Top {min(args.limit, len(rows))} processes")
    print(f"{'PID':<8} {'PPID':<8} {'USER':<18} {'CPU':<8} {'MEM':<10} NAME")
    print("-" * 80)
    for row in rows[: args.limit]:
        flag = " !" if suspicious(row) else ""
        print(f"{row.pid:<8} {row.ppid:<8} {row.user[:18]:<18} {row.cpu:<8} {row.mem:<10} {row.name}{flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
