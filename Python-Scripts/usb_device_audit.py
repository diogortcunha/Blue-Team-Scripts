#!/usr/bin/env python3

"""Inventory removable devices and USB history.

Windows: removable drives now, and every USB storage device ever connected (USBSTOR).
Linux: USB devices now (/sys), USB block devices (lsblk) and kernel USB messages
(journalctl -k, falling back to dmesg).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from btcommon import IS_WINDOWS, Report, make_parser, powershell_json, read_text, reg_query, run, run_first


def linux_sys_devices() -> list[dict[str, str]]:
    devices = []
    for dev in sorted(Path("/sys/bus/usb/devices").glob("*")):
        product = (read_text(dev / "product") or "").strip()
        if not product:
            continue
        devices.append({
            "bus": dev.name,
            "product": product,
            "manufacturer": (read_text(dev / "manufacturer") or "").strip(),
            "serial": (read_text(dev / "serial") or "").strip(),
            "id": f"{(read_text(dev / 'idVendor') or '').strip()}:{(read_text(dev / 'idProduct') or '').strip()}",
        })
    return devices


def usb_block_devices() -> list[dict]:
    result = run(["lsblk", "-J", "-o", "NAME,TRAN,SIZE,MODEL,SERIAL,MOUNTPOINT,RM"])
    if not result.ok:
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return [dev for dev in data.get("blockdevices", []) if dev.get("tran") == "usb" or str(dev.get("rm")) in {"1", "True", "true"}]


_USB_EVENT = re.compile(r"(New USB device found|Product:|Manufacturer:|SerialNumber:|USB Mass Storage|usb-storage|Attached SCSI removable)", re.IGNORECASE)


def main() -> int:
    parser = make_parser("Audit USB/removable devices.")
    parser.add_argument("--limit", type=int, default=50, help="Max kernel USB messages to show (default: 50)")
    args = parser.parse_args()
    report = Report("usb_device_audit", args, needs_admin=True)

    if IS_WINDOWS:
        drives, error = powershell_json(
            "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | Select-Object DeviceID,VolumeName,FileSystem,Size"
        )
        if error:
            report.error(error)
        for drive in drives:
            report.info("removable drives", f"{drive.get('DeviceID')} {drive.get('VolumeName') or ''} {drive.get('FileSystem') or ''}", **drive)
        history = reg_query(r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR", recursive=True)
        seen = 0
        for key, values in sorted(history.items()):
            if "FriendlyName" in values:
                seen += 1
                serial = key.rsplit("\\", 1)[-1]
                report.info("usb storage history (USBSTOR)", f"{values['FriendlyName']} serial={serial}", name=values["FriendlyName"], serial=serial, key=key)
        if not seen:
            report.info("usb storage history (USBSTOR)", "no USB storage devices recorded")
        return report.emit()

    for dev in linux_sys_devices():
        report.info("connected usb devices", f"{dev['bus']:<10} {dev['id']} {dev['manufacturer']} {dev['product']} serial={dev['serial'] or '-'}", **dev)
    for dev in usb_block_devices():
        report.info("usb block devices", f"{dev.get('name')} {dev.get('size')} {dev.get('model') or ''} mounted={dev.get('mountpoint') or '-'}", **dev)

    kernel = run_first(["journalctl", "-k", "--no-pager", "-q", "-o", "short-iso", "-b", "-5"], ["dmesg", "-T"])
    if not kernel.ok:
        report.error(f"kernel log unavailable: {kernel.stderr}")
    events = [line for line in kernel.stdout.splitlines() if _USB_EVENT.search(line)]
    for line in events[-args.limit:]:
        report.info("kernel usb events", line)
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
