#!/usr/bin/env python3

"""Find SUID/SGID binaries and file capabilities that allow privilege escalation.

GTFOBins binaries with SUID, SUID files in user-writable locations and interpreters with
dangerous capabilities are flagged. With --baseline, new SUID files are reported.
Linux/BSD only; run as root for complete results.
"""

from __future__ import annotations

import os
import re
import stat

from btcommon import IS_WINDOWS, SKIP_WALK_DIRS, Report, handle_baseline, load_rules, make_parser, run, walk_files

_GETCAP = re.compile(r"^(\S+)\s*(?:=\s*)?(.+)$")


def parse_getcap(output: str) -> list[tuple[str, str]]:
    """Parse ``getcap -r`` output: ``/path cap_x=ep`` (new) or ``/path = cap_x+ep`` (old)."""
    entries = []
    for line in output.splitlines():
        match = _GETCAP.match(line.strip())
        if match and match.group(1).startswith("/"):
            entries.append((match.group(1), match.group(2).strip()))
    return entries


CAP_NAMES = [
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid",
    "cap_setuid", "cap_setpcap", "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast", "cap_net_admin",
    "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner", "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot",
    "cap_sys_ptrace", "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice", "cap_sys_resource",
    "cap_sys_time", "cap_sys_tty_config", "cap_mknod", "cap_lease", "cap_audit_write", "cap_audit_control",
    "cap_setfcap", "cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm", "cap_block_suspend",
    "cap_audit_read", "cap_perfmon", "cap_bpf", "cap_checkpoint_restore",
]


def _cap_list(mask: int) -> str:
    return ",".join(CAP_NAMES[i] if i < len(CAP_NAMES) else f"cap_{i}" for i in range(64) if mask >> i & 1)


def decode_capabilities(raw: bytes) -> str | None:
    """Decode a ``security.capability`` xattr (vfs_cap_data v1-v3) in getcap-like notation."""
    import struct

    if len(raw) < 12:
        return None
    (magic,) = struct.unpack_from("<I", raw, 0)
    version, effective = magic & 0xFF000000, magic & 1
    words = 1 if version == 0x01000000 else 2
    if len(raw) < 4 + 8 * words:
        return None
    permitted = inheritable = 0
    for word in range(words):
        perm, inh = struct.unpack_from("<II", raw, 4 + 8 * word)
        permitted |= perm << (32 * word)
        inheritable |= inh << (32 * word)
    parts = []
    if permitted:
        parts.append(f"{_cap_list(permitted)}={'e' if effective else ''}p")
    if inheritable:
        parts.append(f"{_cap_list(inheritable)}=i")
    return " ".join(parts) or None


def file_capabilities(path: str) -> str | None:
    try:
        raw = os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError:
        return None
    return decode_capabilities(raw)


def base_name(path: str) -> str:
    name = os.path.basename(path)
    return re.sub(r"\d+(\.\d+)*$", "", name) or name  # python3.11 -> python


def main() -> int:
    parser = make_parser("Audit SUID/SGID binaries and file capabilities.", baseline=True)
    parser.add_argument("roots", nargs="*", default=["/"], help="Directories to scan (default: /)")
    parser.add_argument("--cross-filesystems", action="store_true", help="Descend into other mounted filesystems")
    args = parser.parse_args()
    report = Report("suid_audit", args, needs_admin=True)
    if IS_WINDOWS:
        report.fail("suid_audit is for Linux/BSD")
        return report.emit()
    rules = load_rules("suid_audit", args.rules)
    gtfobins = set(rules.get("gtfobins", []))
    risky_dirs = tuple(d.rstrip("/") + "/" for d in rules.get("suspicious_dirs", []))
    dangerous_caps = rules.get("dangerous_capabilities", [])

    inventory: dict[str, str] = {}
    errors: list[str] = []
    capabilities: list[tuple[str, str]] = []
    read_xattrs = hasattr(os, "getxattr")
    for path in walk_files(args.roots, errors, same_device=not args.cross_filesystems, skip_dirs=SKIP_WALK_DIRS):
        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if read_xattrs:
            capset = file_capabilities(str(path))
            if capset:
                capabilities.append((str(path), capset))
        if not st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            continue
        kind = "SUID" if st.st_mode & stat.S_ISUID else "SGID"
        if st.st_mode & stat.S_ISUID and st.st_mode & stat.S_ISGID:
            kind = "SUID+SGID"
        owner = st.st_uid
        text = str(path)
        inventory[text] = f"{kind} uid={owner} mode={oct(stat.S_IMODE(st.st_mode))}"
        data = {"path": text, "kind": kind, "uid": owner, "mode": oct(stat.S_IMODE(st.st_mode))}
        name = base_name(text)
        if text.startswith(risky_dirs):
            report.add("suid/sgid", "high", f"{kind} file in a user-writable location: {text} (uid {owner})", **data)
        elif "SUID" in kind and owner == 0 and name in gtfobins:
            report.add("suid/sgid", "high", f"{kind} root {text}: GTFOBins binary, gives a root shell/file access", **data)
        elif st.st_mode & stat.S_IWOTH:
            report.add("suid/sgid", "high", f"{kind} {text} is world-writable", **data)
        else:
            report.info("suid/sgid", f"{kind:<9} {oct(stat.S_IMODE(st.st_mode))} uid={owner:<5} {text}", **data)

    if not read_xattrs:  # BSD and others: fall back to getcap, which walks the tree again
        caps = run(["getcap", "-r", *args.roots], timeout=600)
        if caps.returncode is None:
            report.error("getcap not found - file capabilities not checked")
        capabilities = parse_getcap(caps.stdout)
    for path, capset in capabilities:
        inventory[f"cap {path}"] = capset
        hits = [c for c in dangerous_caps if c in capset.lower()]
        name = base_name(path)
        if hits and (name in gtfobins or path.startswith(risky_dirs)):
            report.add("capabilities", "high", f"{path} has {capset} (escalation via {name})", path=path, capabilities=capset)
        elif hits:
            report.add("capabilities", "low", f"{path} has {capset}", path=path, capabilities=capset)
        else:
            report.info("capabilities", f"{path} {capset}", path=path, capabilities=capset)

    for error in errors[:10]:
        report.error(error)
    if len(errors) > 10:
        report.error(f"... {len(errors) - 10} more unreadable paths")
    handle_baseline(report, inventory, check="changes since baseline", added_severity="high", removed_severity="info")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
