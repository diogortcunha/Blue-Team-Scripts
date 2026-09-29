#!/usr/bin/env python3

"""Audit SSH authorized_keys files and the sshd configuration.

Flags forced commands and other risky key options, weak key types (DSA, short RSA),
authorized_keys files writable by others, and insecure sshd settings. With --baseline,
reports keys that were added or removed since the baseline.
"""

from __future__ import annotations

import base64
import os
import stat
import struct
from pathlib import Path

from btcommon import IS_WINDOWS, Report, handle_baseline, home_dirs, is_file, load_rules, make_parser, read_text

KEY_TYPES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
)


def split_options(line: str) -> tuple[str, list[str]]:
    """Split an authorized_keys line into (options, [type, blob, comment...]) honouring quotes."""
    tokens = line.split()
    if tokens and tokens[0] in KEY_TYPES:
        return "", tokens
    in_quotes = False
    for index, char in enumerate(line):
        if char == '"':
            in_quotes = not in_quotes
        elif char in " \t" and not in_quotes:
            return line[:index], line[index:].split()
    return line, []


def rsa_bits(blob_b64: str) -> int | None:
    try:
        blob = base64.b64decode(blob_b64)
        fields = []
        offset = 0
        for _ in range(3):
            (length,) = struct.unpack(">I", blob[offset:offset + 4])
            fields.append(blob[offset + 4:offset + 4 + length])
            offset += 4 + length
    except (ValueError, struct.error):
        return None
    modulus = fields[2].lstrip(b"\x00")
    return len(modulus) * 8 if modulus else None


def parse_authorized_keys(text: str) -> list[dict]:
    keys = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        options, rest = split_options(line)
        if len(rest) < 2 or rest[0] not in KEY_TYPES:
            keys.append({"line": number, "invalid": True, "raw": line[:120]})
            continue
        keys.append({
            "line": number,
            "options": options,
            "type": rest[0],
            "blob": rest[1],
            "comment": " ".join(rest[2:]),
            "bits": rsa_bits(rest[1]) if rest[0] == "ssh-rsa" else None,
        })
    return keys


def key_files() -> list[Path]:
    files = []
    for home in home_dirs():
        for name in ("authorized_keys", "authorized_keys2"):
            files.append(home / ".ssh" / name)
    if IS_WINDOWS:
        files.append(Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ssh" / "administrators_authorized_keys")
    return [f for f in files if is_file(f)]


def sshd_config_paths() -> list[Path]:
    base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ssh" if IS_WINDOWS else Path("/etc/ssh")
    paths = [base / "sshd_config"]
    try:
        paths += sorted((base / "sshd_config.d").glob("*.conf"))
    except OSError:
        pass
    return [p for p in paths if is_file(p)]


SSHD_CHECKS = [
    ("permitemptypasswords", {"yes"}, "high", "empty passwords are allowed"),
    ("permitrootlogin", {"yes"}, "medium", "root can log in with a password"),
    ("passwordauthentication", {"yes"}, "low", "password authentication is enabled (brute-forceable)"),
    ("pubkeyacceptedkeytypes", {"+ssh-dss", "ssh-dss"}, "medium", "DSA keys are accepted"),
    ("pubkeyacceptedalgorithms", {"+ssh-dss", "ssh-dss"}, "medium", "DSA keys are accepted"),
    ("x11forwarding", {"yes"}, "low", "X11 forwarding is enabled"),
    ("permittunnel", {"yes"}, "low", "tunnel devices are allowed"),
    ("gatewayports", {"yes"}, "low", "remote port forwards can bind to all interfaces"),
]


def sshd_settings(paths: list[Path]) -> dict[str, tuple[str, str]]:
    """First value wins, as in sshd; Match blocks are ignored."""
    settings: dict[str, tuple[str, str]] = {}
    for path in paths:
        in_match = False
        for line in (read_text(path) or "").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            key, _, value = line.partition(" ")
            if key.lower() == "match":
                in_match = True
            if in_match:
                continue
            settings.setdefault(key.lower(), (value.strip(), str(path)))
    return settings


def main() -> int:
    parser = make_parser("Audit SSH authorized keys and sshd configuration.", baseline=True)
    args = parser.parse_args()
    report = Report("ssh_key_audit", args, needs_admin=True)
    rules = load_rules("ssh_key_audit", args.rules)
    min_bits = int(rules.get("min_rsa_bits", 2048))
    risky = [o.lower() for o in rules.get("risky_options", [])]

    inventory: dict[str, str] = {}
    for path in key_files():
        try:
            st = path.stat()
        except OSError as exc:
            report.error(f"{path}: {exc}")
            continue
        if not IS_WINDOWS and st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            report.add("file permissions", "high", f"{path} is writable by group/others (mode {oct(stat.S_IMODE(st.st_mode))})", path=str(path))
        text = read_text(path)
        if text is None:
            report.error(f"{path}: unreadable")
            continue
        for key in parse_authorized_keys(text):
            where = f"{path}:{key['line']}"
            if key.get("invalid"):
                report.add("authorized keys", "low", f"{where}: unparseable entry {key['raw']!r}", path=str(path))
                continue
            label = f"{key['type']} {key['comment'] or '(no comment)'}"
            inventory[f"{path}: {key['type']} {key['blob'][-24:]} {key['comment']}".strip()] = key["options"]
            opts = key["options"].lower()
            hit = next((o for o in risky if o in opts), None)
            if hit:
                report.add("authorized keys", "high" if hit == "command=" else "medium", f"{where}: {label} has option {key['options']!r}", path=str(path), options=key["options"])
            elif key["type"] == "ssh-dss":
                report.add("authorized keys", "medium", f"{where}: {label} is a DSA key (deprecated, weak)", path=str(path))
            elif key["bits"] and key["bits"] < min_bits:
                report.add("authorized keys", "medium", f"{where}: {label} is only {key['bits']}-bit RSA", path=str(path), bits=key["bits"])
            else:
                bits = f" {key['bits']}-bit" if key["bits"] else ""
                report.info("authorized keys", f"{where}: {label}{bits}{' options=' + key['options'] if key['options'] else ''}", path=str(path))

    configs = sshd_config_paths()
    settings = sshd_settings(configs)
    for name, bad, severity, reason in SSHD_CHECKS:
        if name in settings and settings[name][0].lower() in bad:
            value, source = settings[name]
            report.add("sshd_config", severity, f"{name} {value} in {source}: {reason}", setting=name, value=value, file=source)
    akf = settings.get("authorizedkeysfile")
    if akf and not all(p in {".ssh/authorized_keys", ".ssh/authorized_keys2", "%h/.ssh/authorized_keys"} for p in akf[0].split()):
        report.add("sshd_config", "medium", f"AuthorizedKeysFile is non-standard: {akf[0]} ({akf[1]})", value=akf[0])
    if settings.get("authorizedkeyscommand"):
        report.add("sshd_config", "medium", f"AuthorizedKeysCommand runs {settings['authorizedkeyscommand'][0]}", value=settings["authorizedkeyscommand"][0])
    if not configs:
        report.info("sshd_config", "no sshd_config found (OpenSSH server not installed?)")

    handle_baseline(report, inventory, check="key changes since baseline", removed_severity="info")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
