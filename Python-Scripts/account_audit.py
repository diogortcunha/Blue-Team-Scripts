#!/usr/bin/env python3

"""Audit local accounts, admin group membership and sudo rules.

Linux: extra UID 0 accounts, accounts without a password, system accounts with a login
shell, members of sudo/wheel/admin, NOPASSWD sudo rules and writable sudoers files.
Windows: enabled Guest, accounts without a required password, Administrators members,
and accounts whose password never expires.
With --baseline, reports accounts and admin memberships that changed.
"""

from __future__ import annotations

import stat
from pathlib import Path

from btcommon import IS_WINDOWS, Report, handle_baseline, is_file, load_rules, make_parser, powershell_json, read_text


def parse_passwd(text: str) -> list[dict]:
    users = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and not line.startswith("#"):
            users.append({"name": parts[0], "password": parts[1], "uid": int(parts[2]) if parts[2].isdigit() else -1, "gid": parts[3], "home": parts[5], "shell": parts[6]})
    return users


def parse_shadow(text: str) -> dict[str, str]:
    return {parts[0]: parts[1] for parts in (line.split(":") for line in text.splitlines()) if len(parts) >= 2}


def parse_group_members(text: str, groups: set[str]) -> dict[str, list[str]]:
    members = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[0] in groups:
            members[parts[0]] = [m for m in parts[3].split(",") if m]
    return members


def sudoers_rules(text: str) -> list[str]:
    """Non-comment sudoers lines, with backslash continuations joined."""
    rules, current = [], ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or (stripped.startswith("#") and not stripped.startswith(("#include", "#includedir"))):
            continue
        current += stripped.rstrip("\\") + " "
        if not stripped.endswith("\\"):
            rules.append(" ".join(current.split()))
            current = ""
    return rules


def linux(report: Report, rules: dict, inventory: dict[str, str]) -> None:
    nologin = set(rules.get("nologin_shells", []))
    users = parse_passwd(read_text("/etc/passwd") or "")
    shadow_text = read_text("/etc/shadow")
    shadow = parse_shadow(shadow_text or "")
    if shadow_text is None:
        report.error("/etc/shadow unreadable: empty-password check skipped (run as root)")

    for user in users:
        name, uid, shell = user["name"], user["uid"], user["shell"]
        has_login = shell not in nologin
        inventory[f"user {name}"] = f"uid={uid} shell={shell}"
        if uid == 0 and name != "root":
            report.add("accounts", "high", f"{name} has UID 0 (a second root account)", user=name)
        pw = shadow.get(name, user["password"] if user["password"] not in {"x", "*"} else None)
        if pw == "" and has_login:
            report.add("accounts", "high", f"{name} has an empty password and shell {shell}", user=name)
        if 0 < uid < 1000 and has_login and name not in {"sync"}:
            report.add("accounts", "medium", f"system account {name} (uid {uid}) has a login shell {shell}", user=name, uid=uid, shell=shell)
        elif uid >= 1000 or uid == 0:
            if has_login:
                report.info("accounts", f"{name:<16} uid={uid:<6} shell={shell} home={user['home']}", user=name)

    groups = parse_group_members(read_text("/etc/group") or "", set(rules.get("admin_groups", [])))
    for group, members in sorted(groups.items()):
        for member in members:
            inventory[f"group {group}: {member}"] = ""
        report.info("admin groups", f"{group}: {', '.join(members) or '(no members)'}", group=group, members=members)

    sudo_files = [Path("/etc/sudoers")]
    try:
        sudo_files += sorted(p for p in Path("/etc/sudoers.d").iterdir() if is_file(p))
    except OSError:
        pass
    for path in sudo_files:
        try:
            st = path.stat()
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or st.st_uid != 0:
                report.add("sudoers", "high", f"{path} is writable by non-root or not owned by root", path=str(path))
        except OSError:
            continue
        text = read_text(path)
        if text is None:
            report.error(f"{path}: unreadable (run as root)")
            continue
        for rule in sudoers_rules(text):
            if rule.startswith(("Defaults", "#include", "@include", "Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias")):
                continue
            inventory[f"sudo {path}: {rule}"] = ""
            upper = rule.upper()
            if "NOPASSWD" in upper and upper.rstrip().endswith("ALL"):
                report.add("sudoers", "medium", f"{path}: passwordless full sudo: {rule}", path=str(path), rule=rule)
            elif "NOPASSWD" in upper:
                report.add("sudoers", "low", f"{path}: passwordless sudo: {rule}", path=str(path), rule=rule)
            else:
                report.info("sudoers", f"{path}: {rule}", path=str(path))


def windows(report: Report, inventory: dict[str, str]) -> None:
    users, error = powershell_json(
        "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,@{n='PasswordExpires';e={[string]$_.PasswordExpires}},"
        "@{n='LastLogon';e={[string]$_.LastLogon}},SID"
    )
    if error:
        report.error(error)
    for user in users:
        name, enabled = user.get("Name"), bool(user.get("Enabled"))
        inventory[f"user {name}"] = f"enabled={enabled}"
        sid = str(user.get("SID", {}).get("Value") if isinstance(user.get("SID"), dict) else user.get("SID") or "")
        if sid.endswith("-501") and enabled:
            report.add("accounts", "high", f"Guest account {name} is enabled", user=name)
        elif enabled and user.get("PasswordRequired") is False:
            report.add("accounts", "medium", f"{name} is enabled with PASSWD_NOTREQD set (its password may be blank; check with 'net user {name}')", user=name)
        elif enabled and not user.get("PasswordExpires"):
            report.add("accounts", "low", f"{name}: password never expires", user=name)
        elif enabled:
            report.info("accounts", f"{name} last logon {user.get('LastLogon') or 'never'}", user=name)
        if sid.endswith("-500") and enabled:
            report.add("accounts", "low", f"built-in Administrator {name} is enabled", user=name)

    admins, error = powershell_json(
        "Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name,ObjectClass,PrincipalSource"
    )
    if error:
        report.error(f"Administrators: {error}")
    for member in admins:
        inventory[f"group Administrators: {member.get('Name')}"] = ""
        report.info("admin groups", f"Administrators: {member.get('Name')} ({member.get('ObjectClass')})", member=member.get("Name"))


def main() -> int:
    parser = make_parser("Audit local accounts, admin groups and sudo rules.", baseline=True)
    args = parser.parse_args()
    report = Report("account_audit", args, needs_admin=True)
    inventory: dict[str, str] = {}
    if IS_WINDOWS:
        windows(report, inventory)
    else:
        linux(report, load_rules("account_audit", args.rules), inventory)
    handle_baseline(report, inventory, check="changes since baseline", added_severity="high", removed_severity="low")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
