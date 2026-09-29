#!/usr/bin/env python3

"""Audit advanced Windows persistence: WMI event subscriptions, IFEO, Winlogon, AppInit,
LSA packages and netsh helpers. Windows only; run as Administrator.
"""

from __future__ import annotations

from btcommon import Report, handle_baseline, load_rules, make_parser, powershell_json, reg_query

IFEO = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
SILENT_EXIT = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
WINLOGON = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
APPINIT_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
]
LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
NETSH = r"HKLM\SOFTWARE\Microsoft\NetSh"

EXPECTED_WINLOGON = {
    "Shell": {"explorer.exe"},
    "Userinit": {r"c:\windows\system32\userinit.exe,", r"c:\windows\system32\userinit.exe"},
}


def multi_values(data: str) -> list[str]:
    """Split REG_MULTI_SZ data as printed by reg query (``a\\0b\\0``)."""
    return [v.strip().lower() for v in data.replace("\\0", "\n").splitlines() if v.strip()]


def check_wmi(report: Report, inventory: dict[str, str], benign: set[str]) -> None:
    consumers, error = powershell_json(
        "Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | "
        "Select-Object Name,@{n='Class';e={$_.CimClass.CimClassName}},CommandLineTemplate,ExecutablePath,ScriptText,ScriptFileName"
    )
    if error:
        report.error(f"WMI consumers: {error}")
    for consumer in consumers:
        name, cls = consumer.get("Name") or "?", consumer.get("Class") or "?"
        action = consumer.get("CommandLineTemplate") or consumer.get("ExecutablePath") or consumer.get("ScriptFileName") or (consumer.get("ScriptText") or "")[:200]
        inventory[f"wmi consumer {cls}:{name}"] = action or ""
        if name in benign:
            report.info("wmi subscriptions", f"{cls} {name} (known benign)")
        elif cls in {"CommandLineEventConsumer", "ActiveScriptEventConsumer"}:
            report.add("wmi subscriptions", "high", f"{cls} {name!r} runs: {action}", consumer=name, cls=cls, action=action)
        else:
            report.add("wmi subscriptions", "low", f"{cls} {name!r}", consumer=name, cls=cls)

    filters, _ = powershell_json("Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object Name,Query")
    for flt in filters:
        inventory[f"wmi filter {flt.get('Name')}"] = flt.get("Query") or ""
        report.info("wmi subscriptions", f"filter {flt.get('Name')}: {flt.get('Query')}")


def check_ifeo(report: Report, inventory: dict[str, str]) -> None:
    for key, values in reg_query(IFEO, recursive=True).items():
        image = key.rsplit("\\", 1)[-1]
        if values.get("Debugger"):
            inventory[f"ifeo debugger {image}"] = values["Debugger"]
            report.add("ifeo", "high", f"{image} is hijacked by Debugger={values['Debugger']}", image=image, debugger=values["Debugger"])
        if values.get("GlobalFlag", "").lower() in {"0x200", "512"}:
            inventory[f"ifeo silentexit {image}"] = values["GlobalFlag"]
    for key, values in reg_query(SILENT_EXIT, recursive=True).items():
        if values.get("MonitorProcess"):
            image = key.rsplit("\\", 1)[-1]
            inventory[f"silent process exit {image}"] = values["MonitorProcess"]
            report.add("ifeo", "high", f"exit of {image} launches {values['MonitorProcess']} (SilentProcessExit)", image=image, monitor=values["MonitorProcess"])


def check_winlogon(report: Report, inventory: dict[str, str]) -> None:
    values = reg_query(WINLOGON).get(WINLOGON.replace("HKLM", "HKEY_LOCAL_MACHINE"), {})
    for name, expected in EXPECTED_WINLOGON.items():
        value = values.get(name, "")
        inventory[f"winlogon {name}"] = value
        if value and value.strip().lower() not in expected:
            report.add("winlogon", "high", f"Winlogon {name} = {value} (expected {sorted(expected)[0]})", value=value)
    for key in APPINIT_KEYS:
        for _, vals in reg_query(key).items():
            dlls = vals.get("AppInit_DLLs", "").strip()
            inventory[f"appinit {key}"] = dlls
            if dlls and vals.get("LoadAppInit_DLLs", "0x0") not in {"0x0", "0"}:
                report.add("appinit", "high", f"AppInit_DLLs loads {dlls} into every GUI process ({key})", dlls=dlls)
            elif dlls:
                report.add("appinit", "low", f"AppInit_DLLs set but disabled: {dlls} ({key})", dlls=dlls)


def check_lsa(report: Report, inventory: dict[str, str], rules: dict) -> None:
    values = next(iter(reg_query(LSA).values()), {})
    for value_name, allowed_key in (("Security Packages", "default_security_packages"), ("Authentication Packages", "default_authentication_packages"), ("Notification Packages", None)):
        packages = multi_values(values.get(value_name, ""))
        inventory[f"lsa {value_name}"] = ",".join(packages)
        allowed = set(rules.get(allowed_key, [])) if allowed_key else {"scecli", "rassfm", "fpnwclnt"}
        for pkg in packages:
            if pkg not in allowed:
                report.add("lsa", "high", f"LSA {value_name} contains unexpected package {pkg!r} (possible credential theft DLL)", package=pkg)


def check_netsh(report: Report, inventory: dict[str, str]) -> None:
    for _, values in reg_query(NETSH).items():
        for name, dll in values.items():
            inventory[f"netsh helper {name}"] = dll
            if "\\" in dll and not dll.lower().startswith(("c:\\windows\\system32", "%systemroot%")):
                report.add("netsh", "high", f"netsh helper DLL outside System32: {dll}", dll=dll)


def main() -> int:
    parser = make_parser("Audit WMI, IFEO, Winlogon, AppInit, LSA and netsh persistence.", baseline=True)
    args = parser.parse_args()
    report = Report("wmi_persistence_audit", args, needs_admin=True)
    if not report.require("Windows"):
        return report.emit()
    rules = load_rules("wmi_persistence_audit", args.rules)
    inventory: dict[str, str] = {}
    check_wmi(report, inventory, set(rules.get("benign_consumers", [])))
    check_ifeo(report, inventory)
    check_winlogon(report, inventory)
    check_lsa(report, inventory, rules)
    check_netsh(report, inventory)
    report.info("summary", f"{len(inventory)} persistence entries collected")
    handle_baseline(report, inventory, check="changes since baseline", added_severity="high")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
