#!/usr/bin/env python3

"""Check PowerShell logging configuration and hunt suspicious script blocks. Windows only.

- ScriptBlock logging, module logging and transcription policies
- PowerShell v2 engine (bypasses logging and AMSI)
- Event 4104 script blocks matching obfuscation/offensive patterns, and blocks that
  PowerShell itself logged as Warning (its own suspicious-content detection)
"""

from __future__ import annotations

import re

from btcommon import Report, compile_patterns, first_match, load_rules, make_parser, powershell_json, reg_query

POLICY = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
POLICY_CHECKS = [
    ("ScriptBlockLogging", "EnableScriptBlockLogging", "medium", "script block logging (event 4104) is not enabled"),
    ("ModuleLogging", "EnableModuleLogging", "low", "module logging (event 4103) is not enabled"),
    ("Transcription", "EnableTranscripting", "low", "transcription is not enabled"),
]
_LONG_B64 = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")
# Wrappers PowerShell generates for CDXML modules (e.g. Defender's Set-MpPreference); their
# parameter names (DisableRealtimeMonitoring, ProxyBypass, ...) would otherwise match rules.
GENERATED_MODULE = "$__cmdletization_"


def policy_enabled(values: dict[str, dict[str, str]], subkey: str, value: str) -> bool:
    for key, data in values.items():
        if key.lower().endswith("\\" + subkey.lower()) and data.get(value, "").lower() in {"0x1", "1"}:
            return True
    return False


def suspicious_block(text: str, patterns: list) -> str | None:
    matched = first_match(text, patterns)
    if matched:
        return f"matches {matched!r}"
    if _LONG_B64.search(text):
        return "contains a long base64 blob"
    if text.count("`") > 20 or len(re.findall(r"\[char\]", text, re.IGNORECASE)) > 10:
        return "heavily obfuscated (backticks/[char] casts)"
    return None


def main() -> int:
    parser = make_parser("Audit PowerShell logging and hunt suspicious script blocks.")
    parser.add_argument("--days", type=int, default=7, help="Look back this many days for 4104 events (default: 7)")
    parser.add_argument("--max-events", type=int, default=3000, help="Max 4104 events to read (default: 3000)")
    args = parser.parse_args()
    report = Report("powershell_logging_audit", args, needs_admin=True)
    if not report.require("Windows"):
        return report.emit()
    patterns = compile_patterns(load_rules("powershell_logging_audit", args.rules).get("suspicious_patterns", []))

    policies = reg_query(POLICY, recursive=True)
    for subkey, value, severity, message in POLICY_CHECKS:
        if policy_enabled(policies, subkey, value):
            report.info("logging policy", f"{subkey} enabled")
        else:
            report.add("logging policy", severity, message, policy=subkey)

    v2, error = powershell_json(
        "Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue | Select-Object State"
    )
    if v2 and str(v2[0].get("State")) in {"Enabled", "2"}:
        report.add("logging policy", "medium", "PowerShell v2 engine is enabled (attackers use 'powershell -version 2' to evade logging/AMSI)")
    elif error:
        report.error(f"PowerShell v2 check: {error}")

    blocks, error = powershell_json(
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; "
        f"StartTime=(Get-Date).AddDays(-{int(args.days)})}} -MaxEvents {int(args.max_events)} -ErrorAction SilentlyContinue | "
        "Select-Object @{n='Time';e={$_.TimeCreated.ToString('o')}},LevelDisplayName,"
        "@{n='Script';e={$_.Properties[2].Value}},@{n='Path';e={$_.Properties[4].Value}},@{n='User';e={$_.UserId.Value}}"
    )
    if error:
        report.error(f"4104 events: {error}")
    seen: set[str] = set()
    for block in blocks:
        script = block.get("Script") or ""
        if GENERATED_MODULE in script and block.get("LevelDisplayName") != "Warning":
            continue
        reason = suspicious_block(script, patterns)
        if block.get("LevelDisplayName") == "Warning" and not reason:
            reason = "PowerShell flagged this block as suspicious (Warning level)"
        key = script[:500]
        if not reason or key in seen:
            continue
        seen.add(key)
        preview = " ".join(script.split())[:200]
        report.add("script blocks", "high", f"{block.get('Time')} user={block.get('User')} {reason}: {preview}", time=block.get("Time"), user=block.get("User"), path=block.get("Path"), reason=reason, script=script[:4000])
    report.info("script blocks", f"{len(blocks)} script block event(s) read from the last {args.days} day(s)")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
