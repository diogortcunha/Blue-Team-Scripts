#!/usr/bin/env python3

"""Check Microsoft Defender health, exclusions and recent detections. Windows only.

Exclusions are a favourite hiding place for malware; non-administrators see them masked,
so run as Administrator.
"""

from __future__ import annotations

from btcommon import Report, load_rules, make_parser, powershell_json

PROTECTION_FLAGS = {
    "AMServiceEnabled": "antimalware service",
    "AntivirusEnabled": "antivirus",
    "RealTimeProtectionEnabled": "real-time protection",
    "BehaviorMonitorEnabled": "behaviour monitoring",
    "IoavProtectionEnabled": "download/attachment scanning",
    "OnAccessProtectionEnabled": "on-access protection",
    "IsTamperProtected": "tamper protection",
}

EXCLUSION_FIELDS = ("ExclusionPath", "ExclusionProcess", "ExclusionExtension", "ExclusionIpAddress")


def evaluate_status(status: dict, max_age: int) -> list[tuple[str, str]]:
    """Return (severity, message) problems for a Get-MpComputerStatus row."""
    problems = []
    for field, label in PROTECTION_FLAGS.items():
        if status.get(field) is False:
            problems.append(("high", f"{label} is disabled ({field}=False)"))
    age = status.get("AntivirusSignatureAge")
    if isinstance(age, int) and age > max_age:
        problems.append(("medium", f"antivirus signatures are {age} days old"))
    if status.get("AMRunningMode") and status["AMRunningMode"] not in {"Normal", "EDR Block Mode"}:
        problems.append(("medium", f"Defender is running in {status['AMRunningMode']} mode"))
    return problems


def exclusions(pref: dict) -> list[tuple[str, str]]:
    result = []
    for field in EXCLUSION_FIELDS:
        values = pref.get(field) or []
        if isinstance(values, str):
            values = [values]
        for value in values:
            if value and "N/A: Must be an administrator" not in str(value):
                result.append((field, str(value)))
    return result


def main() -> int:
    parser = make_parser("Check Microsoft Defender status, exclusions and detections.")
    parser.add_argument("--days", type=int, default=30, help="Show detections from the last N days (default: 30)")
    args = parser.parse_args()
    report = Report("defender_status", args, needs_admin=True)
    if not report.require("Windows"):
        return report.emit()
    rules = load_rules("defender_status", args.rules)

    status_rows, error = powershell_json("Get-MpComputerStatus")
    if error or not status_rows:
        report.fail(f"Get-MpComputerStatus failed (Defender absent or replaced by another AV?): {error or 'no data'}")
        return report.emit()
    status = status_rows[0]
    for severity, message in evaluate_status(status, int(rules.get("max_signature_age_days", 3))):
        report.add("protection", severity, message)
    report.info("protection", f"engine {status.get('AMEngineVersion')} signatures {status.get('AntivirusSignatureVersion')} mode {status.get('AMRunningMode')}")

    prefs, error = powershell_json("Get-MpPreference | Select-Object " + ",".join(EXCLUSION_FIELDS) + ",DisableRealtimeMonitoring,DisableScriptScanning,DisableIOAVProtection,MAPSReporting,SubmitSamplesConsent")
    if error:
        report.error(f"Get-MpPreference: {error}")
    pref = prefs[0] if prefs else {}
    for field, value in exclusions(pref):
        report.add("exclusions", "medium", f"{field}: {value}", field=field, value=value)
    for field in ("DisableRealtimeMonitoring", "DisableScriptScanning", "DisableIOAVProtection"):
        if pref.get(field) is True:
            report.add("preferences", "high", f"{field} is set")
    if pref.get("MAPSReporting") == 0:
        report.add("preferences", "low", "cloud-delivered protection (MAPS) is disabled")

    detections, error = powershell_json(
        f"Get-MpThreatDetection | Where-Object {{ $_.InitialDetectionTime -gt (Get-Date).AddDays(-{int(args.days)}) }} | "
        "Select-Object ThreatID,@{n='Time';e={$_.InitialDetectionTime.ToString('o')}},ActionSuccess,@{n='Resources';e={$_.Resources -join '; '}},ProcessName,DomainUser"
    )
    if error:
        report.error(f"Get-MpThreatDetection: {error}")
    threat_names = {}
    if detections:
        threats, _ = powershell_json("Get-MpThreat | Select-Object ThreatID,ThreatName")
        threat_names = {t.get("ThreatID"): t.get("ThreatName") for t in threats}
    for det in detections:
        name = threat_names.get(det.get("ThreatID"), f"threat {det.get('ThreatID')}")
        severity = "high" if not det.get("ActionSuccess") else "medium"
        report.add("detections", severity, f"{det.get('Time')} {name} in {det.get('Resources')} (process {det.get('ProcessName')}, user {det.get('DomainUser')}, remediated={det.get('ActionSuccess')})", **det)
    if not detections:
        report.info("detections", f"no detections in the last {args.days} days")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
