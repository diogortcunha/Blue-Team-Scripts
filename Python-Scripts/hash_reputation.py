#!/usr/bin/env python3

"""Look up file hashes on VirusTotal and/or MalwareBazaar.

Only SHA-256 hashes are sent - never file contents. API keys are read from the
environment: VT_API_KEY (VirusTotal) and ABUSECH_API_KEY (MalwareBazaar, free at
https://auth.abuse.ch/). Inputs can be hashes, files or directories.
The free VirusTotal API allows 4 lookups per minute, hence the default --delay.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from btcommon import Report, is_dir, is_file, load_rules, make_parser, sha256_file, walk_files

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def http_json(request: urllib.request.Request, timeout: int = 30) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8", errors="replace") or "{}")
        except json.JSONDecodeError:
            body = {}
        return exc.code, body
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return 0, {"error": str(exc)}


def virustotal(sha256: str, key: str) -> dict:
    request = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key})
    status, body = http_json(request)
    if status == 404:
        return {"found": False}
    if status != 200:
        return {"error": f"HTTP {status} {body.get('error', '')}".strip()}
    attrs = body.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()) if stats else 0,
        "name": attrs.get("meaningful_name", ""),
        "label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
    }


def malwarebazaar(sha256: str, key: str) -> dict:
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    request = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=data, headers={"Auth-Key": key})
    status, body = http_json(request)
    if status != 200:
        return {"error": f"HTTP {status}"}
    if body.get("query_status") in {"hash_not_found", "no_results"}:
        return {"found": False}
    if body.get("query_status") != "ok":
        return {"error": str(body.get("query_status"))}
    entry = (body.get("data") or [{}])[0]
    return {"found": True, "signature": entry.get("signature") or "", "file_name": entry.get("file_name") or "", "tags": entry.get("tags") or []}


def collect_hashes(inputs: list[str], report: Report) -> dict[str, str]:
    """Return {sha256: source}."""
    hashes: dict[str, str] = {}
    for item in inputs:
        if _SHA256.match(item):
            hashes[item.lower()] = "argument"
        elif is_file(item) or is_dir(item):
            for path in walk_files([item]):
                digest = sha256_file(path)
                if digest:
                    hashes.setdefault(digest, str(path))
        elif is_file(item.lstrip("@")):
            for line in Path(item.lstrip("@")).read_text().splitlines():
                if _SHA256.match(line.strip()):
                    hashes[line.strip().lower()] = item
        else:
            report.error(f"{item}: not a SHA-256 hash, file or directory")
    return hashes


def main() -> int:
    parser = make_parser("Check file hashes against VirusTotal and MalwareBazaar.")
    parser.add_argument("inputs", nargs="+", help="SHA-256 hashes, files, directories or @file with one hash per line")
    parser.add_argument("--delay", type=float, default=None, help="Seconds between VirusTotal lookups (default: 15, or 0 without VT)")
    parser.add_argument("--max", type=int, default=100, help="Maximum hashes to look up (default: 100)")
    args = parser.parse_args()
    report = Report("hash_reputation", args)
    vt_key, mb_key = os.environ.get("VT_API_KEY", ""), os.environ.get("ABUSECH_API_KEY", "")
    if not vt_key and not mb_key:
        report.fail("set VT_API_KEY and/or ABUSECH_API_KEY in the environment")
        return report.emit()
    min_detections = int(load_rules("hash_reputation", args.rules).get("virustotal_min_detections", 3))
    delay = args.delay if args.delay is not None else (15.0 if vt_key else 0.0)

    hashes = collect_hashes(args.inputs, report)
    if len(hashes) > args.max:
        report.error(f"{len(hashes)} hashes found; only the first {args.max} are checked (--max)")
    for index, (digest, source) in enumerate(list(hashes.items())[: args.max]):
        if index and delay:
            time.sleep(delay)
        label = f"{digest} ({source})"
        if mb_key:
            mb = malwarebazaar(digest, mb_key)
            if mb.get("error"):
                report.error(f"MalwareBazaar {digest}: {mb['error']}")
            elif mb.get("found"):
                report.add("malwarebazaar", "high", f"{label}: known malware {mb['signature'] or ''} {mb['file_name']} tags={','.join(mb['tags'])}", sha256=digest, source=source, **mb)
        if vt_key:
            vt = virustotal(digest, vt_key)
            if vt.get("error"):
                report.error(f"VirusTotal {digest}: {vt['error']}")
            elif not vt.get("found"):
                report.info("virustotal", f"{label}: unknown to VirusTotal", sha256=digest, source=source)
            elif vt["malicious"] >= min_detections:
                report.add("virustotal", "high", f"{label}: {vt['malicious']}/{vt['total']} engines flag it ({vt['label'] or vt['name']})", sha256=digest, source=source, **vt)
            elif vt["malicious"] or vt["suspicious"]:
                report.add("virustotal", "low", f"{label}: {vt['malicious']} malicious / {vt['suspicious']} suspicious of {vt['total']}", sha256=digest, source=source, **vt)
            else:
                report.info("virustotal", f"{label}: clean (0/{vt['total']})", sha256=digest, source=source)
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
