#!/usr/bin/env python3

"""Forward findings from any script's --json output to syslog or a webhook.

Reads JSON reports (one document, or one JSON object per line as printed by
hashwatch_daemon/serviceup) from files or stdin, keeps findings at or above
--min-severity, and sends each one as an RFC 5424 syslog message and/or a webhook POST.

    python3 port_watch.py --json | python3 log_forwarder.py --syslog 10.0.0.5:514
    python3 hashwatch_daemon.py /etc --json | python3 log_forwarder.py --webhook URL --format slack
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from btcommon import SEVERITIES, SEVERITY_RANK, hostname

SYSLOG_SEVERITY = {"info": 6, "low": 5, "medium": 4, "high": 2}  # informational, notice, warning, critical
FACILITY_LOCAL0 = 16


def iter_documents(stream: Iterable[str]) -> Iterator[dict]:
    """Yield JSON objects from a stream holding one pretty-printed document or JSON lines."""
    buffer = ""
    decoder = json.JSONDecoder()
    for chunk in stream:
        buffer += chunk
        while True:
            buffer = buffer.lstrip()
            if not buffer:
                break
            try:
                obj, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                break
            buffer = buffer[end:]
            if isinstance(obj, dict):
                yield obj
    if buffer.strip():
        print(f"warning: ignored trailing non-JSON input: {buffer.strip()[:80]!r}", file=sys.stderr)


def flatten(doc: dict) -> Iterator[dict[str, Any]]:
    """Turn a report (or a single event line) into flat finding records."""
    base = {"tool": doc.get("tool", "?"), "host": doc.get("host") or hostname(), "timestamp": doc.get("timestamp")}
    if "findings" in doc:
        for finding in doc["findings"]:
            yield {**base, "check": finding.get("check"), "severity": finding.get("severity", "info"), "message": finding.get("message", ""), "data": finding.get("data", {})}
    elif "severity" in doc:
        message = doc.get("message") or " ".join(str(doc.get(k, "")) for k in ("status", "path", "detail")).strip()
        yield {**base, "check": doc.get("check", doc.get("tool")), "severity": doc["severity"], "message": message, "data": doc}


def syslog_message(record: dict) -> bytes:
    pri = FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY.get(record["severity"], 6)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    msg = f"[{record['severity'].upper()}] {record['check']}: {record['message']}"
    return f"<{pri}>1 {stamp} {record['host']} {record['tool']} - - - {msg}".encode("utf-8", errors="replace")


def send_syslog(target: str, protocol: str, records: list[dict]) -> None:
    host, _, port = target.rpartition(":") if ":" in target else (target, "", "514")
    address = (host or target, int(port or 514))
    if protocol == "tcp":
        with socket.create_connection(address, timeout=10) as sock:
            for record in records:
                payload = syslog_message(record)
                sock.sendall(f"{len(payload)} ".encode() + payload)  # RFC 6587 octet counting
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for record in records:
                sock.sendto(syslog_message(record)[:8192], address)


def webhook_payload(record: dict, fmt: str) -> dict:
    text = f"[{record['severity'].upper()}] {record['host']} {record['tool']} / {record['check']}: {record['message']}"
    if fmt == "slack":
        return {"text": text}
    if fmt == "discord":
        return {"content": text[:2000]}
    if fmt == "teams":
        return {"text": text}
    return record


def send_webhook(url: str, fmt: str, records: list[dict]) -> int:
    failures = 0
    for record in records:
        body = json.dumps(webhook_payload(record, fmt), default=str).encode()
        request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=15):
                pass
        except (urllib.error.URLError, TimeoutError) as exc:
            failures += 1
            print(f"error: webhook failed: {exc}", file=sys.stderr)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Forward --json findings to syslog or a webhook.")
    parser.add_argument("files", nargs="*", help="JSON report files (default: stdin)")
    parser.add_argument("--syslog", metavar="HOST[:PORT]", help="Send to a syslog server")
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="Syslog transport (default: udp)")
    parser.add_argument("--webhook", metavar="URL", help="POST each finding to this URL")
    parser.add_argument("--format", choices=["json", "slack", "discord", "teams"], default="json", help="Webhook payload format")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="low", help="Minimum severity to forward (default: low)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be sent instead of sending")
    args = parser.parse_args()
    if not (args.syslog or args.webhook or args.dry_run):
        parser.error("choose --syslog, --webhook or --dry-run")

    min_rank = SEVERITY_RANK[args.min_severity]
    streams = [open(f, encoding="utf-8") for f in args.files] if args.files else [sys.stdin]
    sent = failures = 0
    for stream in streams:
        # Forward each document as soon as it is read so streaming daemons are not delayed.
        for doc in iter_documents(stream):
            records = [r for r in flatten(doc) if SEVERITY_RANK.get(r["severity"], 0) >= min_rank]
            if not records:
                continue
            if args.dry_run:
                for record in records:
                    print(syslog_message(record).decode())
            if args.syslog and not args.dry_run:
                try:
                    send_syslog(args.syslog, args.protocol, records)
                except OSError as exc:
                    failures += len(records)
                    print(f"error: syslog failed: {exc}", file=sys.stderr)
            if args.webhook and not args.dry_run:
                failures += send_webhook(args.webhook, args.format, records)
            sent += len(records)
    verb = "would forward" if args.dry_run else "forwarded"
    print(f"{verb} {sent - failures} finding(s), {failures} failure(s)", file=sys.stderr)
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
