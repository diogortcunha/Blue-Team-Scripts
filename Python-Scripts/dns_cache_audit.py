#!/usr/bin/env python3

"""Inspect the DNS cache, resolver configuration and hosts file.

Cached names are checked against suspicious suffixes (dynamic DNS, tunnelling services,
out-of-band testing domains) and a random-looking-label heuristic (DGA). The hosts file is
checked for entries that redirect or block security and update domains.
Cache contents need Windows, or systemd-resolved >= 254 (``resolvectl show-cache``, as root).
"""

from __future__ import annotations

import math
import os
from collections import Counter
from pathlib import Path

from btcommon import IS_WINDOWS, Report, is_loopback, is_unspecified, load_rules, make_parser, powershell_json, read_text, run


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values()) if text else 0.0


def looks_generated(name: str, min_len: int, threshold: float) -> bool:
    labels = name.split(".")[:-2] or name.split(".")[:1]
    longest = max(labels, key=len, default="")
    return len(longest) >= min_len and entropy(longest) >= threshold


def cache_names(report: Report | None = None) -> tuple[dict[str, set[str]], str]:
    """Return ({name: {record data}}, source)."""
    names: dict[str, set[str]] = {}
    if IS_WINDOWS:
        rows, error = powershell_json("Get-DnsClientCache | Select-Object Entry,Data")
        if error and report:
            report.error(error)
        for row in rows:
            entry = (row.get("Entry") or "").rstrip(".").lower()
            if entry:
                names.setdefault(entry, set()).add(str(row.get("Data") or ""))
        return names, "Get-DnsClientCache"
    result = run(["resolvectl", "show-cache"])
    if result.ok:
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "IN":
                names.setdefault(parts[0].rstrip(".").lower(), set()).add(" ".join(parts[2:]))
        return names, "resolvectl show-cache"
    if report:
        report.error("DNS cache contents unavailable (needs systemd-resolved >= 254 and root)")
    return names, ""


def hosts_path() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\drivers\etc\hosts"
    return Path("/etc/hosts")


def hosts_entries() -> list[tuple[str, str]]:
    entries = []
    for line in (read_text(hosts_path()) or "").splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        for name in parts[1:]:
            entries.append((parts[0], name.lower()))
    return entries


def main() -> int:
    parser = make_parser("Audit DNS cache, resolvers and the hosts file.")
    parser.add_argument("--all", action="store_true", help="List every cached name, not only suspicious ones")
    args = parser.parse_args()
    report = Report("dns_cache_audit", args, needs_admin=not IS_WINDOWS)
    rules = load_rules("dns_cache_audit", args.rules)
    suffixes = tuple(s.lower() for s in rules.get("suspicious_suffixes", []))
    security_words = tuple(rules.get("security_domain_keywords", []))

    names, source = cache_names(report)
    for name, data in sorted(names.items()):
        records = ", ".join(sorted(d for d in data if d))[:150]
        if name.endswith(suffixes):
            report.add("dns cache", "medium", f"{name} -> {records} (suffix often abused for C2/tunnelling)", name=name, records=sorted(data))
        elif looks_generated(name, rules.get("min_label_length", 16), rules.get("entropy_threshold", 3.8)):
            report.add("dns cache", "medium", f"{name} -> {records} (random-looking label, possible DGA)", name=name, records=sorted(data))
        elif args.all:
            report.info("dns cache", f"{name} -> {records}", name=name)
    if source:
        report.info("dns cache", f"{len(names)} cached name(s) from {source}")

    for address, name in hosts_entries():
        if name in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "broadcasthost"} or name.startswith("ip6-"):
            continue
        if any(word in name for word in security_words):
            severity = "high" if is_loopback(address) or is_unspecified(address) else "medium"
            report.add("hosts file", severity, f"{name} -> {address} (security/update domain overridden)", name=name, address=address)
        elif not is_loopback(address):
            report.info("hosts file", f"{name} -> {address}", name=name, address=address)

    if IS_WINDOWS:
        servers, _ = powershell_json("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses")
        for row in servers:
            if row.get("ServerAddresses"):
                report.info("resolvers", f"{row.get('InterfaceAlias')}: {', '.join(row['ServerAddresses'])}")
    else:
        for line in (read_text("/etc/resolv.conf") or "").splitlines():
            if line.startswith(("nameserver", "search", "options")):
                report.info("resolvers", line.strip())
        stats = run(["resolvectl", "statistics"])
        if stats.ok:
            for line in stats.lines():
                if "Current Cache Size" in line or "Cache Hits" in line or "Cache Misses" in line:
                    report.info("resolver statistics", line.strip())
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
