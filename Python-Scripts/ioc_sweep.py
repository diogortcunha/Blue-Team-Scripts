#!/usr/bin/env python3

"""Sweep the host for indicators of compromise (IOCs).

The IOC file has one indicator per line (``#`` comments allowed; CSV rows use the first
column). Types are detected automatically:
  MD5/SHA-1/SHA-256 hashes  -> files under --paths are hashed and compared
  IPv4/IPv6 addresses       -> current connections and listeners
  domains                   -> DNS cache and hosts file
  file names / paths        -> file names under --paths, and exact paths
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path

from btcommon import IS_WINDOWS, Report, fmt_endpoint, home_dirs, is_dir, list_sockets, make_parser, walk_files

_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
FILE_EXTENSION_HINT = re.compile(r"\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|sh|py|elf|bin|so|jar|lnk|zip|rar|7z|iso|doc[xm]?|xls[xm]?)$", re.IGNORECASE)


def classify(value: str) -> tuple[str, str] | None:
    """Return (type, normalized value) for an indicator, or None when it is not recognised."""
    value = value.strip().strip('"').strip()
    if not value:
        return None
    defanged = value.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
    lowered = defanged.lower()
    if _HEX.match(lowered) and len(lowered) in HASH_LENGTHS:
        return HASH_LENGTHS[len(lowered)], lowered
    try:
        return "ip", str(ipaddress.ip_address(lowered))
    except ValueError:
        pass
    if lowered.startswith(("http://", "https://")):
        host = lowered.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
        return ("domain", host) if _DOMAIN.match(host) else None
    if "/" in defanged or "\\" in defanged:
        return "path", defanged
    if FILE_EXTENSION_HINT.search(lowered):
        return "filename", lowered
    if _DOMAIN.match(lowered):
        return "domain", lowered
    return "filename", lowered


def load_iocs(path: str) -> dict[str, set[str]]:
    iocs: dict[str, set[str]] = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        first = line.split(",", 1)[0]
        result = classify(first)
        if result:
            iocs.setdefault(result[0], set()).add(result[1])
    return iocs


def default_paths() -> list[Path]:
    paths = [h / sub for h in home_dirs() for sub in ("Downloads", "Desktop", "AppData/Local/Temp", "AppData/Roaming")]
    if IS_WINDOWS:
        paths += [Path(r"C:\Windows\Temp"), Path(r"C:\Users\Public"), Path(r"C:\ProgramData")]
    else:
        paths += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"), Path("/usr/local/bin"), Path("/opt")]
    return [p for p in paths if is_dir(p)]


def hash_file(path: Path, algorithms: list[str]) -> dict[str, str]:
    hashers = {name: hashlib.new(name) for name in algorithms}
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                for hasher in hashers.values():
                    hasher.update(chunk)
    except OSError:
        return {}
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def main() -> int:
    parser = make_parser("Sweep the host for IOCs (hashes, IPs, domains, file names).")
    parser.add_argument("ioc_file", help="File with one indicator per line")
    parser.add_argument("--paths", nargs="*", help="Directories to scan for hashes/file names (default: temp, downloads, profiles)")
    parser.add_argument("--max-size", type=int, default=100, help="Skip files larger than this many MB (default: 100)")
    args = parser.parse_args()
    report = Report("ioc_sweep", args, needs_admin=True)

    try:
        iocs = load_iocs(args.ioc_file)
    except OSError as exc:
        report.fail(f"cannot read {args.ioc_file}: {exc}")
        return report.emit()
    report.info("indicators", ", ".join(f"{kind}={len(values)}" for kind, values in sorted(iocs.items())) or "no indicators recognised")

    hash_types = [kind for kind in ("md5", "sha1", "sha256") if iocs.get(kind)]
    names = iocs.get("filename", set())
    scan_paths = [Path(p) for p in args.paths] if args.paths else default_paths()
    if hash_types or names:
        errors: list[str] = []
        limit = args.max_size * 1024 * 1024
        scanned = 0
        for path in walk_files(scan_paths, errors):
            if path.name.lower() in names:
                report.add("file names", "high", f"file name matches IOC: {path}", path=str(path))
            if not hash_types:
                continue
            try:
                if path.stat().st_size > limit:
                    continue
            except OSError:
                continue
            scanned += 1
            for algorithm, digest in hash_file(path, hash_types).items():
                if digest in iocs[algorithm]:
                    report.add("file hashes", "high", f"{algorithm} {digest} matches IOC: {path}", path=str(path), algorithm=algorithm, hash=digest)
        report.info("file hashes", f"hashed {scanned} file(s) under {len(scan_paths)} folder(s)")
        for error in errors[:10]:
            report.error(error)

    for raw in iocs.get("path", set()):
        candidate = Path(raw)
        if candidate.exists():
            report.add("file paths", "high", f"path from IOC list exists: {candidate}", path=raw)

    if iocs.get("ip"):
        sockets, error = list_sockets()
        if error:
            report.error(error)
        for sock in sockets:
            for addr in (sock.remote_addr, sock.local_addr):
                normalized = addr[7:] if addr.startswith("::ffff:") else addr
                if normalized in iocs["ip"]:
                    report.add("network", "high", f"{sock.proto} {fmt_endpoint(sock.local_addr, sock.local_port)} <-> {fmt_endpoint(sock.remote_addr, sock.remote_port)} involves IOC address {normalized} ({sock.state or 'no state'}, {sock.process or sock.pid or '?'})", ip=normalized, pid=sock.pid, process=sock.process)

    if iocs.get("domain"):
        from dns_cache_audit import cache_names, hosts_entries

        cached, _ = cache_names(report)
        domains = iocs["domain"]
        for name in cached:
            if name in domains or any(name.endswith("." + d) for d in domains):
                report.add("dns", "high", f"DNS cache contains IOC domain {name} -> {', '.join(sorted(cached[name]))}", domain=name)
        for address, name in hosts_entries():
            if name in domains:
                report.add("dns", "high", f"hosts file maps IOC domain {name} -> {address}", domain=name)
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
