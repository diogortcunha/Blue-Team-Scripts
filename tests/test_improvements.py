import argparse
import json
import struct
import subprocess
import sys
from pathlib import Path

import btcommon
from btcommon import Allowlist, Report
from conftest import SCRIPTS

ROOT = SCRIPTS.parent


def ns(**kw):
    defaults = {"json": False, "min_severity": "info", "rules": None, "allowlist": None}
    defaults.update(kw)
    return argparse.Namespace(**defaults)


# --- allowlist ---------------------------------------------------------------------


def write_allowlist(tmp_path, entries, name="al.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"allowlist": entries}))
    return str(path)


def test_allowlist_downgrades_matching_findings(tmp_path):
    path = write_allowlist(tmp_path, [
        {"tool": "t", "check": "c", "match": "google updater", "reason": "known updater"},
        {"match": "other-host-only", "reason": "x", "host": "^no-such-host$"},
    ])
    report = Report("t", ns(allowlist=[path]))
    report.add("c", "medium", "service=Google Updater installed")
    report.add("c", "medium", "other-host-only finding")
    report.add("other", "medium", "service=Google Updater installed")
    severities = [f.severity for f in report.findings]
    assert severities == ["info", "medium", "medium"]
    assert report.findings[0].data["allowlisted"] == "known updater"
    assert report.findings[0].data["original_severity"] == "medium"
    assert report.allowlisted == 1
    assert report.exit_code() == btcommon.EXIT_FINDINGS


def test_allowlist_only_suppression_gives_clean_exit(tmp_path):
    path = write_allowlist(tmp_path, [{"match": ".*", "reason": "everything"}])
    report = Report("t", ns(allowlist=[path]))
    report.add("c", "high", "anything")
    assert report.exit_code() == btcommon.EXIT_CLEAN


def test_allowlist_expired_and_invalid_entries(tmp_path):
    path = write_allowlist(tmp_path, [
        {"match": "a", "reason": "old", "expires": "2000-01-01"},
        {"reason": "no match field"},
        {"match": "(", "reason": "bad regex"},
    ])
    allow = Allowlist.load([path], default=tmp_path / "missing.json")
    assert allow.entries == []
    assert len(allow.errors) == 3 and any("expired" in e for e in allow.errors)


def test_allowlist_example_file_is_valid():
    allow = Allowlist.load([str(SCRIPTS / "allowlist.example.json")], default=Path("/nonexistent"))
    assert allow.entries and not [e for e in allow.errors if "expired" not in e]


def test_allowlist_in_json_output(tmp_path, capsys):
    path = write_allowlist(tmp_path, [{"match": "noise", "reason": "r"}])
    report = Report("t", ns(json=True, allowlist=[path]))
    report.add("c", "low", "noise here")
    report.emit()
    doc = json.loads(capsys.readouterr().out)
    assert doc["allowlisted"] == 1 and doc["summary"]["low"] == 0


# --- tool_integrity_check -----------------------------------------------------------


def test_parse_verify_output_skips_config_files():
    from tool_integrity_check import digest_changed, parse_verify_output

    output = "??5??????   /usr/bin/ps\n??5?????? c /etc/ssh/sshd_config\nS.5....T.    /usr/bin/ss\nmissing     /usr/bin/w\n"
    changed = parse_verify_output(output)
    assert set(changed) == {"/usr/bin/ps", "/usr/bin/ss", "/usr/bin/w"}
    assert digest_changed(changed["/usr/bin/ps"]) and digest_changed(changed["/usr/bin/ss"])
    assert not digest_changed(changed["/usr/bin/w"])


def test_usrmerge_candidates():
    from tool_integrity_check import usrmerge_candidates

    assert usrmerge_candidates("/usr/bin/ss") == ["/usr/bin/ss", "/bin/ss"]
    assert usrmerge_candidates("/sbin/ip") == ["/sbin/ip", "/usr/sbin/ip"]
    assert usrmerge_candidates("/opt/x") == ["/opt/x"]


def test_trust_warning():
    from triage_all import trust_warning

    clean = {"tool": "tool_integrity_check", "summary": {"high": 0, "medium": 0, "low": 0}}
    bad = {"tool": "tool_integrity_check", "summary": {"high": 1, "medium": 0, "low": 0}}
    assert trust_warning([clean]) == ""
    assert "rootkit" in trust_warning([bad])
    assert trust_warning([{"tool": "port_watch", "summary": {"high": 3}}]) == ""


# --- suid_audit capabilities --------------------------------------------------------


def _vfs_cap(version, effective, permitted, inheritable=0):
    magic = version | (1 if effective else 0)
    words = 1 if version == 0x01000000 else 2
    data = struct.pack("<I", magic)
    for word in range(words):
        data += struct.pack("<II", (permitted >> (32 * word)) & 0xFFFFFFFF, (inheritable >> (32 * word)) & 0xFFFFFFFF)
    return data


def test_decode_capabilities_matches_getcap_notation():
    from suid_audit import decode_capabilities

    assert decode_capabilities(_vfs_cap(0x02000000, True, 1 << 13)) == "cap_net_raw=ep"
    assert decode_capabilities(_vfs_cap(0x02000000, False, (1 << 7) | (1 << 21))) == "cap_setuid,cap_sys_admin=p"
    assert decode_capabilities(_vfs_cap(0x02000000, True, 1 << 38)) == "cap_perfmon=ep"  # second 32-bit word
    assert decode_capabilities(_vfs_cap(0x01000000, True, 1 << 10)) == "cap_net_bind_service=ep"
    v3 = _vfs_cap(0x03000000, True, 1 << 13) + struct.pack("<I", 0)  # v3 adds a root uid
    assert decode_capabilities(v3) == "cap_net_raw=ep"
    assert decode_capabilities(b"\x00" * 4) is None


# --- network_beacon_watch UDP --------------------------------------------------------


def test_outbound_includes_connected_udp_only():
    from network_beacon_watch import outbound

    sockets = btcommon.parse_ss(
        'udp ESTAB 0 0 10.0.0.5:40000 203.0.113.9:53 users:(("implant",pid=9,fd=3))\n'
        "udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*\n"
        "tcp ESTAB 0 0 10.0.0.5:5 198.51.100.1:443\n"
        "tcp LISTEN 0 0 0.0.0.0:22 0.0.0.0:*\n"
    )
    assert [(s.proto, s.remote_addr) for s in outbound(sockets, False)] == [("udp", "203.0.113.9"), ("tcp", "198.51.100.1")]


# --- hidden pid scan ----------------------------------------------------------------


def test_hidden_pids_quick_scan_finds_nothing_on_healthy_host():
    import os

    import pytest

    if not os.path.isdir("/proc/self"):
        pytest.skip("needs Linux /proc")
    from ld_preload_check import hidden_pids

    assert hidden_pids(quick=True) == []


# --- single-file archive -------------------------------------------------------------


def test_pyz_build_and_run(tmp_path):
    out = tmp_path / "bts.pyz"
    build = subprocess.run([sys.executable, str(ROOT / "tools" / "build_pyz.py"), "--output", str(out)], capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stderr
    assert (tmp_path / "bts.pyz.sha256").read_text().split()[0] == btcommon.sha256_file(out)

    listing = subprocess.run([sys.executable, str(out), "list"], capture_output=True, text=True, timeout=60)
    assert "triage_all" in listing.stdout and "btcommon" not in listing.stdout

    # rules.json must be readable from inside the archive
    proc = subprocess.run([sys.executable, str(out), "process_monitor", "--json", "--limit", "1"], capture_output=True, text=True, timeout=120)
    doc = json.loads(proc.stdout)
    assert doc["tool"] == "process_monitor"

    checks = subprocess.run([sys.executable, str(out), "triage_all", "--list"], capture_output=True, text=True, timeout=60)
    assert checks.returncode == 0 and "port_watch" in checks.stdout

    unknown = subprocess.run([sys.executable, str(out), "nope"], capture_output=True, text=True, timeout=60)
    assert unknown.returncode == 2
