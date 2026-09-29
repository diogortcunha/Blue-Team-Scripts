# Blue-Team-Scripts

Python scripts for blue-team monitoring, host triage and defensive audits on Linux and Windows.
Standard library only (Python 3.9+), no installation needed. Either copy the `Python-Scripts`
folder to the host (every script imports `btcommon.py` and reads `rules.json` from the same
folder, so copy it as a whole), or use the single-file build described below.

## Quick start

```bash
# Run every applicable check in parallel and write one Markdown report
# (use root/Administrator for full results)
sudo python3 Python-Scripts/triage_all.py
python3 Python-Scripts/triage_all.py --format html -o report.html --allowlist site-allowlist.json

# Run a single check
python3 Python-Scripts/log_triage.py --days 3
python3 Python-Scripts/port_watch.py --json
```

On Windows use `py` or `python` instead of `python3`, from an elevated prompt.

## Single-file build (.pyz)

For incident response it is easier to carry one file. Build it once on a trusted machine:

```bash
python3 tools/build_pyz.py                                  # -> dist/blue-team-scripts.pyz + .sha256
python3 tools/build_pyz.py --allowlist site-allowlist.json  # embed a site allowlist as allowlist.json
```

Then, on the host being triaged (verify the SHA-256 first):

```bash
python3 blue-team-scripts.pyz list
sudo python3 blue-team-scripts.pyz triage_all --format html -o report.html
python3 blue-team-scripts.pyz log_triage --days 3 --json
```

CI builds the archive on every push and publishes it as the `blue-team-scripts-pyz` artifact.

## Common options

Every audit script accepts:

| Option | Meaning |
|---|---|
| `--json` | Print a JSON report (`tool`, `host`, `timestamp`, `privileged`, `summary`, `findings`, `errors`) |
| `--min-severity {info,low,medium,high}` | Hide findings below this severity |
| `--rules FILE` | Use another rules file instead of `rules.json` |
| `--allowlist FILE` | Extra allowlist of known-good findings (repeatable); `allowlist.json` next to the scripts is always read |
| `--write-baseline FILE` / `--baseline FILE` | Save a snapshot, or show what was ADDED/REMOVED/CHANGED since one (scripts marked *baseline* below) |

Exit codes: `0` nothing flagged, `1` at least one low/medium/high finding, `2` the check could not
run (wrong OS, missing data). This makes the scripts usable from cron, CI or monitoring. Scripts
that need root/Administrator warn on stderr and report what they could not read under `errors`.

## Scripts

### Orchestration and integration

| Script | What it does |
|---|---|
| `triage_all.py` | Runs all applicable checks in parallel (`--jobs`, default 4) and builds one Markdown, HTML or JSON report (`--only`, `--skip`, `--list`, `--allowlist`); runs `tool_integrity_check` first and puts a warning at the top of the report if the system tools look tampered with |
| `tool_integrity_check.py` | Verifies the tools every check relies on (`ps`, `ss`, `netstat`, `tasklist`, ...) with `dpkg --verify`/`rpm -V` or Authenticode signatures, finds tools shadowed in PATH and `LD_PRELOAD`; *baseline* also hashes the toolkit's own files |
| `log_forwarder.py` | Sends findings from any `--json` output to syslog (UDP/TCP) or a webhook (JSON, Slack, Discord, Teams) |
| `ioc_sweep.py` | Searches the host for IOCs from a file: hashes, IPs, domains, file names and paths (defanged input accepted) |
| `hash_reputation.py` | Looks up SHA-256 hashes on VirusTotal (`VT_API_KEY`) and/or MalwareBazaar (`ABUSECH_API_KEY`); only hashes are sent |

### Host snapshot and processes

| Script | What it does |
|---|---|
| `system_info.py` | Full system and security snapshot, written with owner-only permissions (`--include-history` opt-in, `--section`) |
| `process_monitor.py` | Top processes plus suspicious tool names and command lines (reverse shells, encoded PowerShell, LOLBins) |
| `process_tree_audit.py` | Suspicious parent/child chains (Office → PowerShell, web server → shell, unexpected lsass parent); `--tree PID` |
| `deleted_binary_check.py` | Processes running from deleted files, memory (`memfd:`) or temp folders |
| `ld_preload_check.py` | Linux rootkit indicators: `ld.so.preload`, `LD_PRELOAD` in processes, hidden modules, hidden PIDs (every PID up to `pid_max`, a few seconds; `--quick-pid-scan` for the old fast mode), kernel taint |

### Network

| Script | What it does |
|---|---|
| `port_watch.py` | Listening ports with owning process; flags backdoor-style ports exposed on the network (*baseline*, `--connections`) |
| `network_beacon_watch.py` | Busiest outbound destinations; with `--samples N --interval S` detects regular beaconing by connection timing (TCP, plus connected UDP sockets on Linux) |
| `dns_cache_audit.py` | DNS cache (dynamic DNS/tunnelling suffixes, random-looking DGA names), resolvers, and hosts-file hijacks |

### Persistence and accounts

| Script | What it does |
|---|---|
| `startup_audit.py` | Autoruns: Run keys, Startup folders, auto-start services / systemd units, XDG autostart, shell rc files, udev, preload (*baseline*) |
| `scheduled_task_audit.py` | Cron (all users and cron.* scripts), at, systemd timers, Windows scheduled tasks (*baseline*, `--all`) |
| `wmi_persistence_audit.py` | Windows: WMI event subscriptions, IFEO debuggers, SilentProcessExit, Winlogon, AppInit, LSA packages, netsh helpers (*baseline*) |
| `account_audit.py` | Extra UID 0, empty passwords, system accounts with shells, sudo NOPASSWD, Guest/PASSWD_NOTREQD, admin members (*baseline*) |
| `ssh_key_audit.py` | `authorized_keys` (forced commands, DSA/short RSA, writable files) and risky `sshd_config` settings (*baseline*) |
| `suid_audit.py` | SUID/SGID binaries and file capabilities (read from xattrs in the same filesystem walk, no `getcap` needed on Linux), GTFOBins and user-writable locations (*baseline*) |

### Logs and Windows security

| Script | What it does |
|---|---|
| `log_triage.py` | Auth logs (rotated/.gz or journald) or Windows Security/System events: brute force per IP, successful login after brute force, account/group changes, cleared logs, new services |
| `powershell_logging_audit.py` | Windows: ScriptBlock/module logging and transcription policy, PowerShell v2, suspicious 4104 script blocks |
| `defender_status.py` | Windows: Defender protection state, signature age, exclusions and recent detections |

### Files, web and devices

| Script | What it does |
|---|---|
| `file_hash_audit.py` | SHA-256 + permission/owner baselines of files and directories (ADDED/REMOVED/CHANGED/PERMS) |
| `hashwatch_daemon.py` | Continuous version of the above; only re-hashes files whose metadata changed (`--interval`, `--once`, `--baseline`) |
| `suspicious_web_root_scan.py` | Web shells: marker regexes in any server-side script, code hidden in images, scripts in upload folders, recently changed scripts |
| `browser_download_audit.py` | Recent downloads: risky types, double extensions, and the source URL from Mark-of-the-Web / xattrs |
| `usb_device_audit.py` | Connected USB devices, USB storage history (USBSTOR) and kernel USB events |
| `serviceup.py` | Watches services and alerts when a running one stops (`--restart ask/auto/never`, `--once`, `--only/--ignore`) |

`user_activity_audit.py`, `scheduled_job_diff.py` and `autorun_diff.py` are deprecated wrappers kept
for compatibility; they now run `log_triage.py`, `scheduled_task_audit.py` and `startup_audit.py`.

## Examples

```bash
# Baselines: record a known-good state, then compare later
python3 Python-Scripts/startup_audit.py --write-baseline autoruns.json
python3 Python-Scripts/startup_audit.py --baseline autoruns.json --min-severity low
python3 Python-Scripts/file_hash_audit.py /etc /usr/bin --write-baseline hashes.json
python3 Python-Scripts/file_hash_audit.py /etc /usr/bin --baseline hashes.json

# Continuous monitoring, forwarded to a SIEM
python3 Python-Scripts/hashwatch_daemon.py /etc --interval 30 --json | python3 Python-Scripts/log_forwarder.py --syslog 10.0.0.5:514
python3 Python-Scripts/serviceup.py --restart never --json | python3 Python-Scripts/log_forwarder.py --webhook "$SLACK_URL" --format slack

# Beacon detection over 10 minutes
python3 Python-Scripts/network_beacon_watch.py --samples 60 --interval 10 --external-only

# IOC sweep and hash reputation
python3 Python-Scripts/ioc_sweep.py iocs.txt --paths /tmp /home /var/www
VT_API_KEY=... python3 Python-Scripts/hash_reputation.py /tmp/suspicious.bin

# Snapshot for an incident ticket
sudo python3 Python-Scripts/system_info.py --include-history
```

## Tuning detections

Detection patterns, suspicious ports, GTFOBins, web-shell markers, log patterns, Windows event IDs,
the list of verified system tools and thresholds live in `Python-Scripts/rules.json`. Edit it (or
pass `--rules my_rules.json`) to add patterns without touching the code.

## Allowlisting known-good findings

To silence findings you have reviewed (an updater that reinstalls its service, a sanctioned
listening port), create `Python-Scripts/allowlist.json` from `allowlist.example.json`, or pass
`--allowlist FILE` (to any script, or to `triage_all.py` which forwards it):

```json
{
  "allowlist": [
    {"tool": "log_triage", "check": "service_installed", "match": "service=Google Updater",
     "reason": "Chrome updater reinstalls its services on every update"},
    {"tool": "port_watch", "match": ":8888 .*jupyter", "reason": "Jupyter on DS workstations",
     "host": "^ds-ws-\\d+$", "expires": "2026-12-31"}
  ]
}
```

`match` is a case-insensitive regex on the finding message; `tool`, `check`, `host` (regex) and
`expires` are optional. Matching findings are not hidden: they become `info`, get
`(allowlisted: reason)` appended and an `allowlisted` field in JSON, and no longer change the exit
code or get forwarded by `log_forwarder.py`. Expired entries are ignored with a warning so
exceptions get reviewed. The streaming tools (`hashwatch_daemon.py`, `serviceup.py`) honour the
allowlist too.

## Trusting the results

A rootkit can make `ps`, `ss` or `tasklist` lie to every check. `triage_all.py` therefore runs
`tool_integrity_check.py` first; if it flags anything, treat the rest of the report with suspicion
and repeat the triage from a trusted live system. Record hashes of the tools and of this toolkit on a
known-good host with `tool_integrity_check.py --write-baseline tools.json` and compare later with
`--baseline tools.json`.

## Development

```bash
pip install pytest ruff
python -m pytest            # tests run on Linux and Windows
ruff check Python-Scripts tests tools
python3 tools/build_pyz.py  # single-file build
```

CI (`.github/workflows/ci.yml`) runs lint and tests on Ubuntu and Windows with Python 3.9 and 3.13,
then builds the `.pyz`.

## Notes

- Output is meant for quick triage and follow-up investigation; findings are leads, not verdicts.
- Reports can contain sensitive host data; `system_info.py` and `triage_all.py` write them with owner-only permissions.
- Antivirus may block the web-shell test fixtures that the test suite creates at runtime; that is expected.
