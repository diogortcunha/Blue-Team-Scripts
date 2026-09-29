# Changelog

## 2.1.0

### Added
- Allowlist of known-good findings: `allowlist.json` next to the scripts plus `--allowlist FILE`
  on every script (and forwarded by `triage_all.py`). Matches become `info` with the reason
  attached; entries can be scoped by tool, check and host, and expire. See `allowlist.example.json`.
- `tool_integrity_check.py`: verifies the system tools the checks rely on (dpkg/rpm verification
  or Authenticode signatures), PATH shadowing and `LD_PRELOAD`; baselines also cover the toolkit.
- Single-file build: `tools/build_pyz.py` creates `dist/blue-team-scripts.pyz` (+ `.sha256`);
  `python3 blue-team-scripts.pyz <script> [args]`. CI publishes it as an artifact.

### Changed
- `triage_all.py` runs checks in parallel (`--jobs`, default 4; about 4x faster on Windows), runs
  `tool_integrity_check` first and warns at the top of the report when tools look tampered with.
- `suid_audit.py` reads file capabilities from xattrs during its own walk instead of a second
  `getcap -r` pass (about 4x faster), falling back to `getcap` where xattrs are unavailable.
- `ld_preload_check.py` scans every PID up to `pid_max` for hidden processes by default
  (`--quick-pid-scan` for the old behaviour) and confirms candidates twice to avoid races.
- `network_beacon_watch.py` also tracks connected UDP sockets on Linux.
- `pyproject.toml` version 2.1.0.

### Fixed
- `ld_preload_check.py` could report a short-lived process as hidden when other checks were
  spawning processes at the same time.

## 2.0.0

### Added
- `btcommon.py`: shared helpers (safe command runner, `--json`/`--min-severity`/`--rules` options,
  consistent exit codes, privilege warnings, baselines, socket/process/log/registry parsers).
- `rules.json`: all detection patterns and thresholds in one editable file.
- New scripts: `triage_all.py`, `log_forwarder.py`, `ioc_sweep.py`, `hash_reputation.py`,
  `process_tree_audit.py`, `deleted_binary_check.py`, `ld_preload_check.py`, `account_audit.py`,
  `ssh_key_audit.py`, `suid_audit.py`, `wmi_persistence_audit.py`, `defender_status.py`,
  `powershell_logging_audit.py`.
- Beacon detection by connection timing in `network_beacon_watch.py` (`--samples`, `--interval`).
- Baseline support in `port_watch.py`, `startup_audit.py` and `scheduled_task_audit.py`.
- Test suite (pytest), ruff configuration and GitHub Actions CI on Linux and Windows.

### Changed
- `user_activity_audit.py` merged into `log_triage.py`, `scheduled_job_diff.py` into
  `scheduled_task_audit.py`, `autorun_diff.py` into `startup_audit.py`; the old names are wrappers.
  Baselines written by the old diff scripts must be recreated.
- `system_info.py` and `serviceup.py` rewritten: argparse, no `shell=True`, one failing section no
  longer loses the report, shell history is opt-in, reports are written with 0600 permissions.
- Windows event logs are read through Get-WinEvent structured fields, so parsing works on any
  Windows display language; Windows sockets come from Get-NetTCPConnection (netstat as fallback).

### Fixed
- `network_beacon_watch.py` reported Recv-Q ("0") as the destination on Linux, and the local
  address for UDP rows on Windows.
- Missing `ss`/`netstat` crashed `port_watch.py`/`network_beacon_watch.py` instead of falling back.
- `log_triage.py`/`user_activity_audit.py` never matched Windows events (`Event ID:` format) and read
  the oldest events; Linux ignored journald and rotated logs.
- `file_hash_audit.py` crashed on unreadable files and reported new files as CHANGED.
- `scheduled_job_diff.py` diffs were always noisy because they included next/last run times.
- `process_monitor.py` flagged `launchd`, `rsync`, `vncserver`, ... because of substring matching.
- `serviceup.py` recorded failed units under the name `●`, had a wrong header comment and never
  identified who stopped a service.
- `system_info.py` ran `net user` for words like "The" and "command", used `wmic` (removed in recent
  Windows), wrote `secedit` output to the working directory and missed dash's "not found" message.
- `browser_download_audit.py` scanned the Windows Downloads folder twice.
- `usb_device_audit.py` relied on `wmic` and root-only `dmesg`.
