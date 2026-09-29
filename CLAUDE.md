# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Blue-team host triage and defensive audit scripts for Linux and Windows, in `Python-Scripts/`. Standard library only, Python 3.9+, run directly (no packaging). `README.md` documents every script; update its tables and `CHANGELOG.md` when adding or changing scripts.

## Commands

```bash
python3 Python-Scripts/<script>.py [--json] [--min-severity low]   # run one check
python3 Python-Scripts/triage_all.py --list                          # checks that apply to this OS
python -m pytest                                                     # all tests
python -m pytest tests/test_scripts.py::test_log_triage_detects_bruteforce_and_success_after_it
ruff check Python-Scripts tests tools                                # lint (config in pyproject.toml)
python3 tools/build_pyz.py                                           # single-file dist/blue-team-scripts.pyz
```

Tests import scripts as modules via `tests/conftest.py`, which puts `Python-Scripts/` on `sys.path`. CI runs Ubuntu and Windows × Python 3.9 and 3.13, so avoid syntax/APIs newer than 3.9 (e.g. backslashes inside f-string expressions) and mark POSIX-permission tests with `skipif`.

## Architecture

- **`btcommon.py`** is imported by every script (so the folder must be copied as a whole). It provides:
  - `run()` / `run_first()` / `run_powershell()` / `powershell_json()`: never raise on missing tools, timeouts or permissions; Windows console output is decoded as OEM, PowerShell output as UTF-8.
  - `Report` + `make_parser()`: the standard CLI (`--json`, `--min-severity`, `--rules`, optional `--write-baseline/--baseline`) and exit codes (0 clean, 1 findings above info, 2 `report.fail()`). Findings are `(check, severity, message, data)` with severities `info/low/medium/high`; `info` is inventory and does not affect the exit code.
  - `Allowlist`: `Report.add()` downgrades findings matching `allowlist.json` / `--allowlist` entries to `info` (with `allowlisted` in data). Streaming tools call `Allowlist.match()` themselves.
  - `read_resource()`: data files (`rules.json`, `allowlist.json`) are read through it so they also load from inside the `.pyz`.
  - `handle_baseline()`: baselines are `{stable key: value}` dicts; ADDED/REMOVED/CHANGED are computed by key, so keys must exclude volatile data (run times, PIDs).
  - Parsers shared across scripts: `list_sockets()` (ss/netstat/Get-NetTCPConnection), `list_processes()`, `auth_log_lines()` (auth.log/secure incl. rotated .gz, else journald), `windows_events()`, `reg_query()`.
- **`rules.json`** holds all detection data (regexes, names, ports, thresholds), loaded with `load_rules(section, args.rules)`. The shared `commands.patterns` section is used by process, cron/scheduled task and autorun checks — test new patterns against benign command lines (see `test_command_patterns`).
- **Windows localization:** never parse rendered event messages or localized tool text. `windows_events()` returns `WinEvent.data` from the event XML (`TargetUserName`, `IpAddress`, `LogonType`, ...), and PowerShell error handling keys on `FullyQualifiedErrorId`.
- Scripts may import each other's functions (`hashwatch_daemon` ← `file_hash_audit`, `system_info` ← `suspicious_web_root_scan`, `ioc_sweep` ← `dns_cache_audit`). Keep the reusable logic in pure functions (parsers, `classify`, `compare`) so it is unit-testable without the OS.
- `triage_all.py` runs checks as subprocesses with `--json` (in parallel, `tool_integrity_check` first) and renders one report; its `CHECKS` table lists each script's supported OSes and default arguments. Add new audit scripts there.
- **Single-file build:** `tools/build_pyz.py` zips every `Python-Scripts/*.py` plus data files with `tools/pyz_main.py` as `__main__`, which dispatches `python3 x.pyz <script> [args]` via `runpy`. Inside the archive `Path(__file__).parent` is the `.pyz` file itself: never glob or open sibling files directly (use `read_resource()`; `triage_all.script_command()` handles subprocesses).
- Streaming tools (`hashwatch_daemon.py`, `serviceup.py` watch mode) print one JSON object per line with `--json`; `log_forwarder.py` accepts both that and full reports.
- `user_activity_audit.py`, `scheduled_job_diff.py`, `autorun_diff.py` are deprecated wrappers around `log_triage.py`, `scheduled_task_audit.py`, `startup_audit.py`.

## Gotchas

- On Windows, antivirus quarantines web-shell test fixtures written at runtime; tests build those strings by concatenation and tolerate the files disappearing or being unreadable.
- `Path.is_file()/is_dir()` raise `PermissionError` under unreadable parents on Python 3.12+; use `btcommon.is_file()/is_dir()`.
