# Blue-Team-Scripts
Python scripts for blue-team monitoring, host triage, and basic defensive audits.

## What’s Included

- `system_info.py` - system and security snapshot collector
- `serviceup.py` - service status monitoring and restart helper
- `process_monitor.py` - process snapshot and suspicious name triage
- `log_triage.py` - auth and security log triage
- `startup_audit.py` - persistence and startup location audit
- `port_watch.py` - listening port and connection inspection
- `file_hash_audit.py` - SHA-256 integrity baselines and comparisons
- `scheduled_task_audit.py` - scheduled task and cron review
- `usb_device_audit.py` - removable device inventory
- `suspicious_web_root_scan.py` - recent and suspicious web root scan
- `network_beacon_watch.py` - repeated outbound destination review
- `user_activity_audit.py` - recent user and authentication activity
- `scheduled_job_diff.py` - scheduled job snapshot and diff tool
- `autorun_diff.py` - persistence and autorun diff tool
- `dns_cache_audit.py` - local DNS cache and resolver audit
- `browser_download_audit.py` - recent download review
- `hashwatch_daemon.py` - continuous file hash watch

## Script Reference

- `system_info.py`: collect host details, services, ports, users, firewall state, and other defensive data.
- `serviceup.py`: watch service status and optionally restart stopped services.
- `process_monitor.py`: list running processes and flag common suspicious binaries.
- `log_triage.py`: summarize authentication and security-related log entries.
- `startup_audit.py`: inspect common persistence locations such as autoruns, cron, and startup files.
- `port_watch.py`: show listening ports and active connections.
- `file_hash_audit.py`: create or compare SHA-256 baselines for files and directories.
- `scheduled_task_audit.py`: review cron jobs and scheduled tasks for suspicious execution.
- `usb_device_audit.py`: inspect removable media and recent USB-related activity.
- `suspicious_web_root_scan.py`: scan common web roots for recent or suspicious web files.
- `network_beacon_watch.py`: summarize outbound connections and repeated destinations.
- `user_activity_audit.py`: summarize recent user and authentication activity.
- `scheduled_job_diff.py`: snapshot and compare cron jobs and scheduled tasks.
- `autorun_diff.py`: snapshot and compare common autorun and persistence locations.
- `dns_cache_audit.py`: inspect local DNS cache or resolver state.
- `browser_download_audit.py`: review recent browser download locations for risky files.
- `hashwatch_daemon.py`: continuously monitor files for hash changes.

## Usage

Run scripts directly with Python:

```bash
python3 Python-Scripts/system_info.py
python3 Python-Scripts/process_monitor.py
python3 Python-Scripts/file_hash_audit.py /etc /usr/bin
```

Some scripts are OS-specific and may require elevated privileges depending on what they inspect.

## Example Commands

```bash
python3 Python-Scripts/system_info.py
python3 Python-Scripts/serviceup.py
python3 Python-Scripts/process_monitor.py --limit 20
python3 Python-Scripts/log_triage.py --limit 25
python3 Python-Scripts/startup_audit.py
python3 Python-Scripts/port_watch.py
python3 Python-Scripts/file_hash_audit.py /etc /usr/bin --write-baseline baseline.json
python3 Python-Scripts/file_hash_audit.py /etc /usr/bin --baseline baseline.json
python3 Python-Scripts/scheduled_task_audit.py
python3 Python-Scripts/usb_device_audit.py
python3 Python-Scripts/suspicious_web_root_scan.py --days 7
python3 Python-Scripts/network_beacon_watch.py --limit 20
python3 Python-Scripts/user_activity_audit.py --limit 25
python3 Python-Scripts/scheduled_job_diff.py --write-baseline jobs.json
python3 Python-Scripts/scheduled_job_diff.py --baseline jobs.json
python3 Python-Scripts/autorun_diff.py --write-baseline autoruns.json
python3 Python-Scripts/autorun_diff.py --baseline autoruns.json
python3 Python-Scripts/dns_cache_audit.py
python3 Python-Scripts/browser_download_audit.py --days 7
python3 Python-Scripts/hashwatch_daemon.py /etc/ssh/sshd_config --once
python3 Python-Scripts/hashwatch_daemon.py /etc --interval 30
```

## Notes

- The scripts are intentionally lightweight and mostly dependency-free.
- Output is meant for quick triage and follow-up investigation.
- Not every check will work on every system because permissions and tooling vary by OS.

