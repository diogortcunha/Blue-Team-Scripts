"""Shared helpers for Blue-Team-Scripts.

Every script in this folder imports this module, so copy the whole folder (or at
least the script, ``btcommon.py`` and ``rules.json``) to the host being triaged.

Standard library only; Python 3.9+.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX = SYSTEM == "Linux"
IS_POSIX = os.name == "posix"

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SEVERITIES = ("info", "low", "medium", "high")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

RULES_PATH = Path(__file__).with_name("rules.json")
ALLOWLIST_PATH = Path(__file__).with_name("allowlist.json")
PRIV_WARNING = "not running as root/Administrator: some data will be missing"


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------


@dataclass
class CmdResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int | None = None

    @property
    def output(self) -> str:
        """stdout when the command succeeded, otherwise whatever it printed."""
        return self.stdout if self.ok else (self.stdout or self.stderr)

    def lines(self) -> list[str]:
        return self.stdout.splitlines() if self.ok else []


def run(cmd: list[str], timeout: int = 120, input_text: str | None = None, encoding: str | None = None) -> CmdResult:
    """Run a command without a shell. Never raises for missing tools or timeouts.

    Windows console tools write in the OEM code page (e.g. cp850), not the ANSI one
    Python would assume, so that is the default there.
    """
    if encoding is None and IS_WINDOWS:
        encoding = "oem"
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding=encoding,
            errors="replace",
            check=False,
            timeout=timeout,
            input=input_text,
        )
    except FileNotFoundError:
        return CmdResult(False, "", f"command not found: {cmd[0]}")
    except PermissionError as exc:
        return CmdResult(False, "", f"permission denied running {cmd[0]}: {exc}")
    except subprocess.TimeoutExpired:
        return CmdResult(False, "", f"timed out after {timeout}s: {' '.join(cmd)}")
    except OSError as exc:
        return CmdResult(False, "", f"could not run {cmd[0]}: {exc}")
    return CmdResult(result.returncode == 0, result.stdout.strip(), result.stderr.strip(), result.returncode)


def run_first(*cmds: list[str], timeout: int = 120) -> CmdResult:
    """Run the first command whose binary exists and succeeds; return the last failure otherwise."""
    last = CmdResult(False, "", "none of the commands are available: " + ", ".join(c[0] for c in cmds))
    for cmd in cmds:
        if not shutil.which(cmd[0]):
            continue
        last = run(cmd, timeout=timeout)
        if last.ok:
            return last
    return last


def run_powershell(script: str, timeout: int = 180) -> CmdResult:
    exe = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
    prefix = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ProgressPreference = 'SilentlyContinue'; "
    return run([exe, "-NoProfile", "-NonInteractive", "-Command", prefix + script], timeout=timeout, encoding="utf-8")


def powershell_json(script: str, timeout: int = 180) -> tuple[list[dict[str, Any]], str | None]:
    """Run PowerShell, convert the pipeline output to JSON and return (rows, error)."""
    result = run_powershell(f"{script} | ConvertTo-Json -Depth 4 -Compress", timeout=timeout)
    if not result.ok:
        message = (result.stderr or result.stdout or "PowerShell command failed").strip().splitlines()
        return [], message[0] if message else "PowerShell command failed"
    if not result.stdout:
        return [], None
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return [], f"could not parse PowerShell output: {exc}"
    if isinstance(data, dict):
        data = [data]
    return [row for row in data if isinstance(row, dict)], None


# ---------------------------------------------------------------------------
# Privileges, hosts and users
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def hostname() -> str:
    return socket.gethostname()


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def home_dirs() -> list[Path]:
    """Home directories of every local account that has one (including root)."""
    homes: list[Path] = []
    if IS_POSIX:
        try:
            import pwd

            for entry in pwd.getpwall():
                home = Path(entry.pw_dir)
                if entry.pw_dir not in ("", "/", "/nonexistent") and is_dir(home):
                    homes.append(home)
        except Exception:
            pass
    elif IS_WINDOWS:
        users_root = Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
        try:
            for child in users_root.iterdir():
                if is_dir(child) and child.name.lower() not in {"public", "default", "default user", "all users"}:
                    homes.append(child)
        except OSError:
            pass
    current = Path.home()
    if is_dir(current):
        homes.append(current)
    return dedupe_paths(homes)


def dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if IS_WINDOWS:
            key = key.lower()
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


def is_file(path: Path | str) -> bool:
    """``Path.is_file`` that returns False instead of raising on permission errors."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def is_dir(path: Path | str) -> bool:
    try:
        return stat.S_ISDIR(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def read_text(path: Path | str, max_bytes: int | None = None) -> str | None:
    """Read a text file, returning None when it is missing or unreadable."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(max_bytes) if max_bytes else handle.read()
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def read_lines_any(path: Path) -> list[str]:
    """Read a (possibly gzip-compressed) log file."""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                return handle.read().splitlines()
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, EOFError, gzip.BadGzipFile):
        return []


def sha256_file(path: Path | str) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


SKIP_WALK_DIRS = {"/proc", "/sys", "/dev", "/run"}


def walk_files(
    roots: Iterable[Path | str],
    errors: list[str] | None = None,
    same_device: bool = False,
    skip_dirs: Iterable[str] = (),
) -> Iterator[Path]:
    """Yield regular files and symlinks below ``roots`` without following directory symlinks.

    Unreadable directories are recorded in ``errors`` instead of raising.
    """
    skip = {str(Path(d)) for d in skip_dirs}
    for raw in roots:
        root = Path(raw)
        try:
            root_stat = root.lstat()
        except OSError as exc:
            if errors is not None:
                errors.append(f"{root}: {exc.strerror or exc}")
            continue
        if not stat.S_ISDIR(root_stat.st_mode):
            yield root
            continue

        def onerror(exc: OSError) -> None:
            if errors is not None:
                errors.append(f"{exc.filename}: {exc.strerror or exc}")

        for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
            kept = []
            for name in dirnames:
                full = os.path.join(dirpath, name)
                if full in skip:
                    continue
                if same_device:
                    try:
                        if os.lstat(full).st_dev != root_stat.st_dev:
                            continue
                    except OSError:
                        continue
                kept.append(name)
            dirnames[:] = kept
            for name in filenames:
                yield Path(dirpath) / name


def file_mtime(path: Path) -> datetime | None:
    """Newest of mtime and ctime: ctime cannot be set back with ``touch`` on POSIX systems."""
    try:
        st = path.stat()
    except OSError:
        return None
    newest = st.st_mtime if IS_WINDOWS else max(st.st_mtime, st.st_ctime)
    return datetime.fromtimestamp(newest)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

_rules_cache: dict[str, dict[str, Any]] = {}


def read_resource(path: Path) -> str:
    """Read a data file that sits next to the scripts, also when they run from a .pyz archive."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        loader = globals().get("__loader__")
        if loader is not None and hasattr(loader, "get_data"):
            return loader.get_data(str(path)).decode("utf-8")
        raise


def load_rules(section: str, path: str | Path | None = None) -> dict[str, Any]:
    """Return one section of rules.json (detection patterns and thresholds)."""
    rules_file = Path(path) if path else RULES_PATH
    key = str(rules_file)
    if key not in _rules_cache:
        try:
            _rules_cache[key] = json.loads(read_resource(rules_file))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"error: cannot load rules file {rules_file}: {exc}") from exc
    return _rules_cache[key].get(section, {})


@dataclass
class AllowEntry:
    reason: str
    match: re.Pattern[str]
    tool: str = "*"
    check: str = "*"
    host: re.Pattern[str] | None = None


class Allowlist:
    """Known-good findings to downgrade to info.

    Entries come from ``allowlist.json`` next to the scripts (if present) and any ``--allowlist``
    files. Each entry: ``{"match": regex on the message, "reason": "...", "tool": "...",
    "check": "...", "host": regex, "expires": "YYYY-MM-DD"}``; only ``match`` and ``reason`` are
    required. Expired entries are ignored so exceptions get reviewed.
    """

    def __init__(self, entries: list[AllowEntry] | None = None, errors: list[str] | None = None) -> None:
        self.entries = entries or []
        self.errors = errors or []

    @classmethod
    def load(cls, extra_files: Iterable[str] = (), default: Path | None = None) -> Allowlist:
        default = ALLOWLIST_PATH if default is None else default
        entries: list[AllowEntry] = []
        errors: list[str] = []
        sources: list[tuple[str, str]] = []
        try:
            sources.append((str(default), read_resource(default)))
        except OSError:
            pass
        for name in extra_files:
            try:
                sources.append((name, Path(name).read_text(encoding="utf-8")))
            except OSError as exc:
                errors.append(f"cannot read allowlist {name}: {exc}")
        today = datetime.now().date().isoformat()
        for name, text in sources:
            try:
                raw = json.loads(text)
            except json.JSONDecodeError as exc:
                errors.append(f"invalid allowlist {name}: {exc}")
                continue
            items = raw.get("allowlist", []) if isinstance(raw, dict) else raw
            for index, item in enumerate(items if isinstance(items, list) else []):
                if not isinstance(item, dict) or "match" not in item or "reason" not in item:
                    errors.append(f"{name} entry {index}: needs 'match' and 'reason'")
                    continue
                if item.get("expires") and str(item["expires"]) < today:
                    errors.append(f"{name} entry {index} expired on {item['expires']}: {item['reason']}")
                    continue
                try:
                    entries.append(AllowEntry(
                        str(item["reason"]),
                        re.compile(item["match"], re.IGNORECASE),
                        item.get("tool", "*"),
                        item.get("check", "*"),
                        re.compile(item["host"], re.IGNORECASE) if item.get("host") else None,
                    ))
                except re.error as exc:
                    errors.append(f"{name} entry {index}: bad regex: {exc}")
        return cls(entries, errors)

    def match(self, tool: str, check: str, message: str, host: str | None = None) -> str | None:
        host = host or hostname()
        for entry in self.entries:
            if entry.tool not in ("*", tool) or entry.check not in ("*", check):
                continue
            if entry.host is not None and not entry.host.search(host):
                continue
            if entry.match.search(message):
                return entry.reason
        return None


def compile_patterns(patterns: Iterable[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def first_match(text: str, patterns: Iterable[re.Pattern[str]]) -> str | None:
    for pattern in patterns:
        if pattern.search(text):
            return pattern.pattern
    return None


# ---------------------------------------------------------------------------
# Findings and reports
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    check: str
    severity: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)


class Report:
    """Collects findings and prints them as text or JSON with a consistent exit code.

    Exit codes: 0 = nothing above ``info``, 1 = at least one low/medium/high finding,
    2 = the check could not run (see ``fail``).
    """

    def __init__(self, tool: str, args: argparse.Namespace, needs_admin: bool = False) -> None:
        self.tool = tool
        self.args = args
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.fatal = False
        self.allowlisted = 0
        self.allowlist = Allowlist.load(getattr(args, "allowlist", None) or [])
        self.errors.extend(self.allowlist.errors)
        self._printed: set[str] = set()
        self.admin = is_admin()
        if needs_admin and not self.admin:
            msg = PRIV_WARNING
            self.errors.append(msg)
            self._printed.add(msg)
            print(f"warning: {msg}", file=sys.stderr)

    def add(self, check: str, severity: str, message: str, **data: Any) -> Finding:
        if severity not in SEVERITY_RANK:
            raise ValueError(f"unknown severity {severity!r}")
        if severity != "info":
            reason = self.allowlist.match(self.tool, check, message)
            if reason:
                self.allowlisted += 1
                data = {**data, "allowlisted": reason, "original_severity": severity}
                message = f"{message}  (allowlisted: {reason})"
                severity = "info"
        finding = Finding(check, severity, message, {k: v for k, v in data.items() if v not in (None, "")})
        self.findings.append(finding)
        return finding

    def info(self, check: str, message: str, **data: Any) -> Finding:
        return self.add(check, "info", message, **data)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def fail(self, message: str) -> None:
        self.errors.append(message)
        self.fatal = True

    def require(self, *systems: str) -> bool:
        if SYSTEM in systems:
            return True
        self.fail(f"{self.tool} only supports {', '.join(systems)} (this host runs {SYSTEM})")
        return False

    def exit_code(self) -> int:
        if self.fatal:
            return EXIT_ERROR
        if any(SEVERITY_RANK[f.severity] > 0 for f in self.findings):
            return EXIT_FINDINGS
        return EXIT_CLEAN

    def to_dict(self) -> dict[str, Any]:
        min_rank = SEVERITY_RANK[getattr(self.args, "min_severity", "info")]
        return {
            "tool": self.tool,
            "host": hostname(),
            "os": platform.platform(),
            "timestamp": now_iso(),
            "privileged": self.admin,
            "exit_code": self.exit_code(),
            "summary": {sev: sum(1 for f in self.findings if f.severity == sev) for sev in SEVERITIES},
            "allowlisted": self.allowlisted,
            "findings": [asdict(f) for f in self.findings if SEVERITY_RANK[f.severity] >= min_rank],
            "errors": self.errors,
        }

    def emit(self) -> int:
        if getattr(self.args, "json", False):
            print(json.dumps(self.to_dict(), indent=2, default=str))
        else:
            self._print_text()
        return self.exit_code()

    def _print_text(self) -> None:
        min_rank = SEVERITY_RANK[getattr(self.args, "min_severity", "info")]
        current_check = None
        for finding in self.findings:
            if SEVERITY_RANK[finding.severity] < min_rank:
                continue
            if finding.check != current_check:
                if current_check is not None:
                    print()
                print(f"== {finding.check} ==")
                current_check = finding.check
            prefix = "" if finding.severity == "info" else f"[{finding.severity.upper()}] "
            print(f"{prefix}{finding.message}")
        flagged = [f for f in self.findings if f.severity != "info"]
        if self.findings:
            print()
        counts = ", ".join(f"{sev}={sum(1 for f in flagged if f.severity == sev)}" for sev in SEVERITIES[1:])
        extra = f", {self.allowlisted} allowlisted" if self.allowlisted else ""
        print(f"{self.tool}: {len(flagged)} flagged finding(s) ({counts}{extra})")
        for error in self.errors:
            if error not in self._printed:
                print(f"error: {error}", file=sys.stderr)


def make_parser(description: str, baseline: bool = False) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="info",
        help="Hide findings below this severity (default: info)",
    )
    parser.add_argument("--rules", help="Alternative rules.json file")
    parser.add_argument(
        "--allowlist",
        action="append",
        metavar="FILE",
        help="Extra allowlist JSON file of known-good findings (repeatable; allowlist.json is always read)",
    )
    if baseline:
        parser.add_argument("--write-baseline", metavar="FILE", help="Save the current snapshot to a JSON baseline")
        parser.add_argument("--baseline", metavar="FILE", help="Compare the current snapshot against a JSON baseline")
    return parser


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


def save_baseline(path: str, tool: str, items: dict[str, Any]) -> None:
    payload = {"tool": tool, "version": 2, "host": hostname(), "created": now_iso(), "items": items}
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def load_baseline(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "items" in data and isinstance(data["items"], dict):
        return data["items"]
    if isinstance(data, list):  # v1 format: sorted list of strings
        return {item: "" for item in data}
    if isinstance(data, dict):  # v1 file_hash_audit format: {path: sha256}
        return data
    raise ValueError(f"unrecognised baseline format in {path}")


def diff_items(baseline: dict[str, Any], current: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """Return (added, removed, changed) keys."""
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    changed = sorted(key for key in set(current) & set(baseline) if current[key] != baseline[key])
    return added, removed, changed


def handle_baseline(
    report: Report,
    items: dict[str, Any],
    check: str = "baseline",
    added_severity: str = "medium",
    removed_severity: str = "low",
    changed_severity: str = "medium",
) -> bool:
    """Apply --write-baseline/--baseline. Returns True when a diff was performed."""
    args = report.args
    if getattr(args, "write_baseline", None):
        save_baseline(args.write_baseline, report.tool, items)
        report.info(check, f"wrote {len(items)} entries to {args.write_baseline}")
    if not getattr(args, "baseline", None):
        return False
    try:
        baseline = load_baseline(args.baseline)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report.fail(f"cannot read baseline {args.baseline}: {exc}")
        return True
    added, removed, changed = diff_items(baseline, items)
    for key in added:
        report.add(check, added_severity, f"ADDED {key}", key=key, value=items[key])
    for key in removed:
        report.add(check, removed_severity, f"REMOVED {key}", key=key, value=baseline[key])
    for key in changed:
        report.add(check, changed_severity, f"CHANGED {key}", key=key, old=baseline[key], new=items[key])
    if not (added or removed or changed):
        report.info(check, f"no differences against {args.baseline} ({len(items)} entries)")
    return True


# ---------------------------------------------------------------------------
# Sockets
# ---------------------------------------------------------------------------


@dataclass
class Socket:
    proto: str
    state: str
    local_addr: str
    local_port: int | None
    remote_addr: str
    remote_port: int | None
    pid: int | None = None
    process: str = ""

    @property
    def listening(self) -> bool:
        return self.state in {"LISTEN", "LISTENING"} or (self.proto.startswith("udp") and self.state in {"UNCONN", ""})


def split_host_port(value: str) -> tuple[str, int | None]:
    """Split ``1.2.3.4:80``, ``[::1]:80``, ``*:68``, ``0.0.0.0%eth0:68`` or ``*.*``."""
    value = value.strip()
    if value.startswith("["):
        host, _, port = value[1:].partition("]")
        port = port.lstrip(":")
    elif value.count(":") > 1 and "." not in value.rsplit(":", 1)[-1]:
        host, _, port = value.rpartition(":")
    else:
        host, _, port = value.rpartition(":")
        if not host:
            host, port = value, ""
    host = host.split("%", 1)[0]
    try:
        port_num: int | None = int(port)
    except ValueError:
        port_num = None
    return host, port_num


_SS_PROCESS = re.compile(r'\("([^"]*)",pid=(\d+)')


def parse_ss(output: str) -> list[Socket]:
    """Parse ``ss -H -tunap`` output (Netid State Recv-Q Send-Q Local Peer [Process])."""
    sockets: list[Socket] = []
    for line in output.splitlines():
        parts = line.split(None, 6)
        if len(parts) < 6 or parts[0] not in {"tcp", "udp", "tcp6", "udp6"}:
            continue
        local, lport = split_host_port(parts[4])
        remote, rport = split_host_port(parts[5])
        pid, name = None, ""
        if len(parts) == 7:
            match = _SS_PROCESS.search(parts[6])
            if match:
                name, pid = match.group(1), int(match.group(2))
        sockets.append(Socket(parts[0], parts[1], local, lport, remote, rport, pid, name))
    return sockets


def parse_netstat_linux(output: str) -> list[Socket]:
    """Parse ``netstat -tunap`` output; UDP rows may have no State column."""
    sockets: list[Socket] = []
    for line in output.splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith(("tcp", "udp")) or len(parts) < 5:
            continue
        rest = parts[5:]
        state = ""
        if rest and not re.match(r"^(\d+/|-$)", rest[0]):
            state = rest.pop(0)
        pid, name = None, ""
        if rest and "/" in rest[0]:
            pid_text, _, name = rest[0].partition("/")
            pid = int(pid_text) if pid_text.isdigit() else None
        local, lport = split_host_port(parts[3])
        remote, rport = split_host_port(parts[4])
        proto = parts[0].replace("6", "")
        sockets.append(Socket(proto, state, local, lport, remote, rport, pid, name))
    return sockets


def parse_netstat_windows(output: str) -> list[Socket]:
    """Parse ``netstat -ano``: ``TCP local remote STATE PID`` / ``UDP local *:* PID``."""
    sockets: list[Socket] = []
    for line in output.splitlines():
        parts = line.split()
        if not parts or parts[0].upper() not in {"TCP", "UDP"}:
            continue
        proto = parts[0].lower()
        if proto == "tcp" and len(parts) >= 5:
            state, pid_text = parts[3], parts[4]
        elif proto == "udp" and len(parts) >= 4:
            state, pid_text = "", parts[3]
        else:
            continue
        local, lport = split_host_port(parts[1])
        remote, rport = split_host_port(parts[2])
        pid = int(pid_text) if pid_text.isdigit() else None
        sockets.append(Socket(proto, state, local, lport, remote, rport, pid))
    return sockets


def windows_process_names() -> dict[int, str]:
    result = run(["tasklist", "/fo", "csv", "/nh"])
    names: dict[int, str] = {}
    import csv

    for row in csv.reader(result.lines()):
        if len(row) >= 2 and row[1].isdigit():
            names[int(row[1])] = row[0]
    return names


def _camel_to_state(value: str) -> str:
    """``TimeWait`` -> ``TIME_WAIT``, ``Listen`` -> ``LISTEN`` (Get-NetTCPConnection states)."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).upper()


def windows_sockets_cim() -> tuple[list[Socket], str | None]:
    """Sockets from Get-NetTCPConnection/Get-NetUDPEndpoint (states are not localized)."""
    rows, error = powershell_json(
        "@(Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object @{n='Proto';e={'tcp'}},LocalAddress,LocalPort,"
        "RemoteAddress,RemotePort,@{n='State';e={[string]$_.State}},OwningProcess) + "
        "@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object @{n='Proto';e={'udp'}},LocalAddress,LocalPort,"
        "@{n='RemoteAddress';e={'*'}},@{n='RemotePort';e={$null}},@{n='State';e={''}},OwningProcess)"
    )
    if error or not rows:
        return [], error or "no sockets returned"
    sockets = [
        Socket(
            row.get("Proto") or "tcp",
            _camel_to_state(row.get("State") or ""),
            row.get("LocalAddress") or "",
            row.get("LocalPort"),
            row.get("RemoteAddress") or "",
            row.get("RemotePort"),
            row.get("OwningProcess"),
        )
        for row in rows
    ]
    return sockets, None


def list_sockets() -> tuple[list[Socket], str | None]:
    """Return (sockets, error) for TCP and UDP on Linux or Windows."""
    if IS_WINDOWS:
        sockets, _ = windows_sockets_cim()
        if sockets:
            names = windows_process_names()
            for sock in sockets:
                if sock.pid is not None:
                    sock.process = names.get(sock.pid, "")
            return sockets, None
        result = run(["netstat", "-ano"])
        if not result.ok:
            return [], result.stderr or "netstat failed"
        sockets = parse_netstat_windows(result.stdout)
        names = windows_process_names()
        for sock in sockets:
            if sock.pid is not None:
                sock.process = names.get(sock.pid, "")
        return sockets, None
    if shutil.which("ss"):
        result = run(["ss", "-H", "-tunap"])
        if result.ok:
            return parse_ss(result.stdout), None
    result = run(["netstat", "-tunap"])
    if result.ok or result.stdout:
        return parse_netstat_linux(result.stdout), None
    return [], result.stderr or "neither ss nor netstat is available"


def fmt_endpoint(addr: str, port: int | None) -> str:
    host = f"[{addr}]" if ":" in addr else addr
    return f"{host}:{port if port is not None else '*'}"


def is_unspecified(addr: str) -> bool:
    return addr in {"", "*", "0.0.0.0", "::", "0:0:0:0:0:0:0:0"}


def is_loopback(addr: str) -> bool:
    return addr.startswith("127.") or addr in {"::1", "localhost"}


def is_private(addr: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------


@dataclass
class Process:
    pid: int
    ppid: int | None
    name: str
    user: str = ""
    cmdline: str = ""
    exe: str = ""
    cpu: float | None = None
    mem: float | None = None


def normalize_name(name: str) -> str:
    name = os.path.basename(name.strip().replace("\\", "/")).lower()
    return name[:-4] if name.endswith(".exe") else name


def list_processes() -> tuple[list[Process], str | None]:
    if IS_WINDOWS:
        rows, error = powershell_json(
            "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,"
            "ExecutablePath,WorkingSetSize"
        )
        procs = [
            Process(
                pid=int(row.get("ProcessId") or 0),
                ppid=row.get("ParentProcessId"),
                name=row.get("Name") or "",
                cmdline=row.get("CommandLine") or "",
                exe=row.get("ExecutablePath") or "",
                mem=round((row.get("WorkingSetSize") or 0) / 1024 / 1024, 1),
            )
            for row in rows
        ]
        return procs, error
    result = run(["ps", "-eo", "pid=,ppid=,user:32=,pcpu=,pmem=,args="])
    if not result.ok:
        return [], result.stderr or "ps failed"
    return parse_ps(result.stdout), None


def parse_ps(output: str) -> list[Process]:
    """Parse ``ps -eo pid=,ppid=,user:32=,pcpu=,pmem=,args=`` (args last, so spaces are safe)."""
    procs: list[Process] = []
    for line in output.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        args = parts[5] if len(parts) == 6 else ""
        name = ""
        exe = ""
        if IS_LINUX:
            name = (read_text(f"/proc/{pid}/comm") or "").strip()
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                exe = ""
        if not name:
            first = args.split(" ", 1)[0] if args else ""
            name = os.path.basename(first.strip("[]")) or first
        try:
            cpu, mem = float(parts[3]), float(parts[4])
        except ValueError:
            cpu = mem = None
        procs.append(Process(pid, int(parts[1]) if parts[1].isdigit() else None, name, parts[2], args, exe, cpu, mem))
    return procs


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")
_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:?\d{2}|Z)?")
_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_log_time(line: str, now: datetime | None = None) -> datetime | None:
    """Timestamp of a syslog (``Sep 29 10:00:00``) or ISO-8601 log line, as naive local time."""
    now = now or datetime.now()
    match = _ISO_TS.match(line)
    if match:
        text = match.group(1).replace(" ", "T")
        tz = match.group(3)
        try:
            if tz:
                tz = "+00:00" if tz == "Z" else (tz if ":" in tz else f"{tz[:3]}:{tz[3:]}")
                return datetime.fromisoformat(text + tz).astimezone().replace(tzinfo=None)
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    match = _SYSLOG_TS.match(line)
    if match and match.group(1) in _MONTHS:
        month = _MONTHS[match.group(1)]
        try:
            stamp = datetime(now.year, month, int(match.group(2)), int(match.group(3)), int(match.group(4)), int(match.group(5)))
        except ValueError:
            return None
        if stamp > now + timedelta(days=1):  # e.g. a December line read in January
            stamp = stamp.replace(year=now.year - 1)
        return stamp
    return None


def auth_log_lines(days: int) -> tuple[list[str], str]:
    """Authentication log lines from the last ``days`` days on Linux/BSD, plus the source used."""
    cutoff = datetime.now() - timedelta(days=days)
    for base in (Path("/var/log/auth.log"), Path("/var/log/secure")):
        if not base.exists():
            continue
        files = sorted(base.parent.glob(base.name + "*"), key=lambda p: p.stat().st_mtime if p.exists() else 0)
        lines: list[str] = []
        for path in files:
            try:
                if datetime.fromtimestamp(path.stat().st_mtime) < cutoff:
                    continue
            except OSError:
                continue
            lines.extend(read_lines_any(path))
        kept = [line for line in lines if (ts := parse_log_time(line)) is None or ts >= cutoff]
        if kept or lines:
            return kept, str(base)
    if shutil.which("journalctl"):
        result = run(
            [
                "journalctl", "--no-pager", "-q", "-o", "short-iso", "--since", f"-{days}d",
                "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10",
            ],
            timeout=180,
        )
        if result.ok:
            return result.stdout.splitlines(), "journalctl (auth/authpriv)"
    return [], ""


@dataclass
class WinEvent:
    id: int
    time: str
    log: str
    summary: str
    data: dict[str, str] = field(default_factory=dict)
    level: str = ""

    def field(self, name: str) -> str:
        """An EventData/UserData field such as TargetUserName, IpAddress or LogonType.

        These names are the same on every Windows language, unlike the rendered message.
        """
        value = self.data.get(name) or ""
        return "" if value == "-" else str(value)


def windows_events(log: str, ids: Iterable[int], days: int, max_events: int = 2000) -> tuple[list[WinEvent], str | None]:
    id_list = ",".join(str(i) for i in ids)
    script = (
        f"$start=(Get-Date).AddDays(-{int(days)}); $r = @(try {{ "
        f"Get-WinEvent -FilterHashtable @{{LogName='{log}'; Id={id_list}; StartTime=$start}} "
        f"-MaxEvents {int(max_events)} -ErrorAction Stop | "
        "Select-Object Id,@{n='Time';e={$_.TimeCreated.ToString('o')}},LevelDisplayName,"
        "@{n='Summary';e={($_.Message -split \"`r?`n\")[0]}},"
        "@{n='Data';e={$x=[xml]$_.ToXml(); $h=@{}; "
        "foreach($d in $x.Event.EventData.Data){ if($d.Name){ $h[$d.Name]=[string]$d.'#text' } }; "
        "if($x.Event.UserData){ foreach($n in $x.Event.UserData.FirstChild.ChildNodes){ $h[$n.LocalName]=[string]$n.InnerText } }; $h}}"
        # NoMatchingEventsFound is not an error; the id is the same in every language.
        " } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { "
        "[Console]::Error.WriteLine($_.FullyQualifiedErrorId + ': ' + $_.Exception.Message); exit 1 } }); $r"
    )
    rows, error = powershell_json(script, timeout=300)
    if error and "UnauthorizedAccess" in error:
        error = f"cannot read the {log} log (run as Administrator)"
    events = [
        WinEvent(
            int(row.get("Id") or 0),
            row.get("Time") or "",
            log,
            row.get("Summary") or "",
            {k: str(v) for k, v in (row.get("Data") or {}).items()} if isinstance(row.get("Data"), dict) else {},
            row.get("LevelDisplayName") or "",
        )
        for row in rows
    ]
    return events, error


# ---------------------------------------------------------------------------
# Windows registry
# ---------------------------------------------------------------------------

_REG_VALUE = re.compile(r"^\s{4}(.*?)\s{4}(REG_[A-Z_]+)(?:\s{4}(.*))?$")


def parse_reg_query(output: str) -> dict[str, dict[str, str]]:
    """Parse ``reg query`` output into {key: {value_name: data}}."""
    keys: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in output.splitlines():
        if not line.strip():
            continue
        if line.startswith("HKEY_"):
            current = line.strip()
            keys.setdefault(current, {})
            continue
        match = _REG_VALUE.match(line)
        if match and current is not None:
            keys[current][match.group(1)] = (match.group(3) or "").strip()
    return keys


def reg_query(key: str, recursive: bool = False) -> dict[str, dict[str, str]]:
    cmd = ["reg", "query", key] + (["/s"] if recursive else [])
    result = run(cmd)
    return parse_reg_query(result.stdout) if result.ok else {}

