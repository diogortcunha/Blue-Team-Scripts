#!/usr/bin/env python3

"""Check that the system tools the other scripts rely on have not been tampered with.

On a compromised host a rootkit can replace ps, ss, netstat, tasklist... so that every other
check lies. This script:
- verifies those binaries against the package manager (dpkg --verify / rpm -V) on Linux, or
  their Authenticode signatures on Windows;
- flags tools shadowed earlier in PATH (e.g. /usr/local/bin/ps, or netstat.exe outside System32);
- flags LD_PRELOAD/LD_LIBRARY_PATH in its own environment;
- with --write-baseline/--baseline, records SHA-256 hashes of the tools and of this toolkit's
  own files, so a copy carried on a USB stick can be checked before use.
Run it first; if it reports problems, prefer a trusted live system or static binaries.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from btcommon import IS_WINDOWS, Report, handle_baseline, load_rules, make_parser, powershell_json, run, sha256_file

TRUSTED_DIRS_POSIX = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/libexec/", "/usr/lib/")
TOOLKIT_DIR = Path(__file__).resolve().parent


def usrmerge_candidates(path: str) -> list[str]:
    """Paths under which a package may have registered a file on a merged-/usr system."""
    candidates = [path]
    for a, b in (("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/")):
        if path.startswith(a):
            candidates.append(b + path[len(a):])
        elif path.startswith(b):
            candidates.append(a + path[len(b):])
    return candidates


def parse_verify_output(output: str) -> dict[str, str]:
    """Parse dpkg --verify / rpm -V lines (``??5?????? c /path``) into {path: flags}.

    Config files (``c``) are skipped: admins are expected to edit them.
    """
    changed = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[-1][0] != "/" or (len(parts[0]) < 8 and parts[0] != "missing"):
            continue
        if len(parts) == 3 and parts[1] == "c":
            continue
        changed[parts[-1]] = parts[0]
    return changed


def digest_changed(flags: str) -> bool:
    return len(flags) > 2 and flags[2] == "5"


def linux_owner(path: str) -> tuple[str, str] | None:
    """(package, path as registered) for a file, using dpkg or rpm."""
    for candidate in usrmerge_candidates(path):
        if shutil.which("dpkg"):
            result = run(["dpkg", "-S", candidate])
            if result.ok and ":" in result.stdout:
                package = result.stdout.splitlines()[0].rsplit(": ", 1)[0].split(":")[0].split(",")[0].strip()
                return package, candidate
        if shutil.which("rpm"):
            result = run(["rpm", "-qf", candidate])
            if result.ok and "not owned" not in result.stdout:
                return result.stdout.splitlines()[0].strip(), candidate
    return None


def check_linux(report: Report, tools: dict[str, str]) -> None:
    owners: dict[str, list[tuple[str, str]]] = {}
    for name, path in tools.items():
        real = os.path.realpath(path)
        if not real.startswith(TRUSTED_DIRS_POSIX):
            report.add("path shadowing", "high", f"{name} resolves to {real}, outside the system directories", tool=name, path=real)
        owner = linux_owner(real)
        if owner is None:
            report.add("package verification", "medium", f"{name} ({real}) is not owned by any package", tool=name, path=real)
            continue
        owners.setdefault(owner[0], []).append((name, owner[1]))

    if not owners:
        return
    verifier = ["dpkg", "--verify"] if shutil.which("dpkg") else ["rpm", "-V"]
    result = run(verifier + sorted(owners), timeout=300)
    if result.returncode is None:
        report.error(f"{verifier[0]} could not run: {result.stderr}")
        return
    changed = parse_verify_output(result.stdout)
    for package, entries in sorted(owners.items()):
        for name, registered in entries:
            flags = next((changed[p] for p in usrmerge_candidates(registered) if p in changed), None)
            if flags and digest_changed(flags):
                report.add("package verification", "high", f"{name} ({registered}) differs from package {package} (flags {flags}): possible trojaned binary", tool=name, path=registered, package=package, flags=flags)
            elif flags and flags.startswith("missing"):
                report.add("package verification", "high", f"{name} ({registered}) is missing from package {package}", tool=name, package=package)
            elif flags and "?" in flags[:3]:
                report.info("package verification", f"{name}: could not verify {registered} ({flags}); run as root", tool=name)
            else:
                report.info("package verification", f"{name} OK ({package})", tool=name, package=package)
    other = [f"{p} ({f})" for p, f in changed.items() if digest_changed(f) and not any(p in usrmerge_candidates(r) for e in owners.values() for _, r in e)]
    for item in other[:20]:
        report.add("package verification", "medium", f"other modified file in the same packages: {item}")


def check_windows(report: Report, tools: dict[str, str]) -> None:
    system32 = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32").as_posix().lower()
    for name, path in tools.items():
        if not Path(path).as_posix().lower().startswith(system32) and name not in {"python", "py"}:
            report.add("path shadowing", "high", f"{name} resolves to {path}, outside System32", tool=name, path=path)
    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in tools.values())
    rows, error = powershell_json(
        f"Get-AuthenticodeSignature -FilePath {quoted} | Select-Object Path,@{{n='Status';e={{[string]$_.Status}}}},"
        "@{n='Signer';e={$_.SignerCertificate.Subject}}"
    )
    if error:
        report.error(f"signature check: {error}")
    by_path = {str(row.get("Path") or "").lower(): row for row in rows}
    for name, path in tools.items():
        row = by_path.get(path.lower())
        if row is None:
            continue
        status, signer = row.get("Status"), row.get("Signer") or ""
        if status != "Valid":
            report.add("signatures", "high", f"{name} ({path}) signature status is {status}", tool=name, path=path, status=status)
        elif "O=Microsoft Corporation" not in signer and name not in {"python", "py"}:
            report.add("signatures", "medium", f"{name} ({path}) is signed by {signer}, not Microsoft", tool=name, signer=signer)
        else:
            report.info("signatures", f"{name} OK ({signer.split(',')[0]})", tool=name)


def main() -> int:
    parser = make_parser("Verify the integrity of the system tools the triage relies on.", baseline=True)
    args = parser.parse_args()
    report = Report("tool_integrity_check", args, needs_admin=not IS_WINDOWS)
    rules = load_rules("tool_integrity_check", args.rules)
    names = rules.get("windows_tools" if IS_WINDOWS else "posix_tools", [])

    tools = {name: found for name in names if (found := shutil.which(name))}
    missing = sorted(set(names) - set(tools))
    if missing:
        report.info("tools", f"not installed: {', '.join(missing)}")

    for var in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME"):
        if os.environ.get(var):
            severity = "high" if var.startswith("LD_") else "medium"
            report.add("environment", severity, f"{var} is set: {os.environ[var]}", variable=var)

    if IS_WINDOWS:
        check_windows(report, tools)
    else:
        check_linux(report, tools)

    items = {f"tool {name}": sha256_file(os.path.realpath(path)) or "unreadable" for name, path in tools.items()}
    if TOOLKIT_DIR.is_file():  # running from blue-team-scripts.pyz: hash the archive itself
        items[f"toolkit {TOOLKIT_DIR.name}"] = sha256_file(TOOLKIT_DIR) or "unreadable"
    else:
        for path in sorted(TOOLKIT_DIR.glob("*.py")) + [TOOLKIT_DIR / "rules.json", TOOLKIT_DIR / "allowlist.json"]:
            if path.exists():
                items[f"toolkit {path.name}"] = sha256_file(path) or "unreadable"
    handle_baseline(report, items, check="hashes since baseline", added_severity="low", removed_severity="low", changed_severity="high")
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
