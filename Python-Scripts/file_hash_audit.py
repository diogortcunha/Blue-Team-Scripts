#!/usr/bin/env python3

"""Create or compare SHA-256 integrity baselines (content, permissions and ownership)."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from btcommon import Report, load_baseline, make_parser, save_baseline, sha256_file, walk_files

Entry = dict[str, Any]


def _signature(st: os.stat_result) -> tuple:
    return (st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino, st.st_mode, st.st_uid, st.st_gid)


def snapshot(
    paths: list[str],
    errors: list[str],
    cache: dict[str, tuple[tuple, Entry]] | None = None,
) -> dict[str, Entry]:
    """Hash every file under ``paths``. ``cache`` lets repeated runs skip files whose stat is unchanged."""
    data: dict[str, Entry] = {}
    roots = [Path(p).absolute() for p in paths]
    for path in walk_files(roots, errors):
        key = str(path)
        try:
            st = path.lstat()
        except OSError as exc:
            errors.append(f"{path}: {exc.strerror or exc}")
            continue
        if stat.S_ISLNK(st.st_mode):
            try:
                data[key] = {"link": os.readlink(path)}
            except OSError as exc:
                errors.append(f"{path}: {exc.strerror or exc}")
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        sig = _signature(st)
        if cache is not None and key in cache and cache[key][0] == sig:
            data[key] = cache[key][1]
            continue
        digest = sha256_file(path)
        if digest is None:
            errors.append(f"{path}: unreadable")
            continue
        entry: Entry = {"sha256": digest, "size": st.st_size, "mode": oct(stat.S_IMODE(st.st_mode))}
        if os.name == "posix":
            entry.update(uid=st.st_uid, gid=st.st_gid)
        data[key] = entry
        if cache is not None:
            cache[key] = (sig, entry)
    return data


def compare(old: dict[str, Any], new: dict[str, Entry]) -> list[tuple[str, str, str]]:
    """Return (status, path, detail) with status ADDED, REMOVED, CHANGED or PERMS."""
    changes: list[tuple[str, str, str]] = []
    for path in sorted(set(new) - set(old)):
        changes.append(("ADDED", path, ""))
    for path in sorted(set(old) - set(new)):
        changes.append(("REMOVED", path, ""))
    for path in sorted(set(old) & set(new)):
        before, after = old[path], new[path]
        if isinstance(before, str):  # v1 baseline: {path: sha256}
            before = {"sha256": before}
        if before.get("sha256") != after.get("sha256") or before.get("link") != after.get("link"):
            changes.append(("CHANGED", path, "content" if "sha256" in after else f"link -> {after.get('link')}"))
            continue
        diffs = [
            f"{field} {before[field]} -> {after.get(field)}"
            for field in ("mode", "uid", "gid")
            if field in before and before[field] != after.get(field)
        ]
        if diffs:
            changes.append(("PERMS", path, ", ".join(diffs)))
    return changes


SEVERITY = {"ADDED": "medium", "REMOVED": "low", "CHANGED": "high", "PERMS": "medium"}


def main() -> int:
    parser = make_parser("Hash files for integrity checks.", baseline=True)
    parser.add_argument("paths", nargs="+", help="Files or directories to hash")
    args = parser.parse_args()
    report = Report("file_hash_audit", args)

    errors: list[str] = []
    current = snapshot(args.paths, errors)
    for error in errors:
        report.error(error)

    if args.write_baseline:
        save_baseline(args.write_baseline, report.tool, current)
        report.info("baseline", f"wrote {len(current)} entries to {args.write_baseline}")

    if args.baseline:
        try:
            old = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            report.fail(f"cannot read baseline {args.baseline}: {exc}")
            return report.emit()
        changes = compare(old, current)
        for status, path, detail in changes:
            report.add("integrity", SEVERITY[status], f"{status} {path}" + (f" ({detail})" if detail else ""), status=status, path=path, detail=detail)
        if not changes:
            report.info("integrity", f"no changes in {len(current)} files")
    elif not args.write_baseline:
        for path, entry in sorted(current.items()):
            report.info("hashes", f"{entry.get('sha256') or '-> ' + entry.get('link', '')}  {path}", path=path, **entry)
    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main())
