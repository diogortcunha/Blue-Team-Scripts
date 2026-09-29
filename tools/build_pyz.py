#!/usr/bin/env python3

"""Build dist/blue-team-scripts.pyz: every script, rules.json and allowlists in one runnable file.

    python3 tools/build_pyz.py [--output PATH] [--allowlist FILE]

The archive runs with any Python 3.9+ (``python3 blue-team-scripts.pyz list``). A .sha256 file is
written next to it so the copy can be verified before use on a suspect host.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "Python-Scripts"
DATA_FILES = ["rules.json", "allowlist.json", "allowlist.example.json"]


def build(output: Path, allowlist: Path | None = None) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        for script in sorted(SCRIPTS.glob("*.py")):
            shutil.copy2(script, staging / script.name)
        for name in DATA_FILES:
            if (SCRIPTS / name).exists():
                shutil.copy2(SCRIPTS / name, staging / name)
        if allowlist:
            shutil.copy2(allowlist, staging / "allowlist.json")
        shutil.copy2(Path(__file__).with_name("pyz_main.py"), staging / "__main__.py")
        output.parent.mkdir(parents=True, exist_ok=True)
        zipapp.create_archive(staging, output, interpreter="/usr/bin/env python3", compressed=True)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + ".sha256").write_text(f"{digest}  {output.name}\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the single-file toolkit.")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "blue-team-scripts.pyz")
    parser.add_argument("--allowlist", type=Path, help="Site allowlist to embed as allowlist.json")
    args = parser.parse_args()
    path = build(args.output, args.allowlist)
    print(f"built {path} ({path.stat().st_size // 1024} KiB)", file=sys.stderr)
    print(path.with_name(path.name + ".sha256").read_text(encoding="utf-8").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
