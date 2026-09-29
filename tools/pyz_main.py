"""Entry point of the single-file toolkit (copied into the archive as __main__.py).

    python3 blue-team-scripts.pyz list
    python3 blue-team-scripts.pyz triage_all --format html -o report.html
    python3 blue-team-scripts.pyz log_triage --days 3 --json
"""

import runpy
import sys
import zipfile
from pathlib import Path

ARCHIVE = Path(__file__).resolve().parent
HIDDEN = {"__main__", "btcommon"}


def scripts() -> list[str]:
    with zipfile.ZipFile(ARCHIVE) as archive:
        names = [n[:-3] for n in archive.namelist() if n.endswith(".py") and "/" not in n]
    return sorted(n for n in names if n not in HIDDEN)


def main() -> int:
    available = scripts()
    if len(sys.argv) < 2 or sys.argv[1] in {"list", "-h", "--help"}:
        print(f"usage: python3 {ARCHIVE.name} <script> [arguments]\n\nscripts:")
        print("\n".join(f"  {name}" for name in available))
        return 0
    name = sys.argv[1].removesuffix(".py")
    if name not in available:
        print(f"error: unknown script {name!r}; run 'python3 {ARCHIVE.name} list'", file=sys.stderr)
        return 2
    sys.argv = [f"{name}.py", *sys.argv[2:]]
    runpy.run_module(name, run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
