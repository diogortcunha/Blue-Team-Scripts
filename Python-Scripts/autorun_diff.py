#!/usr/bin/env python3

"""Deprecated: merged into startup_audit.py (--baseline/--write-baseline), which this wrapper runs."""

from __future__ import annotations

import sys

from startup_audit import main

if __name__ == "__main__":
    print("note: autorun_diff.py is deprecated; use startup_audit.py (baselines from the old script must be recreated)", file=sys.stderr)
    raise SystemExit(main())
