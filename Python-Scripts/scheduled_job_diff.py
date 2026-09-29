#!/usr/bin/env python3

"""Deprecated: merged into scheduled_task_audit.py (--baseline/--write-baseline), which this wrapper runs."""

from __future__ import annotations

import sys

from scheduled_task_audit import main

if __name__ == "__main__":
    print("note: scheduled_job_diff.py is deprecated; use scheduled_task_audit.py (baselines from the old script must be recreated)", file=sys.stderr)
    raise SystemExit(main())
