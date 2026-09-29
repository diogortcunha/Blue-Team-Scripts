#!/usr/bin/env python3

"""Deprecated: merged into log_triage.py, which this wrapper runs with the same arguments."""

from __future__ import annotations

import sys

from log_triage import main

if __name__ == "__main__":
    print("note: user_activity_audit.py is deprecated; use log_triage.py", file=sys.stderr)
    raise SystemExit(main())
