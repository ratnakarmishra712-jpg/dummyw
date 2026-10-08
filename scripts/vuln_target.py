#!/usr/bin/env python3
"""Standalone launcher for the deliberately-vulnerable demo target.

The actual app lives in recontoreport/web/demo_target.py so the UI's
"Start demo target" button and this script share one implementation.

Usage:
    python scripts/vuln_target.py     # serves http://127.0.0.1:8911/

For the privilege-escalation demo, scan it with two cookie roles:
    admin → cookie "session=admin" (privilege 10)
    user  → cookie "session=user"  (privilege 1)
(The UI's "Load demo setup" button fills these in automatically.)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recontoreport.web.demo_target import start_demo

if __name__ == "__main__":
    url = start_demo()
    print(f"Vulnerable demo target on {url}  (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
