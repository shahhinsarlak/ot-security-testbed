#!/usr/bin/env python3
"""
Goulburn Water Treatment Plant -- Scenario 3: DoS Flood
========================================================
This file is an alias for scenario3_dos_flood.py.
Run scenario3_dos_flood.py directly for the full implementation.

Usage:
    python3 scenario3_dos_flood.py [--target 10.0.0.2] [--port 5502]
                                   [--threads 300] [--duration 30]
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scenario3_dos_flood import main  # noqa: F401

if __name__ == "__main__":
    main()
