#!/usr/bin/env python3
"""
Entry point to run the Smart Firewall Simulation Platform.
"""

import atexit
import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import app


def _on_exit():
    from app.engine.enforcer import cleanup_all_blocks
    cleanup_all_blocks()


atexit.register(_on_exit)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
