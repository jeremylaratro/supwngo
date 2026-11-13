"""Mutant `hang` (SP-01 plan 3.7): sleeps past any budget and prints nothing."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    time.sleep(3600)


shim.main(handle)
