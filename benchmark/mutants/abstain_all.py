"""Mutant `abstain_all` (SP-01 plan 3.7): a well-formed decline from every command.

Exit code 2 with the command's failure envelope. ROBUST passes; every semantic
metric must score ABSTAIN, never PASS or FAIL.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    return None


shim.main(handle)
