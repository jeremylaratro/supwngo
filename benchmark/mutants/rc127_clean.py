"""Mutant `rc127_clean` (SP-01 plan 3.7): a clean failure document with exit 127.

A well-formed decline, but 127 is not the failure envelope's exit code (2), so
ROBUST must FAIL.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    return shim.decline(call.command), 127


shim.main(handle)
