"""Mutant `list_none` (SP-01 plan 3.7): an empty strategy list that is not a decline.

pwn succeeds (rc 0, no error) with ``recommended: null`` and ``strategies: []``.
The other commands decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    if call.command == "pwn":
        return shim.pwn_success([]), 0
    return None


shim.main(handle)
