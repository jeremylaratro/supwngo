"""Mutant `list_all` (SP-01 plan 3.7): lists all 15 method families.

In plan 2.2 order with strictly descending confidence, so the top 3 is ret2win,
ret2libc, rop_syscall for every target. The other commands decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    if call.command == "pwn":
        return shim.pwn_success(list(shim.FAMILIES)), 0
    return None


shim.main(handle)
