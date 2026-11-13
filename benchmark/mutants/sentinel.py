"""Mutant `sentinel` (SP-01 plan 3.7): decompile returns a failure sentinel as code.

The code is the 32-character ``// Decompilation failed for main`` at the right
address, which is what a failed decompile prints today. The other commands
decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402

SENTINEL = "// Decompilation failed for main"
assert len(SENTINEL) == 32


def handle(call):
    if call.command == "decompile" and call.truth:
        return shim.decompile_success("main", call.truth["address"], SENTINEL), 0
    return None


shim.main(handle)
