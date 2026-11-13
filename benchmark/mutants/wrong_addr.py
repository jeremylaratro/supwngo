"""Mutant `wrong_addr` (SP-01 plan 3.7): the right code at the wrong address.

decompile returns a body with every anchor call, labelled with address 0x1,
which is in no target's ``default_function_any_of``. The other commands decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    if call.command == "decompile" and call.truth:
        calls = call.truth["calls"]
        return shim.decompile_success("f", "0x1", shim.code_with_calls(calls), calls), 0
    return None


shim.main(handle)
