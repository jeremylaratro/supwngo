"""Mutant `empty_body` (SP-01 plan 3.7): the right address with an empty function.

decompile returns the correct address and a function whose body has been reduced
to nothing, so no anchor call is present. The other commands decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    if call.command == "decompile" and call.truth:
        return (
            shim.decompile_success("f", call.truth["address"], "void f(void)\n{\n}\n"),
            0,
        )
    return None


shim.main(handle)
