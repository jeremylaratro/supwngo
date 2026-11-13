"""Mutant `anchor_in_comment` (SP-01 plan 3.7): anchors only inside comments.

decompile returns the right address and a body that mentions every anchor call
only in comments. Anchors are matched after comment stripping, so this must
FAIL. The other commands decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    if call.command == "decompile" and call.truth:
        code = shim.code_with_calls(call.truth["calls"], commented=True)
        return shim.decompile_success("f", call.truth["address"], code), 0
    return None


shim.main(handle)
