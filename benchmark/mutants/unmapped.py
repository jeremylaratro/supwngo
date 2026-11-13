"""Mutant `unmapped` (SP-01 plan 3.7): recommends a name outside the tool vocabulary.

pwn recommends and lists ``FOO_BAR``. The scorer must FAIL it with an
``unmapped`` warning, not skip it. The other commands decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    if call.command == "pwn":
        return shim.pwn_success(["FOO_BAR"]), 0
    return None


shim.main(handle)
