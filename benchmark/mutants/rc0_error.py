"""Mutant `rc0_error` (SP-01 plan 3.7): a failure envelope with exit code 0.

What `decompile` does today on a failed decompile. The content is a decline (the
semantic metrics score ABSTAIN) but the (rc, envelope) pair is illegal, so ROBUST
must FAIL.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    return shim.decline(call.command), 0


shim.main(handle)
