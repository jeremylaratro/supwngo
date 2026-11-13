"""Mutant `vuln_axis` (SP-01 plan 3.7): recommends a defect, not a method.

``NEGATIVE_SIZE_BYPASS`` maps to the vuln axis (``integer``), so it can never
satisfy a method accept-set: METHOD-R0 FAIL, and the VULN column shows it. The
other commands decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    if call.command == "pwn":
        return shim.pwn_success(["NEGATIVE_SIZE_BYPASS"]), 0
    return None


shim.main(handle)
