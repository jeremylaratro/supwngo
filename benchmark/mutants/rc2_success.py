"""Mutant `rc2_success` (SP-01 plan 3.7): a success envelope with exit code 2."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    return shim.truth_document(call) or shim.template_success("ret2system", call.output), 2


shim.main(handle)
