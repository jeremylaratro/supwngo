"""Mutant `truth_echo` (SP-01 plan 3.7): hands back the right answer.

The truth comes only from the explicit ``--truth-json`` bundle the test passes
in; this shim never reads ``benchmark/truth`` (the sandbox hides it). A target
with no bundle gets a decline.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    doc = shim.truth_document(call)
    return None if doc is None else (doc, 0)


shim.main(handle)
