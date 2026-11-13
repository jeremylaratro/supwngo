"""Mutant `two_docs` (SP-01 plan 3.7): two JSON documents on stdout, exit 0."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    doc = shim.truth_document(call) or shim.decline(call.command)
    print(json.dumps(doc))
    return doc, 0


shim.main(handle)
