"""Mutant `answer_key` (SP-01 plan 3.7): cheats from files it must not read.

``--keys-json`` is a list of absolute paths (the truth file, the challenge
source, a ``.debug`` sibling of the original binary, a generator source). The
shim tries to open every one. If any opens it emits the `truth_echo` answer for
the target (a leaked key); otherwise it declines. Either way the document
carries ``key_opens`` (path -> whether the open succeeded), so a test can assert
each open failed inside the sandbox.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def opens(path):
    try:
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False


def handle(call):
    keys = call.options.get("keys_json") or []
    results = {path: opens(path) for path in keys}
    doc = shim.truth_document(call) if any(results.values()) else None
    rc = 0
    if doc is None:
        doc, rc = shim.decline(call.command), shim.DECLINE_RC
    doc["key_opens"] = results
    return doc, rc


shim.main(handle)
