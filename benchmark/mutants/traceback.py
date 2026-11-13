"""Mutant `traceback` (SP-01 plan 3.7): crashes with an uncaught exception.

Prints a Python traceback on stderr and nothing on stdout, for every command.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    raise RuntimeError("shim: planted traceback")


shim.main(handle)
