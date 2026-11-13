"""Mutant `const` (SP-01 plan 3.7): the same constant answer for every target.

pwn recommends ROP_SYSTEM, template emits ret2system, offset is 0 with no canary
offset, decompile returns one unrelated function. All four are well-formed
success documents, so ROBUST passes while the semantic metrics reveal it.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def handle(call):
    if call.command == "pwn":
        return shim.pwn_success(["ROP_SYSTEM"]), 0
    if call.command == "template":
        return shim.template_success("ret2system", call.output), 0
    if call.command == "decompile":
        code = "int main(void)\n{\n  return 0;\n}\n"
        return shim.decompile_success("main", "0x401000", code), 0
    return shim.offset_success(0, None), 0


shim.main(handle)
