# supwngo Phase-1 benchmark corpus + measurement harness

This directory is the Phase-1 deliverable of
`docs/plans/2026-09-23-effectiveness-and-usability.md`: a small, purposefully
vulnerable, hand-verified corpus of x86-64 Linux ELF binaries plus a harness
that runs supwngo's real `autopwn` CLI against it and honestly measures how
often the tool's own generated exploit actually works.

```
benchmark/
├── corpus/<NN>_<slug>/<slug>.c   committed C source for each target (only
│                                 the .c files are tracked -- see .gitignore)
├── corpus.yaml                   manifest: protections, intended solve path,
│                                 difficulty, hand-verified status
├── build_all.sh                  idempotent builder (documented flags)
├── run_bench.py                  the measurement harness
└── results/<timestamp>/          generated per-run (gitignored, like the
                                   binaries -- reproducible, not committed)
```

## Build

```bash
benchmark/build_all.sh                    # build all 15 targets
benchmark/build_all.sh 07_ret2libc_leak    # build just one
```

Binaries and `flag.txt` files are generated, not committed (see
`benchmark/.gitignore`); only the `.c` sources and this build recipe are
tracked. The script is idempotent: every invocation recompiles unconditionally
from the committed source with the exact flags documented inline (and
mirrored in `corpus.yaml`'s `protections:` block per target).

## Run the harness

```bash
python3 benchmark/run_bench.py                        # all 15 targets
python3 benchmark/run_bench.py --target 15_win_function
python3 benchmark/run_bench.py --timeout 15            # per-attempt timeout passed to autopwn
```

`run_bench.py` builds any missing binaries automatically, then for each
target:

1. Runs `python3 -m supwngo.cli autopwn <binary> --timeout <T> --json` to
   capture autopwn's own structured self-report (technique tried, its own
   success/verified claim, per-attempt log). Note: the `supwngo` console
   script declared in `pyproject.toml` is not installed in every
   environment, so the harness invokes the CLI module directly with
   `PYTHONPATH` set to the repo root — confirmed as the working invocation
   method before this harness was written.
2. Runs autopwn a second time *without* `--json` (with `-o <script>`),
   because reading `supwngo/cli.py`'s `autopwn` command shows the
   `-o`/`--output` file is only ever written inside the `else` branch of
   `if json_output: ... else: ...` — in `--json` mode the generated script
   is never saved to disk, regardless of `-o`.
3. **Genuinely, independently verifies the result**: re-executes the
   generated script as a *fresh* subprocess (a small, fixed, harmless stdin
   script — `cat flag.txt` + a marker echo — is piped in so that exploits
   which land a shell get a chance to read the flag file, same as a human
   would at the resulting prompt) and checks whether the exact,
   target-specific flag string (read from that target's `flag.txt`) appears
   in its captured output. **This is the only thing that determines
   SUCCESS** — autopwn's own "success"/"verified" self-report is never used
   for that determination, only recorded alongside it for context.
4. Classifies each target:
   - **SUCCESS** — the independent re-run in step 3 produced the flag.
   - **PARTIAL** — autopwn self-reported success (or a successful
     intermediate attempt) but the independent re-run did not reproduce the
     flag.
   - **FAILED** — neither of the above.
5. Writes `benchmark/results/<timestamp>/report.json` (full raw data,
   including every generated script and a tail of its verification output)
   and a human-readable `summary.txt`.

## The 15 targets

All 15 targets below were **hand-verified end-to-end** with a real,
independent pwntools exploit script during corpus construction — not just
inspected by reading the source — well beyond the plan's 5-6-target minimum.
Full protection ground truth (checksec-verified, not just build intent) and
one-paragraph solve-path descriptions live in `corpus.yaml`; summarized here:

| # | slug | technique | difficulty |
|---|------|-----------|------------|
| 01 | shellcode_stack | stack shellcode (no protections) | easy |
| 02 | ret2plt_system | ret2plt `system("/bin/sh")`, no leak needed | easy |
| 03 | pie_leak_ret2libc | PIE self-leak -> GOT leak -> ret2libc | medium |
| 04 | canary_leak_bypass | raw 8-byte canary echo -> bypass | medium |
| 05 | fmtstr_arbread | `%N$p` canary leak -> bypass | medium |
| 06 | fmtstr_arbwrite | `%n` write, NUL-in-address ordering gotcha | medium |
| 07 | ret2libc_leak | GOT leak via ROP -> ret2libc | medium |
| 08 | ret2dlresolve | forged relocation via a ROP-driven write primitive | hard |
| 09 | srop | `rt_sigreturn`-forged register state -> `execve` | hard |
| 10 | int_overflow | 8-bit truncation bypassing a length check | medium |
| 11 | heap_uaf_leak | dangling pointer read after `free()` | medium |
| 12 | heap_tcache_poison | safe-linking-aware tcache poison -> GOT overwrite | hard |
| 13 | off_by_one | single NUL byte past a stack buffer | easy |
| 14 | negative_index | negative array index aliasing an adjacent field | easy |
| 15 | win_function | plain overflow -> `win()`, sanity baseline | easy |

### Notable technique nuances discovered while hand-verifying

These are worth knowing before reading `run_bench.py`'s results, since they
explain *why* a fully-capable automated pipeline still has real work to do
even on a "simple" corpus:

- **Stack-alignment fixer** (02, 03, 07, 08): glibc's `do_system()` executes
  a `movaps [rsp], xmm1`, which SIGSEGVs unless the stack is 16-byte aligned
  at the call. A correct ROP chain into `system()`/a resolved libc call needs
  one extra bare `ret` gadget to flip stack parity.
- **Shellcode placement** (01): shellcode must be placed *after* the
  overwritten return address, not inside the overflow buffer itself — RSP
  lands there post-`ret`, and an in-buffer placement self-corrupts via the
  shellcode's own `push` instructions.
- **Format-string embedded-NUL ordering** (06): a raw pointer value placed
  before a `%n` directive can contain an embedded `0x00` byte that
  prematurely truncates `printf`'s NUL-terminated-string parsing before the
  `%n` is ever reached. The fix is exploit-technique-only (no source change):
  put the `%N$n` directive first, 8-byte aligned, with the target address
  occupying a *later* argument slot.
- **Sign-extension vs. truncation** (10): a negative `int` sign-extended to
  a 64-bit `size_t` read-count is *never* exploitable on real Linux — the
  resulting value is always near 2**64, and the kernel's own `access_ok()`
  range check rejects it with `EFAULT` before touching any buffer,
  regardless of whether the call goes through glibc's `read()` wrapper or a
  raw `syscall(SYS_read, ...)`. The genuinely exploitable variant of this bug
  class requires truncation to a narrow type (e.g. `(unsigned char)len`),
  which is what this target actually does.
- **tcache count vs. entries desync, and 16-byte alignment** (12): safe-linking's
  mangled `next` pointer must be corrupted on the chunk that is *still* the
  freelist head (before any pop), or `tcache`'s `counts[]` field desyncs from
  `entries[]` and the forged pointer is silently never consulted. glibc's
  `tcache_get()` also asserts the popped chunk address is 16-byte aligned
  (`aligned_OK()`), which rules out targeting a raw, 8-byte-aligned GOT entry
  directly — the working technique targets the *preceding* aligned word and
  writes two 8-byte values so the second lands on the real target.
- **ret2dlresolve needs a write primitive, not just gadgets** (08): the
  forged `Elf64_Rela` + fake `Elf64_Sym` + symbol-name bytes that
  `_dl_fixup` reads live at a *fixed* `.bss` address — appending them to a
  stack-based overflow payload does nothing, since nothing ever reads the
  stack there. A second ROP-driven call to a libc function that accepts
  attacker input (here, `read()` again) is required to actually place them.
- **Two-stage I/O timing** (08): when a two-stage payload is sent as two
  back-to-back writes with no delay, the OS can deliver both to the
  *first*, already-blocking `read()` call at once (if their combined size
  fits its requested count), starving the second, ROP-driven `read()` of
  any data. A short delay between the two sends is needed so the child
  process actually reaches its second blocking read first.
- **checksec false positive on static binaries** (14): checksec reports
  "Canary found" purely because the `__stack_chk_fail` symbol exists
  *somewhere* in a statically-linked glibc image (pulled in by other glibc
  internals compiled with stack-protector), independent of whether the
  target's own code was compiled with `-fstack-protector`. Ground truth,
  verified via `objdump -d --disassemble=vuln`, is canary=OFF for this
  target's own code, as intended and as recorded in `corpus.yaml`.

### Targets whose source was redesigned during hand-verification

Three targets had their C source genuinely edited because the
originally-conceived vulnerability mechanism turned out to be structurally
unexploitable, not just because the exploit script needed tuning:

- **09 (SROP)** — a full pwntools `SigreturnFrame` (248 bytes, including the
  FP/xsave area) plus its ROP prefix doesn't fit in a 200-byte read; the read
  size was increased to 400 bytes, and a fixed `/bin/sh` string was added so
  the forged frame's `rdi` doesn't require a separate stack/libc leak.
- **10 (integer overflow)** — the original sign-extension-to-huge-`size_t`
  design is never exploitable on real Linux (see above); the vulnerability
  mechanism was redesigned to an 8-bit truncation bug instead, which is
  genuinely exploitable and still legitimately CWE-190/197.
- **08 (ret2dlresolve)** — the original source had no gadgets and no fixed
  string at all, making it impossible to both set `system()`'s argument
  after resolution *and* plant the forged relocation data (ret2dlresolve
  only resolves the function; it doesn't set up its own argument or write
  its own forgery). Two gadgets (`pop rdi; ret` and
  `pop rdi; pop rsi; pop rdx; ret`) and a fixed `/bin/sh` string were added.

## Phase-1 baseline

Run `python3 benchmark/run_bench.py` and see the generated
`benchmark/results/<timestamp>/summary.txt` / `report.json` for the current
baseline numbers against this branch's `supwngo autopwn`. Results are
timestamped and gitignored (reproducible from the corpus + this harness, like
the binaries themselves), so they are not committed as static files here —
re-run the harness to reproduce.
