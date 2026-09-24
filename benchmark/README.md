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

## Flag and build convention (CANONICAL — every corpus must follow this)

This is the normative contract for **all** benchmark corpora, including the
`benchmark/corpus_r<N>/` rounds. It exists because the original scheme was
unsound and silently invalidated the Phase-1 baseline: `build_all.sh` derived
each flag by grepping `FLAG{...}` out of the target's **git-committed** C
source, with a fallback of `FLAG{supwngo_bench_$(basename "$dir")}` — i.e. a
constant derivable from the directory name alone. A script that printed that
literal scored `SUCCESS` on 9 of 15 targets without exploiting anything. Full
analysis: `docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md`.

### R1 — The flag MUST NOT be derivable from anything committed

No flag may be recoverable from the target's name, its C source, the manifest,
or any other tracked file. **No flag literal is ever committed to git.** In
particular, do **not** carry over the old
`FLAG{supwngo_bench_<dirname>}`-style fallback in any form.

*Status of the R1 corpus:* `benchmark/corpus/*.c` still contain their original
`#define FLAG "FLAG{supwngo_bench_<name>}"` placeholders (the corpus sources
are the fixed measurement instrument and were deliberately not edited by the
soundness audit). Those placeholders are **inert** — `run_bench.py` always
rebuilds with `-DFLAG`, so they are never the scored flag, and the harness
fails closed to `VOID` if the override didn't apply. They are nonetheless not
the pattern to copy: new corpora should use an obviously-inert placeholder
like `FLAG{placeholder_overridden_at_build_time}` as in R3. Note that invoking
`build_all.sh` by hand *without* `SUPWNGO_BENCH_FLAG` still yields the legacy
weak flag; that path is for ad-hoc local builds only and no score is ever
derived from it.

### R2 — The flag MUST be a fresh random secret, minted per run

`run_bench.py` mints one per target per run and hands it to the builder:

```python
# benchmark/run_bench.py
SECRET_FLAG_LEN = 38                       # "FLAG{" + 32 hex + "}"
def mint_secret_flag() -> str:
    return "FLAG{" + secrets.token_hex(16) + "}"
```

Use `secrets`, never `random`. Keep the length **fixed** so target memory
layout is stable run to run.

**Length is a corpus contract.** If a target copies its flag into a
fixed-size buffer, an over-long flag corrupts the very behaviour being
measured. The tightest case in R1 is `11_heap_uaf_leak`:

```c
chunks[0] = malloc(80);
memcpy(chunks[0] + 16, FLAG, strlen(FLAG) + 1);   /* needs 16+len+1 <= 80 */
```

so `len(flag) <= 63`. A new corpus with a tighter flag buffer must either
raise its buffer or declare the bound; `run_bench.py` asserts
`SECRET_FLAG_LEN <= MAX_SAFE_FLAG_LEN`.

### R3 — Compile-time injection: exact form

Every target that prints its own flag MUST guard it so `-DFLAG` can override
it. In the C source (this is the **only** flag-related thing in a `.c` file):

```c
#ifndef FLAG
#define FLAG "FLAG{placeholder_overridden_at_build_time}"
#endif

void win(void) { puts(FLAG); }
```

The builder reads `SUPWNGO_BENCH_FLAG` and injects it, quotes included:

```bash
BENCH_FLAG="${SUPWNGO_BENCH_FLAG:-}"
# ... per-target protection flags accumulate in flags=() ...
if [[ -n "$BENCH_FLAG" ]]; then
    flag="$BENCH_FLAG"
    flags+=(-DFLAG="\"$flag\"")      # note the escaped inner quotes
fi
gcc "${flags[@]}" -o "$out" "$src"
```

The `-DFLAG="\"$flag\""` form matters: `FLAG` must expand to a C *string
literal*, so the inner quotes have to survive into the compiler invocation.

### R4 — `flag.txt` for file-reading (shell-obtaining) targets

Targets whose intended solve path ends in a shell never print a flag
themselves; the flag exists only on disk, and the exploit reads it from the
shell it obtained. The **same** secret is written next to the binary:

```bash
printf '%s\n' "$flag" > "$dir/flag.txt"
```

Write `flag.txt` for every target (harmless and unused for `win()`-style
ones). Note that a target which prints a compiled-in flag necessarily carries
the secret inside its binary image — see "Known limitation" below. **Prefer
designing new targets to print the *contents of* `flag.txt` rather than a
compiled-in literal**, which removes that exposure entirely.

**Do the read once at startup, immediately after `setvbuf()` — never lazily
inside `win()`.** `fopen`/`getline`/`fclose` allocate, and on a heap target
those allocations land in the same tcache bins the intended exploit grooms. A
read that happens after the exploit has arranged the heap can perturb the exact
state the exploit depends on, changing the target's difficulty with no signal
that it moved. Reading before any allocation the exploit cares about keeps the
flag out of the binary *and* keeps the measurement stable. This placement is
load-bearing for allocation-sensitive targets; treat it as part of R4, not a
style preference.

Whenever you change an existing target this way, the acceptance criterion is
**"the reference exploit still passes"**, not merely "the scrape probe now
fails". A target whose scrape is closed but whose intended exploit broke is a
worse outcome than the defect you fixed.

### R5 — Gitignore

Never commit binaries, `flag.txt`, run output, or the harness lock:

```gitignore
corpus_r<N>/*/*
!corpus_r<N>/*/*.c
results_r<N>/*/
corpus*/.run_bench.lock
```

### R6 — Fail closed, and prove it landed

The harness verifies provisioning and scores the target `VOID` rather than
reporting a number it cannot trust, if either: `flag.txt` does not contain
this run's secret (builder ignored `SUPWNGO_BENCH_FLAG`), or a source that
defines its own `FLAG` produced a binary not containing the secret (`-DFLAG`
silently didn't apply). A builder that doesn't honour the env var therefore
shows up as a loud `VOID`, never as a quiet mis-measurement.

### R7 — Every new target MUST fail its negative controls

This is the acceptance test for a target, not an afterthought. The harness runs
each target with **no exploit at all** and `VOID`s it if the flag appears. Three
controls, all standard, all run for every target on every round:

| control | input | what a leak proves |
| --- | --- | --- |
| `bare_run_verify_stdin` | the harness's own 27-byte injected stdin | **instrument fault** — the harness is solving the target |
| `bare_run_filler` | 512 bytes of `'A'` | the target cannot discriminate a reasoned exploit from a blind blob |
| `bare_run_menu_walk` | `<n>\n0\n` for n in 1..6, **each in a fresh process** | the read path has no liveness/authorization gate |

Two R1 targets fail this and are `VOID`. Both are *detected*, not hardcoded:

- **`13_off_by_one`** — leaks to `bare_run_filler`. `read(0, s.buf, 32)` returns
  32 for *any* input of ≥32 bytes and the bug then fires unconditionally, so
  garbage solves it.
- **`11_heap_uaf_leak`** — leaks to `bare_run_menu_walk`. `show_note()` gates
  only on `chunks[idx]` being non-NULL and in range, never on liveness, and
  index 0 is pre-populated with the flag. So menu `3` / index `0` dumps it out
  of a **live** chunk: no delete, no dangling pointer, no use-after-free. The
  technique the target claims to require is never exercised.

That makes the R1 scoring denominator **13**: 01–10, 12, 14, 15.

Two methodological caveats, so these controls are not over-read:

- 512 bytes of `'A'` is *also* the shape of a blind stack-overflow payload, so a
  `bare_run_filler` leak strictly means "the canonical structure-free first
  payload wins, with no offset, address or gadget computed" rather than "any
  garbage wins". Either way the target does not discriminate, which is what
  disqualifies it.
- The menu probes **must** each run in a fresh process. A single concatenated
  stream is unsound: one menu option is invariably "exit", and once the walk
  selects it every later option goes untried. An earlier single-stream version
  of this control gave `11_heap_uaf_leak` a clean bill of health for exactly
  that reason.

Verify a candidate target before adding it:

```bash
python3 benchmark/run_bench.py --corpus-root benchmark/corpus_r2 \
    --manifest benchmark/corpus_r2.yaml --target 03_your_new_target
```

Any `VOID` verdict means the target is not a measurement. Fix the target.

To check a whole corpus at once, without paying for `autopwn` runs (seconds
per target rather than minutes), use the dedicated sweep — it exits non-zero
if any target is unmeasurable or mis-provisioned, so it drops straight into a
build script:

```bash
python3 benchmark/soundness_probes/negative_control_sweep.py \
    --corpus-root benchmark/corpus_r2 --manifest benchmark/corpus_r2.yaml
```

For R1 it reports `13_off_by_one` and `11_heap_uaf_leak` as unmeasurable and
flags the 9 scrapeable targets (R8); the other 13 are clean.

### R8 — A target's flag SHOULD NOT be readable from its binary image

`strings <binary> | grep FLAG{` is routine first-step recon for an exploitation
framework, so this is not a hypothetical channel — a tool could score on it
without anyone intending to cheat. **Per-build randomisation does not close it:**
it changes *which* string is embedded, not whether one is. The harness measures
the channel behaviourally (it really runs `strings`) for every target every run
and records it as `flag_scrapeable_without_exploit`.

On R1 this is true for 9 targets — 04, 05, 06, 10, 11, 12, 13, 14, 15 — each of
which has a `win()` that `puts()` a compiled-in `FLAG` literal. The six
shell-based targets (01, 02, 03, 07, 08, 09) are clean: their binaries contain
no flag at all, so a flag in their output can only have come from the running
target. That is a *structural* argument. For the other nine, only
`run_bench.py`'s bypassable script audit stands in the way.

The harness therefore does **not** silently equate the two. A `SUCCESS` on a
scrapeable target is labelled `[WEAK ATTRIBUTION]` in its reason and broken out
in `summary.txt`; `--strict-attribution` `VOID`s them outright, which is how to
measure how much of a score rests on the script audit.

**The real fix is corpus-side: have `win()` print the CONTENTS OF `flag.txt` at
runtime** instead of embedding the literal, the way the six shell-based targets
already do. New corpora should do this from the start. (The R1 sources were left
untouched by the soundness audit — they are the fixed measurement instrument and
the audit's remit was the harness; changing them is a maintainer decision.) A
target whose `win()` reads `flag.txt` must be run with that file present in the
process's cwd: `run_bench.py` always writes it into the target directory and
runs both the target and the generated script with `cwd` set there, for the
controls and the verification alike.

### R9 — An alternate corpus MUST declare its protection flags

`build_all.sh` keys per-target protection flags off a `case` on the directory
name, which only knows the 15 R1 targets. Per-target protections **are** the
measurement, so for a directory it does not recognise the builder refuses to
guess and **fails closed**. Declare them in a `cflags` file beside the source,
one gcc flag per line (blank lines and `#` comments ignored):

```
benchmark/corpus_r2/03_your_target/cflags
    # canary=OFF nx=ON pie=OFF
    -fno-stack-protector
    -no-pie
```

Without that file the build fails with a message naming the missing path, so a
new corpus round cannot quietly be built with default protections — which would
measure a different challenge than its manifest claims.

## Run the harness

```bash
python3 benchmark/run_bench.py                        # all 15 targets
python3 benchmark/run_bench.py --target 15_win_function
python3 benchmark/run_bench.py --timeout 15            # per-attempt timeout passed to autopwn

# reuse the harness against a later corpus round
python3 benchmark/run_bench.py \
    --corpus-root benchmark/corpus_r2 --manifest benchmark/corpus_r2.yaml
```

`--corpus-root`/`--manifest` default to `benchmark/corpus/` and
`benchmark/corpus.yaml`; results for an alternate round land in a sibling
`benchmark/results_r<N>/`. Only one run may hold a given corpus at a time —
each run rebuilds its targets (see step 0), so the harness takes a lock and
fails fast rather than letting two runs corrupt each other.

`run_bench.py` then, for each target:

0. **Rebuilds the target with a fresh, unguessable per-run secret flag**
   (`FLAG{<32 hex>}`), passed to `build_all.sh` via `SUPWNGO_BENCH_FLAG`,
   which both compiles it in (`-DFLAG`, honoured by every win()-style
   source's `#ifndef FLAG` guard) and writes it to `flag.txt`. A flag string
   appearing in a script's output therefore cannot have been known in
   advance. If the secret doesn't actually land in both places, the target is
   scored `VOID` rather than measured.

   *Why:* the flag used to be grepped out of the target's **git-committed** C
   source, making it a public constant that a script could simply hardcode or
   scrape with `strings`. See
   `docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md`.
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
3. **Runs negative controls**: executes the target with *no exploit at all*
   under the same conditions — once with the harness's own injected stdin,
   once with 512 bytes of benign filler. If this run's secret flag turns up
   there, the flag was free and nothing a generated script does can be
   credited to exploitation, so the target is scored `VOID`.

   *Why:* the harness's injected stdin is itself attacker-controlled input to
   the target. At its original 48 bytes it single-handedly solved
   `13_off_by_one` (`read(0, s.buf, 32)` returns 32 for any input of ≥32
   bytes, then writes `s.buf[32]`), so a script whose whole body was
   `subprocess.run(['./off_by_one'])` scored `SUCCESS`. The stdin is now
   27 bytes, but the negative control — not the byte count — is the actual
   guarantee, and it generalises to corpora not yet written.
4. **Genuinely, independently verifies the result**: re-executes the
   generated script as a *fresh* subprocess (a small, fixed, harmless stdin
   script — `cat flag.txt` plus `echo $((6*7))` — is piped in so that
   exploits which land a shell get a chance to read the flag file, same as a
   human would at the resulting prompt) and checks whether this run's secret
   flag appears in its captured output. **This is the only thing that
   determines SUCCESS** — autopwn's own "success"/"verified" self-report is
   never used for that determination, only recorded alongside it for context.

   The `$((6*7))` marker is shell arithmetic: a real command interpreter
   prints `42`, whereas a target that merely echoes its input prints the
   literal `$((6*7))`. This is recorded as a `shell_proven` diagnostic, *not*
   a SUCCESS gate — win()-style targets legitimately never yield a shell.
5. **Audits the generated script itself**, not just its output: a script that
   contains the secret literal, reads `flag.txt` in Python, or shells out to
   `strings`/`objdump`/`readelf`/`xxd` at runtime is scored `VOID`. The check
   is deliberately narrow — sending `cat flag.txt` *to a shell the exploit
   obtained* is the intended solve path for the shell targets and is not
   flagged.
6. Classifies each target:
   - **VOID** — not measurable: a negative control produced the flag, the
     target couldn't be built with a real secret, or the script gamed the
     check. Excluded from the success-rate denominator rather than counted as
     a pass or a failure.
   - **SUCCESS** — the independent re-run in step 4 produced this run's
     secret flag, and the negative controls did not.
   - **PARTIAL** — autopwn self-reported success (or a successful
     intermediate attempt) but the independent re-run did not reproduce the
     flag.
   - **FAILED** — none of the above.
7. Writes `benchmark/results/<timestamp>/report.json` (full raw data,
   including every generated script, the negative-control results, the script
   audit, and head+tail excerpts of the verification `stdout`/`stderr`) and a
   human-readable `summary.txt`.

### Behavioural attribution — who wrote the flag

A flag string in the output is a *proxy* for exploitation. Every
false-positive channel this harness has suffered lived in the gap between the
proxy and the thing, and the pattern audit (step 5) can never fully close it,
because verification is not sandboxed and a string-built path or directory walk
is out of reach of any regex — `soundness_probes/pure_python_scrape.py` defeats
it in four lines.

So the harness no longer asks *whether* the flag appeared. It asks **who wrote
it**. `benchmark/attribution.py` re-executes the script under `strace -f`,
reconstructs the process tree from `execve`/`clone`/`write`, and credits a
`SUCCESS` only if the flag was written by the **target process or a descendant
of it** — the target's own `win()`, or `cat` running under a shell the exploit
obtained. A write by the script, or by a child of the script, is not credited.

That closes `cat flag.txt`, `open()`, `glob`, `strings` and `ELF.search` in one
move, including variants nobody has enumerated, because none of them route
through the target's address space. Measured on the real corpus:

| probe | string match | attribution |
| --- | --- | --- |
| `real_exploit_15.py` (genuine ret2win) | flag found | **credited** — `win_function` wrote it |
| `real_exploit_02*.py` (genuine ret2plt) | flag found | **credited** — `cat` under the obtained shell |
| `pure_python_scrape.py` | flag found | **not credited** |
| `hardcoded_flag.py` | flag found | **not credited** |

How to read a result:

- **`BEHAVIOURALLY ATTRIBUTED`** — the exploitation event was observed. Strong.
- **`VOID` / `script_gamed_the_check`** — we *watched* the script obtain the
  flag without exploiting. A finding about supwngo, not a guess.
- **`UNWITNESSED`** — no usable witness (no `strace`, or ptrace denied), so the
  result falls back to string match plus the bypassable pattern audit and says
  so. A missing witness is never treated as a negative one.
  `--strict-attribution` refuses to score these at all.

`summary.txt` always breaks the successes into witnessed and unwitnessed, so
**quote both numbers.** A run on a box without `strace` says so explicitly.

Residual gap, stated plainly: a script could still deliberately write the flag
into the target's own output channel. That takes real effort rather than a
shortcut, and `shell_exec_by_target` corroborates the six shell-based targets
independently, but it is not structurally prevented. Witnessing the target's
control flow directly (a breakpoint on `win()`) would close it.

### Run time

Targets run in parallel — one worker per core, capped at 8
(`--jobs N`, `--jobs 1` to force serial). Each target is confined to its own
directory and gets a private `TMPDIR`, and results are reported in **manifest
order regardless of completion order**, so a parallel run and a serial run
produce the same report. A crash or hang in one target cannot alter another's
verdict: it becomes a `harness_error` `VOID`, which is *fatal* and withholds
the whole run's rate rather than quietly shrinking the denominator.

### Reps: `solved` and `reliability` are both the answer

Exploit delivery is **not deterministic**, and the failure does not look like a
race — it looks like a capability limit. A target whose intended chain works can
still fail some fraction of runs because of a stdin synchronisation race, heap
layout, or ASLR. One measured example: a genuine ret2plt exploit failed 4/96
times under 24-way contention and 0/40 unloaded, presenting as
`shell_proven=True, flag_found=False` — a shell was obtained but its commands
were swallowed by the target's single `read()`.

So the harness runs **`--reps N` (default 5)** and reports two numbers:

| | meaning |
|---|---|
| `solved` | credited in **at least one** rep — can this be exploited at all |
| `reliability` | **k/N** reps credited — how dependably |

**Neither is the score on its own.** Quoting `solved` without `reliability` is
best-of-N cherry-picking; quoting a single rep understates real capability. Cite
the pair — and note that the pair is more informative than either, because 5/5
and 1/5 are genuinely different claims about a target.

Details that keep this honest: reps run **sequentially within a target** (each
rebuilds the binary with a fresh secret, so concurrent reps would race on that
rebuild), a `VOID` **settles** a target rather than being re-rolled (the controls
and provisioning checks are deterministic, so re-rolling would only burn time),
a single-rep run reports **no** reliability rather than a misleading `1/1`, and
each rep gets its own results subdirectory so an intermittent target's evidence
survives. `reps` is recorded in `report.json`.

The `OVERALL` headline also states that its rate is best-of-N and splits the
successes into fully-reliable versus intermittent. That belongs on the headline
rather than only in the table below it, because the headline is the line that
gets quoted and a disclosure elsewhere in the file does not travel with it.

**Each rep records its own secret** in `attempts[]`, which is what keeps a
multi-rep verdict falsifiable. Every rep rebuilds the target with a fresh flag,
so without the per-rep secret you could not re-derive rep 3's verdict from rep
3's own `strace.log` — you would not know which string to search for, and a wrong
verdict in a later rep would be undetectable after the fact. `attempts[]` also
carries each rep's status, reason and elapsed time, and `elapsed_sec_total` is the
target's real cost across reps (`elapsed_sec` remains one representative
attempt, so it stays comparable against a single-rep report).

Builds are deliberately **not** cached. `gcc` on a single small C file is
milliseconds against ~2 minutes of `autopwn` per target, so caching would save
under 1% while risking the thing that matters most: for the win()-style targets
the flag is compiled in, so a cached binary would carry a **stale flag** and
silently break per-run flag rotation.

### Re-checking the harness itself

`benchmark/soundness_probes/` holds the adversarial probes behind the audit:
four non-exploiting scripts that must never be credited, and genuine
hand-written exploits for both target families — `real_exploit_02.py` /
`real_exploit_02_explicit.py` (shell-obtaining, in `io.interactive()` and
explicit-`sendline` shapes) and `real_exploit_15.py` (ret2win) — which must
never be lost to buffering or to the anti-gaming checks.

```bash
# does any target hand out its flag to benign input, or scrape from .rodata?
python3 benchmark/soundness_probes/negative_control_sweep.py

# does attribution credit real exploits and reject scrapes? (exits non-zero if not)
python3 benchmark/soundness_probes/attribution_sweep.py
```

Pure-logic regressions live in `tests/test_bench_harness_soundness.py`.

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

> **⚠ The `2/15 (13.3%)` figure quoted below is SUPERSEDED — do not cite it.**
> The 23 Sep 2026 soundness audit
> (`docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md`) proved the harness
> could report `SUCCESS` with zero exploitation, and that both of those two
> successes were affected. `13_off_by_one` is now `VOID` (arbitrary garbage
> input captures its flag, so it cannot discriminate a real exploit from a
> no-op); `15_win_function` re-verified as a **genuine** success against a
> per-run secret flag. The corrected figure is **1/14 scorable (7.1%)**.
> The narrative below is kept for the per-target technique analysis, which
> remains accurate. Re-run the fixed harness for current numbers.

Run `python3 benchmark/run_bench.py` and see the generated
`benchmark/results/<timestamp>/summary.txt` / `report.json` for the current
baseline numbers against this branch's `supwngo autopwn`. Results are
timestamped and gitignored (reproducible from the corpus + this harness, like
the binaries themselves), so they are not committed as static files here —
re-run the harness to reproduce.

As of this branch (`feat/benchmark-corpus-20260923`, rebased onto
`integration/phases-0-4-7-20260923` -- Phase 0 import baseline, Phase 2
consolidated pipeline, Phase 3 repaired leak/Z3/tester modules, Phase 4
structured hand-off, Phase 6 `solve` command + the `verify_payload()`
interactive-shell-verification fix, all present), a real run against
`autopwn` with `--timeout 12` produced:

```
OVERALL: 2/15 SUCCESS (13.3%), 0 PARTIAL, 13 FAILED
  easy:   2/5 SUCCESS (13_off_by_one, 15_win_function)
  medium: 0/7 SUCCESS
  hard:   0/3 SUCCESS
```

autopwn's own self-report agreed with independent verification on all 15
targets (0 PARTIAL) -- the 13 FAILED targets were not cases where the tool
claimed success and the flag just didn't reproduce; autopwn itself reported
`success: false` for all 13. Spot-checking two targets with the new `solve`
command (a thin wrapper over the same `CanonicalAutopwnEngine`) reached the
same verified result in both cases: `SUCCESS`/`FLAG_CAPTURED` on
`15_win_function` (and it wrote a working, independently-replayable script
to `solve_output/<binary>_exploit.py` by default, confirmed by re-running it
fresh), and the same `FAILED` outcome on `02_ret2plt_system` -- notably,
`solve`'s structured hand-off shows *why*: its `ret2libc` strategy is
gated on having "a real libc-base leak", even though `02_ret2plt_system`
doesn't need one at all (`system@plt` and a `"/bin/sh"` string already exist
in the binary -- see its `corpus.yaml` entry). That's a real, specific gap
in the tool's current strategy set, not a benchmark artifact: the
consolidated pipeline doesn't yet recognize the "call system@plt directly,
no leak needed" case that ret2plt-style targets exercise.
