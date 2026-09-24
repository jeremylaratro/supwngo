# Benchmark harness soundness audit — `benchmark/run_bench.py`

**Date:** 23 Sep 2026
**Auditor branch:** `fix/benchmark-harness-soundness-20260923` (off `integration/phases-0-4-7-20260923`)
**Subject:** the Phase-1 measurement instrument — `benchmark/run_bench.py` + `benchmark/build_all.sh`
**Verdict:** **the harness was UNSOUND. The 2/15 (13.3%) baseline in `docs/reports/PHASE1-BASELINE-24SEP2026.md` does not stand.** Corrected baseline: **1/13 (7.7%)**.

**Root fix landed:** SUCCESS is no longer inferred from a flag string appearing. It now requires a **behavioural witness** — the flag must have been written by the target's own process tree. See "The root fix" below; the one surviving SUCCESS (`15_win_function`) is now *evidenced* rather than *inferred*.

---

## Headline: the harness could report SUCCESS with zero exploitation

Two independent false-positive channels were found and reproduced. Between
them they could manufacture SUCCESS on **10 of the 15 targets, including both
targets the 2/15 baseline rested on.**

Two further defects were found during remediation and are covered below: a
second unmeasurable target (`11_heap_uaf_leak`, whose flag comes out of a *live*
chunk with no use-after-free), and a `strings`-recon channel that per-build flag
randomisation does **not** close on the 9 win()-style targets. One residual hole
is knowingly left open and documented rather than papered over: verification is
not sandboxed, so the script-side anti-gaming checks are a bypassable heuristic,
not a proof.

### FP-1 — the harness solved `13_off_by_one` by itself (critical)

To give shell-obtaining exploits a fair chance, the harness piped a fixed
stdin script into the re-executed exploit:

```python
VERIFY_STDIN = b"cat flag.txt\necho __SUPWNGO_BENCH_VERIFY_DONE__\n"   # 48 bytes
```

`13_off_by_one`'s vulnerability is:

```c
int n = (int)read(0, s.buf, 32);
if (n > 32) n = 32;
s.buf[n] = 0;   /* BUG: n==32 writes one byte past buf, into s.guard */
```

`read()` returns 32 for **any** stdin of ≥32 bytes. The harness's own stdin was
48 bytes. So merely *starting the process with the harness's stdin attached*
zeroed `guard`'s low byte, called `win()`, and printed the flag.

**Reproduction.** A script whose entire body is:

```python
import os, subprocess
cands = [f for f in sorted(os.listdir('.')) if os.path.isfile(f) and os.access(f, os.X_OK)]
subprocess.run(['./' + cands[0]])
```

pushed through the harness's own `independent_verify()` + `classify()`:

```
13_off_by_one   donothing_subprocess.py   -> SUCCESS  flag_found=True
  output tail: '=== 13 off-by-one single-byte overwrite ===\nInput: You said: cat flag.txt\necho __SUPWNGO_BENC\nFLAG{supwngo_bench_13_off_by_one}\ndone\n'
```

No payload, no offset, no address, no ROP — **SUCCESS**. `13_off_by_one`'s
contribution to the baseline was an artifact of the measurement apparatus.

Note also that the effect was *delivery-shape dependent*: a pwntools
`process()` + `interactive()` no-op script scored FAILED on the same target,
because `interactive()` forwards stdin line-by-line (13 bytes first, so
`n==13` and the off-by-one never fires). The instrument's verdict depended on
how a script happened to chunk stdin.

### FP-2 — the "secret" flag was a public constant committed to git (critical)

`build_all.sh` derived the flag by grepping the target's **committed** C source:

```bash
flag="$(grep -oE 'FLAG\{[^}]*\}' "$src" | head -1 || true)"
printf '%s\n' "$flag" > "$dir/flag.txt"
```

So the flag was (a) in git, (b) identical on every build, and (c) compiled
verbatim into the `.rodata` of all 9 win()-style targets. Anything that
hardcoded the literal or ran `strings` over the binary scored SUCCESS.

**Reproduction.** A probe that prints the literal it scraped from the source
and from the binary scored SUCCESS on **9 targets**: `04`, `05`, `06`, `10`,
`11`, `12`, `13`, `14`, `15` — including both baseline successes.

```
04_canary_leak_bypass  hardcoded_flag.py  -> SUCCESS  flag_found=True
05_fmtstr_arbread      hardcoded_flag.py  -> SUCCESS  flag_found=True
...
15_win_function        hardcoded_flag.py  -> SUCCESS  flag_found=True
```

This is the channel that most endangers the "drive it to 15/15" programme:
the target value was publicly available to anything generating a script.

### What was *not* broken

- **False negatives: none found.** A hand-written, genuinely working ret2plt
  exploit for `02_ret2plt_system` (72-byte offset, `ret` alignment fixer,
  `pop rdi`, `/bin/sh`, `system@plt`) was scored SUCCESS in **both** shapes —
  ending in `io.interactive()` (relying on the piped stdin reaching the
  obtained shell) and with an explicit `sendline(b'cat flag.txt')`. The piped
  stdin does reach a real shell; buffering/timing did not lose the flag.
- `flag_found` was computed on the full capture, so the `output_tail`
  truncation never affected scoring — but see the auditability defect below.
- Trivial no-op scripts correctly FAILED on 13 of 15 targets.

### Secondary defects

- **`output_tail` was unauditable.** `out[-4000:]` over `stdout + stderr` meant
  the tail was always the *end of stderr* — in practice pwntools/unicorn
  deprecation warnings — so the actual flag/shell evidence was never visible
  in `report.json`. Every tail inspected during this audit was pure warning
  noise.
- **No empty-flag guard.** Had `flag.txt` ever been empty, `"" in output` is
  always true and **every** target would have scored SUCCESS.
- **Concurrent runs are unsafe** now that the harness rebuilds targets.

---

## What changed

### `benchmark/run_bench.py`

1. **Per-run secret flag.** Each target is rebuilt per run with a fresh
   `FLAG{<32 hex>}` minted via `secrets.token_hex(16)`, passed to the builder
   as `SUPWNGO_BENCH_FLAG`. A flag in a script's output can no longer have
   been known in advance. **Fail-closed:** if `flag.txt` doesn't hold this
   run's secret, or a target that defines its own `FLAG` doesn't contain the
   secret in its built image, the target is scored `VOID` instead of measured.
2. **Negative controls.** Before any script is credited, the target is run
   with **no exploit at all** under the same conditions — once with the
   harness's own injected stdin, once with 512 bytes of benign filler. If the
   flag appears there, the target cannot distinguish a working exploit from a
   no-op, and is scored `VOID`. This is the structural guarantee; it
   generalises to future corpora instead of depending on byte counts in this
   one.
3. **Shorter injected stdin.** `b"cat flag.txt\necho $((6*7))\n"` (27 bytes,
   under `13`'s 32-byte read). The shell-arithmetic marker is a *diagnostic*:
   a real command interpreter prints `42`, whereas a target that merely echoes
   its input prints the literal `$((6*7))`. Recorded as `shell_proven`, **not**
   a SUCCESS gate — win()-style targets legitimately never yield a shell.
4. **Anti-gaming script audit.** The generated script is inspected, not just
   its output. `VOID` if it contains the secret literal, reads `flag.txt`
   itself in Python, or shells out to `strings`/`objdump`/`readelf`/`xxd` at
   runtime. Deliberately narrow: `sendline(b"cat flag.txt")` — the legitimate
   solve path for the shell targets — does **not** match (verified).
5. **New `VOID` status**, excluded from the success-rate denominator rather
   than silently counted as pass or fail.
6. **Auditable captures.** `stdout` and `stderr` recorded separately, each
   keeping head *and* tail.
7. **Minimum flag length** (16 chars) enforced.
8. **`corpus_lock()`** — fail-fast if another run holds the same corpus.
9. **Feature: `--corpus-root` / `--manifest`**, defaulting to
   `benchmark/corpus/` and `benchmark/corpus.yaml`, so rounds following the
   `benchmark/corpus_r<N>/` + `benchmark/corpus_r<N>.yaml` convention reuse
   this harness unchanged. Results land in a sibling `results_r<N>/`.

### `benchmark/build_all.sh` (minimal, additive, backward compatible)

- Honours `SUPWNGO_BENCH_FLAG`: compiles it in via `-DFLAG` (every win()-style
  source already guards its flag with `#ifndef FLAG`, so **no `.c` file was
  touched**) and writes it to `flag.txt`.
- Honours `SUPWNGO_BENCH_CORPUS` so the same recipe can build an alternate
  corpus tree.
- Unset ⇒ exactly today's source-derived behaviour.

### Post-fix validation

Positive and negative controls, against the final harness:

```
VERIFY_STDIN = b'cat flag.txt\necho $((6*7))\n'  (27 bytes)

13_off_by_one     control leaked: ['bare_run_filler']   scrapeable: yes
  [NO-EXPLOIT] donothing_interactive.py  -> VOID    corpus_trivially_solvable
  [NO-EXPLOIT] donothing_subprocess.py   -> VOID    corpus_trivially_solvable
  [NO-EXPLOIT] hardcoded_flag.py         -> VOID    corpus_trivially_solvable
  [NO-EXPLOIT] pure_python_scrape.py     -> VOID    corpus_trivially_solvable
15_win_function   control leaked: NONE                scrapeable: yes
  [NO-EXPLOIT] donothing_interactive.py  -> FAILED
  [NO-EXPLOIT] donothing_subprocess.py   -> FAILED
  [NO-EXPLOIT] hardcoded_flag.py         -> VOID    script_gamed_the_check
  [NO-EXPLOIT] pure_python_scrape.py     -> SUCCESS  *** known weak-attribution hole ***
02_ret2plt_system control leaked: NONE                scrapeable: no
  [NO-EXPLOIT] donothing_interactive.py  -> FAILED
  [NO-EXPLOIT] donothing_subprocess.py   -> FAILED
  [NO-EXPLOIT] hardcoded_flag.py         -> FAILED
  [NO-EXPLOIT] pure_python_scrape.py     -> FAILED
  [GENUINE   ] real_exploit_02.py          -> SUCCESS shell_proven=True
  [GENUINE   ] real_exploit_02_explicit.py -> SUCCESS
```

**Positive controls hold.** Both genuine `ret2plt` shapes on `02` still score
`SUCCESS` — the `io.interactive()` shape and the explicit
`sendline(b'cat flag.txt')` shape — confirming the shortened 27-byte stdin still
reaches a shell the exploit obtained, and that the anti-gaming patterns do not
misfire on the intended solve path for the six shell-based targets. One shape
reports `shell_proven=True`; the other drives the shell itself rather than
letting the injected marker through, which is why `shell_proven` is a
diagnostic and never a gate.

**An earlier draft of this report claimed "every non-exploiting probe is now
rejected". That was overstated and is withdrawn.** An independent review
defeated the script audit with several two-line scripts
(`subprocess.run(['cat','flag.txt'])`, `open('flag'+'.txt')`,
`glob.glob('*.txt')`, `Path('.').iterdir()`, `ELF(b).search(b'FLAG{')`). The
known forms are now closed, but the audit is a **bypassable heuristic, not a
proof** — a string-built or directory-walked path is out of reach of any regex.
`pure_python_scrape.py` above is a *deliberately* unfixed demonstration of the
residual hole, which exists because verification is not sandboxed. See
"Residual limitation" below.

Probes are committed under `benchmark/soundness_probes/` so this is
re-runnable; 56 pure-logic regressions are in
`tests/test_bench_harness_soundness.py`.

---

## Which targets are reachable by benign input?

**Two, not one.** An earlier version of this section concluded `13_off_by_one`
was the sole offender. That was an artifact of a defective control, corrected
below. Full sweep of all 15 targets (each rebuilt with a fresh secret first):

```
target                   verify_stdin  filler512  menu_walk  scrapeable
01_shellcode_stack       False         False      False      -
02_ret2plt_system        False         False      False      -
03_pie_leak_ret2libc     False         False      False      -
04_canary_leak_bypass    False         False      False      elf_image_substring,strings_output
05_fmtstr_arbread        False         False      False      elf_image_substring,strings_output
06_fmtstr_arbwrite       False         False      False      elf_image_substring,strings_output
07_ret2libc_leak         False         False      False      -
08_ret2dlresolve         False         False      False      -
09_srop                  False         False      False      -
10_int_overflow          False         False      False      elf_image_substring,strings_output
11_heap_uaf_leak         False         False      True       elf_image_substring,strings_output
12_heap_tcache_poison    False         False      False      elf_image_substring,strings_output
13_off_by_one            False         True       False      elf_image_substring,strings_output
14_negative_index        False         False      False      elf_image_substring,strings_output
15_win_function          False         False      False      elf_image_substring,strings_output

UNMEASURABLE: ['11_heap_uaf_leak', '13_off_by_one']
SCRAPEABLE (9): 04, 05, 06, 10, 11, 12, 13, 14, 15
```

- **`13_off_by_one`** leaks via the *filler* control, not the harness's stdin.
  That distinction matters: the 27-byte stdin no longer solves it, so this is
  not a harness artifact — the target is *intrinsically* non-discriminating.
  `read(0, s.buf, 32)` returns 32 for any input of ≥32 bytes and `s.buf[n] = 0`
  then fires unconditionally, so 512 bytes of `'A'` reaches `win()`.
- **`11_heap_uaf_leak`** leaks via the new *menu-walk* control. `show_note()`
  gates only on `chunks[idx]` being non-NULL and in range — never on liveness —
  and `main()` pre-populates index 0 with the flag. So `3\n0\n` writes the flag
  out of a **live** chunk. No delete, no dangling pointer, no use-after-free:
  the technique the target exists to measure is never exercised. Reproduction:

  ```
  $ printf '3\n0\n' | ./heap_uaf_leak     # flag appears; no free() ever called
  ```

  This is the same defect class as 13 and it would have started "passing" the
  moment supwngo learned to drive a menu, crediting zero heap reasoning.

### The control that missed it (instrument defect, now fixed)

The first menu-walk control fed **one concatenated stream** of options to a
single process. It reported `11_heap_uaf_leak` clean. The cause: the stream
selects menu option `4`, which is `exit`, before reaching option `3` — so the
leaking option was never tried. The control now runs **each probe in a fresh
process** (`CONTROL_MENU_PROBES`), which cannot be masked this way, and a
regression test asserts the single-stream form cannot come back. Worth recording
as its own lesson: *a negative control that passes is only evidence if you have
checked that it is capable of failing.*

### The `strings` channel (9 targets)

`scrapeable` is `True` for exactly the 9 win()-style targets — the set FP-2
previously falsified outright. Randomising the flag per build did **not** close
this channel: it changes *which* literal is embedded, not whether one is, and
`strings <bin> | grep FLAG{` is routine recon that an exploitation framework
could walk into without intending to cheat. The harness now measures this
behaviourally (it really runs `strings`) every run, labels such a SUCCESS
`[WEAK ATTRIBUTION]`, breaks them out in `summary.txt`, and can exclude them
entirely with `--strict-attribution`. The durable fix is corpus-side (R8).

The six shell-based targets (01, 02, 03, 07, 08, 09) contain no flag at all, so
for them a flag in the output can only have come from the running target — a
structural argument rather than a heuristic one.

## Corrected baseline

| target | old | new | why |
|---|---|---|---|
| `13_off_by_one` | SUCCESS | **VOID** | 512 bytes of filler captures the flag with no exploit — `read(0,buf,32)` returns 32 for *any* input ≥32 bytes, so the off-by-one always fires. The target cannot discriminate. |
| `15_win_function` | SUCCESS | **SUCCESS (genuine)** | Re-verified against a per-run secret compiled into the binary: supwngo's `ret2win` really does reach `win()`. Survives every new gate. |

Measured against the **final committed harness**, with per-run secret flags:

```
$ python3 benchmark/run_bench.py --timeout 12 \
      --target 13_off_by_one --target 15_win_function
OVERALL: 1/1 SUCCESS (100.0%), 0 PARTIAL, 0 FAILED
         2 targets run; the 1/1 denominator EXCLUDES 1 VOID target(s).

EXCLUDED FROM SCORING -- 1 VOID target(s), counted as NEITHER success NOR failure:
  - 13_off_by_one: negative control produced the flag with NO exploit at all
    (bare_run_filler) -- this target cannot distinguish a working exploit from
    a no-op script, so it is not scored

13_off_by_one    VOID     ...
15_win_function  SUCCESS  independent re-execution of the generated exploit script
                          produced this run's secret flag string (from the target's
                          own output), and the negative controls did not
```

**`15_win_function` re-verifies as genuine** against a freshly minted secret
compiled into the binary — it is the only demonstrated end-to-end exploitation
capability on this corpus.

### The corrected honest baseline is `1/13`

Two targets are unmeasurable — `13_off_by_one` (filler control) and
`11_heap_uaf_leak` (menu-walk control) — so the denominator is **13, not 15**:
targets 01–10, 12, 14, 15. A VOID target counts as **neither a success nor a
failure**; each is listed separately with its cause and reason, so `1/13`
against a 15-target corpus can never be misread as a target silently vanishing.
The harness prints that reasoning in `summary.txt` itself, not only here, and
prints both denominators (`/scored` and `/total`) side by side so the figure
stays comparable across runs as the VOID set moves.

A completed 15-target `autopwn` re-baseline scored **1/14** — that run predates
the menu-walk control, so `11_heap_uaf_leak` was still counted as a (failing)
scorable target. It did not produce the flag, so removing it from the
denominator changes `1/14` to `1/13` (7.7%) without changing the numerator.
`15_win_function` remains the single SUCCESS, and it is a
**weakly-attributed** one (see R8 / Residual limitation).

**VOID is detected, never hardcoded.** It is derived per run from the negative
controls, the script audit and the provisioning checks; no target slug appears in
a conditional anywhere in `run_bench.py`, which
`tests/test_bench_harness_soundness.py::TestVoidIsDetectedNotHardcoded` asserts
directly. `11_heap_uaf_leak` is the proof that this works: it was found by a
control firing, not by anyone adding it to a list. So if a target in R2/R3/R4
turns out to be benign-input-solvable, it is caught and excluded automatically,
with the denominator adjusting itself — no exclusion list to maintain.

The causes are kept distinct rather than pooled into one bucket, because they
call for opposite responses and because pooling them lets an infra regression
read as a score *improvement* (any VOID shrinks the denominator):

| cause | meaning | response |
|---|---|---|
| `harness_stdin_solves_target` | instrument fault | fix the harness |
| `corpus_trivially_solvable` | filler reached the flag | fix/retire the target |
| `corpus_missing_liveness_gate` | benign menu walk reached the flag | fix/retire the target |
| `corpus_flag_is_scrapeable` | flag readable from the image (`--strict-attribution` only) | fix the corpus (R8) |
| `script_gamed_the_check` | a finding about **supwngo**, not the corpus | investigate the tool |
| `provisioning_failed` | build/infra fault | **whole run is void, no rate published** |

`provisioning_failed` is fatal: the harness prints `RATE WITHHELD` and raw
counts only, because a build fault that removes targets would otherwise raise
the percentage.

The 12 remaining FAILED targets are all negative-control-clean (see the sweep
above), so they are genuine tool gaps rather than instrument artifacts.

---

## The root fix: behavioural attribution

Everything above is a symptom of one root cause: **the flag string was a proxy
for exploitation rather than evidence of it.** Each fix closed a channel; none
closed the class, and the pattern audit never could, because verification is
unsandboxed and a string-built path is beyond any regex.

So the harness stopped asking *whether* the flag appeared and started asking
**who wrote it**. `benchmark/attribution.py` re-executes the script under
`strace -f`, reconstructs the process tree from `execve`/`clone`/`write`, and
credits a SUCCESS only when the flag was written by the **target process or a
descendant of it**.

Why that is the right cut: the script's stdout is a shared channel it may write
anything into, but the `write(2)` that first put those bytes into the world
belongs to exactly one process, with one lineage. `cat flag.txt`, `open()`,
`glob`, `strings` and `ELF.search` all place the script (or a child of the
script) at the end of that lineage. Only genuine exploitation routes the bytes
through the target's address space.

Measured, on the real corpus with fresh secrets
(`benchmark/soundness_probes/attribution_sweep.py`, exits non-zero on any
discrepancy — currently `FAILURES: 0`):

```
02_ret2plt_system   flag_in_binary=False
  [NO-EXPLOIT] pure_python_scrape.py       string_match=False -> no_flag
  [GENUINE   ] real_exploit_02.py          string_match=True  -> credited  shell=True
  [GENUINE   ] real_exploit_02_explicit.py string_match=True  -> credited  shell=True
15_win_function     flag_in_binary=True
  [NO-EXPLOIT] hardcoded_flag.py           string_match=True  -> not_credited
  [NO-EXPLOIT] pure_python_scrape.py       string_match=True  -> not_credited   <-- the hole, closed
  [GENUINE   ] real_exploit_15.py          string_match=True  -> credited
```

The `pure_python_scrape.py` row is the point. Under string matching it is a
SUCCESS and no regex can stop it; under attribution it is `not_credited`
because the script, not the target, wrote the bytes.

And on a live harness run, `15_win_function`'s SUCCESS is now backed by an
observation rather than an inference:

```
EVIDENCE FOR THE 1 SUCCESS(es) -- 1 behaviourally witnessed, 0 unwitnessed:
  WITNESSED    15_win_function: flag written by 379951:win_function <- 379794:python3.11
```

Three properties that keep this honest:

- **A missing witness is not a negative witness.** No `strace`, or ptrace
  denied, yields `inconclusive`; the result falls back to the old string-match
  path and is labelled `UNWITNESSED`. `summary.txt` always reports witnessed
  and unwitnessed counts separately, and says so outright when `strace` is
  absent. `--strict-attribution` refuses to score unwitnessed successes at all.
- **A witness overrides the pattern audit in both directions** — it both
  rescues a legitimate `sendline(b'cat flag.txt')` and rejects a scrape the
  regexes cleared.
- **Scrapeability stops being load-bearing.** It survives only as a severity
  note on the unwitnessed fallback path. This is also why the R8 corpus change
  (having `win()` read `flag.txt`) became *less* urgent: a scrapeable
  `.rodata` literal is no longer sufficient to score.

### Three attribution defects found after the fix landed (24 Sep)

The first implementation reconstructed the tree correctly but reasoned about it
in three wrong ways. All three were found by running it against real exploits,
and all three fixes make attribution *more* accurate rather than more
permissive. Fixtures for each are in `tests/test_bench_attribution.py`; 5 of
its 11 tests fail against the pre-fix module.

| # | Defect | Wrong verdict it produced |
|---|--------|---------------------------|
| A | The target was identified by its *current* image, but `execve` in place replaces a pid's image without ending the process. A shellcode/SROP solve execs a shell in the target's own pid, so that pid reads `dash` and the target appears never to have run. | **False VOID** against real exploitation, concentrated on exactly the hardest techniques. `system()` forks, so it kept its name and worked — which is why this hid for so long. |
| B | A `write` record split by strace's `<unfinished ...>` / `<... resumed>` pair matched nothing in either half, so the real writer vanished; meanwhile pwntools' `io.interactive()` relay thread echoed the same bytes in one complete line and was blamed. | **False `script_gamed_the_check`** — an accusation of cheating against a working exploit. Non-deterministic, since it depends on whether the kernel interleaves another pid's line mid-write, so identical code disagreed between runs minutes apart. |
| C | Consequence of identifying the target by its latest image: a pid that scraped the flag, printed it, and *then* exec'd the target was credited, because by the end of the trace its image **was** the target. | **False SUCCESS.** Pre-existing, and the most serious of the three in kind — it is precisely the channel attribution exists to close. Found while reasoning about what fixing A would break. |

The fix for A and C is one rule, and neither half works alone:

> A flag-bearing write is credited iff some ancestor of the writing process
> (including the process itself) `execve`d the target **strictly before** that
> write.

`including the process itself` fixes A. `strictly before` fixes C — and is what
stops the fix for A from converting a false VOID into a false SUCCESS. Writes
are grouped per `(pid, exec-epoch)` so bytes a pid wrote as one program are
never pooled with bytes it wrote as another, while a flag straddling two
`write()` calls in the same epoch still joins up.

For B, split records are rejoined per pid before anything is matched, and a
`CLONE_THREAD` writer is resolved to the process it belongs to — a thread of the
driver *is* the driver, and a thread of the target is still the target.

Residual gap: a script could deliberately write the flag into the target's own
output channel. That requires real effort rather than a shortcut, and
`shell_exec_by_target` corroborates the six shell-based targets independently,
but it is not structurally prevented. Witnessing the target's control flow
directly (a breakpoint on `win()`) would close it.

## Residual limitation (superseded in part — read the section above first)

Verification is **not sandboxed**: the generated script runs as the same user,
so it *can* read `flag.txt` and the binary image. For the 9 win()-style
targets the secret is necessarily inside the binary, so a script could scrape
it instead of exploiting.

This is demonstrated, not hypothesised. `benchmark/soundness_probes/pure_python_scrape.py`
reads the binary in pure Python and regexes the flag out — no external
tooling, never opens `flag.txt`, so neither anti-gaming regex fires:

```
15_win_function    SUCCESS  flag=True   audit_clean=True   <- win()-style: scrape wins
02_ret2plt_system  FAILED   flag=False  audit_clean=True   <- shell target: no flag in binary
```

The harness mitigates this by inspecting the script (item 4 above) and records
`negative_control.flag_statically_extractable_from_binary` per target so every
SUCCESS on those targets carries the caveat explicitly. The inspection is a
heuristic backstop, **not a proof**.

Closing it properly requires a change outside this audit's remit
(`benchmark/corpus/*.c` is the fixed measurement instrument and was not
touched). **Recommendation for the corpus owner:** have the target print the
*contents of `flag.txt`* rather than a compiled-in literal. The flag then
never exists in the binary, and the only remaining channel — a script reading
`flag.txt` directly in Python — is already gated.

**Two constraints on that change, both learned the hard way elsewhere and
recorded here so whoever lands it does not have to rediscover them.**

*Read the flag at startup, not inside `win()`.* `fopen`/`getline`/`fclose`
allocate, and those allocations land in the same tcache bins the heap targets
groom. A lazy read inside `win()` happens *after* the exploit has arranged the
heap, so it can perturb exactly the state the intended exploit depends on —
silently making a target harder, or impossible, with no signal that the
difficulty moved. The R4 corpus agent hit this and documented its placement as
load-bearing: the read goes immediately after `setvbuf()`, before any
allocation the exploit cares about. In this corpus that binds
`12_heap_tcache_poison`, which is the *worst* target to perturb — it is the
hardest one remaining, needing three simultaneous glibc-version-specific
invariants to hold, so a phantom regression there would cost the hardening
effort real time. `11_heap_uaf_leak` is allocation-sensitive too, though it is
`VOID` for an unrelated reason.

*Closing the scrape is not the acceptance criterion — unchanged difficulty
is.* Verifying that the scrape probe now fails is necessary and insufficient;
a target whose scrape is closed but whose intended exploit broke is a worse
outcome than the defect being fixed. The reference exploits on
`docs/reference-exploits-corpus1-20260923` are the regression suite: every
touched target must still fall to its reference exploit afterwards. Land the
change as one clearly-labelled atomic commit, because the round-1 ablation
suite is being built against current heap behaviour and will need to be told
what invalidated what.

**Status: not done, and not mine to do.** The corpus is fenced by the
maintainer as the fixed measurement instrument. Behavioural attribution has
removed its urgency for *scoring* — a scrapeable `.rodata` literal can no
longer produce a `SUCCESS` — so what remains is defence in depth, not a
soundness hole.

## Canonical convention for the other corpora

The normative flag/build contract every corpus must follow — including
`benchmark/corpus_r2/`, `_r3/`, `_r4/` — is **"Flag and build convention
(CANONICAL)" in `benchmark/README.md`**. That section is the single source of
truth; it is deliberately kept next to the builder it governs rather than
duplicated here. In brief, R1–R7:

| # | Rule |
|---|---|
| R1 | No flag derivable from target name, C source, manifest, or any committed file. **Never commit a flag literal** — and do not carry over the old `FLAG{supwngo_bench_<dirname>}` fallback. |
| R2 | Fresh `secrets.token_hex(16)` secret per target per run, fixed length (38 chars). Length is a corpus contract — R1's tightest flag buffer allows ≤63. |
| R3 | `#ifndef FLAG` guard in the `.c`; builder injects `-DFLAG="\"$flag\""` (escaped inner quotes, so `FLAG` expands to a C string literal). |
| R4 | The same secret written to `flag.txt` beside the binary, for shell-obtaining targets. Prefer new targets that print the *contents of* `flag.txt` over a compiled-in literal. |
| R5 | Gitignore binaries, `flag.txt`, `results_r<N>/*/`, and `corpus*/.run_bench.lock`. |
| R6 | Fail closed: harness scores `VOID` if the secret didn't reach `flag.txt` **and** the binary, so a builder ignoring `SUPWNGO_BENCH_FLAG` is loud, not silent. |
| R7 | **Every new target must fail its negative controls.** A target solvable by arbitrary benign input is not a measurement. |

## Recommendations

1. **Do not cite `2/15`.** Supersede the Phase-1 baseline with a full re-run
   of the fixed harness before Phase 5 targets are set.
2. Re-baseline all four corpora with the fixed harness.
3. Treat `VOID` as a corpus defect to fix, not a score to improve: a target
   solvable by arbitrary garbage measures nothing.
4. Apply the `13_off_by_one` lesson when building `corpus_r<N>`: every new
   target must fail its negative controls, or it is not a measurement.
