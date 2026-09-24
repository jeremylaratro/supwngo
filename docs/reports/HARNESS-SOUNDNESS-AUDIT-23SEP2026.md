# Benchmark harness soundness audit — `benchmark/run_bench.py`

**Date:** 23 Sep 2026
**Auditor branch:** `fix/benchmark-harness-soundness-20260923` (off `integration/phases-0-4-7-20260923`)
**Subject:** the Phase-1 measurement instrument — `benchmark/run_bench.py` + `benchmark/build_all.sh`
**Verdict:** **the harness was UNSOUND. The 2/15 (13.3%) baseline in `docs/reports/PHASE1-BASELINE-24SEP2026.md` does not stand.**

---

## Headline: the harness could report SUCCESS with zero exploitation

Two independent false-positive channels were found and reproduced. Between
them they could manufacture SUCCESS on **10 of the 15 targets, including both
targets the 2/15 baseline rested on.**

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

Every non-exploiting probe is now rejected, and both genuine exploit shapes
still pass:

```
13_off_by_one    negative control leaked: ['bare_run_filler']
  [NO-EXPLOIT] donothing_subprocess.py   -> VOID    ok
  [NO-EXPLOIT] hardcoded_flag.py         -> VOID    ok
15_win_function  negative control leaked: NONE
  [NO-EXPLOIT] donothing_subprocess.py   -> FAILED  ok
  [NO-EXPLOIT] hardcoded_flag.py         -> VOID    ok
02_ret2plt_system negative control leaked: NONE
  [NO-EXPLOIT] hardcoded_flag.py         -> VOID    ok
  [GENUINE   ] real_exploit_02.py           -> SUCCESS shell=True  ok
  [GENUINE   ] real_exploit_02_explicit.py  -> SUCCESS             ok
```

Probes are committed under `benchmark/soundness_probes/` so this is
re-runnable; pure-logic regressions are in
`tests/test_bench_harness_soundness.py`.

---

## Is `13_off_by_one` the only target reachable by benign input?

**Yes.** Swept all 15 targets' negative controls (each rebuilt with a fresh
secret first), on an isolated copy of the corpus via `--corpus-root`:

```
target                   verify_stdin   filler512   in_binary
01_shellcode_stack       False          False       False
02_ret2plt_system        False          False       False
03_pie_leak_ret2libc     False          False       False
04_canary_leak_bypass    False          False       True
05_fmtstr_arbread        False          False       True
06_fmtstr_arbwrite       False          False       True
07_ret2libc_leak         False          False       False
08_ret2dlresolve         False          False       False
09_srop                  False          False       False
10_int_overflow          False          False       True
11_heap_uaf_leak         False          False       True
12_heap_tcache_poison    False          False       True
13_off_by_one            False          True        True
14_negative_index        False          False       True
15_win_function          False          False       True

LEAK TO BENIGN INPUT: ['13_off_by_one']
```

Three things worth noting:

- **`13_off_by_one` is the sole offender**, and it now leaks via the *filler*
  control, not the harness's stdin. That distinction matters: the 27-byte
  stdin no longer solves it, so this is not a harness artifact — the target is
  *intrinsically* non-discriminating. `read(0, s.buf, 32)` returns 32 for any
  input of ≥32 bytes and `s.buf[n] = 0` then fires unconditionally, so 512
  bytes of `'A'` reaches `win()`. No exploitation technique is being measured.
- **All 14 other targets are clean** under both controls. The remaining
  FAILEDs are genuine tool gaps, not instrument noise.
- `in_binary` is `True` for exactly the 9 win()-style targets — the set
  subject to the residual scrape limitation above, and exactly the set that
  FP-2 previously falsified.

## Corrected baseline

| target | old | new | why |
|---|---|---|---|
| `13_off_by_one` | SUCCESS | **VOID** | 512 bytes of filler captures the flag with no exploit — `read(0,buf,32)` returns 32 for *any* input ≥32 bytes, so the off-by-one always fires. The target cannot discriminate. |
| `15_win_function` | SUCCESS | **SUCCESS (genuine)** | Re-verified against a per-run secret compiled into the binary: supwngo's `ret2win` really does reach `win()`. Survives every new gate. |

Measured directly:

```
$ python3 benchmark/run_bench.py --timeout 12 --target 13_off_by_one --target 15_win_function
OVERALL: 1/1 SUCCESS (100.0%) of scorable targets, 0 PARTIAL, 0 FAILED, 1 VOID -- 2 targets run
13_off_by_one    VOID     negative control produced the flag with NO exploit at all (bare_run_filler)
15_win_function  SUCCESS  ...produced this run's secret flag string (from the target's own output), and the negative controls did not
```

**So `2/15 (13.3%)` becomes `1/14 scorable (7.1%)`** — one genuine success, one
target withdrawn as unmeasurable. `15_win_function` is the only demonstrated
end-to-end exploitation capability on this corpus.

---

## Residual limitation (honest disclosure)

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
touched). **Recommendation for the corpus owner:** have `win()` print the
*contents of `flag.txt`* rather than a compiled-in literal. The flag then
never exists in the binary, and the only remaining channel — a script reading
`flag.txt` directly in Python — is already gated.

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
