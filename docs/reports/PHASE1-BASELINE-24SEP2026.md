# Phase-1 baseline: `supwngo autopwn` vs. the 15-target benchmark corpus

**Date:** 24 Sep 2026
**Branch:** `feat/benchmark-corpus-20260923`, rebased onto `integration/phases-0-4-7-20260923`
**Run:** `benchmark/results/20260924-014522Z/` (`report.json` + `summary.txt`)
**Harness:** `benchmark/run_bench.py --timeout 12` (see `benchmark/README.md` for full methodology)

This is the first honest Phase-1 baseline called for by
`docs/plans/2026-09-23-effectiveness-and-usability.md`. It measures the
**fully consolidated pipeline** — Phase 0 (importable baseline), Phase 2
(`CanonicalAutopwnEngine` consolidation), Phase 3 (repaired
leak/Z3/tester modules), Phase 4 (structured hand-off), Phase 6 (`solve`
command + the exploit-script-on-success fix), and the
`ExploitVerifier.verify_payload()` interactive-shell-verification fix — all
present on the branch this run executed against. This is the number Phase 5
(reliability hardening) should treat as its starting point.

## Headline result

```
OVERALL: 2/15 SUCCESS (13.3%), 0 PARTIAL, 13 FAILED
  easy:   2/5 SUCCESS (40%)
  medium: 0/7 SUCCESS (0%)
  hard:   0/3 SUCCESS (0%)
```

## Classification rule (never trust the tool's own claim)

Per target, the harness:

1. Runs `python3 -m supwngo.cli autopwn <binary> --timeout 12 --json` to
   capture `autopwn`'s own structured self-report.
2. Runs it a second time without `--json` (with `-o <script>`), since
   `cli.py`'s `autopwn` command only writes the generated script to `-o`
   inside the non-JSON branch.
3. **Independently, genuinely verifies the result**: re-executes the
   generated script as a *fresh* subprocess, feeds it a small fixed benign
   stdin script (`cat flag.txt` + a marker echo, so a shell-obtaining
   exploit gets a chance to read the flag file the way a human would), and
   checks whether the exact, target-specific flag string appears in its
   captured output.
4. Classifies:
   - **SUCCESS** — the independent re-run in step 3 produced the flag. This
     is the *only* thing that determines SUCCESS.
   - **PARTIAL** — `autopwn` self-reported success (or a successful
     intermediate attempt) but the independent re-run did not reproduce the
     flag.
   - **FAILED** — neither of the above.

On this run, **0 targets were PARTIAL** — `autopwn`'s own `success` field
agreed with independent verification on all 15 targets (`true` for
`13_off_by_one`/`15_win_function`, `false` for the other 13). The FAILED
results are not a case of the tool over-claiming; it correctly reported
failure on those 13 by its own logic too.

## Per-target results

| # | slug | difficulty | intended technique | status | wall time | non-skipped techniques `autopwn` actually tried |
|---|------|-----------|---------------------|--------|-----------|---------------------------------------------------|
| 01 | shellcode_stack | easy | stack_shellcode | FAILED | 122.8s | direct_shellcode, variable_overwrite, format_string |
| 02 | ret2plt_system | easy | ret2plt_system | FAILED | 118.0s | variable_overwrite, ret2libc, format_string |
| 03 | pie_leak_ret2libc | medium | pie_leak_ret2libc | FAILED | 253.3s | variable_overwrite, ret2libc, format_string |
| 04 | canary_leak_bypass | medium | canary_leak_bypass | FAILED | 136.2s | ret2win, variable_overwrite, negative_size_bypass, format_string |
| 05 | fmtstr_arbread | medium | fmtstr_arbread | FAILED | 125.6s | ret2win, variable_overwrite, negative_size_bypass, format_string |
| 06 | fmtstr_arbwrite | medium | fmtstr_arbwrite | FAILED | 98.1s | ret2win, variable_overwrite, negative_size_bypass, format_string |
| 07 | ret2libc_leak | medium | ret2libc_leak | FAILED | 215.4s | variable_overwrite, ret2libc, format_string |
| 08 | ret2dlresolve | hard | ret2dlresolve | FAILED | 118.7s | variable_overwrite |
| 09 | srop | hard | srop | FAILED | 118.2s | variable_overwrite, format_string |
| 10 | int_overflow | medium | integer_overflow | FAILED | 97.7s | ret2win, variable_overwrite, negative_size_bypass, format_string |
| 11 | heap_uaf_leak | medium | heap_uaf_read | FAILED | 88.0s | variable_overwrite, format_string |
| 12 | heap_tcache_poison | hard | heap_tcache_poison | FAILED | 97.8s | ret2win, variable_overwrite, negative_size_bypass, format_string, uaf, double_free |
| 13 | off_by_one | easy | off_by_one | **SUCCESS** | 5.6s | ret2win |
| 14 | negative_index | easy | negative_index_oob_write | FAILED | 98.2s | ret2win, variable_overwrite |
| 15 | win_function | easy | ret2win_baseline | **SUCCESS** | 5.6s | ret2win |

(`elapsed_sec` covers both `autopwn` invocations plus the independent
verification re-run per target; the "techniques tried" column excludes
entries the engine itself marked `SKIPPED` as not applicable to that
target.)

### What this actually shows

`autopwn`'s technique-attempt list is currently a **fixed set of ~11
generic executors** (`variable_overwrite`, `ret2win`, `ret2libc`,
`direct_shellcode`, `negative_size_bypass`, `format_string`, `uaf`,
`double_free`, `scanf_canary_bypass`, `srop`, `stack_shellcode`) tried in
strategy-ranked order against every target, regardless of which technique a
target actually needs. That explains most of the FAILED results directly:

- **No dedicated executor exists yet** for `ret2dlresolve` (08), a real
  ROP-driven `SROP`/`execve` setup (09 — `srop` is in the executor list by
  name but never reached verification here), `format_string`-driven
  *arbitrary write* to flip a gate variable (06 — the generic
  `format_string` executor tried but didn't succeed), genuine heap
  UAF-read/tcache-poison exploitation (11, 12 — `uaf`/`double_free` are
  present but didn't reach the corpus's actual technique), or
  negative-index OOB writes (14).
- **`ret2libc`'s current implementation apparently requires a leaked libc
  base even when the target doesn't need one.** Spot-checking
  `02_ret2plt_system` with the new `solve` command (see below) shows its
  structured hand-off gating `ret2libc` on "libc base not leaked" —
  but `02_ret2plt_system` calls `system@plt` directly with a fixed
  `"/bin/sh"` string already in the binary; no leak is required at all
  (see its `benchmark/corpus.yaml` entry). This is a real, specific gap in
  the tool's current strategy set worth a Phase 5 look, not a corpus
  artifact — targets 02, 03, and 07 all attempted `ret2libc` and all
  failed, and 02 specifically shouldn't have needed the leak the tool is
  blocking on.
- The two successes (13, 15) are exactly the two targets whose intended
  technique — `ret2win` — *is* one of the fully-implemented, well-tested
  generic executors.

### `solve` cross-check

The plan also asked for a spot-check of the new `solve` command (Phase 6,
a thin wrapper over the same `CanonicalAutopwnEngine`) against a couple of
targets:

- **`15_win_function`**: `solve` reached the same verified
  `SUCCESS`/`FLAG_CAPTURED` result as `autopwn`, and — unlike `autopwn`,
  where `-o` is opt-in — wrote a working exploit script by default to
  `solve_output/win_function_exploit.py`. Independently re-running that
  script fresh (fed the same benign `cat flag.txt` stdin) reproduced the
  flag, confirming `solve`'s "always write a working script on success"
  guarantee holds for this target.
- **`02_ret2plt_system`**: `solve` reached the same `FAILED` result as
  `autopwn`, and its structured hand-off surfaced the `ret2libc`
  leak-gating gap described above.

## Why four earlier runs were discarded

This worktree's `feat/benchmark-corpus-20260923` branch originally forked
from `fix/phase0-import-baseline-20260923` — the only branch that existed
when corpus construction started — and was not rebased when
Phase 2/3/4/6 later landed on `integration/phases-0-4-7-20260923`. Four
benchmark runs were executed before this was caught (confirmed by the
generated scripts' own docstring: `"Generated by supwngo
EnhancedAutoExploit"`, the pre-consolidation engine's template header, not
the canonical pipeline's). Coincidentally, those runs also measured
2/15 (13.3%) with the same two successes — but they were benchmarking the
wrong code (the old `EnhancedAutoExploiter`, pre-verification-fix in three
of the four cases), not the tool this repository is actually building.
They are preserved, clearly marked, at
`benchmark/results/_stale_pre_consolidation/` (see that directory's
`NOTE.txt`) for audit purposes only — **do not cite their numbers**. This
report's run, `20260924-014522Z`, is the first one executed after the
branch was rebased onto `integration/phases-0-4-7-20260923`, and is the
authoritative Phase-1 baseline.

## Harness bug found and fixed while producing this baseline

The first post-rebase run crashed `run_bench.py` partway through
(`03_pie_leak_ret2libc`) with `TypeError: argument should be integer or
bytes-like object, not 'str'`. Root cause: `subprocess.run(...,
text=True)` re-raises a `subprocess.TimeoutExpired` from
`Popen.communicate()` as-is — the text-decoding step only runs on the
success path, so `TimeoutExpired.stdout`/`.stderr` are always raw bytes
even when `text=True` was requested. `03_pie_leak_ret2libc`'s `autopwn
--json` invocation took long enough (of the ~11 generic techniques,
several ran against a PIE target) to exceed the harness's per-invocation
wall-clock guard, triggering the bug. Fixed in `run_bench.py`'s
`run_supwngo()`: the `TimeoutExpired` branch now decodes bytes
defensively, and the wall-clock guard itself was raised (from
`max(60, timeout*10+30)` to `max(120, timeout*15+60)`) to reflect the
consolidated pipeline's larger technique-attempt budget (~11 techniques,
not the ~7 the original math assumed). See commit
`fix(benchmark): decode bytes from timed-out subprocess, raise wall-clock budget`.

## Reproducing this baseline

```bash
git checkout feat/benchmark-corpus-20260923
python3 benchmark/run_bench.py --timeout 12
# see the freshly generated benchmark/results/<timestamp>/{report.json,summary.txt}
```
