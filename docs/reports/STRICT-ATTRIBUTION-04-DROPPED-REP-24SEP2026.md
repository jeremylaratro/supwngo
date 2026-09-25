# The one dropped rep in `04_canary_leak_bypass` — diagnosis

**Date:** 2026-09-24
**Plan:** `docs/plans/2026-09-24-strict-attribution-04-canary-dropped-rep.md`
**Branch:** `fix/strict-attribution-04-canary-20260924` (from `integration/phases-0-4-7-20260923`, `b3a40b4`)

## Verdict

**Explanation 1: ordinary contention noise. It is NOT a strict-attribution defect.**

The dropped rep never produced a flag at all, so there was no attributed flag
write for the strict path to decline. Strict mode is **provably not reachable**
from the branch that classified it. Strict is not under-crediting.

The failure is real, and it is upstream of attribution — upstream even of the
exploit. In that one rep, `autopwn`'s *leak-source discovery probe* failed to
observe the target's canary-leaking echo, so the pipeline never built an exploit;
it emitted its do-nothing fallback template instead.

**Measured rate: 1 failed rep in 10** (5 default + 5 strict reps of target 04, at
`jobs: 8`, with other benchmark agents running concurrently on the same host).
This is one observation, not a calibrated probability — see *Honest limits*.

## Correction to the artifact paths

The strict report is `benchmark/results/20260924-110437Z/`, not
`.../20260924-111152Z/`. Directories are named for a run's **start**; `111152Z` is
that run's `generated_at` (`2026-09-24T11:11:52Z`), i.e. its **end**. Verified by
`strict_attribution: true` in its `report.json`. No `20260924-111152Z` exists.

## Evidence

### 1. The dropped rep is rep 1, and it died at `PARTIAL` — before attribution

`20260924-110437Z/report.json`, `04_canary_leak_bypass` → `attempts[]`:

| rep | status | elapsed |
|----:|--------|--------:|
| 1 | **PARTIAL** | **111.0 s** |
| 2 | SUCCESS | 57.0 s |
| 3 | SUCCESS | 56.2 s |
| 4 | SUCCESS | 56.7 s |
| 5 | SUCCESS | 57.2 s |

All five default-mode reps: SUCCESS, 56.2–57.0 s.

Rep 1's reason is
`"autopwn self-reported success (or a successful intermediate attempt), but
independently re-running the generated script did not reproduce the flag"`.
That string is emitted from exactly one site in `benchmark/run_bench.py`
(line 852), and that site is reachable **only** when `verify["flag_found"]` is
false. So the flag never appeared in rep 1's independent re-run.

### 2. Strict mode cannot reach that branch

`strict_attribution` is a pure pass-through — argv → `run_targets` → `run_reps` →
`run_one` → `classify` — and `classify()` reads it at **exactly one** site,
line 810, which sits *inside* `if verify["flag_found"]:` (line 781). The `PARTIAL`
return is at line 851, outside and after that block. `benchmark/attribution.py`
has no knowledge of strict mode at all (its only `strict` match is the word
"strictly" in a comment).

Therefore a rep with `flag_found == false` classifies identically in both modes.
Strict did not decline anything here; it was never consulted.

### 3. No attribution was even attempted for rep 1

`run_one` gates the witness on the same condition (line 936: *"Only run when the
plain verification actually produced the flag — there is nothing to attribute
otherwise"*). Consistent with that, `rep1/04_canary_leak_bypass_attribution/`
**does not exist**, while reps 2–5 each have one. There is no archived
flag-bearing write, and no trace, for strict to have mis-read.

### 4. Root cause: the generated script in rep 1 was the no-technique fallback

This is the decisive artifact. Comparing the archived generated scripts:

```
112888a47b1be0eeca93bfb7dc49b0f5  strict  rep1..rep5  -> reps 2,3,4,5
5718f0472c78619125a8040c1bce1b56  strict  rep1        <-- the outlier
112888a47b1be0eeca93bfb7dc49b0f5  default rep1..rep5  -> all five
```

Nine of ten reps produced a **byte-identical working exploit**
(`Canary leak + ret2win ... technique: canary_leak_ret2win`). Strict rep 1 alone
produced `Universal Exploit Template ... (no technique verified)` — a stub with
`offset = 0  # TODO: confirm/find correct offset` and every payload line
commented out. It cannot produce a flag; it does nothing.

The stub's own embedded attempt table records why:

```
#   - canary_leak_ret2win: FAILED (canary is enabled but the target never hands
#     it back (no over-long raw echo, no user-controlled printf format))
```

So the `canary_leak_ret2win` executor failed at the **ANALYSIS** stage, in
`_discover_leak_sources`.

### 5. Where the flakiness lives

`supwngo/exploit/pipeline/executors/canary_leak_techniques.py`:

- `_probe_echo_sizes` sweeps `ECHO_FILL_SIZES` (13 sizes), each a **separate
  process launch** with `deliver_parts(..., timeout=2.0)`.
- Target 04 (`benchmark/corpus/04_canary_leak_bypass/canary_leak_bypass.c`) does
  `read(0, buf, 72)` → `write(1, buf, 72+8)` → `read(0, buf, 200)`. The echo
  exposes the canary at **exactly one** fill size: 72. Every other size in the
  sweep is structurally incapable of revealing it.
- `deliver_parts` collects output with `io.recvall(timeout=2.0)` and swallows any
  exception into `output = b""`. Because the target's second `read(0, buf, 200)`
  blocks (stdin is left open), that probe always waits the full 2.0 s wall.

So the entire technique rests on a **single 2.0-second-budget probe**. If that one
probe is starved of CPU — the host was running this benchmark's 8 workers plus a
second agent's concurrent benchmark — the echo is not seen inside the budget,
`_discover_leak_sources` returns empty, and the technique is declared
inapplicable. There is no retry and no confirmation pass.

This is the same *class* of defect as the previously localized unsynchronized send
(measured 4/96 under contention, 0/96 after synchronizing), but a **different
site**. Note that the fix from that work is present and working in the *generated*
exploit — reps 2–5's script carries `SETTLE = 0.12` and a `send_part()` helper
whose docstring names exactly that hazard. The surviving flakiness is in the
*discovery probe* that runs before any script exists, which has no equivalent
synchronization or retry.

### 6. The 111 s vs 57 s timing corroborates it

A successful rep short-circuits: `canary_leak_ret2win` verifies and the pipeline
stops. Rep 1's technique failed, so the pipeline continued through the remaining
techniques (`fmtstr_write_gate`, `tcache_poison_got`, `srop`, `ret2libc_leak`,
`ret2dlresolve`, `variable_overwrite`, `format_string` …), each with its own
probes and timeouts. The ~54 s of extra wall time is that tail — and note rep 1
was *slower* despite skipping the strace attribution pass that every successful
rep pays for. The extra time is spent failing, not being declined.

## Why I did not re-run

The plan set two pre-committed flip-conditions that would have justified gathering
more samples. **Neither is met:**

1. Dropped rep shows `verify.flag_found == true` with an
   `inconclusive`/`not_credited` verdict → **No.** The `PARTIAL` reason string is
   emitted only from the `flag_found == false` path.
2. Archived strace for the dropped rep shows an attributable flag-bearing write →
   **No.** No strace exists for rep 1; attribution never ran.

Re-running was rejected on the merits, not for cost: sampling estimates a *rate*
and cannot discriminate a race from a logic defect, because both are consistent
with either outcome. The question asked was *which explanation holds*, and that
was settled by the single read site of `strict_attribution` being dominated by the
`flag_found` guard — a proof, not an estimate. Re-running until the anomaly
vanished was the specific failure mode to avoid here.

## Honest limits

- **n = 1.** One failure in ten reps of one target. Do not quote "10%" as a
  failure probability; the sample cannot support it.
- **Per-rep records are slimmed.** `run_reps` keeps only
  `rep/status/reason/void_cause/secret_flag/elapsed_sec`, so rep 1's
  `verification` and `autopwn_json_probe` dicts are gone. The stage was
  recoverable only because (a) the reason string is unique to one branch and
  (b) the generated script embeds its own attempt table. That second property is
  load-bearing for post-hoc diagnosis and worth keeping.
- **`jobs: 8`, not 24.** Both reports record `jobs: 8`. Host-level contention
  exceeded 8 because a second agent was driving a benchmark concurrently, but the
  "24-way" figure is not what this run's provenance records.
- **Not fixed.** The single-probe fragility in `_probe_echo_sizes` is diagnosed,
  not repaired. Repairing it means touching exploit-pipeline behaviour, which is
  outside this diagnosis; see below.

## Recommendation (not done here)

`_probe_echo_sizes` / `_probe_fmtstr_indices` should not let a 2.0 s scheduling
stall turn into "this technique does not apply". The cheap, honest fix is to
re-probe the fill sizes once before concluding *no leak source exists*, and to
distinguish "probed and the echo was absent" from "probed and the target produced
nothing in time" — the latter is a measurement failure, not a negative result.
That is a behaviour change to the exploit pipeline and wants its own plan.

Nothing in the benchmark's verification logic or the corpus was weakened, and
nothing should be: **strict was right, and so was default.** Both scored this rep
exactly as its evidence warranted. The scoreboard difference is a genuine
exploit-generation failure that happened to land in the strict run.

## Change made

No production change — no defect was found in the harness. One test added:

`tests/test_bench_harness_soundness.py::TestClassificationOrdinaryPaths::
test_strict_attribution_cannot_change_a_no_flag_verdict` pins the invariant the
diagnosis turned on: for a rep with `flag_found == false`, `classify()` returns an
identical `(status, reason, void_cause)` with and without strict, and never
attributes it to `unwitnessed_success`.

It is a guard, not a fix, and **it can fail.** Verified by mutation: hoisting the
`strict_attribution` check above the `verify["flag_found"]` guard in
`classify()` fails all 3 parametrizations with
`lenient=FAILED/None vs strict=VOID/unwitnessed_success`. The mutation was then
reverted and `benchmark/run_bench.py` confirmed byte-identical to `b3a40b4`.
Suite: 92 passed (`test_bench_harness_soundness.py` + `test_bench_attribution.py`).

Without that guard, hoisting the check would make every ordinary failed rep
report itself as a strict-mode decline — which is precisely the false diagnosis
this investigation had to rule out by hand.
