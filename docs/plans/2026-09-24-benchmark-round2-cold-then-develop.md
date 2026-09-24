# Benchmark round 2 — measure cold first, then develop

**Date:** 24 Sep 2026
**Author:** d0sf3t
**Branch:** `bench/round2-cold-and-dev-20260924` (from
`integration/phases-0-4-7-20260923` @ `b3a40b4`; R2 merged at `f00461f`)
**Corpus under test:** `feat/benchmark-corpus-r2-20260923` @ `09bf135`
**Revision:** rev 3 — rev 1 was returned **NOT-APPROVED** by an independent
same-tier peer review (5 blocking, 3 major); rev 2 resolved 5 of 8 and was
returned **NOT-APPROVED** again on the remaining 3 plus 2 new findings. Both
reviews: `docs/reports/reviews/2026-09-24-r2-plan-review-r1.md`,
`…-review-r2.md`. Findings are cross-referenced `[R-n]`; the second round's are
`[R2-n]`.

Rev 3 concedes one substantive error rather than defending it: rev 2's
contamination check `[R-4]` was a **rationalisation**, as the reviewer said.
`attribution.py`'s `witness()` straces the *generated script*, not the autopwn
analysis and generation passes, so it could not observe the reads it claimed to
rule out. Replaced with a check that actually observes them (§6).

---

## 1. Goal and the one thing that must not be got wrong

Round 1 closed at **13/13 SUCCESS** (default: all 13 at 5/5 reliability; strict:
12 at 5/5, `04_canary_leak_bypass` at 4/5), with `11_heap_uaf_leak` and
`13_off_by_one` `VOID` and excluded. R1 is the corpus the pipeline was developed
against, so 13/13 is an upper bound contaminated by fitting and its
generalization content is approximately zero.

Round 2 is the instrument that can measure generalization, and it can do so
**exactly once**. The cold number is destroyed by the first line of exploitation
code written with knowledge of an R2 failure, and re-running does not recover it.

Ordered plan — the order *is* the deliverable:

1. Prove the R2 corpus is a sound measurement instrument; **declare the
   denominator and the primary endpoint before any number exists**.
2. Measure R2 cold against the pipeline exactly as it stands at the base commit —
   no tuning, no fixes, no "while I'm here". Commit the report.
3. Only then develop against R2. **That second number is training performance on
   R2, not generalization** `[R-7]`.

Expected cold result: well below 13/13. That is the measurement working. It is
reported as-is, with no softening and no post-hoc denominator adjustment.

## 2. What is already known about R2

`b3a40b4...09bf135` is purely additive apart from two shared files. R2 adds
`benchmark/corpus_r2/` (15 targets + `cflags`), `benchmark/corpus_r2.yaml`,
`benchmark/build_all_r2.sh`, `benchmark/corpus_r2_reference/` (15 reference
exploits + its own `ablation.py`). It touches **no** exploitation code and **no**
harness code — `run_bench.py` and `attribution.py` are byte-identical to the ones
that produced the R1 13/13, which is what makes the two numbers comparable at
all. Verified by **file whitelist**, not `diff --stat` alone `[R-8]`: every path
in the merge is under `benchmark/corpus_r2/`, `benchmark/corpus_r2_reference/`,
`benchmark/corpus_r2.yaml`, `benchmark/build_all_r2.sh`, `benchmark/.gitignore`
or `CHANGELOG.md`.

### 2.1 R2's own `ablation.py` has no positive control — its 15/15 is not evidence

`benchmark/corpus_r2/README.md` claims "All 15 ablations pass (0/15 produced the
flag)". Reading `benchmark/corpus_r2_reference/ablation.py`: each case runs *only*
the ablated chain and asserts the flag is absent. There is no intact-chain leg
anywhere in the file, `EOFError` is caught and converted to `out = ""`, and
`main()` returns 0 whenever `leaks == 0`.

That is exactly the defect `benchmark/ablation/ablate.py` exists to prevent:

> **A positive control per target, from the same code.** … So `BLOCKED` cannot be
> an artifact of broken harness code — broken code fails the positive control,
> and the target is reported `NOT MEASURABLE` instead of passing silently.

A driver whose `recvuntil(b"shellcode> ")` no longer matches, a read timeout, or
an `EOFError` all yield `no-flag`. **A clean R2 ablation run is consistent with 15
broken drivers.** It is also one ablation per target (15/15) against R1's 49
across 13, so it probes far less.

### 2.2 R2's `benchmark/.gitignore` dropped rules — resolved as a union

R2's version omitted `results_*/` and `corpus*/.run_bench.lock` and narrowed
`results/*` to `results/*/`, which would have left `benchmark/results_r2/` and the
harness lock trackable — one `git add -A` from committing per-run binaries,
`flag.txt` secrets and run output. Resolved as a union in `f00461f`; a
`git status --porcelain` artifact gate runs before every commit.

## 3. Decision: repair vs. replace vs. exclude degenerate targets

| option | effect | cost |
|---|---|---|
| **A — exclude** | denominator shrinks; corpus stays wholly author-written | a degenerate target yields no information |
| **B — repair before measuring** | full 15-wide denominator | I co-author the held-out corpus *before* measuring it and calibrate difficulty with no reviewer |
| **C — replace before measuring** | full 15-wide denominator | strictly worse than B: the target becomes entirely my design |

**Chosen: A for the cold run; B only in step 3, and only for the developmental
number.** A degenerate target is excluded from the cold denominator, named with
its evidence, declared before the cold number is quoted. Exclusion requires
**positive evidence of degeneracy** (a negative control leaked, or an ablation
showed the claimed technique is not required) — never a mere `FAILED`.

**Predeclared adequacy threshold `[R-5]`: ≥ 12 of 15 targets sound.** Below that,
R2 **cannot support a cold estimate at all** and the report says exactly that; I
do not repair and relabel the result "cold". An evaluator-repaired target is never
cold, and rev 1's "below ~8, repair first and call it cold" escape hatch was
invalid and is **removed**. Below threshold the correct outcome is to report the
failure of the instrument and request an independently authored corpus.

**Not taken: C.** Maximises my authorship of the instrument for no gain over B.

**Status after step 1 (already executed, §6):** all 15 targets pass the negative
controls and all 15 reference exploits pass, so the threshold question is very
likely moot — but the ablation leg (§4.2) is what actually decides it.

## 4. Decision: how far the timeout can be ruled out, and what stays open

Rev 1 proposed re-running failures at `--timeout 60`. The reviewer's blocking
objection `[R-1]` is correct and I accept it: **a re-run hands every failure extra
stochastic dice rolls, so a flip proves nothing about truncation** — it is
confounded with the known delivery flake. Reporting such a flip as "capability"
would be exactly the self-deception this plan exists to avoid.

The reviewer proposed instead a single 60 s cold run with the 20 s result derived
by censoring attempts on recorded time-to-success. I reject that too, for a reason
the review could not see from the plan text alone: **`--timeout` is not a
wall-clock cap on one fixed process — it is a per-attempt budget passed into
autopwn, and it changes autopwn's own control flow.** At 60 s the tool may spend
its whole budget inside technique #1 and never reach #4; at 20 s it may reach #4
quickly. A 60 s run is therefore not a superset of a 20 s run and censoring it is
not sound either. Two `--timeout` values are two *configurations of the tool*, not
one run observed at two horizons.

**Chosen: one predeclared configuration — `--reps 5 --jobs 8 --timeout 20`,
identical to R1's authoritative run — with *outer* truncation ruled out by reading
the cold run's own transcripts rather than by any re-execution, and *inner*
(per-technique) truncation left explicitly open and disclosed.**

`run_bench.py` records autopwn's structured self-report per rep, including its
per-attempt log. For every non-SUCCESS target I check whether autopwn **exhausted
its technique list and self-reported failure** (as it did on all 13 R1 failures)
or whether attempts were cut off with budget remaining unspent. The former is the
tool running out of *ideas*, not *time*, and rules out **outer** truncation
directly. The latter is positive evidence of truncation and is reported as such.

Zero extra executions, zero stochastic contamination, no loss of R1
comparability. `--timeout 20` is also the *only* value that keeps the R1↔R2
comparison valid, and that comparison is the entire point.

**Accepted residual limit `[R2-1]`.** The reviewer is right that exhausting the
technique list rules out only an *outer* kill: it does not prove the 20 s budget
never truncated or altered an *individual* technique (a gadget search that needed
25 s would report "did not apply", indistinguishably). I cannot close that from
transcripts, and any second execution is confounded. So I do not claim it is
closed. Instead the cold figure is **defined** as:

> capability at the R1-comparable per-attempt budget of 20 s

and it explicitly does **not** claim to equal capability at an unbounded budget.

Separately, and only *after* the cold figure is committed, `--timeout 60` is run
as its own labelled configuration ("R2 at `--timeout 60`") with its own reliability
split. It is **never** merged into the cold figure and **never** used to upgrade a
cold verdict `[R-6]` — so it cannot function as a rescue mechanism, which is what
made rev 1's version confounded. The gap between the two configurations is itself
the budget-sensitivity result, reported as such.

## 4.1 Predeclared endpoints, fixed before any number exists `[R-6]`

Rev 1 left the numerator floating. Fixed now:

- **Primary endpoint: count of targets at 5/5 reliability SUCCESS**, i.e. credited
  in every rep. Least luck-dependent.
- **Secondary (reported, required, explicitly exploratory): `solved` = credited in
  ≥1 of 5 reps.** This is an upper bound and is labelled as one; quoting it as the
  headline rewards luck.
- Both reported in **both** attribution modes (default and
  `--strict-attribution`), per target, as the pair `solved` + `reliability` k/N.
- **Never** combined across attribution modes or across timeout configurations.
  No "best of" across runs.

**Predeclared exclusion policy, fixed now so no number can influence it
`[R2-new-blocking]`.** A target leaves the cold denominator for exactly three
reasons, all requiring positive evidence:

1. **Degenerate** — a negative control leaked, or an ablation showed the claimed
   technique is not required.
2. **Unmeasurable** — `VOID` from provisioning (the secret did not land) or a
   `harness_error`.
3. **Contaminated** — the contamination check (§6) shows the pipeline read that
   target's `.c` or any reference-exploit file.

In all three cases the target is named with its evidence and the denominator
shrinks. The **≥12-of-15 adequacy threshold (§3) applies to the total surviving
set, whatever the mix of reasons.** Below 12 surviving, R2 cannot support a cold
estimate and the report says exactly that instead of quoting a number.

Additionally, **if contamination alone affects more than 3 targets it is systemic,
not per-target**: the cold estimate is void in full and reported as void, because a
pipeline that reads sources on 4+ targets was plausibly doing so everywhere and
the surviving targets cannot be trusted either. A `FAILED` verdict is never
grounds for exclusion under any of the three.

## 4.2 The ablation positive control, done properly `[R-2]`

The reviewer is right that running a separate reference exploit cannot prove
`ablation.py`'s own prompt handling, delivery and parsing work — it is a different
code path, so it cannot vouch for the ablation drivers. Rev 1's design is
insufficient.

**Chosen: port R1's `ablate.py` guarantee to R2.** Build
`benchmark/ablation/ablate_r2.py` in which each target has **one parametrised
chain function whose defaults are the working exploit**, and each ablation is the
same function with one keyword flipped — so the intact-chain positive control and
the ablation run through the *identical* driver path, delivery and parsing, on a
fresh process. Verdicts:

- positive control produces the flag **and** ablation does not → `BLOCKED` (pass)
- positive control fails → **`NOT MEASURABLE`**, exit 2 (never a silent pass)
- ablation produces the flag → defect, exit 1

Also adopted from `ablate.py`: rebuild each target with a fresh random secret via
the harness's own `build_with_secret()`, and hold `corpus_lock`. Exit codes keep
`ablate.py`'s split (0 pass / 1 corpus defect / 2 could-not-measure) so a caller
testing only for nonzero cannot confuse them.

This is corpus-side measurement tooling: it touches no exploitation code, so
building it before the cold run does not contaminate the cold number.

`benchmark/ablation/ablate.py` is additionally run **unchanged against R1** as a
control that the ablation machinery is healthy on this branch (expected 49/49
blocked, 13/13 positive controls, exit 0). It is *not* pointed at `corpus_r2`: its
49 cases are hardcoded R1 chains and its own README calls it "a template, not a
drop-in", so aiming it at different binaries would manufacture meaningless
`BLOCKED`s — the precise false confidence it was built to prevent. This is a
deliberate, stated deviation from the task's literal wording.

## 5. Decision: generalize vs. target-specific fixes

Binding rules for step 3:

1. **A fix may only key off a property of the binary discovered by analysis** —
   "imports `strcat`, contains no `/bin/sh` string, so build one at runtime";
   "this comparison immediate is the gate constant". **Never** off a target name,
   slug, path, corpus root, file size, or a hardcoded offset/address.
2. **Reference exploits are read for diagnosis only.** They may confirm a target
   *is* solvable and name the missing technique class. **No constant, offset,
   address, gadget or prompt string from a reference exploit may enter the
   pipeline.** Copying a number from the answer key is fitting in a
   generalization costume.
3. **No R1 regression.** Full R1 re-run after fixes; R1 must hold 13/13 with its
   reliability split.
4. **Per fix, record the falsifiable prediction** — what a later round would show
   if the fix were secretly target-specific.
5. **Never weaken verification or a corpus vulnerability to make a target pass.**
   Cardinal rule. Corpus edits are permitted only to repair a proven degeneracy,
   only toward requiring *more* of the claimed technique, and only with the
   target's reference exploit still passing (README R4's acceptance criterion).

**Accepted limitation `[R-7]`, and it changes the reporting, not just the
caveats:** rules 1–4 cannot *establish* generalization. A heuristic keyed to a
property I discovered *because* an R2 target failed can still be corpus-specific,
and neither an R1 regression test nor a written prediction can detect that. So:

- The post-development R2 figure is labelled **training performance on R2**, never
  generalization.
- **Only the cold figure is generalization evidence**, and there will not be
  another one for R2.
- Code is **frozen before any R3/R4/R5 access**, and the next untouched cold round
  is what actually tests generalization. An ancestry check keeps R3/R4 out of the
  tree but does **not** enforce that embargo on its own; the embargo is a
  procedural commitment recorded here.

**Not taken: target-specific handling, even as temporary scaffolding.** A scaffold
that scores is never removed. If a target genuinely needs bespoke handling, the
honest outcome is to leave it `FAILED` and write down the missing capability.

## 5.1 Known live bug to triage against, NOT to fix before the cold run

A concurrent diagnosis of R1's one anomaly (`04_canary_leak_bypass`, 4/5 strict)
found contention noise rather than an attribution defect, but identified a live
pipeline bug that R2 will likely hit:

`_probe_echo_sizes` in `_discover_leak_sources`
(`supwngo/exploit/pipeline/executors/canary_leak_techniques.py:174`) rests on a
**single 2.0 s probe per fill size with no retry**, and
`deliver_parts` (`supwngo/exploit/pipeline/delivery.py:161`) does
`try: output = io.recvall(timeout=timeout) / except Exception: output = b""` with
**no `timed_out` field on `DeliveryResult`** — so a scheduling stall is
*indistinguishable* from "the target printed nothing", i.e. from "this technique
does not apply". On target 04 the canary leaks at exactly one fill size, so one
stalled probe loses the whole technique: 9 of 10 reps produced a byte-identical
working exploit and the 10th produced the stub. **The failure is at ANALYSIS
stage, before any script exists.** Same *class* as the previously fixed
unsynchronized-send flake, different *site* — the generated exploit carries the
`SETTLE`/`send_part()` fix; this pre-generation discovery probe does not.

**This is explicitly not applied before the cold run.** Two consequences:

1. **Triage rule, binding on step 2's write-up.** Before attributing any R2 cold
   failure to capability, check the generated artifact for the
   `Universal Exploit Template … (no technique verified)` stub
   (`supwngo/exploit/pipeline/templates.py:49-50`) with `offset = 0  # TODO`. That
   stub means *discovery* failed and may be this flake, not a capability gap.
   Conflating the two would understate the cold number — a dishonesty in the
   generous direction, still a dishonesty.
2. **Legitimate step-3 fix** (fixes what genuinely failed; generalizes). Options
   to weigh when I get there: (a) make the stall observable — add `timed_out` to
   `DeliveryResult` so a timeout stops being silent; (b) retry with backoff;
   (c) widen the 2.0 s budget; (d) probe more fill sizes. (a) is the root fix and
   the others are palliative without it, since the code currently *cannot tell the
   two apart at all*; (a) is also the one that makes the remaining choices
   measurable rather than guessed. Statistically, at `--reps 5` a ~10%/rep stall
   barely touches `solved` (five consecutive stalls needed to lose a target) but
   **does** move the `reliability` k/N split — so a 4/5 is not read as a capability
   signal without checking for the stub first.

## 6. Execution

### Step 0 — merge R2 only ✅ done (`f00461f`)

Union-resolved `.gitignore`; `CHANGELOG.md` kept both sides with the R2 entry's
"never merged" claim corrected and the §2.1 caveat recorded. **R3 (`9326d95`) and
R4 (`9868b75`) verified NOT ancestors of HEAD**, before and after. Whitelist-checked
`[R-8]`. Working tree clean of artifacts.

### Step 1 — soundness, then declare the denominator

Absolute `--corpus-root` into this worktree throughout; other agents hold
`corpus_lock` on their own worktrees.

1. ✅ **cflags ↔ manifest mirror**: all 15 match.
2. ✅ **Shared-builder build** (`build_all.sh` + `SUPWNGO_BENCH_CORPUS`, the path
   `run_bench.py` uses, not R2's own convenience builder): all 15 build.
3. ✅ **Scrape channel (R8), independently measured**: `strings` over all 15
   binaries → **0 `FLAG{` hits**, and all 15 `flag.txt` present. R2 therefore has
   **no** weak-attribution targets, against R1's 9 — so on R2, default and strict
   modes can differ only on `UNWITNESSED` results.
4. ✅ **Negative controls** (`negative_control_sweep.py`): all 15 clean on
   `verify_stdin`, `filler512` and `menu_walk` (fresh process per probe — load
   bearing; a single concatenated stream gave R1's `11_heap_uaf_leak` a false
   clean bill).
5. ✅ **Reference exploits**: 15/15 pass against a freshly rotated secret.
6. ⬜ **Ablations with a same-driver positive control** via the new
   `ablate_r2.py` (§4.2). This is the leg that decides the denominator.
7. ⬜ **R1 ablation control**: `ablate.py` unchanged → exit 0.
8. ⬜ **Declare the denominator and endpoints in the report, committed, before
   step 2 runs.**

### Step 2 — the cold run (single-use)

**Pre-run readiness gate `[R-3]`.** Rev 1 merely recorded load; the reviewer is
right that recording it afterwards cannot recover a contaminated result, and
§5.1's bug makes the contention path concrete rather than theoretical. Gate,
checked and recorded immediately before launch:

- no other `run_bench.py` process anywhere on the host (checked with
  `ps aux | grep -c "[r]un_bench.py"` — **never** `until ! pgrep -f …`, which
  self-matches and has burned three agents in this project);
- 1-minute loadavg below 8 on this 32-core host;
- my corpus lock free; tree clean.

If the host will not go quiescent in reasonable time, I **wait** rather than
spend the measurement. If waiting proves unbounded I say so and hand the decision
back rather than quietly running under load.

**Continuous load sampling, not a snapshot `[R2-3]`.** A single pre-run reading
cannot detect contention that *arises during* the irreplaceable run, and I cannot
reserve the host. So a sampler records loadavg and the `run_bench.py` process count
every 15 s for the whole run, and the **load profile is reported with the result**.
Any rep whose window overlaps a load excursion above the gate threshold is flagged,
and intermittency inside such a window is treated as a contention suspect rather
than a capability signal (§5.1). This bounds the problem honestly rather than
claiming to have eliminated it.

```
python3 benchmark/run_bench.py \
    --corpus-root <abs>/benchmark/corpus_r2 \
    --manifest    <abs>/benchmark/corpus_r2.yaml \
    --reps 5 --jobs 8 --timeout 20
```

**Completion detection `[R2-major]`:** the harness is launched as a *tracked
background process* and its **exit status** is what signals completion; the report
is then validated for the expected 15 target records. Rev 2's
`until [ -f …/report.json ]` is dropped — a sentinel file is not guaranteed to be
written atomically or last, and it carries no exit status. (`pgrep -f` remains
banned for the self-match reason.)

**Provenance, recorded in the committed report `[R-8]`:** evaluation commit SHA,
`git status --porcelain` emptiness, the exact command line, environment
(gcc/glibc/pwntools/python versions, `nproc`, loadavg at start), exit status,
per-target binary sha256, the results directory path, the load profile, and a
sha256 of `report.json`.

**Committed evidence, not just a digest `[R2-8]`.** A digest of a gitignored file
a third party cannot obtain proves nothing about selective transcription, which is
a fair objection. So a **redacted** `report.json` is committed alongside: every
occurrence of every per-rep secret flag is replaced with
`<REDACTED-SECRET-rep-N>`, leaving structure, per-rep statuses, reasons,
attribution verdicts and timings intact and independently checkable against the
prose. The unredacted original stays on disk at a recorded path with its sha256
in the report. Redaction is verified by asserting that no `FLAG{<32 hex>}`-shaped
string survives in the committed copy — the same check the corpus contract uses.

Both attribution modes are derived from the **same** transcripts, not from a
second execution `[R-1]`.

**Contamination check `[R-4]`, corrected.** Rev 2 proposed grepping the cold run's
`attribution.py` strace logs. That was wrong, and the reviewer's "rationalisation"
verdict is accepted: `witness()` straces the **generated script's** re-execution,
so it never observes the autopwn *analysis* and *generation* passes — precisely
where a source read would happen. The check could not have detected what it
claimed to.

Replaced with two checks that do observe it, neither of which touches
`run_bench.py` or the cold run:

1. **Static audit** of the pipeline's own file access: the whole `supwngo/` tree
   is audited for any read of corpus-adjacent source (`.c`/`.py` opens, `glob`,
   directory walks) on the autopwn path. The pipeline's only documented input is
   a single binary path.
2. **Direct dynamic observation**, run *after* the cold run so it adds no load to
   it: for each target, the **same** `python3 -m supwngo.cli autopwn …` command
   line the harness uses is executed once under `strace -f -e trace=openat,open`,
   and the log is checked for any open of a `.c`, `_reference.py`, or
   `corpus_r2_reference` path. This observes analysis and generation directly.

Per-target contamination is handled by the predeclared policy in §4.1 (exclude and
name; >3 targets ⇒ the cold estimate is void in full).

Note the *bound* on this risk either way, which is why it is a validity question
and not a flag-integrity one: R2's flags exist only in `flag.txt` at runtime, and
attribution credits a success only when the **target process or a descendant**
writes the flag. Reading a `.c` could make the tool better informed than it should
be; it could not manufacture a flag.

I keep the corpus layout unchanged (target `.c` in the target's cwd) because R1
was measured that way and the R1↔R2 comparison is the cold number's purpose — but
that is now a stated cost paired with a check that genuinely tests it, not a
substitute for one.

Report: `docs/reports/BENCHMARK-R2-COLD-24SEP2026.md`, committed **before** any
exploitation-code edit.

### Step 3 — develop toward 15/15

Per failing target: triage from the structured hand-off and `report.json`
attempt log — applying §5.1's stub rule first — name the missing capability, fix
under §5's rules, re-run that target, re-run R1 for regression. Repair proven
degeneracies under §3's B. Final full R2 + R1 run, both modes. Freeze before any
R3/R4/R5 access.
Report: `docs/reports/BENCHMARK-R2-POST-DEV-24SEP2026.md`, headline labelled
**training performance on R2**.

## 7. Files touched

- this plan; `docs/reports/reviews/2026-09-24-r2-plan-review-r1.md`
- `docs/reports/BENCHMARK-R2-COLD-24SEP2026.md`,
  `docs/reports/BENCHMARK-R2-POST-DEV-24SEP2026.md`
- `benchmark/.gitignore`, `CHANGELOG.md` (merge resolution, done)
- `benchmark/ablation/ablate_r2.py` (new; measurement tooling only)
- step 3 only: `supwngo/exploit/**`, `supwngo/vulns/**`, `supwngo/analysis/**`;
  `benchmark/corpus_r2/<target>/*.c` only to repair a proven degeneracy
- **never**: `benchmark/run_bench.py`, `benchmark/attribution.py`,
  `benchmark/soundness_probes/**` verification logic

## 8. Risks

| risk | mitigation |
|---|---|
| Cold number destroyed by an early fix | steps ordered; cold report committed before any exploitation-code edit; §5.1's known bug explicitly deferred |
| R2's unverified ablation taken at face value → an `11_heap_uaf_leak`-class target scored | §4.2 same-driver positive control, `NOT MEASURABLE` + exit 2 on failure |
| Re-running failures at a longer timeout mistaken for a truncation finding | §4: no re-run; **outer** truncation ruled out from the cold transcripts, **inner** per-technique truncation disclosed as open (§4, §11) |
| Contention corrupts the irreplaceable measurement | §6 pre-run readiness gate + continuous load sampling; wait rather than spend it |
| Pipeline reads target `.c` and looks more capable than it is | §6 static audit + direct `strace` of the autopwn command; §4.1 predeclared exclusion policy |
| Cold figure over-read as budget-independent capability | §4 defines it as capability at a 20 s per-attempt budget; the 60 s configuration is separate and cannot upgrade a verdict |
| Discovery-stall flake (§5.1) read as a capability gap | stub-signature triage rule before any capability claim |
| Headline inflated by best-of-5 luck | §4.1 primary endpoint is 5/5; `solved` labelled exploratory |
| Post-dev R2 mistaken for generalization | §5 labels it training performance; embargo before R3/R4/R5 |
| `.gitignore` leak of binaries/`flag.txt`/run output | union resolution + `git status --porcelain` gate before every commit |
| R3/R4 merged by accident | `--is-ancestor` check before and after |
| Selective transcription of results | §6 provenance block: commit SHA, hashes, command, exit status, `report.json` digest |
| `until ! pgrep -f …` self-match infinite loop | wait on `until [ -f …/report.json ]` |

## 9. Test strategy

- `pytest tests/test_bench_harness_soundness.py tests/test_bench_attribution.py`
- `benchmark/soundness_probes/attribution_sweep.py` (non-zero on failure)
- `benchmark/ablation/ablate.py` on R1 → exit 0
- `benchmark/ablation/ablate_r2.py` on R2 → exit 0
- R1 regression after every step-3 fix: full run at `--reps 5 --jobs 8 --timeout 20`,
  both modes

## 10. Definition of done

- [ ] Corpus soundness independently verified, including a same-driver ablation
      positive control; denominator and endpoints declared and committed **before**
      the cold number exists
- [ ] Cold figure committed with provenance, both modes, primary (5/5) and
      exploratory (`solved`) endpoints, outer truncation ruled out from transcripts
      and the §11 residual limits reproduced in the report, no softening
- [ ] Post-development figure committed, labelled training performance, each fix
      with its generalization argument and falsifiable prediction
- [ ] R1 still 13/13 with its reliability split
- [ ] No verification logic weakened; no corpus vulnerability weakened
- [ ] R3/R4 still not ancestors of HEAD; code frozen before any R3/R4/R5 access
- [ ] `CHANGELOG.md` under `[Unreleased]`; Conventional Commits; no secrets,
      binaries or run output committed

## 11. Residual limits — disclosed, not closed

These survived three rounds of independent review. They are **not** resolved, and
this section is reproduced verbatim in the cold report so the caveats travel with
the number instead of living only here.

1. **Inner (per-technique) truncation at the 20 s budget is not ruled out**
   `[R2-1]`. Transcript analysis catches only an outer kill. A technique needing
   25 s of gadget search would report "did not apply" indistinguishably from one
   that genuinely did not apply. No second execution can settle it without
   confounding on the known delivery flake. Hence the cold figure is defined as
   *capability at a 20 s per-attempt budget*, never as unbounded capability.

2. **Source-read contamination is checked on replay, not on the cold executions
   themselves** `[R2-1 / round-3 #1]`. The reviewer's objection is correct and is
   recorded rather than argued away: the §6 `strace` run replays the same command
   line on the same binaries *after* the cold run, and in principle a cold
   execution's access path could differ.

   Why I accept this rather than instrument the cold run: observing it from inside
   would mean an audit hook (via a `sitecustomize.py` on the `PYTHONPATH`
   `run_bench.py` already sets) running in every measured process, adding per-`open`
   overhead inside the very 20 s budget that limitation 1 shows is already tight —
   i.e. trading a real risk to the *primary* measurement for a check on a
   *secondary*, bounded one. The bound: R2's flags exist only in `flag.txt` at
   runtime and attribution credits a success only when the target process or a
   descendant writes the flag, so a source read could yield an informational
   advantage but **cannot manufacture a flag**. The static audit also establishes
   that no source-reading code path exists on the autopwn route, and nothing in the
   pipeline is nondeterministic about *which* files it opens.

   **Structural fix, deferred to R3+**: design the audit hook in from the start of
   a round, where it is part of the instrument for both the baseline and the
   measurement, rather than bolted onto an irreplaceable run. Recorded here so the
   next round can close it properly.

3. **The host cannot be reserved** `[R2-3]`. Contention is sampled continuously and
   reported as a load profile; it is not eliminated.

4. **The committed `report.json` is redacted** `[R2-8]`. Per-rep secrets are
   replaced with placeholders, so a reader can check structure, statuses, reasons,
   attribution verdicts and timings against the prose, but not re-derive a verdict
   from the raw secret. The unredacted original stays on disk with its sha256
   recorded. This is forced by the corpus contract's no-flag-in-git rule.
