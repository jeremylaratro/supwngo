# Benchmark round 2 — measure cold first, then develop

**Date:** 24 Sep 2026
**Author:** d0sf3t
**Branch:** `bench/round2-cold-and-dev-20260924` (from
`integration/phases-0-4-7-20260923` @ `b3a40b4`)
**Corpus under test:** `feat/benchmark-corpus-r2-20260923` @ `09bf135`
**Status:** awaiting independent same-tier review before the cold run

---

## 1. Goal and the one thing that must not be got wrong

Round 1 closed at **13/13 SUCCESS** (default mode: all 13 at 5/5 reliability;
strict mode: 12 at 5/5, `04_canary_leak_bypass` at 4/5), with `11_heap_uaf_leak`
and `13_off_by_one` `VOID` and excluded. R1 is the corpus the pipeline was
developed against, so 13/13 is an upper bound contaminated by fitting, and its
generalization content is approximately zero.

Round 2 is the instrument that can measure generalization, and it can do so
**exactly once**. The cold number is destroyed by the first line of
exploitation code written with knowledge of an R2 failure, and re-running does
not recover it.

So the plan is ordered, and the order is the deliverable:

1. Prove the R2 corpus is a sound measurement instrument, and **declare the
   scoring denominator before any number exists**.
2. Measure R2 cold — the untouched `b3a40b4` pipeline, no tuning, no fixes, no
   "while I'm here". Commit the report.
3. Only then develop against R2, aiming at 15/15.

Expected cold result: well below 13/13. That is the measurement working. It
gets reported as-is, with no softening language and no reframing of the
denominator after the fact.

## 2. What is already known about R2 (read-only inspection, no merge yet)

`git diff --stat b3a40b4...09bf135` is **purely additive** except for two
shared files. R2 adds `benchmark/corpus_r2/` (15 targets + `cflags`),
`benchmark/corpus_r2.yaml`, `benchmark/build_all_r2.sh`,
`benchmark/corpus_r2_reference/` (15 reference exploits + its own
`ablation.py`). It touches **no** exploitation code and **no** harness code —
`run_bench.py` and `attribution.py` are untouched, so the measuring instrument
is byte-identical to the one that produced the R1 13/13. That is what makes the
two numbers comparable at all, and it is worth stating explicitly.

Two problems found before merging, both of which change what step 1 has to do.

### 2.1 R2's own `ablation.py` has no positive control — its 15/15 is not evidence

`benchmark/corpus_r2/README.md` claims "All 15 ablations pass (0/15 produced the
flag)". Reading `benchmark/corpus_r2_reference/ablation.py` (on `09bf135`): each
case runs *only* the ablated chain and asserts the flag is absent. There is no
intact-chain leg anywhere in the file, and `main()` returns 0 whenever
`leaks == 0`.

That is precisely the defect `benchmark/ablation/ablate.py` exists to avoid. Its
README states the guarantee plainly:

> **A positive control per target, from the same code.** … So `BLOCKED` cannot
> be an artifact of broken harness code — broken code fails the positive
> control, and the target is reported `NOT MEASURABLE` instead of passing
> silently.

Under R2's suite, a driver whose `recvuntil(b"shellcode> ")` no longer matches
the target's prompt, a timed-out read, or an `EOFError` (which the code catches
and converts to `out = ""`) all produce `no-flag` — indistinguishable from a
genuinely blocked ablation. **A clean R2 ablation run is therefore consistent
with 15 broken drivers.** It is also one ablation per target (15 cases / 15
targets) against R1's 49 across 13, so it probes far less.

Consequence: R2's self-reported soundness is *unverified*, not *verified*, and
step 1 must supply the missing leg rather than quoting the README.

### 2.2 R2's `benchmark/.gitignore` silently drops rules the integration branch added

R2's version of the file omits `results_*/` and `corpus*/.run_bench.lock`, and
narrows `results/*` to `results/*/`. Taking R2's side of that conflict would
leave `benchmark/results_r2/` and the harness lock **trackable**, i.e. one
`git add -A` away from committing per-run binaries, `flag.txt` secrets and run
output — the exact class of leak the corpus contract's R1/R5 rules forbid. Both
sides also touched `CHANGELOG.md`.

Resolution: the merge is a **union**, keeping every integration-side rule and
adding R2's `corpus_r2` rules. A post-merge `git status --porcelain` must be
clean of any `corpus_r2/*/` artifact, any `results_r2/`, and any `.run_bench.lock`
before anything is committed. This is a checklist item, not a footnote — it is a
secrets-in-git risk.

## 3. Decision: repair vs. replace vs. exclude degenerate R2 targets

R1 shipped two targets that were not measurements: `11_heap_uaf_leak` handed
over the flag to menu-walking with small integers (its display path read a
**live** chunk, so the UAF was never required) and `13_off_by_one` fell to 512
bytes of structure-free filler. Both are `VOID`. If step 1 finds R2 equivalents,
three options:

| option | effect on the cold number | cost |
|---|---|---|
| **A — exclude** | denominator shrinks; cold number stays measured on a corpus I did not author | a degenerate target contributes no information; 15/15 becomes unreachable without later work |
| **B — repair before measuring** | full 15-wide denominator | I become a co-author of the held-out corpus *before* it is measured, and I calibrate difficulty with no independent reviewer; a botched repair can break the target's reference exploit |
| **C — replace before measuring** | full 15-wide denominator | strictly worse than B: an entirely new target is entirely my design, so its difficulty is whatever I happen to make it, and nothing holds it to R2's family coverage |

**Chosen: A for the cold run, B afterwards.** Any degenerate target is excluded
from the cold denominator and the exclusion plus its evidence is declared in the
report **before** the cold number is quoted. Repairs happen in step 3, are
measured separately, and are reported as a clearly-labelled *repaired-corpus*
figure that is never folded into the cold generalization figure.

Rationale: the cold number's entire value is that the corpus was written without
knowledge of the pipeline and the pipeline without knowledge of the corpus.
Repairing first spends that property to buy denominator width — and denominator
width is recoverable later, whereas the held-out property is not. Excluding is
also what R1 did, so the two rounds stay comparable.

**What would flip this:** if the sound set falls below ~8 of 15, the cold
measurement is too thin to support a generalization claim at all, and B becomes
the only way to get a signal. In that case I repair first and the report's
headline is labelled "cold on a partially repaired corpus" with the repaired
targets named in the headline itself, not in a footnote. I am also *not* free to
choose A for a target that is merely *hard*: exclusion requires positive
evidence of degeneracy (a negative control leaked, or an ablation showed the
claimed technique is not required), never a `FAILED` verdict.

**Not taken: C (replace).** Rejected because it maximises my authorship of the
instrument for no gain over B.

## 4. Decision: how the timeout gets ruled out rather than assumed

R1's authoritative run used `--timeout 20`, and uniform 5/5 reliability across
all 13 scored targets is strong evidence that nothing there was truncated — a
target being cut off mid-chain would show as intermittency. **That inference is
about R1 and does not transfer to an unfamiliar corpus**, where a longer chain,
a slower gadget search, or a heavier `angr` path could sit just past 20 s and
present as a clean `FAILED`. Assuming otherwise would let a measurement artifact
masquerade as a capability limit, and would inflate the apparent gap between R1
and R2.

| option | how it rules the timeout out | cost |
|---|---|---|
| **A — cold at 20, then a sensitivity sweep at 60 on every non-SUCCESS target, both before any code change** | empirically: if no target flips at 60, the 20 s budget provably truncated nothing and the cold figure stands | one extra pass over the failures |
| **B — cold at 60 from the start** | by making truncation implausible | loses direct comparability with R1's 20; ~3× runtime on failures |
| **C — assume 20 is fine because R1 was** | it does not | an unknown number of `FAILED`s may be artifacts |

**Chosen: A.** The cold figure is the `--timeout 20 --reps 5 --jobs 8` run, matching
R1 exactly. Immediately afterwards — still before any code change — every target
that did not reach SUCCESS is re-run at `--timeout 60`. The sweep is a
*measurement-parameter* check, not tuning: it changes no exploitation code and
consumes none of R2's held-out value. It is reported as an annex, and if any
target flips, the report carries **both** figures and names the 20 s number
"budgeted" and the 60 s number "capability", rather than quietly adopting
whichever is higher.

**Not taken: B.** Would have been chosen if R1 had shown any intermittency
consistent with truncation, or if a scoping check showed autopwn routinely
running past its per-attempt budget. Neither holds.

## 5. Decision: generalize vs. add target-specific handling

Target-specific handling raises the R2 score without raising capability, and R3
(`9326d95`), R4 (`9868b75`) and R5 exist specifically to expose it. Binding
rules for step 3:

1. **A fix may only key off a property of the binary discovered by analysis** —
   "imports `strcat` and contains no `/bin/sh` string, so build one at runtime",
   "this comparison immediate is the gate constant". Never off a target name,
   slug, path, corpus root, file size, or a hardcoded offset/address.
2. **Reference exploits are read for diagnosis only.** They may be consulted to
   confirm a target *is* solvable and to name the missing technique class. **No
   constant, offset, address, gadget, or prompt string from a reference exploit
   may enter the pipeline.** Copying a number from the answer key is fitting
   wearing a generalization costume.
3. **No R1 regression.** Every fix is followed by a full R1 re-run; R1 must stay
   at 13/13 with its reliability split intact. A fix that trades R1 for R2 is a
   refit, not a generalization.
4. **Per fix, record the falsifiable prediction**: what a future round would show
   if this fix were secretly target-specific. That is what makes R3/R4/R5 able to
   convict it.
5. **Never touch the verification logic or the corpus vulnerabilities to make a
   target pass.** Cardinal rule. Any temptation to loosen `attribution.py`,
   `classify()`, the negative controls, or a target's `.c` bug means the fix is
   wrong. Corpus-side edits in step 3 are permitted *only* to repair a
   degeneracy found in step 1, only in the direction of requiring more of the
   claimed technique, and only with the target's reference exploit still passing
   afterwards (README R4's acceptance criterion).

**Not taken: target-specific handling, even as a temporary scaffold.** Rejected
because a scaffold that scores is never removed. What would flip it: nothing
within this task — if a target genuinely needs bespoke handling, the honest
outcome is to leave it `FAILED` and write down the missing capability.

## 6. Execution

### Step 0 — merge the R2 corpus (and nothing else)

- `git merge feat/benchmark-corpus-r2-20260923`; resolve `benchmark/.gitignore`
  as a **union** (§2.2) and `CHANGELOG.md` by keeping both sides' entries.
- **Do not merge `9326d95` (R3) or `9868b75` (R4).** They stay held out for
  their own rounds; merging one early destroys it. Verified before and after:
  `git merge-base --is-ancestor <sha> HEAD` must stay non-zero for both.
- Verify the manifest ↔ `cflags` mirror, and that `build_all.sh`'s R9 fallback
  builds all 15 R2 targets (R2's `build_all_r2.sh` is a convenience builder; the
  harness uses the shared one, so the shared path is what must work).
- `git status --porcelain` clean of built artifacts, `flag.txt`, `results_r2/`,
  `.run_bench.lock`.

### Step 1 — prove the corpus is sound, then declare the denominator

All legs run against **`--corpus-root <this worktree>/benchmark/corpus_r2`** with
absolute paths. Other agents hold `corpus_lock` on their own worktrees
concurrently; four `run_bench.py` processes were live at planning time.

1. **Negative controls** — `benchmark/soundness_probes/negative_control_sweep.py
   --corpus-root … --manifest …`. Generic across corpora. Non-zero exit = at
   least one unmeasurable target. This catches the `13_off_by_one` class
   (structure-free filler) and the `11_heap_uaf_leak` class (menu-walk with small
   integers, fresh process per probe — the fresh process is load-bearing; a single
   concatenated stream hits "exit" and gave `11` a false clean bill in R1).
2. **Scrape channel (R8)** — independently run `strings` over all 15 built R2
   binaries and confirm 0 `FLAG{` hits. R2 claims structural cleanliness (flags
   read from `flag.txt` at runtime, never compiled in). If true, R2 has **no**
   weak-attribution targets at all and default and strict modes should agree
   except on `UNWITNESSED` results — which is itself a meaningful difference from
   R1, where 9 targets were scrapeable.
3. **Positive-control leg, run FIRST** — all 15 R2 reference exploits against a
   freshly rotated secret. This is the leg R2's ablation suite is missing (§2.1),
   and it runs before the ablations deliberately, so a `no-flag` ablation verdict
   cannot be an artifact of a broken driver.
4. **Ablations** — R2's `benchmark/corpus_r2_reference/ablation.py`. A `no-flag`
   verdict is accepted **only** for a target whose reference exploit passed in
   leg 3, on the same build. Anything else is reported `NOT MEASURABLE`, not
   passing.
   - *Deviation from the task text, stated openly:* the task asks for
     `benchmark/ablation/ablate.py` against R2. That file's 49 cases are
     hardcoded R1 chain functions and its own README calls it "a template, not a
     drop-in"; pointing it at `corpus_r2` would drive R1 chains against
     different binaries and produce meaningless `BLOCKED`s — the exact
     false-confidence the tool was built to prevent. The R2-appropriate necessity
     suite is R2's own `ablation.py`, gated as above. `ablate.py` is still run
     **unchanged against R1** as a control that the ablation machinery is healthy
     on this branch (expected: 49/49 blocked, 13/13 positive controls, exit 0).
   - If the combined gate is cheap to express as a small script, add it under
     `benchmark/ablation/`; it is corpus-side tooling and touches no
     exploitation code.
5. **Declare the denominator in the report file, committed, before running
   step 2.** Any `VOID`/degenerate target is named with its evidence.

### Step 2 — the cold run (single-use; do not repeat and do not precede with any fix)

```
python3 benchmark/run_bench.py \
    --corpus-root <abs>/benchmark/corpus_r2 \
    --manifest    <abs>/benchmark/corpus_r2.yaml \
    --reps 5 --jobs 8 --timeout 20
```

- Reported **twice**: default and `--strict-attribution`, per R1's convention.
- Reported as the pair **`solved` (≥1 rep) and `reliability` (k/N)** for every
  target. `solved` alone is best-of-N cherry-picking; a single rep understates.
- Machine load recorded at start (other agents' benches are running). The known
  delivery flake — an unsynchronized send against a single `read(0,buf,300)`
  measured 4/96 under 24-way contention, 0/96 synchronized — means **~1/7-shaped
  intermittency is a synchronization suspect before it is a capability claim**, and
  gets checked as such rather than written up as a capability limit.
- Then the `--timeout 60` sensitivity sweep over every non-SUCCESS target (§4).
- Report: `docs/reports/BENCHMARK-R2-COLD-24SEP2026.md`, committed **before** any
  exploitation-code edit. Includes the declared denominator, the VOID list with
  evidence, both modes, per-target reliability, the timeout annex, and the R1
  comparison.

### Step 3 — develop toward 15/15

Per failing target: diagnose from autopwn's own structured hand-off and the
`report.json` attempt log, name the missing capability, fix it under §5's rules,
re-run that target, re-run R1 for regression. Repair degenerate targets under
§3's B. Full R2 + R1 re-run at the end, both modes.
Report: `docs/reports/BENCHMARK-R2-POST-DEV-24SEP2026.md`.

## 7. Files touched

- `docs/plans/2026-09-24-benchmark-round2-cold-then-develop.md` (this file)
- `docs/reports/BENCHMARK-R2-COLD-24SEP2026.md`,
  `docs/reports/BENCHMARK-R2-POST-DEV-24SEP2026.md`
- `benchmark/.gitignore`, `CHANGELOG.md` (merge resolution)
- possibly `benchmark/ablation/` (the R2 positive-control gate)
- step 3 only: `supwngo/exploit/**`, `supwngo/vulns/**`,
  `supwngo/analysis/**`; `benchmark/corpus_r2/<target>/*.c` only to repair a
  proven degeneracy
- **never**: `benchmark/run_bench.py`, `benchmark/attribution.py`,
  `benchmark/soundness_probes/**` verification logic

## 8. Risks

| risk | mitigation |
|---|---|
| Cold number destroyed by an early "quick win" | steps are ordered and the cold report is committed before any exploitation-code edit |
| R2's unverified ablation accepted at face value → an `11_heap_uaf_leak`-class target scored | §2.1: reference exploits run first as the positive control; `no-flag` only counts with a passing positive control |
| `.gitignore` merge leaks binaries/`flag.txt`/run output into git | §2.2 union resolution + `git status --porcelain` gate before every commit |
| R3/R4 merged by accident | `--is-ancestor` check before and after the merge |
| Contention-induced flake read as capability | load recorded; ~1/7 intermittency treated as a synchronization suspect first |
| Timeout truncation read as capability | §4 sensitivity sweep at 60 before any code change |
| Score inflated by target-specific handling | §5 rules 1–4, R1 regression gate, falsifiable prediction per fix |
| `until ! pgrep -f "<pattern>"` self-match infinite loop (has bitten three agents here) | wait on `until [ -f …/report.json ]`, never `pgrep -f` |

## 9. Test strategy

- Harness pure-logic regressions: `pytest tests/test_bench_harness_soundness.py
  tests/test_bench_attribution.py`.
- Attribution still credits real exploits and rejects scrapes:
  `benchmark/soundness_probes/attribution_sweep.py` (non-zero on failure).
- R1 ablation control: `benchmark/ablation/ablate.py` → exit 0.
- R1 regression after every step-3 fix: full `run_bench.py` on `benchmark/corpus`
  at `--reps 5 --jobs 8 --timeout 20`, both modes.

## 10. Definition of done

- [ ] Corpus soundness verified independently; denominator declared and committed
      **before** the cold number exists
- [ ] Cold R2 figure committed, both modes, `solved` + `reliability` per target,
      timeout annex, no softening
- [ ] Post-development figure committed, both modes, with each fix's
      generalization argument and falsifiable prediction
- [ ] R1 still 13/13 with its reliability split
- [ ] No verification logic weakened; no corpus vulnerability weakened
- [ ] R3/R4 still not ancestors of HEAD
- [ ] `CHANGELOG.md` under `[Unreleased]`; Conventional Commits; no secrets,
      binaries or run output committed
