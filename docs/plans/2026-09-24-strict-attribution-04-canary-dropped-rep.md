# Plan — diagnose the one dropped rep in `04_canary_leak_bypass` (strict attribution)

**Date:** 2026-09-24
**Branch:** `fix/strict-attribution-04-canary-20260924` (from `integration/phases-0-4-7-20260923`, `b3a40b4`)
**Status:** plan written before the decisive step; initial triage was read-only report inspection.

## Goal

Round 1 closed 13/13 in both modes. `04_canary_leak_bypass` is `5/5` reps in
default mode and `4/5` in strict-attribution mode; every other scorable target is
`5/5` in both. Decide **which of two mutually exclusive explanations** holds for
that one dropped rep, and do not average them:

1. **Ordinary contention noise** — the rep genuinely failed to land the exploit
   under 24-way parallel contention. Consequence: nothing to fix in the harness;
   report the measured rate.
2. **A strict-attribution defect** — the exploit landed and produced an
   attributed flag write, but the strict path declined to credit it. Consequence:
   strict is under-crediting, which is far more serious than one rep, and needs a
   fix plus a regression test that fails against the pre-fix code.

These have opposite meanings for the harness's trustworthiness, so the
deliverable must name one, with evidence, not hedge between them.

## Artifacts

- default: `benchmark/results/20260924-105723Z/report.json` (`strict_attribution: false`)
- strict: `benchmark/results/20260924-110437Z/report.json` (`strict_attribution: true`,
  `generated_at` = `2026-09-24T11:11:52Z` — this is the `111152Z` in the task's
  label; the directory is named for the run's *start* time, the label for its end.
  Worth recording because the directory the task names does not exist.)

## Method — the fork, weighed

The two candidate methods answer **different questions**, so the choice is not a
matter of taste.

### Option A (NOT taken): re-run reps to gather more samples

- **Answers:** "what is the failure *rate*?"
- **Cost:** ~340 s per 5 reps of target 04 alone, holds `corpus_lock`, and
  another agent is concurrently driving a benchmark.
- **Fatal flaw for this question:** a re-run cannot *distinguish* the two
  explanations. If the anomaly reproduces, that is consistent with both a race
  and a logic defect. If it does not reproduce, that is consistent with both a
  race and a logic defect that needs a particular interleaving. Either outcome
  leaves the verdict undetermined, so sampling would buy precision on a quantity
  (the rate) that is not the question asked.
- **Named failure mode it invites:** re-running until the anomaly disappears and
  calling that a result. The task explicitly forbids this, and it is the single
  most likely way to get a confidently wrong answer here.

### Option B (TAKEN): forensically read the archived strict run and the code path

- **Answers:** "what *caused* the decline?" — which is the question.
- **Method:** read the per-rep `attempts[]` records in the strict `report.json`,
  establish which stage the dropped rep died at, then read `classify()` /
  `run_one()` in `benchmark/run_bench.py` to determine whether the
  `strict_attribution` flag is even *reachable* from that stage.
- **Why it is decisive:** `strict_attribution` is a single boolean threaded from
  argv to exactly one read site. If the dropped rep terminated on a branch that
  is upstream of that read site, then strict mode provably cannot have caused it,
  and explanation (2) is eliminated by construction rather than by sampling. That
  is a proof, not an estimate.
- **Cost:** zero inference cycles on the corpus, no `corpus_lock` contention.

**Decision:** Option B. Determine the cause from the archive and the code; use
re-running only if the archive turns out to be ambiguous about the stage.

## What would flip the decision (i.e. make me re-run)

I re-run **only** if the forensic read leaves the stage ambiguous — concretely, if
either:

- the dropped rep's record shows `verify.flag_found == true` **and** an
  attribution verdict of `inconclusive`/`not_credited` (that is the actual strict
  decline path, and then I need to know how often it fires); or
- the archived strace for the dropped rep shows a flag-bearing write whose writer
  has a target ancestor, i.e. evidence the write *was* attributable and strict
  declined anyway.

If I re-run, I **pre-commit here** to **5 reps of `04_canary_leak_bypass` only**,
against `--corpus-root` inside this worktree, and I will report whatever those 5
reps give — including if they are 5/5 and therefore uninformative. I will not
extend the count afterwards to chase a cleaner number.

## Files expected to be touched

- `docs/plans/2026-09-24-strict-attribution-04-canary-dropped-rep.md` (this file)
- `docs/reports/STRICT-ATTRIBUTION-04-DROPPED-REP-24SEP2026.md` (the deliverable)
- `benchmark/run_bench.py` and/or `benchmark/attribution.py` **only if** a strict
  defect is found
- `tests/` — a regression test **only if** a defect is found, and it must fail
  against the pre-fix code (this project has already shipped four tests that
  could not fail; a test that cannot fail is worse than no test)
- `CHANGELOG.md` if anything user-visible changes; otherwise an honest
  `changelog: none` footer

## Risks

- **Confirmation bias toward "noise."** "It was contention" is the comfortable
  answer and it exonerates the harness. Mitigation: require a *structural* reason
  the strict flag could not have applied, not merely an absence of evidence that
  it did.
- **Over-reading a single rep.** n=1 cannot support a rate claim. Mitigation: if
  the verdict is noise, state it as a single observed failure out of the reps
  actually run, and do not dress it up as a measured probability.
- **Hard constraint:** do not weaken verification or the corpus to make the rep
  pass. If strict is right to decline, say so. `b"flag" in out` self-scoring stays
  prohibited.

## Test strategy

- If defect: new test reproduces the declined-but-attributable write, asserted to
  fail on `b3a40b4` and pass after the fix.
- If noise: no production change; the deliverable is the report. Verify the
  structural claim by grepping every `strict_attribution` use and showing the
  single read site is dominated by the `verify["flag_found"]` guard.
