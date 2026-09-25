# Independent peer review — round-2 benchmark plan, rev 1

**Date:** 24 Sep 2026
**Reviewer:** gpt-5.6-sol (`model_reasoning_effort=xhigh`, read-only sandbox) —
an independent same-tier model, per the tiering/review contract in the global
operating rules (non-trivial plans get a second same-tier reviewer).
**Subject:** `docs/plans/2026-09-24-benchmark-round2-cold-then-develop.md` rev 1
**Verdict:** NOT-APPROVED (5 blocking, 3 major)

Rev 2 of the plan addresses every finding and cross-references them as `[R-n]`
matching the numbering below. Two findings were accepted but implemented
differently from the reviewer's suggestion, with the reasoning stated in the
plan rather than silently diverging:

* `[R-1]` (timeout) — the re-run objection is accepted; the proposed
  censoring remedy is rejected because `--timeout` is a per-attempt budget that
  changes autopwn's control flow, so a 60 s run is not a superset of a 20 s run.
  Truncation is instead ruled out from the cold run's own transcripts, with no
  re-execution at all.
* `[R-4]` (sandbox) — the concern is accepted and *tested* from the cold run's
  `strace` logs rather than remedied by restructuring the corpus, because R1 was
  measured with the target `.c` in cwd too and changing that would invalidate the
  R1↔R2 comparison the cold number exists to support.

Review verbatim below.

---

NOT-APPROVED

1. [BLOCKING] The timeout fork violates the single-use rule. Adaptively rerunning failures at 60 seconds gives them extra stochastic chances; a flip does not prove timeout truncation. Choose B: make one predeclared 60-second cold run, record time-to-success, and derive the 20-second budgeted result by censoring the same attempts. Derive default and strict attribution from the same transcripts—never rerun for classification.

2. [BLOCKING] The proposed positive control does not repair the ablation defect. A separate reference exploit passing cannot prove that `ablation.py`’s prompt handling, delivery, and parsing work. Each ablation must have an intact-chain leg using the exact same driver path and settings, on a fresh process; require intact=flag and ablated=no-flag.

3. [BLOCKING] Running the irreplaceable measurement under known contention is unacceptable. Recording load and diagnosing “~1/7-shaped” failures afterward cannot recover the cold result. Defer execution until the host is quiescent or resources are exclusively reserved, with pre-run readiness criteria.

4. [BLOCKING] Reference exploits—and apparently target sources—remain accessible in the evaluation worktree. The plan never proves the evaluated pipeline cannot read them or prior soundness outputs. Run cold in a clean sandbox containing only contractually permitted inputs; exclude reference/source trees, rotate the secret again, and remove all soundness artifacts before launch.

5. [BLOCKING] Exclusion is the correct choice for objectively proven degenerates, but the “below ~8, repair first and call it cold” escape hatch is invalid. Evaluator-repaired targets are never cold. Predeclare an exact adequacy threshold; below it, report that R2 cannot support a cold estimate and obtain a new independently authored corpus. Repairs belong only to the developmental result.

6. [MAJOR] The primary numerator is not fixed. Calling `≥1/5` “solved” rewards luck and inflates the headline. Predeclare one primary endpoint—such as 5/5 SUCCESS or aggregate success rate with uncertainty—and label `≥1/5` exploratory. Never combine successes across modes or timeout conditions.

7. [MAJOR] The generalization fork points the right way, but its controls do not establish generalization. A heuristic keyed to an R2-discovered binary property can still be corpus-specific; R1 regression and a written prediction cannot detect that. Label post-development R2 strictly as training performance, freeze code before any R3/R4/R5 access, and let the next untouched cold round test generalization. An ancestry check alone does not enforce that embargo.

8. [MAJOR] Cold-run provenance is too weak. A committed prose report does not prove which invocation was first or prevent selective transcription. Freeze and record the exact evaluation commit, clean-tree state, pipeline/manifest/binary hashes, command, environment, exit status, and immutable raw results or sanitized results plus secure digests. Verify the merge against a file whitelist, not merely `diff --stat`.