# Peer review — 2026-09-26-a1-plan-review-r1-sol

Model: Sol 5.6 (xhigh). Date: 2026-09-26. Non-interactive file handoff.

## Verbatim review

## Critical

**C1 — The core “files per capability” measurement has no stable capability unit, so its result is not reproducible.** The probes mix a sink, an envelope, a technique, an oracle, and an engine replacement; P1 even permits either an environment variable or a socket, which have radically different integration costs ([plan §3](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:49)).

- **FAILURE SCENARIO:** Analyst A chooses an env-var sink and counts three files; Analyst B chooses a socket and counts eight. Meanwhile Sprint 2′ is counted as one capability despite adding argv, file-argv, file-fixed, CLI controls, and verifier/artifact behavior. Both analyses follow the plan but reach opposite modularity conclusions.
- **Fix:** Freeze one concrete acceptance contract per probe, at a named base commit, and define exactly what constitutes a mandatory file/function/decision-point change. Compare only like-grained capabilities or report categories separately rather than aggregating them.

**C2 — T-A1 and M-A1 are omission-blind, allowing an incomplete or payload-blind assessment to pass.** T-A1’s concrete RED condition catches unnecessary named files, but not missing files; its single “paper” spot-check is authored from the same assumptions being tested ([T-A1](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:140)).

- **FAILURE SCENARIO:** P1 lists only `contracts.py` and `cli.py`, omitting verifier and generated-artifact parity. Both named files really require changes, and a deliberately incomplete paper implementation touches nothing else. T-A1 passes and M-A1 reaches 5/5 even though the predicted change set is incomplete.
- **Fix:** Give every probe an end-to-end behavioral acceptance contract. Independently derive the required set from those behaviors—preferably by a second trace or reviewer—and gate exact set equality for all five probes. Prove RED by deleting a genuinely required entry, not merely by adding an unnecessary one.

**C3 — T-A2’s unbased `git diff --stat` cannot enforce the documentation-only scope.** A normal `git diff` ignores committed branch changes and untracked files ([scope gate](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:132)).

- **FAILURE SCENARIO:** Modify `orchestrator.py`, commit it with the assessment, then run `git diff --stat`; the output is empty and T-A2 passes. An untracked production file is likewise invisible.
- **Fix:** Record the sprint base SHA and inspect `<base>...HEAD`, staged changes, unstaged changes, and untracked files. Gate the resulting path set against an explicit `docs/` allowlist; account for the pre-existing dirty state with a recorded baseline manifest.

## High

**H1 — The planned deliverables do not satisfy the queue entry that A-1 claims to close.** The queue requires retrospective coupling across Sprint 1, Sprint 2′, and B-3, a “right seam” versus “modularity defect” decision for every seam, and at most three proposals mapped to newly additive capabilities ([queue exit](/srv/share/dev/supwngo/docs/process/2026-09-26-standard-work-queue.md:96)); A1–A4 require none of those conditions ([deliverables](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:105)).

- **FAILURE SCENARIO:** The author completes P1–P5, provides five proposals, omits Sprint 1, and never classifies seams. Every stated A-1 gate passes, yet the queue entry is marked closed without meeting its exit criteria.
- **Fix:** Add an explicit queue-exit traceability gate covering every clause. If B-3 must contribute actual rather than predicted cost, either schedule A-1 after B-3 or revise the queue formally and keep the later calibration open.

**H2 — P2’s future implementation cost is not an independent falsification oracle for the assessment.**

- **FAILURE SCENARIO:** A2 predicts “four files”; B-3 touches four different files, so the number appears correct despite identifying the wrong seams. Conversely, B-3 touches six files because its scope includes two formats and extra CLI behavior, causing a false “refutation” of an otherwise correct architectural prediction. “Materially different” is also undefined ([A4](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:113)).
- **Fix:** Pre-register the exact behavioral scope and predicted file/function/decision-point sets, distinguish mandatory architectural edits from discretionary implementation work, and score precision and recall. Describe this as calibration, not independent refutation; use a completed, held-out historical change for independent validation.

**H3 — T-A0 proves only that a search is repeatable, not that broad negative claims are true.**

- **FAILURE SCENARIO:** An exact-token search finds one `FILE_DELIVERY_ALLOWLIST`, so E2 reports it as the only gate while an equivalent restriction exists under another name. Likewise, a CLI-only constructor search reports four `EnhancedAutoExploiter` sites while the production factory also constructs it at [enhanced_auto.py](/srv/share/dev/supwngo/supwngo/exploit/enhanced_auto.py:1431). The search is perfectly rerunnable, so T-A0 remains green.
- **Fix:** For “only” and “no contract” claims, require a declared search universe at a pinned SHA, symbol/reference searches, aliases and factories, and a call-path review. Keep broad negatives `inferred` unless the method is demonstrably exhaustive.

**H4 — The null result and Method-B fallback are stated but not operationally reachable gates.** Tests are excluded and the measured eight-file set contains production files, yet the null trigger depends partly on tests dominating the cost; if probes share no seam, the plan says Method B is preferable but contains no step requiring it ([scope](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:31), [decision branches](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:83)).

- **FAILURE SCENARIO:** Every cross-cutting edit is judged an appropriate interface boundary, or the five probes share no seam. Neither “tests dominated” nor any mandatory Method-B work occurs, but A0–A4 can still be published with a seam-oriented conclusion.
- **Fix:** Define executable decision thresholds—for example seam recurrence, intrinsic-boundary classification, and projected edit reduction—and require either the null report or Method B when its trigger fires. Remove tests from the null criterion unless test cost is brought into scope.

## Medium

**M1 — Several provenance labels contradict the plan’s own taxonomy.**

- **FAILURE SCENARIO:** E6 is cited from the prior G-W3-1 artifact but enters as `measured`, although prior cited evidence is defined as `recorded`; M-A1 calls the absence of any assessment `measured`; and E1 measures eight touched files while the classification of that work as exactly one capability remains inferred ([provenance table](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:88), [metrics](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:146)).
- **Fix:** Label E6 `recorded` until rerun on the pinned HEAD, label open-world absence and capability grouping `inferred`, and separate E1’s measured numerator from its inferred denominator. Supply provenance for M-A2.

**M2 — “Ranked by cost-to-benefit” has no defined benefit calculation.**

- **FAILURE SCENARIO:** One proposal saves a file on one probe; another costs more but removes three repeated decision points across four probes. Either can be ranked first by narrative preference while satisfying A3.
- **Fix:** Define benefit as a quantified reduction in mandatory files/functions/decision points over the fixed probe set, define implementation cost on the same basis, prevent double-counting shared edits, and record uncertainty for counterfactual savings.

NOT-APPROVED