# Peer review — 2026-09-27-a1-plan-review-r3-sol

Model: Sol 5.6 (xhigh). Date: 2026-09-27. Non-interactive file handoff. **Round 3 of 3 — FINAL.**

## Verbatim review

## Critical

**C1 — A5′ is still not held out: its implementation is already present in the repository used to make the prediction.** This is the same defect class as R2 C3 recurring again; the validation design—not another gate—must be escalated.

- **FAILURE SCENARIO:** `1e26373` is an ancestor of the probe base `37a8d9b`. Given the disclosed subject and flag names, an analyst searches the descendant tree for `--strategy` and `--all-strategies`, copies the resulting file/function/decision-point identities, and scores perfect precision/recall without predicting anything from the pre-change architecture.
- **Fix:** Void `1e26373` for this analyst. Use a fresh evaluator isolated to the commit’s parent tree, with no descendant tree or history access, and provide a fully frozen behavioral contract rather than only the subject. A separate custodian can unblind and score it. I verified ancestry only and did not inspect the commit’s diff.

**C2 — The probe contracts remain post-hoc because their “full form” is deferred to the deliverable.** This is the third occurrence of the R1 C1/R2 C1 defect; the design should be escalated to a separate immutable preregistration phase.

- **FAILURE SCENARIO:** After tracing P4, the author chooses the filename-selection mechanism, negative control, receipt fields, and replay requirement that fit the files already found. Both derivations then agree because they receive the same retrospectively narrowed contract, while the abbreviated plan appears satisfied.
- **Fix:** Before either derivation or repository tracing, publish and hash the complete contract for every probe—including exact target, inputs, outputs, negative control, replay semantics, and inclusions/exclusions. Do not permit the assessment deliverable to complete or reinterpret those contracts.

**C3 — P1’s contract is impossible because a POSIX environment value cannot contain an embedded NUL.**

- **FAILURE SCENARIO:** P1 requires arbitrary payload bytes including NUL through `--input-vector env`. `execve` environment entries are NUL-terminated; Python’s subprocess path rejects such a value with `ValueError: embedded null byte`. No implementation can meet the contract, so 5/5 completion is impossible—or the analyst silently introduces encoding and target-side decoding, changing the capability and mandatory set.
- **Fix:** Freeze P1 to an environment-safe byte domain, or choose a genuinely binary-safe sink. If encoding is intended, specify the codec and target-side decoding behavior explicitly in the preregistered contract.

## High

**H1 — R3.2’s concealed-ground-truth gate checks only omissions, so a maximally overinclusive method passes.**

- **FAILURE SCENARIO:** Both derivations return every production file. Their sets agree, and the concealed case misses no mandatory file, so the procedure is published as adequate despite near-zero precision and no useful localization.
- **Fix:** Preselect the concealed case before derivation, freeze its behavioral scope, and score both precision and recall against an independently established identity set with preregistered thresholds. Describe success on one case as validation evidence, not proof that the procedure detects omissions generally.

**H2 — The Method-B/null branch remains non-executable and still ignores function cost.** This repeats R1 H4 and R2 H1; the decision framework itself should be redesigned rather than patched with another threshold.

- **FAILURE SCENARIO:** Four disjoint seams trigger Method B; the author emits any import graph, because no required metric or outcome rule exists. Each probe touches two files and one decision point but twelve functions. The author labels every seam “intrinsic with a reason,” passes the stated null ceiling, and declares the architecture adequate despite substantial mandatory spread.
- **Fix:** Define Method B’s exact graph, universe, metrics, and RED outcomes; provide reviewable criteria for `intrinsic`; and include a function-edit ceiling in the null condition. Alternatively, remove the adequacy conclusion and report the result as unresolved when the evidence is diffuse.

**H3 — R3.1 makes P2 incompatible with the B-3 calibration that remains in A4.** This reintroduces the scope-mismatch defect from R1 H2; the calibration design should be split rather than gate-patched.

- **FAILURE SCENARIO:** P2 correctly omits the registry, WAV, and shared finalization because R3 explicitly excludes them. B-3 necessarily includes all three. Scoring P2 against B-3’s actual change falsely reports missing identities; excluding those identities from ground truth means the gate is no longer calibrating against the actual B-3 change.
- **Fix:** Either align P2 exactly with B-3’s frozen acceptance contract or remove B-3 as its scored calibration target. A narrower hypothetical BMP probe may remain, but it needs its own scope-matched validation.

## Medium

**M1 — Pareto ranking, weighted tie-breaking, and “no scalar score” do not define a reproducible ordering.**

- **FAILURE SCENARIO:** Two proposals are Pareto-incomparable—one removes file edits across several probes while another removes many function edits from one probe. Pareto produces no ordering; positive weights either imply a prohibited scalar aggregation or have no stated operation. Weights selected after seeing the vectors can justify either preferred answer.
- **Fix:** Publish nondominated tiers without forcing a total rank, or preregister an explicit lexicographic/scalar rule, its timing, and sensitivity bounds before proposal vectors are known.

**M2 — The plan still calls counterfactual probe costs “measured” when they are inferred predictions.**

- **FAILURE SCENARIO:** A paper trace reports that a hypothetical probe requires two files; an eventual implementation exposes a third runtime path. The assessment nevertheless presents the original change cost as measured because files were named and two derivations agreed.
- **Fix:** Label hypothetical mandatory sets, seam-removal benefits, and implementation costs `inferred` or `predicted`. Reserve `measured` for observed repository state and post-change results; report held-out precision/recall separately.

**VERDICT: NOT-APPROVED**