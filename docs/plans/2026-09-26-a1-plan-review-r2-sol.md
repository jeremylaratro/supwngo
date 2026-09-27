# Peer review — 2026-09-26-a1-plan-review-r2-sol

Model: Sol 5.6 (xhigh). Date: 2026-09-26. Non-interactive file handoff. Round 2 of 3.

## Verbatim review

## Critical

**C1 — R2.1’s “frozen” probes still do not define deterministic end-to-end capabilities, so mandatory sets remain analyst-dependent.**

- **FAILURE SCENARIO:** P2 says “BMP envelope per B-3 §2,” but the referenced scope requires a pluggable registry with two formats ([A-1 plan](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:202), [B-3 scope](/srv/share/dev/supwngo/docs/plans/2026-09-26-b3-container-registry-plan.md:53)). Analyst A counts BMP plus `DeliverySpec` wiring; Analyst B counts the registry, BMP, WAV, and shared finalization. Both follow the text and produce different costs. P3 is similarly satisfied textually by an allowlist edit even though its two-part stdin delivery remains unchanged.
- **Fix:** State each behavioral contract inline: concrete input/target state, payload byte domain, entry point, required verifier receipt, artifact replay, negative control, and explicit inclusion/exclusion of CLI, registry, second formats, and engine selection behavior. Also define “mandatory function,” not only file and decision point.

**C2 — T-A1′ remains omission-blind because both “independent” derivations share the same analyst-selected candidate-file universe.**

- **FAILURE SCENARIO:** The analyst overlooks `templates.py`, so it appears in neither the forward set nor the “backward” candidate list. Exact equality passes. Deleting a known entry proves only that the set comparator detects a mismatch; it cannot expose a file omitted from both sets.
- **Fix:** Require a genuinely independent trace not seeded with the first candidate set—such as a blind second reviewer tracing every contract behavior from entry point to observable output. Compare both sets before either analyst sees the other, and adjudicate their union. Use a validation case with a concealed ground-truth set to prove common omissions are detected.

**C3 — A5 is neither held out nor identity-sensitive, so a payload-blind method can pass its alleged independent validation.**

- **FAILURE SCENARIO:** Revision 2 discloses Sprint 1’s answer—one file and its exact name—before requiring the prediction, while the original plan already disclosed Sprint 2′’s eight files ([A5](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:300)). A method returns one arbitrary file for Sprint 1 and eight arbitrary files for Sprint 2′; the stated count gate passes despite naming every seam incorrectly.
- **Fix:** Relabel these cases calibration. Select an actually undisclosed completed change, freeze its behavioral scope, preregister exact file/function/decision-point identities, then unblind the diff and score precision/recall against an independently adjudicated mandatory set.

## High

**H1 — The null, Method-B, and defect thresholds overlap and force an unsupported “architecture adequate” result.**

- **FAILURE SCENARIO:** Each of five probes implicates one different, expensive seam. “No seam appears in ≥2 probes” triggers the null and stop, while “≥4 distinct seams with no overlap” simultaneously mandates Method B ([thresholds](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:315)). Every seam is also automatically classified `right seam`, even if one costs five files, because only one probe samples its axis.
- **Fix:** Define precedence: diffuse results run Method B before any null decision. Permit a null only after per-probe cost ceilings and intrinsic seam classifications pass. Allow a single-probe seam to be defective, and recognize reductions in functions or decision points—not only file count.

**H2 — R2.8 creates a dimensionally invalid score and contradicts R2.1’s ban on cross-probe aggregation.**

- **FAILURE SCENARIO:** Proposal A eliminates the same mandatory file edit from all five future probe changes; deduplication records one unit of benefit. Proposal B removes two decision points from one probe; unweighted addition ranks B higher, even though files and decision points are incomparable and A removes five recurring edits ([benefit metric](/srv/share/dev/supwngo/docs/plans/2026-09-26-a1-modularity-assessment-plan.md:343)).
- **Fix:** Report a benefit vector per probe—file-edit occurrences, function-edit occurrences, and decision points—and a separate one-time implementation-cost vector. Use Pareto ranking or preregister justified weights with sensitivity analysis; do not deduplicate recurring future edits as though they were one event.

**H3 — T-A2′’s four-entry untracked baseline is incompatible with the command it proposes to compare.**

- **FAILURE SCENARIO:** `git ls-files --others --exclude-standard` emits individual leaf files under `report_output/`, `solve_output/`, and `tests/htb-targets/`, not those three directory names. An exact four-entry baseline leaves the gate permanently red; prefix-exempting the directories makes `tests/htb-targets/new_file.py` disappear behind the baseline and lets the list grow quietly.
- **Fix:** Snapshot the exact leaf-path output at sprint start and reject `current_untracked − baseline_untracked`; never treat a baselined directory as a wildcard. Specify the comparison algorithm in T-A2′.

## Medium

**M1 — T-A3 does not gate the queue’s required artifact location.**

- **FAILURE SCENARIO:** The author appends A0–A5 to the current plan, maps clauses (a)–(d), and closes A-1. T-A3 passes even though the queue requires a written assessment under `docs/research/` ([queue exit](/srv/share/dev/supwngo/docs/process/2026-09-26-standard-work-queue.md:107)).
- **Fix:** Add the exit preamble to T-A3 and require the final assessment to exist under `docs/research/`, with its path recorded beside the queue closure.

**M2 — R2.7 promotes an inferred causal explanation into a mandatory factual conclusion.**

- **FAILURE SCENARIO:** Non-overlap occurs because the five heterogeneous probes sample five different axes, but the null branch must state that Sprint 2′’s eight files were “the one-time price of a new axis.” Only the eight-file numerator is measured; R2.8 itself correctly labels the capability grouping inferred.
- **Fix:** Report only that the evidence is “consistent with” an axis-specific cost, label it `inferred`, and allow competing explanations—especially until Method B resolves diffuse results.

NOT-APPROVED