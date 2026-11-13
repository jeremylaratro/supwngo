# Review r2 — retire hardcoded target values plan (Daybreak Blue, xhigh, 2026-11-13)

Verification round against plan rev 2. Verbatim below; disposition in plan rev 3 §9 (Round 2).

---

## Verdict: REWORK

Finding 3 remains partial, and the revision introduces one new HIGH issue.

| # | Status | Evidence |
|---|---|---|
| 1 | RESOLVED | The plan specifies pinned AST/token searches, a machine-generated `path:line:class:status` manifest, and failures for unclassified/stale hits; all cited omissions are seeded. `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md:30-52` |
| 2 | RESOLVED | W-0/W-1 absorb the focused corpus, reusable sandboxed runner, cache and budgets; constants and marker plumbing precede W-4 confirmation. `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md:88-108,133-142`; `docs/roadmaps/2026-11-12-mythos-roadmap.md:1071` |
| 3 | PARTIAL | Exact denominators, non-abstention, provenance and negative controls are now present. However, “twins” are defined only as 16 rename twins, and W-5 exercises commands only on those twins. The binding checklist requires rename **and strip** twins for every payoff-selecting command. `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md:92-103,108-113`; `docs/plans/2026-11-12-session-goals-checklist.md:48-51,221-222` |
| 4 | RESOLVED | A single payoff API, per-consumer seam tests, four named mutants, disjoint seeded names, and truth-RVA assertions are explicit. `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md:56-57,112,115-130` |
| 5 | RESOLVED | The roadmap now records the SP-01b dependency, removes name tie-breaking and SP-04b from the cut order, and adopts AMD-19..22. `docs/roadmaps/2026-11-12-mythos-roadmap.md:327,709,818,1067-1074` |
| 6 | RESOLVED | The checker has a negative test, W-6 pins exact scores/errors/runtime, and one-rep canaries run after W-1/W-4/W-5. `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md:107,113,146-149` |

## New HIGH

**Manifest lifecycle is internally inconsistent.** Every manifest entry must continue matching or be rejected as stale, but W-5 deletes hardcoded sites while requiring their entries to become `migrated`. A deleted site necessarily stops matching. `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md:39-42,107,112`

**Concrete fix:** keep an immutable baseline inventory with stable IDs and closure status, plus a separately generated current-hit manifest. Require every baseline ID to be `migrated` or justified `allowed`, and require the current scan to contain zero unclassified/open hits. Exempt closed tombstones from the current-hit stale check. Also add explicit strip-twin pairs to W-5 and run all four CLIs against both rename and strip twins.