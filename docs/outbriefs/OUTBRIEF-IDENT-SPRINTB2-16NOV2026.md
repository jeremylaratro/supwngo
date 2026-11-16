# Outbrief — Identification Sprint-B2 (VULN-axis detector wiring)

- **Date:** 2026-11-16
- **Branch:** `feat/w-ident-baseline` · **Base SHA:** `2b71633`
- **Path:** dev-methodology full cycle, Sprint-B2 · **Decision:** user-approved
  "bounded fix now, honest partial."
- **Objective (effort):** ≥90% per-family precision AND recall on both ID axes
  (VULN + METHOD) before full exploitation. **This sprint is VULN-axis only and
  is NOT expected to turn the gate green** — it moves two families off 0 recall
  honestly, without regression or overclaim.

## What changed

| Area | Change |
|------|--------|
| `supwngo/vulns/detector.py` | add `VulnType.OFF_BY_ONE` |
| `supwngo/reporting/cvss.py` | add `off_by_one` CVSS vector (keeps the pinned unmapped-set test green) |
| `supwngo/vulns/_disasm.py` (new) | shared `objdump -d -M intel` helper + `IMM_STORE`/`NULL_QWORD_STORE` regexes; **raises `DisassemblyUnavailable`** when objdump can't run |
| `supwngo/vulns/uaf.py` | contract-valid `detect(crash=None)` + `get_exploit_primitive`; cheap free-without-null body signal |
| `supwngo/vulns/off_by_one.py` | contract-valid `detect(crash=None)` + `get_exploit_primitive`; length-terminating-copy signal → `OFF_BY_ONE` only |
| `supwngo/reporting/adapter.py` | wire both detectors (`static_detectors()` now returns 7) |
| `tests/test_vuln_ident_detectors_b2.py` (new) | 11 new-behavior + honesty tests |
| `docs/plans/…sprintB-plan.md` | record **G2e** (controls are symbol/import-identical to positives → discrimination needs dataflow; deferred) |

## Result (measured, same harness)

- **Benefit (VULN-axis scorer, `benchmark/score_vuln_ident.py`, 73/73 scored):**
  | family | recall before → after | precision | 
  |--------|----------------------|-----------|
  | uaf | 0/7 → **1/7** | 1/1 = 100% (corpus) |
  | off_by_one | 0/13 → **1/13** | 1/1 = 100% (corpus) |
  | stack_bof / format_string / integer / heap_overflow | unchanged | unchanged |
  Both target families moved **off 0 recall** at 100% corpus precision; no other
  family perturbed. Scorer verdict stays **RED (exit 2)** — expected and honest
  under the bounded fix.
- **Regression: GREEN.** Full `tests/` run vs the Phase-5 baseline manifest by
  per-test identity: **0 pass→fail/error, 0 pass→skip, 0 pass→missing, 0 new
  failures.** Totals `143 failed / 3418 passed / 165 skipped / 4 errors` —
  fail/skip/error identical to baseline; passed +16 (15 new B2 tests + 1
  auto-generated `VulnType.OFF_BY_ONE` parametrization case). The 143 pre-existing
  failures are the known Fedora gcc-14 codegen + base-SHA env artifacts, unchanged.

## Honesty notes (no overclaim)

- The "0 FP" claim is **corpus-scoped**. The presence-based signals cannot
  separate safe from unsafe uses: off_by_one fires on **3/27** unrelated negative
  controls (all via safe `snprintf` — the same function as the only true positive
  `obo_14`), uaf on **0/27**. Separating them is the deferred **G2e** dataflow
  follow-on, materially larger than this bounded sprint.
- Independent review (Codex Daybreak Blue, cyber-top), two rounds. Round 1
  `FIX-FIRST` (3 HIGH + 1 MEDIUM): HIGH-3 (objdump-unavailable read as a complete
  report) **fixed**; HIGH-1 accepted as deferred-G2e with the claim corrected;
  HIGH-2 documented (0 corpus repro); MEDIUM-4 pre-existing (base SHA), not
  adopted. Round 2 `FIX-FIRST` found one gap *in* the HIGH-3 fix (R2-HIGH:
  `PermissionError`/other `OSError` launch failures still read as complete) —
  **fixed** (`except OSError → DisassemblyUnavailable`) and self-verified; no
  round 3. Full record:
  `docs/reviews/2026-11-16-identification-sprintB2-diff-review.md`.

## Deferred (scoped follow-on, NOT done here)

- **G2e** — per-shape intra-function dataflow to discriminate positives from their
  symbol/import-identical controls (the path to ≥90% recall+precision per family).
- `TypeConfusionDetector` wiring (excluded this sprint).
- PX-1 — detectors skip `super().__init__()` (base read/summary API unreachable
  via the adapter path; pre-existing at base SHA).

## Rollback

Revert the merge commit; no schema/data migration, no persisted-state change.
