# Test card — Identification Sprint-B2 (VULN-axis detector wiring)

- **Date:** 2026-11-16
- **Branch:** `feat/w-ident-baseline`
- **Base SHA:** `2b71633` (feat(benchmark): add VULN-axis identification scorer + frozen truth + B2 baseline)
- **Scope:** Wire `UAFDetector` + `OffByOneDetector` into `reporting/adapter.py`
  `static_detectors()`; add `VulnType.OFF_BY_ONE` + CVSS vector; new
  `supwngo/vulns/_disasm.py`. Bounded "honest-partial" fix (user-approved).
- **Path (dev-methodology):** Full cycle, Sprint-B2. This card covers Phase 7.

## Files changed (product)

| File | Change |
|------|--------|
| `supwngo/vulns/detector.py` | `VulnType.OFF_BY_ONE = auto()` |
| `supwngo/reporting/cvss.py` | `off_by_one` CVSS vector (keeps the pinned unmapped-set test green) |
| `supwngo/vulns/_disasm.py` (new) | `objdump -d -M intel` helper + `IMM_STORE` / `NULL_QWORD_STORE` regexes; raises `DisassemblyUnavailable` when objdump cannot run (honesty fix, review HIGH-3) |
| `supwngo/vulns/uaf.py` | contract-valid `detect(crash=None)`, `get_exploit_primitive`, `_scan_free_without_null` |
| `supwngo/vulns/off_by_one.py` | contract-valid `detect(crash=None)`, `get_exploit_primitive`, `_scan_terminating_copy_calls` |
| `supwngo/reporting/adapter.py` | wire both detectors (static_detectors now returns 7) |
| `tests/test_vuln_ident_detectors_b2.py` (new) | new-behavior tests |

## (a) Regression — nothing that passed now fails

- **Baseline manifest:** `scratchpad/b2_regression_manifest_99c29d8.tsv`
  (per-test identity → status; 3713 nodes: 3402 pass / 143 fail / 165 skip / 4
  error). Base `99c29d8`; the two commits to `2b71633` are docs/benchmark-only,
  no product code, so the manifest is valid for the product regression surface.
- **Command:** `python3 -m pytest tests/ -p no:cacheprovider -q --junitxml=…`
- **Targeted pre-check (read directly):** `test_reporting_adapter.py`,
  `test_new_modules.py`, `test_heap_offbynul_executor.py`,
  `test_cli_report_command.py` all pass. `test_walkthrough_off_by_one.py` shows
  **45 fail / 19 pass** — the *identical* 45 node IDs that fail at baseline
  (`comm -13` of the baseline-fail set vs the now-fail set = empty; zero new
  failures, zero fixes). These are pre-existing Fedora gcc-14 codegen artifacts
  (positive vs control `read_line` bodies differ by two instructions — `cmp`
  operand order + `jae`/`jb` — not one), independent of the Python edits.
- **Full-suite verdict:** **GREEN.** Full run (`tests/`, 30m20s;
  `b2_regression_after.xml`) vs the baseline manifest by per-test identity:
  **0 pass→fail/error, 0 pass→skip, 0 pass→missing/renamed, 0 new failures.**
  Totals `143 failed / 3418 passed / 165 skipped / 4 errors` — fail/skip/error
  identical to baseline; passed **+16**, fully accounted: 15 = the new B2 file,
  1 = `test_reporting_adapter…test_every_vuln_type_converts[VulnType.OFF_BY_ONE]`
  (the existing all-`VulnType` parametrization auto-gained the new member's case,
  and it passes). The 143 pre-existing failures match baseline by signature
  (Fedora gcc-14 codegen + the base-SHA env failures in memory `known pre-existing
  gate failures`). Diff tool: `scratchpad/b2_identity_diff.py`.

## (b) New behavior proven — `tests/test_vuln_ident_detectors_b2.py` (15/15 pass)

| Test | Proves |
|------|--------|
| `…uaf_detector_emits_use_after_free_on_known_positive` | `UAFDetector` emits `USE_AFTER_FREE` on `uafr_10_show_after_free` |
| `…uaf_detector_is_silent_on_cleared_on_free_control` | silent on `uafr_90_neg_cleared_on_free` (0 FP on the control) |
| `…off_by_one_detector_emits_off_by_one_on_known_positive` | `OffByOneDetector` emits `OFF_BY_ONE` on `obo_14_snprintf_ret_caller_frame` |
| `…off_by_one_detector_never_emits_generic_overflow_types` | precision guard: never `STACK_`/`HEAP_BUFFER_OVERFLOW` |
| `…off_by_one_detector_is_silent_on_bounded_control` | silent on `obo_90_neg_bound_fixed` (0 FP on the control) |
| `…detectors_accept_crash_kwarg_and_expose_primitive` (×2) | `detect(crash=None)` + `get_exploit_primitive` → `ExploitPrimitive("write")` |
| `…detectors_return_empty_for_pathless_binary` (×2) | path-less binary → `[]`, no raise (adapter contract) |
| `…objdump_launch_failure_raises_disassembly_unavailable` (×3) | objdump not-installed / not-executable / timeout → `DisassemblyUnavailable` (not a silent `[]`) — HIGH-3 + R2-HIGH |
| `…detect_all_marks_report_incomplete_when_objdump_cannot_run` (×3) | each launch failure → 2 `DetectorFailure`s, `report.complete is False` — HIGH-3 + R2-HIGH |

Result: `15 passed in 2.76s`. Corpus binaries are build artifacts → a missing
one `pytest.skip`s, never fails. The ×3 parametrization covers every way objdump
can fail to run (`FileNotFoundError`, `PermissionError`/other `OSError`,
`TimeoutExpired`) — R2-HIGH closed the `OSError` gap left by round 1.

### Precision honesty (review HIGH-1 / HIGH-2)

The B2 "0 FP" claim is **corpus-scoped**: 100% precision / 0 FP on the 73-binary
vuln-ident corpus. The presence-based signals cannot separate safe from unsafe
uses, so on unrelated binaries they do fire:

| Detector | Corpus precision | Broader negative-control FPs | Note |
|----------|------------------|------------------------------|------|
| off_by_one | 1/1 = 100% | **3/27** (`sym_90_neg_nofollow`, `toctou_90_neg_fd_anchored`, `trav_90_neg_realpath_confined`) | all 3 via safe `snprintf` — same function as the sole true positive `obo_14`; separating them is the deferred G2e dataflow |
| uaf | 1/1 = 100% | **0/27** (measured) | review HIGH-2's `free();flag=1;` shape not corpus-reproduced; theoretical |

Tightening is **not** a cheap body-level change (it needs the deferred dataflow),
so the code is unchanged and the claim is scoped. See
`docs/reviews/2026-11-16-identification-sprintB2-diff-review.md`.

## (c) New gate shown able to go RED

**N/A — no new gate.** The VULN-axis scorer
(`benchmark/score_vuln_ident.py`, exit 0/2/1) was introduced at the base SHA
`2b71633`, not in this sprint; B2 adds only ordinary unit tests. The pre-existing
scorer gate is RED both before and after this change (exit 2) — expected and
honest under the bounded fix (recall < 90%).

## Peer diff review (Phase 6 gate)

- Reviewer: Codex **Daybreak Blue** (cyber-top, xhigh, read-only), file handoff.
- Round 1: `FIX-FIRST` (3 HIGH + 1 MEDIUM). HIGH-3 (objdump honesty) **fixed**;
  HIGH-1 accepted as deferred-G2e with the claim corrected; HIGH-2 documented
  (0 corpus repro); MEDIUM-4 pre-existing, not adopted. Full dispositions +
  empirical verification: `docs/reviews/2026-11-16-identification-sprintB2-diff-review.md`.
- Round 2: `FIX-FIRST` — confirmed HIGH-3 for the translated cases and raised one
  new HIGH (R2-HIGH: `PermissionError`/other `OSError` launch failures still read
  as complete). **Fixed** (`except OSError → DisassemblyUnavailable`) and
  self-verified; dispositions of HIGH-1/HIGH-2/MEDIUM-4 confirmed acceptable. No
  round 3 (interop rule 8). Record in `docs/reviews/`.
