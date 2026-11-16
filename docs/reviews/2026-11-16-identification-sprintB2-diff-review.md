# Sprint-B2 diff review — independent (Codex Daybreak Blue, cyber-top)

- **Date:** 2026-11-16
- **Artifact:** uncommitted B2 diff on `feat/w-ident-baseline` (base `2b71633`).
- **Reviewer:** Codex Daybreak Blue, cyber-top tier, xhigh, read-only, file handoff.
- **Author:** Claude (Opus) — this session.
- **Round-1 verdict:** `FIX-FIRST` (3 HIGH + 1 MEDIUM).
- **Round-2 verdict:** `FIX-FIRST` — one new HIGH (a gap *in* the HIGH-3 fix),
  now fixed and self-verified; the other three dispositions confirmed acceptable.
  No further Codex round (interop rule 8 caps at 2); final fix verified in-session.

Every finding was reproduced or refuted empirically before disposition (peer
output is a claim, not a fact).

## Findings and dispositions

### HIGH-1 — off_by_one false-positives on safe copy calls → **ACCEPTED (deferred G2e); claim corrected**
Codex: emitting `OFF_BY_ONE` on the mere presence of
`snprintf`/`strncpy`/`strncat` fires on safe binaries; reproduced on
`trav_90_neg_realpath_confined` and two others.

Verified: reproduced 3/27 FPs on negative controls
(`sym_90_neg_nofollow`, `toctou_90_neg_fd_anchored`,
`trav_90_neg_realpath_confined`). **All three — and the one true positive
`obo_14` — fire on `snprintf` specifically** (zero `strncpy`/`strncat` among
them). Safe vs unsafe `snprintf` are syntactically identical; separating them is
precisely the dataflow discrimination the user explicitly deferred (plan G2e).
Dropping `snprintf` would return recall to 0/13. So the FP rate is the known
cost of the cheap signal, not a fixable-now defect.

Action: code unchanged; **the overclaim was fixed** — CHANGELOG, test card and
outbrief no longer assert global "0 FP". Honest claim: 100% precision / 0 FP
*within the 73-binary vuln-ident corpus*; ~3/27 FP on unrelated negative
controls, deferred to G2e.

### HIGH-2 — uaf false-positive on `free(p); flag=1;` → **DOCUMENTED (theoretical)**
Codex: a non-zero store after `free` not tied to the freed pointer is reported
as UAF.

Verified: **0 reproduced across all 27 real negative controls.** Codex's case
was constructed, not a corpus binary. The heuristic requires a non-zero
immediate store AND no NULL-qword store within an 8-instruction post-`free`
window bounded by the next `ret`/`call`/`jmp`/`leave`. Recorded as a known
precision limitation of the cheap signal (same deferred bucket); not
corpus-reproduced, not a ship-blocker.

### HIGH-3 — objdump unavailable read as a clean complete report → **FIXED**
Codex: missing/timed-out objdump → `[]` → no `DetectorFailure` →
`build_report` marks `complete: true`. Violates the adapter's load-bearing
honesty contract. (New code; genuinely in scope.)

Verified and fixed: `supwngo/vulns/_disasm.py` now raises
`DisassemblyUnavailable` on `FileNotFoundError` / `TimeoutExpired` / non-zero
objdump exit, returning `[]` only for a path-less binary or
objdump-ran-no-rows. Both detectors' `detect()` re-raise
`DisassemblyUnavailable` (while still swallowing unexpected errors), so
`detect_all` records a `DetectorFailure` and `build_report` marks
`complete: false`. End-to-end probe (objdump forced missing): 2 failures
recorded, `complete == False`. New tests
`test_objdump_missing_raises_disassembly_unavailable` and
`test_detect_all_marks_report_incomplete_when_objdump_missing` pass.

### MEDIUM-4 — skipped base `__init__` → `_vulnerabilities` undefined → **PRE-EXISTING, not adopted**
Codex: `get_vulnerabilities()`/`clear()`/`summary()`/`CompositeDetector.summary()`
raise `AttributeError` because the constructors store `self.vulnerabilities`
and skip `super().__init__()`.

Verified: **identical at base SHA `2b71633`** (confirmed via `git show`); not
introduced by this diff. Unreachable via the path this sprint adds — the
reporting adapter's `detect_all` calls only `.detect()`, never `.summary()` /
`.get_vulnerabilities()`, and nothing wires these detectors into
`CompositeDetector`. A proper fix (unifying on `_vulnerabilities`) is
non-trivial and outside this bounded sprint. Recorded as a pre-existing item
for a follow-on; adopting it here would be unplanned scope.

## Round 2 — verify the HIGH-3 fix

Codex re-reviewed the post-round-1 diff (read-only, cyber-top, xhigh). It
confirmed HIGH-3 for the translated cases (forced-missing executable, timeout,
non-zero exit each gave two `DetectorFailure`s and `complete=False`), and
confirmed the HIGH-1/HIGH-2/MEDIUM-4 dispositions as acceptable under the bounded
scope (3/27 off_by_one FPs all via `snprintf`; 0/27 uaf; MED-4 pre-existing +
unreachable). It raised **one new HIGH**:

### R2-HIGH — launch failures other than `FileNotFoundError`/`TimeoutExpired` still read as complete → **FIXED**
`objdump_intel` translated only `FileNotFoundError` and `TimeoutExpired`. A
different launch failure — e.g. objdump present but **not executable**
(`PermissionError`), or any other `OSError` — propagated as a generic exception,
which the detectors' broad `except Exception` swallowed → `[]` → no
`DetectorFailure` → `complete: true`. The exact gap HIGH-3 set out to close, via a
different exception.

Verified (did not take the claim on faith): monkeypatched `subprocess.run` to
raise `PermissionError`; before the fix `detect_all` gave `findings=0,
failures=0, complete=True`. Fix: added `except OSError -> DisassemblyUnavailable`
(after the `FileNotFoundError` and `TimeoutExpired` clauses, so their specific
messages are kept; `OSError` then covers `PermissionError` and any other launch
failure). After the fix the same input gives `failures=2, complete=False`. New
tests parametrize all three launch failures (`not_installed`, `not_executable`,
`timeout`) across both the raise and the incomplete-report assertions
(`test_objdump_launch_failure_raises_disassembly_unavailable`,
`test_detect_all_marks_report_incomplete_when_objdump_cannot_run`). B2 file 15/15.

No further Codex round (interop rule 8 caps review at two rounds); this final
one-clause fix was verified in-session.

## Pre-existing items surfaced (own IDs, not fixed here)

- **PX-1** `UAFDetector`/`OffByOneDetector` (and any detector not overriding the
  base `name = "base_detector"`) skip `super().__init__()`, so `_vulnerabilities`
  is undefined and the base read/summary API raises; `DetectorFailure.detector`
  also labels every such failure `base_detector`. Present at base SHA. Follow-on.
