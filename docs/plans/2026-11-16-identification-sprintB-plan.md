# Sprint B — two-axis technique-family identification to ≥90% — plan — 16NOV2026

**Base SHA:** `1b117a2` (branch `feat/w-ident-baseline`). **Objective:** per-family
identification ≥90% on BOTH axes (METHOD + VULN) over corpus/ + corpus_r2 + the
specialized corpora. Gap analysis: `docs/research/2026-11-16-identification-baseline-gap-analysis.md`.
Methodology: full cycle (multi-item, cross-module, a VulnType **schema change**, a
target metric). Plan status: **skeleton + approaches; peer review pending; baselines
deferred to each sprint's Phase 6.**

## Constraints (settled; not re-litigated)

- Scope = IDENTIFICATION only; the solve/exploitation rate is deferred (user).
- Honesty: a deliberate benchmark constant is a feature; a wrong number is fixed
  in the corpus or the measurement, never by redesigning the tool.
- The METHOD-axis instrument is the **existing** passcard `score_method_r0`/
  `score_method_l` driven by the **real `pwn --json` CLI** — not an in-process
  suggester (proven to diverge: `09_srop` CLI=`SROP`, in-process=`ROP_EXECVE`).
- No Claude trailer on commits/PRs. Ship-when-done; zero dangling git state.

## Sprint map

| Sprint | Band | Axis | Items | Shippable unit |
|---|---|---|---|---|
| **B1** | P1 | METHOD | author `method_accept` truth for corpus targets; baseline via passcard; close <90% families | truth files + measurement, no engine change unless a real precision gap is confirmed |
| **B2** | P1 | VULN | wire excluded detectors to the adapter contract + add `VulnType` members (G2a); lift integer/heap under-detection (G2b); vuln-ID scorer + vuln-family truth | detector/schema change + scorer + truth |

B1 and B2 are independent (different seams: strategy vs detector) → may branch
from the same base `1b117a2`. Order: **B2 first** (its baseline is already
captured and trustworthy; its gaps are structural and unambiguous), then B1.

## B2 — VULN-axis identification

**Closes:** G2a (structural exclusion), G2b (under-detection), G3 (baseline).
**Benefit baseline (captured now, HEAD `1b117a2`, `detect_all` any-match, 30
targets):** overall 19/30=63%; `stack_bof` 14/15, `format_string` 5/5,
`heap_overflow` 0/2, `integer` 0/3, `uaf` 0/2, `off_by_one` 0/3.

### Open decisions (need the 2nd-model review + possibly user)

1. **`VulnType` schema vs. family remap.** `off_by_one` has no `VulnType`.
   - (a) Add `VulnType.OFF_BY_ONE` + `TYPE_CONFUSION`; wire `OffByOneDetector`/
     `TypeConfusionDetector`/`UAFDetector` into `static_detectors()` by adapting
     their return to `Vulnerability`. Faithful taxonomy; schema change + 3
     detector adapters.
   - (b) Accept `STACK_BUFFER_OVERFLOW` as satisfying an `off_by_one` truth (an
     off-by-one onto the saved RA *is* a stack BOF at the VulnType grain) and
     wire only `UAFDetector`. Smaller; blurs the family the corpus separates.
   - **Lean (a)** for the structural families the corpus names explicitly;
     flip-to-(b) evidence = if the review judges off_by_one not meaningfully
     distinct from stack_bof at the detector grain.
2. **Metric: any-match vs dominant.** PRIMARY (gate) = any-match ("did the right
   class appear"); SECONDARY (informational) = dominant/precision, because
   `FormatStringDetector` over-fires (precision, not coverage, is its problem).
3. **Static-binary detection** (`07_static_ret2syscall` → empty): accept as a
   known static-ELF limitation (document) or extend detectors to static symbols
   (larger). Lean: document, exclude from the family rate with a noted reason.

### Sub-components (files, change, failure mode) — to fill after review
- `supwngo/vulns/detector.py` — add `VulnType` members. Failure mode: a new
  member unhandled by a `match`/dict elsewhere.
- `supwngo/reporting/adapter.py` `static_detectors()` + adapters for
  `UAFDetector`/`OffByOneDetector`/`TypeConfusionDetector`. Failure mode: a
  detector that raises becomes a permanent `DetectorFailure` (the docstring's
  exact warning) — adapter must normalise, not just append.
- `benchmark/…` vuln-family truth (technique→vuln_family; robust, low-contest).
- `benchmark/score_vuln_ident.py` (new scorer) + `tests/` for it.

### Test plan (Phase 7) — written before execution
- Regression: full `pytest` manifest at base (per-test identity, not totals);
  compare after. Watch the known pre-existing env failures (memory
  `supwngo-known-pre-existing-gate-failures`) by signature, not name.
- New behavior: a uaf target and an off_by_one target now classify to the right
  family via `detect_all`; integer/heap targets detect their family.
- New gate (the vuln-ID scorer): prove RED — run it at base `1b117a2` and show
  the structural families fail; or mutate truth to a wrong family and show FAIL.

## B1 — METHOD-axis identification

**Closes:** G1 (truth coverage), G3. **Instrument:** passcard `pwn --json` →
`score_method_r0`/`_l`. **Baseline:** deferred to B1 Phase 6 (capture via the
passcard CLI harness at B1's base SHA — the in-process spike is NOT it).

### The one decision that defines B1
When the framework recommends a **different-but-valid** method than the corpus
label (it recommends `ROP_EXECVE`/`rop_syscall` and `RET2WIN` broadly), is that
a PASS or a MISS? Resolution: author `method_accept` as **every method that
genuinely solves that target** (what the passcard field means), reviewed
per-target. Then a residual MISS is a real suggester precision gap (e.g.
`ROP_EXECVE` recommended for a dynamic-NX `ret2libc` target with no syscall
gadget / no static `/bin/sh`), fixed by tuning `StrategySuggester` confidence/
priority — not by widening accept to hide it. Evidence to author accept: does
the recommended approach have the gadgets/strings it needs in that binary?

### Sub-components — to fill after review
- `benchmark/truth/…` or corpus yaml `method_accept` per corpus target.
- Possibly `supwngo/exploit/strategy.py` priority/confidence tuning IF a real
  precision gap survives honest accept-sets (own Phase-1 item + test).

## Risks / rollback
- Schema change (`VulnType`) ripples: grep every `VulnType.` switch before merge.
- Truth authoring is the error-prone core → it is the peer-review focus.
- Rollback: each sprint is its own branch off `1b117a2`; revert the branch.

## Peer review (Phase 5 gate) — PENDING
Send THIS plan to a second model (Codex daybreak-blue xhigh via /codex-interop):
judge the B2 schema-vs-remap decision, the any-match metric, the B1 accept-set
policy, and whether B2-before-B1 ordering is right. Record findings by class.
