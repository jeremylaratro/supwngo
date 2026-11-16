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

**FROZEN benefit baseline (`measured` 16NOV2026, base SHA `374836c`, product
unchanged).** Instrument: `benchmark/score_vuln_ident.py` over
`benchmark/vuln_ident_truth.yaml` (73 targets: 65 positive, 8 control), the exact
`detect_all` production path. Metric = per-family precision AND recall (R3). Raw:
`scratchpad/b2_benefit_baseline_99c29d8.json`. Command:
`python3 benchmark/score_vuln_ident.py --json <out>`.

| family | positives | recall | precision | gate |
|---|---|---|---|---|
| `stack_bof` | 32 | 18/32 = **56%** | 18/52 = **35%** | FAIL |
| `format_string` | 5 | 5/5 = 100% | 5/31 = **16%** | FAIL |
| `integer` | 3 | 0/3 = **0%** | n/a | FAIL |
| `heap_overflow` | 5 | 0/5 = **0%** | n/a | FAIL |
| `uaf` | 7 | 0/7 = **0%** | n/a | FAIL |
| `off_by_one` | 13 | 0/13 = **0%** | n/a | FAIL |

Overall verdict **RED** (scorer exit 2) — this is also the Phase-7c RED proof of
the new gate at base. The precision+recall metric exposes what the old "63%
any-match" hid: `format_string` fires on 31 targets but only 5 are right (16%
precision), `stack_bof` on 52 with 18 right (35%). **This is new, larger scope
than the approved detector-wiring** — see G2c/G2d. B2 is therefore re-scoped to
the structural + under-detection gap it was reviewed for; the existing-detector
precision recalibration is sequenced as a follow-on (B2b) rather than silently
absorbed.

### New Phase-1 findings surfaced by the frozen metric (16NOV2026)
- **G2c — production-detector precision collapse** `measured`. `FormatStringDetector`
  precision 16% (fires on 31/73, 5 correct); `StackBufferOverflow` precision 35%
  (52 firings, 18 correct). The any-match baseline hid both. Type: **gap (quality)**;
  **not** in the originally-approved B2 scope. Lane: follow-on sprint **B2b**
  (existing-detector calibration — a different seam from wiring the excluded two).
- **G2d — `stack_bof` recall 56%** `measured`. 14/32 stack_bof positives are not
  emitted at all (independent of the precision collapse). Lane: **B2b**.

### B2 (this sprint) scope — confirmed
Add `VulnType.OFF_BY_ONE` (+CVSS vector), refactor & negatively-calibrate
`UAFDetector` + `OffByOneDetector` onto the adapter contract, wire into
`static_detectors()`, and lift `integer`/`heap_overflow` under-detection (G2b).
Target: `uaf`, `off_by_one`, `integer`, `heap_overflow` each to ≥90% precision+recall.
B2 does **not** turn the overall gate GREEN (format_string/stack_bof remain B2b);
its Phase-8 benefit is those four families' deltas.

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

## Peer review round 1 (Codex daybreak-blue xhigh) — VERDICT: FIX-FIRST

Review saved at `docs/reviews/sprintB-plan-review-codex-16NOV2026.md`. All six
findings were **verified against the source** (not taken on the reviewer's word)
and **all six accepted** — none rejected. Resolutions by class; these **supersede**
the "Open decisions" leanings above.

**R1 [BLOCKER, D1 — detector/schema bundle].** Verified: `off_by_one.py` models
null-byte/one-byte causes across **heap and stack** (`OffByOneType.HEAP_METADATA`,
`STACK_CANARY`, …) → remap→`stack_bof` is **wrong**; decision (a), `VulnType.OFF_BY_ONE`,
stands. BUT `get_exploit_primitive` is `@abstractmethod` on the ABC and **neither
`UAFDetector` nor `OffByOneDetector` implements it** (grep=0); `UAFVuln(name=…,
severity="medium")` mismatches the `Vulnerability` contract (`vuln_type`/`VulnSeverity`);
and both fire on **mere PLT presence** of `malloc`/`free`/`read`/`memcpy` (uaf.py:103,
off_by_one.py:117). → **Revised:** adapting is a *real refactor with negative
calibration*, not "append to the set": implement the ABC method, fix construction,
and gate each detector on evidence beyond import-presence (else corpus-wide FPs).
**TypeConfusion is DEFERRED** (bare class in `uaf.py`, not the ABC; would emit for
every binary; and it is not even a vuln *family* — see R2).

**R2 [MAJOR, D1 — enum blast radius].** Verified: `passcard_families.py:157` maps
`type_confusion_tag → _v("logic")` — `TYPE_CONFUSION` is **not** a VULN family, so
do **not** add that member; type-confusion truth maps to `logic`. Verified:
`tests/test_reporting_adapter.py:333` pins `unmapped ==
{"integer_underflow","null_pointer_deref","unknown"}`, so adding `VulnType.OFF_BY_ONE`
**fails that test** unless it gets a CVSS vector in `CVSSCalculator.VULN_VECTORS`
(or the pinned set is updated as a recorded decision). → **Revised sub-component
list names every consumer:** `CVSSCalculator.VULN_VECTORS`, the two
`test_reporting_adapter` tests, `passcard_families.map_name`, `SARIFExporter`. Sweep
**string-key registries**, not only `VulnType.` switches.

**R3 [BLOCKER, D2 — metric].** Verified: any-match is **recall** and is gameable
exactly because R1's detectors fire on imports. → **Revised metric:** the ≥90% gate
is **per-family precision AND recall** (F-style), on **multi-label accepted truth**
(a binary may genuinely carry >1 defect). "Dominant" is defined **separately** and
only informationally — `detect_all` merely appends detector output in registration
order, so there is no intrinsic dominance to lean on. The captured **63% is a
recall baseline**, not the gate.

**R4 [MAJOR — denominator].** → **Revised:** freeze a **complete target manifest**
(core + specialized corpora) and the **exclusion/VOID policy** *before* measuring.
`07_static_ret2syscall` stays a **miss** unless a supported-domain change is
pre-registered and re-baselined. No post-hoc denominator shrinking.

**R5 [MAJOR, D3 — B1 accept-set circularity].** → **Revised:** authoring
`method_accept` from the method the CLI recommended is **label leakage** (gadget/
string presence is necessary, not sufficient — register/control constraints remain).
Author **independent, target-specific feasibility witnesses BEFORE** the scored CLI
run; later widening needs evidence + an audit trail.

**R6 [MINOR, D4 — ordering].** B2-before-B1 kept. → **Revised:** recapture the
**complete recall+precision baseline at B2's real branch base** before the first
edit (not the recall-only 63% spike).

## B2 frozen target manifest + scope/VOID policy (R4 deliverable — pre-registered 16NOV2026)

Discharges R4: the complete denominator and exclusion policy are fixed **before**
measurement, so the gate cannot be inflated by post-hoc shrinking. Inventory
`measured` 16NOV2026 (`benchmark/`, 185 built binaries; 123 manifested across 16
corpora). **Negative precision controls** are encoded as `role: control` (and a
`_NN_neg_` slug), truth = ∅: a detector emitting ANY in-scope family on one is a
false positive. The frozen truth carries 8 such controls. Precision is also
**cross-corpus**: a detector emitting family F on a truth-G positive is an F false
positive. Truth artifact: `benchmark/vuln_ident_truth.yaml` (generator
`benchmark/gen_vuln_ident_truth.py`); 73 in-scope targets (65 positive, 8 control).

**IN-SCOPE families (the VULN-identification gate; a detector targets each):**

| Family | Detector | Corpora (truth source) |
|---|---|---|
| `stack_bof` | StackBufferOverflow (prod) | core stack targets, `corpus_scanf` (7), `corpus_variants` (6), `corpus_vectors` (8) |
| `format_string` | FormatString (prod) | core fmtstr targets |
| `integer` | IntegerOverflow (prod) | core integer targets |
| `heap_overflow` | HeapVulnerability (prod) | core heap targets, `corpus_bon` (4) |
| `uaf` | UAFDetector (**B2 adds**) | `corpus_uafread` (6), core `heap_uaf*` targets |
| `off_by_one` | OffByOneDetector (**B2 adds**) | `corpus_offbynul` (6), `corpus_offbyone` (6), core `off_by_one*` targets |

`double_free` is a 7th family with **no dedicated detector**; HeapVulnerability may
emit it. It is **IN-SCOPE only if a positive target exists** in the frozen truth;
otherwise recorded as *no-positives → not gated* (not a pass, not a fail).

**OUT-OF-SCOPE / VOID (declared now; documented, NOT in the gate denominator):**
- **No-detector-by-design families:** `corpus_typeconf` (→ `logic`, TypeConfusion
  deferred per R1), `corpus_toctou` (→ `race_condition`), `corpus_traversal`
  (→ `path_traversal`), `corpus_uninit` (no `VulnType`), `corpus_fsop` (3, an
  `_IO_FILE` arbitrary-read primitive — two qword writes, no overflow/UAF — so a
  method/`logic` shape, not a `heap_overflow` the detector set targets),
  `corpus_objptr` (12) / `corpus_envpath` (5) / `corpus_libhijack` (6, 3 built)
  (method/`logic`, not a memory-safety defect the detector set targets).
  Rationale: the gap analysis
  scopes the detector set to memory-safety defect classes; these are METHOD/logic
  families, scored on the METHOD axis (B1), never the VULN detector axis.
- **Unmanifested build dirs (62 bins, no per-target truth):** `corpus_allocsize`,
  `corpus_eintr`, `corpus_finiarray`, `corpus_g23`, `corpus_heap_variants`,
  `corpus_inject`, `corpus_objptr_libc`, `corpus_prng`, `corpus_srop`,
  `corpus_symlink`, `corpus_r2_reference` (0 built). **VOID = no truth manifest**;
  a corpus is promoted into the gate only by authoring its per-target truth first.
- **`07_static_ret2syscall`** stays a **miss** inside `stack_bof` (R4): a `-static`
  ELF the detectors return empty on; not excluded.
- **`corpus_libhijack`** is OUT regardless of the 3/6 `.so` build gap (G4).

**Exclusion changes are a pre-registered, re-baselined act** — never a measurement-time
edit. Promoting a VOID corpus or an OUT family requires authoring its truth and
recapturing the baseline. This policy is itself an input to the round-2 review.

## Status after round 1
Plan is **FIX-FIRST → revised, not yet re-reviewed**. The revisions expand B2
beyond the original scope (real detector refactor + FP calibration; a precision+recall
metric on multi-label truth; a frozen full-corpus manifest). A round-2 review (verify
these fixes only) is owed **after** the user confirms the expanded B2 scope and the
precision-metric definition — both are consequential product decisions gated before
Phase 6.
