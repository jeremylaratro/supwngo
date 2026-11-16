# Identification-accuracy gap analysis — 16NOV2026

**Effort:** raise supwngo *identification* (not exploitation) accuracy to ≥90%
per category, in two sprints the user sequenced:

- **Sprint A — payoff identification** (the directive-W "win function" axis).
- **Sprint B — technique-family identification**, both axes gated ≥90%:
  - **METHOD** axis: HOW it's exploited (ret2win, ret2libc, srop, shellcode,
    fmt_write, heap_metadata, …; 15 families).
  - **VULN** axis: WHAT defect is abused (stack_bof, heap_overflow, uaf,
    double_free, integer, format_string, off_by_one, logic; 8 families).

Methodology: dev-methodology full cycle. This document is the Phase-1 artifact.
Provenance labels: `measured` (ran it), `recorded` (cited prior artifact),
`inferred` (reasoned).

---

## Objective (Phase-1 gate)

Per-family identification accuracy **≥ 90%** on both axes, over the framework's
built benchmark corpora. Phase-8 re-measures against the baselines captured here.

---

## Sprint A — payoff identification: **NULL GAP (already 100%)** `measured`

Baseline sweeps (cache off → a real Ghidra pass per binary), scorer =
`payoff.rank_payoffs` top-candidate RVA == planted `payoff_rva`, plus required
(position,value) args for gated shapes.

| Class | n | Metric | Result |
|---|---|---|---|
| Clean positives (ELF+PE × exec/file/arg1/arg3 × PIE × stripped) | 56 | RVA (+args) | **56/56 = 100%** |
| Negatives (false-positive control) | 8 | COMPLETE ∧ 0 candidates | **8/8, 0 FP** |
| Gate-encoding falsifiers (disj/bool/relational/nonconst/arith/loop/sparse/…) | 27 | RVA + args_status + args | **27/27 = 100%** |
| `decoy_sink` (payoff among decoys) | 1 | correct sink | **1/1** |
| rename twins (symbols renamed) | 16 | payoff RVA | **16/16 = 100%** |
| strip twins (symbols stripped) | 16 | payoff RVA | **16/16 = 100%** |

- Evidence: `scratchpad/payoff_baseline.json`, `scratchpad/payoff_precision.json`.
- Per-category minimum is 100%; the ≥90% objective is met with full margin, on
  every category **including the adversarial precision classes** (falsifiers
  prove the identifier correctly *declines* to invent args on non-constant /
  relational / disjunctive gates — the false-precision failure the decoys exist
  to catch).
- **Conclusion:** Sprint A is a null gap. Per methodology, no sprint is
  manufactured for a saturated metric. Honest scope note: 100% is on the
  framework's *own* designed matrix (the falsifiers/decoys are the anti-overfit
  controls, so this is evidence against overfit, not a claim about arbitrary
  real-world binaries — that generalization question is Sprint B).
- Harness-bug erratum: an early precision scorer mis-scored the 32 twins
  (compared candidate `args_status` to a field twin truth files don't carry).
  Corrected scoring gives 59/59 RVA across all adversarial classes. The bug was
  in the scratchpad scorer, not the framework.

---

## Sprint B — technique-family identification

### What already exists `measured`

| Capability | Location | State |
|---|---|---|
| METHOD-axis ID scorer | `benchmark/passcard_score.py` `score_method_r0` / `score_method_l` | **exists** — maps `pwn --json` `recommended.approach` via `passcard_families.map_name` → PASS if family ∈ target `method_accept`; independent of solve (`score_off` is the separate solve column) |
| Family taxonomy | `benchmark/passcard_families.py` | **exists** — 15 method + 8 vuln families; `APPROACH_MAP`, `TEMPLATE_MAP`, `TECHNIQUE_MAP`, `map_name()` |
| Method seam | `supwngo pwn --json` → `recommended.approach` (ExploitApproach) | **works** — smoke test: `01_shellcode_stack` → `SHELLCODE` (→ method/shellcode) |
| Vuln seam | `CompositeDetector(binary)` + per-detector `add_detector` → `detect_all()` → `Vulnerability.vuln_type` (`VulnType`) | **works** (detectors must be registered; no auto-registry) |
| Built corpora | `benchmark/corpus*`, 26 dirs | **186 binaries** built (`fix 1b117a2`); only `corpus_libhijack` 4/7 (needs companion `libsupwngoext.so.1`) |

### Gaps (Phase-1 items)

- **G1 — METHOD truth coverage is sparse.** `method_accept` truth exists for
  only **9** curated `benchmark/truth/s0/*.yaml` targets (rop_syscall×2,
  ret2libc×2, srop×2, objptr_hijack, heap_metadata, ret2win, env_hijack)
  `measured`. `corpus.yaml`/`corpus_r2.yaml` carry a free-text `technique`
  (30 distinct values) instead; most specialized corpora carry only
  `slug`+`role`, with the family stated at the corpus-level header, not
  per-target. → Need a derived technique/corpus → method-family truth map to
  score the ~177 corpus binaries. Type: **blocked-on-labeling** (spike: build
  the map, Phase 4). `inferred` that the map is derivable from the existing
  `technique` names + corpus headers + `passcard_families`.
- **G2 — VULN-axis identification metric does not exist.** The passcard reports
  VULN only *informationally*, derived from the method recommendation, never
  from `detect_all()`; there is **no** detector-classification scorer and **no**
  `vuln_accept` truth `measured`. → Build a vuln-ID scorer (register all
  detectors, `detect_all()` → dominant `VulnType` → vuln-family → compare to
  truth) + label vuln-family truth. Type: **gap (missing capability)**.
- **G3 — no baseline captured** for either axis over the full corpus. Type:
  **target** (becomes the Phase-8 metric).
- **G4 (pre-existing, not caused here) — `corpus_libhijack` 3/7 unbuildable**
  without its companion `.so`; **env_hijack** family representation is reduced.
  Type: **blocked/externally reported** (spike: build the `.so`, or exclude &
  note).

### Phase-4 spike measurement (corpus/ + corpus_r2, 30 targets) `measured`

Harness `scratchpad/ident2axis_baseline.py`. Two harness facts were established
first (both load-bearing):

- **Loader matters.** `Binary(path)` yields a half-initialised object (no
  protections/symbols); the suggester then defaults to `SHELLCODE` and the
  detectors find nothing. The production path is `Binary.load(path)` (as
  `cli.py` uses). An early run on the bare constructor produced a spurious
  "6.7% / all-SHELLCODE" result — a harness bug, corrected before any number was
  trusted.
- **In-process method ≠ CLI method.** `suggest_strategies(Binary.load(...))`
  diverges from `pwn --json`: for `09_srop` the CLI recommends `SROP`, the
  in-process call recommends `ROP_EXECVE` (the CLI builds and passes a
  gadget_finder; the in-process call does not). **So the method axis must be
  measured through the real `pwn --json` CLI / the passcard harness, not an
  in-process shortcut.** The method numbers below are directional only.

| Axis | Instrument fidelity | Result (30) | Trust |
|---|---|---|---|
| VULN (any-match) | `reporting.adapter.detect_all` — **exact production report path** | **19/30 = 63%** | trustworthy baseline |
| METHOD-R0 | in-process suggester (diverges from CLI) | 11/30 = 37% | directional only |
| METHOD-L | in-process suggester (diverges from CLI) | 17/30 = 57% | directional only |

**VULN-axis per family (trustworthy):** `format_string` 5/5, `stack_bof` 14/15
(the one miss is `static_ret2syscall` — a `-static` binary the static detectors
return empty on), `heap_overflow` 0/2, `integer` 0/3, `uaf` 0/2, `off_by_one`
0/3. Gap structure, now concrete:

- **Structural exclusion (G2a):** `uaf` and `off_by_one` score 0 because
  `static_detectors()` deliberately omits `UAFDetector`/`OffByOneDetector`
  (their `detect()` breaks the adapter contract), **and** `VulnType` has no
  `OFF_BY_ONE`/type-confusion member to map to. No amount of input reaches these
  families through the production path.
- **Under-detection (G2b):** `integer` 0/3 and `heap_overflow` 0/2 — the
  detectors *are* in the set and run clean, but emit nothing on these targets.
- **Precision caveat:** `FormatStringDetector` fires on many non-fmt targets
  (e.g. `shellcode_stack` reports `format_string`). Any-match hides this; a
  dominant-vuln metric would expose low precision. Noted for the scorer design.

Revised **G2** reading: the vuln axis is not merely "no metric" — the production
detector path has a **structural coverage hole** (G2a) plus an **under-detection
gap** (G2b). Closing it is real product work (wire the excluded detectors to the
adapter contract; add the missing `VulnType` members), gated behind a plan +
user sign-off, not a measurement-only change.

### Out of scope (declared, repeat in every delegated prompt)

- The *exploitation / solve* success rate (the user deferred it explicitly).
- Tool-hardening / compliance-control findings; deliberate benchmark constants
  are features. A number that looks wrong is fixed in the corpus or the
  measurement, never by redesigning the tool.
- Payoff identification (Sprint A, closed null).
