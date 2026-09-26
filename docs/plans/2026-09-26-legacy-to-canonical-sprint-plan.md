# Legacy → Canonical Port: Sprint Plan (26SEP2026)

Phase 5 of the 8-phase cycle. Companion to
`2026-09-26-legacy-to-canonical-gap-analysis.md` (Phases 1–3).

Closes: **G-1**, **B-1** (Sprint 1), **G-2** (Sprint 2). Defers **G-3** to a
spike. Target: **T-1** — canonical solves ≥3/7 HTB targets without legacy
fallback.

---

## Pre-registered benefit metrics (Phase 8 contract)

Registered **before** the after-measurement, with baselines measured on `main`
at `311ff25` — i.e. pre-change for the whole effort. Sprint 1 is already
committed on a branch, so `main` is still the honest pre-change tree.

### M-1 (primary, regression + improvement) — R1 corpus SUCCESS count

- **Harness**: `benchmark/run_bench.py --jobs 4` (15 targets × 5 reps).
  Chosen because it mints a fresh per-run secret flag per target, runs negative
  controls, and determines SUCCESS by re-executing the generated script and
  grepping for that run's secret — it never trusts supwngo's self-report.
- **Command**: `python3 benchmark/run_bench.py --jobs 4`
- **Inputs**: `benchmark/corpus` + `benchmark/corpus.yaml` (R1, shared).
- **Reps**: 5 (the harness default) — spawn timing makes this metric noisy, so
  report per-rep spread, not a single number.
- **Baseline** (`measured`, `main` @ `311ff25`, run `20260926-164613Z`,
  finalized 2026-09-26T17:00:27Z): **13/13 SUCCESS (100.0%)**, 0 PARTIAL,
  0 FAILED. All 13 fully reliable (5/5 reps), 0 intermittent. 2 targets VOID and
  excluded from scoring — both **corpus faults, not supwngo faults**:
  `11_heap_uaf_leak` (`corpus_missing_liveness_gate`) and `13_off_by_one`
  (`corpus_trivially_solvable`). Per-target (all SUCCESS unless noted):

  | target | class | target | class |
  |---|---|---|---|
  | 01_shellcode_stack | SUCCESS | 09_srop | SUCCESS |
  | 02_ret2plt_system | SUCCESS | 10_int_overflow | SUCCESS |
  | 03_pie_leak_ret2libc | SUCCESS | 11_heap_uaf_leak | **VOID** |
  | 04_canary_leak_bypass | SUCCESS | 12_heap_tcache_poison | SUCCESS |
  | 05_fmtstr_arbread | SUCCESS | 13_off_by_one | **VOID** |
  | 06_fmtstr_arbwrite | SUCCESS | 14_negative_index | SUCCESS |
  | 07_ret2libc_leak | SUCCESS | 15_win_function | SUCCESS |
  | 08_ret2dlresolve | SUCCESS | | |

- **Direction**: SUCCESS count must **not decrease**, and the comparison is
  **per-target, not aggregate**.
- **Note on saturation (answers peer finding 8/M-1).** The baseline is 100%,
  so M-1 cannot measure *improvement* on this corpus — only regression. That
  also disposes of the peer's objection that an aggregate gain elsewhere could
  mask a per-target regression: at 13/13 there is **no headroom for a
  compensating gain**, so any target that drops is unambiguously visible. The
  per-target table above is the comparison basis regardless.
- **Do NOT "fix" the 2 VOIDs.** They are corpus discrimination faults detected
  by the harness's own negative controls. Making them scoreable is a corpus
  change, out of scope here, and must never be done to raise a score.

### M-2 (secondary, the actual target) — HTB canonical solve count

- **Harness**: `supwngo solve <target> --strategy <technique>` per target,
  canonical engine only, legacy fallback not counted.
- **Inputs**: the 7 HTB targets under `tests/htb-targets/`.
- **Baseline**: canonical 1/7 (`rocket_blaster_xxx` via `ret2libc_leak`),
  `recorded` from this session's forced-strategy matrix.
- **Direction**: must increase. T-1 wants ≥3/7.

### M-3 (cost guard) — worst-case `variable_overwrite` spawn count

- **Harness**: candidate-count probe over each target binary (the measurement
  already run for B-1 in the gap analysis).
- **Baseline**: 126 spawns (9 values × 14 buffer sizes), all targets, pre-change.
- **Direction**: must stay within **1.25x** of 126 (≤158) on every measured
  target. This is the bound B-1 exists to enforce.

---

## Sprint 1 (P0) — Candidate recovery for `variable_overwrite`

Closes **G-1** (cannot recover a non-folklore gate constant) and **B-1** (the
cost bound on G-1's own fix).

### Candidate methods

1. **Call the existing `comparison_immediates()` recovery helper, capped.**
   Chosen. The helper already existed and was already used by
   `IntTruncationBypassExecutor`; it reads `cmp`/`test` immediates from the
   target's own instruction stream and orders them most-plausible-first
   (ascending bit-length). Capping the recovered slice bounds the added cost.
2. **Move `variable_overwrite` out of `LAST_TECHNIQUES`.** Rejected. It would
   let the technique run before the wall-clock budget is burned on `sick_rop`,
   but it slows down *every* other target, where the technique wastes its whole
   sweep. Better candidate selection beats reordering.
3. **Widen the hardcoded `MAGIC_VALUES` list.** Rejected. Unbounded in
   principle (any 32-bit constant is a legal gate), and it cannot ever solve
   fixture-B-shaped targets. Treats the symptom.

**What would flip the choice**: if `comparison_immediates()` turned out to miss
the constant on real targets (e.g. constants materialized via `mov`+`cmp reg`
rather than a `cmp $imm`), method 1 degrades to the fallback list and a
disassembly-level rewrite would be needed instead.

### Sub-components

| # | File | Change | Contract affected | Failure mode introduced |
|---|---|---|---|---|
| 1a | `stack_techniques.py` | Call `comparison_immediates(binary, limit=RECOVERED_LIMIT)`; fall back to `FALLBACK_MAGIC_VALUES` when `context.binary is None` | none (executor-internal) | A target with no binary loaded silently gets folklore-only candidates |
| 1b | `stack_techniques.py` | Swap loop order to magic-outer / buffer-inner | none | Reported offset is no longer the *smallest* winning buffer size, only *a* winning one |
| 1c | `stack_techniques.py` | `RECOVERED_LIMIT = 6` | none | A target whose constant ranks 7th+ by plausibility is missed |
| 1d | `stack_techniques.py` | Provenance: `recovered_immediate` when the winning value is absent from the fallback set, else `literal_magic_list` | `AttemptRecord.candidate_provenance` → `report.json` | A value in *both* sets is attributed to the fallback list (deliberate: conservative) |
| 1e | `tests/test_i3_candidate_provenance.py` | Fixture B flips from "provably unreachable" to "reachable via recovered immediate"; load a real `Binary` into the context | test contract | — |

**On 1d**: attributing an in-both value to `literal_magic_list` is the
conservative direction. The instrument exists to prove a value *could only* have
come from reading the binary; a folklore value that also appears in a `cmp` is
ambiguous, so it must not be credited as recovered.

### Test plan (written before execution)

- **Regression surface**: `tests/test_i3_candidate_provenance.py` (16 tests) and
  `tests/test_i5_failure_reason.py` (27 tests) both import `MAGIC_VALUES` and
  assert on this executor. Full suite for wider regressions.
- **New behavior**: fixture B (gate `0x12345678`, absent from the folklore list)
  must now reach SUCCESS with `candidate_provenance.source ==
  "recovered_immediate"` and `value == 0x12345678`.
- **Gate proven able to go RED**: the provenance gate's existing red-proofs
  (`test_gate_reds_on_missing_provenance`, `test_gate_reds_on_mismatched_expected_source`)
  must still fail when provenance is deleted or the two fixtures' expected
  sources are swapped — i.e. the gate distinguishes the two sources rather than
  accepting either.
- **Cost bound (M-3)**: candidate-count probe on all measured targets ≤158 spawns.

### Rollback

`git revert ae0cd73` (Sprint 1) — self-contained in one executor plus its tests.

---

## Sprint 2 (P0) — Menu-aware delivery for ROP executors

Closes **G-2**.

### Candidate methods

1. **Inject a `navigate_to_vuln()` helper into the generated script.** Chosen.
   Keeps the artifact readable, is reusable across the two ret2libc stages
   (both must re-enter the menu), and matches the `menu_cmd()` function-shaped
   precedent already in `heap_techniques.py`. Sourced from the Phase-4 research
   pass (VRv5 AEG specialist + pwntools/Zeratool survey).
2. **Emit the recv/send pair inline before every payload send.** Rejected:
   duplicates the pattern at each send site and makes a two-stage script
   noticeably harder to read, for no functional gain.
3. **Make executors pwntools-native and drop script generation.** Rejected:
   the generated script *is* the verified artifact and the thing the user
   receives; verifying something other than what is handed over is the weaker
   guarantee.

**What would flip the choice**: if targets commonly needed *nested* menu
navigation, a single `navigate_to_vuln()` would be insufficient and the
`menu_navigation_sequence` (list of prompt/choice pairs) variant would win.
Phase-4 research put single-level menus at the large majority, so the sequence
form is deliberately deferred.

### Sub-components

| # | File | Change | Contract affected | Failure mode introduced |
|---|---|---|---|---|
| 2a | `core/context.py` | Add `profile_menu_roles: Dict[str, int]` | `ExploitContext` (additive, defaulted) | none |
| 2b | `profile_stage.py` | On menu detection, call `discover_menu()` and store roles | runs one extra subprocess during profiling | Profiling gets slower by one target spawn; wrapped in try/except |
| 2c | `script_builder.py` | `menu_nav_globals()` emits the `navigate_to_vuln()` definition | generated-script shape | — |
| 2d | `script_builder.py` | `resolve_vuln_menu_option()` picks the option reaching the vulnerable read | none | **Heuristic**: prefers `edit`→`show`→`create`. A target whose overflow sits behind a role not in that order gets the wrong option and fails as before |
| 2e | `rop_techniques.py` | `Ret2LibcLeakExecutor`/`Ret2PltSystemExecutor` prepend `navigate_to_vuln(io)` before each send when a menu was found | generated-script shape | A *false-positive* menu detection on a non-menu target would inject a spurious option-send and break a currently-passing target |

**2e is the regression risk of this sprint** and is exactly what M-1 must catch:
`profile_has_menu` is set by a loose substring test (`'1.'`, `'2.'`, `'choice'`,
`'menu'`, `'option'` — `profile_stage.py:210`), so a non-menu target printing
`"1."` in its banner could be misclassified. Menu navigation is only injected
when `discover_menu()` *also* returns at least one role, which narrows it, but
does not eliminate it.

### Test plan (written before execution)

- **Regression surface**: M-1 (R1 corpus, 5 reps). Two R1 targets solve via
  ret2plt/ret2libc (`02_ret2plt_system`, `03_pie_leak_ret2libc`) and are
  directly on 2e's blast radius. Plus the full unit suite.
- **New behavior**: a menu-driven target where the pre-change script fails and
  the post-change script succeeds. `ancient_interface` is the intended case.
- **Gate proven able to go RED**: `resolve_vuln_menu_option()` must return the
  *role-appropriate* option, not merely "a number" — assert it picks `edit` over
  `exit` given both, and returns `None` for an empty role map. A test that only
  asserts "returned something" would pass a stub that always returns `1`.
- **Negative control for 2e**: assert `navigate_to_vuln` is **absent** from a
  generated script when no menu was detected — and, per the
  never-let-an-absence-assertion-stand-alone rule, assert in the same test that
  it is **present** when a menu *was* detected. Otherwise a rename of the helper
  makes the absence check vacuously pass.

### Rollback

Revert `e39994a`'s `rop_techniques.py` + `script_builder.py` + `profile_stage.py`
hunks. `profile_menu_roles` on the context is additive and inert once unused.

---

## Sprint 3 (P2, spike first) — SROP verification I/O

**Not planned as an implementation sprint.** G-3's root cause is undiagnosed;
the earlier plan doc's "add `recv()` between stages" was a guess, and planning a
fix around a guess is what the spike exists to prevent.

**Spike exit criteria** (what must be true before a Sprint 3 plan is written):
a reproduction that shows *where* the three-stage script blocks — which stage,
and whether it is the script's own I/O or `verify_script()`'s stdin piping.
Until then G-3 stays in `later`.

---

## Peer review

Plan sent to a second, independent model at the same tier per the model-tiering
contract (cyber work → Daybreak Blue, `xhigh`). Out-of-scope classes
(tool-hardening, compliance controls, "deliberate constants are a weakness")
restated in the prompt. Findings answered **by class with a stated sweep match
identity**, capped at 3 rounds.
