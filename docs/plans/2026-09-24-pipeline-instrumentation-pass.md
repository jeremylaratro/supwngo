# Instrumentation pass — make the pipeline observable enough to plan against

**Date:** 24 Sep 2026
**Branch:** `bench/round2-cold-and-dev-20260924`
**Revision:** 3 — **APPROVED** at `3005733`, subject to M8-M12 at the stated gates, which
this revision records. Round 1 (`31196d2`) was NOT-APPROVED on B1/B2/B3 + M1-M7.
Review file: `docs/reviews/2026-09-24-instrumentation-pass-review.md`.
**Supersedes as the active document:** `2026-09-24-r2-step3-primitive-acquisition.md`
(rev 1 and rev 2 both NOT-APPROVED; no rev 3 of *that* document will be written)
**Scope:** instrumentation only. **No capability change.**
**Status:** awaiting re-review. `supwngo/` untouched since `b3a40b4`.

---

## 0. Disposition of the review

| finding | disposition |
|---|---|
| **B1** I4 infeasible — 7 of 9 sites have no `AttemptRecord`; one precedes any record | **Accepted.** I4 re-scoped onto a context-level collector; per-window recording; all 7 helpers named (§4 I4, §4.1) |
| **B2** §1 row 2 has no instrument | **Accepted.** `benchmark/run_bench.py` brought into scope for an additive probe duration; §9 narrowed to say so (§4 I2b, §9) |
| **B3** §6 step 2 unexecutable; hardens a parser | **Accepted.** Header parsing deleted; gate reads `parsed.technique`; per-target map now in §2.1; VOID slugs excluded by name (§2.1, §6) |
| **M1** `variable_overwrite` in 46 scripts, not 1 | **Accepted and owned** (§2.2) |
| **M2** multiset conceals `05 → canary_leak_ret2win` | **Accepted.** Per-target map replaces the multiset; §8's phase-1a argument corrected (§2.1, §8) |
| **M3** I1's predicate not idempotent | **Accepted, and it selects the design** (§4 I1) |
| **M4** I3 has no gate; opt-in gate passes vacuously | **Accepted.** Required-provenance list, gate fails on missing (§4 I3, §5) |
| **M5** I2 excludes the prologue; overstates absence | **Accepted** (§4 I2, and the new §4.0 inventory rule) |
| **M6** `to_dict()` unmentioned | **Accepted.** Named, plus artifact-level assertions (§4.1, §5) |
| **M7** the "figure moves" rule is unenforceable for R2 | **Accepted.** Kept for R1, dropped for R2 (§9) |
| **m1, m1b** proofs pass vacuously / mutation catches absence only | **Accepted, and generalised to all five** (§5) |
| **m2** "and `continue`s" understates the case | **Accepted** — it strengthens B1's point (§4 I4) |
| **m3, m5, m6, m7** | **Accepted** (§3, §4, §7) |
| **m4** `handoff.py:292` precedence | **Accepted and pre-declared** (§4 I5) |
| **m8** script-audit hazard already closed | **Accepted and claimed** (§4.3) |
| §9 R5 block, §7 reasoning | Concurred by the reviewer; §7 now carries the coordinator's decision (§7) |

**Round 2 — APPROVED at `3005733`, subject to five MAJORs at the gates the reviewer set.**

| finding | disposition |
|---|---|
| **M8** I1's risk stated in the wrong direction; inertness is not about purity | **Accepted.** Risk restated bidirectionally; correct invariant adopted; the five executors needing a **new guard** enumerated (§4 I1). Gate: before step 5. |
| **M9** §9's narrowing is a denylist omitting two cheat-detection generators | **Accepted.** Inverted to an allowlist (§9.1). Gate: before any step. |
| **M10** I3's required-provenance gate cannot be proven red on any available data | **Accepted — the defect is mine.** Two fixtures moved onto the I3 gate; missing-provenance failure conditioned on an attempt having occurred (§4 I3, §7). Gate: before §7's R5 precondition counts as met. |
| **M11** one `duration_sec` cannot settle row 2 — `elapsed_sec` spans two pipeline invocations | **Accepted.** Second field on `autopwn_script_generation` (§4 I2b). Gate: before step 2. |
| **M12** the all-runs search rule was owned by prose | **Accepted.** Codified as a rule (§9.2). Gate: before any step. |
| **m9** 4 of 9 sites have no `context` either | **Accepted — carrier changed, not chosen again.** I4 now instruments the `deliver_parts` chokepoint; full 9-site enumeration recorded (§4 I4). |
| **m10** "40 windows" is wrong; it is 8 | **Accepted** (§4 I4). |
| Reviewer **withdrew** its `objdump` finding; `attempt():76` correction in my favour | **Banked** (§4.3, §4 I1). |

---

## 1. Why the method changed

Two rejections in the same family: **both predecessor plans asserted properties of the code
that a reviewer falsified by reading it.** The common cause is that **the pipeline is not
observable enough to plan against**, so planning against it produces claims the code
contradicts.

Every unsettleable finding across those reviews resolves to a missing instrument:

| # | finding that could not be settled | instrument |
|---|---|---|
| 1 | "discovery past 30 s" as a Fork B threshold | I2 — per-attempt duration + prologue timing |
| 2 | per-target pipeline time vs harness overhead | I2b — probe duration in the harness |
| 3 | new primitive vs retained legacy fallback | I3 — candidate provenance |
| 4 | why the nine stub targets skipped a technique | I1 — decision-time skip reasons |
| 5 | whether a stub is a *deterministic* probe timeout | I4 — per-window timeout capture |
| 6 | why `variable_overwrite` failed on all 11 R2 failures | I5 — `failure_reason` at the swallowing sites |

Row 2 previously named no instrument. Rather than withdraw it I have brought the harness
change into scope as **I2b** and narrowed §9 accordingly (§9), because the split between
pipeline cost and harness overhead is exactly what a future timeout decision turns on, and
the change is one additive field.

---

## 2. Verification: are the published figures contaminated by the magic sweep?

**Both halves, and the answer is structural rather than textual.**

**Half 1 — retroactively clean, confirmed independently.** No credited target in either
published run has `autopwn_json_probe.parsed.technique == "variable_overwrite"`: 0 of 17.
**The R2 cold 4/15 and the R1 13/13 stand and need no annotation.**

**Half 2 — prospectively exposed.** `MAGIC_VALUES` (`stack_techniques.py:59-62`) is 9
constants; `VariableOverwriteExecutor.attempt()` (`:73-96`) sweeps 14 buffer sizes × 9
magics = **126 unconditional `verify_payload` calls** (the sweep itself is `:78-93`) with no
recovery step and no `comparison_immediates()` call. Inertness on R1/R2 does not protect a
future round: different binaries, different constants, single-use. I did not investigate
provenance of the list, per instruction; the defect is structural regardless.

### 2.1 The per-target map (replaces the multiset — M2, B3)

Derived from `autopwn_json_probe.parsed.technique`. **This table, not a multiset, is what
the R1 gate asserts.**

| slug | intended | winning technique |
|---|---|---|
| `01_shellcode_stack` | `stack_shellcode` | `stack_shellcode` |
| `02_ret2plt_system` | `ret2plt_system` | `ret2plt` |
| `03_pie_leak_ret2libc` | `pie_leak_ret2libc` | `ret2libc_leak` |
| `04_canary_leak_bypass` | `canary_leak_bypass` | `canary_leak_ret2win` |
| `05_fmtstr_arbread` | `fmtstr_arbread` | **`canary_leak_ret2win`** |
| `06_fmtstr_arbwrite` | `fmtstr_arbwrite` | `fmtstr_write_gate` |
| `07_ret2libc_leak` | `ret2libc_leak` | `ret2libc_leak` |
| `08_ret2dlresolve` | `ret2dlresolve` | `ret2dlresolve` |
| `09_srop` | `srop` | `srop` |
| `10_int_overflow` | `integer_overflow` | `int_truncation_bypass` |
| `12_heap_tcache_poison` | `heap_tcache_poison` | `tcache_poison_got` |
| `14_negative_index` | `negative_index_oob_write` | `negative_index_write` |
| `15_win_function` | `ret2win_baseline` | `ret2win` |

R2 credited (4): `07 → srop`, `10 → ret2libc_leak`, `13 → ret2win`, `15 → ret2libc_leak`.

Two gate requirements that follow directly:

1. **Exclude the VOID slugs by name.** `11_heap_uaf_leak` (`corpus_missing_liveness_gate`)
   and `13_off_by_one` (`corpus_trivially_solvable`) are VOID, but `13_off_by_one` still
   reports `technique == "ret2win"`. A "every slug with a technique" filter yields **14**,
   not 13. The gate excludes the two by name and asserts the count is 13.
2. **`05_fmtstr_arbread → canary_leak_ret2win` is pinned explicitly**, so the off-intent
   credit is visible in the gate rather than buried. This materially changes §8's
   phase-1a argument and is carried there.

### 2.2 Two method failures in this document, owned

**M1 — I searched R1 and not R2.** I wrote "`variable_overwrite` appears in exactly one
generated script across both runs". The real count is **46**: 1 in R1, 45 in R2 (9 stub
targets × 5 reps). My sentence described both runs; my search covered one. The conclusion
survived only because a stronger route existed — the structured field — and not because the
search was sound.

**B3/§2.1 — my §6.1 map defect had the same shape.** Generated scripts use two header
formats (`(technique: X)` and `Technique: X`); my text extraction matched one and silently
dropped two rows. My proposed fix was to teach the parser the second format. That is wrong:
a tolerant parser fails quietly on format three. The reviewer rebuilt both complete maps
from `parsed.technique` in a single pass.

**The common lesson, which is now a rule below: both failures were ad-hoc text searches
over generated artifacts for facts that exist as structured fields, and both times the
field was right.** This is the third parser gap in this project to produce a wrong
conclusion, after the hex-text-only leak scanner and the desynchronised positional probe.

---

## 3. The inversion this pass exists to stop repeating

Two rounds of planning argued about a capability to **add**. The actual defect is an
executor that does not use a capability the repo already has: `comparison_immediates()` is
defined at `input_shape_techniques.py:68` and called from **exactly one** site, `:240`,
inside its own module. `stack_techniques.py` never calls it and brute-forces a folklore
list instead.

Two corrections to how I stated this (m5, m7):

- **`find_return_offset()` is not in use by that executor.** `stack_techniques.py:76`
  hardcodes its own 14-element buffer-size list. My §7 cited `find_return_offset()` as
  though the legitimate half were already wired up; it is not.
- **`VariableOverwriteExecutor` is the only one of 17 executors with no `is_applicable`**
  (it falls through to the `contracts.py:181` default). *That* is why the 126 calls are
  unconditional, and it makes "give it a predicate" a third option in §7 that dominates
  "disable it".

---

## 4. The instruments

### 4.0 Binding rule: inventory before proposing

Three times in this round a plan proposed building something that partly or wholly existed
(`comparison_immediates()` twice, the `%N$p` sweep for target `05`, timing). So **every
instrument below states what already exists and why it is insufficient.** Where the honest
answer is "consume this rather than build it", that is said, and the pass gets smaller.

### I1 — decision-time skip reasons

**Inventory.** A specific-skip-reason mechanism **already exists and is already used.**
**21** sites across the executor modules set `AttemptOutcome.SKIPPED` *inside*
`attempt()` together with a specific `failure_reason` — e.g. `rop_techniques.py:216`
`"no '/bin/sh' string in the binary image"` and `:226` `"no 'pop rdi; ret' gadget to load
system()'s argument"`. Those are the reasons that already appear in generated scripts. The
generic `"not applicable to this target"` comes from exactly one place: the orchestrator's
`applicable == False` branch (`orchestrator.py:203-213`), which also swallows an
`is_applicable` **exception** into the same string (`:205-207`).

**Why that is insufficient:** 16 of 17 executors define `is_applicable`, so their gating
decisions bypass the good idiom entirely, and a raise is indistinguishable from a
considered non-match.

**Therefore I1 is a migration, not a new mechanism.** No new hook, no signature change, no
optional out-parameter. Per executor, move the decision-bearing part of the predicate into
`attempt()` and use the existing SKIPPED + specific-`failure_reason` idiom. Separately, the
orchestrator's exception branch records the exception text instead of the generic string.

**This is what resolves M3.** `LeakedStackShellcodeExecutor.is_applicable`
(`shellcode_techniques.py:49-62`) performs process I/O with a 1.5 s timeout
(`_probe_stack_leak`, `:64-66`), against the base-class contract at `contracts.py:178-180`
("Executors should not do network/process I/O here"). One precision the review did not
draw: the probe is on a **fallback** path — `:61` short-circuits with `return True` when
`context.leaks.get("stack")` is already populated, so the spawn happens only when the
profiling stage missed the leak's phrasing. That makes the predicate's cost *and* its
answer depend on upstream state, which strengthens rather than weakens the point. A
companion reason hook would have re-run that probe and could return a verdict
contradicting the decision it explains. Migrating the probe into
`attempt()` makes the probe run **once**, and the reason is produced by the same execution
as the verdict — never recomputed. The coordinator's constraint and the fix are the same
change.

**Declared behaviour delta, corrected (M8).** After migration the orchestrator calls
`attempt()` where it previously skipped. My previous statement of the risk was wrong in
direction and wrong in its criterion:

- **The risk is bidirectional, not "can only lower a score".** An incomplete migration can
  *credit* a technique that was previously skipped, or change which technique wins, as well
  as turn one off.
- **Inertness has nothing to do with predicate purity.** The correct invariant is: a
  migration is inert **iff `attempt()` already reproduces the full predicate.** 15 of 16
  predicates are pure reads, so my purity claim was true and irrelevant.

`DirectShellcodeExecutor` is the counter-example that kills the old rule: its predicate
(`stack_techniques.py:155-156`) is the purest in the tree, yet `attempt()` (`:158-183`)
spawns the target and calls `verify_shell` with **no NX check**, and can set SUCCESS at
`:179`. The purest predicate has the *least* inert migration.

**Which migrations are pure deletions and which need a new guard:**

| executor | `attempt()` reproduces predicate? | migration |
|---|---|---|
| `Ret2WinExecutor` (`stack:111`) | yes, exactly (`:110-112`) | pure deletion |
| the other 11 with SKIPPED guards | yes | pure deletion |
| **`IntTruncationBypassExecutor`** (`input_shape:136-147`) | **no guard at all** (`:235-256`) — deliberately excludes menu-driven heap targets; **can SUCCEED where previously skipped** | **must add guard** |
| **`NegativeIndexWriteExecutor`** (`input_shape:227-233`) | no guard | **must add guard** |
| **`DirectShellcodeExecutor`** (`stack:155-156`) | no guard, can set SUCCESS | **must add guard** |
| **`FormatStringExecutor`** (`stack:198-199`) | no guard (PARTIAL-only, lower impact) | **must add guard** |
| **`LeakedStackShellcodeExecutor`** | re-checks the leak at `:76` but **not** the `nx_off or profile_is_shellcode_runner` half (`:53-55`) | **partial guard** |

So for these five, migration means **adding** guard code, not moving it — a larger edit than
"a migration into an existing idiom" conveys. Any executor whose `attempt()` does not
reproduce its predicate is a **score-change risk**: convert it last, individually, with the
R1 gate run either side.

Conversion order: pure deletions first, cheapest predicate first
(`ScanfCanaryBypassExecutor`, `heap_and_bypass.py:50-53`, reads `context.protections.canary`
and `binary.plt` only); then the five above individually;
`LeakedStackShellcodeExecutor` **last**.

**A correction in my favour, banked:** `attempt():76` already re-probes the stack leak, so
today's fallback path spawns the target **twice**. The I1 migration is a *deletion* that
removes a spawn, not an addition.

### I2 — per-attempt duration, and the profiling prologue

**Inventory — what exists.** `report.json` already carries per-target `elapsed_sec` and
`elapsed_sec_total`, and per-rep `elapsed_sec` in `attempts[]` (R2 `01` reads
`[139.9, 137.1, 136.9, 136.6, 135.9]`, reproducible to ~1 %). `VerificationReceipt` already
carries `verified_at` (`contracts.py:134`). **A target-level 30 s threshold is measurable
today.** My "no timing field" row overstated absence; `AttemptRecord` having no timing field
is literally true but does not make discovery time unmeasurable.

**What is missing:** per-*technique* attribution. That is what I2 adds.

**Scope correction (M5):** wall-clock around `attempt()` alone cannot yield a
from-run-start figure, because `orchestrator.py:186-188` runs `run_static_analysis`,
`run_dynamic_profile` and `acquire_leaks` before the first `attempt()`. I2 therefore also
times those three stages — three more wall-clock pairs in the same function, no extra risk.

### I2b — probe duration in the harness (settles row 2, was B2)

**Inventory.** `autopwn_json_probe` carries `returncode`, `wall_timed_out` and `parsed`, and
no duration. The neighbouring `verification` and `negative_control` objects already carry
`timed_out`, so a duration field matches the existing shape.

**Two additive `duration_sec` fields, not one (M11).** `elapsed = time.time() - t0` at
`run_bench.py:949` spans `negative_control()` at `:913` through `attribution_witness` at
`:937`, and **the pipeline runs twice inside that span**: `run_supwngo(... ["--json"])` at
`:916` (the probe) and `run_supwngo(... ["-o", script_path])` at `:922` (script generation).
Subtracting only the probe duration would attribute a whole second pipeline invocation to
"harness overhead" — on R1 `01`, roughly a full pipeline run inside a 35.8 s budget. So one
field yields probe-versus-everything-else, not the split row 2 names.

`autopwn_script_generation` at `:969-972` has the identical wrapper shape, so `duration_sec`
goes on **both** wrappers. Row 2 is then settleable; with one field it would have stayed
unsettled, which is B2's failure shape at narrower scope.

Verified out of all four forbidden categories: `classify()` is called at `:950` with
`supwngo_json = parse_json_result(out1)` (`:917`) — the *parsed* payload. Both wrapper
objects are assembled separately at `:963-972` for reporting only and never reach
`classify`. Gate: R1 still reports 13/13 with the §2.1 map unchanged.

### I3 — candidate provenance (the R5 guard)

**Inventory.** A *prose* form exists in one executor: `input_shape_techniques.py:240-241`
appends `"candidate gate values from the binary's own cmp insns: [...]"` to `notes`. Nothing
records, in an assertable form, **which** candidate produced the payload or **where that
value came from**.

**What I3 adds:** a structured per-attempt field naming the winning candidate and its
source — `recovered_immediate` (with the instruction address it was decoded from) versus
`literal_magic_list` versus `hardcoded_offset_list`.

**`VariableOverwriteExecutor` is the first conversion**, per the coordinator's decision. It
is the contamination channel, so it is the highest-value instance and it gives I3 a real
subject rather than a convenient one.

**Gate (M4), and the fixtures it cannot work without (M10).** I3 supplies a field, not a
verdict. A gate phrased "if provenance is present it must equal X" passes vacuously on the
unconverted executors — an assertion of absence. But the required-provenance list I wrote to
fix that created a worse defect, and it is mine:

**`variable_overwrite` wins 0 of 17 credited targets and returns FAILED on all 12
target-runs where it executes. So no run in R1 or R2 populates the provenance the gate
requires.** The two available readings were "always red" (the gate fails on all 13 R1
targets, since provenance is required and never present) or "skip when absent" (vacuous).
I3's swept-provenance path could be entirely broken and every test would still pass. **I
specified a gate that cannot fail, in the pass written to stop gates that cannot fail** —
and I did it while the fixture that would have fixed it sat in §7, attached to the item I
had just declared *not* the precondition.

The gate is therefore specified as:

1. **Two purpose-built fixtures**, and they live with the I3 gate, not with §7's capability
   work:
   - **Fixture A** — gate constant **in** `MAGIC_VALUES`, so `variable_overwrite` genuinely
     succeeds and I3 records swept provenance on a **real success**. This is I3's positive
     control; without it the gate is worthless.
   - **Fixture B** — gate constant **not** in `MAGIC_VALUES`. This makes "recovered from the
     instruction stream" and "found by sweep" *provably distinguishable* rather than merely
     differently labelled.
2. **Missing-provenance failure is conditioned on the attempt having produced a payload or
   reached SUCCESS**, not asserted unconditionally across all 13 R1 targets.
3. Red-proof: delete provenance from Fixture A's success and assert the gate reds on
   *missing*; swap Fixture A's and B's expected sources and assert it reds on *mismatch*.

**Until both fixtures pass, §7's R5-measurement precondition is NOT satisfied.**

### I4 — per-window probe-timeout capture

**Inventory.** `DeliveryResult.timed_out` exists (`delivery.py:97/104/110`), is set once at
`:181` from `still_running`, and is read **only** by `__repr__` (`:120`). Zero functional
consumers, confirmed by grep across `supwngo/`. The information is already produced and
then discarded.

**Re-scope (B1).** My "9 call sites across 6 modules, risk medium" was wrong: only **2 of
9** sites sit inside `attempt()` where an `AttemptRecord` exists.

| site | enclosing function | record in scope? |
|---|---|---|
| `input_shape_techniques.py:252` | `attempt()` | yes |
| `fmtstr_techniques.py:102` | `attempt()` | yes |
| `shellcode_techniques.py:66` | `_probe_stack_leak` | **no — precedes any record** |
| `heap_techniques.py:70` | `discover_menu` (module-level) | no |
| `rop_techniques.py:359` | `_probe_pie_leak` | no |
| `fmtstr_techniques.py:138` | `_find_buffer_arg_index` | no |
| `fmtstr_techniques.py:175` | `_write_targets` | no |
| `canary_leak_techniques.py:154` | `_probe_fmtstr_indices` | no |
| `canary_leak_techniques.py:180` | `_probe_echo_sizes` | no |

**The failure this would have caused is instance 10 of this project's signature defect, and
it is the reason this instrument is re-scoped rather than trimmed.** Implemented as
originally written, I4 lands at the two easy sites, its §5 proof passes there, and the two
sites that matter most — `_find_buffer_arg_index` (`fmtstr_techniques.py:141-142`) and
`_probe_fmtstr_indices` (`canary_leak_techniques.py:157-159`), which **abandon an entire
sweep on a first-window timeout** — stay unreachable. The re-run would then report *no
deterministic timeouts exist* precisely where they are most likely, and I would have closed
the one gap my own divergence analysis honestly left open with a false negative, in the
observability pass written to stop absence conclusions being produced for free. My
"and `continue`s" phrasing was literal at only 3 of 9 sites and understated my own case.

**Scope enumeration — mandatory before choosing a mechanism.** The carrier has now failed
scope twice: round 1 chose `AttemptRecord` (absent at 7 of 9), round 2 chose
`ExploitContext` (absent at **4 of 9**, *including both sites this instrument's own proof
mandates*). Twice the carrier was out of scope exactly where it mattered, so the problem is
the approach, not the choice. This table is derived mechanically from the enclosing
function signature of each site and is a precondition of the design below:

| site | enclosing function | `self`? | `context`? |
|---|---|---|---|
| `fmtstr_techniques.py:102` | `attempt` | yes | **yes** |
| `input_shape_techniques.py:252` | `attempt` | yes | **yes** |
| `shellcode_techniques.py:66` | `_probe_stack_leak` | yes | **yes** |
| `rop_techniques.py:359` | `_probe_pie_leak` | yes | **yes** |
| `fmtstr_techniques.py:138` | `_find_buffer_arg_index` | yes | **no** ← proof site |
| `canary_leak_techniques.py:154` | `_probe_fmtstr_indices` | yes | **no** ← proof site |
| `canary_leak_techniques.py:180` | `_probe_echo_sizes` | yes | no |
| `fmtstr_techniques.py:175` | `push` (nested closure) | no | no |
| `heap_techniques.py:70` | `discover_menu` (module-level) | no | no |

Two corrections this produced: `context` reaches only 4 of 9, and `fmtstr_techniques.py:175`
sits in a nested closure named `push`, not in `_write_targets` as round 1's table stated —
so it has neither `self` nor `context`.

**Design — instrument the chokepoint, not the callers.** All 9 sites already call
`deliver_parts`, and `timed_out` is already computed there, at `delivery.py:181`. The defect
was never that the information is unavailable; it is that callers discard it. So record it
**once, where it is already computed**, in a module-level collector in `delivery.py` that
the orchestrator resets and drains around each `attempt()`. Consequences: **zero call-site
changes, zero signature changes, and no site out of scope** — the enumeration above becomes
irrelevant to the mechanism rather than a constraint on it. Verified safe: there is no
threading anywhere in `supwngo/exploit/pipeline/`, and `--jobs` parallelism in the harness
is process-level, so a module-level collector cannot interleave.

Records **per window**, so a sweep that dies on window 1 is distinguishable from one that
completes all **8** and finds nothing (`_find_buffer_arg_index` sweeps 8 windows, not the
40 I wrote). Also records the third state visible at the chokepoint: `delivery.py:183-190`
returns `DeliveryResult(error=...)` with `timed_out=False`, so a spawn failure is
distinguishable from both a timeout and a clean non-match.

Risk re-rated down from medium-high to **low-medium**: it is now one collector plus a
reset/drain pair, not a seven-helper refactor. It still lands last, because it is the only
instrument whose value depends on the diagnostic re-run already having a baseline.

Risk re-rated from medium to **medium-high**: seven helpers each need a signature or
return-type decision, and it is the largest edit in the pass. It therefore lands **last**
(§6).

### I5 — `failure_reason` at the two swallowing sites

**Inventory.** The field exists; nothing branches on it. Every consumer is display or
serialisation: `cli.py:2420`, `orchestrator.py:353`, `handoff.py:53/108/292`,
`templates.py:38`, `contracts.py:101`. The orchestrator's best-partial selection keys on
`outcome` and `partial_artifacts`. **I5 is genuinely behaviour-neutral.**

Two sites:

- `stack_techniques.py:95-96` — the sweep exhausts, appends a note, returns `FAILED` with
  `failure_reason` unset. Recorded cause for **11 of 11** R2 failures.
- `heap_and_bypass.py:105-107` — `scanf_canary_bypass` wraps its body in
  `except Exception`, logs at `debug` only, sets `record.error`, returns. It swallows two
  ways: an exception leaves no `failure_reason`, and `_test_scanf_bypass()` returning
  `False` silently leaves the record `PARTIAL` with no reason at all.

**Pre-declared meaning change (m4):** `handoff.py:292` is
`failure_reason = record.failure_reason or record.error or None`. For
`scanf_canary_bypass` the handoff today reports the exception text via `record.error`;
after I5 the new `failure_reason` wins and that field changes source. So "no existing field
changes meaning" was not strictly true, and this is the exception.

### 4.1 Files touched

| file | instrument |
|---|---|
| `supwngo/exploit/pipeline/contracts.py` — fields **and `to_dict()` at `:96-112`** | I2, I3, I4 |
| `supwngo/exploit/pipeline/orchestrator.py` — `:186-188` prologue timing, `:203-213` exception text, timing around `attempt()` | I1, I2 |
| `supwngo/core/context.py` — diagnostics collector | I4 |
| `supwngo/exploit/pipeline/delivery.py` — surface `timed_out` to the collector | I4 |
| `stack_techniques.py`, `heap_and_bypass.py` | I5 |
| `stack_techniques.py` (`VariableOverwriteExecutor`) | I3 first conversion |
| the 7 helpers named in §4 I4, individually | I4 |
| `supwngo/exploit/pipeline/handoff.py` | declared output change at `:292` (m4) |
| `benchmark/run_bench.py` | I2b probe duration; R1 per-target map gate |
| `tests/` | per-instrument proofs + artifact-level assertions (§5) |
| `CHANGELOG.md` under `[Unreleased]` | user-visible — `templates.py:38` interpolates `failure_reason` into generated scripts |

`templates.py` needs **no** edit: `:38` already renders `failure_reason` conditionally.
Noted so a reader does not read its absence as an omission.

**M6 is the trap in this table.** `AttemptRecord.to_dict()` is an explicit dict literal, not
`dataclasses.asdict`. A field not added there never reaches
`autopwn_json_probe.parsed.attempts`, which is the only place §6 can read it. The concrete
failure: I2/I3/I4 land, in-process tests pass, the re-run completes, and the artifacts are
byte-identical to today's — instruments that exist and measure nothing observable. Hence
the artifact-level assertions in §5.

### 4.2 Risks

- **I1 can move a score in either direction** (M8) — credit a previously-skipped technique,
  change which technique wins, or turn one off. Mitigation: pure deletions first; the five
  guard-requiring executors individually with the §2.1 gate either side;
  `LeakedStackShellcodeExecutor` last; I1 lands only after the diagnostic baseline exists.
- **I4 is now a small edit** (one chokepoint collector, zero call-site changes) rather than
  the 7-helper refactor of revision 2. Mitigation: recording-only; lands last.
- **I2's timing must not perturb timing.** Wall-clock around `attempt()` and the three
  prologue stages only; nothing inside the 126-iteration sweep.
- **I2b touches the harness.** Mitigation: additive field only; gate is R1 13/13 with the
  §2.1 map unchanged.

### 4.3 The script-audit path — checked, and already closed (m8)

Worth recording because it is the one plausible mechanism by which "recording only" text
could move a published figure. `templates.py:38` interpolates `failure_reason` into the
generated script, and `run_bench.py:626-627` audits generated scripts with a **bare**
`\b(strings|objdump|readelf|xxd)\b` match routing to a cheat verdict (`:692-695`). So a
`failure_reason` mentioning `objdump` reaching an audited script would VOID an honest
target.

One correction to the review's framing, which I checked rather than repeated: the string it
cites as evidence that the repo already produces such text —
`input_shape_techniques.py:101`, `"comparison_immediates: objdump pass failed"` — is a
`logger.debug()` call, **not** a `failure_reason`, so it never reaches `templates.py:38`.
No current `failure_reason` in the repo contains an audited word. The hazard is therefore
prospective rather than live, which matters because I5 and I3 are about to write *new*
reason and provenance strings, and a provenance string naming its extraction method is
exactly the kind of text that would.

**It cannot.** `inspect_generated_script` strips comments and docstrings first
(`run_bench.py:645`, implementation `:657-678`), and its docstring at `:633-636` records
that this was done for exactly this reason. Both interpolation paths (`templates.py:38` and
`:145`) emit `#`-prefixed lines inside the module docstring, so both the AST path and the
unparseable fallback (`:664`) remove them. **Already safe — no work needed.**

`templates.py:145` is the `record.notes` block, so **`notes` reaches the generated script
too** — which is how `input_shape_techniques.py:240`'s existing prose provenance already
gets there. That yields a design constraint for I3: put provenance in a **structured field**
and not in `notes`. A gate cannot assert prose, and prose is the half that lands in audited
script text. Flagged forward: a future instrument writing provenance into *executable* code
rather than comments would not be covered by the stripping.

---

## 5. Every instrument must be shown to report the negative

Two structural upgrades over the previous revision, both from the review:

**(a) Mutate to *wrong but present*, not only to absent.** "Revert the instrument and
confirm the test goes red" catches absence only. A constant-valued instrument —
`duration = 1.0`, `failure_reason = "failed"` — survives that mutation while measuring
nothing, which is this project's signature defect in miniature. **Every proof below gets
both mutations: instrument absent, and instrument present but returning a constant or
wrong value.**

**(b) Assert at the artifact level, not only in process.** Each new field must be shown
present in a real `report.json`, not merely on an in-memory record (M6).

| instrument | negative-report proof |
|---|---|
| I1 | Force an `is_applicable` to raise; assert the record distinguishes *raised* from *genuine non-match*. Built-in positive control: today both paths produce the identical `"not applicable to this target"`, so a broken instrument leaves them identical and the assertion fails. |
| I2 | **Two-executor differential** (m1): assert two executors in the same run record *different* durations and that the sleeping one's exceeds the other's. A single whole-run duration stamped onto every record fails this; a one-executor test would have passed it. Plus: prologue time is non-zero and separately attributed. |
| I2b | Assert probe `duration_sec` is present, non-zero, and **less than** the target's `elapsed_sec`; and that a deliberately slowed probe moves it. |
| I3 | Assert the record names the winning candidate *and* its source, and that a different candidate yields a different record. Plus the **required-provenance gate**: delete provenance from a required executor and assert the gate goes red on *missing*, not just on mismatched. |
| I4 | Patch a probe target to hang; assert the timeout surfaces and is distinguishable from an empty response. **Critically, prove it at a sweep-abandoning site** (`_find_buffer_arg_index` or `_probe_fmtstr_indices`) and assert window 1 of *n* is distinguishable from *n* of *n* — if the proof only passes at the two easy sites, B1's failure has not been fixed. |
| I5 | Three-way differential: sweep-exhaust, raise, and `_test_scanf_bypass` returning `False`. The latter two are today indistinguishable, so this is a genuine positive control. |

---

## 6. Sequencing — gate first, then the safe instruments, then the risky ones

Reordered per the review. The previous order ran I1 conversions against a count-only gate,
which is the configuration that let the rev-2 error through.

0. **§9.1 allowlist and §9.2 search rule land first** (M9, M12) — they govern every step
   after them, so they cannot follow the work they constrain.
1. **R1 per-target map gate**, read from `parsed.technique`, asserting the 13 rows of §2.1
   with the two VOID slugs excluded by name. **Delete the header parsing rather than
   teaching it a second format.** Prove it red: swap two targets' expected techniques and
   confirm failure — a multiset gate cannot catch that, which is why the map is per-target.
2. **I2 + I2b + I3 + I5**, with proofs and artifact-level assertions. These are
   write-only fields with no control-flow surface. Within this step: **I2b carries both
   `duration_sec` fields** (M11) before row 2 is claimed settled, and **I3 ships with
   Fixture A and Fixture B** (M10) before §7's R5 precondition is treated as met.
3. **Instrumented R1 + R2 re-run** — `--reps 5 --jobs 8 --timeout 20`, the diagnostic
   baseline.
4. **Re-derive the failure table from artifacts.** Every row becomes *recorded*; no row may
   be *inferred* from a target source (rule 2a). Unexplained rows stay unexplained. This
   alone settles row 6 and most of row 4's motivation.
5. **I1**, one executor at a time, R1 gate after each. Pure deletions first
   (`ScanfCanaryBypassExecutor` cheapest); then the five executors whose `attempt()` does
   **not** reproduce their predicate, individually, with the gate either side (M8);
   `LeakedStackShellcodeExecutor` last.
6. **I4**, chokepoint design per §4, with the 9-site scope enumeration already recorded
   there.

I1 and I4 land *after* the re-run deliberately: they are the only two with control-flow
surface, and landing both before the baseline would leave any movement with two candidate
causes and no way to localise it.

Then, and only then, one short plan per phase against measured facts.

**R2 re-runs here are diagnostic.** They are training-set measurements and cannot restate
the cold figure, which is spent.

---

## 7. §7 decided: the magic sweep, and what actually gates R5

**Decision taken: do not disable `variable_overwrite`.** Deleting a technique class to
remove an exposure is the wrong trade even at zero measured cost. Searching for a buffer
offset is legitimate discovery; **only the value list is illegitimate**, because a fixed
nine-constant sweep has no recovery step and its successes generalise to nothing.

**I3 is the guard, not the capability fix.** Candidate provenance makes a swept credit
self-identifying: if the record says the payload's value came from a literal `MAGIC_VALUES`
entry rather than a recovered immediate, any R5 target credited by sweep is visibly flagged
at report time and reported separately from the headline figure. That is the R5 spec's
"flag and report separately" option, it is already in scope, and it is additive and
low-risk.

| gate | status |
|---|---|
| **R5 measurement** | Gated on **I3 covering `variable_overwrite`, evidenced by Fixture A and Fixture B both passing a red-proven gate** (§4 I3). Not satisfied by I3 merely being implemented: `variable_overwrite` wins 0 of 17 credited targets, so no existing target exercises the path, and without the fixtures the gate cannot fail (M10). |
| **R5 corpus generation and sealing** | **Not gated.** It touches nothing in the pipeline and cannot be contaminated by a sweep. Proceeds now. My earlier "no R5 access" was too broad; the precondition binds measurement only, per the R5 spec at `55a8db4`. |
| **The `comparison_immediates()` sourcing fix** | Still happens — a genuine improvement — as its own per-phase plan against measured facts, with the provenance gate (recovered value's instruction address and decoded immediate disclosed). **Not a precondition for R5.** Note the fixture that previously sat on this row has **moved to the I3 gate**, where it is load-bearing; leaving it here attached to a non-precondition is what let M10 through. |

This decouples "R5 is safe to measure" from "the capability work is finished", which
matters because the second has no bounded schedule. A third option also now exists and
dominates disabling: **give `VariableOverwriteExecutor` the `is_applicable` predicate it
uniquely lacks** (§3), which makes the 126 calls conditional rather than unconditional.

---

## 8. Corrections carried forward

- **Phase 1a serves one target, not three.** `05` gains nothing (`_find_buffer_arg_index`
  already sweeps `%N$p`, and `%p` always renders as hex); `14` needs an index sweep plus
  little-endian reassembly from decimal `arr[%d] = %d` output — a different fix, and
  shape-fittable. Only `03` is served. The three-target claim was the promotion rationale;
  **withdrawn**.
- **And §2.1 weakens the phase-1a argument further (M2).** `05_fmtstr_arbread` is credited
  to `canary_leak_ret2win`, not to any format-string technique. So `05`'s credit does not
  currently come from the format-string path at all — which I reasoned about at length
  without noticing. Any phase-1a exposure argument must be rebuilt on §2.1.
- **Widening the leak scanner is not additive.** `profile_stage.py:160-165` is
  first-write-wins per bucket, so extra candidates can **displace** the correct
  `libc`/`pie`/`stack` leak on R1 `03` and `07`. **Test it; do not assert it.**
- Phase 1a's real consumer set is `01`, `03`, `06`, `07` — exposure **not** smaller than
  phase 3's.
- The "phase 3 is highest exposure" headline is **withdrawn**; it was computed from the
  incomplete map.
- `deliver_parts`'s one "caller-supplied" timeout (`heap_techniques.py:213`) passes nothing,
  so it runs at 3.0 (m3).

---

## 9. Non-goals, and what is actually enforceable

**Non-goals.** No capability change. No new executor. No primitive layer. No change to any
corpus file. No R3/R4/R5 *measurement*.

### 9.1 Harness changes are an allowlist, not a denylist (M9)

My previous wording — "no change to verification, attribution, classification or scoring
logic" — is the wrong **shape**, independently of whether it is correct for I2b. It omits two
cheat-detection subsystems that are *generated* separately and only *consumed* by
`classify()`, so weakening either makes targets pass without `classify` being touched at all:

- **negative-control generation** — `negative_control()` builds `controls` at
  `run_bench.py:494-530`, including `bare_run_verify_stdin`, `bare_run_filler` and the
  `bare_run_menu_walk` probe set; `classify` reads only the *result*, at `:755`. Dropping a
  menu probe weakens cheat detection invisibly to that clause.
- **script-audit generation** — `inspect_generated_script` (`:630-654`) and
  `script_cheat_reason` (`:681-695`). Same structure.

A denylist cannot be made safe here, because the next person adds a category nobody thought
to forbid. So, inverted:

> **The only changes to anything under `benchmark/` in this pass are: (a) an additive
> `duration_sec` on the `autopwn_json_probe` wrapper, (b) an additive `duration_sec` on the
> `autopwn_script_generation` wrapper, and (c) the R1 per-target map gate assertion.
> Nothing else under `benchmark/` is touched.**

An allowlist cannot be read as licence for anything, which is the property required of a
clause that will outlive this pass and govern the per-phase plans after it. The standing
project constraint it serves — the harness's verification and cheat-detection logic is never
weakened to make a target pass — only survives later good-faith editing in this form.

### 9.2 Codified: the all-runs search rule (M12)

This was owned by prose in §2.2. It is now a rule, because it is the rule that would have
caught the 1-instead-of-46 undercount:

> **A factual claim about "both runs" / "all runs" must be produced by a search that
> enumerates every run directory, and the enumeration must be visible in the command or
> script that produced it. Where the fact exists as a structured field in `report.json`,
> read the field; never text-search generated scripts for it.**

Both of this round's search failures violated exactly this: an ad-hoc text search over
generated artifacts, scoped to fewer runs than the sentence describing it claimed, for a
fact that existed as a structured field. Third parser gap in the project, after the
hex-text-only leak scanner and the desynchronised positional probe.

**What is enforceable (M7).** R1's 13/13 **with the §2.1 per-target map** is the enforcement
instrument: it is repeatable on a fixed corpus, so any movement is attributable and blocks
the pass. The previous revision extended that rule to R2's 4/15; **that half is withdrawn.**
§6 concedes R2 re-runs cannot restate the cold figure, so a moved R2 number provides no way
to separate an instrumentation defect from ordinary post-cold drift — the rule would have
read as a guarantee while functioning as neither gate nor diagnostic. **The R2 re-run is
diagnostic only and no figure claim attaches to it.**
