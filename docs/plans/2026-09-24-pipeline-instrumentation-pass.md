# Instrumentation pass — make the pipeline observable enough to plan against

**Date:** 24 Sep 2026
**Branch:** `bench/round2-cold-and-dev-20260924`
**Revision:** 2 — addresses the independent review at `31196d2`
(`docs/reviews/2026-09-24-instrumentation-pass-review.md`), which was NOT-APPROVED on
B1/B2/B3 + M1-M7.
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

**Declared behaviour delta:** after migration the orchestrator calls `attempt()` where it
previously skipped. The recorded outcome is `SKIPPED` either way, but the executor's code
now runs. For cheap pure predicates this is inert; for `LeakedStackShellcodeExecutor` it
*moves* a process spawn rather than adding one. Conversion order is cheapest-and-purest
first — `ScanfCanaryBypassExecutor` (`heap_and_bypass.py:50-53`, reads
`context.protections.canary` and `binary.plt` only) — with `LeakedStackShellcodeExecutor`
**last**, and the R1 per-target gate run after each.

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

One additive `duration_sec` on the probe object in `benchmark/run_bench.py`. Subtracting it
from the existing per-target `elapsed_sec` gives the pipeline-vs-harness split that row 2
names. This touches no verification, attribution, classification or scoring logic — see the
narrowed §9 — and its gate is that R1 still reports 13/13 with the §2.1 map unchanged.

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

**Gate (M4).** I3 supplies a field, not a verdict, and because conversion is per-executor a
gate phrased "if provenance is present it must equal X" passes vacuously on exactly the
unconverted executors — an assertion of absence, this project's signature defect. So the
gate carries an explicit **required-provenance list** naming the converted executors, and
**fails when a required provenance is missing**, not only when it mismatches. "Not yet
converted" can never read as "no swept candidate found."

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

**Design.** A mutable diagnostics collector on `ExploitContext`. The context predates the
`AttemptRecord` (`orchestrator.py:204` precedes `:217`), so the same channel covers
`_probe_stack_leak`'s pre-record case — **no site is declared out of scope**, and none is
left silently uncovered. Records **per window**, so a sweep that dies on window 1 is
distinguishable from one that completes 40 windows and finds nothing. Lands as
**recording only**: no call site changes its control flow in this pass.

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

- **I1 is the only instrument that can silently lower a score.** Mitigation: migration into
  an existing idiom rather than a signature change; one executor at a time; the §2.1
  per-target gate after each; `LeakedStackShellcodeExecutor` last.
- **I4 is the largest edit** (7 helpers). Mitigation: recording-only, lands last, after the
  diagnostic re-run.
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

1. **R1 per-target map gate**, read from `parsed.technique`, asserting the 13 rows of §2.1
   with the two VOID slugs excluded by name. **Delete the header parsing rather than
   teaching it a second format.** Prove it red: swap two targets' expected techniques and
   confirm failure — a multiset gate cannot catch that, which is why the map is per-target.
2. **I2 + I2b + I3 + I5**, with proofs and artifact-level assertions. These are
   write-only fields with no control-flow surface.
3. **Instrumented R1 + R2 re-run** — `--reps 5 --jobs 8 --timeout 20`, the diagnostic
   baseline.
4. **Re-derive the failure table from artifacts.** Every row becomes *recorded*; no row may
   be *inferred* from a target source (rule 2a). Unexplained rows stay unexplained. This
   alone settles row 6 and most of row 4's motivation.
5. **I1**, one executor at a time, cheapest predicate first (`ScanfCanaryBypassExecutor`),
   `LeakedStackShellcodeExecutor` last, R1 gate after each.
6. **I4**, re-scoped per §4.

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
| **R5 measurement** | Gated on **I3 covering `variable_overwrite`** — hence its first conversion. Once a swept credit is distinguishable in the artifacts, a sweep-credited R5 target cannot be silently counted as capability. |
| **R5 corpus generation and sealing** | **Not gated.** It touches nothing in the pipeline and cannot be contaminated by a sweep. Proceeds now. My earlier "no R5 access" was too broad; the precondition binds measurement only, per the R5 spec at `55a8db4`. |
| **The `comparison_immediates()` sourcing fix** | Still happens — a genuine improvement — as its own per-phase plan against measured facts, with the provenance gate (recovered value's instruction address and decoded immediate disclosed; a fixture with an undisclosed constant). **Not a precondition for R5.** |

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

**Non-goals.** No capability change. No new executor. No primitive layer. No change to the
harness's **verification, attribution, classification or scoring logic**. No change to any
corpus file. No R3/R4/R5 *measurement*.

The §9 non-goal is **narrowed** from "no change to the harness" to the list above, because
I2b adds one timing field to `benchmark/run_bench.py` and the R1 gate is a harness-side
assertion. Neither is verification, attribution, classification or scoring. Stating this
explicitly rather than leaving a row unsettled behind an over-broad prohibition.

**What is enforceable (M7).** R1's 13/13 **with the §2.1 per-target map** is the enforcement
instrument: it is repeatable on a fixed corpus, so any movement is attributable and blocks
the pass. The previous revision extended that rule to R2's 4/15; **that half is withdrawn.**
§6 concedes R2 re-runs cannot restate the cold figure, so a moved R2 number provides no way
to separate an instrumentation defect from ordinary post-cold drift — the rule would have
read as a guarantee while functioning as neither gate nor diagnostic. **The R2 re-run is
diagnostic only and no figure claim attaches to it.**
