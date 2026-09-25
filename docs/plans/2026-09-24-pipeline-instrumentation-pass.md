# Instrumentation pass — make the pipeline observable enough to plan against

**Date:** 24 Sep 2026
**Branch:** `bench/round2-cold-and-dev-20260924`
**Supersedes as the active document:** `2026-09-24-r2-step3-primitive-acquisition.md`
(rev 1 and rev 2 both NOT-APPROVED; **no rev 3 will be written**)
**Scope:** instrumentation only. **No capability change. No R2 score change expected.**
**Status:** awaiting review. `supwngo/` untouched since `b3a40b4`.

---

## 1. Why the method changed

Two rejections in the same family: **both plans asserted properties of the code that a
reviewer falsified by reading it.** Rev 1 claimed the GOT was excluded (it was
enumerated); rev 2 claimed phase 1a served three targets (it serves one) and published a
regression map missing a row. The common cause is not carelessness about any one fact — it
is that **the pipeline is not observable enough to plan against**, so planning against it
produces claims the code contradicts.

Every unfalsifiable or unmeasurable finding across both reviews resolves to a missing
instrument:

| finding that could not be settled | missing instrument |
|---|---|
| "discovery past 30 s" as a Fork B threshold | `AttemptRecord` has **no timing field** |
| per-target pipeline time vs harness overhead | `autopwn_json_probe` carries **no duration** |
| whether the R1 gate distinguishes the new primitive from a retained legacy fallback | **no field naming which candidate produced a payload** |
| why any of the nine stub targets skipped a technique | `is_applicable` reasons collapse into one generic string |
| whether a stub is a *deterministic* probe timeout | `timed_out` has **no functional consumer** |
| why `variable_overwrite` failed on all 11 R2 failures | `failure_reason` left **empty** |

So this pass builds the instruments, re-derives the failure table from artifacts, and only
then writes one short plan per phase against **measured** facts. The alternative —
splitting rev 2 into per-phase documents — is necessary later but insufficient now:
smaller documents making unverified claims about code fail the same way.

---

## 2. Verification asked for: are the published figures contaminated by the magic sweep?

**Confirmed, not assumed. Both halves:**

**Retroactively clean.** No credited target in either published run was solved by
`variable_overwrite`.

| run | credited targets | solving techniques |
|---|---|---|
| **R2 cold (4)** | `07`, `10`, `13`, `15` | `srop`, `ret2libc_leak`, `ret2win`, `ret2libc_leak` |
| **R1 baseline (13)** | all 13 | `stack_shellcode`, `ret2plt`, `ret2libc_leak` ×2, `canary_leak_ret2win` ×2, `fmtstr_write_gate`, `ret2dlresolve`, `srop`, `int_truncation_bypass`, `tcache_poison_got`, `negative_index_write`, `ret2win` |

`variable_overwrite` appears in exactly one generated script across both runs —
R1 `11_heap_uaf_leak`, which is **VOID and not credited**. **So the 4/15 and 13/13 figures
stand and need no annotation.**

**Prospectively exposed, and unrecoverably so for R5.** `MAGIC_VALUES`
(`stack_techniques.py:59-63`) is 9 constants; `VariableOverwriteExecutor.attempt()`
(`:76-93`) sweeps 14 buffer sizes × 9 magics = **126 unconditional `verify_payload` calls**
with no recovery step and no `comparison_immediates()` call. Inertness on R1/R2 does not
protect R5: different binaries, different constants, single-use. A natural gate choice like
`0xdeadbeef` would be credited by sweep, count toward the gate as capability, and
generalise to nothing.

**I did not investigate provenance** — `0x1337` and `0xdeadbeef` are genuine CTF folklore,
so whether the lists were seeded from a corpus is likely unanswerable, and the defect is
structural regardless.

### 2.1 My own §6.1 defect, recorded

Rev 2's R1 technique map had **12 rows for 13 credited targets**; `15_win_function` was
missing, and the "phase 3 is highest exposure" headline was computed from the incomplete
table. Cause: generated scripts use **two header formats** — `(technique: X)` for most and
`Technique: X` for `ret2win` — and my extraction matched only the first. Same class of
error as the rest of this round: I published a table without checking it covered every row
it claimed to. The complete map is in §2 above.

---

## 3. The inversion this pass exists to stop repeating

Two rounds of planning argued about a capability to **add**. The actual defect is an
executor that **does not use a capability the repo already has**:

- `comparison_immediates()` is defined at `input_shape_techniques.py:68` and called from
  **exactly one** site, `input_shape_techniques.py:240`, inside its own module.
- `stack_techniques.py` never calls it, and brute-forces a folklore list instead.

Sourcing that executor's candidates from the instruction stream is small, genuine, and
generalising — **the opposite of what both revisions proposed.** Neither round could see it
because both reasoned about what to build rather than about what the code does.

**This pass does not fix it** — that is a capability change and belongs in a per-phase plan
written against measured facts. See §7 for the R5 gating question it raises, which needs a
decision before any R5 access.

---

## 4. The instruments

Five changes. Each must be able to **report the negative** (§5).

| # | instrument | where | risk |
|---|---|---|---|
| **I1** | `is_applicable` gains an **optional** skip reason, keeping its `bool` return | base class + `orchestrator.py:202-206`; executors opt in incrementally | **not zero** — see below |
| **I2** | per-attempt **duration** on `AttemptRecord` | `AttemptRecord`, set by the orchestrator around `attempt()` | low |
| **I3** | per-attempt **candidate provenance**: which candidate, from which source, produced the payload | `AttemptRecord`; populated by executors that search candidates | low |
| **I4** | functional consumer for `timed_out` so a **deterministic** probe timeout is distinguishable from a genuine non-match | 9 `deliver_parts` call sites across 6 executor modules | medium |
| **I5** | `failure_reason` populated at the two sites that currently swallow it | `stack_techniques.py:95-96`, `heap_and_bypass.py:105-107` | low |

**I1 is deliberately optional, not a mandatory signature change.** The review's point is
accepted: the repo has **17 executor classes and 16 `is_applicable` predicates**, so
changing the signature is not an observability-only edit, and its R1 exposure is **not
zero** — a typo in any predicate silently turns a working technique off. The safe form is a
companion hook defaulting to `None`, so an unconverted executor behaves exactly as today.
Executors convert one at a time, each with the R1 gate run after.

**I4's scope, measured.** `timed_out` is set once, at `delivery.py:181` from
`still_running`, and read **only** by `DeliveryResult.__repr__` (`:120`) — zero functional
consumers, confirmed by grep across all of `supwngo/`. The 9 executor call sites use
hardcoded timeouts (`1.5`, `2.0` ×4, `3.0` ×3, and one caller-supplied) across
`heap_techniques`, `fmtstr_techniques` (×3), `rop_techniques`, `shellcode_techniques`,
`input_shape_techniques`, and `canary_leak_techniques` (×2). Every one of them treats a
timed-out probe as an ordinary non-match and `continue`s. **This is also the operationally
important half of the erratum**: a future round that wants longer probes must change these
call sites — there is no budget flag to pass.

**I5's two sites, both confirmed by reading:**
- `stack_techniques.py:95-96` — the sweep exhausts, appends a note, returns `FAILED` with
  `failure_reason` unset. This is the recorded cause for **11 of 11** R2 failures.
- `heap_and_bypass.py:105-107` — `scanf_canary_bypass` wraps its whole body in
  `except Exception`, logs at `debug` level only, sets `record.error`, and returns. It
  swallows two ways: an exception leaves no `failure_reason`, and `_test_scanf_bypass()`
  returning `False` silently leaves the record `PARTIAL` with no reason at all.

**I3 is the field BLOCKING 4 needed and neither revision scheduled.** Without it, an R1 gate
cannot tell a new primitive from a retained legacy fallback, and no amount of plan prose
fixes that.

**I4 closes the gap my own divergence analysis left open.** `rep_divergence.py` establishes
that no R2 failure is a *flaky* stall (15/15 deterministic). It cannot rule out a
**deterministic** stall, and I said so. I4 is the only thing that closes it.

### 4.1 Files touched

| file | instrument |
|---|---|
| `supwngo/exploit/pipeline/contracts.py` | I2, I3 (new `AttemptRecord` fields), I1 (base-class hook) |
| `supwngo/exploit/pipeline/orchestrator.py` | I1 (`:202-206` reason capture), I2 (timing around `attempt()`) |
| `supwngo/exploit/pipeline/delivery.py` | I4 (surface `timed_out` to callers) |
| `supwngo/exploit/pipeline/executors/stack_techniques.py` | I5 |
| `supwngo/exploit/pipeline/executors/heap_and_bypass.py` | I5 |
| the 6 executor modules with `deliver_parts` call sites | I4 consumers |
| `tests/` | one negative-report test per instrument (§5) |
| `CHANGELOG.md` | under `[Unreleased]` — these change generated-script contents, so user-visible |

New fields are **additive with defaults**, so any executor not yet converted keeps its
current behaviour. No existing field changes meaning.

### 4.2 Risks

- **I1 is the only one that can silently lower a score** (a mistyped predicate turns a
  technique off). Mitigation: optional hook, one executor at a time, R1 gate after each.
- **I4 can change control flow** if a call site starts treating a timeout as a distinct
  case. Mitigation: first land it as *recording only* — no branch changes — then act on what
  the re-run shows.
- **I2's timing must not itself perturb timing.** Wall-clock around `attempt()` only; no
  per-payload instrumentation inside the 126-iteration sweep.

---

## 5. Every instrument must be shown to report the negative

Non-negotiable: this project's signature defect is validation that cannot fail, and
committing an unfalsifiable observability pass would be absurd. Per instrument, a test that
**fails before the instrument exists**:

| instrument | negative-report proof |
|---|---|
| I1 | force an `is_applicable` to raise; assert the record distinguishes *raised* from *genuine non-match* (today both yield `"not applicable to this target"`) |
| I2 | patch an executor to sleep; assert the recorded duration reflects it and is not zero/absent |
| I3 | run an executor whose payload came from candidate *k*; assert the record names *k* and its source, and that a different candidate yields a different record |
| I4 | patch a probe target to hang past its hardcoded timeout; assert `timed_out` surfaces in the attempt record and is distinguishable from an empty response |
| I5 | force the sweep to exhaust; assert `failure_reason` is non-empty and states what was tried. Separately, make `scanf_canary_bypass` raise and assert the exception text reaches `failure_reason` rather than only a `debug` log — and make `_test_scanf_bypass` return `False` and assert that is distinguishable from the raise |

Plus: **mutation-test the tests.** Revert each instrument and confirm its test goes red.
An instrument test that passes without the instrument is measuring nothing.

---

## 6. Then re-derive the diagnosis, and only then plan

1. Instruments land, each with its negative-report proof and the R1 gate green.
2. **R1 gate asserts the complete 13-row per-target technique map in §2** — count-only is
   insufficient (rev 2 BLOCKING 6), and the map must be extracted by a method that handles
   **both** header formats (§2.1).
3. Re-run **R1 and R2 instrumented**, `--reps 5 --jobs 8 --timeout 20`.
4. **Re-derive the failure table from artifacts.** Every row becomes *recorded*; no row may
   be *inferred* from a target source (rule 2a). Rows that remain unexplained stay
   unexplained.
5. Write **one short plan per phase**, each against measured facts only.

R2 re-runs here are diagnostic. **They are training-set measurements and cannot restate the
cold figure**, which is spent.

---

## 7. Decision needed: the magic sweep before R5

Not part of this pass, but it must be settled before any R5 access, and I recommend
against the obvious option.

| option | assessment |
|---|---|
| **Disable `variable_overwrite`** | Removes the R5 exposure entirely and costs **nothing measurable** — it credits 0 of 17 credited targets across both runs. But it deletes a technique class rather than fixing it, and if a later target genuinely needs an adjacent-variable overwrite, the capability is simply gone. |
| **Source candidates from `comparison_immediates()`, keep the buffer-size search** (recommended) | The buffer-size sweep is legitimate — searching for an offset is normal, and `find_return_offset()` already exists for it. Only the **magic value** list is illegitimate. This fixes the actual defect, uses a capability already in the repo, and generalises to any comparison constant. |
| Leave as is until after R5 | **Rejected.** R5 is single-use; a contaminated credit there is unrecoverable. |

Either way **R5 must not be accessed until this is resolved**, and the resolution needs its
own per-phase plan with the §5.1-style provenance gate from rev 2 (recovered value's
instruction address and decoded immediate disclosed; a fixture with an undisclosed
constant). Flagging the interim risk window explicitly: it is open now.

---

## 8. Corrections carried forward from the rev-2 review

- **Phase 1a serves one target, not three.** `05` gains nothing (`_find_buffer_arg_index`
  already sweeps `%N$p`, and `%p` always renders as hex). `14` needs an index sweep plus
  little-endian reassembly from decimal `arr[%d] = %d` output — a different fix, and
  shape-fittable. Only `03` is served. **The three-target claim was the promotion
  rationale; it is withdrawn.**
- **Widening the leak scanner is not additive.** `profile_stage.py:160-165` is
  first-write-wins per bucket, so extra candidates can **displace** the correct
  `libc`/`pie`/`stack` leak on R1 `03` and `07`. **Test it; do not assert it.**
- Phase 1a's real consumer set is `01`, `03`, `06`, `07` — its exposure is **not** smaller
  than phase 3's.
- The "phase 3 is highest exposure" headline is withdrawn pending the complete map (§2.1).

## 9. Non-goals

No capability change. No new executor. No primitive layer. No change to the harness's
verification logic or to any corpus file. No R3/R4/R5 access. The R2 cold figure of 4/15
and the R1 baseline of 13/13 are unaffected by anything in this pass; if either moves, that
is a defect in the instrumentation, not a result.
