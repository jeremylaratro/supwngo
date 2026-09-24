# R2 step 3 — close the primitive-acquisition gap, generally

**Date:** 24 Sep 2026
**Revision:** **rev 2** — rev 1 returned **NOT-APPROVED**, 6 blocking + 2 major.
All are treated as binding. Rev 1's defects are recorded in §0, not quietly fixed.
**Branch:** `bench/round2-cold-and-dev-20260924`
**Predecessor:** `docs/plans/2026-09-24-benchmark-round2-cold-then-develop.md` (rev 3)
**Cold figure this develops against:** 4/15, committed `40bd6ca` / `9f31360`
**R1 regression baseline on this commit:** 13/13 @ 5/5, committed `15215b6`
**Status:** awaiting re-review. **No implementation has started.**

---

## 0. What rev 1 got wrong

Rev 1 was one approval away from sending an implementer to build on a diagnosis wrong
in three places. Recorded because a plan that silently absorbs its review teaches
nobody, and because two of these were errors of *method*, not detail.

| # | rev 1 claim | truth | how it was wrong |
|---|---|---|---|
| B1 | "the GOT is never a candidate, so `12` is unreachable" | `_writable_ranges` enumerates `.got` **and** `.got.plt` (`fmtstr_techniques.py:196`); `12`'s `.got.plt` is `0x404000`+104 and `puts@got = 0x404020` sits inside it | **Inverted, not overstated.** The GOT was *attempted*. An implementer told to "add the GOT" adds what is already there, believes the fix landed, and mis-attributes any later pass to it. |
| B2 | "`is_applicable` requires `win_function`, so `05` is refused before it starts" | `05` reached `Stage.DELIVERY`, so `win_function` was **not** `None` — contradicting rev 1's own §2.1 two paragraphs away. And `context.win_function` is the only source of the write *value* for `12`'s `puts@got` | Remedy deleted the input its own phase-1 target needs. |
| B3 | `05` bucketed as missing-write-primitive | `05` needs a format-string **read** (PIE defeat via a code pointer) | Corrected: **A = {06, 12} = 2**, **B = {03, 05} = 2**, **C = 4 — largest by 2×**. Rev 1's §4 ordering rationale did not survive its own corrected table. |
| B4 | §5 listed rules 1, 3, 5 | Predecessor rules **2 and 4** were silently dropped | Rule 2 (no reference-exploit constant enters the pipeline) is load-bearing: phase 1 needs `0x1337`, and `ablate_r2.py:471` holds that literal. Rule 4 (per-fix falsifiable prediction) is the only written guard against the failure this document exists to prevent. |
| B5 | write *value* provenance unspecified; "`%n` = 8 bytes" | `%n` writes **4** bytes on x86-64 (1/2/4 = `%hhn`/`%hn`/`%n`; 8 needs `%lln`) | The value's provenance decides whether phase 1 is capability or fit, and **neither gate could tell.** |
| B6 | flip-condition: keep legacy path ordered first | `orchestrator.py:196-197` breaks at first success, and R1 `06_fmtstr_arbwrite` is the **only** R1 target solved by this executor | The escape hatch and the R1 gate **cancel**: legacy first ⇒ 13/13 with the new primitive exercised by zero R1 targets. |
| M1 | "`03` is correctly self-diagnosed" | `03` **does** emit a code pointer, as a raw 8-byte binary `write()`. `scan_hex_addresses` (`delivery.py:299-319`) matches `0x[0-9a-f]{6,16}` **text only** — a raw little-endian qword can never match | The executor's message is *factually wrong about the target*. Building a PIE-leak primitive routes around a **parser gap** that then survives into R3. |
| M2 | ablation counted as one of three gates | `ablate_r2.py` has **zero** `supwngo` imports; it drives hand-written chains against corpus binaries | **No pipeline change can move an ablation verdict.** It is a corpus tripwire, not a fix gate. Rev 1 had 3 gates; really **1**, and it was technique-blind. |

Two of these are method failures worth naming separately:

**Diagnosis by answer key.** Rev 1's §2.1 column said "recorded cause" for all eleven
rows. For `08`, `09` and `14` the actual recorded text is the orchestrator's generic
stamp `"not applicable to this target"`; my stated causes ("matches truncation not
multiplication", "negative-index write not positive read") came from **reading the
target `.c` headers**. The inferences were substantively right, which makes this a
provenance defect rather than a wrong answer — but reading target sources to diagnose is
exactly what dropped rule 2 governs, and presenting inference as record is worse than
being wrong openly. §2.1 now labels every row *recorded* or *inferred*.

**Asserting a mechanism that does not exist.** Rev 1 inherited "inner truncation at the
20 s per-technique budget". There is no such budget — `--timeout` is capped to 2.0 s for
profiling, bounds *verification* not discovery, and the executors' probes are hardcoded
1.5/3.0 s at 8 call sites. This had propagated into the **committed** cold report and is
corrected there by erratum (`be0874d`), which also made Fork B's flip-condition
unfalsifiable as rev 1 wrote it.

---

## 1. Goal, and what success is not

Raise R2 by fixing what genuinely failed, **without** fitting to R2's surface shapes.

The post-development R2 number is **training performance**, not generalization. R2's
capacity to measure generalization was spent by the cold run. §2.10.2 of the cold report
is the standing warning: nine technique families already failed to survive *one* change
of surface mechanic.

**Primary success criterion is not the R2 score.** It is: *each fix is a capability that
does not name a target; R1 still solves 13/13 **by the same technique per target**; and
each fix carries a falsifiable prediction (rule 4) about what a later round would show
if it were secretly target-specific.*

---

## 2. Diagnosis — provenance labelled

### 2.1 What blocked each of the 11 failures

`recorded` = the executor emitted this specific reason. `generic` = the orchestrator's
hardcoded `"not applicable to this target"` stamp, which carries **no** information.
`inferred` = my reading, with its basis named.

| # | target | provenance | cause | bucket |
|---|---|---|---|---|
| 06 | `fmtstr_short_write` | **recorded** | `fmtstr_write_gate`: found arg index, no gate variable unlocked the win path. Target needs an exact 16-bit value; `_payload` can emit only the small fixed character-count value (never `0x1337`) | **A** |
| 12 | `fmtstr_got_overwrite` | **recorded** | same reason string. GOT **was** a candidate and **was** attempted; it failed on the *value*, not the *address* | **A** |
| 05 | `fmtstr_pie_leak` | **recorded** | reached `Stage.DELIVERY`. Needs a format-string **read** to defeat PIE, not a write | **B** |
| 03 | `pie_write_leak_ret2libc` | **recorded but factually wrong** | `ret2libc_leak` says "printed no code pointer". The target **does** print one, as a raw binary `write()`; the scanner is hex-text-only | **B / parser gap** |
| 01 | `stack_shellcode_relay` | **recorded** | `stack_shellcode`: "placed past the return address but no offset / NOP-sled combination produced a verified shell" | **C** |
| 04 | `canary_relay_bypass` | **recorded** | `canary_leak_ret2win`: "never hands it back (no over-long raw echo, no user-controlled printf format)" | **C** |
| 08 | `int_mul_overflow` | **generic** + inferred | `int_truncation_bypass` SKIPPED, no reason. Inferred from the R1↔R2 pairing (R1 `10` was plain truncation) that the predicate matches truncation only — **unverified; phase 2 must confirm from the predicate, not the source** | **C** |
| 14 | `oob_read_flag_array` | **generic** + inferred | `negative_index_write` SKIPPED, no reason. Inferred from pairing (R1 `14` was a negative-index write). Also an output-encoding gap: the flag is printed by the target, and extraction is the issue | **C / parser gap** |
| 09 | `heap_dangling_global` | **generic** | `uaf` SKIPPED, no reason. **Cause genuinely unknown** — could be a non-match or a *crashing predicate* (see §2.3) | **D** |
| 02 | `ret2plt_strcat_system` | **recorded** | technique generated and ran, no flag | **E** |
| 11 | `heap_overflow_tcache_poison` | **recorded** | technique generated and ran, no flag | **E** |

**Corrected buckets: A = 2 · B = 2 · C = 4 · D = 1 · E = 2.** Bucket C is the largest.

### 2.2 The cross-cutting capability gap rev 1 missed: output-encoding-agnostic extraction

The most valuable finding from review, and it is a *capability* by construction rather
than a fit. `scan_hex_addresses` is the only leak scanner and matches
`0x[0-9a-fA-F]{6,16}` in decoded text. Therefore the pipeline cannot see a value a target
emits as:

- a raw little-endian binary `write()` — **`03`**, whose "no code pointer" message is
  produced by this gap and is wrong about the target;
- bytes that are not pointer-shaped hex — **`14`**, where the OOB read's product is the
  secret itself;
- partially, **`05`**, whose PIE defeat depends on recognising a code pointer however it
  is rendered.

**One fix serves three targets, names none of them, and cannot be shape-fitted** — it
strictly widens what counts as an observed value. It is also cheap next to a primitive
layer. It is promoted to phase 1 on its own merits.

### 2.3 `is_applicable` failures are indistinguishable from crashes

`orchestrator.py:202-206`:

```python
try:
    applicable = executor.is_applicable(self.context)
except Exception as e:
    logger.debug(f"is_applicable() raised for '{name}': {e}")
    applicable = False
```

A raising predicate and a genuine non-match both become `applicable = False` and both
emit the same `"not applicable to this target"`. **Across all nine 5/5 targets this makes
every SKIPPED row uninformative**, and it is why `09`'s cause is unknown and `08`/`14`
had to be inferred. Making this state its reason is **phase 0**: it is the single change
that would have prevented this entire class of misdiagnosis, and without it phase 2
cannot be planned from evidence.

### 2.4 `_probe_echo_sizes` versus `deliver_parts` — rev 1 conflated them

Two different things:

- **`_probe_echo_sizes`** (`canary_leak_techniques.py:174`), a single 2.0 s probe, no
  retry. Reaches **`04` only**. Rev 1's scoping of this was right.
- **`deliver_parts`** (`delivery.py`), used by **seven modules** and on the path of
  **all nine** stub targets. `DeliveryResult.timed_out` **already exists**
  (`delivery.py:97`) and has **zero functional consumers** — set at :110, read only by
  `__repr__` at :120. So the undone work is caller-side across seven modules, and it
  could plausibly affect `05`/`06`/`12`/`08`, not just `04`.

Rev 1 deprioritised this on a **scope** argument that was wrong. It is still
deprioritised, on the **determinism** argument, which is the one the evidence supports:
all nine are 5/5, so whatever is happening is deterministic, and a timeout that fires
identically on every rep is not the flaky-probe story. Fixing the `timed_out` blindness
is scheduled in **phase 0** as an observability change (it makes a deterministic timeout
*visible*), not as a capability fix expected to move targets.

---

## 3. Fork A — primitive layer versus more executors

**Option 1 (chosen): a `FormatStringPrimitive` layer; executors become thin consumers.**
`write(addr, value, width)` over `%hhn`/`%hn`/`%n`, `read(addr)` over `%s`,
`leak_slot(index)` over `%N$p`. `06` and `12` become two *applications* of one
capability — and per B1/B2 the real gap for both is the **value**, not the address.

- Cost: touches the path R1 `06` flows through — 1 R1 target of regression exposure.
- Benefit: one implementation covers the exact-value gate, the GOT write, and shapes
  nobody has written, including R3's.

**Option 2 (not taken): add `fmtstr_exact_write` / `fmtstr_got_overwrite` /
`fmtstr_pie_leak`.** Cheaper, lower-risk, probably +2 on R2 this week. Rejected as the
inflation §5 forbids — three executors each encoding one R2 mechanic, which R3 breaks
the same way it broke the existing one. **Recorded so a later reader can tell a
principled choice from a convenient one.**

**Flip condition, rewritten — rev 1's version made the R1 gate vacuous (B6).** If the R1
gate cannot be held through the refactor:

1. the legacy `FmtStrWriteGateExecutor` is **unregistered**, never merely reordered;
2. its `_payload` is retained **only as the last entry in the new primitive's own
   candidate list** — a fallback *inside* the new path, so R1 `06` still exercises the
   new code;
3. the R1 gate asserts **per-target solving technique**, not a count.

Rev 1's "retain legacy, ordered first" is prohibited: `orchestrator.py:196-197` breaks
at first success and R1 `06` is the only R1 target this executor solves, so legacy-first
yields 13/13 with the new primitive exercised by **zero** R1 targets.

## 3.1 Fork B — argument index: dynamic probe or static call-site?

**Option 1 (chosen): keep dynamic probing, harden it.** `_find_buffer_arg_index` located
the index correctly on all three R2 format-string targets.

**Option 2 (not taken): recover it statically from the `printf` call site.** More
precise, but brittle across compilers/inlining, and a static source-shaped dependency in
a pipeline whose premise is the binary.

**Flip condition, rewritten — rev 1's was unfalsifiable** because it named a 20 s
per-technique budget that does not exist. Restated against real numbers: flip if hardened
probing pushes a single technique's discovery past **30 s** measured wall time, or if
total autopwn time per target exceeds **180 s** (half the 360 s outer wall at
`run_bench.py:407`). Both are measurable before and after.

---

## 4. Work order — re-derived from the corrected buckets

Rev 1's ordering rested on "A = 3, largest". Corrected, **C = 4 is largest**, and phase 0
is now a precondition for planning phase 2 at all.

| phase | work | R2 targets | R1 exposure (§6.1) |
|---|---|---|---|
| **0** | **Observability, no capability claim.** `is_applicable` states its reason and distinguishes a raised exception from a non-match (§2.3). `timed_out` gets callers across the seven `deliver_parts` modules (§2.4). | none directly | **0** |
| **1a** | **Output-encoding-agnostic value extraction** (§2.2) — widen observation beyond hex text. | 03, 14, part of 05 | `03`, `07` via `ret2libc_leak` |
| **1b** | **`FormatStringPrimitive`**: arbitrary-value/width write, `%s` read, `%N$p` slot leak. Rewrite the gate executor as a consumer. | 06, 12 | `06` |
| **2** | Generalise executor **preconditions** by capability rather than R1 mechanic — *using phase 0's reasons, not target sources.* | 01, 08, 14 | `01`, `10`, `14` |
| **3** | PIE-defeat leak consuming 1a; canary acquisition via relay + `_probe_echo_sizes` retry. | 03, 04 | `03`, `07`, `04`, `05` — **highest** |
| **4** | UAF discovery for dangling globals — *only after phase 0 says why `09` was skipped.* | 09 | none |
| **5** | `02`, `11` — lowest leverage, as directed: each moves exactly 1. | 02, 11 | `02`, `12` |

Phase 0 first because it is the cheapest change with the largest effect on every later
phase's evidence, and phases 2 and 4 are **not plannable without it** — their rev 1
diagnoses were inferences from target sources, which rule 2 forbids relying on.

---

## 5. Rules — predecessor §5 restored **verbatim**, nothing dropped

1. No fix may name a target, a slug, or a corpus path.
2. **No constant, offset, address, or prompt string taken from a reference exploit may
   enter the pipeline.** Live for phase 1: `0x1337` appears at `ablate_r2.py:471` and in
   `corpus_r2_reference/15_ret2win_arg_gate_reference.py:45`. The pipeline must *recover*
   it, never be told it.
3. Every fix must be expressible as "the pipeline can now do X", where X is a capability,
   **with its reliability split.**
4. **For each fix, record the falsifiable prediction of what a later round would show if
   the fix were secretly target-specific** — before measuring.
5. Never weaken verification logic or corpus vulnerabilities to make a target pass.
6. No self-scoring. `b"flag" in out` inside an executor's *search* loop is a heuristic;
   the *verdict* stays `verifier.verify_script` plus the harness's independent
   re-execution and behavioural attribution.

Added for this phase:

7. **R1 gate asserts per-target solving technique**, not the 13/13 count (§6.1).
8. Implementation on **Sonnet**; plan and review on Opus-tier. Re-review before build.

### 5.1 The write value — the thing that decides capability versus fit (B5)

For `06` the pipeline must write the exact 16-bit `0x1337`. Three routes, and **only one
is acceptable**:

| route | verdict |
|---|---|
| **Recover the constant from the comparison immediate** in the gate's instruction stream | **Required.** A real capability: it generalises to any exact-value gate. |
| Sweep plausible values until one passes | **Prohibited.** Passes `06`, learns nothing, and is undetectable from the score. |
| Read `0x1337` from the target source or a reference exploit | **Prohibited** by rule 2. |

Both prohibited routes yield +2 on R2 with zero capability gain, and **no gate in rev 1
could distinguish them.** New gate: phase 1's commit must show the recovered value's
*provenance* — the instruction address and decoded immediate it came from — and a unit
test on a fixture with a **different** magic constant, built for the test and never
disclosed to the pipeline. Rule 4 prediction: *if this is secretly fitted, a later round
with a different constant fails while `06`-shaped targets pass.*

Spec correction (rev 1 was wrong): on x86-64 `%hhn` = 1 byte, `%hn` = 2, `%n` = **4**,
`%lln` = 8. `06` needs `%hn`.

---

## 6. Test strategy

- **Unit**: primitives against purpose-built fixtures in `tests/`, **never** corpus
  targets — a primitive tested only on R2 is fitted to R2. Includes the different-magic
  fixture from §5.1.
- **Regression — the only real gate (see §6.2)**: full R1 at `--reps 5 --jobs 8
  --timeout 20`, asserting **13/13 and the per-target technique map** below.
- **R2 measurement**: same config, both attribution modes, `solved` + `reliability`
  split, in a report titled **training performance on R2**.

### 6.1 R1 per-target technique map — the gate's actual assertion

Measured from the baseline run (`15215b6`). A phase that changes any target's solving
technique must justify it explicitly; a phase that makes a target pass by a *different*
route has not demonstrated the capability it claims.

| solving technique | R1 targets | phase that risks it |
|---|---|---|
| `canary_leak_ret2win` | **04, 05** | 3 |
| `ret2libc_leak` | **03, 07** | 1a, 3 |
| `fmtstr_write_gate` | **06** | 1b |
| `stack_shellcode` | 01 | 2 |
| `int_truncation_bypass` | 10 | 2 |
| `negative_index_write` | 14 | 2 |
| `ret2plt` | 02 | 5 |
| `tcache_poison_got` | 12 | 5 |
| `ret2dlresolve` | 08 | — |
| `srop` | 09 | — |

**Phase 3 carries the highest regression exposure — 4 R1 targets — not phase 1.** Rev 1
did not have this table and so could not see that.

### 6.2 The ablation gate is a corpus tripwire, not a fix gate (M2)

`ablate_r2.py` imports nothing from `supwngo` and drives hand-written reference chains
against corpus binaries. **No pipeline change can move one of its verdicts.** Rev 1's
claim that it tests the necessity *of a fix* is withdrawn.

It is retained, with its real purpose: a tripwire that fires if the **corpus** is
accidentally edited — which is the cardinal rule expressed as an executable check. Run
before and after the phase series; 15/15 positive controls and 51/51 blocked must be
unchanged. It is **not** counted as one of the three gates rev 1 claimed. After this and
B6, regression coverage is **one** gate, which is why §6.1 makes it technique-aware
rather than count-only.

---

## 7. Risks

| risk | handling |
|---|---|
| **Phase 3 breaks 2 R1 targets via `canary_leak_ret2win` (04, 05) plus 2 via `ret2libc_leak` (03, 07)** | highest-exposure phase; gate per §6.1 runs after each phase, not once at the end |
| Phase 1b breaks R1 `06` | 1 target; flip condition §3, legacy `_payload` as in-primitive fallback |
| Phase 1a changes what counts as a leak, affecting `ret2libc_leak` (R1 03, 07) | widening observation should be additive; assert both targets keep `ret2libc_leak` |
| **Phase 1 passes `06` by sweeping or by a source-read constant** | §5.1: provenance shown in the commit, plus a different-magic fixture |
| Hardened probing slows discovery | Fork B thresholds: 30 s per technique, 180 s per target, measured |
| "Training performance" quoted as generalization | post-dev report titled so, and says so in its first line |
| Fixes drift toward R2 shapes under score pressure | rules 1–4; each commit states the capability and its rule-4 prediction |

## 8. Residual limits inherited

Cold report residual limits 1–6 carry forward, **with limit 1 as corrected by erratum
`be0874d`**: there is no 20 s per-technique budget; the real bounds are hardcoded
1.5–3.0 s probes at 8 call sites under a 360 s outer wall, and `--timeout` bounds
verification rather than discovery. Limit 6 stands unchanged: **R2 can never separate
flag-delivery mechanism from technique class**, so nothing here can validate that axis.
