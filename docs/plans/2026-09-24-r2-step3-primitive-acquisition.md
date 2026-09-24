# R2 step 3 — close the primitive-acquisition gap, generally

**Date:** 24 Sep 2026
**Branch:** `bench/round2-cold-and-dev-20260924`
**Predecessor:** `docs/plans/2026-09-24-benchmark-round2-cold-then-develop.md` (rev 3)
**Cold figure this develops against:** 4/15, committed at `40bd6ca` / `9f31360`
**Status:** plan, awaiting same-tier peer review before implementation

---

## 1. Goal, and what success is not

Raise R2 by fixing what genuinely failed, **without** fitting to R2's surface shapes.

The post-development R2 number is **training performance**, not generalization. R2's
capacity to measure generalization was spent by the cold run. Only R3/R4/R5 can
measure it again, and §2.10.2 of the cold report is the standing warning: nine
technique families already failed to survive *one* change of surface mechanic. A fix
fitted to R2's mechanics would reproduce that failure on R3 exactly.

**Primary success criterion is therefore not the R2 score.** It is: *each fix is
expressed as a capability that does not name a target, and R1 still holds 13/13.*
The R2 number is a secondary readout.

---

## 2. Evidence-based diagnosis — which replaces the pre-run hypothesis

The pre-registered triage classified the nine 5/5-stub targets as "discovery failure,
cause undetermined". **That verdict was correct as a pre-registered call on the
evidence then available, and is now superseded by better evidence.** The stub scripts
carry a full per-technique attempt log; the cause is recorded, not undetermined.

Recording the correction explicitly because it changes the work order, and because
"cause undetermined" was published:

> The stub marker means *no technique was **verified***, not *no technique was
> **proposed***. Discovery ran on all nine and proposed techniques on seven of them.

### 2.1 What actually blocked each of the 11 failures

| # | target | recorded cause | bucket |
|---|---|---|---|
| 05 | `fmtstr_pie_leak` | `fmtstr_write_gate` FAILED: found arg index, no gate variable unlocked the win path; `format_string` PARTIAL: *"format-string write automation is out of scope (Phase 5)"* | **A** missing primitive |
| 06 | `fmtstr_short_write` | same pair; target needs an exact 16-bit value via `%hn`, executor only writes *non-zero* | **A** + **C** |
| 12 | `fmtstr_got_overwrite` | same pair; target needs a **GOT** write, executor only considers "gate variables" | **A** + **C** |
| 03 | `pie_write_leak_ret2libc` | `ret2libc_leak` SKIPPED: *"target is PIE but printed no code pointer, so the image base is unknown (a separate PIE-defeating leak primitive would be needed first)"* | **B** missing primitive, correctly self-diagnosed |
| 01 | `stack_shellcode_relay` | `stack_shellcode` FAILED: *"shellcode was placed past the return address but no offset candidate / NOP-sled size combination produced a verified shell"* — overflow is a relay through an intermediate buffer, not a direct `read()` | **C** shape-fitted |
| 04 | `canary_relay_bypass` | `canary_leak_ret2win` FAILED: *"canary is enabled but the target never hands it back (no over-long raw echo, no user-controlled printf format)"* — the canary is **relayed**, not raw-echoed | **C** shape-fitted |
| 08 | `int_mul_overflow` | `int_truncation_bypass` SKIPPED "not applicable" — detector matches plain truncation, target is a *multiplication* overflow | **C** shape-fitted |
| 14 | `oob_read_flag_array` | `negative_index_write` SKIPPED "not applicable" — R1's shape was a **negative** index **write**, R2's is a **positive** OOB **read**; no OOB-read technique exists at all | **C** shape-fitted |
| 09 | `heap_dangling_global` | `uaf` SKIPPED "not applicable" — the dangling-global UAF is not recognised | **D** discovery gap |
| 02 | `ret2plt_strcat_system` | real technique generated and ran, no flag | **E** |
| 11 | `heap_overflow_tcache_poison` | real technique generated and ran, no flag | **E** |

Buckets: **A** format-string write primitive absent (3) · **B** PIE-defeat leak
primitive absent (1) · **C** executor precondition fitted to R1's mechanic (4) ·
**D** vulnerability not recognised (1) · **E** technique reached and failed (2).

### 2.2 The `_probe_echo_sizes` / `deliver_parts` bug is not the main cause

Held at the pre-registered "cause undetermined" through the cold run, and now
resolvable on evidence: of the nine stubs, **only `04` plausibly touches that path**
(it is the one whose failure text turns on an echo probe). The other eight failed for
reasons unrelated to probe timing. So the empirical test proposed for it — fix
`deliver_parts` and see whether stubs become techniques — **can move at most 1
target, not 9.**

It remains a real bug worth fixing (cheap, and it improves diagnosis fidelity for
every future round by making a timeout distinguishable from an empty response). It is
therefore scheduled **with the canary work in phase 3, not as phase 1.** Sequencing it
first would have spent the highest-attention slot on the smallest lever.

### 2.3 `FmtStrWriteGateExecutor` is shape-fitted in three independent ways

`supwngo/exploit/pipeline/executors/fmtstr_techniques.py:61`. Each of these is
individually sufficient to fail an R2 target:

1. **Writes only a non-zero value.** The success note is literally *"wrote a non-zero
   value to …"*. R2 `06` gates on an exact 16-bit magic value, so "non-zero" cannot
   satisfy it.
2. **Candidate addresses are "gate variables"** — writable globals plus printed
   pointers (`_write_targets`). The GOT is never a candidate, so R2 `12` is
   unreachable.
3. **`is_applicable` requires `context.win_function is not None`.** A target whose
   route is *leak first, then redirect* (R2 `05`) is refused before it starts.

This is the concrete mechanism behind §2.10.2's paired result: the executor encodes
R1 `06`'s mechanic ("8-byte `%n` write to make a bool nonzero") rather than the
capability ("format-string arbitrary write").

---

## 3. Two methods weighed

### Fork A — a primitive layer, or more executors?

**Option 1 (chosen): introduce an explicit primitive layer and make executors thin
consumers of it.** A `FormatStringPrimitive` exposing `write(addr, value, width)` over
`%hhn`/`%hn`/`%n`, `read(addr)` over `%s`, and `leak_slot(index)` over `%N$p`. The
three R2 format-string targets then stop being three problems and become three
*applications*: an exact-value write, a GOT write, and an image-base leak.

- Cost: larger diff; touches a code path R1 currently passes through, so it carries
  real regression risk against the 13/13 gate.
- Benefit: one implementation covers the exact-value gate, the GOT overwrite, the PIE
  leak, and shapes nobody has written yet — including R3's, which is the whole point.

**Option 2 (not taken): add `fmtstr_exact_write`, `fmtstr_got_overwrite`,
`fmtstr_pie_leak` as three new executors alongside the existing one.** Cheaper, lower
regression risk, and would very likely move R2 by +3 this week. Rejected because it is
precisely the inflation the predecessor plan's §5 forbids: three more executors each
encoding one R2 mechanic, which R3 would break the same way it broke the existing one.
It would raise the score without raising capability.

**What would flip this decision:** if the R1 13/13 regression cannot be held while
refactoring the shared path. The response then is *not* to fall back to Option 2, but
to land Option 1 behind a selection flag with the existing executor retained as a
fallback — keeping the general primitive as the primary route while preserving the R1
path verbatim.

### Fork B — dynamic probing or static call-site analysis for the argument index?

**Option 1 (chosen): keep dynamic probing, harden it.** `_find_buffer_arg_index`
already works — it correctly located the index on all three R2 format-string targets,
which the attempt logs confirm. Add retry and timeout/empty disambiguation.

**Option 2 (not taken): recover the index statically from the `printf` call site.**
More precise and budget-free at runtime, but brittle across compilers, optimisation
levels and inlining — and a static reader is a new source-shaped dependency in a
pipeline whose premise is working from the binary.

**What would flip it:** evidence that probing cannot fit the 20 s per-technique budget
once retries are added. Measure before assuming; the budget is residual limit 1 and is
already the tightest constraint.

---

## 4. Work order, by measured leverage

Deviating from the ordering suggested at GO, because §2.1 refines the hypothesis it
rested on. The *principle* given was "order by leverage"; following it on the evidence
requires this order. Flagged explicitly rather than silently re-sequenced.

| phase | work | targets in scope | bucket |
|---|---|---|---|
| **1** | `FormatStringPrimitive`: arbitrary-value / arbitrary-width write, `%s` read, stack-slot leak. Rewrite `FmtStrWriteGateExecutor` as a consumer; drop the three shape constraints in §2.3. | 05, 06, 12 | A + C |
| **2** | Generalise executor preconditions so applicability is tested by *capability*, not by R1's mechanic: relay-through-buffer overflow (01), multiplication as well as truncation overflow (08), OOB **read** as a first-class outcome (14). | 01, 08, 14 | C |
| **3** | PIE-defeat leak primitive feeding `ret2libc_leak` (03); canary acquisition via relay, plus the `deliver_parts` timeout/empty disambiguation (04). | 03, 04 | B + C |
| **4** | UAF discovery for dangling globals (09). | 09 | D |
| **5** | `02_ret2plt_strcat_system`, `11_heap_overflow_tcache_poison` — lowest leverage, as directed: the pipeline already reaches the technique stage on both, so each fix moves exactly 1. | 02, 11 | E |

Phase 1 is first on three counts: it is the largest single bucket, its gap is
*declared* in the source (`"out of scope (Phase 5)"`) rather than inferred, and the
primitive it adds is a prerequisite for several later phases.

---

## 5. Rules carried forward from the predecessor plan §5

1. No fix may name a target, a slug, or a corpus path.
2. No fix may key on a string the corpus happens to print.
3. Every fix must be expressible as "the pipeline can now do X", where X is a
   capability, not a target.
4. **Never weaken verification logic or corpus vulnerabilities to make a target pass.**
   Cardinal rule. A fix that edits `benchmark/` to pass is a defect, not a fix.
5. No self-scoring. `b"flag" in out` inside an executor's *search* loop is fine —
   that is a search heuristic. The *verdict* remains `verifier.verify_script` plus the
   harness's independent re-execution and behavioural attribution.

Added for this phase:

6. **Regression gate before any R2 re-measurement:** R1 must hold 13/13. A phase that
   raises R2 and lowers R1 is rejected, not traded off.
7. Implementation on **Sonnet**; this plan and its review on **Opus**-tier models, per
   the repo contract. Peer review by an independent same-tier model before build.

---

## 6. Test strategy

- **Unit**: `FormatStringPrimitive` write/read/leak against purpose-built fixtures in
  `tests/`, *not* against corpus targets — a primitive tested only on R2 is a primitive
  fitted to R2.
- **Regression**: full R1 run, `--reps 5 --jobs 8 --timeout 20`, must report 13/13.
- **Ablation**: `ablate_r2.py` must still return 15/15 positive controls and 51/51
  blocked after any change. A fix that also makes an ablated chain succeed has broken
  the corpus's necessity property and is a defect.
- **R2 measurement**: same configuration, reported in both attribution modes with the
  `solved` + `reliability` k/N split, in a separately titled report labelled **training
  performance on R2**.

## 7. Risks

| risk | handling |
|---|---|
| Refactoring the shared fmtstr path breaks R1 | R1 regression gate runs before R2 is re-measured, not after; fallback is the flagged-dual-path response in Fork A, never Option 2 |
| Added retries push techniques past the 20 s inner budget | measure probe cost before and after; residual limit 1 says this budget is already tight |
| Fixes drift toward R2's shapes under score pressure | rules 1–3; every phase's commit message must state the capability added without naming a target |
| "Training performance" gets quoted as generalization | the post-dev report is titled as training performance and says so in its first line |

## 8. Residual limits inherited, not closed

Residual limits 1–6 from the cold report §2.9 carry forward unchanged. In particular
limit 6: **R2 can never separate flag-delivery mechanism from technique class**, so
nothing in this plan can validate that axis — it is R5's job.
