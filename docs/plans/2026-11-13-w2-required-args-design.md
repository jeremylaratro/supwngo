# W-2 — required-args extraction: constants from the binary (class B) (2026-11-13, Rev 3)

Detailed design for **directive W, phase W-2**. Parent plan:
`docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md` (§3 principle 3 / §82-84, §4 row W-2 / §130,
§12 class-B notes / §240). Builds directly on **W-1** (`supwngo/analysis/payoff.py` + `SupwngoPayoff.java`,
merged PR #39, `9f543bb`). Branch `feat/w2-required-args` off `main` `9f543bb`.

> **Rev 3 — reworked after a second independent review of Rev 2 returned REWORK.** The Rev-2 edge-domination
> idea is kept and is sound, but the material defects around it are fixed:
> - **Requiredness runs inside `analyze()` over the live `HighFunction`** — Rev 2 falsely claimed "W-1 records
>   the sink CALL op." It does not; `Evidence` (`SupwngoPayoff.java:392`) stores only `sinkApis`/`sinkTargets`.
>   The pass uses the transient `op`/`hf`/`f` while they are live, over the **const-string-target sinks only**
>   (§2.2, §3).
> - **Slot lattice is a true join with `AMBIGUOUS` as top** and an **entry-value guard** (`isInput()` or a
>   value-preserving def chain): a *redefined* parameter (`a = a*2; if (a==X)`) can no longer emit a wrong
>   value as `known` (§2.1, B1/B2).
> - **A collective ungating test (Test U)** separates a genuinely unconstrained sink (`known + []`) from a
>   disjunctive/relational gate (`unknown` → legacy fallback), removing the Option-A capability regression
>   Rev 2 introduced (§2.2, §2.3, B3).
> - **Fan-out, baseline reachability, multi-sink scoping, and `(slot,value)` dedup** are specified (§2.2, B4/B6).
> - **Args flow through `FunctionEvidence` → `score_function` → `PayoffEvidence`**, with `__post_init__`
>   invariants guarding both the envelope and the cache-deser paths, and a **per-record `try/catch`** so one
>   bad function can't downgrade the whole report (§4, B8).
> - **Decoy + filler records are swept** as the real anti-hallucination control (Rev 2's T3 was vacuous), and
>   **two new falsifiers** (`gate_relational`, `gate_arith`) make B1/B2/B3 falsifiable in the corpus (§3a, §6, B7).
> - **Ret2win rewire looks up the candidate by `rva == win_addr`** (not `candidates[0]`), degrades to the legacy
>   path on `unknown`/non-`COMPLETE` (so a wrong `known` on an optimized binary is impossible, not merely
>   unlikely), maps `position → reg` with a **loud failure above arg 3**, and scopes the end-to-end proof to a
>   dedicated overflowable fixture (§5.4, §6 T12, B9).
>
> Rev 1→2 changes (provenance ≠ gating; serialized provenance; exact-emptiness decoy tests; versioned cache;
> evidence-based disposition table resolving the parent's §130-vs-§240 contradiction; pinned slot API) are
> retained. Parent amendments this requires are in §9.

## 0. Goal (exact, from the parent plan's Done-when, as amended in §9)

Given a binary and the payoff RVA that W-1's `rank_payoffs` already identifies, recover the payoff's
**required argument constants** — the fixed values a caller must pass so that the payoff's own
parameter checks let control reach its W-1 sink — **from the binary**, not from a guessed list:

- On the **16/16 argument-checked positives** (corpus shapes `arg1` and `arg3`), the recovered
  `required_args` **equals truth** (`[{position, value}, …]`, 1-based position), **and every recovered value
  carries serialized parameter-slice provenance** that terminates at a `HighParam` (§2.4) — each value is
  proven to come from a comparison that (a) slices back to a specific formal parameter *entry value* and (b) is
  **required on every path to the sink** (§2.2).
- The **exec/file positives (16/16)**, the decoy/filler functions, and the **non-gating falsifiers**
  (`gate_audit`, `gate_invert`) yield `args_status=="known"` with **`required_args == ()` exactly**. The
  **unresolvable-gate falsifiers** (`gate_disj`, `gate_relational`, `gate_arith`) yield
  `args_status=="unknown"` with an empty list and a `reason` — a real gate W-2 cannot pin to a single required
  value, which must therefore **not** suppress the legacy fallback (§2.3, §5.4, §6 T3/T4). A spurious arg is
  never emitted for any of them.
- Every **class-B** baseline inventory entry (69, all `open` at W-0) is resolved to **`migrated`**,
  **`allowed`**, or **`reassigned`** (to a later phase), each with a justification string, per the disposition
  table in §5 (audit result: **27 `allowed` / 42 `reassigned` / 0 `migrated`**). The inventory test is green on
  the class-B slice.
- **The ret2win arg path is redirected onto the new extractor (Option A, §5.3/§5.4).** `_discover_args` sources
  `(position, value)` from the extractor for the pipeline-chosen win function (looked up by RVA), maps each
  position to the correct register, and reaches the win call — proven by a seam test (always-run) and an
  end-to-end test on a dedicated overflowable `arg1`/`arg3` fixture (§6 T12). The weak, symbol-dependent,
  mis-ordering `find_required_args` is deprecated on that path.

Non-goals (deferred): class A/A′ payoff-name migration (W-5), success detection (W-3), dynamic confirmation
(W-4), and **robustness to compiler optimization** (the dev corpus is `-O0`, `generate.py:101`; W-2 makes no
`-O1`/`-O2` claim — see §6 note and R7). W-2 is **static extraction + inventory resolution**, plus the **single
owner-approved ret2win arg-path rewire** (§5.4); no *other* consumer is rewired to read `required_args` (that is
W-5). Range/inequality satisfaction (a gate needing `a>K` or `a∈{X,Y}`, not a single value) is out of scope: W-2
reports those `unknown` so a later phase or a provided component handles them.

## 1. Why a P-code scan is style-agnostic (necessary, not sufficient)

The corpus writes the argument gate three ways (`payoff_source.py:234-250`): `and`
(`if (a==X && b==Y) {sink}`), `nest` (nested `if`s), and `early` (`if (a!=X) return; … sink`). All three
lower, in Ghidra's decompiler P-code, to the **same** shape: an `INT_EQUAL` / `INT_NOTEQUAL` op comparing a
**parameter varnode** against a **constant varnode**. So W-2 does **not** parse source or match control-flow
templates; it scans the payoff's decompiled P-code for integer-equality comparisons.

**But style-agnosticism is not requiredness.** A parameter-vs-constant comparison proves only *where an
operand came from*, not that *satisfying it is necessary to reach the sink*. The same P-code shape appears in
all of these, where the arg is **not** a single required value:

```c
if (a == X) audit();   system("/bin/sh");   // X gates a non-sink call; sink is unconditional  → known, []
if (a == X) return;    system("/bin/sh");   // reaching the sink requires a != X (no single required value) → known, []
if (a == X || a == Y)  system("/bin/sh");   // a ∈ {X,Y}: neither individually required → unknown (fall back)
if (a > K)             system("/bin/sh");   // a range, not a value → unknown (fall back)
a = a * 2; if (a == X) system("/bin/sh");   // required value is X/2, not X → unknown (never emit X)
```

The corpus `and`/`nest`/`early` positives happen to use only the favorable forms, so a bare scan would pass on
them — that is corpus compatibility, not a requiredness proof. §2.2 adds the control-flow test that
distinguishes these, and §3a adds a corpus falsifier for each false shape above.

## 2. Provenance + requiredness model (the discriminator)

A `required_arg {position, value}` is emitted **iff** an `INT_EQUAL`/`INT_NOTEQUAL` P-code op in the payoff's
`HighFunction` satisfies **all three**:

1. **one input resolves to a complete formal-parameter *entry* value** under the slot lattice (§2.1) —
   `PARAM(slot, width, full)` with `full == true`;
2. **the other input is a constant varnode** (`Varnode.isConstant()`); and
3. the equality is **individually required on every path to every (const-string) W-1 sink** under the
   edge-domination test (§2.2).

Everything else is either **skipped** (not a parameter gate at all) or **taints the function to `unknown`**
(a parameter gate is present but cannot be pinned to a single required value — §2.3). This is **fail-closed**:
a comparison of a local/global against a constant (the decoy shape) has no `PARAM` operand (condition 1 fails)
→ skipped; a constant that only appears as a sink argument is in no equality against a parameter → skipped; a
parameter compared against a non-constant → skipped; a parameter gate that *is* required but whose slot/value
cannot be pinned, or a disjunctive/relational/transformed gate, → `unknown` (never a guessed position, never a
silently-dropped gate).

### 2.1 Slot lattice with an entry-value guard (MAJOR 1 / BLOCKER B1, B2)

W-1's `traceTarget` returns `PARAM` if **any** `MULTIEQUAL` arm is a parameter (`SupwngoPayoff.java:299`) and
treats a computed value as plain non-param. That is sound for *disqualifying a sink target* but unsafe for
*assigning an argument value*: (a) a phi merging parameter 1 and parameter 2 must not select either slot, and
(b) a **redefined** parameter varnode (`a = a*2; …`) whose `getHigh()` the decompiler still labels `HighParam`
must not report its post-arithmetic constant as the required value. W-2 uses a dedicated tracer
`traceParamSlot(Varnode)` over an explicit three-point lattice ordered `NONPARAM, PARAM ⊏ AMBIGUOUS`
(`AMBIGUOUS` is **top**):

- **`NONPARAM`** — proven to carry no formal-parameter value (a local, a global, a constant, or a value all of
  whose inputs are `NONPARAM`).
- **`PARAM(slot, width, full)`** — carries formal parameter `slot`'s **entry** value; `full == true` only when
  the whole parameter value participates and no non-value-preserving op intervened.
- **`AMBIGUOUS`** (top) — param-derived but the slot/slice/value cannot be pinned (a transform, a phi over
  different slots, a partial slice, an indirect).

**Entry-value guard.** A varnode is `PARAM(slot, size, full=true)` **only** when it is the formal input itself
(`v.isInput() && v.getHigh() instanceof HighParam`) **or** it is reached from such an input through a def chain
of **only value-preserving ops** (`COPY`, `CAST`, and width-safe `INT_ZEXT`/`INT_SEXT`, §below). A `HighParam`
-labelled varnode with **any other defining op** is `AMBIGUOUS`, not `PARAM` — this closes B1.

Transfer functions (a true lattice join; any op not listed, applied to a `PARAM`/`AMBIGUOUS` input, yields
`AMBIGUOUS` — this closes B2):

| opcode | result |
|---|---|
| input varnode, `getHigh() instanceof HighParam` | `PARAM(getSlot(), size, full=true)` |
| `COPY`, `CAST` of `PARAM(full)` | pass through unchanged |
| `INT_ZEXT`/`INT_SEXT` of `PARAM(full)` | `PARAM(slot, extended_width, full=true)` **only if** the compared constant is representable in the **source** param width (so `ZEXT(a)==X` ⇔ `a==X`); otherwise `AMBIGUOUS`. The corpus keeps constants in 31 bits (`CONST_RANGE`, `payoff_source.py:81`), so its positives satisfy this. |
| `SUBPIECE` (partial slice) | `AMBIGUOUS` — a byte/word slice does not prove equality of the whole formal parameter |
| `INDIRECT` | `AMBIGUOUS` — not guaranteed value-preserving |
| `PTRSUB`, `PTRADD` | `AMBIGUOUS` — addresses a location, not a scalar value |
| `INT_ADD/SUB/MULT/AND/OR/XOR/LEFT/RIGHT/…` (any arithmetic/logic) with a `PARAM`/`AMBIGUOUS` input | `AMBIGUOUS` — param-derived, value not invertible to a single required constant |
| `MULTIEQUAL` (phi) | **join**: `PARAM(s,w,full)` iff **every** non-back-edge arm is `PARAM` with the **same** slot and `full==true`; a self-referential loop back-edge arm contributes nothing (skipped); if **all** arms are `NONPARAM` → `NONPARAM`; **any other mix** (a `PARAM`+`NONPARAM`, two different slots, a partial) → `AMBIGUOUS` |
| all inputs `NONPARAM` | `NONPARAM` |

For a candidate equality op: classify both inputs.
- exactly one input `PARAM(full)` and the other `isConstant()` → a **pinnable** gate candidate `(slot+1, const)`.
- exactly one input `AMBIGUOUS` and the other `isConstant()` → a **param gate we cannot pin** → this equality,
  **if it is required** (§2.2), taints the function `unknown(reason=ambiguous_slot)`.
- neither input param-ish (both `NONPARAM`), or the other input non-constant → **not an argument gate** → the
  op is ignored for emission (but a param-dependent branch still participates in Test U, §2.2).

### 2.2 Requiredness via edge-domination + a collective ungating test (BLOCKER 1 / B3, B4, B5, B6)

**Where the data comes from (B5).** W-1 does **not** persist the sink CALL op — `Evidence`
(`SupwngoPayoff.java:392`) stores only `sinkApis`/`sinkTargets`. The requiredness analysis therefore runs
**inside `analyze()`** (the method that already walks `hf.getPcodeOps()` and finds each sink `op` at
`:435-450`), while `op`, `hf`, and `f` are live. The **sink set** for the tests below is **exactly the sink
CALL ops whose target `Trace` resolved to a constant string** (`EXEC_FAMILY`/`FILE_OPEN_FAMILY` with a
`CONST_STRING` target — the sinks that made the function a payoff hypothesis in the first place), gathered in
that same loop. Param-target and unknown-target sinks are **not** in the set.

Let `Entry = hf.getBasicBlocks()[0]` (the decompiler lists the entry block first; verified live in de-risk step 2).
Let `Sinks` = the parent `PcodeBlockBasic` of each const-string sink op (via `op.getParent()`).

**Step 0 — baseline reachability (B6).** If any block in `Sinks` is **not reachable** from `Entry` in the
uncut block graph (e.g. an unresolved `BRANCHIND`/jump table leaves the CFG irreducible), do not run the cuts
— emit nothing and taint `unknown(reason=irreducible_cflow)`. (Otherwise a vacuously-"dominating" edge would
false-emit.)

**Collect param-dependent branches.** Walk every `CBRANCH`. Trace its boolean condition back (counting
`BOOL_NEGATE`, `INT_EQUAL`/`INT_NOTEQUAL`, `INT_SLESS`/`INT_LESS`/… ) to its ultimate comparison. A branch is
**param-dependent** if that comparison has a `PARAM` or `AMBIGUOUS` operand (per §2.1). For each, determine its
**satisfying edge**:
- an `INT_EQUAL`(param, const) / `INT_NOTEQUAL`(param, const) with a single `CBRANCH` consumer → the out-edge
  taken when `param == const` holds (from the op kind, the `CBRANCH` target semantics, and `BOOL_NEGATE`
  parity);
- anything else param-dependent (relational, `strcmp`-result, `AMBIGUOUS`, or an equality whose boolean
  **fans out to ≠1 `CBRANCH` or to a non-branch use** — B4) → its satisfying edge is **indeterminate**;
  conservatively mark **both** out-edges.

**Step 1 — individual requiredness (emit).** For each **pinnable** candidate equality `E` (§2.1,
`PARAM(full)` vs const) with a single governing `CBRANCH` and a determinate satisfying edge `s_E`: cut `s_E`
alone and test reachability of **every** block in `Sinks` from `Entry`. If **all** become unreachable, `E` is
required on every sink path → **emit** `(slot+1, value)` with provenance (§2.4). If an equality that is
required this way is **`AMBIGUOUS`** (not pinnable) or compares against a non-constant → taint
`unknown(reason=ambiguous_required_gate)`.

**Step 2 — collective ungating (Test U — B3).** Cut **all** marked satisfying edges (determinate ones for
resolvable equalities, both edges for indeterminate param-dependent branches) **simultaneously**, then test
whether any block in `Sinks` is reachable from `Entry`:
- **reachable ⇒ ungated.** No parameter equality is needed to reach the sink. Any non-emitted equality is a
  genuine non-gate (e.g. `gate_audit`: both edges reach the sink) or a value-avoidance guard (`gate_invert`:
  reaching the sink needs `a != X`, satisfied by a default). → contributes to `known`.
- **unreachable ⇒ gated-but-unresolved.** The sink needs *some* param condition, but Step 1 pinned no single
  required equality for it — a disjunction (`a∈{X,Y}`), a relational (`a>K`), a transformed compare
  (`(a*2)==X`), or an indeterminate/ambiguous branch. → taint `unknown(reason=unresolved_gate)` so the legacy
  fallback still applies (no regression, §5.4).

**Multiple sinks.** The "all blocks in `Sinks`" quantifier in Steps 0–2 enforces that a gate must dominate
**every** const-string sink to be emitted; a gate dominating only one of two sinks is not universally required.

**Conflicts.** If Step 1 emits two gates assigning **different** values to the **same** slot (an unsatisfiable
`a==X ∧ a==Y` on every sink path), taint `unknown(reason=conflict)`. Distinct slots each with one value (the
`arg3` case) all emit independently. **Dedup:** identical `(slot, value)` pairs are collapsed before emission
(B6), so a decompiler CSE that re-tests the same equality does not create a false conflict or a duplicate.

**Why this is correct on the falsifiers** (worked in §3a; summarized): `gate_audit`→ungated→`known,[]`;
`gate_invert`→ungated (cut the `a==X`→`return` edge, `a!=X`→sink remains)→`known,[]`; `gate_disj`→not
individually required, and cutting both `==X`/`==Y` satisfying edges disconnects the sink→`unknown`;
`gate_relational`/`gate_arith`→the controlling compare is non-equality or the operand is `AMBIGUOUS`, both
edges cut, sink disconnected→`unknown` (and `gate_arith` never emits the literal `X`). The genuine `early`
positive (`if(a!=X)return; sink`) still emits: the `a==X` satisfying edge is the `INT_NOTEQUAL`-false edge,
the only route to the sink, so cutting it disconnects the sink → required → emit `X`.

### 2.3 `args_status`: two states + an explicit reason (BLOCKER 2 / B3, MINOR 2)

The record carries a status and, when `unknown`, a machine-readable `reason`; the empty list is never
ambiguous:

- **`known`** — the payoff was **successfully decompiled** and its parameter gates fully analyzed. The list is
  authoritative. It is **empty iff the sink is ungated** (Test U reachable, §2.2): no parameter equality is
  required to reach it. This covers the `exec`/`file` payoffs (no checked params), the decoy/filler functions
  (compares against non-params), and the non-gating falsifiers `gate_audit` (non-sink gate) and `gate_invert`
  (an inequality with no single required value — a default argument reaches the sink, so suppressing the legacy
  fallback here is correct, not a regression).
- **`unknown` (+`reason`)** — the payoff was decompiled, **a parameter condition that gates the sink exists but
  cannot be pinned to the single required value(s)**: `unresolved_gate` (disjunction/relational/transformed —
  `gate_disj`/`gate_relational`/`gate_arith`), `ambiguous_slot`, `ambiguous_required_gate`, `conflict`,
  `fanout`, or `irreducible_cflow`. The list is empty. `unknown` means "there is a required param gate I cannot
  trust — do not suppress the fallback," never "I found constants that aren't gates." This is the state the
  legacy path keys off (§5.4).
- **Decompile failure is not a per-function `unknown`.** W-1 returns `null` on decompile failure
  (`SupwngoPayoff.java:407`), omits the record, and the pass is incomplete (`:519`) ⇒ the **report** is
  `DEGRADED`. `args_status=="unknown"` applies only to a *successfully decompiled* record whose argument
  analysis was incomplete.

**Invariant:** `args_status=="unknown"` ⇒ `required_args == ()` and `reason != None`; `args_status=="known"`
⇒ `reason == None`. Enforced in `__post_init__` and envelope parsing (§4).

This refines the parent's literal "decoys give `args: unknown`" (§130) and the §82 "otherwise `unknown`"
phrasing; the amendment is in §9. The anti-hallucination property the parent wants — unrelated immediates
never becoming arguments — is enforced more strongly here (exact emptiness on every non-payoff record, §6
T3/T3′) than the original "unknown" phrasing would have.

> **Note (reasoned divergence from the review).** The reviewer grouped `gate_invert` with `gate_disj` as a
> "real param gate" that should be `unknown`. W-2 classifies `gate_invert` as `known,[]` on purpose: its only
> constraint is `a != X`, which has **no single required value** and is satisfied by essentially any default
> argument, so reaching the sink needs no arg setup — and routing it to the legacy fallback is actively
> harmful (the fallback returns `[X]`, which ret2win would load into `rdi`, *taking* the `a==X` return branch
> and missing the sink). `gate_disj`/`gate_relational` genuinely need a value the default won't supply, so they
> are `unknown`→fallback. Test U (§2.2) is exactly the discriminator: `gate_invert` is reachable with the
> satisfying edge cut, `gate_disj` is not. Flagged for the re-review to adjudicate.

### 2.4 Recorded provenance (MAJOR 2)

The parent (§82-84) requires the provenance to **record the slice**, not merely that a tracer ran internally.
Each emitted arg is serialized as an object, not a bare pair:

```
{ "position": <int ≥ 1>, "value": <int>,
  "slot": <int ≥ 0>, "width": <int>,
  "op": "INT_EQUAL"|"INT_NOTEQUAL", "op_addr": <unsigned>,
  "sink_addrs": [<unsigned>, …],
  "transform": ["COPY","INT_SEXT", …] }   // the param→compare value-preserving slice chain, entry-first
```

`value` is the constant operand masked to the comparison width (31-bit corpus range ⇒ ELF/PE agree). Tests
(§6 T1) read the **raw envelope** and assert every arg's `transform` chain terminates at the `HighParam` for
`slot` and contains only value-preserving ops, and that `op_addr`/`sink_addrs` are present. Python surfaces the
`(position, value)` pair for consumers and keeps the full provenance on the candidate (§4).

## 3. Extractor change (`SupwngoPayoff.java`)

Additive; **no change to the W-1 evidence fields**:

- Inside `analyze(Function f)` (`:407`), after the existing sink-collection loop, call a new
  `extractRequiredArgs(HighFunction hf, List<PcodeOp> constStringSinkOps)` that returns `(status, reason,
  List<RequiredArg>)`. It iterates `hf.getPcodeOps()` for `INT_EQUAL`/`INT_NOTEQUAL`, classifies inputs with
  `traceParamSlot` (§2.1), and applies the edge-domination + ungating tests (§2.2) against the const-string
  sink blocks. The result is stored on a new `Evidence` field and serialized by `appendRecord`.
- **Failure isolation (B8).** `extractRequiredArgs` is wrapped in its **own `try/catch`**. On any exception it
  returns `unknown(reason=analysis_exception)` **for that function only** — it never propagates to
  `analyze()`'s caller and never turns the whole pass incomplete (W-1's COMPLETE invariant is preserved; one
  pathological function cannot downgrade the report to `DEGRADED`/`ERROR`).
- **Slot API (MINOR 1, pinned to Ghidra 12.1.3):**
  ```java
  HighVariable hv = v.getHigh();
  if (v.isInput() && hv instanceof HighParam) { int slot = ((HighParam) hv).getSlot(); }   // 0-based, entry value
  // or, by index: hf.getLocalSymbolMap().getParam(i)  →  HighParam;  getNumParams() bounds i.
  ```
  Prefer `HighParam.getSlot()` over `HighSymbol.getCategoryIndex()`.
- **CFG API:** `hf.getBasicBlocks()` → `PcodeBlockBasic[]`, entry = index `0`; successor edges via
  `getOut(i)`/`getOutSize()` and the conditional `getTrueOut()`/`getFalseOut()`; each sink block is
  `sinkOp.getParent()`. Reachability-with-edges-cut is a plain BFS over the block graph. The exact conditional
  accessors are **verified live** in de-risk step 2 (as the slot API was for W-1).
- **Dedup + ordering:** identical `(slot, value)` pairs are collapsed; emitted args are sorted by `position`
  deterministically before serialization (B6).
- The record gains `"required_args": [ <provenance object>, … ]`, `"args_status": "known"|"unknown"`, and
  `"args_reason": <string|null>`. `SCRIPT_VERSION` bumps **`w1.1` → `w2.0`** (new output contract).
- **Scope of extraction:** the extractor emits args for **every** enumerated function (uniform records, same as
  W-1); the Python side reads args for the chosen payoff RVA only (§5.4). A function with no const-string sink
  skips the requiredness pass and reports `known + []` (no sink ⇒ no required gate to prove).

### 3a. Adversarial falsifiers (new corpus category — BLOCKER 1 / B1, B2, B3, B7)

Five new payoff shapes, each containing a **real const-string sink** (so W-1 still promotes them) but whose
parameter handling is **not** a single required gate. They make the §2.1/§2.2 model falsifiable in the corpus;
a naive scan (Rev-1 model) emits a spurious arg on all five, the §2.2 model on none. Truth per shape:

| shape | source sketch | truth `args_status` | truth `required_args` | kills |
|---|---|---|---|---|
| `gate_audit` | `if (a==X) benign(); sink;` (X gates a non-sink call) | `known` | `[]` | unconditional-sink false positive |
| `gate_invert` | `if (a==X) return; sink;` (reaching sink needs `a!=X`) | `known` | `[]` | inverted-guard false positive (ungated; §2.3 note) |
| `gate_disj` | `if (a==X \|\| a==Y) sink;` (neither individually required) | `unknown` (`unresolved_gate`) | `[]` | disjunction false positive **and** the Option-A fallback regression (B3) |
| `gate_relational` | `if (a > K) sink;` (a range, not a value) | `unknown` (`unresolved_gate`) | `[]` | relational-gate false positive (B3) |
| `gate_arith` | `b = a*2; if (b==X) sink;` (required value is `X/2`) | `unknown` (`unresolved_gate`) | `[]` | **redefined-param wrong-value** emission (B1/B2); test also asserts **no emitted value == `X`** |

Emitted as a **separate `role:"falsifier"` category** in `benchmark/gen/payoff/`, **not** added to `SHAPES` —
so the merged W-1 denominators ("32 positives + 32 twins + 8 negatives + 8 PE", parent §128) are **unchanged**.
Matrix (R6 cost): one non-PIE unstripped ELF per shape (5 units) + a stripped twin and a PE variant of
`gate_disj` (to prove requiredness survives symbol loss and the PE calling convention) = **7 units**.
`index.json` lists each with `role:"falsifier"`, its truth `args_status`/`required_args`, and (for `gate_arith`)
the literal compared constant so the test can assert it is never emitted. **Generator hygiene (MINOR):** the
new category must (a) be skipped by every W-1 counter/test that iterates `index.json` by filtering on `role`,
and (b) draw from the existing `_Consts` stream without perturbing the positives' constants or RVAs — verified
in §7 step 1 by diffing the regenerated positive/twin/negative/PE `index.json` rows against the W-1 baseline.

## 4. Python change (`supwngo/analysis/payoff.py`)

The scoring flow is `_evidence_from_envelope → List[FunctionEvidence]` (`:580/601`) →
`rank_candidates(fes)` (`:307`) → `score_function(fe) -> PayoffEvidence` (`:247`, constructs at `:298`) →
`PayoffCandidate` (`:203`). Args must flow the **whole** way (B8):

- A new frozen `RequiredArg` dataclass mirrors the provenance object (§2.4), with `__post_init__` invariants:
  `position:int≥1`, `value:int`, `slot:int≥0`, `width:int>0`, `op∈{INT_EQUAL,INT_NOTEQUAL}`, `op_addr` present,
  `transform` a tuple of known value-preserving op names; **`bool` rejected as `int`** (reuses the W-1
  `isinstance(v,int) and not isinstance(v,bool)` guard, `:331`).
- **`FunctionEvidence`** (`:179`) gains `required_args: tuple[RequiredArg, ...]`, `args_status: str`,
  `args_reason: str | None`; `_evidence_from_envelope` populates them from each raw record.
- **`score_function`** (`:247`) copies the three fields into the `PayoffEvidence` it builds (`:298`), so the
  ranked candidate carries them. **`PayoffEvidence`** (`:192`) gains the same three fields with a
  `__post_init__` asserting the §2.3 cross-field invariant (`unknown ⇒ empty list ∧ reason!=None`;
  `known ⇒ reason==None`), **unique positions**, and **no same-position value conflict**. Because the invariant
  lives in `__post_init__`, it guards **both** the envelope path **and** the cache-deser path (`report_from_json`
  rebuilds these dataclasses), closing the B8 "cache has no validation" gap. Any violation raises ⇒ report
  `ERROR`, not cached (W-1's fail-to-ERROR rule). Java already dedups/orders and enforces these at emit, so a
  violation here only ever means a corrupted/tampered cache row — correctly fatal.
- **Cache ser/deser (MAJOR 3).** `report_to_json` (`:379`) and `report_from_json` (`:423`) are hand-written;
  both gain `required_args` (full provenance), `args_status`, `args_reason`. **`CACHE_ENVELOPE_VERSION` bumps
  `1 → 2`** (`:348`) so any pre-existing row is a miss. A test asserts a cache **miss→hit** preserves all three
  (incl. provenance) byte-for-byte, and that a v1 row is a miss (§6 T9).
- **No ranking change.** Args annotate the W-1-chosen payoff; they do not affect which function is the payoff.
  `COMPLETE`/cache/TOCTOU/`DEGRADED`-angr semantics are unchanged; the cache key picks up `script_version`
  (`w2.0`) automatically, invalidating W-1 rows (Q4).
- Public accessor `required_args_for(report, *, rva=None) -> tuple[tuple[int,int], ...] | None`: the
  `(position, value)` pairs of the candidate at `rva` (or the top candidate if `rva is None`) **when that
  candidate's `args_status=="known"`**, else `None` (so `unknown` is distinguishable from `known + []` by the
  caller — §5.4 relies on it). Full provenance stays on the candidate.

## 5. Inventory resolution — the 69 class-B entries (BLOCKER 3)

**Parent contradiction resolved.** The parent's exact W-2 row (§130) says class-B entries are "all
`migrated`"; its own W-0 note (§240) enumerates ~10 class-B entries that "W-2 must mark `allowed`." §240 is
the correct intent; §130 is overstated. W-2 resolves **each** class-B entry to one of three dispositions,
every one carrying a justification string in `tests/data/target_values_baseline.json` (status is the only
mutable field; IDs/paths/class stay frozen):

**Audit result (the substantive W-2 finding).** A full read of all 69 class-B consumer sites found
**0 payoff-formal-argument guesses** — not one class-B entry is a hardcoded list of values a win()-style
function's *parameter* must equal. The breakdown is **27 `allowed`** (ABI/infrastructure constants) and
**42 `reassigned`** (per-binary *target* guesses that are not payoff args: buffer/ret offset sweeps, PIE base
guesses, canary-slot offsets, PRNG modulus/length fallbacks, and "CTF magic value" lists written into program
*state*). The payoff-argument capability already exists as a **principled per-binary extractor**:
`WinFunctionFinder.find_required_args(binary_path, func_name)` (`offset_finder.py:1109`) scans the win
function's own disassembly for `cmp $imm` constants and feeds `StackTechniques._build_arg_chain`
(`stack_techniques.py:303`) into `rdi/rsi/rdx`. It is **not** one of the 69 entries, so there is no hardcoded
payoff-arg list for `required_args_for(...)` to replace — **W-2's inventory migration count is 0.**

That pre-existing extractor is, however, **weak**: a flat `objdump` regex scan that grabs every
`cmp $imm > 0xff` in the named function with **no requiredness check** (it would emit the `gate_audit`,
`gate_disj`, `gate_invert`, `gate_relational`, and `gate_arith` false positives of §3a), **no parameter-slice
provenance** (§2.1), **no positions** (it returns a bare `List[int]`, so it cannot order multi-arg chains), and
it **fails on stripped binaries** (it matches on the objdump symbol label). So W-2's extractor is a **rigorous
replacement** of `find_required_args`, not a duplicate — see §5.3.

- **`allowed`** — a stable ABI / protocol / OS / tooling / architecture constant, **not** a per-binary target
  guess (signal sets, bad-char lists, mask bytes, crash/exploitability signatures, ioctl codes, slab sizes,
  format-string probe offsets, page sizes). Not migratable; correctly hardcoded.
- **`migrated`** — a genuine guess of a **payoff formal-argument** constant, repointed at
  `required_args_for(...)`. This is the only disposition W-2's new capability can satisfy (count: 0).
- **`reassigned`** — a per-binary target guess that is **not** a payoff formal argument (PIE/base-address
  guesses, canary-offset fallbacks, PRNG modulus/length fallbacks, "CTF magic value" lists compared against
  program state). These need a different analysis capability; W-2 records the entry as `reassigned` with the
  target phase (W-3/W-4, or a new follow-up) and a justification. **W-2 does not migrate them** and does not
  edit their consumers.

### 5.1 R5 narrowed (BLOCKER 3 / R5 inconsistency)

Since the audit found **0 `migrated`** entries, W-2 edits **no class-B consumer at all**: every one of the 69
entries is `allowed` or `reassigned`, i.e. a baseline `status` + justification change only. R5 therefore holds
for the inventory: **W-2 performs no class-A/A′ payoff-selection rewiring, no generated-script
(`inputs_required`) rewiring, and no class-B consumer rewiring.** R5 is amended for **exactly one** edit outside
the inventory, approved by the owner (Option A, §5.3): redirecting the ret2win arg path
(`StackTechniques._discover_args` / `_build_arg_chain`) off the weak `find_required_args` onto the new
extractor (§5.4), which carries its own seam test. No other consumer is touched in W-2.

### 5.2 Per-entry disposition table

**`allowed` — 27 entries** (stable ABI/infrastructure/architecture constants; correctly hardcoded):

| id | path:line | justification |
|---|---|---|
| W-0007 | cli.py:1610 | ioctl command codes (`_IOW` series) fingerprinting a driver |
| W-0043 | enhanced_auto.py:520 | generic signed/negative integer-overflow probe values |
| W-0044 | enhanced_auto.py:522 | use of the generic negative-size probe set |
| W-0052 | offset_finder.py:1048 | `nm` symbol-discovery subprocess; no integer target at this line |
| W-0053 | offset_finder.py:1073 | `objdump` file-op discovery; tooling, no integer target |
| W-0060 | delivery.py:61 | `FAULT_SIGNALS` — fault signal-code set (SIGILL/TRAP/ABRT/BUS/FPE/SEGV/SYS) |
| W-0061 | delivery.py:180 | use of the fault-signal set to detect a crash |
| W-0063 | allocsize_techniques.py:510 | integer-overflow wrap boundaries from word width + element sizes |
| W-0080 | heap_techniques.py:70 | `TCACHE_SIZES` — glibc tcache size classes |
| W-0081 | heap_techniques.py:354 | use of the tcache size-class set |
| W-0086 | input_shape_techniques.py:44 | `NEGATIVE_LENGTHS` — signed/truncation overflow boundary lengths |
| W-0089 | input_shape_techniques.py:168 | use of the signed-length overflow probe set |
| W-0111 | shellcode_techniques.py:40 | `SLED_SIZES` — generic NOP-sled placement/alignment sizes |
| W-0112 | shellcode_techniques.py:98 | use of the generic NOP-sled sizes |
| W-0126 | reliability.py:621 | x86-64 canonical-address high-byte signature for leak validation |
| W-0140 | verify.py:477 | common bad-character probe list (LF/CR/TAB/space/'%') |
| W-0146 | heap_probe.py:925 | allocator size-class request sizes (tcache bins + one above 0x408) |
| W-0147 | crash_triage.py:446 | controlled-PC crash signature patterns (AAAA/BBBB) |
| W-0148 | crash_triage.py:447 | use of PC-control signature patterns |
| W-0149 | crash_triage.py:528 | PC-control crash signature patterns (AAAA/BBBB/CCCC) |
| W-0150 | crash_triage.py:536 | use of PC-control signature patterns |
| W-0151 | module.py:68 | Linux kmalloc slab size classes |
| W-0152 | module.py:69 | use of the slab size-class list |
| W-0154 | integer.py:215 | signed/unsigned integer type-max boundary values (INT_MAX etc.) |
| W-0155 | integer.py:232 | use of integer-max + overflow boundary value sets |
| W-0156 | stack_bof.py:378 | common bad-character probe list (LF/CR/space/TAB) |
| W-0157 | stack_bof.py:380 | use of the bad-character probe list |

**`reassigned` — 42 entries** (per-binary *target* guesses, **not** payoff formal args; each needs a dynamic
capability, not `required_args_for`; target phase noted — "offset/size discovery" → W-4 dynamic confirmation
or the existing `OffsetFinder`; "program-state magic / gate value" → W-3 success-detection or a dedicated
"dynamic compare-immediate" follow-up):

| id | path:line | justification | → phase |
|---|---|---|---|
| W-0009/W-0010 | auto.py:440,442 | tiny-binary SROP buffer-offset guesses | offset discovery |
| W-0011 | auto.py:548 | guessed buffer→retaddr offsets (ret2win) | offset discovery |
| W-0014/W-0015 | auto.py:946,947 | guessed ret2system buffer offsets | offset discovery |
| W-0017 | auto.py:1119 | guessed buffer offsets (puts/leak stage) | offset discovery |
| W-0023/W-0025 | auto.py:1905,1918 | guessed input sizes for a `size<=N` check | offset/size discovery |
| W-0024/W-0026 | auto.py:1908,1919 | guessed buffer+rbp+ret offsets (intoverflow) | offset discovery |
| W-0037/W-0040 | enhanced_auto.py:119,384 | `MAGIC_VALUES` CTF magics written into a compared variable | program-state magic |
| W-0038/W-0039 | enhanced_auto.py:381,383 | guessed buffer sizes (variable-overwrite) | offset/size discovery |
| W-0041/W-0042 | enhanced_auto.py:438,439 | guessed ret2win buffer offsets | offset discovery |
| W-0045 | enhanced_auto.py:527 | guessed buffer offsets w/ negative size | offset discovery |
| W-0048/W-0049 | enhanced_auto.py:600,602 | guessed buf-distance-from-rbp (shellcode placement) | offset discovery |
| W-0057/W-0058/W-0059 | pie_bypass.py:424,430,438 | hardcoded PIE base-address guesses (64/32-bit) | dynamic leak (W-4) |
| W-0062 | allocsize_techniques.py:468 | fallback allocation-size-cap guesses | offset/size discovery |
| W-0064/W-0067 | canary_leak_techniques.py:45,221 | `ECHO_FILL_SIZES` over-long-echo fill guesses | offset/size discovery |
| W-0065/W-0068 | canary_leak_techniques.py:55,271 | `CANARY_OFFSET_FALLBACK` canary-slot offset guesses | offset discovery |
| W-0066 | canary_leak_techniques.py:182 | guessed fill sizes probing for a volunteered canary | offset/size discovery |
| W-0070/W-0072 | fmtstr_techniques.py:47,209 | `_FALLBACK_VALUES` gate-state fallbacks (not a formal arg) | program-state magic |
| W-0073 | fmtstr_techniques.py:224 | writes `1` to flip a boolean gate global | program-state magic |
| W-0083 | heap_techniques.py:1097 | guessed max object-index values (loop-bound) | offset/size discovery |
| W-0087/W-0088 | input_shape_techniques.py:49,116 | `FALLBACK_MAGIC_VALUES` CTF magics vs program state | program-state magic |
| W-0093/W-0094 | loop_counter_techniques.py:212,705 | `FIXED_SWEEP` loop-counter/bound brute-force values | offset/size discovery |
| W-0113/W-0114 | stack_techniques.py:99,133 | guessed buffer sizes (variable-overwrite sweep) | offset/size discovery |
| W-0120/W-0122 | weak_prng_techniques.py:125,455 | `_FALLBACK_MODULI` PRNG modulus fallbacks | dynamic PRNG (W-4) |
| W-0121/W-0123 | weak_prng_techniques.py:132,458 | `_FALLBACK_LENGTHS` PRNG secret-length fallbacks | dynamic PRNG (W-4) |

**`migrated` — 0 entries.** (See §5 audit result and §5.3.)

**Borderline calls flagged by the audit** (none is a payoff-arg guess, so none changes W-2's 0-migrated
result; recorded for the reviewer): W-0043/W-0044/W-0063/W-0086/W-0089 (negative-size / overflow-wrap /
signed-length probes) sit near the A/C line — a stricter reading moves W-0043/W-0044 to `reassigned`;
W-0062 (fallback size caps) is `reassigned` but the values coincide with allocator classes; W-0111/W-0112
(`SLED_SIZES`) is `allowed` but could read as a padding guess. These do not affect the extractor design.

Totals: **27 `allowed` + 42 `reassigned` + 0 `migrated` = 69.** The inventory test enforces that no class-B
entry remains `open`, that every resolution carries a justification, and that the frozen fields are unchanged
(`git show <W-0>:…`).

### 5.3 Relationship to the existing `find_required_args`, and the scope decision it forced

The audit surfaced that a payoff-argument extractor **already exists** (`find_required_args`,
`offset_finder.py:1109`) and is **already wired** into the ret2win-with-args path
(`StackTechniques._discover_args` → `_build_arg_chain` → `rdi/rsi/rdx`). It is the weak version described above.
W-2's extractor is its rigorous successor. This forced a scope decision (the parent approved W-2 under the
now-falsified premise that class-B held migratable payoff-arg lists, and did not know `find_required_args`
existed):

- **Option A (chosen) — build the Ghidra extractor *and* redirect the ret2win arg path onto it**, proving it
  end-to-end on `arg1`/`arg3` (incl. stripped, where `find_required_args` fails). Closes the September
  ret2win-with-args gap now and serves directive F-1. Expands W-2 by one audited consumer rewire and amends R5
  to permit exactly that edit (with a seam test); `find_required_args` is then deprecated.
- **Option B** — build + prove on the corpus, defer the rewire to W-5. Tighter, but the gap stays open longer.
- **Option C** — harden `find_required_args` in place. Rejected: requiredness (CFG) and param-slice provenance
  are not tractable over an `objdump` regex scan, and it cannot work on stripped binaries.

**Owner chose Option A (2026-11-13).** §5.4 specifies the single rewire; R5 is amended (§5.1); T12 proves it.

### 5.4 Ret2win arg-path rewire (Option A — B9)

`StackTechniques._discover_args(binary, win_name)` (`stack_techniques.py:296`) currently returns
`find_required_args(path, win_name)` — a flat `List[int]` in **disassembly-appearance order**, which
`_build_arg_chain` (`:304`) maps **positionally** (index 0→`rdi`, 1→`rsi`, 2→`rdx`). That ordering is unsound
(it assumes the win function compares its parameters in source order) and breaks on a stripped binary (no
`win_name`). The rewire:

- **Candidate chosen by RVA, not rank.** `_discover_args` calls `rank_payoffs(binary.path)` and resolves the
  **win address the pipeline already settled on** — `context.win_addr`/`win_function` from
  `profile_stage.py:132-148` (symbol table → `WinFunctionFinder` → `--win` override) — then looks up the
  candidate whose `rva == win_addr` via `required_args_for(report, rva=win_addr)`. **It does not assume
  `candidates[0]`** (W-1's top-ranked function need not be the pipeline's chosen win).
- **Fallback discipline (closes C1 / the optimized-binary risk).** `_discover_args` uses the extractor result
  **only when `required_args_for(...)` is not `None`** — i.e. the matching candidate is `COMPLETE` **and**
  `args_status=="known"`. In that case it returns the `(position, value)` pairs (possibly empty, which is the
  honest "no arg needed" for an ungated win). On **`unknown`**, **no matching candidate**, or a non-`COMPLETE`
  report (e.g. an optimized binary the Ghidra path degrades on) it **falls back to `find_required_args`** — so
  no capability is lost and a wrong value can never be emitted as authoritative (a mis-analyzed optimized
  binary degrades to the *current* behavior, never worse).
- **Position-aware register mapping.** `_build_arg_chain` maps `position → {1:rdi, 2:rsi, 3:rdx}` directly
  (SysV integer-class only). A required `position > 3`, or a float/non-integer class, **raises a clear
  `NotImplementedError`** (loud, not the current silent `break`), so an un-handleable win is surfaced rather
  than mis-exploited. Its only caller is `_discover_args`'s technique (confirmed during implementation).
- `find_required_args` is marked deprecated with a pointer to `required_args_for`; its deletion is left to W-5
  (which owns list deletion and generated-script rewiring) to keep W-2's footprint to the one rewire.

## 6. Test matrix (RED-first; real-Ghidra tests gated by `SUPWNGO_REQUIRE_GHIDRA=1`)

| # | test | kind | asserts |
|---|------|------|---------|
| T1 | `arg1`/`arg3` positives (16) | real-Ghidra | `required_args` of the ranked payoff **equals truth** (by `position`, order-insensitive); each arg's serialized `transform` chain **terminates at the `HighParam` for its slot** and is all value-preserving (raw-envelope, §2.4); `args_status=="known"`; `COMPLETE` |
| T2 | all three styles present | real-Ghidra | ≥1 `and`, ≥1 `nest`, ≥1 `early` unit in T1 passes (style-agnostic proof) |
| T3 | `exec`/`file` positives (16) | real-Ghidra | `args_status=="known"` **and `required_args == ()` exactly** |
| T3′ | **decoy + filler sweep** (every non-payoff record in the envelope, keyed by `index.json` RVA) | real-Ghidra | each `required_args == ()`, `args_status=="known"`, `reason is None` — `decoy_compare`'s non-param compares (`payoff_source.py:279`) and filler functions **never leak a constant into args** (the real anti-hallucination control; Rev-2 T3 was vacuous) |
| T4 | falsifiers, per shape (§3a) | real-Ghidra | `gate_audit`/`gate_invert` → `known, ()`; `gate_disj`/`gate_relational`/`gate_arith` → `unknown, ()` with `reason=="unresolved_gate"`; **`gate_arith` emits no value equal to its literal compared constant** |
| T5 | rename + strip twins | real-Ghidra | `required_args` equals truth on 16/16 rename and 16/16 strip positives; the `gate_disj` strip twin stays `unknown, ()` |
| T6 | PE | real-Ghidra | `required_args` equals truth on **all four** PE argument binaries (enumerated, not sampled); 32-bit `long` agreement; the `gate_disj` PE variant stays `unknown, ()` |
| T7 | malformed args envelope | mock | a bad field, a non-unique position, a same-position value conflict, `bool`-as-int, or `unknown` with a non-empty list / missing `reason` → `ERROR`, not cached (mirrors W-1 failure-injection; exercised via **both** `_evidence_from_envelope` and a hand-built cache row to prove `__post_init__` guards both paths) |
| T8 | value-width / masking + constant-left | mock/unit | a 32-bit comparison constant is reported un-truncated and matches `CONST_RANGE`; a comparison with the **constant as the left operand** is handled identically |
| T9 | cache round-trip | mock | a miss→hit second call preserves `required_args` (incl. provenance), `args_status`, `args_reason`; a `CACHE_ENVELOPE_VERSION==1` row is a miss |
| T10 | `unknown` path | mock/crafted | an `AMBIGUOUS`-slot / non-constant / fan-out / conflict gate yields `args_status=="unknown"` + the right `reason` + empty list; a decompile failure yields report-level `DEGRADED`, not per-function `unknown` (§2.3); an `extractRequiredArgs` exception yields `unknown(reason=analysis_exception)` for that record **without** downgrading the report (B8) |
| T11 | inventory | unit | no class-B entry is `open`; every resolution has a justification; frozen fields unchanged; 0 `migrated`, so no class-B consumer edit; the ret2win rewire (§5.4) is the only non-inventory edit |
| T12 | ret2win arg path (Option A, §5.4) | seam=always-run; e2e=gated | **seam:** patch `payoff.py`/`rank_payoffs` to return a candidate at a given `rva` with known `required_args` at **random, non-contiguous positions**; assert `_discover_args` (looking up by `rva`) → `_build_arg_chain` pops each value into the register for its `position` (not list index); `position>3` raises; an `unknown`/absent candidate falls back to `find_required_args`. **end-to-end (gated):** on a dedicated overflowable, non-PIE, no-canary `arg1` **and** `arg3` fixture (added in §7 step 1; offsets provided per directive-W PASS criterion b; `arg3` includes a `pop rdx` gadget), `_discover_args` sources from the extractor and the win call is reached with each param set; the **stripped** variant uses `--win <rva>` (PASS criterion a). `find_required_args` is not consulted when the report is `known`. |

T1–T6 + T3′ extend the existing `tests/test_payoff_ranker.py` corpus harness (same `index.json` driver,
module-scoped cache). T7–T10 are fast always-run mocks. T12's seam is an always-run mock; its end-to-end leg is
gated by `SUPWNGO_REQUIRE_GHIDRA=1` (it needs a real decompile).

**Optimization note (MINOR 3 / R7):** the dev corpus is `-O0` (`generate.py:101`), so W-2 makes **no** claim of
robustness to optimization reordering; that is out of scope (optimized fixtures are future work). On an
optimized binary the extractor is expected to degrade to `unknown` (transformed/coalesced operands → `AMBIGUOUS`
→ §2.3), and §5.4's fallback discipline then uses the legacy path — never a wrong `known`. The `and`/`nest`/
`early` positives plus the five falsifiers are the robustness envelope W-2 proves.

## 7. Execution order (one commit per step, RED test first; execute on Sonnet)

1. **Corpus falsifiers + e2e fixture** — add the `falsifier` category + five shapes (§3a) and the one
   overflowable `arg1`/`arg3` ret2win fixture (§6 T12) to `benchmark/gen/payoff/`; regenerate dev; confirm
   `index.json` carries the seven `role:"falsifier"` units with their truth `args_status`/`required_args`, and
   **diff the positive/twin/negative/PE rows against the W-1 baseline to prove they are byte-unchanged** (no
   RNG/namespace perturbation, MINOR). (Done first so T4 exists to fail against.)
2. **Extractor args pass** — `SupwngoPayoff.java`: `traceParamSlot` lattice with the entry-value guard (§2.1),
   `extractRequiredArgs` with individual edge-domination + Test U (§2.2) inside `analyze()`, own `try/catch`,
   dedup/order, serialized provenance (§2.4), `SCRIPT_VERSION → w2.0`. De-risk by running `analyzeHeadless` by
   hand on one `arg3`, one `gate_invert`, one `gate_disj`, and one `gate_arith` unit and **verifying the
   conditional-successor accessors and entry-block index live** before wiring Python.
3. **Python model** — `RequiredArg` + `__post_init__`; fields on **`FunctionEvidence`** (populate in
   `_evidence_from_envelope`) **and** `PayoffEvidence` (pass through `score_function`) + its cross-field
   `__post_init__`; `required_args_for(report, *, rva=None)`; cache ser/deser both paths +
   `CACHE_ENVELOPE_VERSION → 2`; unit tests T7–T10.
4. **Corpus tests** — T1–T6 + T3′, driven off `index.json` (gated).
5. **Inventory resolution** — §5.2 table applied to the baseline; T11 green (0 `migrated`, no class-B edit).
6. **Ret2win rewire (Option A)** — `_discover_args` (RVA lookup + fallback discipline) / `_build_arg_chain`
   (position-aware, `>3` raises), `find_required_args` deprecated; T12 seam + end-to-end green.
7. **Docs + CHANGELOG** — status note + one `Added` entry; full gate run under `SUPWNGO_REQUIRE_GHIDRA=1`;
   PR (incl. the three parent amendments, §9); merge; worktree/branch cleanup.

## 8. Risks

- **R1 — CFG edge/entry API drift.** The conditional-successor accessors (`getTrueOut()`/`getFalseOut()`),
  entry-block index, and `BOOL_NEGATE` parity must be verified live on Ghidra 12.1.3; an unresolvable case
  falls to `unknown` (fail-closed), never a mis-attributed arg. De-risk step 2 covers it.
- **R2 — slot coalescing.** If the decompiler coalesces/redefines a parameter, the entry-value guard (§2.1)
  yields `AMBIGUOUS` → `unknown`, never a mis-positioned or wrong-value arg (this is exactly what `gate_arith`
  proves).
- **R3 — constant side / sign.** `INT_NOTEQUAL` (early) and `INT_EQUAL` (and/nest) must map to the same
  `{position,value}`; value is the constant operand regardless of operand order, masked to width. T2/T8 guard
  it.
- **R4 — cache-key churn.** `w1.1`→`w2.0` + envelope `1→2` means W-1 rows no longer hit; intended. TOCTOU/
  COMPLETE-only-cache rules unchanged.
- **R5 — scope creep into W-5.** W-2 edits **no** class-B consumer (0 `migrated`, §5.1); the **only** edit
  outside the inventory is the one owner-approved ret2win arg-path rewire (§5.4), with a seam test. The
  reviewer should confirm no edit beyond that.
- **R6 — falsifier/fixture corpus cost.** Kept to 7 falsifier units (5 ELF + 1 strip twin + 1 PE) + 1 e2e
  ret2win fixture, all in a separate `falsifier`/fixture scope so the merged W-1 denominators are untouched.
- **R7 — optimized binaries.** Out of scope for extraction robustness; §5.4 fallback discipline ensures a
  degraded analysis yields `unknown` → legacy path, never a wrong `known`. Optimized fixtures are future work.

## 9. Resolved questions and parent amendments

**Answers (from the two independent reviews):**

- **Q1 — decoy/no-arg status:** `known + []` for a fully-analyzed *ungated* payoff (exec/file, decoy/filler,
  `gate_audit`, `gate_invert`); `unknown + reason` for a *gated-but-unresolvable* payoff (`gate_disj`,
  `gate_relational`, `gate_arith`) so the legacy fallback is not suppressed. T3/T3′/T4 assert exact emptiness
  and the correct status per shape. Requires the parent amendment below.
- **Q2 — slot API:** `HighParam.getSlot()` (0-based entry value), gated by `v.isInput()`, via
  `v.getHigh() instanceof HighParam` or `getLocalSymbolMap().getParam(i)`. Pinned in §3.
- **Q3 — class-B disposition:** resolved per-entry in §5.2 — **27 `allowed`, 42 `reassigned`, 0 `migrated`.**
  No class-B entry is a payoff-arg guess; a pre-existing (weak) payoff-arg extractor already exists
  (`find_required_args`). This falsifies the parent's "all migrated" premise and forced the §5.3 scope decision.
- **Q4 — versioning:** bump **both** Java and Python `SCRIPT_VERSION` to `w2.0` **and** the cache envelope
  `1→2`; invalidate W-1 rows; test arg-preserving cache hits (T9).

**Parent amendments required before implementation** (to
`docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md`, applied in the same PR and re-reviewed):

1. **§82-84 / §130 decoy semantics** — replace "Otherwise the result is `args: unknown`" / "decoys give
   `args: unknown` on 32/32" with the two-state semantics (§2.3): a fully-analyzed *ungated* payoff is
   `known + []`; `unknown + reason` is reserved for a detected-but-unresolvable parameter gate; decompile
   failure is report-level `DEGRADED`. The W-2 Done-when asserts `required_args == ()` exactly on the 16
   exec/file positives, the decoy/filler records, and the two non-gating falsifiers; `unknown, ()` on the three
   unresolvable-gate falsifiers; and `== truth` with provenance on the 16 arg positives.
2. **§130 inventory** — replace "Class-B baseline entries are all `migrated`" with "every class-B entry is
   resolved to `migrated` / `allowed` / `reassigned` with a justification, per the W-2 disposition table"
   (consistent with §240).
3. **§5 / R5 scope** — record that W-2 edits no class-B consumer (0 `migrated`) and that the one edit outside
   the inventory is the owner-approved ret2win arg-path rewire (§5.1/§5.4).
