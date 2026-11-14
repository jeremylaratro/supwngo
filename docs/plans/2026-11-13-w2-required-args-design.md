# W-2 — required-args extraction: constants from the binary (class B) (2026-11-13, Rev 4)

Detailed design for **directive W, phase W-2**. Parent plan:
`docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md` (§3 principle 3 / §82-84, §4 row W-2 / §130,
§12 class-B notes / §240). Builds directly on **W-1** (`supwngo/analysis/payoff.py` + `SupwngoPayoff.java`,
merged PR #39, `9f543bb`). Branch `feat/w2-required-args` off `main` `9f543bb`.

> **Rev 4 — reworked after the Tier-2 (cyber) re-review of Rev 3 returned REWORK.** The Rev-3 relocation of
> extraction into live `analyze()` state, baseline reachability, individual equality-edge test, multi-sink
> quantifier, and dedup are kept (the reviewer judged them sound). Rev 4 fixes the confirmed defects:
> - **Requiredness is one per-branch *required-outcome* test + a residual disjunction catch** (§2.2), replacing
>   Rev-3's "emit, then Test U." This closes the silent **partial-known** hole (`a==X && (b==Y||b==Z)` no
>   longer returns `known [a=X]`) and correctly classifies inverted/relational/transformed gates.
> - **`gate_invert` (`if(a==X)return; sink`) is `unknown(avoidance_gate)`, not `known,[]`** — `rdi` is
>   caller-saved/arbitrary, so `known,[]` does not establish the required `a!=X`; the reviewer's rebuttal is
>   accepted (B2).
> - **`unknown` means abstain, not fall back.** The equality-only legacy scanner returns actively wrong values
>   for exactly the gates W-2 reports `unknown` (it loads `X` for `gate_invert`, `K` for `a>K`, `X` for
>   `a*2==X`). The ret2win path therefore uses the legacy scanner **only when the extractor had no opinion**
>   (backend unavailable / non-`COMPLETE`), and abstains on a successfully-analysed unresolved gate (B2/MAJOR 4).
> - **The ret2win lookup normalizes the win address to the corpus RVA convention** (`to_corpus_rva`,
>   `payoff.py:79`) before comparing — Rev-3 compared image-base-relative candidate RVAs against an absolute
>   `win_addr` and would always fall back (B3).
> - **No new inventory lifecycle state.** The ratchet allows only `open`/`migrated`/`allowed`
>   (`test_target_value_inventory.py:148,216`); the 42 target-guess entries **stay `open`** (they match live
>   hits, so the ratchet is satisfied) with their owning phase recorded in the plan; W-2 closes only the 27 ABI
>   constants as `allowed` (B4). No parent §2 / W-5 contract change.
> - **Cross-field invariant lives on `FunctionEvidence`** (built inside the envelope `try`, `payoff.py:859-862`)
>   so a malformed live record is `ERROR`; a malformed **cache** row stays a **miss** (`report_from_json`
>   already returns `None`, `:452`) — Rev-3's "cache → ERROR" claim was wrong (MAJOR 3).
> - **Lattice guards tightened** (full-storage size check, canonical SEXT bit-pattern, true-self-reference-only
>   back-edge skip, width-preserving CAST), a **bounded boolean def-use walk** replaces the un-implementable
>   "mark both edges" for fan-out, and **register assignment is read from Ghidra `HighParam` storage** (not a
>   position→reg guess) so float/stack-class params fail closed (MAJOR 1/2/5).
> - **Falsifiers made non-vacuous:** a **const-sink non-param decoy** (`decoy_sink`) actually runs the
>   requiredness pass; `gate_mixed`/`gate_bool`/`gate_multieq` make the partial-known, fan-out, and mixed-slot
>   defects falsifiable in real Ghidra (MAJOR 6).
>
> Rev 1→3 lineage (provenance ≠ gating; serialized provenance; versioned cache; disposition audit resolving the
> parent §130-vs-§240 contradiction; pinned slot API; live-state extraction) is retained. Parent amendments in §9.

## 0. Goal (exact, from the parent plan's Done-when, as amended in §9)

Given a binary and the payoff RVA that W-1's `rank_payoffs` already identifies, recover the payoff's
**required argument constants** — the fixed values a caller must pass so that the payoff's own
parameter checks let control reach its W-1 sink — **from the binary**, not from a guessed list:

- On the **16/16 argument-checked positives** (corpus shapes `arg1`/`arg3`), the recovered `required_args`
  **equals truth** (`[{position, value}, …]`, 1-based position), **and every recovered value carries serialized
  parameter-slice provenance** that terminates at a full `HighParam` entry value (§2.4) — each value is proven
  to come from a comparison whose **required outcome** on every path to the sink is exactly
  `param == const` (§2.2).
- The **exec/file positives (16/16)** and the **const-sink non-param decoy** (`decoy_sink`) yield
  `args_status=="known"` with **`required_args == ()` exactly** (the sink is ungated / all compares are
  non-parameter). The **unresolvable-gate falsifiers** (`gate_invert`, `gate_disj`, `gate_relational`,
  `gate_arith`, `gate_mixed`, `gate_bool`, `gate_multieq`) yield `args_status=="unknown"` with an empty list
  and a `reason`: a real gate W-2 cannot pin to required `param==const` value(s). `gate_audit` (a non-sink
  gate) yields `known, ()`. A spurious arg is never emitted for any of them; `gate_arith`/`gate_mixed` never
  emit the literal compared constant.
- The **27 class-B ABI/infrastructure constants** are closed as `allowed` (with a justification); the remaining
  **42 class-B per-binary target guesses stay `open`** (they still match live hits, so the W-0 ratchet is
  satisfied) with their owning phase recorded in §5.2. **0 `migrated`.** No new lifecycle state is introduced.
- **The ret2win arg path is redirected onto the new extractor (Option A, §5.3/§5.4).** `_discover_args`
  resolves the pipeline-chosen win function, **normalizes its address to the corpus RVA convention**, looks up
  that candidate, and — when `args_status=="known"` — maps each value to the **register Ghidra assigned that
  parameter** and reaches the win call; on `unknown` it **abstains** (no auto-args), on a non-`COMPLETE` report
  it uses the legacy scanner. Proven by an always-run seam test and a gated end-to-end test on a dedicated
  overflowable `arg1`/`arg3` fixture (§6 T12).

Non-goals (deferred): class A/A′ payoff-name migration (W-5), success detection (W-3), dynamic confirmation
(W-4), and **robustness to compiler optimization** (the dev corpus is `-O0`, `generate.py:101`; W-2 makes **no**
optimized-binary soundness claim — see §6 note and R7). W-2 is **static extraction + the 27-entry inventory
closure**, plus the **single owner-approved ret2win arg-path rewire** (§5.4); no *other* consumer reads
`required_args` yet (that is W-5). Range/inequality/disjunction satisfaction (a gate needing `a>K`, `a!=X`, or
`a∈{X,Y}`, not a single required value) is out of scope: W-2 reports those `unknown` so a later phase or a
provided component (`--win`/manual values, directive-W PASS criteria) handles them.

## 1. Why a P-code scan is style-agnostic (necessary, not sufficient)

The corpus writes the argument gate three ways (`payoff_source.py:234-250`): `and` (`if (a==X && b==Y) {sink}`),
`nest` (nested `if`s), and `early` (`if (a!=X) return; … sink`). All three lower, in Ghidra's decompiler
P-code, to the **same** shape: an `INT_EQUAL`/`INT_NOTEQUAL` op comparing a **parameter varnode** against a
**constant varnode**, whose **required outcome to reach the sink is `param == const`**. So W-2 does **not**
parse source or match control-flow templates; it scans the payoff's decompiled P-code and asks, per gating
branch, whether the sink's required outcome is exactly `param == const`.

**But a param-vs-const comparison is not a single required value.** The same P-code shape appears in all of
these, where the required outcome is **not** `param == const` (each has a corpus falsifier in §3a):

```c
if (a == X) audit();   system("/bin/sh");   // sink unconditional; a==X gates only audit()        → known, []   (gate_audit)
if (a == X) return;    system("/bin/sh");   // required outcome is a != X (no single value)        → unknown      (gate_invert)
if (a == X || a == Y)  system("/bin/sh");   // required outcome is a ∈ {X,Y}                        → unknown      (gate_disj)
if (a > K)             system("/bin/sh");   // required outcome is a range                          → unknown      (gate_relational)
b = a * 2; if (b == X) system("/bin/sh");   // required value is X/2, not X                         → unknown      (gate_arith)
if (a == X && (b==Y||b==Z)) system(...);    // a==X required, b unresolved — must NOT return [a=X]  → unknown      (gate_mixed)
c = (a==X); if (c & flag) system(...);      // equality feeds a boolean op, not a CBRANCH           → unknown      (gate_bool)
```

The `and`/`nest`/`early` positives happen to use the favorable form, so a bare scan passes on them — corpus
compatibility, not a requiredness proof. §2.2 is the discriminator; §3a adds a falsifier for each row above.

## 2. Provenance + requiredness model (the discriminator)

A `required_arg {position, value}` is emitted **iff** some parameter-dependent branch in the payoff's
`HighFunction` **gates every (const-string) W-1 sink** and its **required outcome is exactly
`PARAM(slot, full) == const`** (§2.1 pins the operand, §2.2 pins the outcome). Everything else is either
**skipped** (the branch does not gate any sink) or **taints the function `unknown` with a `reason`** (a sink is
gated by a parameter condition that is not a single required equality). This is **fail-closed**: a non-parameter
compare (decoy) is never a gate; a parameter gate that is an inequality, a range, a disjunction, a transformed
value, an ambiguous slot, or a boolean composition is `unknown`, never a guessed or partial result.

### 2.1 Slot lattice with an entry-value guard (MAJOR 1 / B1, B2)

`traceParamSlot(Varnode)` classifies an operand over an explicit lattice ordered `NONPARAM, PARAM ⊏ AMBIGUOUS`
(`AMBIGUOUS` is **top**):

- **`NONPARAM`** — proven to carry no formal-parameter value (local, global, constant, or a value all of whose
  inputs are `NONPARAM`).
- **`PARAM(slot, width, full)`** — carries formal parameter `slot`'s **entry** value; `full == true` only when
  the **whole** storage of the parameter participates and no non-value-preserving op intervened.
- **`AMBIGUOUS`** (top) — param-derived but slot/slice/value not pinnable.

**Entry-value guard (closes B1).** A varnode is `PARAM(slot, size, full=true)` **only** when it is the formal
input itself (`v.isInput() && v.getHigh() instanceof HighParam && v.getSize() == paramStorageSize(slot)` — the
varnode covers the parameter's full storage), **or** it is reached from such an input through a chain of **only
value-preserving ops**. A `HighParam`-labelled varnode with any **other** defining op is `AMBIGUOUS`.

Transfer functions (a true lattice join: any op not listed, with a `PARAM`/`AMBIGUOUS` input, → `AMBIGUOUS`;
closes B2):

| opcode | result |
|---|---|
| input varnode, `isInput()`, `HighParam`, full-storage size | `PARAM(getSlot(), size, full=true)` |
| `COPY` of `PARAM(full)`; `CAST` **iff width-preserving** | pass through unchanged |
| `INT_ZEXT`/`INT_SEXT` of `PARAM(full)` | `PARAM(slot, extended_width, full=true)` **iff** the compared constant survives a canonical round-trip: truncate to source width, re-extend (zero/sign per op), require bit-equality with the comparison-width constant; else `AMBIGUOUS`. (Corpus 31-bit `CONST_RANGE`, `payoff_source.py:81`, satisfies this.) |
| `SUBPIECE` (partial slice) | `AMBIGUOUS` |
| `INDIRECT`, `PTRSUB`, `PTRADD` | `AMBIGUOUS` |
| arithmetic/logic (`INT_ADD/SUB/MULT/AND/OR/XOR/LEFT/RIGHT/…`) with a `PARAM`/`AMBIGUOUS` input | `AMBIGUOUS` |
| `MULTIEQUAL` (phi) | `PARAM(s,w,full)` **iff every** non-trivial arm is `PARAM` with the **same** slot and `full`; a back-edge arm may be ignored **only when it is exactly the phi's own output unchanged** (a true self-reference) — `phi(param, phi+1)` is `AMBIGUOUS`, not `PARAM`; **all** arms `NONPARAM` → `NONPARAM`; any other mix (`PARAM`+`NONPARAM`, two slots, a partial) → `AMBIGUOUS` |
| all inputs `NONPARAM` | `NONPARAM` |

Classification of a compare op's two inputs yields: **pinnable** (exactly one `PARAM(full)`, other `isConstant()`),
**ambiguous-param** (one `AMBIGUOUS`, other constant — a param gate we cannot pin), or **non-gate** (both
`NONPARAM`, or the other operand non-constant).

### 2.2 Requiredness: per-branch required-outcome test + residual disjunction catch (BLOCKER 1 / B3, B4, B5, B6)

**Where the data comes from (B5).** W-1 does **not** persist the sink CALL op — `Evidence`
(`SupwngoPayoff.java:392`) stores only `sinkApis`/`sinkTargets`. The analysis runs **inside `analyze()`** (which
already walks `hf.getPcodeOps()` and finds each sink `op` at `:435-450`) while `op`/`hf`/`f` are live. The
**sink set** is **exactly the const-string-target sinks** (`EXEC_FAMILY`/`FILE_OPEN_FAMILY` with a
`CONST_STRING` target), gathered in that loop. `Entry = hf.getBasicBlocks()[0]`; each sink block is
`sinkOp.getParent()`. (Entry index and conditional accessors verified live in de-risk step 2.)

**Step 0 — baseline reachability (B6).** If any sink block is unreachable from `Entry` in the uncut graph
(irreducible CFG, unresolved `BRANCHIND`/jump table) → emit nothing, taint `unknown(reason=irreducible_cflow)`.

**Collect gating param branches.** For every `CBRANCH`, resolve the governing comparison by a **bounded boolean
def-use walk** back through `COPY`, `CAST`, `BOOL_NEGATE`, `BOOL_AND/OR/XOR` (closes B4/MAJOR 2): follow the
condition to its ultimate integer comparison, tracking inversion parity. If the walk hits an **unmodelled
boolean op**, or the equality's boolean result **fans out to more than one `CBRANCH`** or to a non-branch use
(stored/returned/phi) with no single governing branch, taint `unknown(reason=bool_fanout)`. A branch is
**param-dependent** if its governing comparison has a `PARAM`/`AMBIGUOUS` operand (§2.1).

**Step 1 — per-branch required outcome (emit or taint).** For each param-dependent branch `b`: determine
whether `b` **gates the sinks** — cut each of `b`'s two out-edges in turn and test sink reachability. If exactly
one out-edge, when cut, disconnects **every** sink block from `Entry`, that is `b`'s **required edge** `r_b`
(`b` gates the sinks). Then:
- `r_b` corresponds to the comparison outcome **`param == const` being true** (`INT_EQUAL` true-edge, or
  `INT_NOTEQUAL` false-edge) **and** the param operand is pinnable `PARAM(full)` → **emit** `(slot+1, value)`
  with provenance (§2.4); mark `b` **explained**.
- `b` gates the sinks but `r_b` is the **inequality** outcome (`INT_EQUAL` false-edge / `INT_NOTEQUAL`
  true-edge) → `unknown(reason=avoidance_gate)` (this is `gate_invert`).
- `b` gates the sinks but the comparison is **not equality** (relational), or the param operand is
  **`AMBIGUOUS`** (transformed/partial/phi-mixed) → `unknown(reason=relational_gate` / `ambiguous_gate)`.
- neither out-edge-cut disconnects the sinks → `b` does **not individually gate** → leave for Step 2.

If an emitted set assigns **different** values to the **same** slot (unsatisfiable) → `unknown(reason=conflict)`.
Identical `(slot, value)` pairs are deduped before emission (B6).

**Step 2 — residual disjunction catch (closes the partial-known hole, B3).** If Step 1 raised no `unknown`:
build the subgraph where every **explained** branch is **forced to its required edge** (remove its other
out-edge), and every param-dependent branch that did **not** individually gate has the out-edge(s) matching its
`param==const`-true outcome **cut** (both edges if the outcome is indeterminate). Test sink reachability from
`Entry`:
- **reachable** ⇒ all gating is explained by the emitted equalities ⇒ `known` with the emitted list (possibly
  empty — a truly ungated sink).
- **unreachable** ⇒ a residual disjunctive/collective gate remains (`a∈{X,Y}`, the `b` part of `gate_mixed`) ⇒
  `unknown(reason=unresolved_gate)` — **the emitted-so-far list is discarded; W-2 never returns a partial
  `known`.**

**Reason precedence (MINOR 1).** When several apply, the function's `reason` is the first of:
`irreducible_cflow` ▸ `analysis_exception` ▸ `conflict` ▸ `bool_fanout` ▸ `ambiguous_gate` ▸ `avoidance_gate`
▸ `relational_gate` ▸ `unresolved_gate`. Tests assert the exact reason per shape (§6 T10).

**Worked cases** (all verified by hand; each has a §3a falsifier): `exec/file`/`decoy_sink`→`known,[]`;
`gate_audit`→ no branch gates the sink →`known,[]`; genuine `early` (`if(a!=X)return`)→ required edge is the
`NOTEQUAL`-false (`a==X`) edge → emit `X`; `gate_invert` (`if(a==X)return`)→ required edge is the inequality
→`avoidance_gate`; `gate_disj`→ no single branch gates, residual cut disconnects →`unresolved_gate`; `gate_mixed`
→ emit `a=X` in Step 1, residual cut of `b==Y`/`b==Z` disconnects →`unresolved_gate`, list discarded;
`gate_relational`→`relational_gate`; `gate_arith`→ operand `AMBIGUOUS`→`ambiguous_gate`, literal never emitted;
`gate_bool`→`bool_fanout`; `gate_multieq` (phi over two slots)→ operand `AMBIGUOUS`→`ambiguous_gate`; `arg3`→
three equalities each individually gate → emit `X,Y,Z`, residual reachable →`known,[X,Y,Z]`.

### 2.3 `args_status`: two states + an explicit reason (B2, B3, MINOR 2)

- **`known`** — successfully decompiled, gates fully analysed; the list is authoritative. **Empty iff the sinks
  are ungated** (no param-dependent branch gates any sink): `exec`/`file`, `decoy_sink`, `gate_audit`.
- **`unknown` (+`reason`)** — decompiled, but a parameter condition gating a sink is not a single required
  `param==const` value (reasons per §2.2 precedence). The list is empty. **The consumer abstains on `unknown`**
  (§5.4) — it is never routed to the equality-only legacy scanner, which returns actively wrong values here.
- **Decompile failure** → W-1 returns `null` (`:407`), the pass is incomplete (`:519`) ⇒ the **report** is
  `DEGRADED`; `args_status` is per-successfully-decompiled-record only. An exception inside the args pass yields
  `unknown(reason=analysis_exception)` for that record without downgrading the report (§3).

**Invariant:** `unknown ⇒ required_args==() ∧ reason!=None`; `known ⇒ reason==None`. Enforced in
`FunctionEvidence.__post_init__` (§4).

### 2.4 Recorded provenance (MAJOR 2 / MINOR 2)

Each emitted arg is serialized as an object, independently demonstrating termination at a full `HighParam`:

```
{ "position": <int ≥ 1>, "value": <int>,
  "slot": <int ≥ 0>, "width": <int>, "src_width": <int>, "terminal": "HighParam",
  "reg": "<SysV integer register, e.g. rdi>",           // Ghidra HighParam storage (§3), not a position guess
  "op": "INT_EQUAL"|"INT_NOTEQUAL", "op_addr": <unsigned>,
  "sink_addrs": [<unsigned>, …],                          // non-empty
  "transform": ["COPY","INT_SEXT", …] }                   // value-preserving chain, entry-first, terminal marker last
```

`value` is the constant masked to the comparison width (31-bit corpus ⇒ ELF/PE agree). Tests (§6 T1) read the
**raw envelope** and assert `terminal=="HighParam"`, `transform` is all value-preserving, `reg` is a valid
integer-class register, and `sink_addrs`/`op_addr` are present, non-empty, unsigned (bool rejected). Python
surfaces `(position, value)` + `reg` for the consumer and keeps full provenance on the candidate (§4).

## 3. Extractor change (`SupwngoPayoff.java`)

Additive; **no change to the W-1 evidence fields**:

- Inside `analyze(Function f)` (`:407`), after the sink loop, call `extractRequiredArgs(HighFunction hf,
  List<PcodeOp> constStringSinkOps)` → `(status, reason, List<RequiredArg>)`, stored on a new `Evidence` field
  and serialized by `appendRecord`.
- **Failure isolation (B8).** `extractRequiredArgs` is wrapped in its **own `try/catch`**; any exception →
  `unknown(reason=analysis_exception)` for that function only, never propagating to make the pass incomplete.
- **Slot/storage API (pinned, Ghidra 12.1.3):**
  ```java
  if (v.isInput() && v.getHigh() instanceof HighParam) {
      HighParam p = (HighParam) v.getHigh();
      int slot = p.getSlot();                    // 0-based entry value
      VariableStorage st = p.getStorage();        // register class + size → the `reg` field and full-storage check
  }
  // or by index: hf.getLocalSymbolMap().getParam(i); getNumParams() bounds i.
  ```
  `reg` is derived from `VariableStorage.getRegister()`; a parameter **not** in a single SysV integer register
  (xmm/stack/aggregate) at or below the highest required position makes the function `unknown(reason=abi_class)`
  (closes the MAJOR 5 "position ≠ register" case, e.g. `f(double x, long a)`).
- **CFG API:** `hf.getBasicBlocks()` (entry index `0`); successors via `getOut(i)`/`getOutSize()` and
  `getTrueOut()`/`getFalseOut()`; reachability-with-edges-cut is a BFS. Accessors verified live (de-risk step 2).
- Dedup `(slot,value)`; sort emitted args by `position`. Record gains `"required_args"`,
  `"args_status"`, `"args_reason"`. `SCRIPT_VERSION` **`w1.1` → `w2.0`**.
- The extractor emits for **every** enumerated function; Python reads only the chosen payoff RVA (§5.4). A
  function with no const-string sink reports `known + []`.

### 3a. Adversarial falsifiers (new corpus category — B1/B2/B3/B7, MAJOR 6)

Each shape has a **real const-string sink** (so W-1 still promotes it, and the requiredness pass actually
**runs** — unlike a sink-less decoy, which §3 would skip, making a Rev-3-style T3′ vacuous). Truth per shape:

| shape | source sketch | truth `args_status` | `required_args` | kills |
|---|---|---|---|---|
| `decoy_sink` | real sink; all compares are **globals/locals vs const** (no param) | `known` | `[]` | non-param constant hallucination (the real T3′ control) |
| `gate_audit` | `if (a==X) benign(); sink;` | `known` | `[]` | unconditional-sink false positive |
| `gate_invert` | `if (a==X) return; sink;` | `unknown` (`avoidance_gate`) | `[]` | inverted-guard: a!=X is not a required value (B2) |
| `gate_disj` | `if (a==X \|\| a==Y) sink;` | `unknown` (`unresolved_gate`) | `[]` | disjunction + the Option-A regression |
| `gate_relational` | `if (a > K) sink;` | `unknown` (`relational_gate`) | `[]` | relational gate |
| `gate_arith` | `b=a*2; if (b==X) sink;` | `unknown` (`ambiguous_gate`) | `[]` | redefined-param wrong value (also assert **no emit == X**) |
| `gate_mixed` | `if (a==X && (b==Y\|\|b==Z)) sink;` | `unknown` (`unresolved_gate`) | `[]` | **partial-known** (must NOT return `[a=X]`) (B3/BLOCKER 1) |
| `gate_bool` | `c=(a==X); if (c & flag) sink;` | `unknown` (`bool_fanout`) | `[]` | boolean fan-out / non-CBRANCH consumer (MAJOR 2) |
| `gate_multieq` | phi merging two different param slots, then `== X` | `unknown` (`ambiguous_gate`) | `[]` | mixed-slot MULTIEQUAL mis-assignment (MAJOR 1) |

Emitted as a **separate `role:"falsifier"` category** in `benchmark/gen/payoff/`, **not** added to `SHAPES`, so
the merged W-1 denominators (parent §128) are **unchanged**. Matrix (R6): one non-PIE unstripped ELF per shape
(9 units) + a `gate_disj` stripped twin + a `gate_disj` PE variant = **11 units**. `index.json` lists each with
`role:"falsifier"`, truth `args_status`/`required_args`/`reason`, and (for `gate_arith`) the literal compared
constant. **Generator hygiene:** the new category is skipped by every W-1 counter/test that filters
`index.json` by `role`, draws from the existing `_Consts` stream without perturbing positives' constants/RVAs,
and is verified in §7 step 1 by diffing the regenerated positive/twin/negative/PE rows against the W-1 baseline.

## 4. Python change (`supwngo/analysis/payoff.py`)

Flow: `_evidence_from_envelope → List[FunctionEvidence]` (`:580/601`) → `rank_candidates` (`:307`) →
`score_function → PayoffEvidence` (`:247/298`) → `PayoffCandidate` (`:203`). Args flow the whole way (B8):

- Frozen `RequiredArg` dataclass mirrors §2.4 with `__post_init__`: `position≥1`, `value:int`, `slot≥0`,
  `width>0`, `src_width>0`, `op∈{INT_EQUAL,INT_NOTEQUAL}`, `reg` a known SysV integer register, `op_addr` and
  every `sink_addrs` element a **non-negative int with `bool` rejected**, `sink_addrs` non-empty, `terminal=="HighParam"`,
  `transform` all value-preserving names. (Reuses the W-1 `isinstance(v,int) and not isinstance(v,bool)` guard, `:331`.)
- **`FunctionEvidence`** (`:179`) gains `required_args`, `args_status`, `args_reason`, populated by
  `_evidence_from_envelope`; its **`__post_init__` enforces the §2.3 cross-field invariant** (`unknown ⇒ empty ∧
  reason`; `known ⇒ no reason`; unique positions; no same-slot/position value conflict). Because this runs
  **inside the envelope `try`** (`:859-862`), a malformed **live** record → `ERROR` (MAJOR 3, fixed — Rev 3 put
  this on `PayoffEvidence`, which `rank_candidates` builds at `:315` **outside** that `try`, so it would have
  escaped `rank_payoffs`).
- **`score_function`** copies the three validated fields into `PayoffEvidence` (`:298`); `PayoffCandidate` reads
  them through. `PayoffEvidence.__post_init__` keeps a light assert for defense-in-depth.
- **Cache (MAJOR 3 corrected).** `report_to_json` (`:379`) and `report_from_json` (`:423`) gain the three
  fields (full provenance). A **malformed cache row stays a miss** — `report_from_json` already wraps
  reconstruction in `try/except (KeyError,TypeError,ValueError) → None` (`:452`), so a bad `RequiredArg` row is
  a safe miss, **not** `ERROR`. `CACHE_ENVELOPE_VERSION` **`1 → 2`** (`:348`) ⇒ v1 rows miss. T9 asserts
  miss→hit preserves all three; T7 asserts **envelope**-malformation → `ERROR` and **cache**-malformation →
  miss.
- **No ranking change.** `script_version` (`w2.0`) invalidates W-1 cache rows automatically (Q4).
- `required_args_for(report, *, rva=None) -> tuple[tuple[int,int], ...] | None`: the `(position, value)` pairs
  of the candidate at `rva` (top candidate if `None`) **only when `report.status is COMPLETE` and that
  candidate's `args_status=="known"`**; else `None` (so `unknown` and non-`COMPLETE` are both `None`, letting
  §5.4 distinguish abstain-vs-fallback). A sibling `required_arg_regs(...)` exposes the per-arg `reg`.

## 5. Inventory resolution — the 69 class-B entries (BLOCKER 3 → now B4-clean)

**Parent contradiction resolved.** The parent's W-2 row (§130) says class-B entries are "all `migrated`"; its
own W-0 note (§240) enumerates ~10 that "W-2 must mark `allowed`." §240 is the correct intent. **W-2 does not
invent a lifecycle state:** the ratchet (`tests/test_target_value_inventory.py`) permits only `open`,
`migrated`, `allowed`, and a surviving `open` entry that still matches a live hit is **valid** (only an `open`
entry matching **no** hit is stale, `:169-175`). So W-2:

- closes the **27 ABI/infrastructure constants** `open → allowed` (each with a `justification`, required by
  `:214`);
- **leaves the 42 per-binary target guesses `open`** — they match live hits, so they are ratchet-valid; their
  owning phase and rationale are recorded in §5.2 (plan only; the baseline rows are **untouched**, so the
  frozen-field check `:191` is trivially satisfied) and closed by that later phase;
- migrates **0** (see audit below).

**Audit result (the substantive W-2 finding).** A full read of all 69 class-B consumer sites found **0
payoff-formal-argument guesses** — not one entry is a hardcoded list of values a win()-style function's
*parameter* must equal. The payoff-argument capability already exists as a weak per-binary extractor,
`WinFunctionFinder.find_required_args` (`offset_finder.py:1109`), which is **not** one of the 69 entries, so
there is nothing for `required_args_for(...)` to migrate — **W-2's inventory migration count is 0.** That
extractor is a flat `objdump` regex scan with no requiredness check (it emits every §3a false positive), no
param-slice provenance, no positions (bare `List[int]`), and fails on stripped binaries — so W-2's Ghidra
extractor is its rigorous **replacement** (§5.3), not a duplicate.

### 5.1 R5 scope (B4-clean)

W-2 edits the baseline for **27 entries only** (`open → allowed` + justification), **no** class-B consumer, and
performs the **single** owner-approved edit outside the inventory: the ret2win arg-path rewire (§5.4), with a
seam test. No class-A/A′ payoff-selection or generated-script (`inputs_required`) rewiring. The 42 `open`
entries get **no** code or baseline change in W-2.

### 5.2 Per-entry disposition table

**Close as `allowed` — 27 entries** (stable ABI/infrastructure/architecture constants; `open → allowed`):

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

**Stay `open` — 42 entries** (per-binary *target* guesses, not payoff formal args; **baseline unchanged**;
owning phase recorded here for the phase that will close them — "offset/size discovery" → W-4 dynamic
confirmation or the existing `OffsetFinder`; "program-state magic/gate value" → W-3 or a dedicated "dynamic
compare-immediate" follow-up):

| id | path:line | rationale (not a payoff arg) | owning phase |
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

**`migrated` — 0.** Totals: **27 closed `allowed` + 42 remain `open` + 0 `migrated` = 69.** T11 asserts: the 27
are `allowed` with justifications; the 42 are still `open` **and still match live hits** (not stale); frozen
fields unchanged; 0 `migrated`; no class-B consumer edit.

### 5.3 Relationship to `find_required_args`, and the scope decision it forced

`find_required_args` (`offset_finder.py:1109`) is already wired into the ret2win-with-args path
(`StackTechniques._discover_args` → `_build_arg_chain` → registers). It is the weak extractor above. This forced
a scope decision; **owner chose Option A (2026-11-13)** — build the Ghidra extractor **and** redirect the
ret2win arg path onto it (§5.4), proving it end-to-end, deprecating `find_required_args` on that path. (Option B
= defer the rewire to W-5; Option C = harden the regex scan, rejected as unsound.)

### 5.4 Ret2win arg-path rewire (Option A — B3, MAJOR 4/5)

`StackTechniques._discover_args(binary, win_name)` (`stack_techniques.py:296`) currently returns
`find_required_args(path, win_name)` — a flat `List[int]` in disassembly order, mapped positionally to
`rdi/rsi/rdx` (`:304`), which is unsound and breaks on stripped binaries. The rewire:

- **Address-domain-correct lookup (B3).** `_discover_args` calls `rank_payoffs(binary.path)` and resolves the
  pipeline's chosen win address (`context.win_addr`/`win_function` from `profile_stage.py:132-148`:
  symbol table → `WinFunctionFinder` → `--win`). That address is **absolute/link-time**; candidate RVAs are
  image-base-relative (`to_corpus_rva`, `payoff.py:79`). It normalizes with
  `win_rva = to_corpus_rva(win_addr, image_base)` (image base from the core binary abstraction,
  `binary.py:238-246`) and looks up `required_args_for(report, rva=win_rva)`. **Not `candidates[0]`.**
- **Outcome-typed discipline (B2/MAJOR 4).** Three outcomes, no harmful fallback:
  - `required_args_for(...)` returns a **non-empty** list → map each `(position, value)` to **its recorded
    `reg`** (from provenance, §2.4) and build the chain.
  - returns **`()`** (known-ungated) → no arg setup needed; proceed with an empty chain.
  - returns **`None`** → split on report status: a **`COMPLETE`** report with `args_status=="unknown"` ⇒
    **abstain** (the technique signals it cannot auto-build args — a provided component `--win`/manual values
    is the directive-W path; it does **not** call the legacy scanner, which would load wrong values); a
    **non-`COMPLETE`** report (backend unavailable / `DEGRADED`) ⇒ the extractor had no opinion, so fall back to
    `find_required_args` for compatibility.
- **Register from provenance, loud on unsupported.** `_build_arg_chain` consumes `(reg, value)` pairs and emits
  the pop-gadget for each `reg` directly (no position→reg guess). A required parameter whose `reg` is absent
  (non-integer/stack/xmm — already `unknown` at extraction, §3) never reaches here; a legacy-fallback
  `List[int]` is first normalized to `(reg, value)` via the positional SysV map, and existing `hex()`-per-element
  logging is updated for the pair form (MAJOR 5).
- No optimized-binary soundness claim: an optimized binary that decompiles `COMPLETE` but mis-analyses is
  expected to land in `unknown` (transformed/coalesced → `AMBIGUOUS`) and **abstain**; W-2 ships no optimization
  detector and makes no guarantee beyond `-O0` (R7).
- `find_required_args` is marked deprecated (pointer to `required_args_for`); deletion is W-5's.

## 6. Test matrix (RED-first; real-Ghidra tests gated by `SUPWNGO_REQUIRE_GHIDRA=1`)

| # | test | kind | asserts |
|---|------|------|---------|
| T1 | `arg1`/`arg3` positives (16) | real-Ghidra | `required_args` == truth (by `position`, order-insensitive); each arg's raw-envelope provenance has `terminal=="HighParam"`, value-preserving `transform`, a valid integer `reg`, non-empty `sink_addrs`; `known`; `COMPLETE` |
| T2 | all three styles | real-Ghidra | ≥1 `and`, ≥1 `nest`, ≥1 `early` unit in T1 passes |
| T3 | `exec`/`file` positives (16) | real-Ghidra | `known` **and `required_args == ()` exactly** |
| T3′ | `decoy_sink` (const-sink non-param) | real-Ghidra | the requiredness pass **runs** and emits `known, ()` — non-parameter constants are rejected (the real anti-hallucination control; sink-less decoys/fillers additionally checked for default `[]` serialization but are not the control) |
| T4 | falsifiers, per shape (§3a) | real-Ghidra | each shape's exact `(args_status, required_args, reason)` per the §3a table; `gate_mixed` yields `unknown` with **no `[a=X]`**; `gate_arith` emits no value == its literal constant |
| T5 | rename + strip twins | real-Ghidra | truth on 16/16 rename + 16/16 strip positives; `gate_disj` strip twin stays `unknown, ()` |
| T6 | PE | real-Ghidra | truth on **all four** PE arg binaries; 32-bit agreement; `gate_disj` PE variant stays `unknown, ()` |
| T7 | malformed records | mock | an **envelope** record with a bad field / non-unique position / same-slot conflict / `bool`-as-int / `unknown`+non-empty / missing reason → report `ERROR` (via `FunctionEvidence.__post_init__` inside the envelope `try`); a malformed **cache** row → cache **miss** (not `ERROR`) |
| T8 | width/masking + constant-left | mock/unit | a 32-bit constant reported un-truncated, matches `CONST_RANGE`; constant-as-left-operand handled identically; a SEXT constant failing the canonical round-trip → `AMBIGUOUS` → `unknown` |
| T9 | cache round-trip | mock | miss→hit preserves `required_args` (incl. provenance+`reg`), `args_status`, `args_reason`; a v1 row misses |
| T10 | reason precedence | mock/crafted | each `unknown` reason (`irreducible_cflow`/`conflict`/`bool_fanout`/`ambiguous_gate`/`avoidance_gate`/`relational_gate`/`unresolved_gate`/`analysis_exception`) is produced with the **exact** expected code under the §2.2 precedence; a decompile failure → report `DEGRADED`; an args-pass exception → `unknown(analysis_exception)` for that record without downgrading the report |
| T11 | inventory | unit | 27 entries `allowed`+justification; 42 still `open` **and matching live hits** (not stale); frozen fields unchanged; 0 `migrated`; no class-B consumer edit; the ret2win rewire is the only non-inventory edit |
| T12 | ret2win arg path (§5.4) | seam=always-run; e2e=gated | **seam:** patch `rank_payoffs` to return a candidate at a given `rva` with known args at **random, non-contiguous positions** and recorded `reg`s; assert `_discover_args` (normalized-RVA lookup) → `_build_arg_chain` pops each value into **its recorded `reg`**; a `COMPLETE`+`unknown` report ⇒ abstain (no legacy call); a non-`COMPLETE` report ⇒ legacy fallback (normalized to pairs); an absent RVA match ⇒ `None`. **end-to-end (gated):** on a dedicated overflowable non-PIE no-canary `arg1` **and** `arg3` fixture (§7 step 1; offsets provided, directive-W PASS criterion b; `arg3` has a `pop rdx` gadget), the win call is reached with each param set; the **stripped** variant supplies `--win <link-time VADDR>` (normalized to RVA for lookup, used absolute for the jump — an override-assisted stripped path, **not** automatic stripped win discovery, PASS criterion a) |

T1–T6 + T3′ extend `tests/test_payoff_ranker.py` (same `index.json` driver, module-scoped cache). T7–T10 + the
T12 seam are always-run mocks. T12's end-to-end leg is gated.

**Optimization note (R7):** the dev corpus is `-O0` (`generate.py:101`); W-2 makes **no** optimized-binary
soundness claim and ships no optimization detector. The `and`/`nest`/`early` positives plus the nine falsifiers
are the robustness envelope W-2 proves; optimized fixtures are future work.

## 7. Execution order (one commit per step, RED test first; execute on Sonnet)

1. **Corpus falsifiers + e2e fixture** — add the `falsifier` category + nine shapes (§3a) and the overflowable
   `arg1`/`arg3` ret2win fixture (§6 T12) to `benchmark/gen/payoff/`; regenerate dev; confirm `index.json`
   carries the eleven `role:"falsifier"` units with truth `args_status`/`required_args`/`reason`, and **diff the
   positive/twin/negative/PE rows against the W-1 baseline to prove them byte-unchanged**.
2. **Extractor args pass** — `SupwngoPayoff.java`: `traceParamSlot` lattice with the entry-value/size/SEXT/
   back-edge/CAST guards (§2.1), the bounded boolean def-use walk (§2.2), per-branch required-outcome + residual
   test, `VariableStorage`-derived `reg` + `abi_class` taint, own `try/catch`, dedup/order, provenance (§2.4),
   `SCRIPT_VERSION → w2.0`. De-risk by running `analyzeHeadless` by hand on one each of `arg3`, `gate_invert`,
   `gate_disj`, `gate_mixed`, `gate_bool`, `gate_arith`, verifying the conditional-successor accessors, entry
   index, and storage API **live**.
3. **Python model** — `RequiredArg` + `__post_init__`; fields + cross-field invariant on **`FunctionEvidence`**
   (inside the envelope `try`) and pass-through in `score_function`; `required_args_for`/`required_arg_regs`
   (reject non-`COMPLETE`); cache ser/deser both paths + `CACHE_ENVELOPE_VERSION → 2` (cache-miss semantics);
   T7–T10.
4. **Corpus tests** — T1–T6 + T3′ (gated).
5. **Inventory** — close the 27 `allowed` in the baseline; leave the 42 `open` untouched; T11 green.
6. **Ret2win rewire** — `_discover_args` (normalized-RVA lookup + outcome-typed discipline) / `_build_arg_chain`
   (register-from-provenance, pair-form, updated logging), `find_required_args` deprecated; T12 seam +
   end-to-end green.
7. **Docs + CHANGELOG** — status note + one `Added` entry; full gate under `SUPWNGO_REQUIRE_GHIDRA=1`; PR (incl.
   the §9 parent amendments); merge; worktree/branch cleanup.

## 8. Risks

- **R1 — CFG/storage API drift.** Conditional-successor accessors, entry index, `BOOL_NEGATE` parity, and
  `HighParam.getStorage()` verified live (de-risk step 2); an unresolvable case → `unknown`, never a wrong arg.
- **R2 — slot coalescing / redefinition.** The entry-value guard (§2.1) yields `AMBIGUOUS` → `unknown`
  (`gate_arith`/`gate_multieq` prove it).
- **R3 — constant side/sign.** `INT_NOTEQUAL`(early) and `INT_EQUAL`(and/nest) map to the same `{position,value}`;
  value is the constant regardless of operand order, masked; SEXT canonical check guards sign. T2/T8.
- **R4 — cache-key churn.** `w1.1→w2.0` + envelope `1→2`; W-1 rows miss (intended). TOCTOU/COMPLETE-only rules
  unchanged.
- **R5 — scope.** 27 baseline closures, 0 class-B consumer edits, 1 owner-approved ret2win rewire; reviewer to
  confirm no edit beyond that and no new lifecycle state.
- **R6 — falsifier/fixture cost.** 11 falsifier units + 1 e2e fixture, separate category; W-1 denominators
  untouched.
- **R7 — optimized binaries.** Out of scope; §5.4 abstains on `unknown`, no optimized guarantee, no detector.
- **R8 — ABI class.** Register read from Ghidra storage; a non-integer/stack param at/below the highest required
  position → `unknown(abi_class)`, never a mis-placed value.

## 9. Resolved questions and parent amendments

**Answers (from the two independent reviews):**

- **Q1 — status taxonomy:** `known + []` only for a genuinely *ungated* sink (exec/file, `decoy_sink`,
  `gate_audit`); `known + [args]` for pinned `param==const` gates; `unknown + reason` (and **consumer abstains**,
  not legacy fallback) for every gate that is not a single required equality — including `gate_invert`
  (accepting the reviewer's rebuttal of Rev 3's `known` classification). T3/T3′/T4 assert exact
  status/list/reason per shape.
- **Q2 — slot/ABI API:** `HighParam.getSlot()` (0-based, `isInput()`-gated, full-storage) +
  `HighParam.getStorage().getRegister()` for the SysV register. Pinned in §3.
- **Q3 — class-B disposition:** 27 closed `allowed`, 42 remain `open` (ratchet-valid, owning phase recorded),
  0 `migrated`; no class-B entry is a payoff-arg guess; a weak payoff-arg extractor already exists
  (`find_required_args`). No new lifecycle state.
- **Q4 — versioning:** bump both `SCRIPT_VERSION` to `w2.0` and the cache envelope `1→2`; W-1 rows miss; test
  arg-preserving cache hits (T9).

**Parent amendments required before implementation** (applied in the same PR, re-reviewed):

1. **§82-84 / §130 status semantics** — replace "Otherwise the result is `args: unknown`" / "decoys give
   `args: unknown` on 32/32" with the two-state semantics (§2.3): an *ungated* payoff is `known + []`;
   `unknown + reason` is reserved for a detected-but-unresolvable parameter gate (inequality / range /
   disjunction / transformed / ambiguous / boolean-fanout); decompile failure is report-level `DEGRADED`. The
   W-2 Done-when asserts `required_args == ()` on the 16 exec/file positives + `decoy_sink` + `gate_audit`;
   `unknown, ()` with the stated reason on the seven unresolvable-gate falsifiers; and `== truth` with
   provenance on the 16 arg positives.
2. **§130 inventory** — replace "Class-B baseline entries are all `migrated`" with: "W-2 closes the class-B
   **ABI/infrastructure** constants as `allowed` (with justifications); the class-B **per-binary target-guess**
   entries remain `open` (ratchet-valid, matching live hits) with their owning phase recorded in the W-2
   disposition table, to be closed by that phase; W-2 migrates 0." This introduces **no** new lifecycle state
   and leaves the parent §2 ratchet and W-5's "surviving current hit must be `allowed`" exit rule **unchanged**
   (W-5 and the dynamic phases close the remaining opens).
3. **§5 / R5 scope** — record that W-2 edits no class-B consumer (0 `migrated`) and that the one edit outside
   the inventory is the owner-approved ret2win arg-path rewire (§5.1/§5.4).
