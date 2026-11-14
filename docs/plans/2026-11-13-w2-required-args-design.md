# W-2 — required-args extraction: constants from the binary (class B) (2026-11-13, Rev 6)

Detailed design for **directive W, phase W-2**. Parent plan:
`docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md` (§3 principle 3 / §82-84, §4 row W-2 / §130,
§12 class-B notes / §240). Builds directly on **W-1** (`supwngo/analysis/payoff.py` + `SupwngoPayoff.java`,
merged PR #39, `9f543bb`). Branch `feat/w2-required-args` off `main` `9f543bb`.

> **Rev 6 — reworked after the Tier-2 (cyber) re-review of Rev 5 returned REWORK (2 BLOCKER / 6 MAJOR / 3
> MINOR; 7 CONFIRMED FIXED).** The reviewer confirmed all four Rev-4 BLOCKERs are genuinely closed (bounded
> enumeration, four-way classification, unary-only bool walk fail-closed, typed `ArgDiscovery` abstention),
> the corrected Ghidra API names, the ELF image-base guard, the live-envelope validation placement, and parent
> amendment 4. Rev 6 closes the two new soundness holes and the six refinements the re-review found, each
> grounded against source:
> - **Step 2 is reformulated as must-reach under adversarial branches** (§2.2), closing the new BLOCKER that a
>   short-circuit `||` lowered to **two CBRANCHes** (no `BOOL_OR` op) slipped past the unary walk and returned
>   `known,[]` (`gate_boolor`). Instead of cutting one residual assignment, Step 2 now prunes only the branches
>   an enumeration σ pins, leaves every non-enumerable / uncontrolled branch **both-edges adversarial**, deletes
>   the sink blocks and asks whether a terminal is still reachable; any σ that avoids the sink ⇒
>   `unknown(unresolved_gate)`. This is strictly more correct **and** simpler — it subsumes the Rev-5
>   "fail-closed on non-enumerable residual" special case, and it also fixes the MAJOR that a non-gating
>   relational branch (`if(a>K)audit(); sink;`) wrongly forced `unknown`: it now stays `known,[]` because the
>   sink is must-reached under every σ (falsifiers `gate_boolor`, `gate_relaudit`).
> - **A value reaching the comparison through a memory `LOAD` is `AMBIGUOUS`** (§2.1 new row), closing the
>   BLOCKER that a parameter round-tripped through a `volatile`/global slot (`g=a; if(g==X)…`) was analysed as
>   `NONPARAM` and the gate skipped, yielding false `known,[]` (falsifier `gate_reload`). Bounded store-to-load
>   forwarding is deferred to W-2.1.
> - **The bounded-enumeration domain is built in source-width bitvector space** (§2.2), closing the MAJOR that
>   `{0…255}∪{⊥}` for an 8-bit formal injected an impossible value and produced a false `unknown`: constants are
>   inverse-normalized to the formal's width and deduped, and `⊥` is added **only** when `|D(p)| < 2^width(p)`.
> - **Compound/multi-varnode storage is rejected** (§3 `simpleReg` guard; falsifier `gate_abicompound`), closing
>   the MAJOR that `VariableStorage.getRegister()` returns the first register even for a compound `{RDI,RSI}`
>   parameter, which would have delivered half a value. The guard requires
>   `isRegisterStorage() && !isCompoundStorage() && getVarnodeCount()==1` or emits `unknown(abi_class)`.
> - **The malformed-cache validator is shared and invoked on the cache path** (§4
>   `_validate_required_args(...)`), closing the MAJOR that `report_from_json` builds `PayoffEvidence` **directly**
>   (`payoff.py:432`), bypassing `FunctionEvidence`, so a same-position or `unknown`+non-empty cache row would not
>   have raised; it is now caught inside `report_from_json`'s `try` → cache miss (T7 cache cases).
> - **The consumer abstains on a required register outside the builder's `{rdi,rsi,rdx}`** (§5.4), closing the
>   MAJOR that the extractor's integer set `{rdi,rsi,rdx,rcx,r8,r9}` is wider than `_build_arg_chain`'s, so a 4th
>   arg at `rcx` was treated as missing/undeliverable; it now abstains loudly (zero `verify_payload`) rather than
>   truncate. Extending the builder to `rcx/r8/r9` is W-2.1.
> - **Image-base acquisition is ELF-scoped with an explicit `unavailable` outcome** (§5.4), closing the MAJOR
>   that the PE `ImageBase` fallback was unimplementable — `_lief_binary` is declared but `Binary.load` never
>   populates it (`binary.py:137,198`); a PE / no-base binary now returns `unavailable` (→ legacy), never a
>   misreported `rva_miss`.
> - MINORs folded: Step 1 classifies by §2.1 roles **first** (precedence-table order, `avoidance_gate` reserved
>   for pinnable-equality inverted guards); an **empty sink set returns `known,[]` before Step 0**; T12 counts
>   **one arg-bearing delivery per (offset × alignment variant)** (the `:227-244` alignment loop is **retained**,
>   only the `:262-289` no-args retry is removed). The compound-storage → `abi_class` production is proven by the
>   real-Ghidra `gate_abicompound` falsifier (T4), since a Python mock cannot synthesize Ghidra compound storage;
>   T10 covers only its envelope round-trip and precedence.
>
> **Rev 5 (lineage) — reworked after the Tier-2 (cyber) re-review of Rev 4 returned REWORK.** The reviewer confirmed the
> per-branch required-outcome algorithm on the named shapes, the `gate_mixed` discard of `[a=X]`, `gate_invert →
> unknown(avoidance_gate)`, the inventory 27-`allowed`/42-`open` partition (ratchet-valid, no new state), the
> `to_corpus_rva` math, and the `FunctionEvidence` try-boundary placement. Rev 5 fixes the four remaining
> soundness gaps the reviewer found, each grounded against source:
> - **Step 2 becomes a bounded parameter-value enumeration** (§2.2), replacing Rev-4's single residual cut, which
>   was unsound on `if (a==X || a!=Z) sink` (it wrongly returned `known,[]` though `a==Z` blocks the sink). The
>   enumeration pins explained params, ranges each free param over its compared constants plus one "other"
>   sentinel, prunes the CFG per assignment, and taints `unknown(unresolved_gate)` if **any** assignment (or an
>   over-cap / non-enumerable residual) leaves a sink unreachable (BLOCKER 1; falsifier `gate_disjineq`).
> - **A param comparison that is not exactly one `PARAM(full)` vs one constant is a gate, never a non-gate.** The
>   only true non-gate is **both operands `NONPARAM`.** `if (a==global_key)` and `if (a==b)` are unresolvable
>   parameter gates → `unknown(nonconst_gate)`, not `known,[]` (BLOCKER 2; falsifiers `gate_nonconst`,
>   `gate_paramcmp`).
> - **The boolean walk is unary-only and fails closed on every binary composition.** Rev-4's "walk through
>   `BOOL_AND/OR/XOR` to the ultimate comparison" could emit `X` for `(a==X)||flag` though `flag` alone reaches
>   the sink. Rev 5 follows **only** value-preserving unary ops (`COPY`, width-preserving `CAST`, `INT_ZEXT/SEXT`
>   per §2.1) and `BOOL_NEGATE` (parity); **any** binary boolean/bitwise op (`BOOL_AND/OR/XOR`, `INT_AND/OR/XOR`)
>   feeding a branch condition → `unknown(bool_compose)` (BLOCKER 3; falsifiers `gate_bool`, `gate_boolor`).
> - **The ret2win consumer gets a typed discovery result and abstains before delivery.** The current executor
>   treats a falsey `required_args` as "call win with no args" (`stack_techniques.py:219,227`) and explicitly
>   **retries known-required wins with no args** (`:262-289`), so returning `None` would deliver a payload, not
>   abstain. §5.4 defines `ArgDiscovery` ∈ {`known_empty`, `known_args`, `unknown`, `unavailable`, `rva_miss`};
>   `unknown`/`rva_miss` and any missing required pop-gadget **terminate before `verify_payload`**; only
>   `unavailable` invokes the legacy scanner; the no-args retry is **removed** for a `known_args` result. T12
>   asserts **zero** verifier calls on the abstain paths (BLOCKER 4).
>
> Also corrected: the Ghidra storage API is `p.getSymbol().getStorage()` (12.1.3 has no `HighParam.getStorage()`),
> `getBasicBlocks().get(0)` (ArrayList), and the 4-byte-formal sub-register is normalized through
> `Register.getBaseRegister()` (EDI→RDI); `abi_class` joins the reason precedence and T10 (MAJOR 1). The image
> base is read only when `pwntools_load_state is SUCCESS`, else derived as the lowest `PT_LOAD` vaddr from
> `binary.segments`, and `win_addr` is passed explicitly into `_discover_args` (MAJOR 2). `RequiredArg`/
> `FunctionEvidence` raise `ValueError` (not `assert`, which the envelope `try` would not catch), enforce
> `position == slot + 1`, and reject `bool` on every integer field (MAJOR 3). The parent prose at
> `…retire-hardcoded-target-values-plan.md:55` is amended too (§9, amendment 4).
>
> Rev 1→4 lineage (provenance ≠ gating; serialized provenance; versioned cache; disposition audit resolving the
> parent §130-vs-§240 contradiction; live-state extraction; per-branch required-outcome test; `gate_invert →
> avoidance_gate`; RVA normalization; no new inventory state; `FunctionEvidence` try-boundary) is retained.
> Parent amendments in §9.

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
  non-parameter). The **thirteen unresolvable-gate falsifiers** (`gate_invert`, `gate_disj`, `gate_disjineq`,
  `gate_relational`, `gate_arith`, `gate_mixed`, `gate_bool`, `gate_boolor`, `gate_reload`, `gate_nonconst`,
  `gate_paramcmp`, `gate_multieq`, `gate_abicompound`) yield `args_status=="unknown"` with an empty list and a
  `reason`: a real gate (or an unrepresentable ABI) W-2 cannot pin to a single required `param==const` value.
  `gate_audit` and `gate_relaudit` (branches that do **not** gate the sink) yield `known, ()`. A spurious arg is
  never emitted for any of them; `gate_arith`/`gate_mixed` never emit the literal compared constant.
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
if (a == X || a != Z)  system("/bin/sh");   // only a==Z is blocked; no required equality           → unknown      (gate_disjineq)
if (a > K)             system("/bin/sh");   // required outcome is a range                          → unknown      (gate_relational)
b = a * 2; if (b == X) system("/bin/sh");   // required value is X/2, not X                         → unknown      (gate_arith)
if (a == X && (b==Y||b==Z)) system(...);    // a==X required, b unresolved — must NOT return [a=X]  → unknown      (gate_mixed)
c = (a==X); if (c & flag) system(...);      // equality feeds a binary bitwise op, not a CBRANCH    → unknown      (gate_bool)
if ((a==X) || flag)    system(...);         // flag alone can reach the sink; X is not required     → unknown      (gate_boolor)
if (a == global_key)   system(...);         // other operand is not a constant                      → unknown      (gate_nonconst)
if (a == b)            system(...);         // both operands are parameters                         → unknown      (gate_paramcmp)
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
| `LOAD` (value from memory) | `AMBIGUOUS` — the P-code inputs describe the **address**, not the stored value, so "all inputs `NONPARAM`" would wrongly yield `NONPARAM` for `g = a; if (g == X)` via a real memory round-trip (`volatile`/global). Fail closed: a comparison operand defined by `LOAD` is `AMBIGUOUS` unless a bounded same-function store-to-load forward proves the slot was last written exactly a `PARAM(full)` with no aliasing store between (that refinement is optional for W-2; the corpus positives compare the parameter directly, not through a reload — confirmed in de-risk step 2). `gate_reload` is the falsifier. |
| `INDIRECT`, `PTRSUB`, `PTRADD` | `AMBIGUOUS` |
| arithmetic/logic (`INT_ADD/SUB/MULT/AND/OR/XOR/LEFT/RIGHT/…`) with a `PARAM`/`AMBIGUOUS` input | `AMBIGUOUS` |
| `MULTIEQUAL` (phi) | `PARAM(s,w,full)` **iff every** non-trivial arm is `PARAM` with the **same** slot and `full`; a back-edge arm may be ignored **only when it is exactly the phi's own output unchanged** (a true self-reference) — `phi(param, phi+1)` is `AMBIGUOUS`, not `PARAM`; **all** arms `NONPARAM` → `NONPARAM`; any other mix (`PARAM`+`NONPARAM`, two slots, a partial) → `AMBIGUOUS` |
| all inputs `NONPARAM` | `NONPARAM` |

Classification of a compare op's two inputs (closes BLOCKER 2 — a comparison that *carries* a parameter is a
gate unless proven pinnable; the **only** true non-gate is "no operand carries a parameter"). Call an operand
**param-carrying** if it is `PARAM(…)` or `AMBIGUOUS`. Evaluate in this order (first match wins):

- **non-gate** — **neither** operand is param-carrying (both are constants/globals/locals). Only this is skipped
  as a non-gate (`decoy_sink`).
- **ambiguous-param** — at least one operand is `AMBIGUOUS` (param-derived, slot/slice/value unpinnable). If it
  gates, `unknown(reason=ambiguous_gate)` (`gate_arith`, `gate_multieq`).
- **pinnable** — **exactly one** operand is `PARAM(slot, full)` **and** the other `isConstant()`. The only form
  that can emit a required value.
- **nonconst-param** — any remaining param-carrying comparison (no `AMBIGUOUS` operand, not pinnable):
  `PARAM(full)` vs a non-constant (global/memory load, i.e. `NONPARAM` but not `isConstant()`), or two
  `PARAM(full)` operands (`a==b`). No fixed value exists; if it gates a sink it is `unknown(reason=nonconst_gate)`
  (`gate_nonconst`, `gate_paramcmp`). **Never a non-gate.**

### 2.2 Requiredness: per-branch outcome test + must-reach value enumeration (BLOCKER 1/3 / B5, B6)

**Where the data comes from (B5).** W-1 does **not** persist the sink CALL op — `Evidence`
(`SupwngoPayoff.java:392`) stores only `sinkApis`/`sinkTargets`. The analysis runs **inside `analyze()`** (which
already walks `hf.getPcodeOps()` and finds each sink `op` at `:435-450`) while `op`/`hf`/`f` are live. The
**sink set** is **exactly the const-string-target sinks** (`EXEC_FAMILY`/`FILE_OPEN_FAMILY` with a
`CONST_STRING` target), gathered in that loop. `Entry = hf.getBasicBlocks().get(0)` (the block list is an
`ArrayList`); each sink block is `sinkOp.getParent()`. (Entry index and conditional accessors verified live in
de-risk step 2.)

**Empty sink set — early return (MINOR, Rev-5 `:322`).** If the const-string sink set is **empty** (the function
is not a payoff at all), return `known, ()` **immediately**, before Step 0. (The must-reach test below is
defined over a non-empty sink set; with no sink it would vacuously report "avoidable" and taint everything.)

**Step 0 — baseline reachability (B6).** If any sink block is unreachable from `Entry` in the uncut graph
(irreducible CFG, unresolved `BRANCHIND`/jump table) → emit nothing, taint `unknown(reason=irreducible_cflow)`.

**Collect gating param branches — unary-only condition walk (closes BLOCKER 3).** For every `CBRANCH`, resolve
its governing comparison by walking the condition varnode back through **value-preserving unary ops only**:
`COPY`, width-preserving `CAST`, `INT_ZEXT`/`INT_SEXT` (per §2.1), and `BOOL_NEGATE` (flipping an inversion-parity
bit). The walk succeeds only if it terminates at a **single** integer comparison op (`INT_EQUAL`, `INT_NOTEQUAL`,
`INT_SLESS`, `INT_LESS`, …). It **fails closed** when:
- the chain contains **any binary boolean/bitwise combinator** — `BOOL_AND`, `BOOL_OR`, `BOOL_XOR`, `INT_AND`,
  `INT_OR`, `INT_XOR` — feeding the branch condition (it cannot be reduced to one required comparison):
  `unknown(reason=bool_compose)` (`gate_bool`, `gate_boolor`); **or**
- the comparison's boolean result **fans out** to more than one `CBRANCH`, or to a non-branch use
  (stored/returned/phi) with no single governing branch: `unknown(reason=bool_fanout)`.

A branch is **param-dependent** if its governing comparison is `pinnable`, `nonconst-param`, or `ambiguous-param`
(§2.1); all other branches (non-parameter comparisons, unresolved indirect) are **uncontrolled**. A branch is
**enumerable** iff it is a `pinnable` equality (`PARAM(full)` vs constant); everything else — `nonconst-param`,
`ambiguous-param`, relational, and every uncontrolled branch — is **non-enumerable** and is treated
**adversarially** in Step 2 (its outcome is not fixed; the sink must be reached regardless of it). This is what
catches a short-circuit `||`/`&&` **lowered to control flow** rather than a `BOOL_*` op (`a==X || global_flag`
compiles at `-O0` to two `CBRANCH`es, no `BOOL_OR` — the bool-compose rule above would not fire, so the
uncontrolled `global_flag` branch must instead be adversarial; `gate_boolor` is the falsifier).

**Step 1 — per-branch required outcome (emit or taint).** For each param-dependent branch `b`: cut each of `b`'s
two out-edges in turn and test sink reachability from `Entry`. If exactly one cut disconnects **every** sink
block, that is `b`'s **required edge** `r_b` (`b` individually gates the sinks). Then:
Classify `b` by §2.1 operand roles **first** (so the reason is unambiguous when several descriptions fit — e.g.
`if(a==global_key) return` is both inverted and non-constant; it is `nonconst_gate`, matching the §2.2
precedence, not `avoidance_gate`):
- `b` is `ambiguous-param` → `unknown(reason=ambiguous_gate)` (`gate_arith`, `gate_multieq`).
- `b` is `nonconst-param` → `unknown(reason=nonconst_gate)` (`gate_nonconst`, `gate_paramcmp`).
- `b` is a **relational** `pinnable`/param comparison → `unknown(reason=relational_gate)` (`gate_relational`).
- `b` is a `pinnable` **equality** and `r_b` is the **`param == const` true** outcome (`INT_EQUAL` true-edge /
  `INT_NOTEQUAL` false-edge) → **emit** `(slot+1, value)` with provenance (§2.4); mark `b` **explained** and
  record its required outcome.
- `b` is a `pinnable` **equality** but `r_b` is the **inequality** outcome (`INT_EQUAL` false / `INT_NOTEQUAL`
  true) → `unknown(reason=avoidance_gate)` (`gate_invert`). (`avoidance_gate` is therefore reserved for a
  *pinnable-equality* inverted guard only.)
- neither cut disconnects the sinks → `b` does **not individually gate** → carry it to Step 2.

If two explained branches pin the **same** slot to **different** values → `unknown(reason=conflict)`. Identical
`(slot, value)` pairs are deduped before emission (B6).

**Step 2 — must-reach enumeration (closes BLOCKER 1 and the CFG-`||`/non-gating-relational cases; replaces
Rev-5's may-reach cut).** If Step 1 raised no `unknown`, confirm the emitted equalities are **jointly sufficient
and complete**: the caller controls only the parameters, so a `known` list `L` must **guarantee** the sink —
pinning `L` (and any free param to any value) reaches a sink **no matter what the uncontrolled branches do**. The
test is therefore *must-reach* (sink unavoidable), not *may-reach*; a sink that is merely reachable *through* an
uncontrolled branch (`global_flag`) is **not** guaranteed.

Let the **enumerable set** be every `pinnable`-equality branch; **free params** `F` = the params compared in
enumerable branches that were **not** emitted in Step 1.
- **Interesting-value domain** per free param `p`, built in `p`'s **source-width bitvector space** (MAJOR, Rev-5
  `:225`): `D(p) = { each constant p is compared against (inverse-normalized through any `ZEXT`/`SEXT` to the
  source width, de-duplicated) }`, plus **one sentinel `⊥`** (an unrepresented value) **only when**
  `|D(p)| < 2^width(p)` (so an exhaustive 8-bit cascade covering all 256 values adds no phantom 257th case).
- **Bound:** if `∏_{p∈F} |D(p)|` exceeds `ENUM_CAP = 4096` → `unknown(reason=unresolved_gate)` (fail closed).
- For each assignment `σ` in the cartesian product, build the **pruned CFG**: fix every `pinnable`-equality
  branch whose param is bound by `σ` (emitted or free) to its determined edge (remove the other); leave **both**
  edges of every **non-enumerable** branch — relational, `nonconst-param`, `ambiguous-param`, and every
  **uncontrolled** (non-parameter) branch — in place (**adversarial**). Then test **sink-avoidability**: delete
  the sink blocks and BFS from `Entry`; if any **return/terminal** block (a `RETURN`, or a block with no
  successors that is not a sink) is reachable, the sink is **avoidable** under `σ`.
  - If **some** `σ` makes the sink avoidable ⇒ a residual constraint `L` does not capture (a disjunction, an
    `a==X || a!=Z`, a `global_flag` the caller can't set) ⇒ `unknown(reason=unresolved_gate)` — **the
    emitted-so-far list is discarded; W-2 never returns a partial `known`.**
  - If **no** `σ` makes the sink avoidable (the sink is unavoidable for every assignment) ⇒ `known` with the
    emitted list (possibly empty — a truly ungated sink: `exec`/`file`/`decoy_sink`/`gate_audit`, and a
    non-gating uncontrolled branch such as `if(a>K) audit(); sink;`, whose both edges rejoin before the
    unconditional sink).

The must-reach formulation **subsumes** Rev-5's "fail closed on any non-enumerable branch in U": a non-gating
relational/uncontrolled branch no longer forces `unknown` (its two edges rejoin before the sink, so no `σ` can
avoid the sink through it), while a *gating* one (a disjunction arm, a `global_flag`) does expose an avoid-path
and correctly yields `unknown`.

**Reason precedence (MINOR 1).** When several apply, the function's `reason` is the first of:
`irreducible_cflow` ▸ `analysis_exception` ▸ `conflict` ▸ `abi_class` ▸ `bool_compose` ▸ `bool_fanout`
▸ `ambiguous_gate` ▸ `nonconst_gate` ▸ `avoidance_gate` ▸ `relational_gate` ▸ `unresolved_gate`. Tests assert
the exact reason per shape (§6 T10).

**Worked cases** (each has a §3a falsifier; "avoidable?" = the Step-2 must-reach test): `exec/file`/`decoy_sink`
→`known,[]`; `gate_audit` (`if(a==X)audit(); sink;`)→ a==X branch does not individually gate, both edges rejoin
before the unconditional sink → no `σ` avoids →`known,[]`; non-gating relational `if(a>K)audit(); sink;`→ a>K
adversarial but both edges rejoin → no `σ` avoids →`known,[]` (the Rev-5 `:220` false-unknown is gone); genuine
`early` (`if(a!=X)return`)→ required edge is the `NOTEQUAL`-false (`a==X`) edge, pinnable → emit `X`, `a=X`
unavoidable →`known,[X]`; `gate_invert` (`if(a==X)return`)→ pinnable-equality inverted guard →`avoidance_gate`;
`gate_nonconst`/`gate_paramcmp`→ gating equality against a non-constant →`nonconst_gate`; `gate_disj`
(`a==X||a==Y`)→ `a=⊥` avoids →`unresolved_gate`; `gate_disjineq` (`a==X||a!=Z`)→ `a=Z` avoids
→`unresolved_gate`; `gate_mixed` (`a==X && (b==Y||b==Z)`)→ emit `a=X`, free `b∈{Y,Z,⊥}`, `b=⊥` avoids
→`unresolved_gate`, list discarded; `gate_relational` (`if(a>K)sink; else return;`)→ individually gates,
relational →`relational_gate`; `gate_arith` (`b=a*2;b==X`)→ operand `AMBIGUOUS`→`ambiguous_gate`, literal never
emitted; `gate_bool` (`c=(a==X); if(c&flag)`)→ binary `INT_AND` in the condition →`bool_compose`; `gate_boolor`
(`if(a==X || global_flag)`, **lowered to two `CBRANCH`es**)→ `global_flag` branch is uncontrolled/adversarial,
`a=⊥` avoids →`unresolved_gate`; `gate_reload` (`g=a; if(g==X)` via a real memory `LOAD`)→ operand is a `LOAD`
→`AMBIGUOUS`→`ambiguous_gate`; `gate_multieq` (phi over two slots)→ operand `AMBIGUOUS`→`ambiguous_gate`; `arg3`
(`a==X&&b==Y&&c==Z`)→ three equalities each individually gate → emit `X,Y,Z`, all pinned → unavoidable
→`known,[X,Y,Z]`.

### 2.3 `args_status`: two states + an explicit reason (B2, B3, MINOR 2)

- **`known`** — successfully decompiled, gates fully analysed; the list is authoritative. **Empty iff the sinks
  are ungated** (no param-dependent branch gates any sink): `exec`/`file`, `decoy_sink`, `gate_audit`,
  `gate_relaudit`.
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
  "reg": "<SysV integer *base* register, e.g. rdi>",    // getSymbol().getStorage().getRegister().getBaseRegister() (§3); EDI→RDI normalized, never a position guess
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
- **Slot/storage API (pinned, Ghidra 12.1.3 — corrected per MAJOR 1; `HighParam.getStorage()` does *not* exist
  in 12.1.3):**
  ```java
  if (v.isInput() && v.getHigh() instanceof HighParam) {
      HighParam p = (HighParam) v.getHigh();
      int slot = p.getSlot();                           // 0-based entry value
      VariableStorage st = p.getSymbol().getStorage();  // storage lives on HighSymbol, not HighParam
      // Reject compound/aggregate storage: getRegister() returns the FIRST register even
      // for a {RDI,RSI} two-register parameter, which the consumer would half-fill.
      boolean simpleReg = st.isRegisterStorage() && !st.isCompoundStorage()
                          && st.getVarnodeCount() == 1;
      Register r  = simpleReg ? st.getRegister() : null; // may be a 32-bit sub-register (EDI)
      Register br = (r != null) ? r.getBaseRegister()    // normalize EDI→RDI / ESI→RSI for the ROP consumer
                                : null;
  }
  // or by index: hf.getLocalSymbolMap().getParam(i); getNumParams() bounds i.
  ```
  The corpus deliberately includes `int`/`unsigned int` params (`payoff_source.py:74`), whose 4-byte storage
  yields `EDI`/`ESI`/`EDX`; the `reg` field records the **base** register `br`. A parameter at or below the
  highest required position makes the function `unknown(reason=abi_class)` when its storage is **not a single
  simple register** (`!simpleReg` — stack/aggregate/**compound multi-register**, so `r == null`) or whose base
  is **not** a SysV integer argument register `{RDI,RSI,RDX,RCX,R8,R9}` (xmm/float). This closes both the MAJOR 5
  "position ≠ register" case (`f(double x, long a)`, where `a` is position 2 but uses `RDI`) and the Rev-5
  compound-storage case (a `{RDI,RSI}` 16-byte struct-by-value must **not** be accepted as `RDI`).
- **CFG API:** `hf.getBasicBlocks()` returns an `ArrayList<PcodeBlockBasic>` — entry is `.get(0)`, **not** `[0]`;
  successors via `getOut(i)`/`getOutSize()` and the conditional `getTrueOut()`/`getFalseOut()`; reachability-with-
  edges-cut is a BFS over a copy with the cut edge(s) masked. Accessors verified live (de-risk step 2).
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
| `gate_audit` | `if (a==X) benign(); sink;` | `known` | `[]` | unconditional-sink false positive (equality branch does not gate) |
| `gate_relaudit` | `if (a > K) benign(); sink;` | `known` | `[]` | **must-reach regression** — a non-gating *relational* branch must NOT force `unknown` (Rev-5 `:220`) |
| `gate_invert` | `if (a==X) return; sink;` | `unknown` (`avoidance_gate`) | `[]` | inverted-guard: a!=X is not a required value |
| `gate_disj` | `if (a==X \|\| a==Y) sink;` | `unknown` (`unresolved_gate`) | `[]` | disjunction — enumeration `a=⊥` disconnects |
| `gate_disjineq` | `if (a==X \|\| a!=Z) sink;` | `unknown` (`unresolved_gate`) | `[]` | **Step-2 single-cut soundness** — only `a=Z` blocks (BLOCKER 1) |
| `gate_relational` | `if (a > K) sink;` | `unknown` (`relational_gate`) | `[]` | relational gate |
| `gate_arith` | `b=a*2; if (b==X) sink;` | `unknown` (`ambiguous_gate`) | `[]` | redefined-param wrong value (also assert **no emit == X**) |
| `gate_mixed` | `if (a==X && (b==Y\|\|b==Z)) sink;` | `unknown` (`unresolved_gate`) | `[]` | **partial-known** (must NOT return `[a=X]`) (BLOCKER 1) |
| `gate_bool` | `c=(a==X); if (c & flag) sink;` | `unknown` (`bool_compose`) | `[]` | binary `INT_AND` **P-code op** in condition (Rev-5 BLOCKER 3); T4 asserts the op form is `INT_AND`/`BOOL_AND` |
| `gate_boolor` | `if ((a==X) \|\| global_flag) sink;` **short-circuit → two `CBRANCH`es** | `unknown` (`unresolved_gate`) | `[]` | CFG-form `\|\|` (no `BOOL_OR` op) — the uncontrolled `global_flag` branch is adversarial, `a=⊥` avoids (Rev-5 new-BLOCKER); T4 asserts the P-code is **two `CBRANCH`es, no `BOOL_OR`** |
| `gate_reload` | `volatile int g; g = a; if (g == X) sink;` | `unknown` (`ambiguous_gate`) | `[]` | parameter round-tripped through a real memory `LOAD` (Rev-5 new-BLOCKER); operand `LOAD`→`AMBIGUOUS` |
| `gate_nonconst` | `if (a == global_key) sink;` | `unknown` (`nonconst_gate`) | `[]` | param-vs-global false `known` (Rev-4 BLOCKER 2) |
| `gate_paramcmp` | `if (a == b) sink;` (two params) | `unknown` (`nonconst_gate`) | `[]` | param-vs-param false `known` (Rev-4 BLOCKER 2) |
| `gate_multieq` | phi merging two different param slots, then `== X` | `unknown` (`ambiguous_gate`) | `[]` | mixed-slot MULTIEQUAL mis-assignment (MAJOR 1) |
| `gate_abicompound` | `struct pair{long a,b;}; void win(struct pair p){ if(p.a==X) sink; }` — a ≤16B all-integer struct gets **compound storage** `{RDI,RSI}` | `unknown` (`abi_class`) | `[]` | compound/multi-varnode storage must NOT be accepted as its first register `RDI` (silent half-value delivery) — Rev-5 MAJOR `:303`; T4 asserts the HighParam storage is `isCompoundStorage()` / `getVarnodeCount()>1` so the §3 `simpleReg` guard fires |

Emitted as a **separate `role:"falsifier"` category** in `benchmark/gen/payoff/`, **not** added to `SHAPES`, so
the merged W-1 denominators (parent §128) are **unchanged**. Matrix (R6): one non-PIE unstripped ELF per shape
(**16 units**) + a `gate_disj` stripped twin + a `gate_disj` PE variant = **18 units** (one representative twin/PE
is enough — every falsifier shares the same P-code requiredness pass, so strip/PE robustness is a property of the
pass, not of each shape). `index.json` lists each with `role:"falsifier"`, truth
`args_status`/`required_args`/`reason`, and (for `gate_arith`) the literal compared constant. **Generator
hygiene:** the new category is skipped by every W-1 counter/test that filters `index.json` by `role`, draws from
the existing `_Consts` stream without perturbing positives' constants/RVAs, and is verified in §7 step 1 by
diffing the regenerated positive/twin/negative/PE rows against the W-1 baseline.

## 4. Python change (`supwngo/analysis/payoff.py`)

Flow: `_evidence_from_envelope → List[FunctionEvidence]` (`:580/601`) → `rank_candidates` (`:307`) →
`score_function → PayoffEvidence` (`:247/298`) → `PayoffCandidate` (`:203`). Args flow the whole way (B8):

- Frozen `RequiredArg` dataclass mirrors §2.4. Its `__post_init__` **raises `ValueError`** (never a bare
  `assert` — `AssertionError` is not in the envelope `try`'s `except` tuple, so an `assert` would escape
  `rank_payoffs`, MAJOR 3) on any of: `position<1`, `slot<0`, **`position != slot + 1`** (the SysV position is
  the slot ordinal + 1 — enforced, not merely independent validity), `width<=0`, `src_width<=0`,
  `op∉{INT_EQUAL,INT_NOTEQUAL}`, `reg` not a known SysV integer base register, `sink_addrs` empty,
  `terminal!="HighParam"`, or a `transform` name that is not value-preserving. **Every integer field**
  (`position`, `value`, `slot`, `width`, `src_width`, `op_addr`, and each `sink_addrs` element) is checked with
  `isinstance(x,int) and not isinstance(x,bool)` (the W-1 guard, `:331`) so `bool` is rejected as an int
  everywhere; `op_addr`/`sink_addrs` elements must additionally be `>= 0`.
- **Shared cross-field validator.** A module-level `_validate_required_args(status, reason, args) -> None`
  **raises `ValueError`** on any §2.3 invariant breach: `unknown ⇒ args==() ∧ reason!=None`; `known ⇒
  reason==None`; **unique positions**; **no same-slot/position value conflict**. It is called from **both** the
  live path and the cache path (next two bullets), so the cross-field invariant cannot be bypassed by whichever
  constructor a path happens to use.
- **`FunctionEvidence`** (`:179`) gains `required_args`, `args_status`, `args_reason`, populated by
  `_evidence_from_envelope`; its `__post_init__` calls `_validate_required_args(...)`. Both `RequiredArg` and
  `FunctionEvidence` are constructed by `_evidence_from_envelope` **inside the envelope `try`** (`:601`, within
  `:859-862`), whose `except (KeyError,TypeError,ValueError)` turns a malformed **live** record into `ERROR`
  (Rev 3 put this on `PayoffEvidence`, built by `rank_candidates` at `:315` **outside** that `try`, so it would
  have escaped — MAJOR 3 fixed).
- **`score_function`** copies the already-validated fields into `PayoffEvidence` (`:298`); `PayoffCandidate`
  reads them through. `PayoffEvidence` performs **no fail-raising re-validation** (built outside the `try`, a
  raise there would escape); it only carries the copied fields.
- **Cache (Rev-5 MAJOR `payoff.py:422` — the cache path does NOT go through `FunctionEvidence`).**
  `report_to_json` (`:379`) and `report_from_json` (`:423`) gain the three fields (full provenance).
  `report_from_json` builds `PayoffEvidence` **directly** at `:432`, bypassing `FunctionEvidence` — so it must
  **call `_validate_required_args(...)` explicitly inside its existing `try`** (`:423-452`, which already catches
  `(KeyError,TypeError,ValueError) → None`). Then a malformed cache row — a bad per-arg field **or** a cross-field
  breach (two `RequiredArg`s with the **same position**, or `unknown` with a **non-empty** list) — becomes a safe
  **cache miss**, never a silently-wrong hit and never `ERROR`. `CACHE_ENVELOPE_VERSION` **`1 → 2`** (`:348`) ⇒ v1
  rows miss. T9 asserts miss→hit preserves all three; T7 asserts **envelope**-malformation → `ERROR`, and the two
  **cache** cross-field cases (same-position, `unknown`+non-empty) → **miss**.
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

### 5.4 Ret2win arg-path rewire (Option A — B3, BLOCKER 4, MAJOR 2/5)

**The consumer contract today (grounded, `stack_techniques.py:205-334`).** The Ret2Win executor calls
`required_args = self._discover_args(binary, win_name)` (`:219`), treats a **falsey** result as "call win with
no arguments" (the main loop at `:227-260` **always** reaches `verifier.verify_payload(...)` at `:244`, with or
without an arg chain), and then has an **explicit no-arg retry** at `:262-289` that re-delivers *known-required*
wins with no args. `_discover_args(binary, win_name)` (`:295-301`) takes no address/context and returns a bare
`List[int]`. So a `None`/`[]` return would **deliver a payload**, not abstain. The rewire therefore changes both
the discovery result type and the delivery control flow (BLOCKER 4):

- **Typed discovery result (BLOCKER 4).** `_discover_args(binary, win_name, win_addr, context)` — signature gains
  `win_addr`/`context` (MAJOR 2) — returns an `ArgDiscovery` tagged union, never a bare list:
  `known_args(pairs)` | `known_empty` | `unknown` | `unavailable` | `rva_miss`.
- **Address-domain-correct lookup (B3) + image-base acquisition (MAJOR 2; PE scoping, Rev-5 `:137`).** The
  pipeline-chosen win address (`context.win_addr`/`win_function`, `profile_stage.py:132-148`: symbol table →
  `WinFunctionFinder` → `--win`) is **absolute/link-time**; candidate RVAs are image-base-relative
  (`to_corpus_rva`, `payoff.py:79`). The image base is **not** `binary.base_address` unconditionally — that field
  (`binary.py:142`) is populated **only** when pwntools loaded (`binary.py:223`) and is otherwise `0`. Acquire it
  in order: (a) `binary.base_address` **iff** `binary.pwntools_load_state is PwntoolsLoadState.SUCCESS`; else
  (b) the **lowest `PT_LOAD` vaddr** from `binary.segments` (populated independently by the ELF pyelftools loader,
  `binary.py:314-324`: `min(s.address for s in binary.segments if s.type == 'PT_LOAD')`). If **neither** yields a
  base — a PE, or a binary with no loadable segments and a failed pwntools load — the base is **unacquirable**
  (the `Binary` abstraction exposes no populated PE `ImageBase`: `_lief_binary` is declared but `Binary.load`
  never fills it, `binary.py:137,198`), so `_discover_args` returns **`unavailable`** (→ legacy path), **not**
  `rva_miss` (which would wrongly claim the win was absent from a correctly-analysed report). W-2's consumer
  end-to-end path is ELF-only; a PE `ImageBase` seam is W-2.1. With a base, `_discover_args` normalizes
  `win_rva = to_corpus_rva(win_addr, image_base)` and calls `required_args_for(report, rva=win_rva)` (**not**
  `candidates[0]`), mapping the report/lookup outcome to the tagged union:
  - image base unacquirable (above) → `unavailable`;
  - lookup returns a **non-empty** pair list → `known_args` with each `(position, value)` mapped to its recorded
    base `reg` (§2.4);
  - lookup returns **`()`** (report `COMPLETE`, candidate `known`, ungated) → `known_empty`;
  - lookup returns **`None`** with a **`COMPLETE`** report (candidate `args_status=="unknown"`) → `unknown`;
  - lookup returns **`None`** with a **non-`COMPLETE`** report (backend unavailable / `DEGRADED`) → `unavailable`;
  - the normalized `win_rva` matches **no** candidate in a `COMPLETE` report → `rva_miss`.
- **Delivery routing — abstain terminates before `verify_payload` (BLOCKER 4).** The executor branches on the
  tag:
  - `known_args` → `_build_arg_chain` pops each value into its recorded `reg`, deliver, verify. **The no-arg
    retry (`:262-289`) is removed for this case** — re-delivering a known-required win with no args is a doomed,
    misleading attempt.
  - `known_empty` → deliver win with an empty chain and verify (the current ungated behavior, now reached only
    when the extractor *proved* the sink ungated).
  - `unknown` or `rva_miss`; **or** `known_args` naming a required `reg` **outside the builder-supported set**
    `{rdi, rsi, rdx}` (MAJOR `profile_stage.py:77`: the extractor's integer-ABI set is `{rdi,rsi,rdx,rcx,r8,r9}`
    but `_build_arg_chain` (`:303-329`) emits pops only for `rdi/rsi/rdx` — a 4th–6th integer arg at `rcx/r8/r9`
    is correctly *extracted* yet **undeliverable** by this builder); **or** `known_args` whose needed
    pop-gadget (`pop rdi`/`pop rsi`/`pop rdx`) is **absent** → **do not call `verify_payload`**; return a
    skipped/abstain result carrying the reason (`required args unresolved — provide via --win / manual values`,
    the directive-W PASS path), so the pipeline moves to the next technique without delivering a payload that
    cannot work. (Extending the builder to `rcx/r8/r9` — discover those gadget keys and add their `pop` chains —
    is the **W-2.1** follow-up; W-2 abstains loudly rather than silently truncating a 4-arg win.)
  - `unavailable` → the extractor had no opinion, so fall back to the legacy `find_required_args` (its `List[int]`
    normalized to `(reg, value)` pairs via the positional SysV map) and deliver as today, for compatibility.
- **Register from provenance, loud on unsupported (MAJOR 5; builder subset, Rev-5 `:77`).** `_build_arg_chain`
  consumes `(reg, value)` pairs and emits the pop-gadget for each `reg` directly (no position→reg guess). Two
  distinct exclusions apply, at two layers: a parameter whose `reg` is non-integer/stack/xmm is already
  `unknown(abi_class)` at **extraction** (§3) and never produces a `known_args`; a parameter at a valid integer
  reg that the **builder** cannot emit (`rcx/r8/r9`, or any `rdi/rsi/rdx` whose gadget is missing) is caught at
  the **consumer** gate above and abstains. The builder therefore only ever sees `reg ∈ {rdi,rsi,rdx}` with a
  present gadget. Existing `hex()`-per-element logging (`:223`) is updated for the pair form.
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
| T4 | falsifiers, per shape (§3a, 16 shapes) | real-Ghidra | each shape's exact `(args_status, required_args, reason)` per the §3a table; `gate_mixed`/`gate_disjineq`/`gate_boolor` yield `unknown(unresolved_gate)` with **no `[a=X]`**; `gate_audit`/`gate_relaudit` yield `known, []` (non-gating branch must NOT force `unknown`); `gate_arith` emits no value == its literal constant; `gate_bool`→`bool_compose` (assert op form `INT_AND`/`BOOL_AND`); `gate_boolor` P-code is **two `CBRANCH`es, no `BOOL_OR`**; `gate_reload` operand is a real `LOAD`→`ambiguous_gate`; `gate_nonconst`/`gate_paramcmp`→`nonconst_gate`; `gate_abicompound`→`abi_class` (assert storage `isCompoundStorage()`/`getVarnodeCount()>1`) |
| T5 | rename + strip twins | real-Ghidra | truth on 16/16 rename + 16/16 strip positives; `gate_disj` strip twin stays `unknown, ()` |
| T6 | PE | real-Ghidra | truth on **all four** PE arg binaries; 32-bit agreement; `gate_disj` PE variant stays `unknown, ()` |
| T7 | malformed records | mock | an **envelope** record with a bad field / non-unique position / same-slot conflict / **`position != slot + 1`** / `bool` in **any** integer field (`position`/`value`/`slot`/`width`/`src_width`/`op_addr`/a `sink_addrs` element) / empty `sink_addrs` / `unknown`+non-empty / missing reason → report `ERROR`, raised as a **`ValueError`** (not `AssertionError`) from `RequiredArg`/`FunctionEvidence.__post_init__` **inside** the envelope `try`, so it is caught and converted; a malformed **cache** row — a bad per-arg field, **or** a cross-field breach that bypasses `FunctionEvidence` (two `RequiredArg`s at the **same position**, **or** `unknown` with a **non-empty** list), caught by the explicit `_validate_required_args(...)` inside `report_from_json`'s `try` — → cache **miss** (not `ERROR`) |
| T8 | width/masking + constant-left | mock/unit | a 32-bit constant reported un-truncated, matches `CONST_RANGE`; constant-as-left-operand handled identically; a SEXT constant failing the canonical round-trip → `AMBIGUOUS` → `unknown` |
| T9 | cache round-trip | mock | miss→hit preserves `required_args` (incl. provenance+`reg`), `args_status`, `args_reason`; a v1 row misses |
| T10 | reason precedence | mock/crafted | each `unknown` reason (`irreducible_cflow`/`analysis_exception`/`conflict`/`abi_class`/`bool_compose`/`bool_fanout`/`ambiguous_gate`/`nonconst_gate`/`avoidance_gate`/`relational_gate`/`unresolved_gate`) is produced with the **exact** expected code under the §2.2 precedence (incl. a crafted case where two reasons apply and the higher-precedence one wins — e.g. `abi_class` over `unresolved_gate`); a decompile failure → report `DEGRADED`; an args-pass exception → `unknown(analysis_exception)` for that record without downgrading the report. (The **production** of `abi_class` from real compound storage is proven by the real-Ghidra `gate_abicompound` falsifier in T4, since a Python mock cannot synthesize Ghidra compound `VariableStorage`; T10 covers only the reason's envelope round-trip and precedence ordering.) |
| T11 | inventory | unit | 27 entries `allowed`+justification; 42 still `open` **and matching live hits** (not stale); frozen fields unchanged; 0 `migrated`; no class-B consumer edit; the ret2win rewire is the only non-inventory edit |
| T12 | ret2win arg path (§5.4) | seam=always-run; e2e=gated | **seam** (patch `rank_payoffs`; assert on a **spied `verifier.verify_payload`**): `known_args` at **random, non-contiguous positions** with recorded `reg`s ⇒ `_discover_args` (normalized-RVA lookup) → `_build_arg_chain` pops each value into **its recorded `reg`**; **every** delivery is **arg-bearing** and the call count equals **(offsets × applicable alignment variants)** — the `for use_align in (True,False)` exploration at `:227-244` is **retained** (one aligned + one unaligned arg-bearing pass per offset), while the separate `"(no args)"` retry at `:262-289` is **removed** (asserted: zero deliveries whose chain omits the arg pops); `known_empty` ⇒ arg-free deliveries, same **(offsets × alignment variants)** count, no arg pops; `COMPLETE`+`unknown` ⇒ **abstain: zero `verify_payload` calls**, no legacy call; `rva_miss` (normalized `win_rva` matches no candidate) ⇒ **zero `verify_payload` calls**; `known_args` but a required `pop` gadget absent ⇒ **zero `verify_payload` calls**; `known_args` naming a required `reg` **outside `{rdi,rsi,rdx}`** (e.g. a 4th arg at `rcx`, within the extractor's integer set but beyond the builder, §5.4) ⇒ **zero `verify_payload` calls** (abstain, not a truncated chain); non-`COMPLETE` report ⇒ `unavailable` → legacy fallback (normalized to pairs), delivered. Image base: one case with `pwntools_load_state==SUCCESS` (uses `base_address`) and one with `!=SUCCESS` (derives lowest `PT_LOAD`); one **no-base/PE** case ⇒ `unavailable` (not `rva_miss`). **end-to-end (gated):** on a dedicated overflowable non-PIE no-canary `arg1` **and** `arg3` fixture (§7 step 1; offsets provided, directive-W PASS criterion b; `arg3` has a `pop rdx` gadget), the win call is reached with each param set; the **stripped** variant supplies `--win <link-time VADDR>` (normalized to RVA for lookup, used absolute for the jump — an override-assisted stripped path, **not** automatic stripped win discovery, PASS criterion a) |

T1–T6 + T3′ extend `tests/test_payoff_ranker.py` (same `index.json` driver, module-scoped cache). T7–T10 + the
T12 seam are always-run mocks. T12's end-to-end leg is gated.

**Optimization note (R7):** the dev corpus is `-O0` (`generate.py:101`); W-2 makes **no** optimized-binary
soundness claim and ships no optimization detector. The `and`/`nest`/`early` positives plus the 16 falsifier
shapes are the robustness envelope W-2 proves; optimized fixtures are future work.

## 7. Execution order (one commit per step, RED test first; execute on Sonnet)

1. **Corpus falsifiers + e2e fixture** — add the `falsifier` category + the **16 shapes** (§3a) and the
   overflowable `arg1`/`arg3` ret2win fixture (§6 T12) to `benchmark/gen/payoff/`; regenerate dev; confirm
   `index.json` carries the **18** `role:"falsifier"` units (16 ELF + `gate_disj` strip twin + `gate_disj` PE)
   with truth `args_status`/`required_args`/`reason`, and **diff the positive/twin/negative/PE rows against the
   W-1 baseline to prove them byte-unchanged**.
2. **Extractor args pass** — `SupwngoPayoff.java`: `traceParamSlot` lattice with the entry-value/size/SEXT/
   back-edge/CAST guards (§2.1), the **unary-only** condition walk (fail closed on binary boolean/bitwise ops,
   §2.2), per-branch required-outcome (Step 1) + **bounded parameter-value enumeration** (Step 2, `ENUM_CAP`),
   `p.getSymbol().getStorage().getRegister().getBaseRegister()`-derived `reg` + `abi_class` taint,
   `getBasicBlocks().get(0)` entry, own `try/catch`, dedup/order, provenance (§2.4), `SCRIPT_VERSION → w2.0`.
   De-risk by running `analyzeHeadless` by hand on one each of `arg3`, `gate_invert`, `gate_disj`,
   `gate_disjineq`, `gate_mixed`, `gate_bool`, `gate_boolor` (confirm the short-circuit lowers to **two
   `CBRANCH`es, no `BOOL_OR`**), `gate_reload` (confirm the operand is a real `LOAD`), `gate_nonconst`,
   `gate_arith`, and `gate_abicompound` (confirm the HighParam storage is compound / `getVarnodeCount()>1`),
   verifying the conditional-successor accessors, the `ArrayList` entry index, and the
   `getSymbol().getStorage()` + `isCompoundStorage()` + `getBaseRegister()` API **live** (MAJOR 1).
3. **Python model** — `RequiredArg` + `__post_init__`; fields + cross-field invariant on **`FunctionEvidence`**
   (inside the envelope `try`) and pass-through in `score_function`; `required_args_for`/`required_arg_regs`
   (reject non-`COMPLETE`); cache ser/deser both paths + `CACHE_ENVELOPE_VERSION → 2` (cache-miss semantics);
   T7–T10.
4. **Corpus tests** — T1–T6 + T3′ (gated).
5. **Inventory** — close the 27 `allowed` in the baseline; leave the 42 `open` untouched; T11 green.
6. **Ret2win rewire** — `_discover_args(binary, win_name, win_addr, context)` returning the `ArgDiscovery`
   tagged union (image-base guard: `pwntools_load_state==SUCCESS` else lowest `PT_LOAD`, else `unavailable` for
   no-base/PE; normalized-RVA lookup); restructure the Ret2Win executor's delivery loop so
   `unknown`/`rva_miss`/missing-gadget/**reg-outside-`{rdi,rsi,rdx}`** **terminate before `verify_payload`**,
   the `for use_align in (True,False)` exploration (`:227-244`) is **retained**, and the separate no-args retry
   (`:262-289`) is **removed** for `known_args`; `_build_arg_chain` (register-from-provenance, pair-form,
   updated logging); `find_required_args` deprecated. T12 seam (spied verifier) + end-to-end green.
7. **Docs + CHANGELOG** — status note + one `Added` entry; full gate under `SUPWNGO_REQUIRE_GHIDRA=1`; PR (incl.
   the §9 parent amendments); merge; worktree/branch cleanup.

## 8. Risks

- **R1 — CFG/storage API drift.** Conditional-successor accessors, the `ArrayList` entry index, `BOOL_NEGATE`
  parity, and `p.getSymbol().getStorage()` + `Register.getBaseRegister()` verified live (de-risk step 2); an
  unresolvable case → `unknown`, never a wrong arg.
- **R2 — slot coalescing / redefinition / memory round-trip.** The entry-value guard (§2.1) yields `AMBIGUOUS`
  → `unknown` on a redefined or phi-merged slot (`gate_arith`/`gate_multieq`), and a value that reaches the
  comparison via a memory `LOAD` is `AMBIGUOUS` (the `LOAD` row in §2.1 — its P-code inputs are the address, not
  the stored value), so a parameter stashed through a global/stack slot cannot be mistaken for a direct compare
  (`gate_reload` proves it). Bounded store-to-load forwarding is a W-2.1 refinement, not a W-2 claim.
- **R3 — constant side/sign.** `INT_NOTEQUAL`(early) and `INT_EQUAL`(and/nest) map to the same `{position,value}`;
  value is the constant regardless of operand order, masked; SEXT canonical check guards sign. T2/T8.
- **R4 — cache-key churn.** `w1.1→w2.0` + envelope `1→2`; W-1 rows miss (intended). TOCTOU/COMPLETE-only rules
  unchanged.
- **R5 — scope.** 27 baseline closures, 0 class-B consumer edits, 1 owner-approved ret2win rewire; reviewer to
  confirm no edit beyond that and no new lifecycle state.
- **R6 — falsifier/fixture cost.** 18 falsifier units (16 ELF + 1 strip twin + 1 PE) + 1 e2e fixture, separate
  category; W-1 denominators untouched.
- **R7 — optimized binaries.** Out of scope; §5.4 abstains on `unknown`, no optimized guarantee, no detector.
- **R8 — ABI class.** Register read from Ghidra storage and normalized to the base register
  (`getBaseRegister()`); a `null`-register (stack/aggregate), **compound/multi-varnode** storage
  (`isCompoundStorage()` / `getVarnodeCount()>1`, `gate_abicompound`), or non-integer (xmm) param at/below the
  highest required position → `unknown(abi_class)`, never a mis-placed or half-written value.
- **R9 — must-reach soundness + enumeration domain (Step 2).** Step 2 decides requiredness by **must-reach under
  adversarial branches**: it prunes only the branches an enumeration assignment σ pins (pinnable-equality edges
  fixed by σ), leaves every non-enumerable / uncontrolled branch (relational / `nonconst-param` /
  `ambiguous-param` / global-reload) **both-edges open**, then asks whether a terminal is reachable with the
  sink blocks deleted; *any* σ under which the sink is avoidable ⇒ `unknown(unresolved_gate)`. The per-param
  domain is built in **source-width bitvector space** — constants inverse-normalized to the formal's width and
  deduped — with `⊥` added **only** when `|D(p)| < 2^width(p)` (so an 8-bit formal whose 256 constants are all
  present gets no spurious `⊥`), capped at `ENUM_CAP` (4096); over-cap fails closed to `unknown`. It never
  produces a `known` it could not fully verify, and a non-gating residual branch (`gate_relaudit`, `a>K` then
  `sink`) correctly stays `known, []` because the sink is must-reached under every σ.
- **R10 — delivery ABI / gadget / image-base gaps.** The extractor's integer set `{rdi,rsi,rdx,rcx,r8,r9}` is
  wider than `_build_arg_chain`'s `{rdi,rsi,rdx}`; a required `rcx/r8/r9` (or an `{rdi,rsi,rdx}` whose gadget is
  missing) is extracted but **undeliverable**, so the consumer **abstains** (zero `verify_payload`, §5.4) rather
  than truncate — extending the builder to `rcx/r8/r9` is W-2.1. The image base is acquired ELF-only
  (`base_address` on pwntools SUCCESS, else lowest `PT_LOAD`); a PE / no-base binary returns `unavailable`
  (→ legacy), never a misreported `rva_miss` (the `Binary` abstraction exposes no populated PE `ImageBase`).

## 9. Resolved questions and parent amendments

**Answers (from the two independent reviews):**

- **Q1 — status taxonomy:** `known + []` only for a genuinely *ungated* sink (exec/file, `decoy_sink`,
  `gate_audit`); `known + [args]` for pinned `param==const` gates; `unknown + reason` (and **consumer abstains**,
  not legacy fallback) for every gate that is not a single required equality — including `gate_invert`
  (accepting the reviewer's rebuttal of Rev 3's `known` classification). T3/T3′/T4 assert exact
  status/list/reason per shape.
- **Q2 — slot/ABI API:** `HighParam.getSlot()` (0-based, `isInput()`-gated, full-storage) +
  `p.getSymbol().getStorage().getRegister().getBaseRegister()` for the SysV base register (12.1.3 has no
  `HighParam.getStorage()`; EDI→RDI normalized). Pinned in §3.
- **Q3 — class-B disposition:** 27 closed `allowed`, 42 remain `open` (ratchet-valid, owning phase recorded),
  0 `migrated`; no class-B entry is a payoff-arg guess; a weak payoff-arg extractor already exists
  (`find_required_args`). No new lifecycle state.
- **Q4 — versioning:** bump both `SCRIPT_VERSION` to `w2.0` and the cache envelope `1→2`; W-1 rows miss; test
  arg-preserving cache hits (T9).

**Parent amendments required before implementation** (applied in the same PR, re-reviewed):

1. **§82-84 / §130 status semantics** — replace "Otherwise the result is `args: unknown`" / "decoys give
   `args: unknown` on 32/32" with the two-state semantics (§2.3): an *ungated* payoff is `known + []`;
   `unknown + reason` is reserved for a detected-but-unresolvable parameter gate (inequality / range /
   disjunction / correlated predicates / transformed / ambiguous / non-constant operand / boolean composition);
   decompile failure is report-level `DEGRADED`. The W-2 Done-when asserts `required_args == ()` on the 16
   exec/file positives + the **three** `known`-ungated falsifiers (`decoy_sink`, `gate_audit`, `gate_relaudit`);
   `unknown, ()` with the stated reason on the **thirteen** unresolvable-gate falsifiers; and `== truth` with
   provenance on the 16 arg positives.
2. **§130 inventory** — replace "Class-B baseline entries are all `migrated`" with: "W-2 closes the class-B
   **ABI/infrastructure** constants as `allowed` (with justifications); the class-B **per-binary target-guess**
   entries remain `open` (ratchet-valid, matching live hits) with their owning phase recorded in the W-2
   disposition table, to be closed by that phase; W-2 migrates 0." This introduces **no** new lifecycle state
   and leaves the parent §2 ratchet and W-5's "surviving current hit must be `allowed`" exit rule **unchanged**
   (W-5 and the dynamic phases close the remaining opens).
3. **§5 / R5 scope** — record that W-2 edits no class-B consumer (0 `migrated`) and that the one edit outside
   the inventory is the owner-approved ret2win arg-path rewire (§5.1/§5.4).
4. **"Red at W-0" prose (`:55-56`, MINOR)** — strike the clause "*or a baseline entry is classified only as
   `open`*" from the W-0 red conditions. It contradicts both the next line (`:57`: only an `open` entry matching
   **no** current hit is stale) and the implemented ratchet (`tests/test_target_value_inventory.py:169-175`,
   where a matching `open` entry passes), as well as the W-5 exit rule (`:59`, which is where every surviving
   `open` must become `allowed`). The W-0 red conditions are exactly: (a) a current hit with no matching baseline
   entry (new hardcoding), and (b) an `open` entry matching no current hit (stale). A matching `open` entry is
   ratchet-valid from W-0 through the phase that owns it — this is precisely what lets W-2's 42 per-binary
   target-guess entries remain `open` (§5.2).
