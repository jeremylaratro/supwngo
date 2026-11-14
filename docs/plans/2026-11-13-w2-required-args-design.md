# W-2 — required-args extraction: constants from the binary (class B) (2026-11-13, Rev 2)

Detailed design for **directive W, phase W-2**. Parent plan:
`docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md` (§3 principle 3 / §82-84, §4 row W-2 / §130,
§12 class-B notes / §240). Builds directly on **W-1** (`supwngo/analysis/payoff.py` + `SupwngoPayoff.java`,
merged PR #39, `9f543bb`). Branch `feat/w2-required-args` off `main` `9f543bb`.

> **Rev 2 — reworked after independent Tier-2 (cyber) review returned REWORK.** Changes vs Rev 1:
> provenance is no longer equated with sink-gating — a recovered equality must be **proven required to reach
> the W-1 sink** via a high-CFG edge-domination test (§2.2); the parameter tracer is replaced by an explicit
> **slot lattice** (§2.1); per-argument **provenance is serialized** (§2.4); the decoy/anti-hallucination
> tests assert **exact emptiness** (§6 T3/T4); three **adversarial requiredness falsifiers** are added to the
> corpus as a separate category (§3a); the **cache ser/deser** round-trip for args is specified and versioned
> (§4); the class-B inventory is resolved via an evidence-based **disposition table** (§5) that also resolves
> the parent's §130-vs-§240 contradiction; and the Ghidra slot API, the `unknown`-vs-DEGRADED boundary, and
> schema tightening are all pinned (§3, §2.3, §4). The parent amendments this requires are listed in §9.

## 0. Goal (exact, from the parent plan's Done-when, as amended in §9)

Given a binary and the payoff RVA that W-1's `rank_payoffs` already identifies, recover the payoff's
**required argument constants** — the fixed values a caller must pass so that the payoff's own
parameter checks let control reach its W-1 sink — **from the binary**, not from a guessed list:

- On the **16/16 argument-checked positives** (corpus shapes `arg1` and `arg3`), the recovered
  `required_args` **equals truth** (`[{position, value}, …]`, 1-based position), **and every recovered value
  carries serialized parameter-slice provenance** that terminates at a `HighParam` (§2.4) — each value is
  proven to come from a comparison that (a) slices back to a specific formal parameter and (b) is **required
  on every path to the sink** (§2.2).
- The **exec/file positives (16/16)** and the three **requiredness falsifiers** yield `args_status=="known"`
  with **`required_args == ()` exactly** — a payoff with no parameter gate, and a payoff whose parameter
  comparison is *not* required to reach the sink, must both produce the empty list, never a spurious arg and
  never `unknown` (§2.3, §6 T3/T4).
- Every **class-B** baseline inventory entry (69, all `open` at W-0) is resolved to **`migrated`**,
  **`allowed`**, or **`reassigned`** (to a later phase), each with a justification string, per the disposition
  table in §5 (audit result: **27 `allowed` / 42 `reassigned` / 0 `migrated`**). The inventory test is green on
  the class-B slice.
- **Ret2win-with-args closes end-to-end (Option A, §5.3/§5.4).** The ret2win arg path is redirected onto the
  new extractor, and on the `arg1`/`arg3` positives (incl. stripped twins) the built ROP chain pops each
  recovered value into the correct register (`position → rdi/rsi/rdx`) and the win call is reached — proven by
  an end-to-end corpus test (§6 T12). This replaces the weak, symbol-dependent, mis-ordering
  `find_required_args` on that path.

Non-goals (deferred): class A/A′ payoff-name migration (W-5), success detection (W-3), dynamic confirmation
(W-4), and **robustness to compiler optimization** (the dev corpus is `-O0`, `generate.py:101`; W-2 makes no
`-O1`/`-O2` claim — see §6 note). W-2 is **static extraction + inventory resolution only**; nothing in the
exploit pipeline is rewired to *consume* `required_args` yet (that is W-5). W-2 makes the value **available
and proven**, and resolves the class-B inventory.

## 1. Why a P-code scan is style-agnostic (necessary, not sufficient)

The corpus writes the argument gate three ways (`payoff_source.py:234-250`): `and`
(`if (a==X && b==Y) {sink}`), `nest` (nested `if`s), and `early` (`if (a!=X) return; … sink`). All three
lower, in Ghidra's decompiler P-code, to the **same** shape: an `INT_EQUAL` / `INT_NOTEQUAL` op comparing a
**parameter varnode** against a **constant varnode**. So W-2 does **not** parse source or match control-flow
templates; it scans the payoff's decompiled P-code for integer-equality comparisons.

**But style-agnosticism is not requiredness.** A parameter-vs-constant comparison proves only *where an
operand came from*, not that *satisfying it is necessary to reach the sink*. The same P-code shape appears in
all of these, where the arg is **not** required:

```c
if (a == X) audit();   system("/bin/sh");   // X gates a non-sink call; sink is unconditional
if (a == X || a == Y)  system("/bin/sh");   // neither X nor Y is individually required
if (a == X) return;    system("/bin/sh");   // reaching the sink requires a != X, not a == X
```

The corpus happens to use only the favorable forms, so a bare scan would pass on it — that is corpus
compatibility, not a requiredness proof. §2.2 adds the control-flow test that distinguishes these.

## 2. Provenance + requiredness model (the discriminator)

A `required_arg {position, value}` is emitted **iff** an `INT_EQUAL`/`INT_NOTEQUAL` P-code op in the payoff's
`HighFunction` satisfies **all three**:

1. **one input resolves to a complete formal parameter slot** under the slot lattice (§2.1) — `PARAM(slot,
   width, full)` with `full == true`;
2. **the other input is a constant varnode** (`Varnode.isConstant()`); and
3. the comparison is **required on every path to the W-1 sink** under the edge-domination test (§2.2).

Everything else is either skipped (not a gate) or taints the function to `unknown` (§2.3). This is
**fail-closed**: a comparison of a local/global against a constant (the decoy shape) has no `PARAM` operand
(condition 1 fails) → skipped; a constant that only appears as a sink argument is in no equality against a
parameter → skipped; a parameter compared against a non-constant → skipped; a parameter gate that *is*
required but whose slot or value cannot be pinned → `unknown` (never a guessed position).

### 2.1 Slot lattice (replaces reuse of W-1's disqualifying tracer — MAJOR 1)

W-1's `traceTarget` returns `PARAM` if **any** `MULTIEQUAL` arm is a parameter (`SupwngoPayoff.java:299`).
That is sound for *disqualifying a sink target* but unsafe for *assigning an argument position*: a phi merging
parameter 1 and parameter 2 must not select either slot. W-2 uses a dedicated tracer `traceParamSlot(Varnode)`
over an explicit three-point lattice:

- **`NONPARAM`** — proven not to carry a whole formal-parameter value (a local, a global, a constant, a
  computed value).
- **`PARAM(slot, width, full)`** — carries formal parameter `slot`'s value; `full == true` only when the
  **whole** parameter value participates.
- **`AMBIGUOUS`** — param-derived but the slot/slice cannot be pinned.

Transfer functions over the W-1 opcode set, tightened:

| opcode | result |
|---|---|
| varnode whose `getHigh() instanceof HighParam` | `PARAM(getSlot(), size, full=true)` |
| `COPY`, `CAST` | pass through unchanged |
| `INT_ZEXT`, `INT_SEXT` of a `full` param | `PARAM(slot, extended_width, full=true)` — equality value is preserved because the corpus keeps constants in 31 bits (`CONST_RANGE`, `payoff_source.py:81`), so `ZEXT(X)==SEXT(X)==X` |
| `SUBPIECE` yielding a partial slice | `AMBIGUOUS` (a byte/word slice does not prove equality of the whole formal parameter) |
| `INDIRECT` | `AMBIGUOUS` (not guaranteed value-preserving) |
| `PTRSUB`, `PTRADD` | `AMBIGUOUS` (addresses a location, not a scalar parameter value) |
| `MULTIEQUAL` (phi) | **join**: `PARAM(s,w,full)` iff **every** arm resolves to `PARAM` with the **same** slot and `full==true`; a self-referential (loop back-edge) arm contributes no new information and is skipped (independent cycle sets); any arm `NONPARAM` → `NONPARAM`; otherwise `AMBIGUOUS` |

For a candidate equality op: classify both inputs. Emit a candidate `(slot+1, const)` only when exactly one
input is `PARAM(full)` and the other is constant. If one input is `AMBIGUOUS` and the other constant (so a
parameter is gated but un-pinnable), the function is tainted `unknown` (§2.3). If neither input is param-ish,
the op is not an argument gate → skipped.

### 2.2 Requiredness via sink edge-domination (BLOCKER 1)

W-1 already records, per function, the sink CALL op(s) (`SupwngoPayoff.java:435`,
`op.getSeqnum().getTarget()`). For each candidate equality op `E` (from §2.1) producing boolean varnode `c`:

1. **Find the governing branch.** Follow `c` forward to the `CBRANCH` that consumes it, counting
   `BOOL_NEGATE` inversions. Require **exactly one** `CBRANCH` consumer; if `c` fans out to several branches,
   to a non-branch use (stored/returned), or to none, `E` does not govern the sink (skip — it is not a gate).
2. **Determine the satisfying edge.** From the `CBRANCH` semantics (`if (cond) goto target`), the op kind
   (`INT_EQUAL` ⇒ true means `param==const`; `INT_NOTEQUAL` ⇒ true means `param!=const`), and the
   `BOOL_NEGATE` parity, compute which successor edge of the branch block is taken **when `param==const`
   holds** — the *satisfying edge* (decompiler block successors via `PcodeBlockBasic.getTrueOut()` /
   `getFalseOut()`; the exact accessor verified live during implementation, as the slot API was for W-1).
3. **Edge-domination test.** Over the `HighFunction` basic-block graph, **cut the satisfying edge** and test
   reachability of the sink op's block from the function entry. If the sink block becomes **unreachable**, the
   satisfying edge edge-dominates the sink ⇒ `param==const` is required on every path ⇒ **emit**. If the sink
   is still reachable, the constraint is **not** required ⇒ **do not emit**.
4. **Multiple sinks.** If W-1 recorded more than one sink op in the function, the satisfying edge must
   edge-dominate **every** sink block; otherwise the gate is not universally required → not emitted.

This rejects all three false-positive shapes by construction: the unconditional-sink case (cutting the
`a==X` edge leaves the sink reachable via the fall-through), the disjunction (cutting `a==X`'s edge leaves the
sink reachable via `a==Y`), and the inverted guard (`if(a==X)return` — the satisfying edge of `a==X` leads to
`return`, so it never dominates the sink). The genuine `early` style (`if(a!=X)return; sink`) still emits:
the satisfying edge for `a==X` is the `INT_NOTEQUAL`-false edge, which is the only edge reaching the sink, so
it dominates. Ambiguous/irreducible control flow (no single governing `CBRANCH`, or the satisfying edge
cannot be determined) → the gate is treated as a detected-but-unresolvable parameter gate ⇒ `unknown` (§2.3).

**Conflicts.** If two emitted gates assign **different** values to the **same** slot (an unsatisfiable
`a==X ∧ a==Y` on every sink path), the function is tainted `unknown` — the model cannot be right. Distinct
slots each with one value (the `arg3` case) all emit independently.

### 2.3 `args_status`: three states (BLOCKER 2, MINOR 2)

The record carries an explicit status; the empty list is never ambiguous:

- **`known`** — the payoff was **successfully decompiled** and its parameter gates fully analyzed. The list is
  authoritative. It is **empty** when there is no parameter gate required to reach the sink — this covers the
  `exec`/`file` payoffs (no checked params) **and** the three requiredness falsifiers (a parameter comparison
  exists but is not required). `known + []` is the honest result for a fully-analyzed payoff with no required
  arg.
- **`unknown`** — the payoff was decompiled, **a parameter gate that governs the sink was detected, but its
  slot or value could not be resolved** (`AMBIGUOUS` slot, partial `SUBPIECE`, non-constant compared value,
  ambiguous control flow, or a same-slot conflict). The list is empty and a `reason` is recorded. `unknown`
  means "there is a required param gate I cannot trust," never "I found constants that aren't gates."
- **Decompile failure is not a per-function `unknown`.** W-1 returns `null` on decompile failure
  (`SupwngoPayoff.java:407`), omits the record, and the pass is incomplete (`:519`) ⇒ the **report** is
  `DEGRADED`. `args_status=="unknown"` applies only to a *successfully decompiled* record whose argument
  analysis was incomplete.

**Invariant:** `args_status=="unknown"` ⇒ `required_args == ()`. Parsing enforces it (§4).

This changes the parent's literal "decoys give `args: unknown`" (§130) and the §82 "otherwise `unknown`"
phrasing; the amendment is in §9. The anti-hallucination property the parent actually wants — unrelated
immediates never becoming arguments — is enforced more strongly here (exact emptiness, §6 T3/T4) than the
original "unknown" phrasing would have.

### 2.4 Recorded provenance (MAJOR 2)

The parent (§82-84) requires the provenance to **record the slice**, not merely that a tracer ran internally.
Each emitted arg is serialized as an object, not a bare pair:

```
{ "position": <int ≥ 1>, "value": <int>,
  "slot": <int ≥ 0>, "width": <int>,
  "op": "INT_EQUAL"|"INT_NOTEQUAL", "op_addr": <unsigned>,
  "sink_addrs": [<unsigned>, …],
  "transform": ["COPY","INT_SEXT", …] }   // the param→compare slice chain, entry-first
```

`value` is the constant operand masked to the comparison width (31-bit corpus range ⇒ ELF/PE agree). Tests
(§6) read the **raw envelope** and assert every arg's `transform` chain terminates at the `HighParam` for
`slot`, and that `op_addr`/`sink_addrs` are present. Python surfaces the pair for consumers and keeps the full
provenance on the candidate (§4).

## 3. Extractor change (`SupwngoPayoff.java`)

Additive; **no change to the W-1 evidence fields**:

- New per-function pass `extractRequiredArgs(HighFunction hf, List<PcodeOp> sinkOps)` returning
  `(status, List<RequiredArg>)`. It iterates `hf.getPcodeOps()` for `INT_EQUAL`/`INT_NOTEQUAL`, classifies the
  two inputs with `traceParamSlot` (§2.1), and applies the edge-domination test (§2.2) against `sinkOps`.
- **Slot API (MINOR 1, pinned to Ghidra 12.1.3):**
  ```java
  HighVariable hv = v.getHigh();
  if (hv instanceof HighParam) { int slot = ((HighParam) hv).getSlot(); }   // 0-based
  // or, by index: hf.getLocalSymbolMap().getParam(i)  →  HighParam;  getNumParams() bounds i.
  ```
  Prefer `HighParam.getSlot()` over `HighSymbol.getCategoryIndex()`.
- **CFG API:** `hf.getBasicBlocks()` → `PcodeBlockBasic[]`; successor edges via `getOut(i)`/`getOutSize()` and
  the conditional `getTrueOut()`/`getFalseOut()`; the sink block is the parent block of each recorded sink op.
  Reachability-with-one-edge-cut is a plain BFS over the block graph.
- The record gains `"required_args": [ <provenance object>, … ]` and `"args_status": "known"|"unknown"`
  (+ `"args_reason"` when `unknown`). `SCRIPT_VERSION` bumps **`w1.1` → `w2.0`** (new output contract).
- **Scope of extraction:** the extractor emits args for **every** enumerated function (uniform records, same
  as W-1); the Python side reads args for the ranked payoff RVA only. A function with no sink op skips the
  requiredness pass and reports `known + []` (no sink ⇒ no required gate to prove).

### 3a. Adversarial requiredness falsifiers (new corpus category — BLOCKER 1)

Three new payoff shapes, each containing a **real sink** (so W-1 still promotes them) but whose parameter
comparison is **not** a required gate, with truth `required_args == []`:

- **`gate_audit`** — `if (a == X) <benign non-sink call>; <sink unconditional>` (X gates a non-sink call).
- **`gate_invert`** — `if (a == X) return; <sink>` (reaching the sink requires `a != X`).
- **`gate_disj`** — `if (a == X || a == Y) <sink>` (neither equality individually required).

These are emitted as a **separate `falsifier` category** in `benchmark/gen/payoff/`, **not** added to `SHAPES`
— so the merged W-1 denominators ("32 positives + 32 twins + 8 negatives + 8 PE", parent §128) are
**unchanged**. Minimal matrix to keep corpus cost low: one non-PIE unstripped ELF per shape (3 units), plus a
stripped twin and one PE variant for `gate_disj` (to prove requiredness survives symbol loss and the PE
calling convention). `index.json` lists them with `role:"falsifier"`, `required_args: []`; W-2 tests key off
that role. A naive scan (Rev-1 model) emits a spurious arg on all three; the §2.2 model emits none.

## 4. Python change (`supwngo/analysis/payoff.py`)

- A new frozen `RequiredArg` dataclass mirrors the provenance object (§2.4). `PayoffEvidence` gains
  `required_args: tuple[RequiredArg, ...]` and `args_status: str` (+ `args_reason: str | None`).
  `PayoffCandidate` reads them through from its evidence.
- `_evidence_from_envelope` validation (reuses the W-1 `isinstance(v, int) and not isinstance(v, bool)` guard
  at `payoff.py:331`): each arg object requires `position:int≥1`, `value:int`, `slot:int≥0`, `width:int>0`,
  `op∈{INT_EQUAL,INT_NOTEQUAL}`, present `op_addr`/`transform`; `args_status∈{known,unknown}`; **`unknown`
  ⇒ empty list**; positions **unique**, no same-position value conflict, sorted by position deterministically;
  `bool` rejected as int. Any violation raises ⇒ `ERROR`, not cached (W-1's fail-to-ERROR rule).
- **Cache ser/deser (MAJOR 3).** `report_to_json` (`payoff.py:379`) and `report_from_json` (`:423`) are
  hand-written; both gain the `required_args` (full provenance) and `args_status`/`args_reason` fields.
  **`CACHE_ENVELOPE_VERSION` bumps `1 → 2`** (`payoff.py:348`) so any pre-existing row is a miss. A new test
  asserts a cache **miss→hit** preserves `required_args` (incl. provenance), `args_status`, and `args_reason`
  byte-for-byte.
- **No ranking change.** Args annotate the W-1-chosen payoff; they do not affect which function is the
  payoff. `COMPLETE`/cache/TOCTOU/`DEGRADED`-angr semantics are unchanged; the cache key picks up the new
  `script_version` (`w2.0`) automatically, invalidating W-1 rows (Q4).
- Public accessor `required_args_for(report) -> tuple[tuple[int,int], ...] | None`: the top candidate's
  `(position, value)` pairs when `args_status=="known"`, else `None`. Full provenance stays on the candidate.

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
`cmp $imm > 0xff` in the named function with **no requiredness check** (it would emit the `if(a==X)audit()`,
disjunction, and inverted-guard false positives of §2.2), **no parameter-slice provenance** (§2.1), **no
positions** (it returns a bare `List[int]`, so it cannot order multi-arg chains), and it **fails on stripped
binaries** (it matches on the objdump symbol label). So W-2's extractor is a **rigorous replacement** of
`find_required_args`, not a duplicate — see §5.3 for the relationship and the scope decision it forces.

- **`allowed`** — a stable ABI / protocol / OS / tooling / architecture constant, **not** a per-binary target
  guess (signal sets, bad-char lists, mask bytes, crash/exploitability signatures, ioctl codes, slab sizes,
  format-string probe offsets, page sizes). Not migratable; correctly hardcoded.
- **`migrated`** — a genuine guess of a **payoff formal-argument** constant, repointed at
  `required_args_for(...)`. This is the only disposition W-2's new capability can satisfy.
- **`reassigned`** — a per-binary target guess that is **not** a payoff formal argument (PIE/base-address
  guesses, canary-offset fallbacks, PRNG modulus/length fallbacks, "CTF magic value" lists compared against
  program state). These need a different analysis capability; W-2 records the entry as `reassigned` with the
  target phase (W-3/W-4, or a new follow-up) and a justification. **W-2 does not migrate them** and does not
  edit their consumers.

### 5.1 R5 narrowed (BLOCKER 3 / R5 inconsistency)

Rev 1's §5 said genuine consumers "will be pointed at the accessor," contradicting R5's "no consumer edit."
Since the audit found **0 `migrated`** entries (§5 audit result), W-2 edits **no class-B consumer at all**:
every one of the 69 entries is `allowed` or `reassigned`, i.e. a baseline `status` + justification change
only. R5 therefore holds trivially for the inventory: **W-2 performs no class-A/A′ payoff-selection rewiring,
no generated-script (`inputs_required`) rewiring, and no class-B consumer rewiring.** R5 is amended for
**exactly one** edit outside the inventory, approved by the owner (Option A, §5.3): redirecting the ret2win
arg path (`StackTechniques._discover_args` / `_build_arg_chain`) off the weak `find_required_args` onto the
new extractor (§5.4), which carries its own seam test. No other consumer is touched in W-2.

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

### 5.3 Relationship to the existing `find_required_args`, and the scope decision it forces

The audit surfaced that a payoff-argument extractor **already exists** (`find_required_args`,
`offset_finder.py:1109`) and is **already wired** into the ret2win-with-args path
(`StackTechniques._discover_args` → `_build_arg_chain` → `rdi/rsi/rdx`). It is the weak version described in
the §5 audit result (no requiredness, no slice, no positions, symbol-dependent). W-2's extractor is its
rigorous successor. This forces a scope decision **for owner sign-off** (the parent approved W-2 under the
now-falsified premise that class-B held migratable payoff-arg lists, and did not know `find_required_args`
existed):

- **Option A (recommended) — build the Ghidra extractor *and* redirect the ret2win arg path onto it**, proving
  ret2win-with-args end-to-end on the `arg1`/`arg3` corpus (incl. stripped binaries, where
  `find_required_args` fails). This closes the September ret2win-with-args gap now and directly serves
  directive F-1. It expands W-2 by one audited consumer rewire (the ret2win arg path only) and amends R5 to
  permit exactly that edit (with a seam test); `find_required_args` is then deprecated/deleted.
- **Option B — build + prove the Ghidra extractor on the corpus, defer the ret2win rewire to W-5** (parent's
  original "extract-only" scope). Tighter W-2 / R5-clean, but ret2win keeps using the weak extractor until
  W-5, so the gap stays open longer.
- **Option C — harden `find_required_args` in place, no new extractor.** Rejected as unsound: requiredness
  (CFG edge-domination) and param-slice provenance are not tractable over an `objdump` regex scan, and it
  cannot be made to work on stripped binaries. Listed for completeness.

**Owner chose Option A (2026-11-13).** W-2 therefore adds a single audited consumer rewire — the ret2win arg
path — specified in §5.4, with R5 amended (§5.1) to permit exactly that edit, a seam test, and an end-to-end
ret2win-with-args corpus test (§6 T12, §7 step 6).

### 5.4 Ret2win arg-path rewire (Option A)

`StackTechniques._discover_args(binary, win_name)` (`stack_techniques.py:296`) currently returns
`find_required_args(path, win_name)` — a flat `List[int]` in **disassembly-appearance order**, which
`_build_arg_chain` (`:304`) then maps **positionally** (index 0→`rdi`, 1→`rsi`, 2→`rdx`). That ordering is
unsound: it assumes the win function compares its parameters in source order, and it breaks entirely on a
stripped binary (no `win_name`). The rewire:

- `_discover_args` calls `rank_payoffs(binary.path)` and, when `args_status=="known"`, returns the
  `required_args_for(report)` `(position, value)` pairs; it falls back to `find_required_args` only when the
  payoff report is not `COMPLETE`/`known` (so no capability is lost on a binary the Ghidra path can't analyze).
  It no longer depends on `win_name`, so it works on stripped binaries (W-1 ranks structurally).
- `_build_arg_chain` is made **position-aware**: it maps `position → {1:rdi, 2:rsi, 3:rdx}` directly rather
  than by list index, fixing the latent ordering bug and tolerating non-contiguous positions. Its only caller
  is `_discover_args`'s technique (confirmed during implementation); the signature change is contained.
- A **seam test** patches `payoff.py` to return a candidate with known `required_args` at random positions and
  asserts the built chain pops the right value into the right register (the §5.1 R5 exception's required test).
- `find_required_args` is marked deprecated with a pointer to `required_args_for`; its deletion is left to W-5
  (which owns list deletion and generated-script rewiring) to keep W-2's footprint to the one rewire.

## 6. Test matrix (RED-first; real-Ghidra tests gated by `SUPWNGO_REQUIRE_GHIDRA=1`)

| # | test | asserts |
|---|------|---------|
| T1 | `arg1`/`arg3` positives, per unit (16) | `required_args` of the ranked payoff **equals truth** (by `position`, order-insensitive); each arg's serialized `transform` chain **terminates at the `HighParam` for its slot** (raw-envelope inspection, §2.4); `args_status=="known"`; `COMPLETE` |
| T2 | all three styles present | at least one `and`, one `nest`, one `early` unit in T1 passes (style-agnostic proof) |
| T3 | `exec`/`file` positives (16) | `args_status=="known"` **and `required_args == ()` exactly** — a decoy constant elsewhere in the binary must never leak into the payoff's args (anti-hallucination for no-arg payoffs) |
| T4 | requiredness falsifiers (`gate_audit`, `gate_invert`, `gate_disj`), real Ghidra | `args_status=="known"` **and `required_args == ()` exactly** — the §2.2 edge-domination test suppresses the non-required equality that a bare scan would emit |
| T5 | rename + strip twins | `required_args` equals truth on 16/16 rename and 16/16 strip twins (args are structural, not name-based); falsifier strip twin stays empty |
| T6 | PE | `required_args` equals truth on **all four** PE argument binaries (enumerated, not sampled); 32-bit `long` value agreement; falsifier PE variant stays empty |
| T7 | malformed args envelope (mock) | a bad `{position,value,slot,width,op,…}`, a non-unique position, a same-position value conflict, `bool`-as-int, or `unknown` with a non-empty list → `ERROR`, not cached (mirrors W-1 failure-injection) |
| T8 | value-width / masking + constant-left (mock or unit) | a 32-bit comparison constant is reported un-truncated and matches `CONST_RANGE`; a comparison with the **constant as the left operand** is handled identically |
| T9 | cache round-trip (mock) | a miss→hit second call preserves `required_args` (incl. provenance), `args_status`, `args_reason`; `CACHE_ENVELOPE_VERSION` bump makes a v1 row a miss |
| T10 | `unknown` path (mock or crafted) | a detected-but-unresolvable parameter gate (`AMBIGUOUS` slot / non-constant value) yields `args_status=="unknown"`, empty list, a `reason`; a decompile failure yields report-level `DEGRADED`, not per-function `unknown` (§2.3) |
| T11 | inventory | no class-B entry is `open`; every resolution has a justification; frozen fields unchanged; 0 `migrated`, so no class-B consumer edit; the ret2win rewire (§5.4) is the only non-inventory edit |
| T12 | ret2win arg-path seam + end-to-end (Option A, §5.4) | **seam:** patching `payoff.py` to return known `required_args` at random positions, `_build_arg_chain` pops each value into the register for its `position` (not list index). **end-to-end:** on `arg1`/`arg3` positives + strip twins, `_discover_args` sources from the extractor (no `win_name`), the chain sets the params and the win call is reached; `find_required_args` is not consulted when the report is `known` |

T1–T6 extend the existing `tests/test_payoff_ranker.py` corpus harness (same `index.json` driver,
module-scoped cache). T7–T10 are fast always-run mocks (T4 is real-Ghidra). T11 extends the inventory test.

**Optimization note (MINOR 3):** the dev corpus is `-O0` (`generate.py:101`), so W-2 makes **no** claim of
robustness to optimization reordering; that is explicitly out of scope and left as future work (optimized
fixtures). The three styles (`and`/`nest`/`early`) + the falsifiers are the robustness envelope W-2 proves.

## 7. Execution order (one commit per step, RED test first; execute on Sonnet)

1. **Corpus falsifiers** — add the `falsifier` category + three shapes (§3a) to `benchmark/gen/payoff/`;
   regenerate dev; confirm `index.json` carries the three `role:"falsifier"` units with `required_args:[]`.
   (Done first so T4 exists to fail against.)
2. **Extractor args pass** — `SupwngoPayoff.java`: `traceParamSlot` lattice (§2.1), `extractRequiredArgs`
   with edge-domination (§2.2), serialized provenance (§2.4), `SCRIPT_VERSION → w2.0`. De-risk by running
   `analyzeHeadless` by hand on one `arg3`, one `gate_invert`, and one `gate_disj` unit before wiring Python.
3. **Python model** — `RequiredArg`, `PayoffEvidence`/`PayoffCandidate` fields, `_evidence_from_envelope`
   validation (schema tightening), `required_args_for`; cache ser/deser + `CACHE_ENVELOPE_VERSION → 2`; unit
   tests T7–T10.
4. **Corpus tests** — T1–T6, driven off `index.json` (gated).
5. **Inventory resolution** — §5.2 table applied to the baseline; T11 green (0 `migrated`, no class-B edit).
6. **Ret2win rewire (Option A)** — `_discover_args`/`_build_arg_chain` sourced from `required_args_for`,
   position-aware register mapping, `find_required_args` deprecated; T12 seam + end-to-end green.
7. **Docs + CHANGELOG** — status note + one `Added` entry; full gate run under `SUPWNGO_REQUIRE_GHIDRA=1`;
   PR (incl. the three parent amendments, §9); merge; worktree/branch cleanup.

## 8. Risks

- **R1 — CFG edge API drift.** The decompiler conditional-successor accessor
  (`getTrueOut()`/`getFalseOut()`) and `BOOL_NEGATE` parity must be verified live on Ghidra 12.1.3; a case
  that can't be resolved falls to `unknown` (fail-closed), never a mis-attributed arg. De-risk step 2 covers
  it.
- **R2 — slot coalescing.** If the decompiler coalesces a trivial parameter into a local, `getHigh()` may not
  be `HighParam` → `AMBIGUOUS` → `unknown`, never mis-positioned.
- **R3 — constant side / sign.** `INT_NOTEQUAL` (early) and `INT_EQUAL` (and/nest) must map to the same
  `{position,value}`; value is the constant operand regardless of operand order, masked to width. T2/T8 guard
  it.
- **R4 — cache-key churn.** `w1.1`→`w2.0` + envelope `1→2` means W-1 rows no longer hit; intended (old rows
  carry no args). TOCTOU/COMPLETE-only-cache rules unchanged.
- **R5 — scope creep into W-5.** Narrowed in §5.1: consumer edits only for `migrated` entries, each with a
  seam test; `allowed`/`reassigned` get status+justification only. The reviewer should confirm no edit beyond
  that set.
- **R6 — falsifier corpus cost.** Kept to 5 units (3 ELF + 1 strip twin + 1 PE) in a separate category so the
  merged W-1 denominators are untouched.

## 9. Resolved questions and parent amendments

**Answers (from the independent review):**

- **Q1 — decoy status:** `known + []` for a fully-analyzed zero-required-arg payoff (cleaner, and preserves
  the honest result for `exec`/`file`), **after** amending the parent (below). T3/T4 assert **exact
  emptiness** regardless of wording.
- **Q2 — slot API:** `HighParam.getSlot()` (0-based), via `v.getHigh() instanceof HighParam` or
  `getLocalSymbolMap().getParam(i)`. Pinned in §3.
- **Q3 — class-B disposition:** resolved per-entry in §5.2 from a full consumer read — **27 `allowed`,
  42 `reassigned`, 0 `migrated`.** The audit's substantive result: no class-B entry is a payoff-arg guess, and
  a pre-existing (weak) payoff-arg extractor already exists (`find_required_args`). This falsifies the parent's
  "all migrated" premise and forces the §5.3 scope decision.
- **Q4 — versioning:** bump **both** Java and Python `SCRIPT_VERSION` to `w2.0` **and** the cache envelope
  `1→2`; invalidate W-1 rows (they carry no args); test arg-preserving cache hits (T9).

**Parent amendments required before implementation** (to
`docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md`):

1. **§82-84 / §130 decoy semantics** — replace "Otherwise the result is `args: unknown`" / "decoys give
   `args: unknown` on 32/32" with the three-state semantics (§2.3): a fully-analyzed payoff with no required
   parameter gate is `known + []`; `unknown` is reserved for a detected-but-unresolvable parameter gate;
   decompile failure is report-level `DEGRADED`. The W-2 Done-when asserts `required_args == ()` exactly on
   the 16 exec/file positives and the 3 falsifiers, and `== truth` with provenance on the 16 arg positives.
2. **§130 inventory** — replace "Class-B baseline entries are all `migrated`" with "every class-B entry is
   resolved to `migrated` / `allowed` / `reassigned` with a justification, per the W-2 disposition table";
   this is consistent with the existing §240 `allowed` note.
3. **§5 / R5 scope** — record that W-2 edits consumers only for `migrated` entries (§5.1).

These amendments are internal plan-consistency fixes (the parent already contradicts itself at §130 vs §240);
they are applied to the parent in the same PR and re-reviewed with this Rev 2.
