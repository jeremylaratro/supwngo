# Unit 1 (canonicalisation) — plan review, round 2

**Date:** 2026-09-24
**Artifact reviewed:** `docs/plans/2026-09-24-schema-unit-1-canonicalisation.md` at **rev 5**
**Answers:** `docs/plans/2026-09-24-schema-unit-1-review-round1.md` (round 1, 8 findings)
**Reviewer:** codex `gpt-5.6-sol`, `model_reasoning_effort=xhigh`, `--sandbox read-only`
**Prompt:** 347,717 bytes on **stdin**, five artifacts inlined,
instructed not to read files
**Output:** 25,236 bytes, **asserted non-empty** before being read
(`OUTPUT_NONEMPTY bytes=25236`) — exit 0 with empty output reads silently as
approval, so the launcher prints `OUTPUT_EMPTY_OR_MISSING` instead.

## Disposition

**NOT-APPROVED. RECURRENCES 4 / NEW 0 / INTRODUCED 5.**

**`NEW 0` for the third round running.** Reported before revising, per protocol.

### NEW classified against the whole document set, not just round 1

Per protocol `1b456ca` §6.1a, a class named anywhere in rounds 1–4 of the parent
effort or in any prior review is a RECURRENCE even if this round's reviewer could
not have seen it. Applying that rule **does not move anything into NEW** — it moves
things the other way, and that is the finding of this round:

**All five INTRODUCED defects are instances of classes that had already been named
to me.** Four by round 1, one by me:

| round-2 finding | the class | where it was already named |
| --- | --- | --- |
| F2 — C3/C9 use finite golden vectors to enforce universal claims | an enforcement narrower than the guarantee it quantifies over | **round 1 F5**, "names prose reasoning as enforcement"; round 1 F4, "validation scope too narrow to reach the behaviour claimed" |
| F4 — §3b narrows its universe before enumerating | a sweep that pre-filters its universe and then reports completeness | **round 1 F4** (allowlist hiding a reachable path) and the whole rounds-1–4 recurrence mechanism |
| F5 — two rev-5 mutants cannot exercise the rule they bind | a mutant that changes a redundant layer or makes no concrete behavioural change | **round 1 F3, verbatim.** I fixed two rows and the replacements carry the same defect |
| F6 — C7/C10 enumerate declarations, not runtime positions and consumers | enforcement attached to a declaration proxy narrower than the guarantee | **round 1 F6, verbatim**, same finding number |
| F9 — §10 claims one owner per row; two rows have two | a claim the artifact does not support | **named by me in rev 3**, correcting "Two methods" over three lettered options |

So the honest reading is not "5 new defects". It is: **rev 5's remediation
re-created five already-named classes.** That is the 5-of-7 pattern from round 4
reproducing itself in this unit — an artifact written to close a finding is the
riskiest artifact in the change — and it is the second consecutive round in which
my own remediation, not the original code, supplied most of the findings.

## Candidates, not findings — I checked all nine before accepting (serial)

Per protocol `1b456ca` §6.1b. Reporting an intentional absence as a gap costs a
round exactly like a skipped sweep.

| hit | verdict |
| --- | --- |
| F1 / the sixth mutant: container subclasses collide | **CONFIRMED, and worse than stated** — see below |
| F5a: `evidence_gate_type_only` with `breaks=None` is routed through P9 | **CONFIRMED.** The meta-test checks must-pass mutants against **P9 only**; P9 does not exercise evidence validation, so it passes even if the mutant is a no-op |
| F5b: `bytes_tag_guards_mappings_only` cannot make P21 red post-split | **CONFIRMED.** After §4a's split a dataclass at an open position is refused, so P21's input never reaches the structural reserved-tag check |
| F7: stale prose still says exactly one site is out of scope | **CONFIRMED** — see the note below, because I nearly rejected it wrongly |
| F8: `Observation.digest()` is SHA-256 and `derive_id` is 128-bit truncated, so C5 cannot follow from C1+C2 | **CONFIRMED.** `_ID_HEX = 32` → 128 bits of a truncated SHA |
| F9: §10 claims one owner per row | **CONFIRMED.** I wrote "every row has exactly one owner"; R4-5 and R4-7 each name two |
| F3: C8 is negative-only | **CONFIRMED by construction** — "errors on a duplicate" says nothing about completeness |
| F4: P-E is a missing stated precondition | **CONFIRMED** — the reviewer quotes the two statements that carry it |
| F6: `binding_for()`/`conditions_map()` are public but not `__all__` entries | **CONFIRMED** by inspection |

**Nine hits, nine confirmed.** No intentional absence was reported as a gap.

### F1 is worse than the reviewer stated

The reviewer named `bytes` and `list` subclasses as uncovered. Measured, **every**
builtin subclass collides with its base under the shipped canonicaliser:

```
MyBytes(b'x') vs b'x'    '{"__bytes_b64__":"eA=="}'  ==  '{"__bytes_b64__":"eA=="}'   COLLIDE
MyList([1])   vs [1]     '[1]'                      ==  '[1]'                       COLLIDE
MyDict(a=1)   vs {'a':1}  '{"a":1}'                  ==  '{"a":1}'                   COLLIDE
MyInt(1)      vs 1       '1'                        ==  '1'                         COLLIDE
MyStr('a')    vs 'a'     '"a"'                      ==  '"a"'                       COLLIDE
```

So §4b's diagnosis was right — `isinstance` dispatch is the root cause — but its
**remedy was scoped to the primitive arm only**, closing two subclass families of
five. That is a **scope mismatch between diagnosis and remedy for the third time**
in this plan: §4a was a fix *wider* than its diagnosis, this is a fix *narrower*
than its diagnosis. The class is the mismatch, not the direction.

### The near-miss on F7, recorded because it is the sharpest lesson here

My verification script searched for `[Ee]xactly one[^.\n]*\.` — a regex requiring
the sentence to end on the same line. The stale sentence wraps, so the script
found only "has exactly one owner" and I was one step from reporting F7 as a
reviewer error. A `grep` for `out of scope` found it immediately at line 906:

> Exactly one site is out of scope today (L200) and it is covered by hand at
> `tests/…:862`. The corrected figure is **28 of 106**.

**A rejection is also a candidate until it is checked.** §6.1b says a sweep yields
candidates rather than findings; the symmetric hazard is that a *refutation* yields
candidates too, and my refuting instrument was narrower than the claim it was
testing — the same defect class this whole unit exists to fix, committed by me
while checking someone else's report of it.

## Correction of record, not softened

The refusal-census error was mine: I told the coordinator the census had no
category for the four bare re-raises without opening the output, and §6's block
already read `bare re-raise sites (exempt): 4`. The coordinator has recorded that
putting an unchecked claim into a process document was their failure to the same
degree. Both halves stand as written; the erratum sits beside the original in the
round-1 record rather than replacing it, which is the point of an erratum. The
resulting protocol line — *before reporting a category absent from an instrument's
output, quote the output* — is at `2bc3aba`.

## Shared-component mutation scope (protocol `67691a6` §6.3)

`_jsonable` is a shared component and exact-type dispatch changes what it decides
for every caller, so the caller set the mutants run against must be visible rather
than inferred. **Stated for the next revision, and currently incomplete:** the
mutant table binds to `tests/test_context_resolve_properties.py` only. The files
encoding what `canonical` should decide for its *callers* —
`dedup_key`/`derive_id`/`candidate_digest`/`canonical_document` behaviour, and the
generated reference tables in `docs/reference/context-resolution-tables.md` whose
bytes are a gate — are not in the mutation run. That is the same shape as the
cited failure elsewhere: every mutant died against the mutated component's own
tests while the file encoding the intended decision was never executed. The
revision must name the caller set explicitly and run it.

---

# The review, verbatim

# VERDICT: NOT-APPROVED

Rev 5 closes the two concrete `IntEnum`/`StrEnum` collisions, corrects C2/C3’s obviously non-enforcing columns, and adds the right kinds of seam guarantees. It is still not ready for implementation. The subclass sweep stops at the primitive arm; C3/C9’s golden vectors do not enforce their universal claims; C8 remains a negative-only contract that permits an incomplete index; §3b omits the observation-digest precondition; and two newly proposed mutant proofs cannot exercise the rule they claim to bind. These are concentrated in rev 5’s new remediation material.

**RECURRENCES 4 / NEW 0 / INTRODUCED 5**

# §4b’S CONSOLIDATION

Exact-type dispatch closes three of the five items outright, one only partially, and does not close the general subclass recurrence.

| Claimed member of the “one root cause” | Does exact primitive dispatch close it? | Result |
|---|---|---|
| Round-1 F2: P21 omits the subclass dimension | **Partially.** It closes `IntEnum`/`StrEnum` and ordinary `int`/`str` subclasses, but only if every concrete open-domain arm is exact. The plan’s C2 cases say only “primitive subclasses”; they do not cover `bytes` or `list` subclasses. | Instance closed, class not swept. |
| Round-1 fifth mutant: restore `isinstance` in the primitive arm | **Yes.** Root and nested `IntEnum`/`StrEnum` cases will make that particular edit red. | Closed. |
| Recurrence 1: every `isinstance` arm’s subclass relation | **No.** `_jsonable` also has `isinstance` arms for `bytes`, `Mapping`, `list`/`tuple`, sets and dataclasses. The plan does not state exact-type policy for all of them or test their subclasses. | Still recurrent. |
| Live collision 7: `IntEnum` versus `int` | **Yes**, in the open encoder. | Closed. |
| Live collision 8: `StrEnum` versus `str` | **Yes**, in the open encoder. | Closed. |

The structural vulnerability is relocated, not made moot. The plan says:

> “if a future `Scope` were an `IntEnum` the structural encoder’s enum branch would be bypassed by the primitive arm. C7’s mechanical check … should therefore also assert…”

That is the same dispatch obligation moved into a type-shape gate. Such a guard could be sufficient if it exhaustively enumerated structural positions and had a hostile positive control. The proposed “check over the dataclass field annotations” establishes neither. A safer structural encoder dispatches through an exact registry of schema types—or checks structural enums before primitive types—so an `IntEnum` conversion cannot bypass the intended encoder.

The “0 primitive-subclass types” measurement is sound only for this narrow statement: none reached the current primitive arm during those 29 property executions. It is useful compatibility evidence for that exercised set. It does not establish:

- that exported `canonical()` has no other callers;
- that previously accepted public inputs are safe to reject;
- that subclasses do not reach the `bytes`, list or mapping arms;
- that the future open/structural routing exercises the same paths.

Therefore “good evidence, not proof” is fair, but “exact-type dispatch changes no current behaviour” is too broad. It changes shipped public behavior for `canonical(MyInt(1))`, whether or not the repository tests call it.

# §3b’S SWEEP

The enumeration is incomplete. There are at least five semantic preconditions, not four.

| ID | Stated precondition | Consumers | Enforcement and failure behavior |
|---|---|---|---|
| P-A | Candidate IDs uniquely identify immutable candidates. | `by_id`, pins, dependency lookup, witness selection. | Fails today as reported; C8 addresses duplicate rejection but not index completeness. |
| P-B | Validation precedes merge’s two-case analysis. | `merge`, `pin`, `unpin`, `retract`. | Clean: the named writers validate transactionally. |
| P-C | Context identities/conditions/mode satisfy `validate_context`. | `applicable` and functions delegating to it. | Fails at exported `applicable`; C10 addresses that instance. |
| P-D | A caller must handle “never measured.” | External callers of `resolve`. | Properly outside an in-module consumer sweep, but not “discharged.” Raising instead of returning a sentinel forces explicit control flow; it cannot prove that an external caller handles the exception. |
| **P-E** | Evidence can be excluded from the dedup key because observations preserve it; `_merge_observations` is a “sorted-set union.” | `_validate_candidate` normalization and `merge` observation union. | **Fails.** Both consumers key by `Observation.digest()`. A canonical or SHA collision makes `_validate_candidate` keep the first observation within one input, and makes merge keep the previously stored observation across inputs. |

The missing statement is locatable in two quotations:

> “Evidence is preserved by `observations` instead, which is strictly better than being a dedup component.”

and:

> “Sorted-set union: commutative, so merge order cannot leak into bytes.”

That reasoning has an unstated precondition: the digest key must distinguish observations. The evidence gate:

> `canonical(ev_items)  # evidence values are open, so this one CAN fail`

only proves encodability; it does not prove that two distinguishable observations receive different union keys.

The inline-raise exclusion is not an honest implementation of the authorized sweep. A locally enforced condition may ultimately be classified clean, but the instruction was to enumerate every stated precondition and then record its enforcement. Pre-filtering on syntax is how shared premises such as P-E disappear. It is reasonable not to treat every error message as a semantic precondition, but the plan needs a reproducible semantic inventory, not the assertion that four statements qualify.

P-D’s scope reclassification is partly honest: its consumers are external and cannot be enumerated from this module. Calling it “discharged structurally” is not. Record it as an external obligation that this unit makes loud but cannot verify.

# THE SEAM CONTRACT C1–C10

| Contract | Can it be broken? | Is the stated enforcement real? |
|---|---|---|
| **C1** | Yes, through an untested container subclass or a conditional encoder outside P21’s examples. | **Partial.** P21 is good regression evidence, not proof of injectivity over a recursive, unbounded domain. |
| **C2** | Yes. Restoring `isinstance` only on the `bytes` or list arm admits subclasses while all listed primitive-subclass cases still refuse. | **Partial.** The rewritten behavioral table is the correct kind of gate, but its subclass sweep is incomplete and the `Mapping` subclass policy remains ambiguous. |
| **C3** | Yes. A stateful encoder can return every golden value correctly once, or a producer-dependent encoder can agree only on the committed examples. | **No.** Golden vectors enforce selected output bytes, not purity or producer independence. |
| **C4** | A `dedup_key` implementation can omit `derived_from` while the constants and P10’s ID/dependency assertions remain unchanged. | **Partial.** P10 substantially protects ID and dependency partitioning, but it does not directly assert the behavior of all three projection functions, especially the content/dedup projection. |
| **C5** | Literally yes: `Observation.digest()` is SHA-256, not an injective function. | **Conditional only.** It follows from C1/C2 only under an explicit cryptographic-collision assumption, or if the union also compares canonical bytes when digests match. |
| **C6** | The main census now lists both builtin sites, but the prose later still says “Exactly one site is out of scope.” | **Internally inconsistent.** L200 has a named control; L2154 `SystemExit` does not. |
| **C7** | Yes. Dataclass field annotations do not enumerate every runtime structural position or prove where the structural/open recursion switches. | **No for the first clause; partial for the other two.** Reserved field names and enum base classes are inspectable, but each absence check needs a hostile positive control. |
| **C8** | Yes. It requires duplicate rejection but not that the resulting index is a bijection over all candidates. | **Negative-only.** “Every consumer errors on a duplicate” does not prove that unique terminal candidates are retained and resolve to the exact object. |
| **C9** | Yes against the proposed gate: change bytes only for a value outside the finite vector set, or silently classify a previously accepted value as “not retained.” | **Partial.** Golden vectors are useful compatibility sentinels but cannot enforce “every previously accepted, retained wire value” without defining and enumerating the retained set. |
| **C10** | Yes. Public `ResolveContext.binding_for()` and `.conditions_map()` are not `__all__` entries, and an exported reader annotated as `Any` escapes a signature-based census. | **Partial.** It catches today’s `applicable` defect, but does not enforce the universal wording. |

A defect can satisfy the ten clauses as written and still break unit-1/unit-2 composition. For example, construct one duplicate-checking index but omit candidates with a rare valid `method` value:

```python
for c in store.all_candidates():
    if c.id in seen:
        raise SchemaError(...)
    seen.add(c.id)
    if c.method != "__compat_probe__":
        index[c.id] = c
```

This still has one construction, rejects duplicates, never “picks,” preserves all canonical bytes and IDs, and satisfies C1–C7/C9/C10. A valid retract or supersede endpoint for the omitted candidate nevertheless becomes dangling in unit 2.

Strengthen C8 to require an index bijection:

- every stored candidate appears exactly once;
- `index[c.id] is c`;
- every unique `by_id(c.id)` returns that same object;
- unknown IDs return the declared absence;
- duplicate IDs raise;
- active and terminal candidates are both positive controls.

If C3 and C9 were genuine universal guarantees and C8 included this completeness condition, I do not see another canonicalisation/ID defect that could satisfy all ten while breaking the stated unit-2 audit rules.

# FINDINGS

## 1

**FINDING HIGH: Exact-type remediation sweeps only the primitive arm, leaving container subclasses and structural dispatch outside C2/P21.**  
**WHERE** §4b: “it makes the subclass dimension moot”; C2: “primitive subclasses, each root and nested”; §8 item 8: “`isinstance` restored in place of `type(obj) in (...)`.”  
**CLASS** A recurrence is closed at the motivating branch without sweeping every dispatch branch carrying the same relation.  
**SWEEP** Enumerate every `_jsonable` predicate and ask whether a subclass reaches an accepted or different arm before the intended refusal.  
**RESULT**

- `bool`: cannot be subclassed.
- `int`/`str`: `MyInt`, `IntEnum`, `MyStr`, `StrEnum` are covered only if “primitive subclasses” is implemented completely.
- `float`: subclasses remain refused; clean.
- `bytes`: `class B(bytes)` is not named and can collide with plain `bytes`.
- list: `class L(list)` is not named and can collide with a plain list.
- `Mapping`: the plan must say whether custom mappings are intentionally one wire value with dicts or are out of domain; it currently says both “Mapping” and “exact type.”
- tuple/set/frozenset/dataclass: open-domain instances and subclasses are refused if the split occurs before their structural branches; clean only if that routing is explicit.
- structural enums: a future primitive enum still bypasses an `isinstance` primitive arm; C7 relocates rather than removes this instance.

No other current `_jsonable` branch family exists.  
**LABEL RECURRENCE**

**Concrete fix:** Specify exact-type policy per arm. Use exact checks for concrete wire types, explicitly define the intended abstract `Mapping` equivalence, and add root/nested `MyInt`, `MyStr`, `MyBytes`, `MyList`, dict-subclass and custom-`Mapping` cases. In the structural encoder, dispatch through registered exact schema types or handle enums before primitives.

## 2

**FINDING HIGH: C3 and C9 use finite golden examples as enforcement for purity, producer independence and universal compatibility.**  
**WHERE** C3: “enforced by C9’s golden vectors”; C9: “for every previously accepted, retained wire value”; §8 item 9: “committed golden vectors.”  
**CLASS** A finite example gate is presented as enforcement of an unbounded universal seam invariant.  
**SWEEP** For each golden-backed claim, vary behavior outside the committed corpus and vary behavior across calls/producers while holding every golden expectation fixed.  
**RESULT**

- C3 can fail through state, locale, process type or call order while every vector matches.
- C9 can fail for any valid string, integer, recursive mapping or schema combination absent from the corpus.
- Exact-type closure also rejects inputs the exported canonicaliser previously accepted. The plan never defines which accepted inputs are “retained,” so the qualifier can exclude every compatibility break.
- No migration or schema-version change is planned for previously accepted tuple/enum/dataclass evidence; only a changelog entry is named.

Swept C1–C10: C3 and C9 are the two columns relying directly on these golden vectors.  
**LABEL INTRODUCED**

**Concrete fix:** Separate the gates. For C3, add repeated/interleaved same-input tests and independent-producer fixtures derived from a published wire algorithm. For C9, define the retained domain, run a differential old-versus-new compatibility corpus covering all schema enums/fields and recursive grammar productions, and require a schema bump plus migration for every removed accepted form—not only changed bytes.

## 3

**FINDING HIGH: C8 rejects duplicate IDs but does not require the shared index to contain every unique candidate, so all ten clauses can coexist with dangling log endpoints.**  
**WHERE** C8: “duplicates rejected”; §8 item 6: “assert that every named consumer errors on a duplicate id.”  
**CLASS** A seam contract asserts absence of ambiguity without asserting completeness of the lookup domain.  
**SWEEP** Mutate the single index in the three independent directions: duplicate picking, candidate omission, and wrong-object substitution; exercise active, superseded and retracted candidates.  
**RESULT**

- Duplicate picking is covered.
- Omission of a unique candidate is not covered.
- Substitution under a unique key is not explicitly covered.
- Terminal candidates receive no positive index control, despite supersede/retract records necessarily naming them.
- A selectively incomplete index can therefore reject a formerly valid unit-2 log while C1–C10 remain true as written.

No second ID-index invariant in C1–C10 supplies completeness.  
**LABEL RECURRENCE**

**Concrete fix:** Make C8 an index-bijection guarantee and add positive controls for every unique active and terminal candidate, identity of the returned object, unknown IDs, duplicates, and agreement between all lookup consumers.

## 4

**FINDING HIGH: §3b’s authorized sweep is incomplete and reclassifies an unenforced external obligation as discharged.**  
**WHERE** §3b: “Four statements qualify”; P-D: “Discharged structurally instead”; omitted `_merge_observations` and `dedup_key` quotations above.  
**CLASS** A remediation sweep narrows its universe before enumeration and consequently reports completeness without covering a known premise.  
**SWEEP** Enumerate each claim of the form “X, therefore Y is safe,” then list all Y call sites before classifying local, external or structurally impossible cases.  
**RESULT**

- P-A, P-B and P-C are as reported.
- P-D is external and unverifiable, not discharged.
- P-E is omitted: observation preservation assumes digest-key distinctness.
- P-E has two consumers: normalization in `_validate_candidate` and cross-candidate union in `merge`; both silently keep one observation on collision.
- `canonical(ev_items)` establishes only that an encoding exists.

Thus there are at least five semantic statements; three in-module premises fail in pristine behavior: P-A, P-C and P-E.  
**LABEL INTRODUCED**

**Concrete fix:** Add P-E to the table, mark P-D “external—made loud, not verified,” and perform the authorized enumeration before excluding locally enforced rows. Tie P-E to C1/C2 and to the explicit digest-collision policy in C5.

## 5

**FINDING HIGH: Two rev-5 mutant proofs cannot exercise the rule they claim to bind.**  
**WHERE** §5 rows `evidence_gate_type_only` and `bytes_tag_guards_mappings_only`; meta-test: `if mutant.breaks is None: ... PROPERTIES["P9"]()`; §5: “P21 must go red” for the bytes-tag mutant.  
**CLASS** A remediation mutant is routed through a property that never reaches the mutated behavior, or an earlier refusal masks the target branch.  
**SWEEP** For every proposed mutant, identify its exact patch target, changed behavior, invoked property, and the first branch reached by that property.  
**RESULT**

- `canonical_coerces_keys`: meaningful after its post-split patch target is named.
- `canonical_accepts_tuple_as_list`: meaningful.
- `evidence_gate_type_only`: still names no exact patched symbol, and `breaks=None` makes the meta-test run **P9**, which never exercises evidence-domain validation. It passes even if the mutant is a no-op.
- `observation_dedup_ignores_values`: meaningful if assigned an explicit property ID.
- `bytes_tag_guards_mappings_only`: P21’s open dataclass input is refused by `_jsonable_open` before the structural reserved-field rule can matter. P21 cannot make removal of the C7 structural check red.
- `isinstance` restored in the primitive arm: meaningful and caught by the planned enum cases.
- `set_sort_by_str`: honestly rejected.

No other listed mutant has this reachability defect.  
**LABEL INTRODUCED**

**Concrete fix:** Replace `breaks=None` with an explicit `must_pass`/`proves` property ID and run a merge/evidence property that reaches the weakened gate. Test the structural reserved-tag checker through a helper accepting a supplied schema type set and a synthetic hostile dataclass; do not bind it to open-domain P21.

## 6

**FINDING HIGH: C7 and C10 enumerate declarations rather than the runtime positions and consumers their guarantees quantify over.**  
**WHERE** C7: “one mechanical check over the dataclass field annotations”; C10: “every `__all__` entry taking a `ResolveContext`.”  
**CLASS** Enforcement is attached to a declaration proxy that is narrower than the objects or consumers named by the guarantee.  
**SWEEP** For C7, compare every structural serializer call and mode switch with the annotation graph. For C10, compare all public context readers with the `__all__`/signature census.  
**RESULT**

- Field annotations do not prove which dataclass types can reach a particular serializer position.
- `Any` and local containers erase the open/structural boundary.
- The three C7 absence checks have no hostile synthetic controls.
- `ResolveContext.binding_for()` and `ResolveContext.conditions_map()` are public readers but not `__all__` entries.
- An exported reader annotated as `Any` can consume context fields while escaping a “taking `ResolveContext`” signature test.
- C10 does catch the current `applicable` instance, but not its universal wording.

Swept both newly extended declaration-based gates; no other C1–C10 enforcement relies on `__all__` or dataclass annotations in this way.  
**LABEL INTRODUCED**

**Concrete fix:** Maintain an explicit structural-position registry or exact wire projectors and test it with hostile synthetic types. For contexts, maintain a `CONTEXT_CONSUMERS` registry checked against exported module functions, either include the public methods or make them private, and add a control showing an unregistered reader makes the census fail.

## 7

**FINDING HIGH: C6 still has contradictory scope accounting and no named control for the second uninstrumentable builtin raise.**  
**WHERE** §6 table: “out of instrument scope … 2”; later: “Exactly one site is out of scope today (L200)”; only `tests/…:862` is named.  
**CLASS** An instrument’s blind-spot correction updates the count but not every claim and control derived from that count.  
**SWEEP** Enumerate every explicit builtin/other exception raise and match each to an out-of-scope row and a named hand control.  
**RESULT**

- L200 `TypeError`: out of scope and has the `bool(ABSENT)` control.
- L2154 `SystemExit`: out of scope but has no named hand control.
- The later “Exactly one” statement remains false.
- Four bare reraises are correctly and separately classified; swept, no other builtin site is shown.

**LABEL RECURRENCE**

**Concrete fix:** Change the stale paragraph to two sites and add a test exercising the `__main__`/`SystemExit(_main(...))` path, or explicitly exclude CLI execution from C6 and state the independent control that owns it.

## 8

**FINDING HIGH: C5 calls a hash-derived key injective without stating or enforcing the collision assumption round 1 required.**  
**WHERE** C5: “`Observation.digest()` distinguishes any two observations”; enforcement: “follows from C1 + C2.”  
**CLASS** An injective serialization guarantee is incorrectly transferred through a finite hash.  
**SWEEP** Enumerate every digest or truncated digest used as an identity/equality key and record collision behavior.  
**RESULT**

- `Observation.digest()`: full SHA-256; a collision silently loses evidence.
- `candidate_digest()`: full SHA-256; a collision can make a changed source appear unchanged.
- `derive_id()`: 128-bit truncated SHA; C8 converts a collision into refusal rather than arbitrary selection.
- `PinRecord.id`: 128-bit truncated SHA; collision behavior is not named.
- C1/C2 prove distinct canonical bytes, not distinct hashes.

No other digest constructor is present in the supplied module.  
**LABEL RECURRENCE**

**Concrete fix:** State the cryptographic assumption explicitly and narrow C5 accordingly, or key observation union by canonical bytes and compare full canonical representations inside any digest bucket before deduplicating.

## 9

**FINDING HIGH: §10 claims exactly one owner per row while two rows explicitly have split ownership.**  
**WHERE** §10: “every row has exactly one owner”; R4-5 owner “split: unit 1 … unit 3”; R4-7 owner “unit 1 … unit 3.”  
**CLASS** A reconciliation manifest asserts single ownership while encoding multiple owners in one cell.  
**SWEEP** Inspect all eight manifest rows and count active owners per row.  
**RESULT**

- R4-1, R4-3, R4-4, R4-6 and R4-8 have one active unit owner.
- R4-2 is recorded closed rather than assigned.
- R4-5 has two owners.
- R4-7 has two owners.
- Swept, no other multi-owner row.

**LABEL INTRODUCED**

**Concrete fix:** Split R4-5 and R4-7 into unit-specific subrows with one owner each, or assign one coordinating owner and move the other unit’s work into a separately numbered dependency.

# THE SIXTH SUBTLER MUTANT

The sixth viable mutation is an arm-local subclass regression:

```python
# correct open-domain list arm
if type(obj) is list:
    return [_jsonable_open(v) for v in obj]

# mutant
if isinstance(obj, list):
    return [_jsonable_open(v) for v in obj]
```

With:

```python
class EvidenceList(list):
    pass

canonical(EvidenceList([1])) == canonical([1])
```

This leaves primitive exact dispatch, enum refusal, tuple refusal, set refusal and dataclass refusal intact. The proposed P21 and C2 table miss it because they name primitive subclasses but not container subclasses. The analogous `bytes`-arm mutation also survives unless `bytes` subclasses are explicitly included.

Bind this exact edit to P21 and add root and nested list-subclass cases.

# THE DEAD GATES

I found these additional dead or misbound gates:

1. `evidence_gate_type_only` with `breaks=None` is always tested through P9. P9 does not exercise evidence validation, so passing says nothing about masking or redundancy.
2. `bytes_tag_guards_mappings_only` cannot make P21 red after the positional split: the open encoder refuses the dataclass before the structural reserved-tag check is reached.
3. C7’s three current-schema absence checks have no hostile positive controls. A check that reports “no reserved field,” “one type per position,” or “no primitive enum” can be deleted or narrowed without necessarily changing the current schema result.
4. C8’s duplicate-only property can fail on duplicates but cannot fail when the shared index silently omits a unique candidate.
5. The inherited `_merge_expecting_refusal` and `test_enumeration_bounds_are_reported` exception-to-pass gates remain correctly identified as unit-3 work; §10 now owns them indirectly but does not repair them here.

I checked the requested shapes: absence assertions produced C7/C8; an earlier refusal masks the bytes-tag mutant; the `breaks=None` routing makes an irrelevant property pass; the two known broad `except` gates remain; and the “every/complete/exactly one” claims fail in §3b, C9 and §10.