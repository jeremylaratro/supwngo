# Unit 1 (canonicalisation) — plan review, round 1

**Date:** 2026-09-24
**Artifact reviewed:** `docs/plans/2026-09-24-schema-unit-1-canonicalisation.md`
**at rev 1** (the plan is now at rev 4; see "What the review could not see" below)
**Reviewer:** codex `gpt-5.6-sol`, `model_reasoning_effort=xhigh`, `--sandbox read-only`
**Prompt:** 271,911 bytes on **stdin**, all four artifacts inlined,
instructed not to read files
**Output:** 18,252 bytes, **asserted non-empty** by the launcher
(`OUTPUT_NONEMPTY bytes=18252`) before being read — exit 0 with empty output reads
silently as approval, so the launcher prints `OUTPUT_EMPTY_OR_MISSING` instead.

## Disposition

**NOT-APPROVED. RECURRENCES 5 / NEW 0 / INTRODUCED 3.**

`NEW 0` for the second round running. Adversarial discovery on this module stayed
converged across the split — the reviewer found no defect *class* that rounds 1–4
had not already named. Every HIGH is either a class whose sweep I skipped, or one
this plan introduced.

Per the standing rule that a recurrence count above zero is reported before it is
revised, **the five skipped sweeps are named below and no revision has been made
in response to this review.**

## Verification of the checkable claims — serial

I checked five claims before accepting them. Four hold; one does not.

| claim | verdict |
| --- | --- |
| F4: explicit builtin raises are more than one; `SystemExit` is a second | **CORRECT.** Two: `L200 TypeError`, `L2154 SystemExit` |
| F4: `transition("active", "append")` reaches the branch I allowlisted as unreachable | **CORRECT.** Raises `undefined transition (active, append)` — a different path from the declared-member call's `refused: cannot append a candidate in state active` |
| F2: `IntEnum`/`StrEnum` collide with `int`/`str` | **CORRECT, AND STRONGER.** Live in the *pristine* canonicaliser today: `canonical(Number.ONE) == canonical(1) == 1`, `canonical(Tag.A) == canonical("a") == "a"` |
| F7: `_merge_expecting_refusal` has no `else: raise` | **CORRECT.** The assert sits *inside* `except R.SchemaError:`; if `merge` does not raise, the helper returns silently and P20 passes |
| F8: `PROPERTIES` has 28 entries, a 29th is unidentified | **WRONG.** 29, and `NARROWNESS` matches it exactly with no symmetric difference. The reviewer's `P1, P1b, P2–P27` enumeration omits **P5b**. The rest of F8 stands. |

### Two live collisions the review surfaced as a hypothetical

F2 and the fifth-mutant section frame `IntEnum`/`StrEnum` as a mutant that would
survive the *planned* P21. Measured, they collide under the **shipped**
canonicaliser, so they are present defects, not future ones: **live collisions 7
and 8**, on top of the five in §2 and the `_BYTES_TAG`-via-dataclass one in §2a.

### Correction to a figure that is already in protocol

`018b3ba` carries "28 of 106 in scope, 1 out of scope" on my authority. Recomputed
over **all** builtin raise sites rather than the one that had bitten me:

```
module error classes (INSTRUMENTABLE, in scope)          : 106   <- unchanged
builtin/other       (UN-INSTRUMENTABLE, out of scope)    :   2   <- was 1
    L200   TypeError
    L2154  SystemExit
bare `raise` re-raises (never classified by the census)  :   4   [591, 1182, 1295, 1392]
TOTAL raise statements                                   : 112
```

The headline figure the protocol propagated — **28 of 106 in scope** — is intact.
What is wrong is the out-of-scope count (1 → 2), and the census never had a
category for the four bare re-raises at all. The "never fired" count is **not
re-measured here**: it needs a full suite pass and I am not alone on the host.

> ### ERRATUM, added with rev 5 — the bare-re-raise half of that sentence is false
>
> "the census never had a category for the four bare re-raises" is **wrong**, and I
> propagated it. The plan's §6 instrument block already contained the line
> `bare re-raise sites (exempt): 4`. The category existed; I did not read it before
> reporting it absent.
>
> The out-of-scope correction (1 → 2) stands, and so does **28 of 106 in scope**.
> Only the bare-re-raise claim is withdrawn. The constructed-exception total also
> moves 107 → 108, since the missing site was `L2154 SystemExit`.
>
> This is the **second** time I have accused this instrument of being worse than it
> is — the first was asserting that `ABSENT.__bool__`'s `# pragma: no cover` comment
> was false when it was true. Both run in the same direction: a false accusation of
> missing coverage. Protocol `018b3ba` requires an instrument to report what it
> cannot instrument as out of scope rather than as uncovered; the symmetric hazard is
> the **auditor** reporting a category as absent rather than reading it, and I am now
> the recorded instance of it twice. Worth a protocol line of its own, if the
> coordinator agrees: *before reporting a category absent from an instrument's
> output, quote the output.*

## The five skipped sweeps

The protocol asks which sweep was skipped, not which instance was missed.

1. **F2, narrowness.** I widened P21 across *distinct types* and never across the
   **subclass relation**. `_jsonable`'s first branch is `isinstance`, not
   `type(obj) is`, so every admitted scalar family has subclasses that reach an
   earlier arm than the refusal meant to catch them. Skipped: *for each
   `isinstance` arm, enumerate the subclasses that reach it first.* I never swept
   the exact-type-vs-subclass dimension at all — it is not in `DIMENSIONS`.

2. **F3, red for the right reason.** I wrote four subtler mutants as prose
   descriptions and never ran the masking check. Skipped: *for every mutant, name
   the exact patched symbol, the changed observable behaviour, and whether a
   second unchanged layer independently produces the same refusal.*
   `evidence_gate_type_only` is masked by `_jsonable`'s own refusal;
   `observation_digest_first_wins` names no edit at all, because `setdefault`
   **already** keeps the first object for an equal digest — so the "mutant"
   describes pristine behaviour. That is the §2a shape (*the pristine
   implementation is the mutant*) which I had just found in P21 and did not apply
   to my own new rows.

3. **F4, instrument scope.** Having found **one** un-patchable builtin raise, I
   fixed that instance and declared the instrument correct. Skipped: *enumerate
   every builtin raise in the module.* Separately, I allowlisted `transition`'s
   undefined-pair branch as unreachable "because P11 enumerates the states" and
   never ran the reachability check; P11 enumerates `None` and declared `State`
   members, and a plain string reaches the branch. Skipped: *for every allowlist
   entry claiming unreachability, construct the input that reaches it.* An
   allowlist entry is an absence assertion and gets the same treatment as any
   other.

4. **F6, §7's file list.** I wrote that `resolve.py` gains `evidence_value_type`
   in `DIMENSIONS`. `DIMENSIONS` is defined only in the test module. Skipped: *for
   every symbol the plan says a file gains, confirm the symbol is defined in that
   file.* One grep.

5. **F7, the deferral inventory.** I wrote "seven false annotation entries" and
   listed three. Naming a count and enumerating fewer than the count is the
   skipped sweep stated in one line. I also never swept the property suite's
   `except` clauses for the exception-to-pass shape, which is on the protocol's
   own list of shapes — `_merge_expecting_refusal` and
   `test_enumeration_bounds_are_reported` are what that sweep would have found.

Four of the five are the same meta-pattern: **I found one instance of a class by
being bitten by it, fixed that instance, and did not enumerate the rest** — which
is the mechanism the three-round-convergence protocol exists to name, applied to
my own remediation rather than to someone else's.

## What the review could not see

The review was dispatched against **rev 1**. The plan is now at **rev 4**, and
three of the reviewer's points had already been found and recorded independently:

- **F1 (INTRODUCED, HIGH) — Option A refuses types the resolver itself
  canonicalises.** This is §4a, committed as rev 2 before the review landed, with
  the same sweep and the same consumer list. Independent confirmation, and the
  calibration the brief's fourth ask was for.
- **F5 (INTRODUCED, HIGH) — a defect can satisfy all of C1–C6 and break the
  unit-1/unit-2 composition.** Confirmed, and the reviewer's instance is
  **different from mine**. Theirs: an injective re-encoding changes every
  `derive_id`, so existing log endpoints dangle — a *byte-stability* gap. Mine
  (§3a, rev 4): `_validate_log`'s index-injectivity precondition is enforced at
  one of two call sites, so I8's domain shrinks in silence — an *index
  construction* gap. Two independent reviewers, two independent contract breaks,
  neither anticipated by C1–C7. That is evidence the contract was
  under-specified rather than that either of us was lucky, and both remedies
  belong in unit 1.
- **§2a's `_BYTES_TAG`-via-dataclass collision** (rev 3) is not in the review.

So the contract needs **C9** (canonical-byte and candidate-ID stability, with
golden vectors and a schema-version migration rule) alongside rev 4's C8, and C3
must be added to unit 2's declared dependencies — the reviewer is right that unit
2 depends on it through `derive_id`, and §3 said "C1 and C5 only".

---

# The review, verbatim

# VERDICT: NOT-APPROVED

The defect should be fixed, but this plan should not be implemented as written. The recommended domain closure would reject types the resolver itself must canonicalise; P21 still misses a plausible `IntEnum`/`StrEnum` collision; two proposed mutant proofs are masked or are not mutations at all; the refusal instrument neither proves domain closure nor has the scope it claims; and C1–C6 omit canonical-byte/ID stability, allowing all six guarantees to hold while unit 2’s log endpoints break. The deferral inventory is also not complete enough to give every inherited defect an owner.

**RECURRENCES 5 / NEW 0 / INTRODUCED 3**

# THE SEAM CONTRACT

| Contract | Can it be broken under this plan? | Is the stated enforcement real? |
|---|---|---|
| C1 — injective canonicalisation | **Yes.** `IntEnum` and `StrEnum` can pass an `isinstance(..., int/str)` primitive arm before an enum refusal. The contract also fails to define whether equality is type-sensitive or a wire-value equivalence. | **No.** The proposed P21 cases cover ordinary `Enum`, tuple, set, frozenset and dataclass, but not primitive subclasses or recursive nesting. |
| C2 — closed, declared, refusal-only domain | **Yes.** `CANONICAL_TYPES` cannot by itself describe recursive container rules, exact-vs-subclass rules, string-only mapping keys, or the reserved bytes key. | **No.** Counting fired `raise` sites cannot detect an unsupported value that is accepted along a non-raising path. |
| C3 — producer-independent and pure | **Yes.** A type-dependent but injective encoding can satisfy P21. | **No.** “§4, option (c) rejected” is reasoning, not enforcement. Unit 2 actually depends on C3 because its log endpoints are candidate IDs derived through `canonical`. |
| C4 — projections unchanged | No defect is exposed here if existing P10 remains in force. | **Yes, substantially.** P10 directly perturbs every digest-partitioned field, although unit 1 should run it before publishing its seam. |
| C5 — distinguishable observations have distinct digests | **Yes as presently designed**, because the proposed domain excludes the `Observation` dataclass that `Observation.digest()` passes directly to `canonical`. | Only conditionally. C1 plus an explicit observation-to-wire projection establishes this modulo the stated cryptographic collision assumption; one merge example does not establish the universal wording. |
| C6 — instrument reports its blind spots | **Yes.** `SystemExit` is a second explicit builtin raise, and the claimed allowlist model misclassifies a reachable transition refusal as unreachable. | **No.** The described instrument records exception construction and its supplied scope accounting is already incomplete. |

**Yes: a defect can satisfy all C1–C6 and still break unit-1/unit-2 composition.** For example, change every retained canonical encoding injectively and deterministically—while keeping the same projections and observation separation. All six guarantees can still hold within the new implementation, but candidate IDs change. An existing `PinRecord.candidate_id` or `by_candidate_id` produced under the unchanged `supwngo.context/v1` schema then names no candidate, so unit 2 rejects or cannot interpret the log.

The contract needs a further guarantee:

> For every previously accepted, retained wire value, canonical bytes and derived candidate IDs remain byte-identical; otherwise the schema version is changed and a migration is supplied.

It also needs to state that unit 1 preserves generation, IDs, and all non-evidence candidate normalization.

# FINDINGS

## 1

**FINDING  HIGH: Option A closes the domain around types that the resolver itself passes to `canonical`, so the recommended implementation breaks core paths.**  
**WHERE** §4: “Declare the canonicalisable domain … `str | int | bool | None | Mapping[str, T] | list/tuple-of-T | bytes(tagged)`, with `tuple` refused”; compare `Observation.digest(): canonical(self)`, `PinRecord.id: canonical(self)`, and `canonical_document()` passing schema dataclasses and tuples to `_jsonable`.  
**CLASS** Remediation changes a shared primitive without sweeping its existing consumers.  
**SWEEP** Enumerate every supplied `canonical`/`_jsonable` consumer and record whether it supplies an enum, tuple, or dataclass that Option A refuses.  
**RESULT** Affected consumers are:

- `Observation.digest()` passes an `Observation` dataclass.
- `derive_id`, `candidate_digest`, and `dedup_key` project `Provenance`, `AppliesTo`, tuple-valued conditions and `derived_from`, and `Ref` dataclasses.
- `PinRecord.id` passes a `PinRecord` dataclass.
- `canonical_document` passes `AppliesTo`, tuples of `Ref`, `Observation`, `PinRecord`, and `Conflict`.
- Validation stores evidence and conditions as tuples before canonicalising them.

The primitive-value comparisons in `classify_pair`, `agreeing`, and `contradiction_guard` are not affected.  
**LABEL** INTRODUCED

**Concrete fix:** Separate external evidence validation from internal wire projection. Convert each schema dataclass and enum explicitly to a JSON-shaped wire object, then let `canonical` accept only that closed wire domain. Do not use generic `dataclasses.is_dataclass`, generic `Enum`, or generic tuple normalization for evidence.

## 2

**FINDING  HIGH: The widened P21 still holds the primitive-subclass dimension constant, allowing a fifth plausible canonical collision.**  
**WHERE** §5: “the five measured pairs, plus `int`/`bool`, `None`/`"None"` and the bytes/string pair”; current `_jsonable` begins with `isinstance(obj, (bool, int, str))`.  
**CLASS** Narrowness—a property holds constant the dimension where the defect lives.  
**SWEEP** For each admitted scalar/container family, examine subclasses that reach an earlier `isinstance` arm before the new refusal.  
**RESULT** `enum.IntEnum` versus `int` and `enum.StrEnum` versus `str` survive the specified P21 set. Ordinary `int`, `str`, list, dict and bytes subclasses present the same policy question unless the domain uses exact types. Recursive occurrences of those values are also absent from the specified cases.  
**LABEL** RECURRENCE

**Concrete fix:** Define whether the domain admits exact builtin types or subclasses. If exact, use `type(obj) is ...`, and add root and nested `IntEnum`/`StrEnum` pairs to P21.

## 3

**FINDING  HIGH: Two of §5’s four “red proofs” are not capable of proving the claimed rule.**  
**WHERE** §5 rows `evidence_gate_type_only` and `observation_digest_first_wins`.  
**CLASS** A mutant either changes a redundant layer or does not make a concrete behavioral mutation, so green/red says nothing about the intended rule.  
**SWEEP** For every §5 row, identify the exact patched symbol, the changed observable behavior, and whether another unchanged layer masks it.  
**RESULT**

- `canonical_coerces_keys`: executable existing patch; meaningful.
- `canonical_accepts_tuple_as_list`: meaningful if implemented as an exact `_jsonable` patch.
- `evidence_gate_type_only`: masked if the separately closed `_jsonable` still refuses the object. P21/merge still rejects it, so weakening only the evidence gate need not go red.
- `observation_digest_first_wins`: no exact edit is named. `_merge_observations` already uses `setdefault` and therefore already keeps the first object for an equal digest. “Drop the injectivity precondition” names no runtime precondition to patch and merely duplicates a canonicalisation mutant.

No other §5 rows have this defect.  
**LABEL** RECURRENCE

**Concrete fix:** Make one layer authoritative for recursive evidence-domain refusal. Mark mutations of a redundant layer `breaks=None`, or patch all layers necessary to expose the wrong behavior. Replace the observation row with an exact edit, such as deduplicating observations by `(at, evidence-name-set)` while ignoring evidence values, and bind it to a merge property using equal timestamps and differing values.

## 4

**FINDING  HIGH: The refusal-coverage instrument neither enforces C2 nor has the scope and allowlist semantics §6 claims.**  
**WHERE** §6: “diff against every `raise` in the module’s AST”; “out of instrument scope (builtin raises): 1”; and “the `transition` L1252 `P11 forbids` note is the model for a legitimate entry.”  
**CLASS** Validation scope is too narrow to reach the behavior being claimed, with an absence allowlist hiding a reachable path.  
**SWEEP** Inspect every explicit builtin raise, every claimed unreachable/allowlisted refusal, and whether raise-site activation can detect acceptance.  
**RESULT**

- Explicit builtin raises are at least `Absent.__bool__`’s `TypeError` **and** the final `raise SystemExit(_main(...))`. The claimed count of one is false unless the CLI is explicitly excluded.
- `transition`’s undefined-pair branch is reachable: `transition("active", "append")` uses a valid event but a non-`State` state and reaches that raise. P11 enumerates only `None` and declared `State` members; it does not forbid this input.
- A type-only evidence gate can still fire on a float, giving the instrument its covered raise site, while silently accepting an enum, tuple or dataclass. Thus full raise-site coverage can coexist with a false C2.
- The current explicit module-error constructions are directly in `raise` expressions; no second construct-without-raise instance appears in the supplied module. The instrument nevertheless measures construction, so this limitation must be structural or declared.

**LABEL** RECURRENCE

**Concrete fix:** Treat refusal-site coverage only as control coverage, not accepted-domain proof. Add behavioral complement tests and recursive type mutants. Explicitly scope or control both builtin sites, and exercise the transition branch with an invalid state rather than allowlisting it as unreachable.

## 5

**FINDING  HIGH: C1–C6 omit canonical-byte and candidate-ID compatibility, while C3 is not enforced and is wrongly omitted from unit 2’s dependencies.**  
**WHERE** §3: “Unit 2 … depends on C1 and C5 only”; C3 is “enforced by §4, option (c) rejected”; §7 says generated bytes are merely “expected unchanged.”  
**CLASS** A seam contract omits a cross-unit invariant and names prose reasoning as enforcement.  
**SWEEP** Hold C1–C6 true while varying canonical bytes, then trace every unit-2 identifier through `derive_id`, `_validate_log`, and supersede endpoints.  
**RESULT** An injective, pure, closed replacement encoding can change `derive_id` for every candidate while satisfying C1–C6. Existing pin, retract, and supersede records then fail `_validate_log` because their endpoints no longer exist under the re-derived IDs. No other C1–C6 guarantee prohibits this.  
**LABEL** INTRODUCED

**Concrete fix:** Add byte/ID stability and schema-version migration guarantees; add committed golden vectors covering canonical bytes, candidate IDs, dependency digests, and log endpoints. Add C3 and this new guarantee to unit 2’s declared dependencies.

## 6

**FINDING  HIGH: The plan assigns `evidence_value_type` to the wrong vocabulary location, so unit 3 can satisfy its seam while checking a different object.**  
**WHERE** §3: “This unit adds `evidence_value_type` to the vocabulary”; §7 assigns “`DIMENSIONS` gains `evidence_value_type`” to `resolve.py`. In the supplied artifacts, `DIMENSIONS` exists only in `tests/test_context_resolve_properties.py`.  
**CLASS** Enforcement is attached to a different object from the declaration it is supposed to validate.  
**SWEEP** Locate every `DIMENSIONS` definition and consumer in the supplied artifacts.  
**RESULT** The only definition is the test-local `DIMENSIONS`; its consumers are `NARROWNESS`, `test_every_property_declares_what_it_varies`, and `test_no_dimension_is_unvaried_by_the_whole_suite`. There is no runtime `resolve.DIMENSIONS`.  
**LABEL** RECURRENCE

**Concrete fix:** Either add `evidence_value_type` to the test-local constant in this unit, or move the canonical vocabulary to `resolve.py` and make the tests consume `R.DIMENSIONS`. Do not maintain two parallel constants.

## 7

**FINDING  HIGH: The unit-3 deferral is incomplete and leaves already-demonstrable dead property gates without an owner.**  
**WHERE** §3’s “Explicitly deferred” list; §9: “seven false entries (P2, P3, P16)” without naming the remaining four; `_merge_expecting_refusal`; and `test_enumeration_bounds_are_reported`.  
**CLASS** Previously named narrowness/dead-gate defects are summarized instead of swept and explicitly assigned.  
**SWEEP** Compare every supplied admission of false breadth or non-failing validation against §3’s unit-3 inventory; inspect every `except` that may turn a property failure into success.  
**RESULT**

- P20’s `_merge_expecting_refusal` has no `else: raise`. A mutant that silently normalizes a wrong caller generation to zero on a fresh store, while retaining terminal-store refusals, survives P20.
- `test_enumeration_bounds_are_reported` catches `AssertionError` through `except Exception: pass` and asserts only that `_COUNTS` is nonempty. One successful property is enough for this “actually exercised” report to pass while other counts are absent.
- §9 admits seven false annotation entries but names only P2, P3 and P16. Concrete false claims include P2 varying `log_record_count` although `_seeded_store` always has the same retract-and-pin records; P3 declaring no varied dimensions although it changes `observation_at`; and P16 holding `state` despite retracting a target.
- P20, the enumeration-report gate, and the unnamed annotation entries do not appear in §3’s explicit inventory.
- The named binding, prefix, staleness, multi-key pin, dedup-projection and ID-perturbation items are correctly owned by unit 3.

No other `except` in the supplied property suite plainly converts the claimed failure into success: P1b, P21–P23 and the mutation meta-test all have explicit wrong-type or `else` failures.  
**LABEL** RECURRENCE

**Concrete fix:** Carry forward a numbered round-4 manifest, one finding per class, with one owning unit. Add P20’s refusal oracle, the enumeration completeness gate, and all seven annotation corrections to unit 3 by exact property and dimension.

## 8

**FINDING  MEDIUM: Several “verified/measured” statements are not established by the evidence the plan quotes.**  
**WHERE** §0 and §9: “all 29 properties,” “Every quantitative claim above names the command”; §4: “no external caller exists yet” based on `grep ... supwngo/`.  
**CLASS** Evidence provenance overclaims what its collection scope establishes.  
**SWEEP** Match each quantitative or universal claim to a reproduced command and check the search domain against the claimed domain.  
**RESULT**

- `PROPERTIES` contains 28 entries: P1, P1b, and P2–P27. If a twenty-ninth test is being counted as a property, it is not identified.
- The plan describes collection methods but does not quote commands for the 840-module count, zero-open result, five collisions, or 28/106 refusal result. Therefore “every quantitative claim … names the command” is false.
- Searching only `supwngo/` cannot prove that no external caller exists, by definition; the patterns also miss imports or calls through other exported names.
- The 75/673 totals are correctly labelled provisional, so I do not count their uncertainty again.

**LABEL** INTRODUCED

**Concrete fix:** Include the exact reproducible commands and commit, identify the alleged twenty-ninth property, and replace “no external caller exists” with the narrower supported claim: “no in-repository production caller matched this search.”

# THE FIFTH SUBTLER MUTANT

Starting from an implementation using exact primitive checks, make this edit:

```python
# correct
if obj is None or type(obj) in (bool, int, str):
    return obj

# mutant
if obj is None or isinstance(obj, (bool, int, str)):
    return obj
```

Keep the later enum-refusal branch unchanged.

Then:

```python
class Number(enum.IntEnum):
    ONE = 1

canonical(Number.ONE) == canonical(1)
```

`Number.ONE` reaches the `int` arm before the enum refusal. The analogous `StrEnum` mutation collides with a plain string.

The planned `prop_P21_canonicalisation_is_injective` expansion does not catch this because its enum example is an ordinary `Enum`, and its scalar controls use builtin `int`, `bool`, `str`, and `None`, not primitive subclasses. Add both root and nested `IntEnum`/`StrEnum` cases.

# DEFERRAL CHECK

The named breadth categories are appropriate for unit 3, but the deferral is not complete.

The phrase “six other narrowness HIGHs” is not mechanically reconcilable with its comma-separated inventory without implicitly grouping items, and §9 separately admits seven false annotations while naming only three. More importantly, P20’s silent-success helper and the incomplete enumeration-report gate are demonstrably live defects and have no named owner.

The round-4 review itself is not inlined, so I cannot verify whether further round-4 finding IDs are missing. The plan must carry forward the exact numbered manifest rather than ask a later reviewer to reconstruct it from summaries.

# THE DEAD GATES

The supplied artifacts contain these dead or misleading gates:

1. `evidence_gate_type_only` can be masked by `_jsonable`’s independent refusal.
2. `observation_digest_first_wins` names no behavior change; pristine code already uses first-wins for an equal digest.
3. Refusal-site coverage cannot fail when an unsupported value is silently accepted without reaching a raise.
4. The proposed transition allowlist hides a reachable refusal; P11 does not make it unreachable.
5. `_merge_expecting_refusal` treats successful acceptance as success because it has no `else`.
6. `test_enumeration_bounds_are_reported` swallows assertion failures and requires only one recorded count.

Those are the dead-gate instances found after sweeping the five requested shapes: absence assertions, checks precluded by earlier checks, exception-to-pass paths, unreachable-input assertions, and unsupported “verified/measured/every” claims.