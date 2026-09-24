# Schema split, unit 1 of 3: canonicalisation

**Date:** 2026-09-24
**Status:** PLAN — awaiting independent review. Not implemented.
**Unit:** 1 of 3 (canonicalisation → audit-log validation → property breadth).
**Parent:** `docs/plans/2026-09-24-standardized-context-schema.md` (v4 rev 4,
HELD FOR A SPLIT), round-4 review at
`docs/plans/2026-09-24-context-schema-v4-review-round4.md`.
**Branch:** `feat/context-schema-v4-20260924` @ `f934f08`.
**Goes first because:** round 4's finding 2 is not a gap in a property. It is a
live defect in shipping code, under the digest the other two units key on.

---

## 0. Evidence provenance

Every figure below is labelled **serial** or **concurrent**, because two
concurrent pytest sessions in this repo have been measured corrupting each other
through shared state, and a result looks identical whether or not the machinery
producing it was working. That is the same defect class this unit exists to fix,
applied to the evidence rather than the code.

| figure | value | collected |
| --- | --- | --- |
| property suite | 75 passed | **concurrent** — provisional as a suite total |
| repo-wide excl. `test_challenges.py` | 673 passed, 10 skipped | **concurrent** — provisional |
| the nine `[RED]` mutation proofs | 9/9 red | **serial**, single process, no pytest |
| the two must-pass mutants | 2/2 pass against P9 | **serial**, same process |
| shared-state exposure of the property suite | **0 files** opened outside the worktree across all 29 properties | **serial**, `sys.addaudithook` |
| pristine canonicaliser collisions | 5 | **serial** |
| refusal sites never fired | **28 of 106 in instrument scope** (see §6 — the first count of 29 of 107 was my own instrument's blind spot) | **serial** |

The exposure figure is the one that settles the hazard. An `open`-event audit
hook, filtered to paths outside this worktree, recorded **zero** opens across all
29 properties — no `~/.supwngo/supwngo.db`, no cache, nothing. The suite imports
the whole `supwngo` package tree (840 modules, because `supwngo/__init__.py` is
eager) but **no** `pwnlib`, `angr`, `capstone`, `keystone`, `ropper`, `elftools`
or `unicorn`, and touches no shared file. So concurrency cannot perturb this
suite's result, which is a structural argument rather than a re-run, and it holds
even though another agent's pytest was running during the measurement.

The two suite totals stay labelled provisional anyway: they include tests outside
this module that *do* use shared state, and re-running them is not this unit's
job.

---

## 1. Inventory — what already exists

Per the review protocol, the search performed and what it found, before
proposing anything.

```
grep -rn "canonical(\|_jsonable(" supwngo/ tests/
```

| exists today | what it does | sufficient? |
| --- | --- | --- |
| `canonical(obj)` / `_jsonable(obj)` | the one canonicalisation entry point; sorted-key compact JSON | **No** — not injective over its accepted domain (§2) |
| `_BYTES_TAG = "__bytes_b64__"` | tags `bytes` as `{_BYTES_TAG: b64}`; reserved, and refused as an ordinary mapping key | Yes, and it is the **precedent** this plan deliberately declines to repeat four more times (§4) |
| non-string mapping keys refused | closed round 3's `str()`-coercion collision | Yes |
| `CONTENT_FIELDS` / `ID_DIGEST_FIELDS` / `DEP_DIGEST_FIELDS` | the three digest projections | Yes — and note `DERIVED_FIELDS` (`observations`, `state`) is in **none** of them, which bounds the blast radius in §2 |
| P21 `prop_P21_canonicalisation_is_injective` | 13 distinct evidence values, hostile mapping, `_BYTES_TAG` spoof | **No** — it does not vary *type* at fixed JSON shape, which is the whole defect |
| `canonical(ev_items)` at `resolve.py:712` | the only gate on evidence values, with the comment *"evidence values are open, so this one CAN fail"* | The comment is **true** (verified: `canonical({"k": 1.5})` raises) but the gate is far too weak (§2) |

Nothing here needs to be built from scratch. This unit changes one function's
accepted domain and adds the instrument that would have caught it.

---

## 2. The defect, verified

Evidence *names* must be non-empty strings; evidence **values are unconstrained**
by design. So whatever `canonical` does to an enum, tuple, set or dataclass is
live behaviour. Measured (serial):

| a | b | both canonicalise to |
| --- | --- | --- |
| `Colour.RED` (enum) | `"red"` | `"red"` |
| `(1, 2)` | `[1, 2]` | `[1,2]` |
| `{1, 2}` | `[1, 2]` | `[1,2]` |
| `frozenset({1, 2})` | `[1, 2]` | `[1,2]` |
| `Pair(a=1, b=2)` (dataclass) | `{"a": 1, "b": 2}` | `{"a":1,"b":2}` |

Five collisions. `int` vs `bool` does **not** collide, `None` vs `"None"` does
**not** collide, and `float` is refused — so the existing rules are right as far
as they go; the domain is simply wider than the encoding is injective over.

### Blast radius, stated precisely

`observations` is in `DERIVED_FIELDS`, therefore in **no** digest projection.
So these collisions **do not** affect candidate ids or `dedup_key`. They land in
exactly two places:

1. **`_merge_observations`** unions by `Observation.digest()`
   (`_sha(canonical(self))`) using `setdefault`. Two *distinguishable*
   observations whose evidence collides get one digest, and **the one that
   arrived first wins**. Verified: merging a candidate with `evidence={"src":
   (1,2)}` and one with `evidence={"src": [1,2]}` yields **1 active candidate
   with 1 observation**, though `ca.observations != cb.observations`.
2. **`canonical_document`** serialises observations through `_jsonable`, so the
   published document cannot distinguish them either.

(1) is the serious one, and it is worse than data loss: it is **order-dependent**
data loss. Merge order decides which evidence survives. Order-independence is
precisely what P2 exists to forbid, and P2 cannot see this because P2 does not
vary evidence *types*. This is the round-3 lesson recurring in a new channel —
and it is why this unit is first.

---

## 3. The seam contract between the three units

The coordinator's condition: specify the seam, or defects move to the boundary
where no unit's review owns them. This unit **owns** and may change:

- `_jsonable`, `canonical`, `_BYTES_TAG` and the accepted-value domain;
- the evidence-value gate at `resolve.py:712`;
- P21 and its mutants;
- the refusal-coverage instrument.

**The contract this unit publishes, which units 2 and 3 may rely on and must not
restate:**

| # | guarantee | enforced by |
| --- | --- | --- |
| C1 | `canonical` is **injective** over its accepted domain: distinct accepted values never share an encoding | P21, widened per §5 |
| C2 | The accepted domain is **closed and declared** (`CANONICAL_TYPES`), and every value outside it is **refused**, never coerced | the new gate; refusal-coverage instrument |
| C3 | `canonical` is a pure function of value, independent of the producer's Python types beyond the declared domain, so a fact serialised by another process reproduces the same digest | §4, option (c) rejected for exactly this |
| C4 | The three digest projections are unchanged: `observations` and `state` remain in no digest | unit 3's P10 |
| C5 | `Observation.digest()` distinguishes any two observations a caller can distinguish | follows from C1 + C2; the positive control is §2's merge case |
| C6 | the refusal-coverage instrument declares its own scope: a site it cannot instrument is reported **out of scope**, never as uncovered | §6 |

**Unit 2 (audit-log validation) depends on:** C1 and C5 only. Log records
reference candidates by id, and ids do not contain observations (C4), so unit 2's
`seq`/terminality properties are independent of this unit's changes. It must not
re-litigate the digest.

**Unit 3 (property breadth) depends on:** C2's declared type list, because the
relational annotation fix needs a name for the "evidence value type" dimension —
which does not currently exist in `DIMENSIONS`. **This unit adds
`evidence_value_type` to the vocabulary**; unit 3 owns the annotations that use
it.

**Explicitly deferred to unit 3, not silently dropped:** the six other narrowness
HIGHs (P6/P24/P25/P26 binding, P15 prefix families, P17 staleness causes, P12
prefix defaults, P16 multi-key pins, P14's dedup projection, P5b's id
perturbation) and the relational-projection annotation checker. This unit fixes
P21 only, and records the rest as unit 3's inventory.

---

## 4. Two methods, weighed

### Option A (recommended) — close the domain and refuse

Declare the canonicalisable domain and refuse everything else:

```
str | int | bool | None | Mapping[str, T] | list/tuple-of-T | bytes(tagged)
```

with `tuple` **refused** rather than silently equal to `list`, or accepted only
by being normalised at the *validation* boundary where the caller can be told.

- **For:** removes the class instead of encoding it; smallest surface; matches
  the module's own stated principle (`applicable`: *refuse rather than guess*)
  and the `_optional_name` decision taken this session for the same reason;
  every refusal is diagnosable by the caller.
- **Against:** callers lose the convenience of passing an enum or a tuple. In
  practice evidence is tool names, versions and output snippets — JSON-shaped
  already — and nothing outside `supwngo.schema` writes candidates yet
  (`grep -rl "validate_candidate\|schema.resolve" supwngo/` → the schema package
  and its tests only), so the migration cost is zero today and rises later. That
  is an argument for doing it **now**.
- **Risk:** a refusal that is too strict is a usability bug, not a correctness
  one, and it fails loudly.

### Option B — tag every non-primitive type

Generalise `_BYTES_TAG` into `{"__enum__": ...}`, `{"__tuple__": [...]}`,
`{"__set__": [...]}`, `{"__dataclass__": {...}}`.

- **For:** keeps expressiveness; no caller changes.
- **Against:** each tag is a **new collision vector with an ordinary mapping**,
  so each must be reserved and refused as an ordinary key — the machinery
  `_BYTES_TAG` needed, five times over. Round 3's bytes defect was *caused* by an
  ad-hoc encoding (`b64:` prefix colliding with a real string); doing that four
  more times repeats the mistake at greater surface. It also grows the encoding's
  dependence on producer-side Python types, weakening C3.
- **Verdict:** rejected. If a future need is concrete, add one tag with the full
  reservation treatment — not four speculatively.

### Option C — encode the Python type of every value

Rejected, and worth naming because it is the obvious first idea. It would make
the encoding depend on the producer's Python types for *all* values, so a fact
serialised by a non-Python tool could not reproduce the digest. For a
*standardized context schema* whose purpose is exchange between commands, that
is disqualifying. It violates C3 by construction.

**What would flip the recommendation:** a real caller that must carry structured
non-JSON evidence. Then Option B for that one type, with reservation, and the
domain stays closed around it.

---

## 5. Red for the right reason — per bound property

The transferable finding of round 4 is that 8 of 8 subtler mutants survived. So
for every mutant this unit touches: name the subtler mutation of the same rule,
and either show it red or **record it as a known blind spot.** An unrecorded
blind spot is indistinguishable from coverage.

| mutant | coarse form | the subtler form | required outcome |
| --- | --- | --- | --- |
| `canonical_coerces_keys` | `str()`-coerce mapping keys | keys and bytes correct, but enum→value, tuple→array, set→sorted array, dataclass→mapping (**= today's pristine behaviour**) | P21 must go **red**; this is the defect |
| new `canonical_accepts_tuple_as_list` | — | accept `tuple` and encode as `list` while refusing sets and dataclasses | P21 red — one type at a time, so P21 cannot pass by catching a different type |
| new `evidence_gate_type_only` | — | check the value is not a `float` but accept any other object | P21 red |
| new `observation_digest_first_wins` | — | keep `_merge_observations` unioning by digest but drop the injectivity precondition | must expose §2's order-dependent loss |

P21's input set must vary **type at fixed JSON shape** — the dimension it
currently holds constant. Concretely: the five measured pairs, plus
`int`/`bool`, `None`/`"None"` and the bytes/string pair as negative controls that
must **not** collide.

---

## 6. The refusal-coverage instrument lands here

Fully mechanical, no annotation: patch each of the module's error classes'
`__init__` to record `sys._getframe(1).f_lineno`, run the suite, diff against
every `raise` in the module's AST. Measured (serial):

```
constructed-exception raise sites:            107
bare re-raise sites (exempt):                   4
in instrument scope (module error classes):   106
out of instrument scope (builtin raises):       1
NEVER FIRED by any test in the repo:           28 / 106
positive-control coverage of refusals:      78/106 in scope
```

Landed as a gate whose uncovered set must equal a **declared allowlist with a
written reason per entry** — the `transition` L1252 `# pragma: no cover - P11
forbids` note is the model for a legitimate entry, because it says *why* the site
is unreachable. The other 27 get a control or a reason.

### The instrument had a blind spot, and finding it is the point

The first run of this sweep reported **29 of 107**, and named
`ABSENT.__bool__` (L200) as a gate whose comment
`# pragma: no cover - exercised via pytest.raises` asserted coverage that did not
exist. **That was wrong.** `tests/test_context_resolve_properties.py:862` calls
`bool(R.ABSENT)`; the comment is true. The sweep missed it because L200 raises a
**builtin** `TypeError`, and CPython forbids patching a builtin exception's
`__init__`:

```
TypeError cannot set '__init__' attribute of immutable type 'TypeError'
```

So the instrument could not observe that site and silently scored it uncovered —
a coverage tool reporting a false negative, which is the same defect class as a
gate that cannot fail, pointed at the measuring device instead of the code. It is
recorded here rather than quietly corrected because it is the strongest available
argument for the instrument's design constraint:

> **C6 (this unit's sixth guarantee): the instrument must declare its own scope.**
> Any raise site whose exception class it cannot instrument is reported as
> **out of scope**, never as uncovered, and out-of-scope sites need a
> hand-verified control named in the allowlist.

Exactly one site is out of scope today (L200) and it is covered by hand at
`tests/…:862`. The corrected figure is **28 of 106**.

Cost: ~28s added to the suite, measured serially. Acceptable; it is the only
instrument here that needs no hand-annotation to be true — provided it reports
its own blind spots, which is now a requirement rather than a hope.

---

## 7. Files touched

- `supwngo/schema/resolve.py` — `_jsonable`/`canonical` domain, the evidence gate
  at L712, `CANONICAL_TYPES`, and `DIMENSIONS` gains `evidence_value_type`.
- `supwngo/schema/mutants.py` — three new subtler mutants (§5).
- `tests/test_context_resolve_properties.py` — P21 widened to vary type at fixed
  JSON shape; the refusal-coverage gate and its allowlist; the `ABSENT.__bool__`
  control.
- `CHANGELOG.md` — under `[Unreleased]`, user-visible (a refused input domain).
- `docs/reference/context-resolution-tables.md` — regenerate only if the
  generated bytes change; expected unchanged, and the byte gate decides, not this
  sentence.

## 8. Test strategy

1. The five collisions become P21 cases and must refuse or encode distinctly.
2. The three negative controls must **not** collide.
3. §2's merge case is the positive control for C5: two distinguishable
   observations must yield two observations, in either arrival order.
4. Each new mutant shown red **serially**, reported with the classification the
   meta-test uses (a crash is not a proof).
5. Refusal coverage recomputed and reported as a ratio, not a boolean.

## 9. Risks

- **A closed domain is a compatibility decision.** Taken now precisely because
  no external caller exists yet; the cost only grows.
- **The refusal-coverage allowlist can rot into a dumping ground.** Mitigation:
  each entry carries a reason, and the count is printed with the enumeration
  bounds so growth is visible.
- **This unit cannot fix the annotation's false claims** — that is unit 3, and
  three of the seven false entries (P2, P3, P16) are about dimensions this unit
  does not own. Recorded, not fixed here.
- **Unverified-self-claim risk in this document.** Every quantitative claim above
  names the command that produced it. The two suite totals are labelled
  provisional because they were collected concurrently and I did not re-run them.
- **The instrument can be wrong in the direction that looks like diligence.** It
  already was: it over-reported by one and named a true comment as false (§6). An
  instrument that over-reports uncovered gates costs work and credibility; one
  that under-reports is the defect it exists to find. C6 forces the first failure
  mode and forbids the second.
