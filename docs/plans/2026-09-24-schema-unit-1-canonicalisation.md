# Schema split, unit 1 of 3: canonicalisation

**Date:** 2026-09-24
**Status:** PLAN rev 6 — **IMPLEMENTATION AUTHORIZED. There is no third plan
review.**

The escalation is recorded rather than assumed. `NEW` was **0 for three
consecutive rounds**, and all five of round 2's INTRODUCED findings were
re-created instances of classes already named to me — two of them under the same
finding *number*. A loop whose output is its own previous output is not
discovering anything, so round 4 of a plan review **escalates**; it does not
proceed. The escalation is to change artifact: prose review has given what it has,
and the remaining risk lives in whether the code does what this plan says, which
only a review of the code can test.

Rev 6 applies what round 2 specified concretely — C8's bijection strengthening,
the per-arm exact-type policy, **P-E**, and the C3/C5/C9 assumption statements —
**self-certifies with the sweeps instead of sending it back out**, and ships to
implementation. The last review round is a **post-implementation review of the
code** against C1–C10.

**Every fix in rev 6 carries a `SCOPE` line** — the diagnosis's extent, the
remedy's extent, and why they are the same set. Mis-scoping is its own protocol
class (`1743788`), it has recurred in this plan in **both** directions (§4a wider,
§4b narrower, §10 incomplete), and **the class is the mismatch, not the
direction**. The scope ledger is §11.

*(Rev 5 status, preserved for the audit trail: round 2 returned NOT-APPROVED,
recorded verbatim at
`docs/reviews/2026-09-24-schema-unit-1-review-round2.md`. RECURRENCES 4 / NEW 0 /
INTRODUCED 5. **Held, not revised:** the counts are reported before the revision.
**`NEW` is 0 for the third consecutive round.** All nine hits were checked against a
deliberate-design explanation before being accepted, and all nine confirmed — the
one I nearly rejected, I rejected with a regex narrower than the claim. One round of
the three-round budget remains.

The decomposition that matters: **all five INTRODUCED defects are instances of
classes already named to me** — four by round 1 (two of them the same finding
number), one by me in rev 3. Rev 5's remediation re-created five named classes; it
did not surface new ones.)*

*(Earlier status line, for the audit trail: rev 5 — revision authorized; round 1
returned NOT-APPROVED, recorded
verbatim at `docs/plans/2026-09-24-schema-unit-1-review-round1.md`.
RECURRENCES 5 / NEW 0 / INTRODUCED 3. **Held, not revised:** the standing rule
is that a recurrence count above zero is reported — with the skipped sweep named
— before the revision. The five skipped sweeps are named in the review record.
Round 1 reviewed **rev 1**; §3a and §4a independently found two of its three
INTRODUCED findings first, and its F5 is a *different* C1–C7 contract break from
§3a's, so the contract needs **C9** (canonical-byte/candidate-ID stability) as
well as C8.)*

**Rev 5 addresses all eight round-1 findings.** Disposition recorded verbatim at
`docs/plans/2026-09-24-schema-unit-1-round1-authorization.md`; two rounds of the
three-round budget remain. The headline change: five of the eight findings were
**one root cause** — `_jsonable` dispatches on `isinstance`, not exact type — and
close together (§4b). The authorized sweep of the newly-named precondition class
found **one further instance** and is recorded at §3b; it is not
"swept, no others".
Not implemented. **Rev 2 corrects a blocking defect in rev 1's own §4**, found
by attacking the seam contract as the review brief asks the reviewer to do; see
§4a. **Rev 3 adds a sixth collision, live today, of exactly the class round 3's
bytes fix claimed to have closed** — see §2a. **Rev 4 answers the review brief's
fourth question in the affirmative: yes, a defect can satisfy every one of C1–C7
and still break the composition of units 1 and 2, and one is in the code now**
— see §3a, which adds C8. Rev 1 is preserved in git history
because the review in flight is against it, and the audit trail matters more
than a clean document.
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

**Rev 5 (F8):** rev 1 claimed "every quantitative claim above names the command".
It did not — four figures described a method without quoting one. The commands are
now in the table, and where a figure has **not** been re-measured it says so
rather than inheriting confidence from the rest of the row.

| figure | value | collected | command |
| --- | --- | --- | --- |
| property suite | 75 passed | **concurrent** — provisional | `python3 -m pytest tests/test_context_resolve_properties.py -q` |
| repo-wide excl. `test_challenges.py` | 673 passed, 10 skipped | **concurrent** — provisional | `python3 -m pytest tests/ -q --ignore=tests/test_challenges.py` |
| the nine `[RED]` mutation proofs | 9/9 red | **serial**, single process, no pytest | `serial_red_proofs.py` — drives `M.applied(mutant)` directly and classifies `AssertionError`/`Failed` as detection, `TypeError`/`ValueError` as a crash (a crash is not a proof) |
| the two must-pass mutants | 2/2 pass against P9 | **serial**, same process | same script, step 3 — mirrors the meta-test exactly: **P9 only**, not all 29 |
| shared-state exposure of the property suite | **0 files** opened outside the worktree across all 29 properties | **serial**, `sys.addaudithook` | `sys.addaudithook` on `open`, filtered to paths outside the worktree, over the 29 `PROPERTIES` entries driven in-process |
| pristine canonicaliser collisions | **8** — 5 cross-type (§2), the `_BYTES_TAG` dataclass spoof (§2a), and `IntEnum`/`StrEnum` (§4b) | **serial** | `verify_p21_collisions.py`, plus `prove_index_seam.py` and `verify_r1_claims.py`; every transcript is reproduced at its section |
| refusal sites never fired | **28 of 106 in instrument scope** — **NOT re-measured since rev 1** | **serial**, but stale | needs a full suite pass under the instrument; not re-run, and must not be re-quoted as if it were. The AST **scope** census *was* re-run (`refusal_scope_census.py`): 106 in scope, **2** out of scope, 4 bare re-raises, 112 statements — see §6 |
| stated preconditions not enforced at their named consumers | **2 of 3 in scope** (P-A, P-C) | **serial** | `sweep_preconditions.py` and `sweep_pc_sharp.py` — §3b |

The exposure figure is the one that settles the hazard. An `open`-event audit
hook, filtered to paths outside this worktree, recorded **zero** opens across all
29 properties — no `~/.supwngo/supwngo.db`, no cache, nothing. The suite imports
the whole `supwngo` package tree (840 modules — `len([m for m in sys.modules if m.startswith("supwngo")])` after importing the
test module, because `supwngo/__init__.py` is eager) but **no** `pwnlib`, `angr`, `capstone`, `keystone`, `ropper`, `elftools`
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


### 2a. A sixth collision, and it is a recurrence of round 3's own fix

Found while trying to construct the **fifth subtler mutant** §5 asks for, which
is how it should have been found the first time.

Round 3 fixed a bytes-encoding collision: `"b64:" + b64` collided with the
*string* `"b64:…"`. The fix encodes bytes as a single-key mapping
`{_BYTES_TAG: b64}` and reserves the key. Its comment states the guarantee:

```python
# A single-key mapping cannot collide with a string, and the reserved key below
# is refused as a mapping key so it cannot collide with a real mapping.
```

The second clause is **false**. The reservation is checked in the `Mapping`
branch of `_jsonable` only — and the **dataclass** branch also produces a
mapping, from field names, with no reservation check:

```python
if dataclasses.is_dataclass(obj):
    return {f.name: _jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
```

`__bytes_b64__` is a legal Python identifier, so a dataclass can have a field
with that name. Measured (serial):

```
canonical(Spoof(__bytes_b64__="eA=="))  ->  {"__bytes_b64__":"eA=="}
canonical(b"x")                         ->  {"__bytes_b64__":"eA=="}
COLLIDE? True
```

and it is **live through the public API today**, not a laboratory curiosity:

```
both accepted by validate_candidate:      True
evidence values distinguishable?          True
Observation.digest() equal (COLLISION)?   True
after merging both: 1 active, 1 observation(s)
```

So a caller-supplied dataclass is indistinguishable from real bytes and the
observation union silently drops one — the same order-dependent evidence loss as
§2, through the same channel, from the defect round 3 believed it had closed.

```
FINDING  HIGH: the _BYTES_TAG reservation guards one branch of two that can
         emit a single-key mapping
CLASS    a reserved tag enforced at some of the sites that can produce its shape,
         not all of them
SWEEP    enumerate every _jsonable branch that can return a Mapping, and check
         each for the reservation
RESULT   two such branches: `Mapping` (guarded) and `dataclass` (unguarded).
         The `set`/`frozenset` and `list`/`tuple` branches return arrays and
         cannot collide with the tag. Swept, no third instance.
LABEL    RECURRENCE — round 3's class, and round 3's own fix
```

**Why the existing gates missed it.** P21 spoofs `_BYTES_TAG` as a *mapping* key,
which is the guarded branch — the property tests the half of the rule that works.
This is round 4's lesson again at one remove: the mutant and the property both
addressed the branch the author was thinking about.

**Consequences for this plan.** Rev 2's positional split makes it unreachable
*from callers* — a dataclass at an open position is refused — but it does not make
it false, because structural dataclasses are still encoded by field name. So C7
grows a second clause:

> **C7.** At every structural position exactly one dataclass type may appear, **and
> no structural dataclass field may be named a reserved tag.** Both halves ship as
> one mechanical check over the dataclass field annotations.

Measured: no current dataclass field is named `__bytes_b64__`, so C7's second
clause holds today — which is exactly the status the first clause had, and exactly
why both are checks rather than sentences.

### The fifth subtler mutant, and one I could not construct

§5's fifth mutant is therefore:

| mutant | the edit | caught? |
| --- | --- | --- |
| `bytes_tag_guards_mappings_only` | reserve `_BYTES_TAG` in the `Mapping` branch but not over dataclass field names — **today's behaviour** | **No.** P21 spoofs the tag only as a mapping key. This must go red. |

And one attempted construction that **failed**, recorded because a blind spot I
looked for and did not find is worth as much as one I found:

| attempted | why it does not work |
| --- | --- |
| `set_sort_by_str` — sort sets by `str(v)` instead of `json.dumps(v, sort_keys=True)` | I expected `{1, "1"}` to reorder. It does not: measured over `{1,'1'}`, `{'a','B'}`, `{True,'True'}` the two sort keys produce **identical** orders, because the JSON quoting is a constant prefix over homogeneous types and the mixed-type cases happen to agree. And post-split, sets survive only at structural positions (`FactSpec.allowed_scopes`, `ResolveContext.identities`), both **homogeneous**. Not a viable mutant; recorded as a checked-and-clear blind spot. |

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
| C1 | `canonical` is **injective** over the **open** domain (evidence values). On the structural domain distinctness follows from the schema fixing the type per position — a different argument, see §4a and C7 | P21, widened per §5 |
| C2 | The **open** domain is **closed and declared**, and every value outside it is **refused**, never coerced (§4a), with **exact-type** dispatch (§4b) | **behavioural**: a table of out-of-domain values — enum, `IntEnum`, `StrEnum`, tuple, set, dataclass, float, primitive subclasses, each **root and nested** — every one of which must raise. *Rev 5: the refusal-coverage instrument is **removed** from this column. It is control coverage only and cannot detect a value accepted along a path that raises nothing, so naming it here was an enforcement that does not enforce — the same defect this table exists to prevent.* |
| C3 | `canonical` is a pure function of value, independent of the producer's Python types beyond the declared domain, so a fact serialised by another process reproduces the same digest | **two gates, because one of them is finite.** (i) A **property** quantifying over the generated domain: for every generated value, `canonical(v) == canonical(v)` across repeated and *interleaved* calls, and the byte string is independent of call order and of any prior call — this is the part that holds universally. (ii) **C9's golden vectors** as *regression evidence* that the bytes have not moved. *Rev 6, F-scope: rev 5 named only the vectors. A finite vector set cannot establish a universal claim; naming it as the enforcement of C3 is "names finite examples as enforcement", which is the original "names prose reasoning as enforcement" class with better manners. **Named assumption for the part the property cannot reach:** purity across *processes* is not in-process provable — the property tests one interpreter, so cross-producer agreement rests on the declared domain being type-closed (C2) plus `json.dumps` with fixed `sort_keys`/`separators`/`ensure_ascii` being version-stable. That assumption is unit 2's to re-examine if it ever ships a second producer.* |
| C4 | The three digest projections are unchanged: `observations` and `state` remain in no digest | unit 3's P10 |
| C5 | `Observation.digest()` distinguishes any two observations a caller can distinguish | follows from C1 + C2 — **and that dependency is now stated, because the consumer that relies on it is `_merge_observations`, which is not in C1's section** (§3b, P-E). Positive control: §2's merge case, **plus** P-E's — two `==`-distinct observations at an equal `at` must both survive `_merge_observations`. **Named assumption:** the union keys on a full 64-hex SHA-256, so beyond C1 it also rests on SHA-256 collision resistance. That is an assumption, not a defect, and it is stated rather than relied on silently. |
| C6 | the refusal-coverage instrument declares its own scope: a site it cannot instrument is reported **out of scope**, never as uncovered | §6 |
| C7 | at every **structural** position exactly one dataclass type may appear, **and no structural dataclass field is named a reserved tag** (§2a) | one mechanical check over the dataclass field annotations, §2a + §4a |
| C8 | the id index is a **bijection** onto the stored candidates, not merely duplicate-free: (a) every stored candidate appears in the index **exactly once**; (b) `index[c.id] is c` — identity, not equality, so a stale copy cannot satisfy it; (c) `by_id(i)` agrees with `index[i]` for every stored id; (d) an id that is **not** stored yields a **declared absence**, not a silent `None` and not a wrong candidate; (e) a duplicate id **raises**, at every construction site; (f) the bijection holds over **active and terminal** candidates alike (§3a) | one test per clause (a)–(f), each shown red first. *Rev 6, F-scope: rev 5's "duplicates rejected + `by_id` raises" is the **contrapositive half** — it forbids one wrong answer without asserting the index is total and injective. A store could satisfy rev 5's C8 with a candidate missing from the index entirely, which is exactly how I8's domain shrank in silence. Clauses (a), (b), (d) and (f) are the half that was missing; (f) is there because a terminal candidate is the one a reader assumes is out of the index.* |
| C9 | for every previously accepted **retained** wire value, canonical bytes and derived candidate IDs stay **byte-identical**; otherwise the schema version changes and a migration ships | **committed golden vectors** over canonical bytes, candidate IDs, dependency digests and log endpoints — a byte gate, not a sentence — stated as **regression evidence, not proof**. *Rev 6 defines "retained", which rev 5 left undefined and therefore unfalsifiable: the **retained set** is the intersection of the values the pre-change domain accepted with the values rev 6's domain accepts. Values the old domain accepted and rev 6 **refuses** — enum, `IntEnum`/`StrEnum`, tuple, set, dataclass, `float`, and every builtin subclass at an open position — are **deliberately not retained**; they are a compatibility break and get a schema-version bump plus a migration note, not a golden vector. **Named assumption:** the vectors are finite, so they can only witness that bytes moved, never that they cannot; the universal half of C9 is carried by C1's injectivity property and C3(i), and C9's own output must say so.* |
| C10 | every public function reading a `ResolveContext` **validates** it; no exported decision function consumes a contract it does not enforce (§3b) | a test calling every `__all__` entry taking a context with each context `validate_context` refuses, requiring a **raise** |

**Unit 2 (audit-log validation) depends on:** C1, C3, C5, **C8 and C9**.
*Rev 5 correction — rev 1 said "C1 and C5 only" and that was wrong, in the
direction that matters: it under-declared the seam, which is exactly how a defect
ends up at a boundary no unit's review owns.* Unit 2's log endpoints are
**candidate IDs derived through `canonical`**, so:

- **C3** (producer-independent and pure) — an id that depends on anything but the
  candidate's content makes a log endpoint unresolvable on a different producer.
- **C8** — `_validate_log`'s index must be injective on id, or I7 validates
  against the wrong candidate and I8's domain shrinks in silence (§3a).
- **C9** — if canonical bytes move, every retained `PinRecord.candidate_id` and
  `by_candidate_id` names no candidate and unit 2 rejects a log that was valid
  when written. This is the reviewer's independent contract break.

What unit 2 still must not do is re-litigate the digest's *field membership*.
It depends on the id being stable and unique, not on what goes into it.

**Unit 3 (property breadth) depends on:** C2's declared type list, because the
relational annotation fix needs a name for the "evidence value type" dimension —
which does not currently exist in `DIMENSIONS` — a **test-local** constant, not a
runtime one (rev 5 correction, §7). **This unit adds
`evidence_value_type` to the vocabulary**; unit 3 owns the annotations that use
it.

**Explicitly deferred to unit 3, not silently dropped:** the six other narrowness
HIGHs (P6/P24/P25/P26 binding, P15 prefix families, P17 staleness causes, P12
prefix defaults, P16 multi-key pins, P14's dedup projection, P5b's id
perturbation) and the relational-projection annotation checker. This unit fixes
P21 only, and records the rest as unit 3's inventory.


### 3a. Yes — a defect can satisfy all of C1–C7 and still break the composition

The review brief asks the reviewer: *can a defect satisfy every one of C1–C6 and
still break the composition of unit 1 and unit 2?  If it cannot, say so plainly;
if it can, that is a blocking finding and it belongs in unit 1.*  It belongs here.

`_validate_log(store, index)` — the whole of unit 2's I7 and I8 — has an
**undeclared precondition**: `index` must be injective on candidate id.  It has
two call sites and the precondition is enforced at one of them.

```python
# validate_store, line 916 -- enforces it, and names the invariant
            if c.id in seen_ids:                                      # I6
                raise SchemaError(f"I6 duplicate candidate id {c.id}")

# current_pins, line 1690 -- does not
    _validate_log(store, {c.id: c for c in store.all_candidates()})
```

A dict comprehension keeps the **last** value for a repeated key. So on a
duplicate id `validate_store` refuses the store and `current_pins` accepts it,
having quietly dropped a candidate — and the candidate it drops is not the one
`FactStore.by_id` returns, which is the **first** match (line 813).

Measured, serially, on one store. The transcript is reproduced in full
because the scratch script that produced it is ephemeral and this is the
evidence; item 6 of §8 turns it into a test that lives in the repo:

```
store holds [superseded, active] with ONE id, log holds NO supersede record

validate_store   -> SchemaError: I6 duplicate candidate id f_061afc3e10c1…
current_pins     -> NO ERROR, returned {}
by_id            -> superseded   (first wins)
comprehension    -> active       (last wins)

I8 iterates index.values(); len = 1 for 2 candidates in the store
states present in the store : ['superseded', 'active']
states visible to I8        : ['active']
```

I8's own docstring states its purpose: *"a terminal state with no record is a
state change that happened outside the state machine, which is exactly what the
log exists to make impossible to hide."*  At this call site it is hidden — not by
failing, but by **having nothing left to check**. An absence assertion whose
domain shrank in silence is the shape of all nine recorded incidents in this
project, and this one is reached through the read path, where `current_pins` is
deliberately revalidating *because* a pin is the one mechanism allowed to
override a measurement.

**Why this answers the brief's question.** The defect is entirely orthogonal to
canonicalisation. `canonical` can be perfectly injective, C1 through C7 can all
hold, and nothing about this changes: it is a property of how an index is
*constructed*, not of how a value is *encoded*. So C1–C7 are satisfiable
alongside it, which is exactly the composition failure the split was supposed to
give an owner.

```
FINDING  HIGH (latent, not live): `_validate_log`'s index-injectivity
         precondition is undeclared and enforced at one of two call sites, so
         I8's domain can shrink without an error
WHERE    supwngo/schema/resolve.py:1690 (`current_pins`) against :916
         (`validate_store`, I6); `FactStore.by_id` :813
CLASS    a hazard mitigated at its source and never at the consumers it was
         diagnosed as endangering
SWEEP    the module names the endangered consumers itself, twice. Take those
         names as the enumeration and check each one's behaviour on a duplicate
         id.
```

Line 315–317: *"a colliding id makes `by_id`, pins, dependency lookup and witness
selection ambiguous — so the width is not cosmetic."*  Line 329–331: *"Without
`generation`, retract + re-merge yielded two candidates with one id, which broke
`by_id`, dependency lookup, the conflict record and candidate ordering all at
once."*  Both times the remedy was applied at the source — widen the id, add
`generation` to the digest — so that collisions become improbable or
content-impossible.  Neither time was any of the four named consumers made safe.

| the consumer the module named | behaviour on a duplicate id today |
| --- | --- |
| `by_id` (:813) | returns the **first** match, silently |
| pins → `current_pins` (:1690) | builds the index by comprehension, **last** wins, silently — **and disagrees with `by_id`** |
| dependency lookup | `_validate_conflicts` :1082 `index.get(ref.id)` takes whatever index it was handed; `is_stale` :1946 `store.by_id(ref.id)` takes first-match — **two dependency lookups that can disagree with each other** |
| witness selection | :1821 `store.by_id(pins[key])`, first-match |

```
RESULT   4 of 4 named consumers resolve a duplicate id silently and arbitrarily,
         and they do not all resolve it the same way. `validate_store` is the
         only site that detects rather than picks. Swept the module for every
         id-keyed mapping and every `by_id` call; no fifth consumer.
LABEL    RECURRENCE — the class is named in the module's own comments at :316
         and :330, and the sweep those comments imply was never run. Two
         instance fixes, no class fix.
```

**Reachability, stated honestly.** The public path is shut *today*: a duplicate
id requires a canonicalisation collision on `ID_DIGEST_FIELDS`, and every field
in that projection is a closed position — measured, `FactSpec.value_type` is only
ever `int`, `bool` or `str`, so `value` cannot collide, and `applies_to` is
normalised by `_validate_conditions` into a sorted tuple of `(str, str)`.  So
this is **latent, not live**.  Two things make it worth fixing here anyway:

1. It becomes reachable the moment unit 2 does what it is chartered to do.
   Asserting the seven in-process log properties means exercising `_validate_log`
   against stores built for the purpose, and the obvious way to build its index
   is the comprehension — the way `current_pins` already models.  Unit 2 would
   then be asserting seven properties of a **weaker function** than the one
   `validate_store` calls, and every one of them would pass.
2. Checking it in `validate_store` only is the same shape as §2a's
   `_BYTES_TAG`: a rule enforced at some of the sites that can reach it.

**The remedy is structural, not documentary.**  Do not write the precondition
down — a precondition is an instruction to a future caller, and this finding
*is* the record of a future caller not following one.  Move the guard inside:
`_validate_log` builds its own index from the store, with the I6 check, so there
is one construction and no precondition to honour.  `current_pins` and
`validate_store` then cannot diverge because there is nothing left to get
different.  This is the same move as answering the cache hazard with immunity
instead of a re-run: prefer making the hazard unreachable to asking everyone to
avoid it.

> **C8.** No consumer resolves a candidate id by picking. There is exactly one
> id-index construction and it rejects duplicates; `by_id` raises on a duplicate
> rather than returning the first match. Enforced by a test that asserts every
> named consumer *errors* on a duplicate id — not that it returns the right one,
> because "the right one" is the assumption that produced this finding.

Cost: one moved check and one changed `by_id` signature contract. Unit 2 gets a
function whose seven properties are worth asserting.

**Side effect of running this sweep:** it independently **verifies** §2's
blast-radius claim, which rev 1 asserted. `value` is closed, so a
canonicalisation collision cannot reach `dedup_key` or an id — the damage really
is confined to the observation union, as §2 says. That claim is now measured.


### 3b. Sweep: "a precondition enforced at the source rather than at the consumers it names"

Round 1 named a class this plan had not. The authorized sweep: *for every
precondition the module **states**, enumerate its call sites and the consumers
named in its statement, and record where it is enforced and what each consumer
does when it does not hold.*

Scope decision, stated so it can be disagreed with: a "stated precondition" is a
claim of the form *X holds, therefore Y is safe*. An inline
`raise SchemaError("... must be ...")` is enforcement **at** the point of use and
so cannot exhibit this defect by construction; counting those would inflate the
denominator with sites that are immune. Four statements qualify.

| | the stated precondition | consumers it names | enforced where | what the consumers do when it does not hold |
| --- | --- | --- | --- | --- |
| **P-A** | *"ids uniquely identify immutable candidates, which is what `generation` and the 128-bit width above are for"* (:339–341) | named at :316 — `by_id`, pins, dependency lookup, witness selection | `validate_store` I6 (:916) — **1 of 2** `_validate_log` call sites | all 4 pick silently **and disagree**: `by_id` first, `current_pins` last, two dependency lookups differently. §3a |
| **P-B** | *"Validation is a precondition, not a case — that is what makes the case analysis disjoint"* (:111, :463, :1090) | merge's two-case `DEDUPED`/`APPENDED` analysis | `merge` :1108, and every other mutating entry via `_append_log` / `_transition_candidate` snapshot→validate→restore | **nothing.** Measured: `merge`, `pin`, `unpin`, `retract` all reach `validate_store`. No consumer can observe an unvalidated candidate. **Enforced at the consumers.** |
| **P-C** | *"context identities must be non-empty, so `"" not in ctx.identities` always"* (:521–523) | the reasoning that an `""` identity is unsatisfiable — i.e. `applicable`, the function that decides it | `validate_context`, called by `resolve` :1803, `conflicts` :1884, `agreements` :1922 | **`applicable` is public (in `__all__`) and calls no validator.** A second instance. |
| **P-D** | `resolve`: *"a fact that was never measured has no candidate, and the caller must handle that"* (:1799) | callers, outside the module | — | **external — made loud, not verified.** `resolve` raises one of five declared refusals and has no `default` parameter, so a caller cannot receive a sentinel by accident. *Rev 6 relabels this: rev 5 called it "discharged structurally", which claims more than the evidence. Nothing here verifies that callers handle the refusal; the module only guarantees the refusal is impossible to miss silently. "Made loud" is what was measured. "Discharged" would have been an absence assertion about code this unit cannot see.* |
| **P-E** | `dedup_key`: *"`evidence` is deliberately excluded ... Evidence is preserved by `observations` instead, which is **strictly better** than being a dedup component"* (:386–390) | `observations` — concretely `_merge_observations` (:395–402), whose `setdefault` keeps **one** member per digest | **nowhere.** The claim is true only if C5 holds, and C5 follows from C1 — which is false today. C1's section and the consumer are in different parts of the module and nothing links them. | **one observation is silently dropped.** Measured, on the fully validated path: 2 live instances. A second live instance of round 1's class. |

```
SWEEP RESULT  (rev 6 -- re-run, one row added)
              5 stated preconditions, 4 in scope for this class.
              P-A  NOT enforced at its 4 named consumers   (§3a, known)
              P-B  enforced at all 4 mutating call sites    clean
              P-C  NOT enforced at `applicable`            (rev 5, NEW then)
              P-E  NOT enforced at `_merge_observations`    NEW
              P-D  external -- made loud, not verified      out of scope
              => NOT "swept, no others". Two further instances: P-C and P-E.
```

#### P-E, measured — and two of my four witnesses were wrong

This is the *candidates-not-findings* rule applied to my own evidence, and it cost
two of the four pairs I started with. Reported in the order I learned it:

```
witness                            ==-distinct?  one digest?  verdict
IntEnum(1) vs 1   in a value          NO            yes       BENIGN -- collapsing
StrEnum('a') vs 'a' in a value        NO            yes       BENIGN -- is correct dedup
tuple-of-pairs vs list-of-lists       yes           yes       CLOSED ALREADY (below)
set vs list       in a value          yes           yes       LIVE
tuple vs list     in a value          yes           yes       LIVE
```

The enum pairs are **not** P-E instances. `IntEnum.ONE == 1` and `StrEnum.A == "a"`,
so a caller cannot distinguish the two observations at all, and keeping one is
*correct* deduplication rather than lost evidence. C5's own wording — "any two
observations a caller **can** distinguish" — is what rules them out, and I only
noticed because the script printed its own criterion instead of just its
conclusion. Had it printed the conclusion alone I would have filed two false
instances.

The outer-container pair is also **not** a live instance: `_validate_candidate`
normalises evidence to `tuple(sorted(ev_pairs, ...))` at :710 and there is exactly
**one** `_validate_candidate` call site (:589), so no unnormalised evidence
container reaches the union. A read of the docstring alone would have called it
live.

What is left is live on the fully validated path:

```
evidence {"trace": {1,2}}  ->  {"at":"...","evidence":[["trace",[1,2]]]}
evidence {"trace": (1,2)}  ->  {"at":"...","evidence":[["trace",[1,2]]]}
==-distinct after validation : True
same digest at equal `at`    : True
_merge_observations length    : 1        <-- an observation the caller can
                                             distinguish is silently dropped
```

```
FINDING  HIGH: `dedup_key` excludes evidence on the stated grounds that
         `observations` preserves it; `_merge_observations` does not, because the
         preservation claim depends on C1 and C1 is false today
WHERE    supwngo/schema/resolve.py:386-390 (the claim), :395-402 (the consumer)
CLASS    a precondition enforced at the source rather than at the consumers it
         names  (round 1's class -- second instance after P-C)
SWEEP    §3b's table, re-run with the fifth statement included
RESULT   4 in scope; P-A, P-C and P-E fail; P-B clean; P-D external
LABEL    NEW as an instance, RECURRENCE as a class -- the class is round 1's and
         was already swept once in rev 5, so under protocol 1b456ca §6.1a the
         class counts as a recurrence even though this instance is new.
```

**The remedy is the domain, not the union's key — and getting that backwards is
the mis-scoping class.** Canonical *bytes* are equal in both live instances, so
re-keying `_merge_observations` by canonical bytes instead of by digest **does not
fix P-E**. It addresses only the separate cryptographic assumption named in C5.
P-E is closed by §4a/§4b closing the open domain — `set` and `tuple` refused at an
open position — i.e. **P-E needs no new code at all**, only a named dependency and
a positive control. Shipping a byte-keyed union as "the P-E fix" would have been a
remedy narrower than its diagnosis that also *looked* more substantial.

#### P-C, measured — and it is a wrong answer, not merely an answer

`applicable` reads `ctx.identities` (:1661) and `ctx.conditions_map()` (:1665)
and validates neither. Every context `validate_context` refuses, `applicable`
answers:

```
identities as a list, not a set          validate_context refuses   applicable -> True
identities containing ''                 validate_context refuses   applicable -> False
conditions with a non-str value          validate_context refuses   applicable -> True
identity_mode a garbage string           validate_context refuses   applicable -> True
```

Sharpened against a candidate that applies only when `aslr == "on"`:

```
aslr='on'   (valid)                      validate_context ACCEPTS   applicable -> True
aslr=1      (refused by validate_context) validate_context refuses  applicable -> False
aslr=True   (refused by validate_context) validate_context refuses  applicable -> False
```

The second and third are the same operator intent as the first, expressed with the
wrong type. `resolve` refuses them. `applicable` — the public function whose entire
job is to answer this question — returns **False**, reporting the candidate as *not
applying* rather than refusing the context. A caller using the documented decision
function directly gets a confident wrong answer where the pipeline would have
raised. That is worse than P-A, which at least disagrees with itself loudly enough
to be findable.

```
FINDING  HIGH: `applicable` consumes a validation contract it does not enforce
         and returns a wrong boolean instead of refusing
WHERE    supwngo/schema/resolve.py:1655-1668, exported in __all__ :47
CLASS    a precondition enforced at the source rather than at the consumers it
         names  (round 1's class)
SWEEP    the table above -- every stated precondition, its named consumers, and
         each consumer's behaviour when it does not hold
RESULT   3 in scope; P-A and P-C fail, P-B is clean. P-D reclassified as an
         outward obligation with a structural discharge.
LABEL    NEW -- the class is round 1's, this instance is not in any round's
         findings. Labelled NEW rather than RECURRENCE because the class was
         named in round 1 and this is the first sweep of it; if it had been
         named earlier and missed, it would be a recurrence.
```

> **C10.** Every public function that reads a `ResolveContext` validates it. No
> exported decision function consumes a contract it does not enforce. Enforced by
> a test that calls **every** `__all__` entry taking a `ResolveContext` with each
> context `validate_context` refuses, and requires a raise — not a return value.

The remedy is the same shape as C8's: move the check to where the contract is
consumed rather than documenting the obligation. `applicable` calls
`validate_context`. The cost is a redundant validation on the `resolve` path,
which is acceptable and which C8 already accepts for the id index.

---

## 4. Three methods, weighed

<!-- rev 3: the heading read "Two methods" over three lettered options.
     Trivial, and the same shape as the findings this plan reports: a claim
     the artifact does not support. Corrected, not excused. -->

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

## 4a. Rev 1's Option A was unimplementable — the diagnosis was positional, the remedy was global

**This is a blocking defect in rev 1 of this plan, found by the author while
attacking the seam contract C1–C6 that rev 1 had just published.** It is recorded
rather than quietly rewritten, because the class it belongs to is more valuable
than the instance.

### What was wrong

Rev 1's §4 Option A proposed closing `_jsonable`'s accepted domain: refuse
`enum`, `tuple`, `set` and `dataclass`. Measured (serial), the module's **own**
most load-bearing function depends on all three of the branches that would
remove:

```
conditions type:   tuple -> (('aslr', 'on'),)        # a tuple OF tuples
applies_to:        AppliesTo (dataclass) -> {'identity': None, 'scope': 'build',
                                            'conditions': [['aslr', 'on']], ...}
applies_to.scope:  Scope (enum)          -> 'build'
state:             State (enum)          -> 'active'
observations:      tuple of Observation dataclasses
CONTENT_FIELDS:    ('key','value','provenance','applies_to','derived_from','method','by')
```

`applies_to` is in `CONTENT_FIELDS`, so `dedup_key` canonicalises a **dataclass**
containing an **enum** and a **tuple of tuples**. Refusing those three types
would not tighten the schema; it would break `dedup_key`, `derive_id`,
`dep_digest` and `canonical_document` simultaneously. Option A as written could
not have been implemented, and a plan that cannot be implemented is worse than one
that is merely wrong, because its review budget is spent on the wrong question.

### The class, and the sweep

```
CLASS  a fix whose scope is wider than the diagnosis that motivated it
```

§2 bounded the blast radius **positionally** and correctly — the collisions are
reachable only where a *caller* supplies an arbitrary object, and
`observations`/`state` are in no digest. §4 then proposed a remedy scoped to the
**function**. Every value in the module passes through the same `_jsonable`, so a
positional defect got a global fix. The diagnosis was right and the remedy did not
inherit its scope.

**Swept:** the other two rejected options are checked against the same class.
Option B (tag four more types) is also global-scoped — it would add reserved keys
that every mapping everywhere must now avoid, to solve a problem that exists at
one position. Option C is global by construction. **So all three of rev 1's
options were scoped to the function rather than the position, and the class
claimed the whole section, not one bullet.** That is why this is recorded as a
class: fixing Option A alone would have left the same error in the alternatives
the next revision might have chosen.

### The corrected method: close the domain per *position*, not per function

The ambiguity is not "which Python types does `_jsonable` accept". It is **at
which positions is the type open**. At every schema-internal position the type is
fixed by the schema — a `Scope` is always a `Scope`, `conditions` is always a
tuple of 2-tuples — so no other type can appear there and **no collision is
possible**. The collision exists only where the caller supplies an arbitrary
object.

So split the function by position, not the domain by type:

| function | used at | domain |
| --- | --- | --- |
| `_jsonable_structural` | the schema's own projections and document: `project(...)`, `AppliesTo`, `Observation`, `Ref`, `PinRecord`, `Conflict`, the enums | unchanged — enum/dataclass/tuple/set/Mapping, because the type at each position is schema-fixed |
| `_jsonable_open` | **evidence values only** | closed: `str`, `int`, `bool`, `None`, `Mapping[str, ·]`, `list`, tagged `bytes`. `enum`, `tuple`, `set`, `dataclass`, `float` and everything else **refused** |

This also *keeps* Option A's virtue — refuse rather than guess — and applies it
exactly where guessing was happening.

### C1 and C2 are restated; a new obligation falls out

- **C1 (was: `canonical` is injective over its accepted domain).** Now: `canonical`
  is injective over the **open** domain. On the structural domain injectivity is
  not the argument at all — distinctness follows from the schema fixing the type
  at each position, which is a *different* claim and must be established as one.
- **C2** applies to the open domain only.
- **C7 (new): at every structural position, exactly one dataclass type may
  appear** — *and, per rev 3's §2a, no structural dataclass field may be named a
  reserved tag; that second clause closes a collision that is live today.* This is the residual risk the split creates and it must not be left
  implicit: `_jsonable_structural` encodes every dataclass as a mapping of its
  fields, so two *different* dataclass types with the same field names and values
  would collide. Today they cannot share a position (`resolutions` holds only
  `PinRecord`, `conflicts` only `Conflict`, and they sit under different document
  keys) — but that is a fact about the current schema, not a guarantee, and it is
  mechanically checkable from the dataclass field annotations. **C7 must ship with
  that check**, or the split trades a measured collision for an unmeasured one.

  C7 is **measured, not asserted** (serial). Over the module's 10 dataclasses:

  ```
  pairs with IDENTICAL field-name sets:          NONE
  pairs where one field set is a strict SUBSET:  NONE
  ```

  The near miss worth naming: `Agreement('candidate_ids','key','value')` and
  `Conflict('candidate_ids','cls','key')` share two of three field names, and
  differ only in the third. That is exactly the kind of margin that vanishes in a
  later edit with nobody noticing — which is why C7 ships as a check and not as
  this paragraph.

### What this costs and what it buys

Cost: one more function and one more contract clause. Buys: the fix becomes
implementable, `dedup_key` keeps working, and the refusal lands at the only
position where a caller can create ambiguity. The five measured collisions all
occur at that position, so the corrected remedy closes every one of them —
verified by construction rather than by assertion, since after the split an enum,
tuple, set or dataclass in an evidence value is refused before it can be encoded.

### Honest note on the review in flight

The round-1 review was dispatched against **rev 1**, so it is reviewing §4 as
originally written. Whether it independently finds this is a useful calibration of
the brief's fourth ask — *can a defect satisfy C1–C6 and still break the
composition?* — since the answer turned out to be that C1 as written could not be
satisfied by any implementable change. That will be recorded either way when the
review lands.

---

## 4b. Five findings, one root cause: `_jsonable` dispatches on `isinstance`

Round 1's finding 2, its fifth subtler mutant, recurrence 1 (the un-swept
exact-type-vs-subclass dimension) and live collisions **7 and 8** are all one
defect:

```python
def _jsonable(obj):
    if obj is None or isinstance(obj, (bool, int, str)):   # <-- here
        return obj
```

`isinstance` admits every subclass. Measured on the **shipped** canonicaliser,
serially — these are not properties of a planned implementation:

```
canonical(Number.ONE)  = 1     canonical(1)   = 1     COLLIDE? True    # IntEnum
canonical(Tag.A)       = "a"   canonical("a") = "a"   COLLIDE? True    # StrEnum
```

So the census of live collisions is **eight**: §2's five cross-type pairs, §2a's
`_BYTES_TAG`-via-dataclass, and these two.

### The fix, and why it is one change rather than five

Exact-type dispatch on the open domain, with explicit refusal for everything
outside the declared wire types:

```python
if obj is None or type(obj) in (bool, int, str):
    return obj
...
raise SchemaError("not canonicalisable: ...")
```

This closes finding 2, both live collisions, the fifth subtler mutant, and
recurrence 1 together — and it makes the subclass dimension **moot** rather than a
new `DIMENSIONS` entry needing its own sweep. That distinction is the whole point:
widening P21 case by case would leave the dispatch defect live and ask a property
to enumerate an **open set** (every subclass of every admitted family), which is
the narrowness shape one level up. A property cannot close an open set; a closed
domain can.

P21 still gains root **and nested** `IntEnum`/`StrEnum` pairs — as *regression
evidence* for a closed domain, not as the mechanism that closes it.

**Named and not taken:** keep `isinstance` and add an ordered enum-refusal branch
*before* the primitive arm. Rejected — it fixes the two enum families and leaves
`class MyInt(int)` and every `bytes`/`dict`/`list` subclass reaching the primitive
arm, i.e. the same class recurring with a different subclass. **What would flip
it:** a consumer that legitimately supplies a primitive subclass and cannot be
changed.

### Feasibility check — rev 1's Option A was unimplementable and I only found out by checking

§4a's lesson was that a remedy can be impossible and a plan can spend a whole
review round on the wrong question. So the flip condition was **measured**, not
reasoned about. `_jsonable` was wrapped for the whole property suite to record
every object reaching the primitive arm for which
`isinstance(obj, (bool, int, str))` is true but `type(obj) not in (bool, int, str)`
— i.e. exactly the objects exact-type dispatch would newly refuse:

```
75 passed in 58.46s
distinct primitive-subclass types reaching the primitive arm: 0
```

**Zero.** So exact-type dispatch changes no current behaviour, and the condition
that would flip the decision did not appear. Unlike Option A, this remedy is
implementable.

*Provenance, stated at the claim:* **serial-safe by immunity, not by isolation** —
the property suite was measured opening zero files outside the worktree, so this
figure is unaffected by whatever else was running, which is the whole point of
having proved immunity rather than re-run under quiet conditions. What the probe
does **not** establish is coverage of consumers the suite never exercises; it is
the suite's reachable set, not the module's. Combined with §4a's hand enumeration
of `canonical`'s consumers — which found enum, tuple and dataclass suppliers and
no primitive-subclass supplier — it is good evidence and not a proof, and it is
labelled as such.

### The per-arm policy, stated per arm, because the diagnosis is per arm

Round 2's condition: the remedy's extent must equal the diagnosis's. The diagnosis
is "`_jsonable` dispatches on `isinstance` **at every arm**", so a remedy naming
only the primitive arm is narrower than its diagnosis — which is precisely the
defect rev 5 shipped. Measured: `MyBytes`, `MyList`, `MyDict`, `MyInt` and `MyStr`
**all** collide with their bases today, so all five families are in the diagnosis.

One row per arm of `_jsonable`, with the policy and what it costs:

| arm | today | rev 6 policy | why |
| --- | --- | --- | --- |
| `None` | `obj is None` | unchanged | identity already exact |
| `bool` | `isinstance` | exact by **construction** | `bool` cannot be subclassed — measured: `type('B',(bool,),{})` raises `TypeError: type 'bool' is not an acceptable base type`. No code needed; recorded so a reader does not add a redundant guard |
| `int`, `str` | `isinstance` | `type(obj) is int` / `is str` | closes `MyInt`, `MyStr`, `IntEnum`, `StrEnum` |
| `bytes` | `isinstance` | `type(obj) is bytes` | closes `MyBytes`; `bytearray` and `memoryview` stay refused |
| `Mapping` | `isinstance(obj, Mapping)` | **open domain: `type(obj) is dict` only; every other `Mapping` is refused.** Structural domain: `dict` is what the module itself produces | rev 5 said both things at once — C2 called mapping subclasses out of domain while the code admitted any `Mapping`. **Decided, not left open:** a caller-supplied custom mapping at an *open* position is refused, because "refuse rather than guess" is this unit's rule and a custom mapping's iteration order and `items()` are not the module's to trust |
| `set`, `frozenset` | sorted by `json.dumps` | **refused at open positions** (§4a), retained at structural positions **which do not exist** — see the coverage note below | a set and a list canonicalise to the same array (P-E's live instance) |
| `list`, `tuple` | `isinstance(obj,(list,tuple))` | open: `type(obj) is list` only, `tuple` refused. Structural: `tuple`, per the declared annotations | a tuple and a list canonicalise identically, so admitting both at one position is non-injective by construction |
| dataclass | `dataclasses.is_dataclass` | structural only, and the registry of admitted dataclass types is **explicit** rather than "anything with fields" (C7) | §2a's `_BYTES_TAG` collision came in through this arm |
| enum | `isinstance(obj, Enum)` | **structural only, and dispatched BEFORE the primitive arms** | ordering is the fix, not an added check: an `IntEnum` reaching an `int` test first is encoded as an int whatever the enum branch says. C7's annotation check stays as a second line, not the first |
| else | `raise SchemaError` | unchanged | |

**Coverage note, measured and not comfortable.** Instrumenting `_jsonable` across
the whole property suite and recording the exact type reaching each arm:

```
75 passed in 69.13s      (serial-safe by immunity: 0 files opened outside the worktree)
none         326693  NoneType
primitive        12  bool        667855  int      1964381  str
enum          14347  ConflictClass  337808 Provenance  350945 Scope
bytes             4  bytes
mapping      337879  dict
list/tuple    16985  list        1261020  tuple
dataclass    350945  AppliesTo  ... Conflict, Observation, PinRecord, Ref
refused           1  float
set/frozenset     0  <-- NEVER REACHED
non-exact types reaching an exact-typed arm: 0
```

Two things fall out, and the second is a gap rather than a reassurance:

1. **Exact-type dispatch refuses nothing this suite produces** — every arm is
   reached only by its canonical wire type. The compatibility cost measured on the
   suite's reachable set is zero, for all five families, not just primitives. This
   is the same immunity-not-isolation caveat as before: the suite's reachable set,
   not the module's.
2. **The `set`/`frozenset` arm is reached 0 times.** That arm's sorting rule is
   entirely unexercised, which is *why* rev 3's set-sort mutant (candidate 5b) was
   non-viable — I recorded it as "could not construct" when the honest statement is
   **"the arm it mutates is dead in this suite"**. A rule no input reaches cannot
   be mutated to red, and an unreached arm is a gate that cannot fail. Rev 6
   therefore refuses sets at open positions **and** asserts the arm is unreachable
   rather than leaving it live-but-untested: §8 item 13.

### Interaction with §4a's positional split

These compose rather than conflict. §4a splits by **position** —
`_jsonable_structural` keeps enum/dataclass/tuple/set because each structural
position's type is schema-fixed; `_jsonable_open` is closed. Rev 5 says the closed
half must be closed by **exact type**, not by `isinstance`. Without that, the
positional split still admits `IntEnum` at an evidence position through the
primitive arm, and §4a's remedy would have shipped with collisions 7 and 8 intact.

Note the structural half needs it too, for a different reason: `Scope` is an
`Enum`, and if a future `Scope` were an `IntEnum` the structural encoder's enum
branch would be bypassed by the primitive arm. C7's mechanical check over
dataclass field annotations should therefore also assert that no structural enum
is a primitive subclass.

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
| ~~`evidence_gate_type_only`~~ **`breaks=None`** (rev 5, F3) | — | check the value is not a `float` but accept any other object | **Cannot prove the rule: masked.** The separately closed `_jsonable` still refuses the object, so P21 goes red for the *other* layer's reason and the mutant proves nothing about the gate. Registered with `breaks=None` — a mutant of a redundant layer is honest as a must-pass, dishonest as a binding. |
| ~~`observation_digest_first_wins`~~ **replaced** (rev 5, F3) | — | ~~drop the injectivity precondition~~ | **Was not a mutation at all.** `_merge_observations` already uses `setdefault`, so it *already* keeps the first object for an equal digest — the row described **pristine behaviour** and named no edit. This is §2a's shape (*the pristine implementation is the mutant*) recurring in my own new rows, one section after I wrote it down. |
| new `observation_dedup_ignores_values` | — | dedup observations by `(at, frozenset(evidence names))`, **ignoring evidence values** | An exact edit with an observable behaviour change. Bound to a merge property using **equal timestamps and differing values**: two observations at `t1` with `size=8` and `size=16` must stay two. Exposes §2's loss without depending on canonicalisation being broken. |
| new `bytes_tag_guards_mappings_only` (**rev 3**, §2a) | — | reserve `_BYTES_TAG` in the `Mapping` branch but not over dataclass field names — **= today's pristine behaviour**, a live collision | P21 must go **red**; today it passes, because it spoofs the tag only as a mapping key |

The fifth was found by trying to falsify "four is enough" (§2a), and a sixth
candidate was constructed, tested and **rejected as non-viable** rather than
quietly dropped — see §2a's second table. Four was not enough; the claim that
five is should be treated the same way.

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
REFUSAL-SITE CONTROL COVERAGE -- NOT a proof of accepted-domain closure
constructed-exception raise sites:            108   (rev 5: was 107)
bare re-raise sites (exempt):                   4
in instrument scope (module error classes):   106
out of instrument scope (UN-INSTRUMENTABLE):    2   (rev 5: was 1)
    L200   TypeError     -- builtin, __init__ not assignable
    L2154  SystemExit    -- builtin, __init__ not assignable
NEVER FIRED by any test in the repo:           28 / 106   (NOT re-measured)
positive-control coverage of refusals:      78/106 in scope (NOT re-measured)
```

**Rev 5, three corrections to this block, two of them to my own earlier
corrections.**

1. **Out of scope is 2, not 1.** Having been bitten by one un-patchable builtin
   raise I fixed that instance and declared the instrument correct, without
   enumerating the rest. `L2154 SystemExit` is the second. The in-scope
   denominator **106 is unchanged**; the constructed total moves 107 → 108.
2. **The header now states what the instrument is not.** Refusal-site coverage is
   **control coverage only, never accepted-domain proof** — full coverage can
   coexist with a false C2, because a type-only evidence gate fires on a `float`
   (giving the site its covered raise) while silently accepting an enum, tuple or
   dataclass along a path that raises nothing. The instrument must say this in its
   own output, not only in a plan, or the next reader takes 106/106 for closure.
3. **I over-reported a defect in my own instrument, again.** I stated in the
   round-1 review record that the census "had no category for the 4 bare
   re-raises". It does — `bare re-raise sites (exempt): 4` was in this block
   already. That is **false and was propagated**, and it is the *second* time I
   have accused this instrument of being worse than it is (the first was the
   `ABSENT.__bool__` pragma, whose comment was true). Both errors run in the same
   direction: a false accusation of missing coverage. Protocol `018b3ba` says an
   instrument must report what it cannot instrument as out of scope rather than as
   uncovered; the symmetric hazard is the *auditor* reporting a category as absent
   rather than reading it, and I am now the recorded instance of it twice.

**The allowlist loses its model entry.** Rev 1 offered `transition`'s L1252
`# pragma: no cover - P11 forbids` as the pattern for a legitimate allowlist
entry. Measured, the branch is **reachable**:

```
transition("active", "append")      -> StateTransitionError: undefined transition (active, append)
transition(R.State.ACTIVE, "append") -> StateTransitionError: refused: cannot append a candidate in state active
```

A plain string is a valid `event` with a non-`State` state, and P11 enumerates
only `None` and declared `State` members — so it never forbade this input. The
two calls take **different paths**, which is the tell. So the entry is deleted and
the branch gets a test with an invalid state instead. Generalised: **an allowlist
entry claiming unreachability is an absence assertion and gets the same treatment
as any other** — construct the input that reaches it, or it is not unreachable,
it is unexamined. The other 27 sites get a control or a reason under that rule,
and the count of *reasons* is reported separately from the count of *controls*.

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

**Two** sites are out of scope today, and rev 6 corrects this sentence, which
still read "exactly one" after rev 5 had already found the second — a stale claim
left standing beside the corrected census two sections above it. This is the F7
near-miss's mirror image: the refuting instrument must be at least as wide as the
claim it tests, and my check for stale "exactly one" sentences had been a regex
that required the sentence to end on one line, so this one — which wraps — was
invisible to it. A plain `grep "out of scope"` finds it at once.

| site | exception | why un-instrumentable | control |
| --- | --- | --- | --- |
| L200 | `TypeError` | builtin, `__init__` not assignable | hand-verified, `tests/test_context_resolve_properties.py:862` calls `bool(R.ABSENT)` |
| L2154 | `SystemExit` | builtin, `__init__` not assignable | **`_main`'s exit path is excluded from the census by declaration, not by omission** — it is the CLI boundary, it carries a process exit status rather than a refusal, and C6 requires a named exclusion rather than a silent one. The exclusion is the control: the census prints it as an excluded CLI site every run |

The corrected in-scope figure remains **28 of 106** (not re-measured — see §0).

Cost: ~28s added to the suite, measured serially. Acceptable; it is the only
instrument here that needs no hand-annotation to be true — provided it reports
its own blind spots, which is now a requirement rather than a hope.

---

## 7. Files touched

- `supwngo/schema/resolve.py` — `_jsonable`/`canonical` domain split (§4a) with
  **exact-type dispatch** on the open half (§4b), the evidence gate at L712,
  `CANONICAL_TYPES`; C8's single id-index inside `_validate_log` and `by_id`
  raising on a duplicate (§3a); C10's `validate_context` call in `applicable`
  (§3b).
- `tests/test_context_resolve_properties.py` — `DIMENSIONS` gains
  `evidence_value_type`. **Rev 5 correction (F6):** rev 1 assigned this to
  `resolve.py`. `DIMENSIONS` is defined **only** in the test module, so that line
  named a change to a symbol the file does not contain. One vocabulary constant,
  not two — it stays test-local, because the runtime has no use for it and a
  second copy is the drift this plan keeps finding elsewhere.

  *The one-grep sweep that should have caught it, re-run across every symbol §7
  claims a file gains:* `CANONICAL_TYPES` — not yet defined anywhere, correctly
  described as new. `_jsonable`, `canonical`, `by_id`, `_validate_log`,
  `applicable`, the L712 gate — all in `resolve.py`. `DIMENSIONS`, `NARROWNESS`,
  `SOLO_DIMENSIONS`, `PROPERTIES` — all test-local. `Mutant` and the registry —
  `mutants.py`. **One error, now fixed; swept, no others.**
- `supwngo/schema/mutants.py` — four new subtler mutants (§5), including
  `bytes_tag_guards_mappings_only` from §2a.
- `supwngo/schema/resolve.py` — **C8 (§3a)**: `_validate_log` builds its own
  id-index with the I6 duplicate check, so `current_pins` and `validate_store`
  cannot diverge; `by_id` raises on a duplicate instead of returning the first
  match. A moved check and a narrowed return contract, not new machinery.
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
6. **C8's gate, and it must be shown red first.** Build the §3a store —
   `[superseded, active]` under one id, no supersede record — and assert that
   *every* named consumer errors: `validate_store`, `current_pins`, `by_id`,
   and both dependency lookups. Red for the right reason means the subtler
   mutation is not "delete the I6 check" but **"keep I6 in `validate_store`
   and leave `current_pins` building its index by comprehension"** — i.e.
   today's behaviour, which is why this test must fail before the fix.
   Assert the consumer *errors*, never that it returns the right candidate:
   "the right one" is the assumption that produced the finding.
7. C7's clauses ship as one mechanical check over the dataclass field annotations
   (§2a): one type per structural position, no field named a reserved tag, and
   (§4b) **no structural enum that is a primitive subclass** — otherwise the
   structural encoder's enum branch is bypassed by the primitive arm.
8. **Exact-type dispatch (§4b).** P21 gains **root and nested**
   `IntEnum`/`StrEnum` pairs — as regression evidence for a closed domain, not as
   the mechanism that closes it. Nested matters: a collision inside a list or
   mapping value is the same defect one level down, and the current cases are all
   at the root. The subtler mutant for this rule is `isinstance` **restored** in
   place of `type(obj) in (...)` with the enum-refusal branch left intact — i.e.
   today's behaviour — and it must go red.
9. **C9's golden vectors (F5).** Commit byte-pinned expectations for canonical
   bytes, candidate IDs, dependency digests and log endpoints, taken **before**
   any change in this unit. A byte gate, not a sentence: §7's "expected
   unchanged" is exactly the form of claim this project has learned not to
   trust. If a vector moves, the schema version moves and a migration ships.
10. **C8's gate** — §8 item 6 — and **C10's**: call every `__all__` entry taking a
    `ResolveContext` with each context `validate_context` refuses, and require a
    **raise**. Shown red first: today `applicable` returns a boolean for all four
    (§3b), so the test fails before the fix and the subtler mutation is
    "validate in `resolve` but not in `applicable`" — today's behaviour.
11. **The new observation mutant** `observation_dedup_ignores_values` (§5) bound to
    a merge property with **equal timestamps and differing evidence values**.
    `evidence_gate_type_only` is **no longer registered `breaks=None`** (rev 6):
    `breaks=None` routes a mutant to **P9 only**, and P9 never exercises evidence
    validation, so the mutant was checked against a property that cannot see it —
    a binding that cannot fail dressed as a deliberate must-pass. It now names an
    explicit property that exercises the evidence gate with a non-primitive value,
    or it does not ship.
12. **P-E's positive control (§3b).** Two `==`-distinct observations at an *equal*
    `at` must both survive `_merge_observations`. Shown red first: today
    `{"trace": {1,2}}` and `{"trace": (1,2)}` collapse to one. No new production
    code — the control passes once §4a/§4b close the open domain, which is the
    point of filing P-E as a named dependency rather than a second fix.
13. **The dead `set`/`frozenset` arm (§4b).** Two tests, because refusing it and
    proving nothing reaches it are different claims: (a) a set at an open position
    **raises**; (b) the structural encoder has **no** position whose declared
    annotation admits a set — a mechanical check over the annotations, so the arm's
    removal is justified by the schema rather than by the suite's silence.
14. **The sixth subtler mutant:** `isinstance(obj, list)` restored in place of
    `type(obj) is list`, with `class EvidenceList(list)` as the witness. It must go
    red. This is the *container* half of §4b's diagnosis; rev 5 had a mutant for
    the primitive half only, which is how the mis-scoped remedy passed its own
    mutation table.
15. **`bytes_tag_guards_mappings_only` is re-bound.** It cannot bind to P21 after
    the positional split (P21 becomes an open-domain property and the mutant is a
    structural-arm defect), so it binds to a helper property with a **synthetic
    hostile dataclass** carrying a field named `_BYTES_TAG`'s value. Left on P21 it
    would have been unbindable and silently dropped.
16. **Hostile positive controls for C7's three absence checks.** Each of "one type
    per structural position", "no field named a reserved tag", and "no structural
    enum is a primitive subclass" gets a purpose-built violator that makes the
    check go red. An absence check with no violator is this project's most repeated
    defect; C7 shipped three of them in one row.

## 9. Risks

- **A closed domain is a compatibility decision.** Taken now precisely because
  **no in-repository production caller matched this search** — narrowed in rev 5
  from "no external caller exists yet", which a `grep` over `supwngo/` cannot
  establish by definition, and which would also miss calls through re-exported
  names. The decision still holds on the narrower claim, because the cost of a
  closed domain only grows; but the claim is now the size of its evidence.
- **The refusal-coverage allowlist can rot into a dumping ground.** Mitigation:
  each entry carries a reason, and the count is printed with the enumeration
  bounds so growth is visible.
- **C8 widens this unit beyond canonicalisation, and that is a real cost.**
  §3a's defect is not a canonicalisation defect; it surfaced while attacking
  this unit's seam contract, and the brief says a contract-breaking defect
  belongs here rather than deferred into unit 2. The alternative — defer it —
  is worse for the measured reason that unit 2 would build its seven log
  properties on top of it and every one would pass. But it is scope growth,
  it is named as such, and §4a's class (*a fix whose scope is wider than the
  diagnosis that motivated it*) applies to me as much as to rev 1: C8 is
  deliberately confined to index construction and `by_id`'s return contract,
  and touches no encoding.
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

---

## 10. Round-4 manifest — one row per class, one owning unit

Rev 1 summarised round 4 in prose and deferred "six other narrowness HIGHs" as a
comma-separated list. Round 1 was right that this is not mechanically reconcilable
and leaves defects without an owner. The manifest is numbered, and **every row has
exactly one owner**.

*Rev 6 makes that sentence true.* R4-5 and R4-7 each said "one owner" in the
heading and then named two in the cell — the claim and the table disagreed, in a
manifest whose entire purpose is that no defect lacks an owner. Both are split into
lettered rows with one owner each, which is the third scope mismatch this plan has
had to repair and the reason §11 exists.

| # | class | owner | status |
| --- | --- | --- | --- |
| R4-1 | canonicalisation not injective over its accepted domain | **unit 1** | §2, §2a, §4b — 8 live collisions |
| R4-2 | falsey value conflated with absent | closed in round 3 remediation + `085d4e5` | fixed; §2a is its bytes-tag cousin |
| R4-3 | property narrowness — input set does not vary the dimension claimed | **unit 3** | the annotation exists and is falsifiable; the *relational* checker is unit 3's |
| R4-4 | annotation entries that are false but well-formed | **unit 3** | all seven named below |
| R4-5a | gate that cannot go red — the refusal instrument's | **unit 1** | §6; and §4b's dead `set` arm, found in rev 6 |
| R4-5b | gate that cannot go red — P20's oracle and the enumeration report's | **unit 3** | `_merge_expecting_refusal`'s missing `else: raise`; `test_enumeration_bounds_are_reported`'s swallowed `AssertionError`. Both detailed below |
| R4-6 | trust-boundary statement broader than what is in-process provable | **unit 2** | the seven in-process log properties |
| R4-7a | subtler mutation of a bound rule survives its property — canonicalisation rules | **unit 1** | §5, six mutants including rev 6's container mutant |
| R4-7b | subtler mutation of a bound rule survives its property — every other bound rule | **unit 3** | the remaining bindings in `NARROWNESS` |
| R4-8 | a precondition enforced at the source, not at the consumers it names | **unit 1** | §3a (P-A) + §3b (P-C); C8, C10 |

### R4-4: all seven false annotation entries, named

Rev 1 admitted seven and named three. All seven, from the round-4 review:

| property | the false claim | the fact |
| --- | --- | --- |
| P2 | claims `log_record_count` varies | `_seeded_store` always contributes one record; batch merges add none |
| P3 | claims `observation_at` is **constant** | it explicitly changes `t1` to `t2` |
| P6, P25 | claim context `binding` variation | every candidate is BUILD-scoped, which takes no binding |
| P8 | claims `identity` and `conditions` are constant | both vary in `pool_raw` |
| P10 | claims `scope` and `conditions` vary | only `identity` inside `applies_to` changes |
| P16 | claims **candidate** `observation_at` varies | it is the log `at` that varies |
| P5b | claims candidate-id variation | not an independent id perturbation |

Seven rows covering eight properties (P6 and P25 share one claim). **Owner: unit
3**, together with the relational checker that would have caught all seven —
*a declared-varying field is not varying if another constraint pins it.*

### R4-5: the two dead gates round 1 found, with owners

Both are in the property suite, both are **unit 3's**, and both are live now:

- **`_merge_expecting_refusal` has no `else: raise`.** The assert sits inside
  `except R.SchemaError:`, so if `merge` does **not** raise, the helper returns
  silently and P20 passes. Verified by reading. A mutant that normalises a wrong
  caller generation to zero on a fresh store, while keeping terminal-store
  refusals, survives P20.
- **`test_enumeration_bounds_are_reported` swallows `AssertionError`** through a
  broad `except` and then asserts only that `_COUNTS` is non-empty — so one
  successful property is enough for the "actually exercised" report to pass while
  every other count is absent.

Neither appeared in rev 1's deferral list. They are named here so the deferral is
an assignment rather than a summary.

---

## 11. Rev 6 scope ledger — one `SCOPE` line per fix

Required by the rev-6 authorization. Mis-scoping is protocol class `1743788`: *a
remedy whose extent differs from its diagnosis's extent.* It has recurred in this
plan in both directions — §4a's remedy was **wider** than its diagnosis, §4b's was
**narrower**, §10's was **incomplete** — and **the class is the mismatch, not the
direction**, so the check is mechanical rather than a judgement about over- or
under-reach. A right diagnosis with a mis-scoped remedy passes review more easily
than a wrong one, which is exactly why it needs a mechanical check.

| fix | diagnosis extent | remedy extent | same set because |
| --- | --- | --- | --- |
| **§4b exact-type dispatch** | every `isinstance` arm of `_jsonable`: primitive (`bool`/`int`/`str`), `bytes`, `Mapping`, `set`/`frozenset`, `list`/`tuple`, dataclass, enum — 5 builtin-subclass families measured colliding | a policy row for **every one of those arms** (§4b's table), plus enum-before-primitive ordering | the table's rows are enumerated **from** `_jsonable`'s branches, not chosen; the arm list is the diagnosis restated. `bool` is in the remedy as "exact by construction" rather than omitted, so the row count matches the branch count |
| **§4a positional split** | non-injectivity at *open* positions only; structural positions are schema-fixed and injective by a different argument | `_jsonable_open` closed; `_jsonable_structural` unchanged in domain | the split is **by position**, and the diagnosis was stated per position. Rev 1's error was applying an open-domain remedy globally; the extents are now both "open positions" |
| **§3a/C8 bijection** | `by_id` first-wins, `current_pins` last-wins, `validate_store` raises, I8 saw 1 of 2 — four consumers disagreeing about one id | clauses (a)–(f): totality, identity, `by_id` agreement, declared absence, duplicate refusal, and **terminal as well as active** candidates | each clause maps to a measured disagreement, and (a)/(d)/(f) cover the *other* half of the diagnosis — a candidate **missing** from the index, which "duplicates rejected" does not address. Confined to index construction and `by_id`'s return contract; touches no encoding |
| **§3b/C10 `applicable`** | one exported decision function reading a `ResolveContext` without validating it | **every** `__all__` entry taking a `ResolveContext` must raise on a refused context | the remedy's extent is the enumeration `__all__` ∩ takes-a-context. `applicable` is the only current member, so a one-function fix and a whole-set gate have the same extent **today** — and the gate keeps them equal as `__all__` grows, which a one-function fix would not |
| **§3b/P-E** | `dedup_key`'s stated reason for excluding evidence depends on C1, which is false; 2 live instances, both nested open-domain container collisions | **no new production code** — a named dependency in C5 plus a positive control | the 2 instances are both open-domain collisions, so the extent of the defect is a **subset** of what §4a/§4b already close. A byte-keyed union would have had an extent **disjoint** from the diagnosis: it fixes a cryptographic assumption nobody measured failing and leaves both live instances live |
| **§6/C6 second out-of-scope site** | one stale sentence ("exactly one site") beside a corrected census reading 2 | the sentence corrected **and** L2154 given a declared CLI exclusion with the census printing it every run | the diagnosis is "a site with no control and no declared exclusion"; the remedy supplies the exclusion and makes it recurring output. Correcting only the prose would have left the extent at 1 of 2 |
| **§8.11 `evidence_gate_type_only`** | `breaks=None` routes to P9, which never exercises evidence validation — the binding cannot fail | an explicit property ID that exercises the evidence gate with a non-primitive value | the diagnosis is about **one** mutant's routing; the remedy changes **that** mutant's registration. The wider remedy (re-audit every `breaks=None`) is *not* taken here: the other must-pass mutant was verified against P9 deliberately, so widening would exceed the diagnosis |
| **§10 manifest** | 2 rows claiming one owner and naming two | those 2 rows split into 4 lettered rows | the other 6 rows were checked and each names exactly one owner; the remedy touches the 2 that did not |

### Mutants of shared components — the caller set each one runs against

Round 2's condition: *a mutant that dies only against its own component's tests
measures the mechanism, not the decision.* Each mutant below is a mutation of a
component **several** callers decide behaviour with, so the gate is the union of
those callers' tests, named here so a missing caller is visible rather than
inferred.

| mutated component | callers whose behaviour it decides | test set the mutant must be run against |
| --- | --- | --- |
| `_jsonable` / `canonical` | `dedup_key`, `derive_id`, `candidate_digest`, `canonical_document`, `Observation.digest`, `_validate_candidate`'s evidence gate (:712), `Ref.digest` | the whole property suite **plus** the byte-gated `docs/reference/context-resolution-tables.md` snapshot, because that document's bytes are a consumer of `canonical` that no test file mentions |
| `dedup_key` | `merge`'s DEDUPED/APPENDED case analysis; P14's dedup projection | merge properties **and** P1's dedup-collision dimension — P1 is the *whole* coverage of `dedup_collision`, so a mutant not run against it is unmeasured |
| `derive_id` | `by_id`, `PinRecord.candidate_id`, `by_candidate_id`, dependency lookup, `_validate_log`'s index, I6 | the store-invariant tests, the log tests, **and** C8's six clauses |
| `candidate_digest` | `Ref.digest`, dependency staleness (P17), conflict records | P17 — the *whole* coverage of `dependency_depth` — plus the conflict tests |
| `canonical_document` | `docs/reference/context-resolution-tables.md`'s byte gate; any exported document | the byte gate. **This is the caller with no test file**, and it is the one a component-local mutation table would miss |

**The rule this encodes:** before a mutant is called dead, the components it
touches are listed, each component's callers are enumerated, and the union of
those callers' tests is the gate. "It died against `test_context_resolve_properties.py`"
is a statement about one file, not about the decision.

### Self-certification, in place of a third review

Round 2's specified items, each with the sweep that checks it rather than a claim
that it was done:

| item | sweep run | result |
| --- | --- | --- |
| C8 bijection | clauses enumerated from the four measured consumer disagreements | 6 clauses, each mapped to a disagreement or to the missing-from-index half |
| per-arm exact-type policy | `_jsonable`'s branches enumerated from source; exact type recorded per arm across 75 passing tests | 10 arms, 10 policy rows; 0 non-exact types reaching any exact-typed arm; **`set` arm reached 0 times** — a new gap, filed as §8.13 |
| P-E | §3b's precondition sweep re-run with the fifth statement | 2 live instances; **2 of my 4 witnesses withdrawn as benign**, 1 as already-closed |
| C3/C5/C9 assumptions | each enforcement column read for "is this finite or universal?" | C3 gains a domain-quantifying property beside the vectors; C5 and C9 gain named assumptions; "retained" defined as a set |
| stale "exactly one" claims | `grep "out of scope"` — deliberately wider than the regex that missed it | 1 stale sentence, corrected |
| one owner per manifest row | all 8 rows read | 2 wrong, split into 4 |

**What this self-certification does not do:** it does not replace an adversarial
reader. Every item above is a check I specified against a defect I already knew
about, which is the definition of a gate whose failure mode I have already
imagined. That is precisely why the remaining round is spent on the **code**, by a
reviewer told that the plan is reviewed to convergence and is not the subject.

---

## 12. Implementation record — and my own counts, not a delegate's

Implemented on Sonnet, **one serial implementer, never parallel** (the 429 that
cost an earlier session came from fan-out). Nine commits on
`feat/context-schema-v4-20260924`:

```
e3dd0d6 test(schema): pin canonical byte vectors before the domain change
8729a10 fix(schema)!: close the canonicalisation domain per position and type
4b0c86b fix(schema): make the candidate id index a bijection
935cf44 fix(schema): validate the context in every exported decision function
f7490e7 test(schema): add hostile controls for the structural-position checks
be6e688 test(schema): bind the canonicalisation mutants to varied properties
3cb5e55 fix(schema)!: refuse subclasses at every structural dataclass position
ee322e9 test(schema): name the over-permissive gate first in P21
f2eeaab test(schema): add the refusal-coverage instrument (C6)
```

### Gates, re-run by me because §5.1 applies without exception

An implementer once reported 5 of 9 red when 7 were, erring in the *safe*
direction, which is exactly why a casual check would have passed it. So every
figure below is one I measured, with the command that produced it. Another agent
was running pytest in `/tmp/st-r16-fix` throughout, so these are **concurrent**;
they are trustworthy anyway for the reason given under "immunity" below.

| gate | command | my result |
| --- | --- | --- |
| schema suites | `pytest tests/test_context_resolve_properties.py tests/test_context_resolve_golden.py tests/test_context_resolve_refusal_coverage.py -q -p no:cacheprovider` | **108 passed** in 75.45s |
| repo-wide, excl. `test_challenges.py` | `pytest tests/ -q -p no:cacheprovider --ignore=tests/test_challenges.py` | **706 passed, 10 skipped** in 234.70s |
| mutation meta-test | `pytest … -k test_mutant_is_caught` | 47 mutants, 2 must-pass |
| **new mutants: died by assertion** | each applied by hand, its bound property run, the exception *type* recorded | **9 / 9 by assertion, 0 by crash, 0 escaped** |
| reference-document byte gate | `pytest … -k "table or stale"` | **2 passed** — generated bytes did not move |
| golden vectors retrofitted? | `git diff e3dd0d6 HEAD -- tests/test_context_resolve_golden.py` | **empty** — every pinned byte survived the domain change untouched |
| refusal census | `pytest tests/test_context_resolve_refusal_coverage.py -s` | 113 constructed / 4 bare re-raise (exempt) / **111 in scope** / **2 out of scope** (`TypeError` L200, `SystemExit` L2368) / **30 never fired** / **81 fired** — all measured this run, none re-quoted |

**A gate that cannot fail is worse than none, so I broke the resolver myself
rather than trusting the report.** Injected a new un-instrumentable builtin raise
site (`raise KeyError(...)`) into `resolve.py` and ran the C6 instrument:

```
AssertionError: raise site(s) for ['KeyError'] are out of instrument scope with no
declared allowlist entry -- C6 requires every out-of-scope site to be named with a
reason, not merely discovered and left unlabelled
1 failed in 44.01s
```

Red, for the right reason, on the clause C6 exists to enforce. File restored;
`git status` clean at `f2eeaab`. The nine mutants are the standing version of the
same proof, and I verified each one's **diagnostic text** as well as its death,
because a mutant that dies on the wrong assertion escapes the moment someone
fixes the side effect it actually tripped.

### Two defects found after implementation, by reading rather than by testing

Both were caught because the suite was green and I read the code anyway.

1. **HIGH — the dataclass arm was still inexact, and it re-created collision #1.**
   `_jsonable_structural` admitted subclasses (`dataclasses.is_dataclass`) while
   the open-field routing beside it keyed on exact `type(obj)`, so a subclass was
   admitted *and* lost its open-position routing:

   ```
   class SubObs(R.Observation): pass
   SubObs('t1', (('k', IntEnum.THREE),)) -> {"at":"t1","evidence":[["k",3]]}
   R.Observation('t1', (('k', 3),))       -> {"at":"t1","evidence":[["k",3]]}   IDENTICAL
   ```

   Public path — `Observation` and `canonical` are both in `__all__`. §4b's own
   dataclass row had specified an **explicit registry** rather than "anything with
   fields"; the code kept the latter. Fixed by `_STRUCTURAL_DATACLASSES` with
   exact-type dispatch, P32 quantifying over the whole registry, and a mutant
   restoring `is_dataclass`. Verified by me: a subclass of **all five** registry
   types is now refused.

   *The uncomfortable part:* this is a **fourth** instance of the mis-scoping
   class, and it is mine — §11 requires a `SCOPE` line for every fix in the plan,
   and I did not apply the same discipline to my own implementation brief.

2. **LOW — P21's diagnostic misnamed a defect.** `evidence_gate_type_only` died on
   "a legal open-domain value `b'x'` was not canonicalisable", a side effect of its
   own patch, rather than on the over-permissive gate. I measured that its named
   defect *was* independently caught (under the mutant, an `IntEnum` member, a
   tuple and a list subclass are all accepted), so this was loop **order**, not a
   weak binding. Refusal loop now runs first; the message now reads
   "`<_ProbeIntEnum.THREE: 3>` reached an open position uncaught".

### §6 was omitted from my brief, and C6 had no enforcement because of it

The refusal-coverage instrument did not exist after the first implementation pass:
`grep -rn "f_lineno\|addaudithook\|raise_sites"` over `tests/` and
`supwngo/schema/` returned nothing. C6's enforcement column names "§6", so the
contract had a row with nothing behind it — the identical defect rev 5's C2 and C3
columns had, which this plan flags twice. My six-step brief simply had no step for
it. Recorded here rather than quietly added, because the brief's extent differing
from the unit's extent is the same class as §4a's and §4b's.

### Four sweep candidates checked and rejected

A sweep yields candidates, not findings, and reporting an intentional absence as a
gap costs a round exactly like a skipped sweep. Of eight hits in the
"inexact admission where exactness decides the outcome" sweep, **one** was a
defect:

| candidate | why it is NOT a finding |
| --- | --- |
| `IntEnum(1)` vs `1`, `StrEnum('a')` vs `'a'` as P-E witnesses | `==`-indistinguishable, so collapsing them is **correct** dedup, not lost evidence. C5's own wording ("any two a caller **can** distinguish") is what rules them out |
| outer evidence container, tuple vs list | already closed: `_validate_candidate` normalises to `tuple(sorted(...))` and there is exactly **one** call site |
| the `value` type gate's `isinstance` | a `MyInt` value is refused **during** validation, measured — so no collision reaches a digest, and §3b's P-B "clean" verdict stands |
| `enum.Enum` dispatch in the structural encoder | deliberate: members legitimately subclass their `Enum`, the arm returns `.value`, and C7 clause 3 separately forbids a primitive-subclass enum. Narrowing it would be a remedy wider than the diagnosis |

### Erratum, beside the original

My earlier figure "the property suite opens **0** files outside the worktree" was
measured with an instrument **narrower than the claim**. A wider audit hook records
**5**. A control run with **zero tests selected** produces the same 5, proving they
are pytest's own output-capture plumbing and not the suite. Immunity therefore
holds in substance — no test code opens anything outside the worktree, so the
concurrent run in `/tmp/st-r16-fix` cannot reach these measurements through shared
state — but the number "0" was wrong, and it was wrong in the same direction as the
F7 near-miss: a refuting instrument must be at least as wide as the claim it tests.

### Outstanding, unfixed, and named rather than left to be discovered

### §7's file list was incomplete, and its own sweep could not have caught it

Measured — what the implementation actually changed, against what §7 claims:

```
CHANGELOG.md                                     claimed  ok
supwngo/schema/resolve.py                        claimed  ok
supwngo/schema/mutants.py                        claimed  ok
tests/test_context_resolve_properties.py         claimed  ok
tests/test_context_resolve_golden.py             NOT CLAIMED -- new file (C9)
tests/test_context_resolve_refusal_coverage.py   NOT CLAIMED -- new file (C6/§6)
docs/reference/context-resolution-tables.md      claimed, correctly hedged; bytes
                                                 unchanged and the byte gate agreed
```

Two **new test files** exist that §7 never names, and §7 attributes the
refusal-coverage gate to `tests/test_context_resolve_properties.py`, where it did
not end up. The reference document's row is the one §7 got right, because it
deferred to the byte gate instead of asserting an outcome.

The instructive part is *why* §7's own sweep missed this. Rev 5 added a one-grep
sweep over every **symbol** §7 claims a file gains, and concluded "**One error, now
fixed; swept, no others**". That sweep was over symbols; the defect is over
**files**. A new file contains no symbol the sweep was looking for, so the
instrument could not have found it however carefully it was run.

That is the **third** instance in this unit's implementation phase of one class:
*a refuting instrument narrower than the claim it tests.* The F7 near-miss (a regex
requiring a sentence to fit on one line), the C10 near-miss (a caller using one
arity for functions with two), and this one. The protocol sentence already covers
it — `1743788` §6.1b, *a refuting instrument must be at least as wide as the claim
it tests* — and the addition this phase earns is that **the claim's dimension** has
to be checked too, not only its breadth: §7's sweep was wide over symbols and had
the wrong dimension entirely.

### C8 verified independently, clause by clause

Six clauses, checked by me rather than inferred from a green suite. Clauses (c) and
(e) are carried by the `candidate_id_index_diverges` mutant, which I confirmed dies
by assertion (`DID NOT RAISE SchemaError`) rather than by crash. The other four,
measured directly on a store holding one **retracted** and one **active** candidate:

```
(a) distinct ids 2 / 2 candidates                      -> bijection
(b) f_551577b06cfc state=retracted  by_id(id) is c  -> True   (identity, not equality)
    f_c2160215216e state=active     by_id(id) is c  -> True
(f) active=1 terminal=1 -- the bijection holds over BOTH
    validate_store on the retracted store            -> clean
```

Clause (f) was worth checking precisely because a reader assumes a terminal
candidate has left the index; it has not, and `by_id` returns it by identity.

**Clause (d), honestly:** `by_id` is annotated `-> Optional[Candidate]` and returns
`None` for an id that is not stored. Whether that is the "declared absence" clause
(d) demands is a judgement, and mine is that the annotation **does** declare it —
`Optional` is not a silent `None`. Recorded rather than filed, with the residual
below, because filing a deliberate and declared design as a gap costs a round
exactly like skipping a sweep.

### C8(d) residual, LOW, and left unfixed

`by_id` conflates *malformed* with *absent*:

```
by_id('f_000...0')  -> None      # a well-formed id that names nothing: correct
by_id('not_an_id')  -> None      # not an id at all
by_id('')           -> None      # not an id at all
```

The module has `_ID_RE` and uses it to reject non-matching ids in log validation,
so the inconsistency is internal: one consumer treats a malformed id as a hard
error and another reports it as absence. A caller with a typo is told the candidate
does not exist. LOW because no wrong candidate is ever returned and no digest is
affected — C8's actual subject is unharmed — but named here rather than left for
someone to rediscover.

### C10 verified independently — and a second near-miss, recorded not corrected

The plan says *every* `__all__` entry taking a `ResolveContext` must raise. I did
not take it on trust that `applicable` was the only member: I enumerated `__all__`
myself and found **six** entries with a context parameter — `validate_context`
(the validator itself) plus five consumers, including **`try_resolve`**, which is
named nowhere in this plan.

My first run reported **8 C10 leaks**: `conflicts` and `agreements` raising
`TypeError` rather than `SchemaError` for all four refused contexts. That would
have been a HIGH finding filed against correct code. It was **my instrument**:

```
conflicts    (store, ctx)              <- two parameters
agreements   (store, ctx)
resolve      (store, key, ctx)         <- three
```

I had called all five with `(store, key, ctx)`, so the `TypeError` was my own
arity error. Re-run correctly:

```
              list-identities  empty-str-identity  non-str-condition  bad-mode
applicable    SchemaError      SchemaError         SchemaError        SchemaError
resolve       SchemaError      SchemaError         SchemaError        SchemaError
try_resolve   SchemaError      SchemaError         SchemaError        SchemaError
conflicts     SchemaError      SchemaError         SchemaError        SchemaError
agreements    SchemaError      SchemaError         SchemaError        SchemaError
C10 leaks: 0   (5 consumers x 4 refused contexts = 20 cases)
```

**C10 holds, measured, with zero leaks.** This is the F7 pattern a second time —
an instrument whose shape did not match the claim it was testing, producing a
confident wrong answer about correct code — and the only reason it did not become
a filed finding is that `TypeError` from five functions at once is too uniform to
be a real defect, so I checked the signatures before writing it up. Recorded
rather than quietly fixed, because a silently corrected near-miss is
indistinguishable from never having erred and teaches nobody. The generalisation
it supports is the one already in protocol: **a crash is not a finding any more
than it is a proof** — when an instrument reports the same exception from every
target, suspect the instrument.

- **LOW.** `tests/test_context_resolve_golden.py`'s purity property is described as
  quantifying over a "**generated** domain", but `_purity_domain()` returns a fixed
  list of 20 values. It is an *enumerated* domain. The distinction is exactly the
  one C9 is careful about — finite examples are regression evidence, not proof — so
  the wording overclaims by the same measure the file elsewhere refuses to. Either
  the word changes or the domain becomes genuinely generated.


---

## §13 Code-review remediation record (post-implementation round)

The final round was a **code** review, not a plan review: the plan had returned
`NEW 0` for three consecutive rounds with every `INTRODUCED` finding a re-created
instance of an already-named class, so round 4 escalated by changing artifact
rather than running a fourth prose round. It returned **8 findings, 8 confirmed,
0 rejected**, four of them HIGH, and is recorded verbatim in
`docs/reviews/2026-09-24-schema-unit-1-code-review.md`. This section records what
was done about them. Every fix carries the `SCOPE` line rev 6 requires: the
diagnosis's extent, the remedy's extent, and why they are the same set.

### R1 — F1, F2, F5: one root, one remedy

**Diagnosis.** A structural position's **declared** type was assumed, never
enforced. The encoder dispatched on the *value's* runtime type at every arm, so
nothing compared the value against what the *position* declares. Three instances,
one cause:

| | witness (measured, pre-fix) |
| --- | --- |
| F2 | `Observation(Scope.BUILD) != Observation("build")` yet both canonicalise to `{"at":"build","evidence":[]}`; `_merge_observations` returned length **1**, silently dropping one |
| F5 | `dataclasses.replace(c, applies_to=Observation(...))` accepted by public `derive_id`, returning `f_69ef452e4651c390767165f1a97278fc` |
| F1 | `canonical((1,2)) == canonical([1,2]) == "[1,2]"`; `canonical(Scope.BUILD) == canonical("build")` |

**Remedy.** `_STRUCTURAL_FIELD_TYPES` (the dataclass arm) and
`_CANDIDATE_FIELD_TYPES` (`Candidate.project()`, since a `Candidate` instance is
never itself passed to the structural encoder), both built once at import from
each dataclass's own `typing.get_type_hints`, consulted at every position; plus
`_check_root_admissible`, which refuses at `canonical()`'s root exactly the four
kinds that are ambiguous *with an admitted type* — `tuple`, `set`, `frozenset`,
and any `Enum` member.

`_resolve_field_shape` **raises at import** on an annotation shape it does not
handle. That is the load-bearing choice: an unhandled shape is exactly how this
defect got in, so the failure mode is a refusal to start rather than a silent
admission.

> **SCOPE.** Diagnosis extent: every structural position at which a declared type
> exists and was unchecked — the 5 registered dataclasses' declared fields, plus
> `Candidate`'s 11 fields via `project()`, plus the root, which has *no* declared
> type and so needs the ambiguity rule instead of a type check. Remedy extent:
> the same three sets, by the same mechanism where a declaration exists and by the
> ambiguity rule where none does. Same set because the enumeration is mechanical,
> not judged: both tables are **total comprehensions** over `dataclasses.fields`,
> so the remedy cannot be narrower than the diagnosis without failing at import;
> and the root is the one position with no declaration, handled by the one rule
> that does not need one. Not wider: a schema-fixed *nested* position (e.g.
> `AppliesTo.conditions`, declared `Tuple[...]`) keeps its tuple repertoire — the
> root guard runs at the root only.

**Note the ordering consequence.** The enum-before-primitive arm is *kept*, and is
still correct: it is right for a position whose declared type **is** an `Enum`.
What was wrong was that nothing stopped it applying where `str` is declared. The
remedy is the per-position check, not a reordering — which is why F2 indicts the
arm's *scope*, not the arm.

### R2 — F7: the version identifier

C9 requires that a break to the accepted domain move the schema version and ship
a migration. Tuple/enum/set/float/dataclass evidence that v1 accepted is now
refused, so `canonical_document` emits **`supwngo.context/v2`**, with a migration
note in `CHANGELOG.md` under `[Unreleased]`.

**This deliberately moved a committed golden vector**, which is the one thing the
C9 integrity check exists to detect, so it is recorded as the contract operating
rather than a vector retrofitted. The v1 bytes are **retained in the file**, not
overwritten, as `test_golden_canonical_document_small_store_PRE_V2_RECORD` — a
frozen literal, because `canonical_document()` can no longer produce v1 bytes at
all. Its hash is unchanged from the pre-change capture
(`b4b79839ed70096dff4d71f30d7f2a4eddc864eaf620877bb655fbccc1b7e9fe`); the new v2
vector hashes to `5012c11b6bf95e9889b776b715fd6c5af3e6ef215eb0cbaac37858b2bc3f364c`
and differs only in the trailing field. The byte-gated
`docs/reference/context-resolution-tables.md` did **not** move, and I verified the
reason rather than asserting it: the document contains `schema_version` **0**
times, and its byte gate was run, not assumed.

> **SCOPE.** Diagnosis extent: one emitted identifier, and the one golden vector
> that pins bytes containing it. Remedy extent: that identifier, that vector (split
> rather than overwritten), and the migration note. Same set because the break
> itself was already shipped and recorded — F7 is about the *label* on it, so the
> remedy is confined to the label and to the one artifact that pins the label's
> bytes. Not wider: no behaviour changed in this commit.

### R3 — F3, F4, F6, F8: four gates narrower than their contracts

All four were weak gates over **correct** code, and the distinction is recorded
because it is the one the class-and-sweep protocol turns on:

- **F3** — P21's refusal table omitted seven families C2 names. I measured that
  the encoder **already refuses every one**, so these are *regression rows*, not
  leak fixes. Widened to root **and** nested, and two mutants added so the new
  rows are not vacuous.
- **F4** — `_purity_domain()` was a fixed 20-item list described as "generated".
  Now genuinely generated by recursive/product construction. This was on §12's own
  outstanding-LOW list before the review returned it, which is why it appears
  twice in this plan's record.
- **F6** — P29 asserted `by_id(a.id) == a`. A stale `dataclasses.replace` copy
  satisfies `==` while violating C8 clause (b). Now `is`, with clauses (a), (d)
  and (f) asserted directly, and a mutant storing copies to prove the identity
  assertion non-vacuous.
- **F8** — P28 hard-coded five function names. Now derived from
  `__all__ ∩ {callables with a ResolveContext-annotated parameter}`, asserted
  non-empty and equal to the set actually exercised.

> **SCOPE.** Diagnosis extent: four test-side gates, each asserting less than the
> contract clause it is named for. Remedy extent: those four gates. Same set
> because no production behaviour was implicated by any of the four — I measured
> the encoder against all seven of F3's families and `by_id`'s identity behaviour
> by hand before deciding — so a production change here would have been *wider*
> than the diagnosis, which is the mis-scoping class in the direction §4a already
> cost a round for. `resolve.py` is untouched by this commit.

### R4 — the gap my own re-run found, and the sweep for its class

**A residual gap in R1's own instrument.** `_STRUCTURAL_OPEN_FIELDS` is normative
data — the contract says there is *exactly one* declared open position — and
nothing pinned its content. Worse, both new instruments **consume it as a skip**:
P33 and P34 each begin `if f.name in open_fields: continue`. So the one table that
is the sole exemption to per-position enforcement was policed only by the two
properties that apply the exemption. Measured, by widening the set to
`{"evidence", "at"}` and re-running both properties directly:

```
P33: PASSED with the open set widened   <-- unpinned
P34: SchemaError                        <-- a crash, not a detection
```

Neither is a gate on this drift: one passes, and the other only escapes an
exception out of its own fixture, which this suite's own meta-test classifies as a
crash rather than a proof. That is an **enforcement column with nothing behind
it** — the identical defect §12 records for C6, recurring inside the remedy for
it. Closed by a property pinning the table's keys and each value set **by
equality** (a subset assertion would pass against a widened set and reproduce the
defect a third time), plus a mutant widening it.

> **SCOPE.** Diagnosis extent: the content of one normative table, unpinned in both
> directions of drift. Remedy extent: one property pinning that table's keys and
> each value set by equality, plus one mutant proving it fails. Same set: the
> remedy pins exactly the table that was unpinned, in both directions, and touches
> neither P33's nor P34's logic — both are correct for what they check; the missing
> thing was a gate on the data they exempt.

**SWEEP for the class** — *normative module-level data whose content no gate pins*
— because an instance is not a finding and a fix for one instance is not a fix for
the class. Ten tables checked; **8 candidates, 7 explained, 1 real gap** (the one
above):

| table | verdict |
| --- | --- |
| `_STRUCTURAL_OPEN_FIELDS` | **the real gap** — fixed above |
| `_BYTES_TAG` | indirectly equality-pinned: the literal `__bytes_b64__` appears inside a golden byte vector |
| `_ID_HEX` | indirectly pinned: 15 frozen golden ids are all exactly 32 hex long |
| `DERIVED_FIELDS` | indirectly pinned in the direction that matters — leaking a derived field into a digest breaks all 15 golden ids |
| `STORE_INVARIANTS` | **equality-pinned** — `assert controlled == set(R.STORE_INVARIANTS)` |
| `_STRUCTURAL_DATACLASSES` | both drift directions caught: de-registering `Ref` → 6 properties red (P32, P33 by `AssertionError`); registering a bogus type → P32 and P33 red |
| `_STRUCTURAL_FIELD_TYPES` | complete by construction (total comprehension) and fail-closed at import; P33 guards the one skip path |
| `_CANDIDATE_FIELD_TYPES` | same, and never mentioned in tests *because* a missing entry is unconstructable |
| `CONTENT_FIELDS` / `ID_DIGEST_FIELDS` / `DEP_DIGEST_FIELDS` | equality-pinned by golden projections |

So the class has **no further live instances**. That is the point of running it:
without the sweep, fixing `_STRUCTURAL_OPEN_FIELDS` would have been an instance
fix wearing a class fix's clothes.

### ERRATUM — my own sweep instrument was narrower than its claim

My first sweep reported `STORE_INVARIANTS` as **"MENTIONED, NOT PINNED"**. That
was wrong, and it is wrong in the already-named way: my detector was
`^.*\bNAME\b.*==.*$`, which only matches a pin where the symbol appears **to the
left** of `==`. The actual pin reads

```
assert controlled == set(R.STORE_INVARIANTS), (
```

— symbol on the right, so my regex could not see it. One more instance of *a
refuting instrument narrower than the claim it tests*, and mine. It was caught
only because the script printed the matching lines beneath its own verdict, so the
output contradicted its own conclusion in the same block; had it printed the
verdict alone I would have filed a false gap. Recorded unsoftened: this is the
third session instance of that class (F7's regex, the C10 arity, now this), and
the erratum stays beside the original because a silently corrected near-miss is
indistinguishable from never having erred.

### My own measured counts

Reported per §5.1 — **I re-ran every gate myself**; none of these is a delegate's
number. (The standing reason: an implementer once reported 5 of 9 red when 7 were,
erring in the safe direction, which a casual check passes.)

```
                MY OWN MEASUREMENTS -- re-run by me, not a delegate's numbers
                =============================================================

three schema suites
  python3 -m pytest tests/test_context_resolve_properties.py \
      tests/test_context_resolve_golden.py \
      tests/test_context_resolve_refusal_coverage.py \
      -q --no-header -p no:cacheprovider
  -> 120 passed in 81.55s              (was 108 before this round)

repo-wide, excluding the benchmark corpus
  python3 -m pytest tests/ -q --no-header -p no:cacheprovider \
      --ignore=tests/test_challenges.py
  -> 718 passed, 10 skipped, 1 warning in 238.98s   (was 706 passed, 10 skipped)
  the warning is pre-existing and unrelated: unicorn's pkg_resources deprecation

mutation meta-test
  python3 -m pytest tests/test_context_resolve_properties.py \
      -k test_mutant_is_caught -q --no-header -p no:cacheprovider
  -> 54 passed, 56 deselected
  54 mutants total: 52 bound to a property, 2 must-pass (provenance_fourth,
  contradiction_guard_disabled), checked against P9 only.  38 properties,
  33 dimensions.  Nothing was shrunk: properties 32 -> 38, mutants 45 -> 54.

the seven NEW mutants, applied directly and classified by ME
  a crash is not a proof: AssertionError / Failed = detection,
  TypeError / KeyError / ValueError = the patch broke the machinery
    structural_field_type_unchecked            -> P34  PROOF
    canonical_root_accepts_ambiguous           -> P35  PROOF
    structural_field_types_missing_a_field     -> P33  PROOF
    open_domain_isinstance_bytes               -> P21  PROOF
    open_domain_admits_unregistered_dataclass  -> P21  PROOF
    candidate_id_index_returns_copies          -> P29  PROOF
    open_field_set_widened                     -> P36  PROOF
  7/7 died by AssertionError/Failed, 0 crashes, 0 escapes, each on the check
  that names ITS OWN defect rather than a side effect of its patch.  Verbatim:
    P33: "AppliesTo.scope is a declared (non-open) field with no shape entry
          in _STRUCTURAL_FIELD_TYPES"
    P29: "by_id('f_86488b4c...') returned an object that is == but not `is`
          the stored candidate -- clause (b) requires the SAME object"
    P36: "Observation's declared open field set is ['at', 'evidence'], not
          exactly {'evidence'}"

the four review witnesses -- all four must now RAISE
    canonical((1,2))                      SchemaError: not canonicalisable at
                                          the root: a bare tuple would collide
                                          with the list it resembles
    canonical(Scope.BUILD)                SchemaError: ... a bare Scope member
                                          would collide with its own .value
    canonical(Observation(Scope.BUILD))   SchemaError: Observation.at: declared
                                          type is str, got Scope
    derive_id(Observation at applies_to)  SchemaError: Candidate.applies_to:
                                          declared type is AppliesTo, got
                                          Observation
  4/4.  And F2's live consequence is closed at the seam, not just the encoder:
  _merge_observations((Observation(Scope.BUILD),), (Observation("build"),))
  now REFUSES where it previously returned length 1, silently dropping one.

P36 measured in BOTH states -- a gate red in both states is no gate either
    live table  {Observation: ['evidence']}          -> GREEN
    widened     {Observation: ['at', 'evidence']}    -> RED, AssertionError
    narrowed    {Observation: []}                    -> RED, AssertionError
  bidirectional, and green on correct code.

refusal-site census -- quoted, not summarised, per the census protocol
  constructed-exception raise sites:            124
  bare re-raise sites (exempt):                   4
  in instrument scope (module error classes):   122
  out of instrument scope (UN-INSTRUMENTABLE):    2
      L203   TypeError    -- builtin, __init__ not assignable
      L2664  SystemExit   -- builtin, __init__ not assignable -- the CLI path
  NEVER FIRED by the representative subset:      38 / 122
  fired at least once (positive-control coverage): 84 / 122
  This round ADDED 11 in-scope refusal sites and 8 of them never fire under the
  representative subset, so positive-control coverage fell 81/111 (73%) to
  84/122 (69%).  Recorded as a regression in the ratio, not glossed: the new
  per-position refusals fire only on a wrong-typed value at one specific field,
  and the subset does not drive every field individually.  The absolute number
  of controlled sites rose; the proportion did not.

C9 integrity -- the one check that exists to catch a retrofitted vector
  The golden file DID move, and deliberately.  The v1 bytes are retained in the
  file as a frozen literal, hash UNCHANGED from the pre-change capture
  (b4b79839ed70096dff4d71f30d7f2a4eddc864eaf620877bb655fbccc1b7e9fe); the v2
  vector hashes 5012c11b6bf95e9889b776b715fd6c5af3e6ef215eb0cbaac37858b2bc3f364c
  and differs only in the trailing schema_version field.
  The byte-gated docs/reference/context-resolution-tables.md did NOT move, and I
  verified WHY rather than asserting it: the document contains "schema_version"
  0 times, and its byte gate was run, not assumed.
```

**The red-first question, stated plainly.** The implementer did **not** show
P33/P34/P35 red against the pre-fix resolver, and said so unprompted rather than
letting it pass. The substitute is this suite's own established one — each new
property is bound to a named mutant, and I verified all **7/7** new mutants die by
`AssertionError`/`Failed`, each on the check that names **its own** defect, not a
side effect of its patch. The diagnostics are quoted in full above. That is
weaker than a literal red run in one specific way worth naming: it proves each
property can fail, but not that it would have failed against the *original* code
rather than against the mutant's particular patch. For P34 and P35 the four
witnesses close that gap directly — they are the original defects, measured
accepting before and refusing now. For P33 no such witness exists, because P33
guards a table that was complete on the day it was written; it is a regression
gate by construction, and is labelled one here rather than credited as a
discovery.

P36 is the exception, and the only new property with a *literal* red-green pair:
I ran it against the live table (green), the widened table (red), and the
narrowed table (red), in one process, and the gap it closes was measured before
the property existed. That is what the other three should have had.

### Commits

| commit | what |
| --- | --- |
| `c778698` | `fix(schema)!:` per-position declared-type enforcement — F1, F2, F5 |
| `1fedba5` | `feat(schema)!:` schema bumped to `supwngo.context/v2` + migration — F7 |
| `f4a7e98` | `test(schema):` four gates widened to their contracts — F3, F4, F6, F8 |
| `54f91a1` | `test(schema):` the one declared open position pinned — the residual gap |

Eight findings, eight closed, plus one gap the remediation's own instrument had
and my re-run found. What carries forward is not the count but the shape: the
review found four HIGH defects in code that three consecutive `NEW 0` plan rounds
could not have found, because they were properties of code that did not exist
when those rounds ran. The escalation from prose to artifact is what produced
them.
