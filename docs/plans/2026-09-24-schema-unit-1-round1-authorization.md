# Unit 1 (canonicalisation) — round-1 disposition and revision authorization

**Date:** 2026-09-24
**Artifact:** `docs/plans/2026-09-24-schema-unit-1-canonicalisation.md`, held at rev 4
**Review:** `docs/plans/2026-09-24-schema-unit-1-review-round1.md`
(codex `gpt-5.6-sol`, `xhigh`, NOT-APPROVED, **RECURRENCES 5 / NEW 0 / INTRODUCED 3**)
**Branch:** `feat/context-schema-v4-20260924` @ `e6498a7`
**Status of this document:** the authorization is **written and queued**, not yet
dispatched — see "Dispatch" at the end. Three agents are running against the ~3
concurrency ceiling and all three sit on the R5 critical path; unit 1 does not.

---

## 1. Disposition: revise. Two rounds of the three-round budget remain.

`NEW 0` for the second round running is the number that matters. Adversarial
discovery on this module is converged: the reviewer found no defect *class* that
rounds 1–4 had not already named. Every HIGH is a class whose sweep was skipped,
or one this plan introduced. That is the signal to finish the unit, not to
re-scope it.

The reported recurrence count was reported **before** revising, per the protocol.
Recorded and accepted.

## 2. Five findings, one root cause — fix the dispatch, not the instances

Recurrence 1 (the un-swept exact-type-vs-subclass dimension), live collisions 7
and 8 (`IntEnum`/`StrEnum`, measured on the **shipped** canonicaliser —
`canonical(Number.ONE) == canonical(1) == 1`), the reviewer's fifth subtler
mutant, and finding 2's concrete fix all resolve to **one** defect:

> `_jsonable` dispatches on `isinstance`, not on exact type.

Switch the primitive arm to exact-type dispatch (`type(obj) is ...`) with an
explicit refusal for everything not in the declared wire domain, and all of those
close at once — and the subclass dimension becomes **moot** rather than needing a
new `DIMENSIONS` entry and a new sweep. Prefer that over widening P21 case-by-case:
widening the property leaves the dispatch defect live and asks the property to
enumerate an open set (every subclass of every admitted family), which is the
narrowness shape one level up.

P21 still gains the root **and nested** `IntEnum`/`StrEnum` pairs — but as
regression evidence for a closed domain, not as the mechanism that closes it.

**Named and not taken:** keep `isinstance` and add an ordered enum-refusal branch
*before* the primitive arm. Rejected — it fixes the two enum families and leaves
every other subclass (`class MyInt(int)`, `bytes`/`dict`/`list` subclasses)
reaching the primitive arm, which is the same class recurring. What would flip it:
a consumer in the sweep that legitimately supplies a primitive subclass and cannot
be changed. None appeared in finding 1's consumer enumeration.

## 3. Sweep the newly-found class

The review names one class the plan had not:

> **A precondition enforced at the source rather than at the consumers it names.**

Instance: `_validate_log`'s index-injectivity precondition is enforced at 1 of 2
call sites, so I8's domain shrinks in silence, and all 4 named consumers resolve a
duplicate silently *and disagree with each other about how*.

This is a class, so it gets a sweep before the revision lands: **for every
precondition the module states, enumerate the call sites and the consumers named
in its statement, and record where it is enforced and what each consumer does when
it does not hold.** Report the result even if it is "swept, no others" — that
sentence is the deliverable.

## 4. Contract changes — endorsed

- **C8** (rev 4) stands.
- **C9 added**: for every previously accepted, retained wire value, canonical
  bytes and derived candidate IDs remain byte-identical; otherwise the schema
  version changes and a migration ships. With committed golden vectors over
  canonical bytes, candidate IDs, dependency digests, and log endpoints.
- **C3 joins unit 2's declared dependencies.** §3's "C1 and C5 only" was wrong:
  unit 2's log endpoints are candidate IDs derived through `canonical`.

**Two independent reviewers broke the seam contract in two different ways** — the
reviewer's byte-stability break (an injective re-encoding dangles every
`derive_id` endpoint) and §3a's index-construction break (injectivity enforced at
one of two call sites). Neither was anticipated by C1–C7. Read that as evidence
the **contract was under-specified**, not that either reviewer got lucky, and not
that one break subsumes the other. Both remedies belong in unit 1.

## 5. The rest, briefly

- **F3 (mutant masking).** `observation_digest_first_wins` describes pristine
  behaviour — `setdefault` already keeps the first object for an equal digest. That
  is §2a's shape ("the pristine implementation is the mutant") recurring in your
  own new rows. Replace it with the reviewer's exact edit (dedup by
  `(at, evidence-name-set)` ignoring values, bound to a merge property with equal
  timestamps and differing values). Mark `evidence_gate_type_only`
  `breaks=None` **or** patch every layer needed to expose the behaviour; a mutant
  masked by a second unchanged refusal is not a proof.
- **F4 (instrument scope).** Refusal-site coverage is **control coverage only**,
  never accepted-domain proof — full coverage can coexist with a false C2. Say so
  in the instrument's own output. Exercise `transition`'s undefined-pair branch
  with an invalid state instead of allowlisting it: an allowlist entry claiming
  unreachability is an absence assertion and gets the same treatment as any other.
- **F6.** One vocabulary constant, not two. Either add `evidence_value_type` to
  the test-local `DIMENSIONS`, or move the vocabulary to `resolve.py` and have the
  tests consume `R.DIMENSIONS`. §7's file list said `resolve.py` gains a symbol
  that is defined only in the test module — re-run that one-grep sweep across
  every symbol §7 claims a file gains.
- **F7.** Carry forward a **numbered** round-4 manifest, one row per class, one
  owning unit. Name all seven false annotation entries, not three. Give P20's
  missing refusal oracle and the enumeration-completeness gate an owner.
- **F8.** `PROPERTIES` has **29** entries and `NARROWNESS` matches exactly; the
  reviewer's enumeration omitted P5b. The rest of F8 stands — quote the exact
  commands, and narrow "no external caller exists" to "no in-repository production
  caller matched this search."

## 6. Correction already propagated

The refusal-census correction is committed in the protocol at `4e5c792`: **2**
sites out of scope (`L200 TypeError`, `L2154 SystemExit`), not 1, and the census
had **no category** for the 4 bare re-raises. The headline **28 of 106 in scope**
is intact; the never-fired count is **not** re-measured and must not be re-quoted
as if it were.

> **ERRATUM (same day).** The "no category" half is **false** and is retracted. The
> census output reads `bare re-raise sites (exempt): 4` — line 609 at `31291c2`,
> line 617 at `e6498a7`, verified in the artifact rather than relayed. **2 out of
> scope, not 1** and **28 of 106 in scope** both stand. Corrected in the protocol at
> `2bc3aba`, where the rule it earns is recorded: *before reporting a category absent
> from an instrument's output, quote the output.*
>
> The agent retracted this against itself and was right to. It also noted this was
> the second time it had accused the same instrument of being worse than it is, both
> in the same direction — and the failure was mine to the same degree, because I put
> the unchecked claim into a process document.

## Dispatch

Queued. Send on the next agent completion, to keep concurrency at or below 3:

- `a5c20160832de222f` — family consolidation + gadget-cache fix (running)
- `a4b4d5e56ab5e05c5` — R2 cold measure (running)
- `a45c79733bf11f352` — I2 timing + I5 failure reasons (running)
