# Standardized context schema (`supwngo.context/v1`)

**Date:** 2026-09-24
**Status:** v4 DRAFT — v1, v2 and v3 all REJECTED. v4 stops specifying the
resolver in prose and specifies it as a reference implementation with
executable properties; the normative tables are **generated from that code**.
**Author:** coordinator (Opus 5)
**Base:** `integration/phases-0-4-7-20260923` @ `ef40e93`

## Revision history

- **v1 — REJECTED** by two independent reviewers who converged on the same
  verdict and the same primary fix.
  - Fatal flaw: `ExploitContext` was to be *the* serialized model, with a
    lossless round-trip, without new import edges. The code permits at
    most one of those three.
  - The merge layer — which v1 itself called "the part most likely to be
    got wrong" — was undefined for its own headline use case (7 of 16
    provenance cells missing, including **every** cell where the incoming
    fact is `asserted`) and failed open on the strongest signal while
    failing closed on the weakest.
  - v1 cited the walkthrough engine's `BINARY_SHA256` preflight as
    precedent for refuse-by-default. That preflight **warns and then
    verifies instructions at claimed addresses** — the opposite of what
    v1 proposed. The precedent argues against v1.
- **v2 — REJECTED.** Two of six blockers fixed (two-authorities,
  round-trip); the merge layer was still wrong, and for one root cause:
  `facts` was an object with **one value per key**, yet the rules said
  "different scope → both retained." The structure could not represent
  what the rules required. Consequently the prose was self-contradictory
  and `--resolve=<key>:<provenance>` could not even name one of two
  conflicting `measured` candidates. Also: demoting provenance to express
  applicability "rewrites what happened"; the verification gate was
  undefined for the majority of facts that are not address claims;
  `derived_from` used `@` as a separator when fact keys already contain
  `@`; libc had no identity of its own; `process`/`attempt` scopes had no
  IDs to be checked against.
- **v3 — REJECTED.** The candidate-set structure was accepted. The
  semantics written on top of it were not. Five defects, all of the same
  kind — English that reads as a rule but does not define a function:
  1. **Overlapping merge predicates.** Row 1 ("no candidate with same
     `applies_to` *and* same value → append") and row 3 ("candidate with
     same `applies_to`, different value, higher rank → supersede") both
     fire when the store holds *both* a same-value and a different-value
     candidate for one `applies_to`. The table was a list of hints, not a
     case analysis; its outcome depended on which row a reader checked
     first.
  2. **Dedup ignored provenance.** "Same `applies_to` and same value →
     update `last_seen`, no new candidate" silently collapses a
     `measured` 72 and an `asserted` 72 into one candidate, destroying the
     record of which authority said what — the exact loss v2 was rejected
     for.
  3. **No normative state transition.** `unresolved` appeared in the
     candidate `state` enum, but merge assigned it to *the key*
     ("the key is `unresolved`"), and nothing defined how anything leaves
     that state. Two different state spaces wearing one name.
  4. **Scope ordering undefined.** "narrower scope beats broader"
     presumes a total order over `build|libc_file|host|boot|process|
     attempt` that the document never gave.
  5. **`last_seen` breaks dependency digests.** `derived_from` pinned
     "sha256 of the candidate's canonical form" while merge *mutated
     `last_seen` on that same candidate*. Every re-observation of an
     unchanged fact changed its digest and therefore marked every
     dependent stale. The staleness mechanism would fire constantly and
     be turned off within a day.
- **v4 — this document.** Three rounds of prose produced three rejections
  of the same layer. v4 changes method, not just content: **the resolver
  is the specification.** See "Method".

## Goal

One document that every supwngo command can **write** and **read**, so a
fact learned by one command is reusable by another, and so a human can
supply facts supwngo cannot measure.

```bash
supwngo analyze binary_01 --context-out ctx.json
supwngo --context ctx.json pwn binary_01
```

## Non-goals

- Not a replacement for `core/database.py` (per-machine SQLite cache).
- **Not a serialization of `ExploitContext`.** Explicitly abandoned; see
  "One-directional flow".
- Not a wire protocol.

---

## Method: the normative artifact is code, not prose

v1, v2 and v3 each specified merge and resolution in English and each was
rejected for a defect that was *invisible in English and trivial in code*:
non-disjoint cases, a missing total order, a mutable field inside a digest.
Prose has no totality checker. A fourth prose round is predicted to fail
the same way.

So v4 inverts the artifact relationship:

- **`supwngo/schema/resolve.py` is normative.** The merge decision, the
  provenance order, the scope order, the specificity order, the candidate
  state machine and the digest projection live there as data and pure
  functions.
- **The tables in this document are generated from it.** A committed
  `docs/reference/context-resolution-tables.md` is produced by
  `python -m supwngo.schema.resolve --emit-tables`, and a test asserts the
  committed file is **byte-identical** to freshly generated output. Prose
  cannot drift from code, because prose is no longer hand-written.
- **Totality and determinism are executable properties**, not claims.
  Exhaustive enumeration over the bounded semantic domain, plus a
  **mutation meta-test** that each property actually fails against a
  deliberately broken resolver.

### Methods weighed

**Method A — reference implementation + generated tables + property tests
(CHOSEN).**
The semantics are Python; the tables are output; the guarantees are tests.
- *For:* a non-disjoint case analysis is a failing totality test, not a
  reading comprehension exercise. A missing total order is a failing
  antisymmetry/transitivity test. A mutable field inside the digest is a
  failing digest-stability test. All three v3-class defects become
  mechanically detectable. Reviewers read ~400 lines of pure functions
  with no I/O instead of 300 lines of English.
- *Against:* the reviewable artifact is code, so a reviewer who only reads
  the plan reviews a summary. Mitigated by inlining the resolver into the
  review prompt alongside the plan, and by the generated tables being the
  human-readable face of it.

**Method B — declarative rule table in JSON, resolver is a generic
interpreter (NOT TAKEN).**
Push all semantics into a data file; ship a small interpreter.
- *For:* the normative artifact is literally the table — no generation
  step, therefore no drift at all, and it is language-agnostic if supwngo
  ever grows a non-Python consumer.
- *Against:* the rules are not per-cell lookups. Maximal-element
  computation over a **partial** order, staleness closure over a DAG, and
  the digest projection cannot be expressed as table rows without an
  embedded expression mini-language — which relocates the ambiguity into
  an untested interpreter, a strictly worse place than Python with tests.
- *What would flip it:* if resolution were ever reduced to pure per-cell
  lookups with no graph traversal and no partial order, B becomes
  strictly better and A's generation step becomes pure overhead.

**Method C — formal model (TLA+ / Alloy) as the spec (NOT TAKEN).**
- *For:* exhaustive guarantees over small scopes, including properties
  exhaustive Python enumeration cannot reach.
- *Against:* the model is not the shipped code, so it adds a second
  authority that can diverge — the same two-authorities defect v2 was
  rejected for, one level up. Nobody in-tree can run it in CI.
- *What would flip it:* a second implementation (a Rust or Go consumer of
  the same documents) needing an arbiter that is neither implementation.

---

## Correction to this plan's own text (v3 was factually wrong)

v3 described the `DetailedProtections.to_dict()` bug as "adds ~20 fields …
emits 6". **The fix has landed at `ef40e93` and the numbers were wrong.**
Introspection at `ef40e93`:

| quantity | value |
|---|---|
| `Protections` declared fields | 8 |
| `Protections.to_dict()` emits | 6 |
| `DetailedProtections` declared fields | **22** |
| fields `DetailedProtections` adds over `Protections` | **14** |
| fields missing from the old serializer | **16** |
| `DetailedProtections.to_dict()` now emits | **16** |
| declared but deliberately **not** emitted (`_UNMEASURED`) | **6** |

The 6 in `_UNMEASURED` are `stack_clash_protection`, `safe_stack`, `cfi`,
`shadow_stack`, `rpath`, `runpath`. **`analyze()` never populates them.**
The fix declares them and deliberately does not emit them, because an
introspective serializer cannot distinguish *measured false* from *never
measured*, and would publish `cfi: false` that nothing computed —
indistinguishable from a measured `nx: false`.

**This is load-bearing for the provenance model, and v4 adopts it as an
invariant:**

> **Absent must not be representable as false.** A fact that was never
> measured has **no candidate**. `resolve()` raises `FactUnavailable`. No
> code path returns a type default for a missing fact, and no adapter may
> emit a fact key from a dataclass default.

Enforced three ways:
1. The protections adapter enumerates an explicit key list; it never
   iterates `dataclasses.fields()`. A test asserts the adapter's key set
   equals `fields(DetailedProtections) - _UNMEASURED`, so adding a
   measured field without adapting it fails, and adding an unmeasured
   field without declaring it fails. (This is the existing
   `tests/test_protections_to_dict.py` contract, extended to the adapter.)
2. `resolve()` has **no default parameter**. There is no
   `resolve(key, default=…)` overload to reach for. Callers that can
   proceed without a fact call `try_resolve()`, which returns an explicit
   `Absent` sentinel object that is not falsey-equivalent to `False` or
   `0` and raises `TypeError` on `bool()`.
3. A property test (P12) asserts that for every key in the registry, an
   empty candidate list yields `FactUnavailable` and never a value.

---

## Why this is not additive

The current state is not "no schema" but **contradictory schemas**:

- `analyze` emits two different shapes for one run — the `--json` stdout
  form flattens `dangerous_functions`/`input_sources`
  (`cli.py:83-90`), the file it writes nests under `analysis`
  (`cli.py:115-126`). It writes that file unconditionally, even in
  `--json` mode.
- **27** `to_dict` methods across 17 modules, no shared envelope
  (`handoff.py` alone has 4 at `:48,:71,:99,:160`).
- `-o` means output *directory* on `analyze`/`fuzz`, output *file* on
  `triage`/`rop`/`exploit`.

## Prerequisites

1. **`DetailedProtections.to_dict()` — DONE**, `ef40e93`. No longer a
   prerequisite; now an input (see "Correction" above).
2. `feat/walkthrough-engine-20260923` — provides `Confidence`
   (`walkthrough/model.py:124-143`), the address-verification preflight
   (`walkthrough/common.py:384-387`), the flag filter
   (`walkthrough/facts.py:14-20`) and `explain`. `explain` **is** already
   registered at `ef40e93` (32 commands, see "Command tiers"), so the
   provenance vocabulary must be re-derived from `model.Confidence` **as
   merged**, not as remembered.

Phase 1 of the implementation (`supwngo/schema/resolve.py` + its tests)
has **no dependency on (2)**: it imports nothing from supwngo and is pure.
That is deliberate — it lets the contested layer be built and reviewed
independently of a branch that has not landed.

## Decisions taken

1. **`--context` is long-form only. No `-c`.** Operator-confirmed intent
   was a dedicated flag; review found the short form unsafe. `exploit`'s
   `-c/--crash` is `type=click.Path(exists=True)` (`cli.py:241`), so
   `supwngo exploit -c ctx.json ./t` — which reads naturally and users
   *will* type — silently accepts the context document **as a crash
   input** (`cli.py:275-277`) and never loads it. `--context-out PATH`
   writes. `-o` is untouched everywhere.
   - Mitigation regardless: `exploit --crash` sniffs for
     `schema_version: supwngo.context/…` and errors out.
2. **All commands classified up front** (operator chose full coverage),
   but as three explicit tiers rather than uniform conformance — see
   "Command tiers". `producer`/`consumer`/`exempt`, with a literal table
   of all **32** registrations and a one-line reason for each exemption.

---

## Design

### One-directional flow (unchanged from v3; accepted)

```
command results ──adapters──▶  facts  ◀──hand-authoring── human
                               │  ▲
                   evidence    │  │ projection (read-only)
                      ▼        │  ▼
                   blocks      └─▶ ExploitContext (in-memory, never written back)
```

- **`facts` is the only normative store.** A consumer reads `facts` and
  never a block.
- **`blocks` are non-normative evidence**, append-only, each carrying
  `produces: ["<fact_key>", …]`.
- **`ExploitContext` is a projection.** A loader populates only the fields
  it can. There is no `to_context_doc()`. It is never serialized back over
  facts.

Forced by the code, not preference:

- `core/context.py:16-28` forbids `core/` importing `supwngo.exploit.*`,
  and types two fields `Any` for exactly that reason
  (`verification_level` at `:256-261`, `attempts` at `:263-267`).
  A `from_context_doc()` must *construct* `AttemptRecord` and
  `VerificationLevel`, i.e. add the forbidden edge. Putting the model in
  `supwngo/schema/` — which may import from `exploit/` — removes the
  conflict.
- **Rehydration mutates what it rehydrates.** `LibcInfo.__post_init__`
  calls `_analyze_libc()` whenever `path` is set (`context.py:83-85`),
  recomputing `system_offset`/`binsh_offset`/hooks from the *local* libc —
  overwriting even a human's `asserted` values. `add_leak()`
  (`context.py:311-318`) re-triggers base derivation. `find_one_gadgets`
  **appends without clearing** (`context.py:130-133`), so each round trip
  lengthens `one_gadgets`. Round-tripping is not merely lossy, it is
  non-idempotent and monotonically corrupting.
- **Existing serializers are destructively lossy by design.**
  `AttemptRecord.to_dict()` reduces `payload: bytes` to
  `payload_len: int` (`contracts.py:104`) and `str()`s non-scalar
  `partial_artifacts` (`:106`). `Vulnerability.to_dict()` drops
  `controllable_input`, `primitives`, `crash`, `details`
  (`detector.py:91-101`). Adapters must read the **live objects**, not
  these `to_dict()`s.
- **Model ambiguity a schema cannot fix:** `ExploitContext.offset`
  (`:250`) and `stack.return_address_offset` (`:154`) are documented as
  deliberately distinct (`:244-249`). Resolve to one field with a stated
  meaning before mapping either to a fact key.

### Facts are candidate sets (unchanged from v3; accepted)

```json
"facts": {
  "stack.return_offset": {
    "candidates": [
      {
        "id": "f_7c1a",
        "value": 72,
        "provenance": "measured",
        "applies_to": {
          "identity": "t_main@sha256:04aa1a…",
          "scope": "build",
          "conditions": {"input_method": "stdin"}
        },
        "verification": {"class": "static_offset", "state": "unverifiable",
                         "reason": "not an instruction-address claim"},
        "derived_from": [],
        "method": "gdb cyclic-pattern probe",
        "evidence": {"rsp": 6748010543161397363, "cyclic_find": 72},
        "by": "supwngo offset", "at": "<ISO-8601>",
        "state": "active",
        "observations": 1, "last_observed_at": "<ISO-8601>"
      }
    ]
  },
  "resolutions": [ … ]
}
```

Three structural changes from v3, each fixing one numbered defect:

- **`resolution` moves out of the fact and up to a document-level
  `resolutions[]`.** v3 stored `{"selected": …, "rule": …}` inside the
  fact, which made a *derived, context-dependent* answer look like stored
  state and is why defect 3 could exist. Selection is computed at read
  time from the invocation's context; the only thing persisted is an
  **operator pin**, which is a deliberate human act and belongs in an
  audit list, not in the fact. (Fixes defect 3.)
- **`state` ∈ `active | superseded | retracted`.** `unresolved` is
  removed: it was never a property of a candidate. Unresolvedness is an
  *outcome of `resolve()`* — the `FactUnresolved` exception. (Fixes
  defect 3.)
- **`observations` / `last_observed_at` are declared mutable and are
  excluded from the digest projection.** (Fixes defect 5.)

`provenance` ∈ `measured | derived | assumed | asserted | unknown`.
`unknown` is load-bearing and carried over from
`walkthrough/model.py:124-143`, where it requires the fact to name a
resolving step; here it requires `resolved_by`.

`scope` ∈ `build | libc_file | host | boot | process | attempt` — validity
lifetime, separate from provenance. `process`/`attempt`-scoped candidates
are **refused on reuse in a new run**, regardless of digest.

`depends_on` ∈ `binary_bytes | binary_symbols | libc_file | runtime`.

`conditions` makes jointly-valid facts explicit. A bare
`stack.return_offset: 72` is ambiguous because `offset --input-method
[stdin|argv|file]` (`cli.py:768`) yields different results per method and
`OffsetResult` (`offset_finder.py:28-42`) does not record which it used.

`confidence` is removed. v1 carried both `provenance` and `confidence` as
independent trust axes but merged only on provenance, so a `measured` fact
at 0.2 would supersede one at 0.99. Where a numeric score genuinely exists
(`Vulnerability.confidence`, `detector.py:75`) it lives in the evidence
block, not in resolution logic.

---

## The resolver (normative: `supwngo/schema/resolve.py`)

This section describes the reference implementation. **The generated
tables in `docs/reference/context-resolution-tables.md` are the normative
statement of every order and every case split**; what follows is the
design rationale a reviewer needs in order to judge the code.

The module is **pure**: stdlib only, no supwngo imports, no filesystem,
no clock, no randomness. Everything it needs is passed in. That is what
makes exhaustive property testing possible and what lets Phase 1 proceed
without the walkthrough branch.

### Merge is three disjoint cases and never supersedes

v3's merge both deduped and superseded, and its predicates overlapped.
v4 removes supersession from merge entirely:

```python
def merge(store: FactStore, incoming: Candidate) -> MergeDecision
```

`MergeDecision` is an enum with exactly three members, decided in this
order, on the **dedup key**:

```python
def dedup_key(c): return (c.key, canonical(c.value),
                          applies_to_digest(c.applies_to), c.provenance)
```

| order | predicate | decision |
|---|---|---|
| 1 | `incoming` fails the key's declared type/shape | `REJECTED` — raises `SchemaError`, store unchanged |
| 2 | some `c ∈ store[key]` with `dedup_key(c) == dedup_key(incoming)` | `DEDUPED` — `c.observations += 1`, `c.last_observed_at` updated, no new candidate |
| 3 | otherwise | `APPENDED` — added with `state=ACTIVE` |

The cases are disjoint by construction (1 is a guard, 2 and 3 are `P` and
`¬P` on a single predicate) and exhaustive. There is no fourth outcome to
forget. (Fixes defect 1.)

`dedup_key` includes `provenance`, so a `measured` 72 and an `asserted` 72
are **two candidates**, not one. They do not conflict — see the
value-agreement rule — but the record of who said what survives.
(Fixes defect 2.)

Supersession is a separate, explicit, audited operation:

```python
def supersede(store, candidate_id, by_candidate_id, reason) -> None
def retract(store, candidate_id, reason) -> None
```

**Consequence — merge is commutative up to dedup.** Merging a batch in any
order yields the same candidate set and the same document digest. This is
property P2, and it is the structural reason v3's order-dependent table
cannot recur.

### Candidate state machine (generated table)

```
          append   supersede   retract
  (none)  ACTIVE   REFUSED     REFUSED
  ACTIVE  REFUSED  SUPERSEDED  RETRACTED
SUPERSEDED REFUSED REFUSED     REFUSED
RETRACTED  REFUSED REFUSED     REFUSED
```

Terminal states are terminal — there is no resurrection, because a
resurrected candidate would invalidate every `derived_from` digest taken
while it was dead. `REFUSED` raises `StateTransitionError`; it is never a
silent no-op. Property P11 asserts the table is **total** over
`(state, event)` — a new state or event that is not classified fails the
test rather than falling through. (Fixes defect 3.)

### Provenance is a partial order, generated from 5 covering edges

The requirement "ordinary `asserted` must not beat contradictory
`measured`" is not expressible as a rank, because a rank is a total order
and a total order always picks a winner. It is expressible as
**incomparability**. So provenance precedence is declared as a DAG of
covering relations and the 25-cell table is computed by transitive
closure:

```python
PROVENANCE_EDGES = (            # (dominates, dominated)
    ("measured",  "derived"),
    ("derived",   "assumed"),
    ("asserted",  "assumed"),
    ("assumed",   "unknown"),
)
```

The consequences, all generated rather than asserted:

- `measured ≻ derived ≻ assumed ≻ unknown`
- `asserted ≻ assumed ≻ unknown`
- **`measured ∥ asserted`** and **`derived ∥ asserted`** — incomparable.
  A human assertion contradicting a machine measurement does **not** win
  and does **not** lose; it makes the key `FactUnresolved` and demands an
  explicit pin. This is the v4 encoding of the operator's rule.

Transitivity holds by construction (closure of a DAG). Property P4
asserts irreflexivity, antisymmetry, transitivity, symmetry of
incomparability, and pins `compare("measured","asserted") ==
INCOMPARABLE` as a named regression.

**Cost, stated honestly:** `asserted` can no longer override anything
supwngo measured without a pin. That is intended — `asserted` exists for
facts nothing else produced, where there is no competing candidate and
resolution succeeds immediately. Where it *does* contradict, the extra
step is one `--pin` and a permanent audit record.

### Scope specificity is a total order by validity lifetime

v3 said "narrower beats broader" without an order. v4 declares one, as an
ordered tuple, shortest-lived last:

```python
SCOPE_ORDER = ("build", "libc_file", "host", "boot", "process", "attempt")
```

Read as strictly shrinking validity: `build` holds for any instance of
these bytes; `libc_file` only while bound to that libc artifact; `host`
only on this host; `boot` until reboot; `process` until that process
exits; `attempt` only within that attempt. A more specific scope was
observed under circumstances closer to now, so it is preferred **after**
applicability filtering has already discarded expired scopes.

Property P5 asserts it is a total order and that every member of the
`scope` enum appears in it exactly once — so adding a scope without
placing it fails the build.

*Option not taken:* a partial order (`libc_file` and `host` arguably lie
on different axes rather than nesting). Rejected because it converts a
common, harmless case into a refusal for no safety gain. **What would flip
it:** a demonstrated case where preferring a `host`-scoped candidate over
a `libc_file`-scoped one for the same key produces a wrong address.

### Specificity order over candidates, and maximal elements

```python
def compare_specificity(a, b) -> Ordering   # GREATER|LESS|EQUAL|INCOMPARABLE
```

Lexicographic over four components, halting on the first that is not
`EQUAL`:

1. identity-bound (1) beats identity-agnostic (0) — total
2. `SCOPE_ORDER` index — total
3. count of matched `conditions` — total
4. provenance — **partial** (above)

**Time is deliberately not a component.** v3 ended its ordering with
"then newest `at`", which (a) is non-deterministic under equal or
skewed timestamps and (b) silently resolves exactly the
measured-vs-asserted conflict the operator said must not resolve
silently. Two candidates that tie through all four components are
genuinely unresolved.

Because component 4 is partial, the composition is a partial order, so
selection uses **maximal elements**, not "sort and take the first":

```python
M = {c ∈ pool : ¬∃ c' ∈ pool with compare_specificity(c', c) is GREATER}
```

Maximality is order-independent, which is why P7 (determinism under
permutation) can hold. A lexicographic product of transitive component
orders with halt-on-incomparable is itself transitive and antisymmetric;
P5 checks this over enumerated candidates rather than trusting the
argument.

### `resolve()` is total: one return type, four named refusals

```python
def resolve(store, key, ctx) -> Selected        # never a bare value
def try_resolve(store, key, ctx) -> Selected | Absent
```

1. `pool = [c for c in store[key] if c.state is ACTIVE]`
2. `pool = [c for c in pool if applicable(c, ctx)]` — pure predicate over
   identity match, scope liveness against `ctx.run_id/process_id/
   attempt_id`, and `conditions` compatibility. A candidate bound to
   another identity is **not demoted** — its provenance is never
   rewritten (the v2 finding); it is simply inapplicable here.
3. If `ctx.pins` holds a pin for `key`: the pinned id must be in `pool`,
   else `PinInapplicable`. A pin is the **only** thing that selects
   against the specificity order.
4. `M = maximal(pool)`.
   - `M` empty → `FactUnavailable`
   - all values in `M` canonically equal → `Selected`, rule
     `unique_maximal` if `|M| == 1` else `agreed_value`, selecting
     `min(M, key=id)` (total, deterministic)
   - values disagree → `FactUnresolved(M)`
5. Selected candidate stale → `FactStale`.

The **value-agreement rule in 4** is new in v4 and is what makes
provenance-aware dedup (defect 2's fix) usable: a `measured` 72 and an
`asserted` 72 are incomparable and both maximal, but they *agree*, so
resolution succeeds and records that two authorities concurred. Conflict
means disagreement about the value, never disagreement about provenance.

Every exit is one `Selected` or one of five declared exceptions —
`FactUnavailable`, `FactUnresolved`, `FactStale`, `PinInapplicable`,
`SchemaError`. Property P6 asserts nothing else ever escapes, for any
enumerated input. None is ever swallowed into a default.

`--pin <key>=<candidate_id>` replaces v3's `--resolve`, and selects by
**candidate id** (v2's `--resolve=<key>:measured` could not distinguish
two conflicting `measured` candidates). It appends a `resolutions[]`
record — who pinned, when, which candidates lost — and invalidates the
dependent closure of the rejected candidates.

### Digest projection: mutable fields are declared and excluded

Defect 5's fix is a single explicit partition of the candidate's fields:

```python
MUTABLE_FIELDS  = frozenset({"observations", "last_observed_at",
                             "state", "stale"})
DIGEST_FIELDS   = ALL_CANDIDATE_FIELDS - MUTABLE_FIELDS
```

`candidate_digest(c) = sha256(canonical_json(project(c, DIGEST_FIELDS)))`.

- `observations` / `last_observed_at` move on every re-observation — the
  v3 bug — and are excluded.
- `state` is excluded too, and for a subtler reason: if superseding a
  candidate changed its digest, then every dependent's recorded
  `derived_from[].digest` would stop matching, making a legitimate
  supersession indistinguishable from tampering. Supersession invalidates
  dependents via the **event**, not via a digest change.

Property P10 is the executable form: **mutating any field in
`MUTABLE_FIELDS` must not change the digest; mutating any field not in it
must change the digest.** The test iterates the real field list, so a
field classified as neither fails — which is the anti-vacuity guard this
project's standing rule demands.

### Dependencies and staleness

`derived_from` holds structured references, `[{"id": "f_7c1a", "digest":
"<sha256 of the DIGEST_FIELDS projection>"}]` — not strings (v2 used `@`
as a separator when fact keys already contain `@`).

A candidate is **stale** iff any referenced source is missing, has a
digest mismatch, is not `ACTIVE`, or is itself stale. Closure uses a
visited set and therefore terminates. Cycles and dangling references are
rejected **at validation time, transactionally**, so an invalid graph is
never persisted. Consuming a stale candidate is `FactStale`, a hard error
— without it, a corrected `puts` leak leaves `libc.base` silently wrong
and every ret2libc address built from it wrong.

### Verification is a registry, and may return "unverifiable"

Every fact key declares a verification class; each class has a verifier
returning `verified | failed | unverifiable`:

| class | verifier | example keys |
|---|---|---|
| `instruction_at` | disassemble and compare mnemonics | `gadget.pop_rdi`, `plt.system` |
| `symbol_addr` | symbol table lookup | `sym.win` |
| `static_offset` | none available | `stack.return_offset` |
| `libc_offset` | resolve against the bound libc artifact | `libc.system_offset` |
| `runtime` | never verifiable statically | `libc.base`, `leak.puts` |

**Missing tooling yields `unverifiable`, never `verified`.**
`unverifiable` is not a pass — a safety-critical consumer refuses it
unless an explicit, per-key, recorded override exists. `failed` refuses
always. This is what makes the identity gate implementable, and it means
the gate degrades honestly on a machine without a disassembler rather
than pretending to have checked.

### Identity: verify, don't just hash

- Record `sha256` **and `build_id`** (`.note.gnu.build-id`), which
  survives `strip`.
- On read, a digest mismatch **warns**, then supwngo **verifies a sample
  of `binary_bytes` facts against the loaded binary**. Refuse on
  **verification failure**, which actually predicts wrongness, rather
  than on a hash difference. `walkthrough/common.py:384-387` already
  implements this check.
- The hash gate was both over- and under-restrictive: **over** —
  `exploit -r host:port` (`cli.py:242,264-266`) and `solve --remote`
  (`:2720`) load a local *copy*; stripping or a `.comment` change alters
  sha256 while every gadget and offset stays correct. **under** — a
  matching sha256 says nothing about the host's libc, yet
  `libc.base`/`system_offset`/one-gadgets are the facts most likely
  wrong and most catastrophic.
- `--target-identity=sha256|build-id|none` replaces v1's blanket
  `--context-mismatch=allow`. `none` permits *selection* of candidates
  bound to a different identity and records an `identity_override` in
  `resolutions[]`; it does **not** disable verification, and
  `runtime`-scoped candidates remain refused.
- `Binary.__post_init__` hashes only `if self.path.exists()`
  (`core/binary.py:137-142`), so a doc can carry `sha256: ""`. **Refuse
  to write** a doc with an empty digest.

### Identities are first-class, and there is more than one

```json
"identities": {
  "t_main":  {"role": "target", "sha256": "…", "build_id": "…",
              "format": "elf", "elf_type": "ET_DYN", "linkage": "dynamic",
              "pie": true, "os_abi": "linux", "arch": "amd64", "bits": 64},
  "l_glibc": {"role": "libc", "sha256": "…", "build_id": "…",
              "version": "2.39"},
  "r_prod":  {"role": "remote", "endpoint": "host:1337"}
},
"runs": [{"run_id": "r_01", "at": "…", "process_ids": ["p_01"]}]
```

- Every candidate's `applies_to.identity` names one of these, bound to
  **the identity actually observed**, never to a stale envelope value.
- **libc gets its own identity**, because `libc.system_offset`,
  one-gadgets and every derived base bind to the libc, not the target.
- `process`/`attempt` scopes reference `run_id`/`process_id`/
  `attempt_id`, which is what makes "refused on reuse in a new run"
  implementable. A new `run_id` per CLI invocation; a new `process_id`
  per spawned or reconnected target process.
- `diff` and `batch` become representable: multiple `target`-role
  identities, facts bound per identity.

`exec|dyn|static` (v1) conflated two dimensions — PIE is normally
`ET_DYN`. Split into `format`, `elf_type`, `linkage`, `pie`, `os_abi`,
`build_id`. `Binary` has **no `to_dict()`**, so `target` needs a new
producer.

### Secrets and flags

`ExploitContext.captured_flag` (`:254`) and `VerificationReceipt.flag`
(`contracts.py:133`) must **not** be serialized by default. The
walkthrough engine deliberately filters flag-shaped strings so its
artifact cannot be used to skip the exercise
(`walkthrough/facts.py:14-20,55-62`); writing flags here would reverse
that control. Reuse its `_is_flagish`; gate on `--context-include-flags`.

`method`/`evidence` carry structured fields, not verbatim command lines
(usernames, tokens, remote endpoints). `target.path` and
`artifacts[].path` are **relative to the document**, with `--binary`
overriding at read time. Provenance commands are never executed.

### Encodings (pinned, because "canonical" is meaningless otherwise)

- bytes → base64 with a `b64:` prefix (never `default=str`, which yields
  an irreversible repr; today's habit at `cli.py:126,1601,1761,1765,…`).
- sets → sorted arrays (`profile_bad_bytes`, `context.py:280`).
- addresses → unsigned int; the schema **rejects** hex strings. In-tree is
  currently inconsistent (`hex()` at `detector.py:96`,
  `offset_finder.py:58-59`, `contracts.py:105`; raw ints elsewhere).
- canonical form: RFC 8785-style — `sort_keys=True`,
  `separators=(",",":")`, `ensure_ascii=False`, integers only where
  integral — plus a separate pretty presentation form that is explicitly
  **not** the digest input.
- YAML: `safe_load` only, duplicate keys rejected, anchors/aliases
  rejected, size/depth limits. YAML 1.1 parses `0x401234` as an int,
  which is why address encoding must be pinned for read parity.

### Persistence

`--context-out` defaults to the `--context` path (in-place accumulate).

Locking `ctx.json` itself does not serialize writers, because the file is
then *replaced* — the lock is held on an inode that no longer backs the
path. The lock lives on a **stable sidecar**, `ctx.json.lock`, and is held
across the whole read → merge → validate → temp-write → `fsync` →
`os.replace()` → directory `fsync` sequence. That is what prevents lost
read-modify-write updates, which atomic replacement alone does not.

**History stays inside the document.** Candidates that are `superseded`
or `retracted` remain in the candidate list with that state; a
`--context-prune` subcommand compacts them on request, so growth is
bounded by an explicit operator action rather than by a silent cap.

Long-running commands (`fuzz -t 3600`, `cli.py:135`) checkpoint
periodically so a killed campaign still contributes.

### Command tiers

Three tiers, with a literal table of all **32** `@cli.command()`
registrations at `ef40e93` (v3 said 31; verified by
`len(cli.commands) == 32`). Concrete exemptions:

- *No target*: `version` (`:1401`), `cyclic` (`:888`), `cyclic-find`
  (`:899` — it produces an offset with no binary, which would manufacture
  the exact unanchored-fact footgun this plan exists to prevent),
  `libc-id` (`:567`).
- *Target is not the binary*: `onegadget <libc>` (`:826`),
  `source <tree>` (`:1177`), `kernel <module>` (`:1295`).
- *Not one target*: `diff <b1> <b2>` (`:1698`), `batch <dir>` (`:924`).
  These need `targets[]` keyed by ID, or stay exempt.
- *Argument-shape traps*: `triage <crash_dir> <binary>` (`:198`) — the
  binary is the **second** positional, so any decorator assuming "first
  argument is the target" is wrong. The decorator therefore takes an
  explicit **target resolver per command**, never positional inference.

Roughly 25 of 32 commands never build an `ExploitContext` at all — a
further argument for the projection model.

---

## Files touched

**Phase 1 — the contested layer, reviewable in isolation:**

- `supwngo/schema/__init__.py`, `supwngo/schema/resolve.py` (new; pure
  stdlib, no supwngo imports).
- `docs/reference/context-resolution-tables.md` (new; **generated**, never
  hand-edited).
- `tests/test_context_resolve_properties.py` (new; properties + the
  mutation meta-test).
- `tests/test_context_resolution_tables.py` (new; byte-gate on the
  generated file).

**Phase 2 — the document:**

- `supwngo/schema/context_v1.py`, `supwngo/schema/context-v1.json` (new).
- `supwngo/core/context.py` — projection loader only; **no**
  `to_context_doc`.
- New non-lossy adapters for `AttemptRecord`, `Vulnerability`,
  `DetailedProtections` (explicit key list, `_UNMEASURED` never emitted),
  plus a `target` producer.
- `setup.py` / `pyproject.toml` / `MANIFEST.in` — `jsonschema>=4` in
  install_requires; `schema/*.json` in `package_data` (currently only
  `payloads/templates/*.py` and `data/*.json`, `setup.py:74-79`, so the
  schema would be **absent from an installed wheel** and validation would
  crash for every pip user).
- `tests/test_context_schema.py`.

**Phase 3 — the CLI surface:**

- `supwngo/cli.py` — `--context`, `--context-out`, `--pin`,
  `--target-identity`, per-command target resolvers.
- `tests/test_context_conformance.py`.

`CHANGELOG.md` under `[Unreleased]` in the same commit as each
user-visible phase.

---

## Test strategy

### Properties (Phase 1; the gate this plan rests on)

`hypothesis` is **not installed** and is deliberately not added. The
semantic domain is small and bounded — 5 provenances × 6 scopes × a
handful of identities, condition sets and values — so the properties are
checked by **exhaustive enumeration**, which is stronger than sampling and
fully reproducible.

| # | property | form |
|---|---|---|
| P1 | **merge totality** | for every (store, incoming) in the enumeration, `merge` returns exactly one `MergeDecision` or raises `SchemaError`; no other exception escapes |
| P2 | **merge determinism** | for every batch and **every permutation**, the resulting candidate set (by `dedup_key`) and the document digest are identical |
| P3 | merge idempotence | merging the same candidate twice == once, plus `observations == 2` |
| P4 | **provenance is a strict partial order** | irreflexive, antisymmetric, transitive, incomparability symmetric; pins `measured ∥ asserted` |
| P5 | **specificity is a strict partial order** | over enumerated candidates; `SCOPE_ORDER` is a total order covering the enum exactly once |
| P6 | **resolve totality** | every call returns `Selected` or raises one of the five declared exceptions; nothing else escapes |
| P7 | **resolve determinism** | result invariant under permutation of the candidate list |
| P8 | resolve never invents | the selected candidate is an element of the input pool, `ACTIVE`, and applicable |
| P9 | asserted never silently beats measured | contradictory equally-applicable pair → `FactUnresolved`; with a pin → the pinned candidate |
| P10 | **digest stability** | mutating any `MUTABLE_FIELDS` member does not change the digest; mutating any other field does; every real field is in exactly one partition |
| P11 | **state machine totality** | every `(state, event)` pair has a defined outcome; terminal states refuse every event |
| P12 | **absent is not false** | for every registry key, an empty candidate list yields `FactUnavailable`; no path returns a type default; `bool(Absent)` raises |

### The mutation meta-test — this is not optional

This project has five recorded instances of a validation step that could
not fail (including a probe driver that omitted the argument it was
validating, and a test asserting `min(a,b) == expected`). So each property
ships with a **named mutant** — a deliberately broken resolver — and a
meta-test asserts the property **fails** against it:

| mutant | breaks |
|---|---|
| `merge_supersedes_on_rank` (restores v3 defect 1) | P1/P2 |
| `dedup_ignores_provenance` (restores v3 defect 2) | P2/P9 |
| `state_allows_resurrection` | P11 |
| `scope_order_missing_member` | P5 |
| `digest_includes_last_observed_at` (restores v3 defect 5) | P10 |
| `specificity_breaks_ties_by_time` (restores v3's `newest at`) | P7/P9 |
| `provenance_total_rank` (asserted > measured) | P4/P9 |
| `resolve_returns_default_on_empty` | P6/P12 |

The meta-test **fails if a mutant passes its property** — i.e. it proves
the property has teeth. The mutant list is the artifact a reviewer diffs:
every mutant is a defect this plan or an earlier round actually shipped.

### Document-level tests (Phase 2)

The v1 "byte-identical round trip" assertion is unachievable and is
replaced by three that are:

1. **Fixpoint stability:** `dump(load(dump(load(d)))) == dump(load(d))`.
   Catches non-idempotent rehydration.
2. **Semantic equality modulo a declared volatile set** (`updated`,
   `last_observed_at`, `runs[].at`, `receipt.verified_at`), the exclusion
   list living in the test so it shows up in diffs. `at` is an
   *observation* time and is never refreshed, so it is not volatile.
3. **No-silent-drop:** against a golden maximally-populated document,
   every JSON pointer in the input is present in the output. The
   `KNOWN_LOSSY` allowlist is restricted to fields explicitly deprecated
   with a migration rule; **unknown fields must round-trip unchanged**.

Plus: dependency-graph cycle and dangling-reference rejection at
validation; verifier registry per class (missing tooling →
`unverifiable`, refused by a safety-critical consumer; `failed` always
refuses); identity behaviour (mismatch warns, verification failure
refuses, `process`-scoped refused in a new run, `--target-identity=none`
records the override and still refuses `runtime`); secret redaction;
YAML/JSON parity including `0x401234` vs `4198964`; atomicity under
interrupt and concurrent writers; and packaging (schema loads via
`importlib.resources` from an installed wheel).

### Conformance tests (Phase 3)

- **Static conformance** over `cli.commands`: every one of the 32
  commands is either in the exemption allowlist **or** accepts both
  flags. v1's test was vacuous — a new command omitting the decorator
  simply wasn't in the parametrization and passed. Driving it from
  `cli.commands` and requiring exhaustive classification is what fixes
  that; the allowlist is the artifact a reviewer diffs.
- **Executed conformance** on `tests/` fixtures, marked
  `@pytest.mark.integration`, because a real sweep needs AFL++, angr,
  Ghidra (`cli.py:1771`), external SAST (`:1171-1173`) and **network
  access to libc.rip** (`remote/libc_db.py`).
- **Flag misplacement:** `supwngo exploit --crash ctx.json ./t` errors
  rather than treating the document as crash bytes.

---

## Risks

- **The resolver is now the spec, so resolver review quality is the
  project's risk.** Mitigated by the mutation meta-test (a reviewer can
  check that each historical defect is represented) and by the generated
  tables being diffable.
- **Generated-table byte gate can rot.** If the generator's formatting
  changes, an unrelated commit fails the gate. Accepted: a noisy gate is
  better than silent prose drift, and the fix is one regeneration
  command. The gate compares bytes, not a parse, on purpose — parser-based
  gates in this org have been downgraded to byte snapshots for exactly
  this reason.
- **`asserted` is weaker than operators may expect.** Contradicting a
  measurement now requires `--pin`. Documented in the CLI help text and
  in the error message of `FactUnresolved`, which names the pin command
  to run.
- **Walkthrough branch unmerged.** Phase 1 is independent of it by
  construction; Phases 2–3 are not, and the provenance vocabulary must be
  re-derived from `model.Confidence` as merged.
- **`cli.py` is ~2,900 lines with concurrent editors.** Phase 3 starts
  after the walkthrough CLI commit lands.
- **Real unit of work is depth, not breadth** — v1 claimed otherwise.
  `AttemptRecord`, `Vulnerability` and `DetailedProtections` each need a
  *new* non-lossy serializer. Sequence: resolver, then envelope + `facts`
  + 3 blocks on the core path, then widen.
- **Breaking consumers** of today's ad-hoc JSON: `--legacy-json` on the
  commands CLAUDE.md documents (`analyze`, `fuzz`, `triage`, `exploit`,
  `rop`, `symbolic`, `libc-id`), byte-identical to today, with a stated
  deprecation horizon.
- **Forward compatibility:** refuse unknown major `schema_version`;
  warn-and-proceed on a newer `tool_version`; preserve unknown fields
  without consuming them.
- **Diagnostics must go to stderr.** 19 commands print JSON to stdout via
  `console.print_json` (`cli.py:88,733,792,850,1116,…`); a warning through
  the same `console` makes stdout unparseable. Conflicts additionally
  appear as a machine-readable `conflicts[]` inside the payload.
