"""Executable properties for :mod:`supwngo.schema.resolve`.

Three prose revisions of these semantics were rejected for defects that prose
cannot check: non-disjoint case analyses, a comparison relation with no declared
order, a mutable field inside a content digest.  So totality and determinism are
asserted here instead, by **exhaustive enumeration over a declared bound**, and
every property is paired with a named mutant in
:mod:`supwngo.schema.mutants` that it must be seen to fail against.

`hypothesis` is not installed and is deliberately not added: the semantic domain
is small enough to enumerate completely, which is stronger than sampling and
fully reproducible.  The bounds are the constants below, and
:func:`test_enumeration_bounds_are_reported` prints the realised case counts so
the bound is observable rather than claimed.

Every property goes through the module object ``R`` rather than importing names
directly, so a mutant that rebinds ``R.merge`` genuinely changes what the
property exercises.
"""

from __future__ import annotations

import dataclasses
import inspect
import itertools
import pathlib
from typing import Any, Dict, List, Sequence, Tuple

import pytest
from _pytest.outcomes import Failed as _PytestFailed

from supwngo.schema import mutants as M
from supwngo.schema import resolve as R

# ---------------------------------------------------------------------------
# Declared enumeration bounds (round-1 finding 12: "exhaustive" needs a bound)
# ---------------------------------------------------------------------------

PROVENANCES = tuple(R.Provenance)                    # all 5
SCOPES = tuple(R.Scope)                              # all 6
STATES = tuple(R.State)                              # all 3
IDENTITIES: Tuple[Any, ...] = ("t_main", "t_other", None)
VALUES: Tuple[int, ...] = (72, 80)
CONDITION_MAPS: Tuple[Tuple[Tuple[str, str], ...], ...] = (
    (),
    (("input_method", "stdin"),),
    (("input_method", "argv"),),
    (("fd", "0"), ("input_method", "stdin")),
)
MAX_STORE = 3
MAX_BATCH = 3
MAX_DEP_DEPTH = 3
MAX_PINS = 2

KEY = "stack.return_offset"        # BUILD-scoped, int-valued
CTX = R.ResolveContext(
    identities=frozenset({"t_main"}),
    conditions=(("fd", "0"), ("input_method", "stdin")),
    host_id="h1", boot_id="b1", process_id="p1", attempt_id="a1",
)

_COUNTS: Dict[str, int] = {}


def _count(name: str, n: int) -> int:
    _COUNTS[name] = n
    return n


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def raw(value=72, provenance=R.Provenance.MEASURED, identity="t_main",
        scope=R.Scope.BUILD, conditions=(), method="m1", by="supwngo offset",
        at="t1", key=KEY, binding=None, derived_from=()) -> Dict[str, Any]:
    """A candidate as it arrives from an adapter: a plain mapping."""
    if binding is None and scope in R._BOUND_SCOPES:
        binding = {R.Scope.HOST: "h1", R.Scope.BOOT: "b1",
                   R.Scope.PROCESS: "p1", R.Scope.ATTEMPT: "a1"}[scope]
    return {
        "key": key, "value": value, "provenance": provenance,
        "applies_to": {"identity": identity, "scope": scope,
                       "conditions": dict(conditions), "binding": binding},
        "method": method, "by": by, "derived_from": list(derived_from),
        "observations": [{"at": at}],
    }


def bare(value=72, provenance=R.Provenance.MEASURED, identity="t_main",
         scope=R.Scope.BUILD, conditions=(), method="m1", at="t1",
         key=KEY) -> R.Candidate:
    """A Candidate built directly, for properties about the pure orders.

    Bypasses the store invariants on purpose: ``compare_specificity`` is a pure
    function on candidates, and per-key allowed scopes are a *store* invariant
    (I4), so the order must be well defined over combinations a store would
    reject.
    """
    binding = {R.Scope.HOST: "h1", R.Scope.BOOT: "b1", R.Scope.PROCESS: "p1",
               R.Scope.ATTEMPT: "a1"}.get(scope)
    c = R.Candidate(
        key=key, value=value, provenance=provenance,
        applies_to=R.AppliesTo(identity, scope, tuple(sorted(conditions)), binding),
        method=method, by="supwngo offset",
        observations=(R.Observation(at),),
    )
    return dataclasses.replace(c, id=R.derive_id(c))


def store_of(*raws) -> R.FactStore:
    s = R.FactStore()
    for r in raws:
        R.merge(s, r)
    return s


#: Normative symmetry reduction for the composed order.  ``compare_specificity``
#: reads only provenance, identity-boundness, scope and conditions -- never
#: value, method, by, observations or state -- which
#: :func:`prop_P5b_specificity_reads_only_ordered_components` proves rather than
#: assumes.  So the order universe fixes the other fields, and one
#: identity-bound / one identity-agnostic representative plus three scopes
#: containing an incomparable pair (``libc_file`` vs ``build``) suffice.
ORDER_SCOPES = (R.Scope.BUILD, R.Scope.LIBC_FILE, R.Scope.PROCESS)
ORDER_IDENTITIES = ("t_main", None)
#: All four condition maps, including the two-element one: without it the
#: universe contained no strict subset pair, so the conditions component was
#: only ever exercised on EQUAL and INCOMPARABLE.
ORDER_CONDITIONS = CONDITION_MAPS


def order_universe() -> List[R.Candidate]:
    """The candidate universe the composed-order properties quantify over."""
    return [
        bare(provenance=prov, identity=ident, scope=scope, conditions=conds)
        for prov, ident, scope, conds in itertools.product(
            PROVENANCES, ORDER_IDENTITIES, ORDER_SCOPES, ORDER_CONDITIONS)
    ]


# ===========================================================================
# Properties.  Each is a plain function that raises AssertionError, so the
# mutation meta-test can call it directly.
# ===========================================================================


def prop_P1_merge_totality_and_semantics() -> None:
    """Not a codomain check.

    The active multiset afterwards must equal an **independently computed** set
    union on dedup keys, and no pre-existing candidate's state may change.  A
    merge that supersedes on rank passes "no exception escaped" and fails this.
    """
    # One representative per digest-bearing axis, so the pair/incoming product
    # stays small while still covering dedup, disagreement and re-observation.
    universe = [
        raw(),
        raw(value=80),
        raw(provenance=R.Provenance.ASSERTED),
        raw(provenance=R.Provenance.ASSUMED, value=80),
        raw(method="m2"),
        raw(at="t2"),
        raw(conditions=CONDITION_MAPS[1]),
        raw(identity=None),
    ]
    n = 0
    # ``retract_first`` matters: without a store that already holds a terminal
    # candidate, a merge that deduped into terminal candidates would behave
    # identically and the property would not see it.
    for pre in itertools.combinations(universe, 2):
        for incoming in universe:
          for retract_first in (False, True):
            s = R.FactStore()
            for r in pre:
                R.merge(s, r)
            if retract_first:
                R.retract(s, s.active(KEY)[0].id, "t0", "superseded by hand",
                          "operator")
            before_states = {c.id: c.state for c in s.all_candidates()}
            expected = {R.dedup_key(c) for c in s.active(KEY)}
            expected |= {R.dedup_key(R.validate_candidate(incoming))}

            # A `SchemaError` on a **valid** candidate is a violation of merge
            # totality, not a crash, so it is diagnosed here rather than
            # escaping. (This is how the store-invariant rollback reports an
            # id collision: the write is refused, and the property says why.)
            try:
                decision = R.merge(s, incoming)
            except R.SchemaError as exc:
                raise AssertionError(
                    f"merge refused a valid candidate: {exc}. Store held "
                    f"{[c.id for c in s.all_candidates()]}"
                ) from exc
            assert decision in R.MergeDecision, decision

            got = {R.dedup_key(c) for c in s.active(KEY)}
            assert got == expected, (
                f"active dedup keys diverged from the oracle: "
                f"missing {expected - got}, extra {got - expected}"
            )
            for cid, st in before_states.items():
                now = s.by_id(cid)
                assert now is not None, f"merge removed {cid}"
                assert now.state is st, f"merge changed state of {cid}: {st} -> {now.state}"
            n += 1
    # Round-2 finding 2, as a named regression: the two-operation sequence that
    # produced a terminal and a live candidate sharing **one id**, which then
    # broke by_id, pins, dependency lookup, the conflict record and ordering at
    # once.  Asserted directly, because the enumeration above would report it
    # only as a confusing dedup-key mismatch.
    s = R.FactStore()
    R.merge(s, raw())
    original = s.active(KEY)[0]
    R.retract(s, original.id, "t0", "measured against the wrong build", "operator")
    try:
        decision = R.merge(s, raw(at="t2"))
    except R.SchemaError as exc:
        # Without `generation` the collision makes the store violate I6, so the
        # write is rolled back and the re-observation cannot be stored **at
        # all**.  Reported as this property failing, with the diagnosis, rather
        # than as the test crashing.
        raise AssertionError(
            f"a re-observation after a retraction could not be stored: {exc}. "
            "The live and terminal siblings collide on one id unless the id "
            "digest distinguishes them."
        ) from exc
    assert decision is R.MergeDecision.APPENDED
    live = s.active(KEY)
    assert len(live) == 1, "a re-observation after a retraction must be live"
    assert live[0].id != original.id, (
        "the live candidate shares its id with its retracted sibling; one "
        "ambiguous id breaks by_id, pins, dependency lookup and array ordering"
    )
    assert live[0].generation == original.generation + 1
    assert R.dedup_key(live[0]) == R.dedup_key(original), (
        "generation must stay out of the dedup key, or a re-observation would "
        "stop folding into its active sibling"
    )
    assert len({c.id for c in s.candidates(KEY)}) == 2
    R.validate_store(s)
    assert any(c.cls is R.ConflictClass.REOBSERVED_AFTER_RETRACTION
               for c in s.conflicts), "the operator was not told"
    _count("P1 (store, incoming) pairs", n)


def prop_P1b_validation_is_the_only_raiser() -> None:
    """Malformed input of any shape raises SchemaError and nothing else."""
    good_ref = {"key": "libc.base", "id": "f_" + "0" * 32, "digest": "a" * 64}
    bad: List[Any] = [
        None, 42, "x", [], {},
        {**raw(), "provenance": "guessed"},
        {**raw(), "value": -1},
        {**raw(), "value": "72"},
        {**raw(), "value": 1.5},
        {**raw(), "key": "no.such.key"},
        {**raw(), "method": ""},
        {**raw(), "observations": []},
        {**raw(), "surprise": 1},
        {**raw(), "id": "f_deadbeefcafe"},
        raw(scope=R.Scope.PROCESS),                  # I4: wrong scope for key
        {**raw(), "applies_to": {"scope": R.Scope.BUILD, "identity": 7}},
        # Round-2 finding 1: these escaped as TypeError/ValueError from inside
        # the field checks, so the funnel -- not a remembered list of shapes --
        # is what makes validation total.
        {**raw(), "observations": 1},
        {**raw(), "observations": {"at": "t1"}},
        {**raw(), "derived_from": 1},
        {**raw(), "applies_to": {"scope": R.Scope.BUILD, "identity": "t",
                                 "conditions": [("x",)]}},
        {**raw(), "applies_to": {"scope": R.Scope.BUILD, "identity": "t",
                                 "conditions": {"x": 7}}},
        {**raw(), "applies_to": {"scope": R.Scope.BUILD, "identity": "t",
                                 "conditions": 5}},
        {1: "not a string field name"},
        # A constructed dataclass is not a validated one.
        {**raw(), "observations": [R.Observation("")]},
        # The case no field-by-field check anticipates: two evidence pairs whose
        # values are of incomparable types, so the failure happens *inside*
        # ``sorted()``.  This is the input that makes the funnel load-bearing
        # rather than decorative -- without it, every raise above is explicit and
        # the funnel is a validation step that cannot fail.
        {**raw(), "observations": [{"at": "t1",
                                    "evidence": [("a", 1), ("a", "x")]}]},
        {**raw(), "observations": [R.Observation("t1", "not pairs")]},
        {**raw(), "applies_to": R.AppliesTo("t", R.Scope.BUILD, ({"x": 1},))},
        {**raw(), "derived_from": [R.Ref("libc.base", "nope", "a" * 64)]},
        {**raw(), "derived_from": [R.Ref("libc.base", "f_" + "0" * 32, "zz")]},
        {**raw(), "derived_from": [{"id": "f_" + "0" * 32}]},
        {**raw(), "derived_from": [{**good_ref, "key": "no.such.key"}]},
        {**raw(), "derived_from": [good_ref, good_ref]},
        # generation is store-assigned and bounded
        {**raw(), "generation": -1},
        {**raw(), "generation": True},
        # A derivation with no source is not a derivation.
        {**raw(), "provenance": R.Provenance.DERIVED},
        # Only the state machine changes states; merge takes ACTIVE only.
        {**raw(), "state": R.State.RETRACTED},
        {**raw(), "state": R.State.SUPERSEDED},
        {**raw(), "state": "resurrected"},
    ]
    for item in bad:
        s = R.FactStore()
        # Not ``pytest.raises``: the property is about the *declared error type*,
        # so an escaping TypeError must be reported as this property failing and
        # not as the test crashing.
        try:
            R.merge(s, item)
        except R.SchemaError:
            pass
        except Exception as exc:  # noqa: BLE001 - that is the property
            raise AssertionError(
                f"merge raised {type(exc).__name__} ({exc}) rather than SchemaError "
                f"for {item!r:.120}; validation is not total in its declared error "
                "type, so callers cannot distinguish bad input from a resolver bug"
            ) from exc
        else:
            raise AssertionError(f"merge accepted malformed input: {item!r:.160}")
        assert not s.keys(), "a rejected candidate must not be persisted"
        assert not s.conflicts and not s.resolutions, \
            "a rejected candidate must not leave a log or conflict record"
    # A store that already violates an invariant is refused *before* the write,
    # rather than being left violating it unless the incoming happens to collide.
    broken = R.FactStore()
    c = R.validate_candidate(raw())
    broken._bucket(KEY).extend([c, c])                 # violates I3 and I6
    with pytest.raises(R.SchemaError):
        R.merge(broken, raw(value=80, method="m9"))
    assert len(broken.candidates(KEY)) == 2, "the refused merge was not rolled back"
    _count("P1b malformed inputs", len(bad) + 1)


def _seeded_store() -> R.FactStore:
    """A store that already exercises the parts of the document a pool of plain
    merges never reaches: a **terminal** candidate, a **dependency** ref, a
    populated **log** and a populated **conflicts** array.

    P2 previously permuted only fresh active candidates, so an order dependence
    in any of those four arrays would not have been visible.
    """
    s = R.FactStore()
    R.merge(s, raw(value=99, method="doomed"))
    doomed = next(c for c in s.active(KEY) if c.method == "doomed")
    R.retract(s, doomed.id, "t0", "measured against the wrong build", "operator")

    # A disagreement, so ``conflicts`` is non-empty in the compared bytes.
    R.merge(s, raw(value=101, method="rival_a"))
    R.merge(s, raw(value=102, method="rival_b", provenance=R.Provenance.ASSUMED))

    R.merge(s, raw(key="libc.system_offset", value=0x50d60,
                   scope=R.Scope.LIBC_FILE))
    src = s.active("libc.system_offset")[0]
    R.merge(s, raw(key="libc.base", value=0x7f0000000000, scope=R.Scope.PROCESS,
                   provenance=R.Provenance.DERIVED, method="derive",
                   derived_from=[{"key": src.key, "id": src.id,
                                  "digest": R.candidate_digest(src)}]))
    R.pin(s, "libc.system_offset", src.id, "t1", "known-good libc", "operator")
    return s


def prop_P2_merge_commutativity() -> None:
    """Canonical document **bytes** identical under every permutation.

    Quantified over a seeded store so the terminal candidates, dependency refs,
    ``resolutions`` and ``conflicts`` arrays are all inside the compared bytes.
    """
    pool = [raw(value=72), raw(value=80), raw(provenance=R.Provenance.ASSERTED),
            raw(method="m2"), raw(at="t2"), raw(conditions=CONDITION_MAPS[1]),
            raw(by="another producer"), raw(identity="t_other"),
            raw(identity=None), raw(value=99, method="doomed", at="t5")]
    n = 0
    for size in range(1, MAX_BATCH + 1):
        for batch in itertools.combinations(pool, size):
            digests = set()
            for perm in itertools.permutations(batch):
                s = _seeded_store()
                for r in perm:
                    R.merge(s, r)
                doc = R.canonical_document(s)
                digests.add(doc)
                n += 1
            assert len(digests) == 1, (
                f"merge is order-dependent for batch of {size}: "
                f"{len(digests)} distinct documents"
            )
    # The compared bytes really do contain all four arrays -- otherwise this
    # property would be checking a narrower document than it claims.
    doc = R.canonical_document(_seeded_store())
    for fragment in ('"resolutions":[{', '"conflicts":[{', '"derived_from":[{',
                     '"state":"retracted"'):
        assert fragment in doc, f"P2's document lacks {fragment!r}; it is narrower than claimed"
    _count("P2 permutations merged", n)


def prop_P3_merge_idempotence() -> None:
    s = R.FactStore()
    assert R.merge(s, raw()) is R.MergeDecision.APPENDED
    once = R.canonical_document(s)
    assert R.merge(s, raw()) is R.MergeDecision.DEDUPED
    assert R.canonical_document(s) == once, "a repeated identical merge changed the document"
    assert len(s.active(KEY)) == 1
    assert len(s.active(KEY)[0].observations) == 1, "dedup-equal observation duplicated"
    # A genuinely new sighting is retained without creating a rival.
    assert R.merge(s, raw(at="t2")) is R.MergeDecision.DEDUPED
    assert len(s.active(KEY)) == 1
    assert len(s.active(KEY)[0].observations) == 2, "a new observation was discarded"
    _count("P3 merges", 3)


def _assert_strict_partial_order(members: Sequence[Any], cmp, label: str) -> int:
    """Exhaustive over all pairs and all triples, via a precomputed matrix.

    The matrix is the only place ``cmp`` is called (``n**2`` times); the triple
    loop is then ``n**3`` table lookups, which is what keeps a genuinely
    exhaustive transitivity check affordable.
    """
    n = len(members)
    mat = [[cmp(a, b) for b in members] for a in members]

    for i, a in enumerate(members):
        assert mat[i][i] is R.Ordering.EQUAL, f"{label}: not reflexive-EQUAL at {a}"
    mirror = {R.Ordering.GREATER: R.Ordering.LESS,
              R.Ordering.LESS: R.Ordering.GREATER,
              R.Ordering.EQUAL: R.Ordering.EQUAL,
              R.Ordering.INCOMPARABLE: R.Ordering.INCOMPARABLE}
    for i in range(n):
        for j in range(n):
            assert mat[j][i] is mirror[mat[i][j]], (
                f"{label}: antisymmetry fails for ({members[i]}, {members[j]}): "
                f"{mat[i][j]}/{mat[j][i]}"
            )
    G = R.Ordering.GREATER
    for i in range(n):
        gi = [j for j in range(n) if mat[i][j] is G]
        for j in gi:
            for k in range(n):
                if mat[j][k] is G:
                    assert mat[i][k] is G, (
                        f"{label}: transitivity fails for "
                        f"({members[i]}, {members[j]}, {members[k]})"
                    )
    return n ** 3


def prop_P4_provenance_partial_order() -> None:
    n = _assert_strict_partial_order(PROVENANCES, R.compare_provenance, "provenance")
    assert R.compare_provenance(R.Provenance.MEASURED, R.Provenance.ASSERTED) \
        is R.Ordering.INCOMPARABLE, \
        "measured and asserted must be INCOMPARABLE: a rank always picks a winner"
    assert R.compare_provenance(R.Provenance.ASSERTED, R.Provenance.ASSUMED) \
        is R.Ordering.GREATER, "an assertion must still beat a guess"
    _count("P4 provenance triples", n)


def prop_P5_scope_and_specificity_partial_orders() -> None:
    mentioned = {x for edge in R.SCOPE_EDGES for x in edge}
    missing = {s.value for s in R.Scope} - mentioned
    assert not missing, f"scope(s) absent from SCOPE_EDGES: {sorted(missing)}"
    n1 = _assert_strict_partial_order(SCOPES, R.compare_scope, "scope")

    assert R.compare_scope(R.Scope.LIBC_FILE, R.Scope.HOST) is R.Ordering.INCOMPARABLE, \
        "libc_file and host are independent axes, not a containment chain"

    # Conditions: subset containment, which a count-based comparator fails on
    # both of these cases.  Two *unrelated* singletons must be INCOMPARABLE (a
    # count calls them EQUAL), and two conditions must not automatically beat
    # one unless they contain it (a count always says they do).
    one_a = R.AppliesTo("t", R.Scope.BUILD, CONDITION_MAPS[1])
    one_b = R.AppliesTo("t", R.Scope.BUILD, CONDITION_MAPS[2])
    two = R.AppliesTo("t", R.Scope.BUILD, CONDITION_MAPS[3])
    assert R.compare_conditions(one_a, one_b) is R.Ordering.INCOMPARABLE, \
        "unrelated single conditions are not equally specific; a count says they are"
    assert R.compare_conditions(two, one_a) is R.Ordering.GREATER, \
        "{fd, input_method} contains {input_method} and so is strictly more specific"
    assert R.compare_conditions(two, one_b) is R.Ordering.INCOMPARABLE, \
        "two conditions must not beat one they do not contain; a count says they do"
    assert R.compare_conditions(one_a, two) is R.Ordering.LESS

    universe = order_universe()
    n2 = _assert_strict_partial_order(universe, R.compare_specificity, "specificity")
    _count("P5 scope triples", n1)
    _count("P5 specificity triples", n2)
    _count("P5 candidate universe", len(universe))


def prop_P5b_specificity_reads_only_ordered_components() -> None:
    """Justifies the symmetry reduction the order universe relies on.

    If ``compare_specificity`` ever started reading ``value`` or ``method``, the
    reduced universe would stop being exhaustive -- so that is checked, not
    assumed.
    """
    base = bare()
    variants = {
        "value": dataclasses.replace(base, value=999),
        "method": dataclasses.replace(base, method="other"),
        "by": dataclasses.replace(base, by="someone else"),
        "state": dataclasses.replace(base, state=R.State.SUPERSEDED),
        "observations": dataclasses.replace(base, observations=(R.Observation("t9"),)),
        "derived_from": dataclasses.replace(
            base, derived_from=(R.Ref("k", "f_000000000000", "d"),)),
    }
    for field, variant in variants.items():
        assert R.compare_specificity(base, variant) is R.Ordering.EQUAL, (
            f"compare_specificity reads {field!r}; the order universe's symmetry "
            "reduction is no longer sound"
        )
        for other in order_universe():
            assert R.compare_specificity(other, base) is \
                R.compare_specificity(other, variant), (
                    f"compare_specificity is not invariant in {field!r}"
                )
    _count("P5b invariance fields", len(variants))


def prop_P6_resolve_totality() -> None:
    allowed = (R.FactUnavailable, R.FactUnresolved, R.FactStale, R.PinInapplicable,
               R.SchemaError)
    pool = [raw(value=72), raw(value=80), raw(provenance=R.Provenance.ASSERTED),
            raw(provenance=R.Provenance.ASSUMED, value=80),
            raw(identity="t_other"), raw(identity=None),
            raw(conditions=CONDITION_MAPS[2])]
    n = 0
    succeeded = 0
    for size in range(0, MAX_STORE + 1):
        for batch in itertools.combinations(pool, size):
            s = store_of(*batch)
            applicable = [c for c in s.active(KEY) if R.applicable(c, CTX)]
            try:
                out = R.resolve(s, KEY, CTX)
            except allowed as exc:
                # Both directions, and neither clause may be a tautology.
                if not applicable:
                    assert isinstance(exc, R.FactUnavailable), \
                        f"empty applicable pool must raise FactUnavailable, got {exc!r}"
                else:
                    assert not isinstance(exc, R.FactUnavailable), \
                        f"non-empty applicable pool raised FactUnavailable: {exc!r}"
                    assert len(applicable) > 1, (
                        f"a single applicable candidate ({applicable[0].id}) must "
                        f"resolve, not raise {type(exc).__name__}"
                    )
                n += 1
                continue
            except Exception as exc:  # noqa: BLE001 - that is the property
                raise AssertionError(f"undeclared exception escaped resolve: {exc!r}")
            assert applicable, "resolve returned a Selected from an empty applicable pool"
            assert isinstance(out, R.Selected)
            succeeded += 1
            n += 1
    # Totality is only half the property: a resolver that refuses everything is
    # total.  Round-2 finding 12 -- "a resolver that always refuses passes P6
    # and P7" -- is closed by requiring the successes.
    assert succeeded >= 4, (
        f"only {succeeded} of {n} stores resolved; a resolver that always refuses "
        "must not pass this property"
    )
    lone = R.resolve(store_of(raw(value=72)), KEY, CTX)
    assert lone.rule == "unique_maximal" and lone.value == 72
    _count("P6 resolve invocations", n)
    _count("P6 resolve successes", succeeded)


def prop_P7_resolve_determinism() -> None:
    pool = [raw(value=72), raw(provenance=R.Provenance.ASSUMED, value=72),
            raw(method="m2"), raw(provenance=R.Provenance.ASSUMED, value=80,
                                  method="m3"),
            raw(scope=R.Scope.BUILD, conditions=CONDITION_MAPS[1], method="m4")]
    n = 0
    outcomes = set()
    for size in range(1, MAX_STORE + 1):
        for batch in itertools.combinations(pool, size):
            s = store_of(*batch)
            bucket = list(s._facts[KEY])
            results = set()
            for perm in itertools.permutations(bucket):
                s._facts[KEY] = list(perm)
                try:
                    out = R.resolve(s, KEY, CTX)
                    results.add(("ok", R.canonical(out.value), out.witness.id, out.rule))
                except LookupError as exc:
                    results.add(("raise", type(exc).__name__))
                n += 1
            assert len(results) == 1, f"resolve depends on candidate order: {results}"
            outcomes |= results
    # Determinism alone is satisfied by a resolver that always raises the same
    # thing, so the enumeration must be seen to produce both outcomes.
    kinds = {o[0] for o in outcomes}
    assert kinds == {"ok", "raise"}, (
        f"P7 only ever observed {sorted(kinds)}; a constant resolver would pass"
    )
    _count("P7 resolve permutations", n)


def prop_P8_resolve_never_invents() -> None:
    """Enumerated, not a single fixture: every store that resolves at all must
    hand back witnesses that are the *same objects* as pooled candidates."""
    pool_raw = [raw(value=72), raw(value=72, provenance=R.Provenance.ASSUMED),
                raw(value=72, method="m2"), raw(value=80, method="m3"),
                raw(identity=None), raw(conditions=CONDITION_MAPS[1])]
    n = 0
    for size in range(1, MAX_STORE + 1):
        for batch in itertools.combinations(pool_raw, size):
            s = store_of(*batch)
            pool = [c for c in s.active(KEY) if R.applicable(c, CTX)]
            try:
                out = R.resolve(s, KEY, CTX)
            except LookupError:
                continue
            for w in (out.witness,) + out.witnesses:
                assert any(w is c for c in pool), (
                    f"witness {w.id} is not the same object as any pooled candidate "
                    "(a fabricated or copied witness passes a type check and "
                    "fails this)"
                )
                assert w.state is R.State.ACTIVE
                assert R.applicable(w, CTX)
                n += 1
            assert out.witness in out.witnesses
            assert R.canonical(out.value) == R.canonical(out.witness.value)
    assert n > 0, "P8 never reached a resolving store"
    _count("P8 witnesses checked", n)


def prop_P9_asserted_never_silently_beats_measured() -> None:
    """Quantified over **every** applicable contradictory pair, across identity,
    scope and condition combinations -- not only pairs tied on earlier
    components, which is the mistake rev 1's P9 made."""
    n = 0
    scope_keys = {R.Scope.BUILD: KEY, R.Scope.HOST: "env.LANG",
                  R.Scope.BOOT: "env.LANG", R.Scope.PROCESS: "libc.base"}
    for m_scope, a_scope in itertools.product(scope_keys, repeat=2):
        if scope_keys[m_scope] != scope_keys[a_scope]:
            continue
        key = scope_keys[m_scope]
        vals = ("72", "80") if key.startswith("env.") else (72, 80)
        for m_ident, a_ident in itertools.product(("t_main", None), repeat=2):
            for m_cond, a_cond in itertools.product(
                    (CONDITION_MAPS[0], CONDITION_MAPS[1]), repeat=2):
                s = R.FactStore()
                R.merge(s, raw(key=key, value=vals[0], provenance=R.Provenance.MEASURED,
                               identity=m_ident, scope=m_scope, conditions=m_cond))
                R.merge(s, raw(key=key, value=vals[1], provenance=R.Provenance.ASSERTED,
                               identity=a_ident, scope=a_scope, conditions=a_cond,
                               method="m2"))
                live = [c for c in s.active(key) if R.applicable(c, CTX)]
                if len(live) < 2:
                    continue
                n += 1
                with pytest.raises(R.FactUnresolved):
                    R.resolve(s, key, CTX)

                # ... and only an explicit, recorded pin may select one.
                asserted = next(c for c in live
                                if c.provenance is R.Provenance.ASSERTED)
                # Through the validated writer, not by appending to a public
                # list: the pin is the one override, so it must be attributed.
                R.pin(s, key, asserted.id, "t9", "operator knows better",
                      "operator@host")
                out = R.resolve(s, key, CTX)
                assert out.witness.id == asserted.id
                assert out.rule == "operator_pin"
                rec = s.resolutions[-1]
                assert rec.actor == "operator@host" and rec.seq >= 1, (
                    "an override with no recorded actor is not a record of an "
                    "explicit operator decision"
                )
    assert n >= 8, f"P9 exercised only {n} contradictory pairs"
    _count("P9 contradictory applicable pairs", n)


def prop_P10_digest_partition() -> None:
    declared = {f.name for f in dataclasses.fields(R.Candidate)}
    partitioned = set(R.DERIVED_FIELDS) | set(R.ID_DIGEST_FIELDS) | {"id"}
    assert declared == partitioned, (
        "every candidate field must be in exactly one digest partition; "
        f"unclassified: {sorted(declared - partitioned)}, "
        f"phantom: {sorted(partitioned - declared)}"
    )
    assert not (set(R.DERIVED_FIELDS) & set(R.ID_DIGEST_FIELDS))

    c = R.validate_candidate(raw())
    id0, dep0 = R.derive_id(c), R.candidate_digest(c)

    mutations: Dict[str, Any] = {
        "observations": c.observations + (R.Observation("t9"),),
        "state": R.State.SUPERSEDED,
        "key": "stack.canary_offset",
        "value": 999,
        "provenance": R.Provenance.ASSUMED,
        "applies_to": dataclasses.replace(c.applies_to, identity="t_other"),
        "derived_from": (R.Ref("k", "f_000000000000", "d"),),
        "method": "other",
        "by": "someone else",
        "generation": c.generation + 1,
    }
    assert set(mutations) >= set(R.ID_DIGEST_FIELDS) | set(R.DERIVED_FIELDS), (
        "P10 must exhibit a mutation for every partitioned field, or a field it "
        "forgot is silently unchecked"
    )
    for field in R.DERIVED_FIELDS:
        m = dataclasses.replace(c, **{field: mutations[field]})
        assert R.derive_id(m) == id0, f"{field} is derived but changed the id digest"
        assert R.candidate_digest(m) == dep0, \
            f"{field} is derived but changed the dependency digest"
    for field in R.ID_DIGEST_FIELDS:
        m = dataclasses.replace(c, **{field: mutations[field]})
        assert R.derive_id(m) != id0, f"{field} is digest-bearing but the id did not change"
        assert R.candidate_digest(m) != dep0, \
            f"{field} is digest-bearing but the dependency digest did not change"

    tampered = dataclasses.replace(c, id="f_000000000000")
    assert R.candidate_digest(tampered) != dep0
    assert R.derive_id(tampered) == id0, "id must be excluded from its own input"
    with pytest.raises(R.SchemaError):
        R.validate_candidate(tampered)
    _count("P10 fields partitioned", len(declared))


def prop_P11_state_machine_totality() -> None:
    states = [None] + list(STATES)
    n = 0
    for st in states:
        for ev in R.STATE_EVENTS:
            n += 1
            assert (st, ev) in R._TRANSITIONS, f"undefined transition ({st}, {ev})"
            try:
                got = R.transition(st, ev)
            except R.StateTransitionError:
                continue
            if st in (R.State.SUPERSEDED, R.State.RETRACTED):
                raise AssertionError(
                    f"terminal state {st.value} accepted {ev!r} -> {got.value}; "
                    "resurrection invalidates every derived_from digest taken "
                    "while the candidate was dead"
                )
    with pytest.raises(R.StateTransitionError):
        R.transition(R.State.ACTIVE, "resurrect")
    _count("P11 (state, event) pairs", n)


def prop_P12_absent_is_not_false() -> None:
    with pytest.raises(TypeError):
        bool(R.ABSENT)
    s = R.FactStore()
    for key in list(R.FACT_KEYS):
        with pytest.raises(R.FactUnavailable):
            R.resolve(s, key, CTX)
        assert R.try_resolve(s, key, CTX) is R.ABSENT
    for name, fn in vars(R).items():
        if not callable(fn) or name.startswith("_") or not inspect.isfunction(fn):
            continue
        params = inspect.signature(fn).parameters
        assert "default" not in params, f"{name}() offers a default to reach for"
    _count("P12 registry keys", len(R.FACT_KEYS))


def _expected_class(a: R.Candidate, b: R.Candidate) -> R.ConflictClass:
    """Independent oracle for the conflict class of a differing-value pair.

    Written from the *rules* rather than by calling ``classify_pair``: an oracle
    that delegates to the code under test cannot disagree with it.
    """
    provs = {a.provenance, b.provenance}
    if provs == {R.Provenance.MEASURED, R.Provenance.ASSERTED}:
        return R.ConflictClass.CONTRADICTION_MEASURED_ASSERTED
    # Recompute the lexicographic order by hand, provenance first.
    for order in (R.compare_provenance(a.provenance, b.provenance),
                  R._compare_identity_bound(a.applies_to, b.applies_to),
                  R.compare_scope(a.applies_to.scope, b.applies_to.scope),
                  R.compare_conditions(a.applies_to, b.applies_to)):
        if order is R.Ordering.EQUAL:
            continue
        if order is R.Ordering.INCOMPARABLE:
            return R.ConflictClass.INCOMPARABLE
        return R.ConflictClass.DOMINATED
    return R.ConflictClass.EQUALLY_SPECIFIC


def prop_P13_conflicts_total_and_partitioned() -> None:
    """Enumerated over stores, and every class must be *reachable* -- an ordered
    partition whose later classes are dead code is not a partition."""
    pool_raw = [
        raw(value=72),
        raw(value=80, provenance=R.Provenance.ASSUMED, method="m2"),
        raw(value=80, provenance=R.Provenance.ASSERTED, method="m3"),
        raw(value=80, method="m4"),
        raw(value=80, identity=None, method="m5"),
        raw(value=72, conditions=CONDITION_MAPS[1], method="m6"),
        # Reaches INCOMPARABLE without reaching the measured/asserted guard: two
        # *unrelated* single conditions, both satisfied by CTX, are incomparable
        # in the conditions component, so this pair disagrees with neither
        # dominating and neither being the guarded class.  Added because the
        # reachability check below found INCOMPARABLE unproduced by the original
        # fixture set.
        raw(value=75, conditions=(("fd", "0"),), method="m7"),
    ]
    seen_classes = set()
    n = 0
    for size in range(0, MAX_STORE + 1):
        for batch in itertools.combinations(pool_raw, size):
            s = store_of(*batch)
            live = [c for c in s.active(KEY) if R.applicable(c, CTX)]
            expected = {
                tuple(sorted((a.id, b.id)))
                for i, a in enumerate(live) for b in live[i + 1:]
                if R.canonical(a.value) != R.canonical(b.value)
            }
            records = R.conflicts(s, CTX)
            got = [c.candidate_ids for c in records]
            assert sorted(got) == sorted(expected), (
                "conflicts is not total over differing-value pairs: "
                f"missing {expected - set(got)}, extra {set(got) - expected}"
            )
            assert len(got) == len(set(got)), "a pair was classified twice"

            # The **class** of each pair, not merely its presence: an
            # independently computed expectation, so a classifier that put every
            # pair in one bucket would pass the presence check and fail here.
            by_pair = {c.candidate_ids: c.cls for c in records}
            for i, a in enumerate(live):
                for b in live[i + 1:]:
                    pair = tuple(sorted((a.id, b.id)))
                    if pair not in by_pair:
                        continue
                    want = _expected_class(a, b)
                    assert by_pair[pair] is want, (
                        f"pair {pair} classified {by_pair[pair].value}, expected "
                        f"{want.value}"
                    )
            agree = {a.candidate_ids for a in R.agreements(s, CTX)}
            assert not (agree & set(got)), "a pair is both agreement and conflict"

            # Recorded at write time, not only when someone resolves: an
            # ``analyze``-only run never calls resolve(), and round-2 finding 8
            # was that such a run accumulated contradictions in silence.
            assert set(R.context_free_conflicts(s)) <= set(s.conflicts), (
                "merge did not record the conflicts visible at write time"
            )
            assert len(s.conflicts) == len(set(s.conflicts)), \
                "the conflicts array is not a set; merge order would leak into it"
            seen_classes |= {c.cls for c in records}
            n += len(expected)
    for required in (R.ConflictClass.CONTRADICTION_MEASURED_ASSERTED,
                     R.ConflictClass.EQUALLY_SPECIFIC,
                     R.ConflictClass.INCOMPARABLE,
                     R.ConflictClass.DOMINATED):
        assert required in seen_classes, (
            f"conflict class {required.value} was never produced; an ordered "
            "partition with an unreachable class is not a partition"
        )
    _count("P13 conflict pairs", n)


def prop_P14_dedup_preserves_authorities() -> None:
    """Same value, different authority: both must survive, in either order."""
    # The two differ in provenance and in *nothing else*: if any other field
    # differed, dedup would keep them apart even with provenance dropped from
    # the key, and the property would be vacuous.
    a = raw(value=72, provenance=R.Provenance.MEASURED)
    b = raw(value=72, provenance=R.Provenance.ASSERTED)
    assert ({k: v for k, v in a.items() if k != "provenance"}
            == {k: v for k, v in b.items() if k != "provenance"}), \
        "P14's operands must differ only in provenance, or the property is vacuous"
    for order in ((a, b), (b, a)):
        s = store_of(*order)
        provs = {c.provenance for c in s.active(KEY)}
        assert provs == {R.Provenance.MEASURED, R.Provenance.ASSERTED}, (
            "dedup collapsed two authorities into one, destroying the record of "
            f"who said what; survivors: {sorted(p.value for p in provs)}"
        )
        out = R.resolve(s, KEY, CTX)
        assert {c.provenance for c in out.witnesses} == provs, \
            "both concurring authorities must appear in Selected.witnesses"
        assert out.rule == "agreed_value"
    _count("P14 orders", 2)


TABLES = pathlib.Path(__file__).resolve().parents[1] / "docs" / "reference" / \
    "context-resolution-tables.md"


def _row_cells(line: str) -> List[str]:
    return [c.strip() for c in line.strip("|").split("|")][1:]


def prop_P15_generated_tables_call_the_runtime() -> None:
    """**Every** generated table is re-derived from the runtime, not only the
    provenance matrix: parsing one table let a constant generator hide a
    divergence in the scope, state or merge tables (round-2 finding 12)."""
    text = R.emit_tables()
    rows = [ln for ln in text.splitlines() if ln.startswith("| **")]
    n = 0

    # (a) provenance matrix
    cursor = 0
    for a in PROVENANCES:
        for cell, b in zip(_row_cells(rows[cursor]), PROVENANCES):
            n += 1
            assert cell == R._SYM[R.compare_provenance(a, b)], (
                f"generated cell ({a.value}, {b.value}) = {cell!r} disagrees with "
                "compare_provenance; a table backed by parallel constants agrees "
                "with itself and not with resolution"
            )
        cursor += 1

    # (b) scope matrix -- where the "total order" mutant hides
    for a in SCOPES:
        for cell, b in zip(_row_cells(rows[cursor]), SCOPES):
            n += 1
            assert cell == R._SYM[R.compare_scope(a, b)], (
                f"generated scope cell ({a.value}, {b.value}) = {cell!r} "
                "disagrees with compare_scope"
            )
        cursor += 1

    # (c) state transition table
    for st in [None] + list(STATES):
        for cell, ev in zip(_row_cells(rows[cursor]), R.STATE_EVENTS):
            n += 1
            try:
                want = R.transition(st, ev).value
            except R.StateTransitionError:
                want = "REFUSED"
            assert cell == want, (
                f"generated transition cell ({st}, {ev}) = {cell!r}, runtime says "
                f"{want!r}"
            )
        cursor += 1
    assert cursor == len(rows), f"{len(rows) - cursor} matrix rows went unchecked"

    # (d) merge decisions: re-run the scenarios and compare the rendered rows
    merge_rows = [ln for ln in text.splitlines()
                  if ln.startswith("| ") and ln.rstrip().endswith("` |")
                  and "`" in ln]
    rendered = {ln for ln in merge_rows}
    for scenario, decision in R._merge_scenarios():
        n += 1
        assert f"| {scenario} | `{decision}` |" in rendered, (
            f"merge scenario {scenario!r} renders as something other than "
            f"{decision!r}"
        )

    # (e) per-key scopes come from the registry the validator uses
    for key, spec in R.FACT_KEYS.items():
        n += 1
        want = ", ".join(sorted(s.value for s in spec.allowed_scopes))
        assert f"| `{key}` | {want} " in text, \
            f"allowed scopes for {key} disagree with FACT_KEYS"

    # (f) the committed file is byte-identical to fresh output
    assert TABLES.exists(), f"missing generated table: {TABLES}"
    assert TABLES.read_text(encoding="utf-8") == text, (
        "docs/reference/context-resolution-tables.md is stale; regenerate with "
        "`python -m supwngo.schema.resolve --emit-tables`"
    )
    _count("P15 generated cells checked", n)


def prop_P16_current_pins_is_a_function() -> None:
    """The fold is on the store-assigned ``seq``, and the operator-supplied
    ``at`` is deliberately adversarial here: ``"t9"`` then ``"t10"`` is the case
    that an ``at``-ordered fold gets backwards (round-2 finding 9)."""
    s = store_of(*[raw(value=72 + 8 * i, method=f"m{i}") for i in range(MAX_PINS)])
    ordered = sorted(s.active(KEY), key=lambda c: c.id)
    assert len(ordered) == MAX_PINS, "the pin enumeration must reach MAX_PINS"
    # Deliberately adversarial `at` labels: "t9" then "t10" then "t11"...
    ats = ["t9"] + [f"t1{i}" for i in range(MAX_PINS - 1)]
    for cand, at in zip(ordered, ats):
        R.pin(s, KEY, cand.id, at, "operator judgement", "operator")
    second = ordered[-1]
    recs = list(s.resolutions)
    assert [r.seq for r in recs] == list(range(1, MAX_PINS + 1)), \
        "seq must be assigned by the store, densely and in write order"

    n = 0
    for perm in itertools.permutations(recs):
        s.resolutions = list(perm)
        pins = R.current_pins(s)
        n += 1
        assert set(pins) <= {KEY}, "current_pins yielded more than one entry per key"
        assert pins[KEY] == second.id, (
            "current_pins must take the latest record by seq; folding on the "
            "free-text `at` makes t10 lose to t9, and taking the first means an "
            "unpin or a re-pin never takes effect"
        )
    s.resolutions = list(recs)
    R.unpin(s, KEY, "t2", "back to the measurement", "operator")
    assert R.current_pins(s) == {}, "an unpin after a pin must leave no entry"

    # The public list is not a back door: an unvalidated record is refused.
    first = ordered[0]
    for bad in (R.PinRecord("pin", KEY, first.id, "t1", 0, "operator"),
                R.PinRecord("pin", KEY, first.id, "", 9, "operator"),
                R.PinRecord("pin", KEY, first.id, "t1", 9, ""),
                R.PinRecord("pin", KEY, "not_an_id", "t1", 9, "operator"),
                R.PinRecord("pin", KEY, None, "t1", 9, "operator")):
        probe = store_of(raw(value=72))
        probe.resolutions.append(bad)
        with pytest.raises(R.SchemaError):
            R.validate_store(probe)
        # And it is refused at **read** time as well, so a hand-appended record
        # cannot be honoured as an operator pin just because nobody re-merged.
        with pytest.raises(R.SchemaError):
            R.resolve(probe, KEY, CTX)
        n += 1
    with pytest.raises(R.StateTransitionError):
        R.pin(s, KEY, "f_" + "0" * 32, "t1", "no such candidate", "operator")
    with pytest.raises(R.StateTransitionError):
        R.pin(s, "libc.base", first.id, "t1", "wrong key", "operator")

    # A pin whose target dies afterwards must refuse **and say why**: the
    # operator's next command is "unpin", not "widen the context", so a
    # retracted target reported as "not applicable here" sends them to the
    # wrong place.
    probe = store_of(raw(value=72), raw(value=80, method="m2"))
    target = probe.active(KEY)[0]
    R.pin(probe, KEY, target.id, "t1", "known good", "operator")
    assert R.resolve(probe, KEY, CTX).witness.id == target.id
    R.retract(probe, target.id, "t2", "measured wrong", "operator")
    with pytest.raises(R.PinInapplicable) as exc:
        R.resolve(probe, KEY, CTX)
    assert "retracted" in str(exc.value), str(exc.value)
    n += 1

    # ... and an *applicable-elsewhere* pin says the other thing.
    probe2 = store_of(raw(value=72, identity="t_other"))
    other = probe2.active(KEY)[0]
    R.pin(probe2, KEY, other.id, "t1", "cross-build pin", "operator")
    with pytest.raises(R.PinInapplicable) as exc2:
        R.resolve(probe2, KEY, CTX)
    assert "not applicable" in str(exc2.value), str(exc2.value)
    n += 1
    _count("P16 pin records checked", n)


def prop_P17_staleness_computed_and_monotone() -> None:
    s = R.FactStore()
    R.merge(s, raw(key="libc.system_offset", value=0x50d60, scope=R.Scope.LIBC_FILE,
                   identity="t_main"))
    src = s.active("libc.system_offset")[0]
    chain: List[R.Candidate] = [src]
    for depth in range(MAX_DEP_DEPTH):
        parent = chain[-1]
        R.merge(s, raw(key="libc.base", value=0x7f0000000000 + depth,
                       scope=R.Scope.PROCESS, provenance=R.Provenance.DERIVED,
                       method=f"derive{depth}",
                       derived_from=[{"key": parent.key, "id": parent.id,
                                      "digest": R.candidate_digest(parent)}]))
        chain.append(s.by_id(R.validate_candidate(
            raw(key="libc.base", value=0x7f0000000000 + depth,
                scope=R.Scope.PROCESS, provenance=R.Provenance.DERIVED,
                method=f"derive{depth}",
                derived_from=[{"key": parent.key, "id": parent.id,
                               "digest": R.candidate_digest(parent)}])).id))
    R.validate_store(s)
    for c in chain:
        assert not R.is_stale(s, c), f"{c.id} stale before anything changed"

    # A diamond: the same source reached by two paths.  The shared visited set
    # must not let the second path read as fresh once the first proved it stale.
    left, right = chain[1], None
    R.merge(s, raw(key="libc.base", value=0xdd00, scope=R.Scope.PROCESS,
                   provenance=R.Provenance.DERIVED, method="right",
                   derived_from=[{"key": src.key, "id": src.id,
                                  "digest": R.candidate_digest(src)}]))
    right = next(c for c in s.active("libc.base") if c.method == "right")
    R.merge(s, raw(key="heap.base", value=0xee00, scope=R.Scope.PROCESS,
                   provenance=R.Provenance.DERIVED, method="join",
                   derived_from=[
                       {"key": left.key, "id": left.id,
                        "digest": R.candidate_digest(left)},
                       {"key": right.key, "id": right.id,
                        "digest": R.candidate_digest(right)}]))
    join = s.active("heap.base")[0]
    assert not R.is_stale(s, join), "the diamond is fresh before anything changes"

    # A ref whose key does not match the candidate it names is structurally
    # false, and therefore stale -- not fresh because the id happened to resolve.
    # Checked **here**, while everything else is fresh, so the only reason it can
    # come out stale is the mismatched key.
    liar = dataclasses.replace(
        join, derived_from=(R.Ref("libc.system_offset", left.id,
                                  R.candidate_digest(left)),))
    honest = dataclasses.replace(
        join, derived_from=(R.Ref(left.key, left.id, R.candidate_digest(left)),))
    assert not R.is_stale(s, honest), "the control case must be fresh"
    assert R.is_stale(s, liar), \
        "a ref naming the right id under the wrong key must not read as fresh"

    # No invalidation call: retracting the root makes the whole closure stale.
    R.retract(s, src.id, "t9", "wrong libc", "operator")
    for c in chain[1:] + [right, join]:
        assert R.is_stale(s, c), (
            f"{c.id} did not become stale when its transitive source was retracted"
        )
    assert not hasattr(R.Candidate, "stale"), "staleness must be computed, not stored"

    # Cycles are not merely rejected -- they are **unconstructible** through the
    # public writers, because a ref pins the source's digest and the source's id
    # is a function of its content including its refs.  So a cycle would require
    # a digest of a candidate that does not exist yet.  That is asserted here
    # rather than asserted in prose.
    solo = R.validate_candidate(raw(key="libc.base", value=1,
                                    scope=R.Scope.PROCESS,
                                    provenance=R.Provenance.DERIVED,
                                    derived_from=[{"key": "libc.system_offset",
                                                   "id": "f_" + "0" * 32,
                                                   "digest": "a" * 64}]))
    self_ref = dataclasses.replace(
        solo, derived_from=(R.Ref(solo.key, solo.id, R.candidate_digest(solo)),))
    assert R.derive_id(self_ref) != solo.id, (
        "a self-reference must change the id it references, which is why a cycle "
        "cannot be constructed rather than merely being rejected"
    )
    cyc = R.FactStore()
    cyc._bucket(self_ref.key).append(self_ref)         # hand-built, not merged
    with pytest.raises(R.SchemaError):
        R.validate_store(cyc)                          # and it is rejected too
    assert R.is_stale(cyc, self_ref) is True, (
        "a hand-built cycle must terminate, and its digest cannot match, so it "
        "is stale"
    )
    _count("P17 dependency depth", MAX_DEP_DEPTH)


def prop_P18_equal_specificity_disagreement_refuses() -> None:
    """Two equally-specific authorities that disagree are unresolved, and a
    timestamp is not allowed to break the tie for them."""
    n = 0
    for t_a, t_b in (("t1", "t2"), ("t2", "t1"), ("t1", "t1")):
        s = store_of(raw(value=72, at=t_a), raw(value=80, at=t_b, method="m2"))
        live = [c for c in s.active(KEY) if R.applicable(c, CTX)]
        assert R.compare_specificity(live[0], live[1]) is R.Ordering.EQUAL
        n += 1
        with pytest.raises(R.FactUnresolved):
            R.resolve(s, KEY, CTX)
    _count("P18 equal-specificity disagreements", n)


def prop_P19_cross_identity_coincidence_is_not_agreement() -> None:
    """Equal encodings are not equal propositions: two builds can both hold
    0x401234 at ``gadget.pop_rdi`` and mean different instructions."""
    ctx = dataclasses.replace(CTX, identity_mode="none")
    s = store_of(
        raw(key="gadget.pop_rdi", value=0x401234, identity="t_main"),
        raw(key="gadget.pop_rdi", value=0x401234, identity="t_other", method="m2"),
    )
    live = [c for c in s.active("gadget.pop_rdi") if R.applicable(c, ctx)]
    assert len(live) == 2, "both identities must be selectable under --target-identity=none"
    assert not R.agreeing(live), \
        "candidates from different identities that coincide numerically are not agreement"
    with pytest.raises(R.FactUnresolved):
        R.resolve(s, "gadget.pop_rdi", ctx)
    _count("P19 cross-identity pairs", 1)


PROPERTIES = {
    "P1": prop_P1_merge_totality_and_semantics,
    "P1b": prop_P1b_validation_is_the_only_raiser,
    "P2": prop_P2_merge_commutativity,
    "P3": prop_P3_merge_idempotence,
    "P4": prop_P4_provenance_partial_order,
    "P5": prop_P5_scope_and_specificity_partial_orders,
    "P5b": prop_P5b_specificity_reads_only_ordered_components,
    "P6": prop_P6_resolve_totality,
    "P7": prop_P7_resolve_determinism,
    "P8": prop_P8_resolve_never_invents,
    "P9": prop_P9_asserted_never_silently_beats_measured,
    "P10": prop_P10_digest_partition,
    "P11": prop_P11_state_machine_totality,
    "P12": prop_P12_absent_is_not_false,
    "P13": prop_P13_conflicts_total_and_partitioned,
    "P14": prop_P14_dedup_preserves_authorities,
    "P15": prop_P15_generated_tables_call_the_runtime,
    "P16": prop_P16_current_pins_is_a_function,
    "P17": prop_P17_staleness_computed_and_monotone,
    "P18": prop_P18_equal_specificity_disagreement_refuses,
    "P19": prop_P19_cross_identity_coincidence_is_not_agreement,
}


@pytest.mark.parametrize("pid", sorted(PROPERTIES))
def test_property(pid: str) -> None:
    PROPERTIES[pid]()


# ===========================================================================
# The mutation meta-test: proof that each property can fail.
# ===========================================================================


@pytest.mark.parametrize("name", sorted(M.MUTANTS))
def test_mutant_is_caught(name: str) -> None:
    """A property no one has seen fail is in the same family as a probe driver
    that omits the argument it validates.  So: break the resolver on purpose and
    require the **named** property to notice."""
    mutant = M.MUTANTS[name]

    if mutant.breaks is None:
        # Redundancy demonstration: a second mechanism catches this defect, so
        # the property must still pass.
        with M.applied(mutant):
            PROPERTIES["P9"]()
        return

    prop = PROPERTIES[mutant.breaks]
    # Only a *property violation* counts as catching the mutant. AssertionError
    # is an explicit assert; Failed is a failed `pytest.raises` (it derives from
    # BaseException, not Exception, which is why an `except Exception` here
    # originally reported two caught mutants as escapes). An unrelated TypeError
    # from the patch itself must NOT be mistaken for the property working.
    violations = (AssertionError, _PytestFailed)
    with M.applied(mutant):
        try:
            prop()
        except violations:
            return
        except (KeyboardInterrupt, SystemExit):  # pragma: no cover
            raise
        except BaseException as exc:  # noqa: BLE001
            raise AssertionError(
                f"mutant {name!r} made property {mutant.breaks} raise "
                f"{type(exc).__name__}: {exc!r}. That is a crash, not a detected "
                "property violation -- tighten the mutant or the property so the "
                "failure is diagnostic."
            ) from exc
    raise AssertionError(
        f"mutant {name!r} (restores: {mutant.restores}) PASSED property "
        f"{mutant.breaks} -- that property has no teeth"
    )


def test_every_mutant_names_a_real_property() -> None:
    for name, mutant in M.MUTANTS.items():
        if mutant.breaks is not None:
            assert mutant.breaks in PROPERTIES, \
                f"mutant {name} is bound to unknown property {mutant.breaks}"
        for attr in mutant.patches:
            assert hasattr(R, attr), f"mutant {name} patches unknown attribute {attr}"


def test_every_property_has_a_mutant() -> None:
    """The other direction, and the one that was false: "every property is paired
    with a mutant" held for the mutants but not for the properties -- six had no
    bound mutant, so nobody had seen them fail (round-2 finding 13)."""
    bound = {m.breaks for m in M.MUTANTS.values() if m.breaks is not None}
    unpaired = sorted(set(PROPERTIES) - bound)
    assert not unpaired, (
        f"properties with no mutant bound to them: {unpaired}. A property no one "
        "has seen fail is a validation step that may not be able to fail."
    )


def test_enumeration_bounds_are_reported(capsys) -> None:
    """Print the realised case counts, so "exhaustive" is observable rather than
    claimed (round-1 finding 12)."""
    for fn in PROPERTIES.values():
        try:
            fn()
        except Exception:  # pragma: no cover - test_property reports failures
            pass
    with capsys.disabled():
        print("\n--- enumeration bounds actually exercised ---")
        print(f"  MAX_STORE={MAX_STORE} MAX_BATCH={MAX_BATCH} "
              f"MAX_DEP_DEPTH={MAX_DEP_DEPTH} MAX_PINS={MAX_PINS}")
        for label in sorted(_COUNTS):
            print(f"  {label:44s} {_COUNTS[label]:>8d}")
        print(f"  {'mutants bound to a property':44s} "
              f"{sum(1 for m in M.MUTANTS.values() if m.breaks):>8d}")
        print(f"  {'mutants proving redundancy (must pass)':44s} "
              f"{sum(1 for m in M.MUTANTS.values() if m.breaks is None):>8d}")
    assert _COUNTS, "no enumeration counts were recorded"
