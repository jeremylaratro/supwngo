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
from collections.abc import Mapping
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


def all_scope_universe() -> List[R.Candidate]:
    """The complement reduction: **every** scope, fewer of everything else.

    Round-3 finding 11: ``ORDER_SCOPES`` names three of six scopes, so a
    scope-specific defect in the *composition* -- as opposed to in
    ``compare_scope``, whose own order is checked exhaustively over all six --
    could pass.  Trading provenance and condition breadth for scope breadth
    covers that direction at 48 members rather than 240, because the triple loop
    is cubic and 240 members is 13.8M triples.
    """
    return [
        bare(provenance=prov, identity=ident, scope=scope, conditions=conds)
        for prov, ident, scope, conds in itertools.product(
            (R.Provenance.MEASURED, R.Provenance.ASSUMED), ORDER_IDENTITIES,
            SCOPES, (CONDITION_MAPS[0], CONDITION_MAPS[3]))
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


class _HostileMapping(Mapping):
    """A mapping that raises when read.

    This is what keeps the validation funnel honest.  Every other malformed
    input below is caught by an explicit check, and when round 3 pointed out
    that the previous funnel-only case (evidence values of incomparable types
    inside ``sorted()``) had since acquired an explicit check of its own, the
    funnel went back to being a step that could not fail -- the mutant that
    removes it passed.  No field-by-field check can catch this one: it fails
    inside ``dict(raw)``, before there is a field to check.  A lazily populated
    config object or a half-initialised adapter really does behave this way.
    """

    def keys(self):
        raise RuntimeError("backing store unavailable")

    def __iter__(self):
        raise RuntimeError("backing store unavailable")

    def __getitem__(self, k):
        raise RuntimeError("backing store unavailable")

    def __len__(self):
        return 1


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
        # The genuinely unanticipatable shape -- see _HostileMapping.
        _HostileMapping(),
        # Round-3 finding 2: every one of these is *falsey*, and
        # ``data.get(name) or ()`` treated falsey as absent, so all four
        # validated clean and produced a candidate nobody wrote.
        {**raw(), "id": 0},
        {**raw(), "derived_from": 0},
        {**raw(), "observations": [{"at": "t1", "evidence": 0}]},
        {**raw(), "applies_to": {"scope": R.Scope.BUILD, "identity": "t",
                                 "conditions": 0}},
        # Round-3 finding 2, second half: unknown *nested* fields were silently
        # discarded, so a typo asserted something other than what was written.
        {**raw(), "applies_to": {"scope": R.Scope.BUILD, "identity": "t",
                                 "scpoe": R.Scope.HOST}},
        {**raw(), "observations": [{"at": "t1", "evidnece": {"a": "b"}}]},
        {**raw(), "derived_from": [{**good_ref, "diegst": "x"}]},
        {**raw(), "observations": ["not a mapping"]},
        # Round-3 finding 3: evidence names must *be* strings.  ``str(k)``
        # coercion mapped 1 and "1" onto one name and then tied on the sort.
        {**raw(), "observations": [{"at": "t1", "evidence": {1: "a"}}]},
        {**raw(), "observations": [{"at": "t1", "evidence": [("", "a")]}]},
        {**raw(), "observations": [{"at": "t1",
                                    "evidence": [("a", "x"), ("a", "y")]}]},
        {**raw(), "observations": [{"at": "t1",
                                    "evidence": {"k": {1: "nested"}}}]},
        {**raw(), "observations": [{"at": "t1",
                                    "evidence": {"k": {R._BYTES_TAG: "spoof"}}}]},
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
    n_all = _assert_strict_partial_order(
        all_scope_universe(), R.compare_specificity, "specificity (all scopes)")
    _count("P5 all-scope specificity triples", n_all)

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


def _resolve_contexts() -> Tuple[R.ResolveContext, ...]:
    """The well-formed contexts the resolution properties quantify over.

    Round-3 finding 11: P6 exercised exactly one context, so every
    context-dependent branch -- ``identity_mode``, a narrower identity set, an
    unconstrained condition -- was untested.  ``identity_mode="none"`` is the
    interesting one: it is the mode under which two identities' matching
    ``0x401234`` become simultaneously applicable.
    """
    return (
        CTX,
        dataclasses.replace(CTX, identity_mode="none"),
        dataclasses.replace(CTX, identities=frozenset({"t_main", "t_other"})),
        dataclasses.replace(CTX, identities=frozenset()),
        dataclasses.replace(CTX, conditions=(("input_method", "stdin"),)),
        dataclasses.replace(CTX, conditions=()),
        dataclasses.replace(CTX, process_id="p2"),
    )


def prop_P6_resolve_totality() -> None:
    allowed = (R.FactUnavailable, R.FactUnresolved, R.FactStale, R.PinInapplicable,
               R.SchemaError)
    pool = [raw(value=72), raw(value=80), raw(provenance=R.Provenance.ASSERTED),
            raw(provenance=R.Provenance.ASSUMED, value=80),
            raw(identity="t_other"), raw(identity=None),
            raw(conditions=CONDITION_MAPS[2])]
    n = 0
    succeeded = 0
    per_context: Dict[str, int] = {}
    for size in range(0, MAX_STORE + 1):
        for batch in itertools.combinations(pool, size):
            s = store_of(*batch)
            for ctx in _resolve_contexts():
                applicable = [c for c in s.active(KEY) if R.applicable(c, ctx)]
                label = repr(ctx)
                try:
                    out = R.resolve(s, KEY, ctx)
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
                    raise AssertionError(
                        f"undeclared exception escaped resolve in context {label}: {exc!r}")
                assert applicable, "resolve returned a Selected from an empty applicable pool"
                assert isinstance(out, R.Selected)
                per_context[label] = per_context.get(label, 0) + 1
                succeeded += 1
                n += 1
    # Every context must actually resolve something, or a context is in the list
    # for decoration and the breadth is an illusion.
    assert len(per_context) == len(_resolve_contexts()), (
        "some context never produced a Selected, so it contributes no coverage: "
        f"{set(f for f in per_context)}")
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


def _oracle_mutually_exclusive(a: R.Candidate, b: R.Candidate) -> bool:
    """Independent re-derivation of "no context can make both applicable".

    Written by hand rather than by calling ``jointly_satisfiable`` for the same
    reason as ``_expected_class``: an oracle that delegates to the code under
    test cannot disagree with it.
    """
    at_a, at_b = a.applies_to, b.applies_to
    if at_a.scope is at_b.scope and at_a.scope in R._BOUND_SCOPES \
            and at_a.binding != at_b.binding:
        return True
    a_map = dict(at_a.conditions)
    return any(name in a_map and a_map[name] != value for name, value in at_b.conditions)


def _oracle_class(a: R.Candidate, b: R.Candidate):
    """Independent oracle for the conflict class of **any** pair, or ``None``.

    Covers the two cases that used to be missing entirely: a pair no context can
    pit against each other is not a conflict, and a pair with equal encodings but
    different subjects *is* one.
    """
    if _oracle_mutually_exclusive(a, b):
        return None
    if R.canonical(a.value) == R.canonical(b.value):
        if a.applies_to.identity == b.applies_to.identity:
            return None
        return R.ConflictClass.AMBIGUOUS_ACROSS_IDENTITIES
    return _expected_class(a, b)


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
                if _oracle_class(a, b) is not None
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
                    want = _oracle_class(a, b)
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


def _probe_value(value_type: type):
    """A value the registry accepts for this key, so a scope rejection is about
    the *scope* and not about the value type."""
    return {int: 1, bool: True, str: "x"}[value_type]


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
        cells = _row_cells(rows[cursor])
        # Round-3 finding 12: ``zip`` stops at the shorter sequence, so a row
        # with a missing cell passed every comparison it was asked to make.
        assert len(cells) == len(PROVENANCES), (
            f"provenance row {a.value!r} has {len(cells)} cells, expected "
            f"{len(PROVENANCES)}; a short row silently skips comparisons")
        for cell, b in zip(cells, PROVENANCES):
            n += 1
            assert cell == R._SYM[R.compare_provenance(a, b)], (
                f"generated cell ({a.value}, {b.value}) = {cell!r} disagrees with "
                "compare_provenance; a table backed by parallel constants agrees "
                "with itself and not with resolution"
            )
        cursor += 1

    # (b) scope matrix -- where the "total order" mutant hides
    for a in SCOPES:
        cells = _row_cells(rows[cursor])
        assert len(cells) == len(SCOPES), (
            f"scope row {a.value!r} has {len(cells)} cells, expected {len(SCOPES)}")
        for cell, b in zip(cells, SCOPES):
            n += 1
            assert cell == R._SYM[R.compare_scope(a, b)], (
                f"generated scope cell ({a.value}, {b.value}) = {cell!r} "
                "disagrees with compare_scope"
            )
        cursor += 1

    # (c) state transition table
    for st in [None] + list(STATES):
        cells = _row_cells(rows[cursor])
        assert len(cells) == len(R.STATE_EVENTS), (
            f"transition row {st} has {len(cells)} cells, expected "
            f"{len(R.STATE_EVENTS)}")
        for cell, ev in zip(cells, R.STATE_EVENTS):
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
    # Exactly three pipes: the registry table below has five, and a looser
    # selector swept its rows into the merge comparison.
    merge_rows = [ln for ln in text.splitlines()
                  if ln.startswith("| ") and ln.rstrip().endswith("` |")
                  and ln.count("|") == 3]
    rendered = {ln for ln in merge_rows}
    expected_rows = {f"| {scenario} | `{decision}` |"
                     for scenario, decision in R._merge_scenarios()}
    n += len(expected_rows)
    # Equality, not containment.  Presence-only checking let the table carry
    # *extra* merge rows that no scenario produces -- a documented decision the
    # resolver never makes, which is the direction that misleads an operator.
    assert rendered == expected_rows, (
        f"merge rows disagree with the scenarios: unrendered "
        f"{expected_rows - rendered}, undeclared {rendered - expected_rows}")

    # (e) the registry table: every row, every column.  The previous check
    # covered exact keys only -- so the seven ``prefix.*`` families went
    # unchecked -- and compared only the scope column, so ``depends_on`` and the
    # declared verification class could say anything at all.
    registry_rows = [ln for ln in text.splitlines()
                     if ln.startswith("| `") and ln.count("|") == 5]
    expected_registry = set()
    for key, spec in sorted(R.FACT_KEYS.items()):
        expected_registry.add(
            f"| `{key}` | {', '.join(sorted(s.value for s in spec.allowed_scopes))} "
            f"| `{spec.depends_on}` | `{spec.verification_class}` |")
    for prefix, spec in sorted(R._FACT_PREFIXES.items()):
        expected_registry.add(
            f"| `{prefix}*` | {', '.join(sorted(s.value for s in spec.allowed_scopes))} "
            f"| `{spec.depends_on}` | `{spec.verification_class}` |")
    n += len(expected_registry)
    assert set(registry_rows) == expected_registry, (
        f"registry table disagrees with the registry the validator uses: "
        f"missing {expected_registry - set(registry_rows)}, "
        f"extra {set(registry_rows) - expected_registry}")
    assert len(registry_rows) == len(R.FACT_KEYS) + len(R._FACT_PREFIXES), (
        f"{len(registry_rows)} registry rows for "
        f"{len(R.FACT_KEYS)} keys + {len(R._FACT_PREFIXES)} prefixes")

    # And the *enforced* column is enforced: a declared scope validates and an
    # undeclared one does not, so the column is not merely decorative text.
    for key, spec in sorted(R.FACT_KEYS.items()):
        for scope in R.Scope:
            probe = raw(key=key, scope=scope,
                        value=_probe_value(spec.value_type))
            accepted = True
            try:
                R.validate_candidate(probe)
            except R.SchemaError:
                accepted = False
            if accepted != (scope in spec.allowed_scopes):
                raise AssertionError(
                    f"{key}: the table says scopes "
                    f"{sorted(s.value for s in spec.allowed_scopes)} but "
                    f"validation {'accepts' if accepted else 'rejects'} "
                    f"{scope.value}")
            n += 1

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

    # Cycles: round-3 finding 13 was right that the previous block proved
    # nothing.  It built a self-reference while keeping the original id, so
    # ``validate_store`` rejected it at I2 -- the id check -- and
    # ``_assert_acyclic`` was never reached.  "One hash iteration did not return
    # the starting id" is also not a proof that fixed points are impossible.
    #
    # So the claim is now split in two, honestly:
    #
    # 1. Unconstructibility is an **argument**, not a test: a ref pins the
    #    source's digest and an id is a function of content including refs, so a
    #    cycle needs a digest of a candidate that does not exist yet.  What is
    #    *tested* is the one checkable consequence -- adding a self-reference
    #    changes the id being referenced.
    # 2. The detector is therefore fed a cycle **directly**, because no store can
    #    hold one.  A detector that has never been shown to fire is exactly the
    #    kind of absence-assertion this project keeps finding cannot fail.
    solo = R.validate_candidate(raw(key="libc.base", value=1,
                                    scope=R.Scope.PROCESS,
                                    provenance=R.Provenance.DERIVED,
                                    derived_from=[{"key": "libc.system_offset",
                                                   "id": "f_" + "0" * 32,
                                                   "digest": "a" * 64}]))
    self_ref = dataclasses.replace(
        solo, derived_from=(R.Ref(solo.key, solo.id, R.candidate_digest(solo)),))
    assert R.derive_id(self_ref) != solo.id, (
        "a self-reference must change the id it references, which is the one "
        "checkable consequence of cycles being unconstructible"
    )
    _assert_cycle_detector_fires()
    _count("P17 dependency depth", MAX_DEP_DEPTH)


def _cyclic_index(kind: str) -> Dict[str, R.Candidate]:
    """An id -> candidate index containing a genuine cycle.

    Built by hand and **not** through a store, because content-derived ids make a
    cycle unstorable: every route through the public writers is rejected before
    the cycle exists.  Keyed by the id each candidate claims, which is what
    ``_assert_acyclic`` and ``is_stale`` actually walk.
    """
    a = R.validate_candidate(raw(key="libc.base", value=1, scope=R.Scope.PROCESS))
    b = R.validate_candidate(raw(key="libc.system_offset", value=2,
                                 scope=R.Scope.LIBC_FILE, method="m2"))
    if kind == "self":
        a = dataclasses.replace(a, derived_from=(
            R.Ref(a.key, a.id, R.candidate_digest(a)),))
        return {a.id: a}
    # A mutual cycle: each names the other, so no single-step check can see it.
    a2 = dataclasses.replace(a, derived_from=(
        R.Ref(b.key, b.id, R.candidate_digest(b)),))
    b2 = dataclasses.replace(b, derived_from=(
        R.Ref(a.key, a.id, R.candidate_digest(a2)),))
    return {a.id: a2, b.id: b2}


def _assert_cycle_detector_fires() -> None:
    """The positive control for I5, and for ``is_stale``'s visited set."""
    for kind in ("self", "mutual"):
        index = _cyclic_index(kind)
        first = next(iter(index.values()))
        try:
            R._assert_acyclic(index, first, set(), set())
        except R.SchemaError as exc:
            assert str(exc).startswith("I5 "), f"wrong invariant reported: {exc}"
        else:
            raise AssertionError(
                f"_assert_acyclic did not detect a {kind} cycle; the acyclicity "
                "invariant is an assertion of absence that has never been shown "
                "to fire"
            )
        # ``is_stale`` must *terminate* on the same input -- that is what its
        # visited set is for -- and report staleness rather than recursing.
        class _CyclicStore(R.FactStore):
            def by_id(self, cid):
                return index.get(cid)

        assert R.is_stale(_CyclicStore(), first) is True, (
            f"is_stale did not terminate-and-refuse on a {kind} cycle")


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


# ---------------------------------------------------------------------------
# Round-3 properties.  Each one is the test that would have caught a HIGH
# finding, and each is bound to a mutant that restores that finding.
# ---------------------------------------------------------------------------


GENERATIONS: Tuple[int, ...] = (0, 1, 5)


def prop_P20_generation_is_store_assigned() -> None:
    """Round-3 finding 1.  ``generation`` and ``id`` are functions of store
    state, so merge order cannot change the document.

    The defect: on a store with no terminal sibling the caller's ``generation``
    survived, so merging the same assertion at 0 and at 5 left whichever arrived
    first and the bytes depended on arrival order.  A determinism property over
    permutations (P2) could not see it, because P2's fixtures all carried the
    same generation.
    """
    pairs = 0
    for g1, g2 in itertools.product(GENERATIONS, repeat=2):
        for seed_terminal in (False, True):
            docs = []
            for order in ((g1, g2), (g2, g1)):
                s = R.FactStore()
                if seed_terminal:
                    # A retracted sibling, so the store has an opinion about the
                    # next generation and the caller's must not override it.
                    R.merge(s, raw())
                    R.retract(s, s.candidates(KEY)[0].id, "t2", "wrong", "op")
                for gen in order:
                    R.merge(s, {**raw(), "generation": gen}) if gen == (
                        1 if seed_terminal else 0) else _merge_expecting_refusal(s, gen)
                docs.append(R.canonical_document(s))
            assert docs[0] == docs[1], (
                f"merge order changed the document for generations {g1},{g2} "
                f"(terminal seeded: {seed_terminal}): generation is not "
                "store-assigned, so the bytes depend on arrival order"
            )
            pairs += 1

    # Stated-but-wrong is refused, and refused *identically* whichever order it
    # arrives in -- that is the half a silent correction would hide.
    s = R.FactStore()
    R.merge(s, raw())
    R.retract(s, s.candidates(KEY)[0].id, "t2", "wrong", "op")
    for wrong in (0, 5):
        try:
            R.merge(s, {**raw(), "generation": wrong})
        except R.SchemaError as exc:
            assert "assigned by the store" in str(exc), str(exc)
        else:
            raise AssertionError(
                f"merge accepted caller-supplied generation {wrong} when the "
                "store had already assigned 1")
    # The round trip the reviewer named: a validated Candidate carries the
    # store's own earlier assignment and must be re-mergeable, because
    # validation necessarily fills in generation and id and there is otherwise
    # no way to express "I have no opinion".
    live = R.validate_candidate({**raw(), "generation": 1})
    assert R.merge(s, live) is R.MergeDecision.APPENDED, \
        "a validated candidate could not be re-merged: generation reads as an " \
        "assertion when it is store state"
    assert R.merge(s, live) is R.MergeDecision.DEDUPED
    _count("P20 generation orders", pairs)


def _merge_expecting_refusal(s: R.FactStore, gen: int) -> None:
    """Merge a candidate stating ``gen``; a wrong statement must be refused, and
    a refusal must leave the store untouched so the two orders still agree."""
    before = R.canonical_document(s)
    try:
        R.merge(s, {**raw(), "generation": gen})
    except R.SchemaError:
        assert R.canonical_document(s) == before, \
            "a refused merge mutated the store"


def _distinct_evidence() -> List[Any]:
    """Evidence values that are pairwise **different facts**.

    Every pair here encoded identically under the shipped canonicaliser, which
    matters because the observation union is keyed by that digest: distinct
    evidence was silently discarded as a duplicate.
    """
    return [
        {"a": "1"},
        {"a": 1},
        {"a": True},
        {"a": None},
        {"a": "b64:eA=="},          # the string that collided with b"x"
        {"a": b"x"},
        {"a": b""},
        {"a": ""},
        {"a": ["1"]},
        {"a": [1]},
        {"a": {"b": "1"}},
        {"a": "1", "b": "2"},
        {"b": "1", "a": "2"},
    ]


def prop_P21_canonicalisation_is_injective() -> None:
    """Round-3 finding 3.  Distinct values encode distinctly; equal values encode
    identically regardless of insertion order.

    Canonicalisation is the foundation every digest rests on, so a collision
    there is not a cosmetic bug: it makes ``_merge_observations`` drop evidence
    and makes equal mappings hash differently depending on how they were built.
    """
    seen: Dict[str, Any] = {}
    for value in _distinct_evidence():
        enc = R.canonical(value)
        assert enc not in seen, (
            f"canonicalisation collision: {value!r} and {seen[enc]!r} both "
            f"encode as {enc} -- distinct evidence is indistinguishable, so the "
            "observation union discards one of them"
        )
        seen[enc] = value

    # Order-independence: equal mappings, different insertion orders.
    for keys in itertools.permutations(("a", "b", "c")):
        built = {k: k.upper() for k in keys}
        assert R.canonical(built) == R.canonical({"a": "A", "b": "B", "c": "C"}), \
            "canonical bytes depend on insertion order"

    # A non-string key is refused rather than coerced, and the reserved bytes tag
    # cannot be spoofed by a real mapping.
    for hostile in ({1: "a"}, {None: "a"}, {(1, 2): "a"}, {R._BYTES_TAG: "spoof"}):
        try:
            R.canonical(hostile)
        except R.SchemaError:
            pass
        else:
            raise AssertionError(
                f"canonical accepted {hostile!r}; a coerced or spoofable key is "
                "a digest collision waiting to happen")
    _count("P21 distinct evidence values", len(seen))


def _pinned_store() -> Tuple[R.FactStore, R.Candidate, R.Candidate]:
    """A store with two candidates for KEY and one for another key."""
    s = store_of(raw(), raw(value=80, method="m2"))
    a, b = s.candidates(KEY)
    R.merge(s, raw(key="libc.base", scope=R.Scope.PROCESS, value=0x7f0000000000,
                   method="m3"))
    return s, a, b


def _forged_log_records(s: R.FactStore, a: R.Candidate, b: R.Candidate):
    """Well-shaped-but-false lifecycle records, with the rule each one breaks."""
    other = s.candidates("libc.base")[0]
    good = dict(cls="pin", key=KEY, candidate_id=a.id, at="t1", seq=99,
                actor="op", reason="why")
    return [
        ("names no candidate", {**good, "candidate_id": "f_" + "e" * 32}),
        ("cross-key target", {**good, "candidate_id": other.id}),
        ("integer candidate id", {**good, "candidate_id": 7}),
        ("unknown key", {**good, "key": "no.such.key"}),
        ("empty reason", {**good, "reason": ""}),
        ("empty actor", {**good, "actor": ""}),
        ("pin carrying a replacement", {**good, "by_candidate_id": b.id}),
        ("unpin naming a candidate", {**good, "cls": "unpin"}),
        ("supersede with no replacement", {**good, "cls": "supersede"}),
        ("supersede naming itself twice",
         {**good, "cls": "supersede", "by_candidate_id": a.id}),
        ("supersede of an active candidate",
         {**good, "cls": "supersede", "by_candidate_id": b.id}),
        ("retract of an active candidate", {**good, "cls": "retract"}),
        ("unknown class", {**good, "cls": "unretract"}),
        ("seq zero", {**good, "seq": 0}),
        ("boolean seq", {**good, "seq": True}),
        ("not a PinRecord", None),
    ]


def prop_P22_the_log_is_referentially_sound() -> None:
    """Round-3 finding 5 and I7/I8.  A forged log record is refused at write
    **and** at read, and a terminal state with no record is refused.

    Shape was not enough: a well-formed record naming a candidate that does not
    exist, or one filed under another key, or a ``supersede`` with no
    replacement, all passed -- and ``resolve`` honoured the resulting pin, which
    is the one mechanism by which an assertion may beat a measurement.
    """
    checked = 0
    for label, fields in _forged_log_records(*_pinned_store()):
        s, a, b = _pinned_store()
        record = "not a record" if fields is None else R.PinRecord(**fields)
        s.resolutions.append(record)
        for reader, call in (
            ("validate_store", lambda: R.validate_store(s)),
            ("current_pins", lambda: R.current_pins(s)),
            ("resolve", lambda: R.resolve(s, KEY, CTX)),
            ("canonical_document", lambda: R.canonical_document(s)),
        ):
            try:
                call()
            except R.SchemaError:
                continue
            except Exception as exc:  # noqa: BLE001 - wrong type is the failure
                raise AssertionError(
                    f"{reader} raised {type(exc).__name__} for a forged record "
                    f"({label}); a malformed log must be a SchemaError, not an "
                    "arbitrary exception from inside a regex"
                ) from exc
            raise AssertionError(
                f"{reader} accepted a forged log record ({label}); the record "
                "that grants an override is not checked where it is honoured"
            )
        checked += 1

    # I8: a terminal state nobody logged.  This is the converse direction --
    # without it the log could be complete and the candidates still lie.
    for state in (R.State.RETRACTED, R.State.SUPERSEDED):
        s, a, _b = _pinned_store()
        s._replace(a, dataclasses.replace(a, state=state))
        with pytest.raises(R.SchemaError):
            R.validate_store(s)
        checked += 1

    # The controls: the real writers produce records that pass, so the checks
    # above are not simply rejecting everything.
    s, a, b = _pinned_store()
    R.pin(s, KEY, a.id, "t1", "operator chose it", "op")
    assert R.current_pins(s) == {KEY: a.id}
    R.unpin(s, KEY, "t2", "changed my mind", "op")
    assert R.current_pins(s) == {}
    R.supersede(s, a.id, b.id, "t3", "better measurement", "op")
    R.validate_store(s)
    assert s.by_id(a.id).state is R.State.SUPERSEDED
    _count("P22 forged log records", checked)


def prop_P23_public_lists_are_validated() -> None:
    """Round-3 finding 6 and I9/I1.  The conflict list and the candidates
    themselves are validated, not merely the log.

    ``store.conflicts`` is as public as ``store.resolutions`` and was checked
    nowhere, so a malformed entry survived a conflict-free merge and surfaced
    later out of ``canonical_document`` -- far from whatever put it there.  And
    I1 only asserted that validation *did not raise*, ignoring the normalised
    candidate it returns, so unsorted or duplicated observations -- which sit
    outside the id digest, where I2 cannot see them -- passed while still
    changing the bytes.
    """
    checked = 0
    s0, a0, b0 = _pinned_store()
    other = s0.candidates("libc.base")[0]
    good_ids = tuple(sorted((a0.id, b0.id)))
    bad_conflicts = [
        ("not a Conflict", "nope"),
        ("class is a string",
         R.Conflict(KEY, "equally_specific", good_ids)),
        ("unknown key",
         R.Conflict("no.such.key", R.ConflictClass.EQUALLY_SPECIFIC, good_ids)),
        ("one candidate",
         R.Conflict(KEY, R.ConflictClass.EQUALLY_SPECIFIC, (a0.id,))),
        ("unsorted ids",
         R.Conflict(KEY, R.ConflictClass.EQUALLY_SPECIFIC,
                    tuple(reversed(good_ids)))),
        ("same id twice",
         R.Conflict(KEY, R.ConflictClass.EQUALLY_SPECIFIC, (a0.id, a0.id))),
        ("dangling id",
         R.Conflict(KEY, R.ConflictClass.EQUALLY_SPECIFIC,
                    tuple(sorted((a0.id, "f_" + "e" * 32))))),
        ("cross-key id",
         R.Conflict(KEY, R.ConflictClass.EQUALLY_SPECIFIC,
                    tuple(sorted((a0.id, other.id))))),
    ]
    for label, entry in bad_conflicts:
        s, _a, _b = _pinned_store()
        s.conflicts.append(entry)
        for reader, call in (("validate_store", lambda: R.validate_store(s)),
                            ("canonical_document", lambda: R.canonical_document(s))):
            try:
                call()
            except R.SchemaError:
                continue
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"{reader} raised {type(exc).__name__} for a malformed "
                    f"conflict ({label}) rather than SchemaError") from exc
            raise AssertionError(
                f"{reader} accepted a malformed conflict record ({label})")
        checked += 1

    # A duplicate, and an out-of-order list: both change the document bytes.
    s, a, b = _pinned_store()
    existing = list(s.conflicts)
    if existing:
        s.conflicts.append(existing[0])
        with pytest.raises(R.SchemaError):
            R.validate_store(s)
        checked += 1

    # I1 as equality: observations are outside the id digest, so only
    # normalisation-equality can see these.
    for label, obs in (
        ("duplicate observations",
         (R.Observation("t1"), R.Observation("t1"))),
        ("unsorted observations",
         (R.Observation("t2"), R.Observation("t1"))),
    ):
        s, a, _b = _pinned_store()
        s._replace(a, dataclasses.replace(a, observations=obs))
        try:
            R.validate_store(s)
        except R.SchemaError:
            checked += 1
        else:
            raise AssertionError(
                f"validate_store accepted {label}; I1 checks only that "
                "validation did not raise, so it ignores the normalised form it "
                "is handed and the document bytes can still change")
    _count("P23 malformed public entries", checked)


def prop_P24_supersede_requires_the_same_proposition() -> None:
    """Round-3 finding 7.  A supersession replaces a fact about the same subject.

    Matching only the key let a candidate about another identity, process, boot
    or mutually exclusive condition set supersede an unrelated fact, silently
    destroying something still true.
    """
    variants = [
        ("identity", dict(identity="t_other")),
        ("conditions", dict(conditions=CONDITION_MAPS[1])),
        ("mutually exclusive conditions", dict(conditions=CONDITION_MAPS[2])),
    ]
    checked = 0
    for label, kwargs in variants:
        s = store_of(raw(), raw(value=80, method="m2", **kwargs))
        target = next(c for c in s.candidates(KEY) if c.value == 72)
        replacement = next(c for c in s.candidates(KEY) if c.value == 80)
        try:
            R.supersede(s, target.id, replacement.id, "t2", "replacing", "op")
        except R.StateTransitionError as exc:
            assert "same proposition" in str(exc), str(exc)
        else:
            raise AssertionError(
                f"a candidate differing in {label} superseded an unrelated fact; "
                "a still-valid measurement was destroyed silently")
        assert s.by_id(target.id).state is R.State.ACTIVE, \
            "the refused supersession still changed a state"
        checked += 1

    # Scope is covered on a key that allows two scopes, since I4 forbids
    # building the cross-scope pair on a build-only key at all.
    s = R.FactStore()
    R.merge(s, raw(key="env.aslr", scope=R.Scope.HOST, value="off", method="m1"))
    R.merge(s, raw(key="env.aslr", scope=R.Scope.BOOT, value="on", method="m2"))
    host_c = next(c for c in s.candidates("env.aslr")
                  if c.applies_to.scope is R.Scope.HOST)
    boot_c = next(c for c in s.candidates("env.aslr")
                  if c.applies_to.scope is R.Scope.BOOT)
    with pytest.raises(R.StateTransitionError):
        R.supersede(s, host_c.id, boot_c.id, "t3", "replacing", "op")
    checked += 1

    # The control that makes the refusals meaningful: same proposition, and it
    # must succeed.
    s = store_of(raw(), raw(value=80, method="m2"))
    target = next(c for c in s.candidates(KEY) if c.value == 72)
    replacement = next(c for c in s.candidates(KEY) if c.value == 80)
    R.supersede(s, target.id, replacement.id, "t2", "better run", "op")
    assert s.by_id(target.id).state is R.State.SUPERSEDED, \
        "a legitimate same-proposition supersession was refused"
    _count("P24 supersede refusals", checked)


def prop_P25_conflict_views_are_one_notion() -> None:
    """Round-3 finding 8.  The stored list, the context-free view and the
    context-sensitive view are nested views of one relation -- and every refusal
    ``resolve`` makes is reported by that relation.

    Two holes: equal encodings across identities made ``resolve`` refuse while
    ``classify_pair`` returned ``None``, so the refusal appeared in no report at
    all; and pairs no context could ever make jointly applicable were recorded as
    conflicts nobody can encounter.
    """
    pool_raw = [
        raw(value=72),
        raw(value=72, identity="t_other", method="m2"),      # equal, other subject
        raw(value=80, method="m3"),
        raw(value=80, conditions=CONDITION_MAPS[1], method="m4"),
        raw(value=75, conditions=CONDITION_MAPS[2], method="m5"),  # argv vs stdin
    ]
    contexts = _resolve_contexts()
    checked = 0
    for size in range(1, MAX_STORE + 1):
        for batch in itertools.combinations(pool_raw, size):
            s = store_of(*batch)
            free = set(R.context_free_conflicts(s))
            stored = set(s.conflicts)
            assert free <= stored, (
                f"merge did not record every context-free conflict: "
                f"{free - stored}")
            for ctx in contexts:
                ctx_conflicts = set(R.conflicts(s, ctx))
                assert ctx_conflicts <= free, (
                    "a context-sensitive conflict is not context-free-visible: "
                    f"{ctx_conflicts - free}")
                # Every refusal is *reported*.  This is the half that was missing.
                try:
                    R.resolve(s, KEY, ctx)
                except R.FactUnresolved as exc:
                    reported = {c.cls for c in free if c.key == KEY}
                    assert exc.conflict_class in reported, (
                        f"resolve refused with {exc.conflict_class.value} but no "
                        f"conflict record mentions it (recorded: "
                        f"{sorted(c.value for c in reported)}); the operator has "
                        "no record of why resolution failed")
                except (R.FactUnavailable, R.FactStale, R.PinInapplicable):
                    pass
                except Exception as exc:  # noqa: BLE001 - part of the property
                    # A classifier with a hole makes ``resolve`` unable to *name*
                    # the conflict it is refusing, and an unnameable refusal is
                    # not one of the declared exits.  Reported as this property
                    # failing rather than as a crash, so the diagnosis points at
                    # the classifier and not at the arithmetic that noticed.
                    raise AssertionError(
                        f"resolve neither selected nor declared a refusal: "
                        f"{type(exc).__name__}({exc}). The pool disagrees but "
                        "classify_pair reports nothing for it, so there is no "
                        "class to refuse with -- that is the reporting hole, seen "
                        "from resolve's side."
                    ) from exc
                checked += 1

    # Mutually exclusive pairs are not conflicts anybody can encounter.
    s = store_of(raw(value=72, conditions=CONDITION_MAPS[1]),
                 raw(value=80, conditions=CONDITION_MAPS[2], method="m2"))
    assert not R.context_free_conflicts(s), (
        "a pair that no context can make jointly applicable was reported as a "
        f"conflict: {R.context_free_conflicts(s)}")
    a, b = s.candidates(KEY)
    assert not R.jointly_satisfiable(a, b)
    # ... and the near-miss control: same condition *name and value* on one side
    # only is still jointly satisfiable, so it must still be reported.
    s2 = store_of(raw(value=72), raw(value=80, conditions=CONDITION_MAPS[1],
                                     method="m2"))
    assert R.context_free_conflicts(s2), \
        "joint satisfiability is over-filtering: a reachable disagreement went " \
        "unreported"
    _count("P25 conflict-view checks", checked)


def _malformed_contexts() -> List[Tuple[str, Any]]:
    return [
        ("identities is None", dataclasses.replace(CTX, identities=None)),
        ("identities holds an int",
         dataclasses.replace(CTX, identities=frozenset({1}))),
        ("identities holds an empty string",
         dataclasses.replace(CTX, identities=frozenset({""}))),
        ("identities is a list", dataclasses.replace(CTX, identities=["t_main"])),
        ("conditions is a short pair",
         dataclasses.replace(CTX, conditions=(("a",),))),
        ("conditions value is an int",
         dataclasses.replace(CTX, conditions=(("a", 1),))),
        ("conditions is an int", dataclasses.replace(CTX, conditions=7)),
        ("duplicate condition names",
         dataclasses.replace(CTX, conditions=(("a", "x"), ("a", "y")))),
        ("host_id is an int", dataclasses.replace(CTX, host_id=7)),
        ("process_id is empty", dataclasses.replace(CTX, process_id="")),
        ("unknown identity_mode",
         dataclasses.replace(CTX, identity_mode="loose")),
        ("capitalised identity_mode",
         dataclasses.replace(CTX, identity_mode="None")),
        ("not a context at all", {"identities": ["t_main"]}),
    ]


def prop_P26_resolve_is_total_over_contexts() -> None:
    """Round-3 finding 9.  Every exit from ``resolve`` is a ``Selected``, one of
    the five declared refusals, or a ``SchemaError`` for a malformed context.

    The claim used to be false: ``identities=None`` leaked ``TypeError`` out of
    ``applicable``, a bad condition pair leaked ``ValueError`` out of ``dict()``,
    and an unknown ``identity_mode`` leaked nothing at all -- it silently meant
    strict, discarding the operator's intent without a word.  P6 quantified over
    one well-formed context, so it could not see any of this.
    """
    s = store_of(raw(), raw(value=80, method="m2"))
    checked = 0
    for label, ctx in _malformed_contexts():
        for fn_name, call in (("resolve", lambda c=ctx: R.resolve(s, KEY, c)),
                              ("conflicts", lambda c=ctx: R.conflicts(s, c)),
                              ("agreements", lambda c=ctx: R.agreements(s, c))):
            try:
                call()
            except R.SchemaError:
                continue
            except Exception as exc:  # noqa: BLE001 - the wrong type IS the bug
                raise AssertionError(
                    f"{fn_name} leaked {type(exc).__name__} ({exc}) for a "
                    f"malformed context ({label}); the declared exit list is "
                    "wrong, so a caller cannot tell bad input from a bug"
                ) from exc
            raise AssertionError(
                f"{fn_name} silently accepted a malformed context ({label}); "
                "an unknown identity_mode that reads as strict discards the "
                "operator's intent without saying so")
        checked += 1
    # The control: every well-formed context is accepted.
    for ctx in _resolve_contexts():
        R.validate_context(ctx)
    _count("P26 malformed contexts", checked)


def _store_mutilations():
    """One store-breaking edit per invariant: the positive controls.

    Every entry in ``R.STORE_INVARIANTS`` asserts that something is **absent**,
    and absence-assertions are exactly the checks this project keeps finding
    cannot fail.  So each is paired with an edit that makes the absent thing
    present, and the invariant must name itself in the refusal.
    """
    def i1(s):
        c = s.candidates(KEY)[0]
        s._replace(c, dataclasses.replace(
            c, observations=(R.Observation("t2"), R.Observation("t1"))))

    def i2(s):
        # A hand-set id that is not a function of the content.  Caught inside
        # ``validate_candidate``, which is where the rule lives -- the duplicate
        # probe that used to sit in ``validate_store`` could never fire.
        c = s.candidates(KEY)[0]
        s._replace(c, dataclasses.replace(c, id="f_" + "a" * 32))

    def i2b(s):
        c = s.candidates(KEY)[0]
        other = s.candidates("libc.base")[0]
        s._bucket(KEY).append(other)

    def i3(s):
        c = s.candidates(KEY)[0]
        sibling = dataclasses.replace(c, generation=c.generation + 1)
        s._bucket(KEY).append(dataclasses.replace(
            sibling, id=R.derive_id(sibling)))

    def i4(s):
        c = s.candidates(KEY)[0]
        moved = dataclasses.replace(
            c, applies_to=dataclasses.replace(c.applies_to, scope=R.Scope.HOST,
                                              binding="h1"))
        s._replace(c, dataclasses.replace(moved, id=R.derive_id(moved)))

    def i5b(s):
        # Reachable through the public API: ``spec_for`` checks that a ref's key
        # *exists*, not that it is the key the named candidate is filed under.
        other = s.candidates("libc.base")[0]
        R.merge(s, raw(value=123, method="derived",
                       provenance=R.Provenance.DERIVED,
                       derived_from=[{"key": "libc.system_offset",
                                      "id": other.id,
                                      "digest": R.candidate_digest(other)}]))

    def i6(s):
        # A *terminal* candidate duplicated, so I3 -- which considers only active
        # candidates -- steps aside and I6 is the invariant actually on trial.
        # Duplicating an active one trips I3 first, which would have made this a
        # control for the wrong rule.
        c = s.candidates(KEY)[0]
        R.retract(s, c.id, "t2", "wrong", "op")
        s._bucket(KEY).append(s.by_id(c.id))

    def i7(s):
        s.resolutions.append(R.PinRecord(
            cls="pin", key=KEY, candidate_id="f_" + "e" * 32, at="t1", seq=99,
            actor="op", reason="forged"))

    def i8(s):
        c = s.candidates(KEY)[0]
        s._replace(c, dataclasses.replace(c, state=R.State.RETRACTED))

    def i9(s):
        s.conflicts.append("not a conflict")

    # I5 is deliberately absent: a cycle cannot be *put into* a store, because
    # ids are content-derived, so any store-level attempt is rejected by I1/I2
    # before the acyclicity walk runs -- which is exactly the vacuity round 3
    # found in the old cycle test.  Its control lives in
    # ``_assert_cycle_detector_fires``, which feeds the detector directly.
    return {"I1": i1, "I2": i2, "I2b": i2b, "I3": i3, "I4": i4,
            "I5b": i5b, "I6": i6, "I7": i7, "I8": i8, "I9": i9}


def prop_P27_every_invariant_has_a_positive_control() -> None:
    """Each declared store invariant can be made to fail, and says which it was.

    Without this, ``validate_store`` is ten assertions of absence that nobody has
    ever seen go red -- the exact shape of the nine validation-that-cannot-fail
    defects already recorded in this project.  The cycle check is the sharpest
    case: cycles are *unconstructible* through the public API because ids are
    content-derived, so the only honest way to test the detector is to hand it a
    cycle built by hand.
    """
    mutilations = _store_mutilations()
    controlled = set(mutilations) | {"I5"}      # I5's control is the direct one
    assert controlled == set(R.STORE_INVARIANTS), (
        "an invariant has no positive control: "
        f"{set(R.STORE_INVARIANTS) - controlled}"
    )
    _assert_cycle_detector_fires()              # I5
    for name, mutilate in sorted(mutilations.items()):
        s, _a, _b = _pinned_store()
        R.validate_store(s)                 # the store starts valid
        # The violation may be refused at the write (a transactional writer sees
        # it immediately) or survive into the store and be caught by the next
        # ``validate_store``.  Both prove the invariant fires; which one happens
        # is a property of the path, not of the invariant.
        raised: List[R.SchemaError] = []
        try:
            mutilate(s)
        except R.SchemaError as exc:
            raised.append(exc)
        if not raised:
            try:
                R.validate_store(s)
            except R.SchemaError as exc:
                raised.append(exc)
        if not raised:
            raise AssertionError(
                f"invariant {name} did not fire on a store that violates it; it "
                "is an assertion of absence that cannot fail")
        assert str(raised[0]).startswith(name + " "), (
            f"{name}'s control tripped a different invariant: {raised[0]}")
    _count("P27 invariants controlled", len(controlled))


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
    "P20": prop_P20_generation_is_store_assigned,
    "P21": prop_P21_canonicalisation_is_injective,
    "P22": prop_P22_the_log_is_referentially_sound,
    "P23": prop_P23_public_lists_are_validated,
    "P24": prop_P24_supersede_requires_the_same_proposition,
    "P25": prop_P25_conflict_views_are_one_notion,
    "P26": prop_P26_resolve_is_total_over_contexts,
    "P27": prop_P27_every_invariant_has_a_positive_control,
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


def test_value_domain_keeps_the_deleted_canonical_gate_dead() -> None:
    """The tripwire for a gate that was **deleted** for being unable to fail.

    ``_validate_candidate`` used to probe ``canonical(candidate.value)`` after
    the per-key type check had already restricted every value to ``int``,
    ``bool`` or ``str`` -- none of which ``canonical`` can reject.  Round-3
    finding 4 named it, and it was deleted rather than defended.

    Deleting a check silently is its own hazard, so this test states the
    condition under which the deletion is safe.  The moment the registry admits
    a value type ``canonical`` could refuse -- ``bytes``, a list, a nested
    mapping -- this goes red and the check must come back.
    """
    canonicalisable_scalars = {int, bool, str}
    declared = {spec.value_type for spec in R.FACT_KEYS.values()}
    declared |= {spec.value_type for spec in R._FACT_PREFIXES.values()}
    assert declared <= canonicalisable_scalars, (
        f"the registry now admits {sorted(t.__name__ for t in declared - canonicalisable_scalars)}, "
        "which canonical() can reject -- restore the per-candidate "
        "canonical(value) check in _validate_candidate, because it is no longer "
        "dead code"
    )
    # And the reason it cannot fail: every admitted type round-trips.
    for value_type in sorted(declared, key=lambda ty: ty.__name__):
        R.canonical(_probe_value(value_type))
    # Evidence, by contrast, is an *open* domain -- so the canonical() call that
    # guards it is live, and here is the proof it can still refuse.
    with pytest.raises(R.SchemaError):
        R.canonical({"k": 1.5})


def test_resolve_priority_covers_every_classifiable_conflict() -> None:
    """``resolve`` picks the class it reports from ``CONFLICT_PRIORITY``.

    It used to walk a hard-coded list of three and fall through to a literal
    ``INCOMPARABLE``, so a class added later would have been silently
    mislabelled -- reported as incomparable when it was something else.  The
    fallback is gone, which is only safe if the map is total over what
    ``classify_pair`` can return.
    """
    returnable = set(R.ConflictClass) - {
        # merge-time classes: recorded against a terminal sibling, never
        # produced by classify_pair and never a resolution outcome.
        R.ConflictClass.REOBSERVED_AFTER_RETRACTION,
        R.ConflictClass.REOBSERVED_AFTER_SUPERSESSION,
    }
    assert returnable <= set(R.CONFLICT_PRIORITY), (
        "classify_pair can return a class resolve has no priority for: "
        f"{sorted(c.value for c in returnable - set(R.CONFLICT_PRIORITY))}"
    )
    assert len(set(R.CONFLICT_PRIORITY.values())) == len(R.CONFLICT_PRIORITY), \
        "two classes share a priority, so which one resolve reports is arbitrary"

    # Every class in the map is reachable from classify_pair -- a priority for a
    # class nothing produces is a rule about nothing.
    produced = set()
    universe = order_universe()
    for a in universe:
        # Same subject, different value: the only way to reach EQUALLY_SPECIFIC,
        # since every *distinct* member of the universe differs in some ordered
        # component.  Excluding the self-pair is what hid that class.
        cls = R.classify_pair(dataclasses.replace(a, value=99), a)
        if cls is not None:
            produced.add(cls)
        for b in universe:
            if a is b:
                continue
            for left, right in ((a, b), (dataclasses.replace(a, value=99), b)):
                cls = R.classify_pair(left, right)
                if cls is not None:
                    produced.add(cls)
    missing = set(R.CONFLICT_PRIORITY) - produced
    assert not missing, (
        "CONFLICT_PRIORITY names classes classify_pair never produces: "
        f"{sorted(c.value for c in missing)}"
    )


# ===========================================================================
# Narrowness annotations.
#
# Round 3 taught the lesson this table exists for: **seven of its nine HIGH
# findings were invisible to this suite rather than absent from it.**  The
# properties ran hundreds of cases each and held the one dimension that mattered
# constant -- every P2 fixture carried the same ``generation``, P6 had a single
# ``ResolveContext``, P5's universe held three of six scopes.  That is a
# different failure mode from a test that asserts nothing, and a worse one:
# case counts and pass counts both look healthy, so **narrowness reads exactly
# like correctness.**
#
# So every property declares which dimensions its input set *varies* and which
# it deliberately *holds constant*.  The meta-tests below then check the claims
# that are mechanically checkable -- that the vocabulary is closed, that nothing
# is both varied and held, and that no dimension is left unvaried by every
# property in the suite.  What they cannot check is whether a declaration is
# **true**; that is a reading task, and the annotation exists to make it a
# 29-claim review instead of a 29-property excavation.
# ===========================================================================

#: The closed vocabulary.  A dimension named in no property's ``varies`` is a
#: dimension of the schema that nothing in the suite exercises -- which is the
#: P27 trick applied one level up, at breadth rather than at invariants.
DIMENSIONS: Tuple[str, ...] = (
    # candidate content
    "value", "provenance", "identity", "scope", "binding", "conditions",
    "method", "by", "observation_at", "evidence", "derived_from", "state",
    "generation", "candidate_id",
    # store shape
    "store_size", "arrival_order", "dedup_collision", "terminal_sibling",
    "dependency_depth", "log_record_shape", "log_record_count",
    "conflict_record_shape", "fact_key",
    # resolve context
    "context_identities", "context_identity_mode", "context_conditions",
    "context_binding",
)

#: ``dimension -> the single property that varies it``, filled in by the breadth
#: meta-test below and printed with the enumeration bounds.  Not an assertion: a
#: dimension with one claimant is a single point of failure for that dimension,
#: and the point is that it is *visible* in every run rather than rediscovered.
SOLO_DIMENSIONS: Dict[str, str] = {}

#: ``pid -> (varies, holds_constant)``.  ``holds_constant`` lists only the
#: dimensions a reader might reasonably expect this property to vary -- it is an
#: admission, not an inventory of everything the fixture happens to fix.
NARROWNESS: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "P1": (("value", "provenance", "method", "observation_at", "conditions",
            "identity", "store_size", "dedup_collision", "terminal_sibling",
            "state"),
           ("scope", "binding", "generation", "fact_key", "arrival_order")),
    "P1b": (("value", "provenance", "scope", "identity", "conditions", "method",
             "observation_at", "evidence", "derived_from", "state", "generation",
             "candidate_id", "fact_key"),
            ("arrival_order", "store_size")),
    "P2": (("value", "provenance", "method", "by", "observation_at",
            "conditions", "identity", "arrival_order", "store_size",
            "terminal_sibling", "derived_from", "log_record_count"),
           # generation is P20's job precisely because P2 could not see it.
           ("generation", "scope", "fact_key")),
    "P3": ((),
           # Deliberately declared empty: P3 is a single fixture merged twice.
           ("value", "provenance", "scope", "conditions", "identity",
            "store_size", "fact_key", "observation_at")),
    "P4": (("provenance",),
           ("value", "scope", "identity", "conditions")),
    "P5": (("scope", "provenance", "identity", "conditions"),
           ("value", "binding", "fact_key")),
    "P5b": (("value", "method", "by", "observation_at", "state", "candidate_id",
             "provenance", "identity", "scope", "conditions"),
            ("fact_key",)),
    "P6": (("value", "provenance", "identity", "conditions", "store_size",
            "context_identities", "context_identity_mode", "context_conditions",
            "context_binding"),
           ("scope", "generation", "fact_key", "arrival_order")),
    "P7": (("value", "provenance", "arrival_order", "store_size"),
           ("scope", "identity", "conditions", "context_identities",
            "context_identity_mode", "fact_key")),
    "P8": (("value", "provenance", "store_size"),
           ("scope", "identity", "conditions", "context_identities", "fact_key")),
    "P9": (("scope", "identity", "conditions", "provenance", "fact_key",
            "binding"),
           ("value", "arrival_order", "context_identity_mode")),
    "P10": (("value", "provenance", "identity", "scope", "conditions", "method",
             "by", "observation_at", "state", "generation", "derived_from",
             "candidate_id"),
            ("fact_key",)),
    "P11": (("state",),
            ("value", "fact_key")),
    "P12": (("fact_key",),
            ("value", "provenance", "scope", "context_identities")),
    "P13": (("value", "provenance", "identity", "conditions", "store_size"),
            ("scope", "context_identities", "context_identity_mode",
             "context_conditions", "fact_key", "arrival_order")),
    "P14": (("provenance", "arrival_order"),
            ("value", "scope", "identity", "conditions", "store_size",
             "fact_key")),
    "P15": (("provenance", "scope", "state", "fact_key"),
            ("value", "identity", "conditions")),
    "P16": (("log_record_shape", "log_record_count", "observation_at",
             "arrival_order", "value"),
            ("fact_key", "provenance", "scope", "state")),
    "P17": (("dependency_depth", "state", "derived_from", "fact_key"),
            ("value", "provenance", "scope", "identity", "conditions")),
    "P18": (("observation_at",),
            ("value", "provenance", "scope", "identity", "conditions",
             "fact_key")),
    "P19": (("identity", "context_identity_mode"),
            ("value", "provenance", "scope", "conditions", "store_size",
             "fact_key")),
    "P20": (("generation", "arrival_order", "terminal_sibling", "candidate_id"),
            ("value", "provenance", "scope", "identity", "conditions",
             "fact_key")),
    "P21": (("evidence",),
            ("value", "provenance", "scope", "fact_key")),
    "P22": (("log_record_shape", "state", "fact_key", "candidate_id"),
            ("value", "provenance", "scope", "identity", "conditions",
             "log_record_count")),
    "P23": (("conflict_record_shape", "observation_at", "candidate_id",
             "fact_key"),
            ("value", "provenance", "scope", "identity", "conditions")),
    "P24": (("identity", "conditions", "scope", "fact_key"),
            ("value", "provenance", "binding", "generation", "store_size")),
    "P25": (("value", "identity", "conditions", "store_size",
             "context_identities", "context_identity_mode",
             "context_conditions", "context_binding"),
            ("scope", "provenance", "binding", "fact_key")),
    "P26": (("context_identities", "context_identity_mode",
             "context_conditions", "context_binding"),
            ("value", "provenance", "scope", "store_size", "fact_key")),
    "P27": (("state", "generation", "derived_from", "log_record_shape",
             "conflict_record_shape", "scope", "candidate_id", "fact_key"),
            ("value", "provenance", "identity", "conditions")),
}


def test_every_property_declares_what_it_varies() -> None:
    """Every property carries a narrowness annotation drawn from the closed
    vocabulary, and nothing is claimed both ways."""
    assert set(NARROWNESS) == set(PROPERTIES), (
        "annotation and property set disagree: "
        f"unannotated {sorted(set(PROPERTIES) - set(NARROWNESS))}, "
        f"stale {sorted(set(NARROWNESS) - set(PROPERTIES))}"
    )
    for pid, (varies, holds) in sorted(NARROWNESS.items()):
        unknown = (set(varies) | set(holds)) - set(DIMENSIONS)
        assert not unknown, (
            f"{pid} names dimensions outside the closed vocabulary: "
            f"{sorted(unknown)} -- either add them to DIMENSIONS deliberately or "
            "use the existing name, so a narrowness audit can be mechanical"
        )
        both = set(varies) & set(holds)
        assert not both, f"{pid} claims to both vary and hold {sorted(both)}"
        assert len(set(varies)) == len(varies), f"{pid} repeats a varied dimension"


def test_no_dimension_is_unvaried_by_the_whole_suite() -> None:
    """The breadth analogue of P27.

    A dimension that **no** property varies is a dimension along which this
    suite cannot fail, however many cases it runs -- which is exactly how seven
    of round 3's nine HIGH findings hid in plain sight.  If a new dimension is
    added to the schema, this fails until some property exercises it.
    """
    claimants: Dict[str, List[str]] = {d: [] for d in DIMENSIONS}
    for pid, (varies, _) in sorted(NARROWNESS.items()):
        for d in varies:
            claimants[d].append(pid)
    unvaried = sorted(d for d, who in claimants.items() if not who)
    assert not unvaried, (
        f"no property varies {sorted(unvaried)}; the suite cannot fail along "
        "that dimension no matter how many cases it runs"
    )
    # Not an assertion: a dimension with a single claimant is a single point of
    # failure for that whole dimension, so name them in the run output rather
    # than leaving them to be rediscovered by the next audit.
    solo = sorted(d for d, who in claimants.items() if len(who) == 1)
    _count("dimensions in the closed vocabulary", len(DIMENSIONS))
    _count("dimensions varied by exactly one property", len(solo))
    SOLO_DIMENSIONS.clear()
    SOLO_DIMENSIONS.update({d: claimants[d][0] for d in solo})


def test_single_fixture_properties_are_declared_as_such() -> None:
    """A property that varies nothing must say so, and be a knowingly narrow one.

    P3 (idempotence) is the honest example: it merges one fixture twice, and its
    claim genuinely does not need breadth to mean something. The point of listing
    it is that *unintended* emptiness is then visible, because any new property
    with an empty ``varies`` has to be added to this list on purpose.
    """
    knowingly_narrow = {"P3"}
    empty = {pid for pid, (varies, _) in NARROWNESS.items() if not varies}
    assert empty == knowingly_narrow, (
        f"properties varying nothing: {sorted(empty)}; expected exactly "
        f"{sorted(knowingly_narrow)}. A property with no varied dimension runs "
        "one case and reads like coverage"
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
    # Fill SOLO_DIMENSIONS here too, so this report does not silently depend on
    # collection order having run the breadth meta-test first.
    test_no_dimension_is_unvaried_by_the_whole_suite()
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
        if SOLO_DIMENSIONS:
            print("  dimensions varied by only one property "
                  "(that property is the whole coverage of it):")
            for dim in sorted(SOLO_DIMENSIONS):
                print(f"      {dim:40s} {SOLO_DIMENSIONS[dim]}")
    assert _COUNTS, "no enumeration counts were recorded"
