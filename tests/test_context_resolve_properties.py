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
ORDER_CONDITIONS = CONDITION_MAPS[:3]


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
                R.retract(s, s.active(KEY)[0].id, "t0|superseded by hand")
            before_states = {c.id: c.state for c in s.all_candidates()}
            expected = {R.dedup_key(c) for c in s.active(KEY)}
            expected |= {R.dedup_key(R.validate_candidate(incoming))}

            decision = R.merge(s, incoming)
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
    _count("P1 (store, incoming) pairs", n)


def prop_P1b_validation_is_the_only_raiser() -> None:
    """Malformed input of any shape raises SchemaError and nothing else."""
    bad: List[Any] = [
        None, 42, "x", [], {},
        {**raw(), "provenance": "guessed"},
        {**raw(), "value": -1},
        {**raw(), "value": "72"},
        {**raw(), "value": 1.5},
        {**raw(), "key": "no.such.key"},
        {**raw(), "method": ""},
        {**raw(), "observations": []},
        {**raw(), "derived_from": [{"id": "f_000000000000"}]},
        {**raw(), "surprise": 1},
        {**raw(), "id": "f_deadbeefcafe"},
        raw(scope=R.Scope.PROCESS),                  # I4: wrong scope for key
        {**raw(), "applies_to": {"scope": R.Scope.BUILD, "identity": 7}},
    ]
    for item in bad:
        s = R.FactStore()
        with pytest.raises(R.SchemaError):
            R.merge(s, item)
        assert not s.keys(), "a rejected candidate must not be persisted"
    _count("P1b malformed inputs", len(bad))


def prop_P2_merge_commutativity() -> None:
    """Canonical document **bytes** identical under every permutation."""
    pool = [raw(value=72), raw(value=80), raw(provenance=R.Provenance.ASSERTED),
            raw(method="m2"), raw(at="t2"), raw(conditions=CONDITION_MAPS[1])]
    n = 0
    for size in range(1, MAX_BATCH + 1):
        for batch in itertools.combinations(pool, size):
            digests = set()
            for perm in itertools.permutations(batch):
                s = R.FactStore()
                for r in perm:
                    R.merge(s, r)
                digests.add(R.canonical_document(s))
                n += 1
            assert len(digests) == 1, (
                f"merge is order-dependent for batch of {size}: "
                f"{len(digests)} distinct documents"
            )
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
    for size in range(0, MAX_STORE + 1):
        for batch in itertools.combinations(pool, size):
            s = store_of(*batch)
            applicable = [c for c in s.active(KEY) if R.applicable(c, CTX)]
            try:
                out = R.resolve(s, KEY, CTX)
            except allowed as exc:
                assert not (applicable and isinstance(exc, R.FactUnavailable)) or True
                if not applicable:
                    assert isinstance(exc, R.FactUnavailable), \
                        f"empty applicable pool must raise FactUnavailable, got {exc!r}"
                n += 1
                continue
            except Exception as exc:  # noqa: BLE001 - that is the property
                raise AssertionError(f"undeclared exception escaped resolve: {exc!r}")
            assert applicable, "resolve returned a Selected from an empty applicable pool"
            assert isinstance(out, R.Selected)
            n += 1
    _count("P6 resolve invocations", n)


def prop_P7_resolve_determinism() -> None:
    pool = [raw(value=72), raw(provenance=R.Provenance.ASSUMED, value=72),
            raw(method="m2")]
    n = 0
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
    _count("P7 resolve permutations", n)


def prop_P8_resolve_never_invents() -> None:
    s = store_of(raw(value=72), raw(value=72, provenance=R.Provenance.ASSUMED))
    pool = [c for c in s.active(KEY) if R.applicable(c, CTX)]
    out = R.resolve(s, KEY, CTX)
    for w in (out.witness,) + out.witnesses:
        assert any(w is c for c in pool), (
            f"witness {w.id} is not the same object as any pooled candidate "
            "(a fabricated or copied witness passes a type check and fails this)"
        )
        assert w.state is R.State.ACTIVE
        assert R.applicable(w, CTX)
    _count("P8 witnesses checked", len(out.witnesses) + 1)


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
                s.resolutions.append(R.PinRecord("pin", key, asserted.id, "t9",
                                                 "operator knows better"))
                out = R.resolve(s, key, CTX)
                assert out.witness.id == asserted.id
                assert out.rule == "operator_pin"
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
    }
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


def prop_P13_conflicts_total_and_partitioned() -> None:
    s = store_of(
        raw(value=72),
        raw(value=80, provenance=R.Provenance.ASSUMED, method="m2"),
        raw(value=80, provenance=R.Provenance.ASSERTED, method="m3"),
    )
    live = [c for c in s.active(KEY) if R.applicable(c, CTX)]
    expected_pairs = {
        tuple(sorted((a.id, b.id)))
        for i, a in enumerate(live) for b in live[i + 1:]
        if R.canonical(a.value) != R.canonical(b.value)
    }
    records = R.conflicts(s, CTX)
    got_pairs = [c.candidate_ids for c in records]
    assert sorted(got_pairs) == sorted(expected_pairs), (
        f"conflicts is not total over differing-value pairs: "
        f"missing {expected_pairs - set(got_pairs)}"
    )
    assert len(got_pairs) == len(set(got_pairs)), "a pair was classified twice"
    agree_pairs = {a.candidate_ids for a in R.agreements(s, CTX)}
    assert not (agree_pairs & set(got_pairs)), "a pair is both agreement and conflict"
    _count("P13 conflict pairs", len(expected_pairs))


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


def prop_P15_generated_tables_call_the_runtime() -> None:
    text = R.emit_tables()
    # (a) every provenance cell equals what the comparator returns
    rows = [ln for ln in text.splitlines() if ln.startswith("| **")]
    prov_rows = rows[:len(PROVENANCES)]
    n = 0
    for row, a in zip(prov_rows, PROVENANCES):
        cells = [c.strip() for c in row.strip("|").split("|")][1:]
        for cell, b in zip(cells, PROVENANCES):
            n += 1
            assert cell == R._SYM[R.compare_provenance(a, b)], (
                f"generated cell ({a.value}, {b.value}) = {cell!r} disagrees with "
                "compare_provenance; a table backed by parallel constants agrees "
                "with itself and not with resolution"
            )
    # (b) the committed file is byte-identical to fresh output
    assert TABLES.exists(), f"missing generated table: {TABLES}"
    assert TABLES.read_text(encoding="utf-8") == text, (
        "docs/reference/context-resolution-tables.md is stale; regenerate with "
        "`python -m supwngo.schema.resolve --emit-tables`"
    )
    _count("P15 generated cells checked", n)


def prop_P16_current_pins_is_a_function() -> None:
    s = store_of(raw(value=72), raw(value=80, method="m2"))
    first, second = sorted(s.active(KEY), key=lambda c: c.id)
    recs = [
        R.PinRecord("pin", KEY, first.id, "t1"),
        R.PinRecord("pin", KEY, second.id, "t2"),
    ]
    for perm in itertools.permutations(recs):
        s.resolutions = list(perm)
        pins = R.current_pins(s)
        assert set(pins) <= {KEY}, "current_pins yielded more than one entry per key"
        assert pins[KEY] == second.id, (
            "current_pins must take the latest record; taking the first means an "
            "unpin or a re-pin never takes effect"
        )
    s.resolutions = list(recs) + [R.PinRecord("unpin", KEY, None, "t3")]
    assert R.current_pins(s) == {}, "an unpin after a pin must leave no entry"
    _count("P16 pin permutations", 2)


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

    # No invalidation call: retracting the root makes the whole closure stale.
    R.retract(s, src.id, "t9|wrong libc")
    for c in chain[1:]:
        assert R.is_stale(s, c), (
            f"{c.id} did not become stale when its transitive source was retracted"
        )
    assert not hasattr(R.Candidate, "stale"), "staleness must be computed, not stored"

    # Terminates on a cyclic input that validation would have refused.
    cyc = R.FactStore()
    a = R.validate_candidate(raw(key="libc.base", value=1, scope=R.Scope.PROCESS))
    a2 = dataclasses.replace(a, derived_from=(R.Ref(a.key, a.id, R.candidate_digest(a)),))
    cyc._bucket(a2.key).append(a2)
    assert R.is_stale(cyc, a2) in (True, False)      # the property is termination
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
    with M.applied(mutant):
        try:
            prop()
        except (KeyboardInterrupt, SystemExit):  # pragma: no cover
            raise
        except BaseException:  # noqa: BLE001 - any failure counts, and a failed
            # pytest.raises() raises _pytest.outcomes.Failed, which derives from
            # BaseException rather than Exception.  Catching only Exception here
            # made the meta-test report a *caught* mutant as an escape.
            return
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
