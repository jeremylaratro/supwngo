"""Deliberately broken resolvers, each bound to the property it must break.

This project has five recorded instances of a validation step that could not
fail -- a probe driver that omitted the argument it was validating, a test
asserting ``min(a, b) == expected``.  A property test nobody has seen fail is
in that family.  So every property in
``tests/test_context_resolve_properties.py`` is paired with a named mutation of
:mod:`supwngo.schema.resolve`, and the meta-test asserts **that named property
fails** against it.  If a mutant passes, the property has no teeth and the
meta-test says so.

Every mutant below restores a defect that was actually shipped or actually
proposed: a v1/v2/v3 plan revision, or a finding from the round-1 review of v4.

Two entries have ``breaks=None`` on purpose.  They restore a genuine defect but
are *caught by the other half of a redundant pair*, so the correct assertion is
that the property still passes -- which is what demonstrates the redundancy is
load-bearing rather than decorative.
"""

from __future__ import annotations

import contextlib
import dataclasses
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence

from . import resolve as R


@dataclasses.dataclass(frozen=True)
class Mutant:
    name: str
    restores: str
    #: property id the meta-test requires to fail, or ``None`` to require that
    #: it still passes because a second mechanism catches this defect
    breaks: Optional[str]
    patches: Dict[str, Any]
    note: str = ""


@contextlib.contextmanager
def applied(mutant: Mutant) -> Iterator[None]:
    """Patch :mod:`supwngo.schema.resolve` for the duration of the block.

    Functions in that module resolve each other through module globals, so
    rebinding an attribute genuinely changes behaviour rather than only the
    name the test calls.
    """
    saved = {name: getattr(R, name) for name in mutant.patches}
    try:
        for name, value in mutant.patches.items():
            setattr(R, name, value)
        yield
    finally:
        for name, value in saved.items():
            setattr(R, name, value)


# ---------------------------------------------------------------------------
# Broken implementations
# ---------------------------------------------------------------------------


def _merge_supersedes_on_rank(store: R.FactStore, incoming: Any) -> R.MergeDecision:
    """v3 defect 1: merge picks a winner, so its predicates overlap."""
    candidate = R.validate_candidate(incoming)
    key = candidate.key
    for existing in store.active(key):
        if R.canonical(existing.applies_to) != R.canonical(candidate.applies_to):
            continue
        if R.canonical(existing.value) == R.canonical(candidate.value):
            store._replace(existing, dataclasses.replace(
                existing,
                observations=R._merge_observations(existing.observations,
                                                   candidate.observations)))
            return R.MergeDecision.DEDUPED
        order = R.compare_provenance(candidate.provenance, existing.provenance)
        if order is R.Ordering.GREATER:
            store._replace(existing, dataclasses.replace(existing,
                                                         state=R.State.SUPERSEDED))
    store._bucket(key).append(candidate)
    store._sorted(key)
    return R.MergeDecision.APPENDED


def _dedup_key_ignores_provenance(c: R.Candidate) -> str:
    """v3 defect 2: a measured 72 and an asserted 72 collapse into one."""
    fields = tuple(f for f in R.ID_DIGEST_FIELDS if f != "provenance")
    return R.canonical(c.project(fields))


def _merge_matches_terminal(store: R.FactStore, incoming: Any) -> R.MergeDecision:
    """Round-1 finding 3: folds a fresh observation into a retracted candidate,
    so a re-observed fact produces no active candidate at all."""
    candidate = R.validate_candidate(incoming)
    key = candidate.key
    dk = R.dedup_key(candidate)
    for existing in store.candidates(key):          # <-- not filtered to ACTIVE
        if R.dedup_key(existing) == dk:
            store._replace(existing, dataclasses.replace(
                existing,
                observations=R._merge_observations(existing.observations,
                                                   candidate.observations)))
            return R.MergeDecision.DEDUPED
    store._bucket(key).append(candidate)
    store._sorted(key)
    return R.MergeDecision.APPENDED


def _make_ids_not_a_function() -> Callable[[R.Candidate], str]:
    """An id that is not a *function* at all: the same candidate gets a different
    id on every call.  Invariant I2 catches this at every write, which is why the
    order-dependence mutant below has to be memoised to get past validation --
    and P10 is the property that names the defect directly."""
    counter = {"n": 0}

    def derive_id(c: R.Candidate) -> str:
        counter["n"] += 1
        return "f_" + format(counter["n"], "0%dx" % R._ID_HEX)

    return derive_id


#: Shared by the pair below: content -> id, assigned in arrival order.
_ARRIVAL_IDS: Dict[str, str] = {}


def _derive_id_by_arrival_order(c: R.Candidate) -> str:
    """Round-1 finding 4, in the only form that reaches the document: ids handed
    out by a counter as candidates *arrive*.

    Memoised on content so the id is a function (I2 is satisfied and nothing
    crashes), but the *number* depends on arrival order -- so two permutations of
    the same batch produce different ids, the candidate arrays sort differently
    and the document bytes diverge.  Both halves are needed: with I2 alone the
    defect is caught early, with the memo alone it is invisible.
    """
    key = R.canonical(c.project(R.ID_DIGEST_FIELDS))
    if key not in _ARRIVAL_IDS:
        _ARRIVAL_IDS[key] = "f_" + format(len(_ARRIVAL_IDS) + 1, "0%dx" % R._ID_HEX)
    return _ARRIVAL_IDS[key]


class _ArrivalOrderFactStore(R.FactStore):
    """Scopes the arrival counter to one store, which is what makes the order
    dependence observable across permutations rather than memoised away by the
    first one."""

    def __init__(self) -> None:
        super().__init__()
        _ARRIVAL_IDS.clear()


def _canonical_document_unsorted(store: R.FactStore) -> str:
    """Round-1 finding 4: canonical JSON does not sort arrays, so insertion
    order leaks into the document digest."""
    import json

    facts = {
        key: [{"id": c.id, "value": R._jsonable_structural(c.value),
               "provenance": c.provenance.value}
              for c in store.candidates(key)]      # <-- insertion order
        for key in store.keys()
    }
    return json.dumps({"facts": facts}, sort_keys=True, separators=(",", ":"))


class _UnsortedFactStore(R.FactStore):
    """Array order is defended on *both* sides -- the write-side sort and the
    sort in ``canonical_document``.  A mutant that removed only one would be
    masked by the other and would wrongly read as "caught"; the meta-test found
    exactly that and this is the fix.
    """

    def _sorted(self, key: str) -> None:      # noqa: D102 - deliberate no-op
        return None


def _transitions_allow_resurrection() -> Dict[Any, Any]:
    table = dict(R._TRANSITIONS)
    table[(R.State.RETRACTED, "append")] = R.State.ACTIVE
    return table


def _compare_specificity_provenance_fourth(a: R.Candidate, b: R.Candidate) -> R.Ordering:
    """The exact v4 rev-1 order that round-1 finding 5 broke: an asserted
    process-scoped 80 beats a measured build-scoped 72 on the scope component,
    never reaching the incomparability meant to prevent it."""
    for result in (
        R._compare_identity_bound(a.applies_to, b.applies_to),
        R.compare_scope(a.applies_to.scope, b.applies_to.scope),
        R.compare_conditions(a.applies_to, b.applies_to),
        R.compare_provenance(a.provenance, b.provenance),
    ):
        if result is not R.Ordering.EQUAL:
            return result
    return R.Ordering.EQUAL


def _contradiction_guard_noop(key: str, pool: Sequence[R.Candidate], pins) -> None:
    return None


def _compare_provenance_total(a: R.Provenance, b: R.Provenance) -> R.Ordering:
    """v1's rank: asserted outranks everything, so a human assertion silently
    overrides a machine measurement."""
    rank = {R.Provenance.ASSERTED: 5, R.Provenance.MEASURED: 4,
            R.Provenance.DERIVED: 3, R.Provenance.ASSUMED: 2,
            R.Provenance.UNKNOWN: 1}
    if rank[a] == rank[b]:
        return R.Ordering.EQUAL
    return R.Ordering.GREATER if rank[a] > rank[b] else R.Ordering.LESS


def _compare_specificity_ties_by_time(a: R.Candidate, b: R.Candidate) -> R.Ordering:
    """v3's "then newest ``at``": silently resolves a disagreement that two
    equally-specific authorities genuinely have."""
    base = R._compare_specificity_pristine(a, b)
    if base is not R.Ordering.EQUAL:
        return base
    if a.last_observed_at == b.last_observed_at:
        return R.Ordering.EQUAL
    return (R.Ordering.GREATER if a.last_observed_at > b.last_observed_at
            else R.Ordering.LESS)


def _candidate_digest_includes_observations(c: R.Candidate) -> str:
    """v3 defect 5: a field merge mutates sits inside the dependency digest, so
    every re-observation marks every dependent stale."""
    fields = R.DEP_DIGEST_FIELDS + ("observations",)
    return R._sha(R.canonical(c.project(fields)))


def _candidate_digest_excludes_value(c: R.Candidate) -> str:
    """The opposite failure: a digest that does not cover the value, so a
    changed value does not invalidate dependents."""
    fields = tuple(f for f in R.DEP_DIGEST_FIELDS if f != "value")
    return R._sha(R.canonical(c.project(fields)))


def _agreeing_ignores_identity(candidates: Sequence[R.Candidate]) -> bool:
    """Round-1 finding 8: two builds coinciding on 0x401234 read as agreement."""
    return len({R.canonical(c.value) for c in candidates}) == 1


def _resolve_returns_default_on_empty(store, key, ctx):
    """Absent silently representable as a value -- the ``cfi: false`` failure
    mode, one level up."""
    R.spec_for(key)
    pool = [c for c in store.active(key) if R.applicable(c, ctx)]
    if not pool:
        fake = R.Candidate(key=key, value=0, provenance=R.Provenance.ASSUMED,
                           applies_to=R.AppliesTo(None, R.Scope.BUILD),
                           method="default", by="default",
                           observations=(R.Observation("t0"),))
        return R.Selected(key, 0, fake, (fake,), "default")
    return R._resolve_pristine(store, key, ctx)


def _resolve_fabricates_witness(store, key, ctx):
    """Round-1 finding 11: a witness that is a *copy* passes a type check and
    fails an identity check."""
    chosen = R._resolve_pristine(store, key, ctx)
    clone = dataclasses.replace(chosen.witness)
    return dataclasses.replace(chosen, witness=clone, witnesses=(clone,))


def _conflicts_only_incomparable(store, ctx) -> List[R.Conflict]:
    """Round-1 finding 7: dominated contradictions are never reported."""
    return [c for c in R._conflicts_pristine(store, ctx)
            if c.cls is not R.ConflictClass.DOMINATED]


def _current_pins_first_wins(store: R.FactStore) -> Dict[str, str]:
    """Round-1 finding 7: an append-only log folded the wrong way, so an
    ``unpin`` or a re-pin never takes effect."""
    out: Dict[str, str] = {}
    for rec in store.resolutions:
        if rec.cls == "pin" and rec.key not in out and rec.candidate_id:
            out[rec.key] = rec.candidate_id
    return out


def _validate_candidate_unfunnelled(raw: Any) -> R.Candidate:
    """Round-2 finding 1: field-by-field checks with no funnel, so
    ``observations=1`` escapes as a ``TypeError`` and merge stops being total in
    its declared error type."""
    return R._validate_candidate(raw)


def _merge_observations_appends(existing, incoming):
    """Observations as a plain list concatenation: re-merging an identical
    candidate grows the array forever, so merge is no longer idempotent and the
    document bytes depend on how many times a producer ran."""
    return tuple(existing) + tuple(incoming)


def _compare_specificity_reads_value(a: R.Candidate, b: R.Candidate) -> R.Ordering:
    """Breaks the symmetry reduction the order universe depends on: if the
    composed order reads a field outside the four ordered components, enumerating
    representatives of those four is no longer exhaustive."""
    base = R._compare_specificity_pristine(a, b)
    if base is not R.Ordering.EQUAL:
        return base
    if R.canonical(a.value) == R.canonical(b.value):
        return R.Ordering.EQUAL
    return (R.Ordering.GREATER if R.canonical(a.value) > R.canonical(b.value)
            else R.Ordering.LESS)


def _resolve_always_refuses(store, key, ctx):
    """A total, deterministic resolver that is also useless.  It satisfies
    "nothing undeclared escapes" and "the answer does not depend on order", which
    is exactly why those two claims alone are not enough."""
    R.spec_for(key)
    raise R.FactUnavailable(f"{key}: refusing on principle")


def _maximal_takes_first(pool: Sequence[R.Candidate]) -> List[R.Candidate]:
    """"Sort and take the first" -- here, take the first in *bucket* order, which
    is what makes a maximal-element selection order-dependent."""
    return list(pool[:1])


def _is_stale_ignores_dead_sources(store, c, _seen=None) -> bool:
    """Staleness that checks the digest but not the source's state, so a
    retracted source leaves its dependents looking fresh and the single
    computed-staleness mechanism silently stops working."""
    seen = set() if _seen is None else _seen
    if c.id in seen:
        return False
    seen.add(c.id)
    for ref in c.derived_from:
        src = store.by_id(ref.id)
        if src is None:
            return True
        if R.candidate_digest(src) != ref.digest:
            return True
        if _is_stale_ignores_dead_sources(store, src, seen):
            return True
    return False


def _emit_tables_from_parallel_constants() -> str:
    """Round-1 finding 13: a generator that agrees with itself byte for byte
    while disagreeing with the comparators it claims to render."""
    text = R._emit_tables_pristine()
    return text.replace("| **measured** | = | ≻ | ≻ | ∥ | ≻ |",
                        "| **measured** | = | ≻ | ≻ | ≻ | ≻ |")


# Pristine references the mutants delegate to.  Captured at import so a mutant
# can reuse the real implementation for the part it is not breaking.
R._compare_specificity_pristine = R.compare_specificity
R._resolve_pristine = R.resolve
R._conflicts_pristine = R.conflicts
R._emit_tables_pristine = R.emit_tables


# --- round-3 findings ------------------------------------------------------


def _merge_generation_from_caller(store: R.FactStore, incoming: Any) -> R.MergeDecision:
    """Round-3 finding 1: take ``generation`` from the caller whenever the store
    has no terminal sibling to override it.

    This is what shipped.  It looks harmless because the id is still derived from
    the generation -- but the generation is now an *input*, so merging the same
    assertion at generation 0 and at generation 5 leaves whichever arrived first
    and reversing arrival order changes the document bytes.
    """
    candidate = R.validate_candidate(incoming)
    appended_state = R.transition(None, "append")
    if candidate.state is not appended_state:
        raise R.SchemaError("merge accepts only active candidates")
    R.validate_store(store)
    key = candidate.key
    dk = R.dedup_key(candidate)
    matches = [c for c in store.active(key) if R.dedup_key(c) == dk]
    terminal = [c for c in store.candidates(key)
                if c.state is not appended_state and R.dedup_key(c) == dk]
    if terminal:                       # only here was the store authoritative
        generation = 1 + max(c.generation for c in terminal)
        candidate = dataclasses.replace(candidate, generation=generation)
        candidate = dataclasses.replace(candidate, id=R.derive_id(candidate))
    snap = store._snapshot()
    try:
        if matches:
            existing = matches[0]
            store._replace(existing, dataclasses.replace(
                existing,
                observations=R._merge_observations(
                    existing.observations, candidate.observations)))
            store._sorted(key)
            decision = R.MergeDecision.DEDUPED
        else:
            for dead in sorted(terminal, key=lambda c: c.id):
                store._record_conflict(R.Conflict(
                    key,
                    R.ConflictClass.REOBSERVED_AFTER_RETRACTION
                    if dead.state is R.State.RETRACTED
                    else R.ConflictClass.REOBSERVED_AFTER_SUPERSESSION,
                    tuple(sorted((dead.id, candidate.id)))))
            store._bucket(key).append(candidate)
            store._sorted(key)
            decision = R.MergeDecision.APPENDED
        store._record_conflicts(R.context_free_conflicts(store, key))
        R.validate_store(store)
    except Exception:
        store._restore(snap)
        raise
    return decision


def _jsonable_coerces_keys(obj: Any) -> Any:
    """Round-3 finding 3: stringify mapping keys and prefix bytes.

    ``str(k)`` maps the distinct names ``1`` and ``"1"`` onto one key whose sort
    keys then tie, so one silently overwrites the other; and ``"b64:" + b64``
    collides with a string that happens to start ``b64:``.  Both make
    ``canonical`` non-injective, which matters because the observation union is
    keyed by exactly this digest.
    """
    import base64 as _b64
    if obj is None or isinstance(obj, (bool, int, str)):
        return obj
    if isinstance(obj, float):
        raise R.SchemaError("floats are not canonicalisable")
    if isinstance(obj, R.enum.Enum):
        return obj.value
    if isinstance(obj, bytes):
        return "b64:" + _b64.b64encode(obj).decode("ascii")
    if isinstance(obj, R.Mapping):
        return {str(k): _jsonable_coerces_keys(v)
                for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (frozenset, set)):
        return sorted((_jsonable_coerces_keys(v) for v in obj),
                      key=lambda v: R.json.dumps(v, sort_keys=True))
    if isinstance(obj, (list, tuple)):
        return [_jsonable_coerces_keys(v) for v in obj]
    if dataclasses.is_dataclass(obj):
        return {f.name: _jsonable_coerces_keys(getattr(obj, f.name))
                for f in dataclasses.fields(obj)}
    raise R.SchemaError(f"not canonicalisable: {type(obj).__name__}")


# ---------------------------------------------------------------------------
# Unit 1 (canonicalisation domain closure): the open-domain mutants, all
# bound to P21, and all sharing one shape -- ``_jsonable_open`` reimplemented
# with exactly one arm widened back to its pre-split, isinstance-based or
# unchecked form.  Each is "today's pristine behaviour" for the one arm it
# touches, per the unit-1 plan's §5 table.
# ---------------------------------------------------------------------------


def _jsonable_open_accepts_tuple(obj: Any) -> Any:
    """new ``canonical_accepts_tuple_as_list``: admit ``tuple`` and encode it
    as a list, while every other arm stays exact-type.  One type at a time,
    so P21 cannot pass by catching a different type."""
    if obj is None:
        return None
    t = type(obj)
    if t is bool or t is int or t is str:
        return obj
    if t is bytes:
        return {R._BYTES_TAG: R.base64.b64encode(obj).decode("ascii")}
    if t is dict:
        R._refuse_mapping_keys(obj)
        return {k: _jsonable_open_accepts_tuple(v) for k, v in sorted(obj.items())}
    if t is list or t is tuple:                      # <-- the defect
        return [_jsonable_open_accepts_tuple(v) for v in obj]
    raise R.SchemaError(f"not canonicalisable at an open position: {t.__name__}")


def _jsonable_open_type_only(obj: Any) -> Any:
    """``evidence_gate_type_only``, no longer ``breaks=None``: check the
    value is not a ``float`` and accept anything else, unrecursed.

    Under the old, single-function architecture this was masked -- a second,
    separately-closed encoder still refused the object downstream, so the
    property went red for the *other* layer's reason and the mutant proved
    nothing about the gate.  After the positional split there is exactly one
    function, used at both the evidence gate and the final encoding, so
    patching it here changes both: a tuple placed in evidence is no longer
    refused by anything, and ``json.dumps`` happily serialises it as an
    array indistinguishable from a real list.
    """
    if isinstance(obj, float):
        raise R.SchemaError("floats are not canonicalisable")
    return obj


def _jsonable_open_isinstance_primitives(obj: Any) -> Any:
    """The primitive half of §4b's isinstance-restored diagnosis: ``int``/
    ``bool``/``str`` dispatch via ``isinstance`` again, so an
    ``IntEnum``/``StrEnum`` member -- itself an int/str subclass -- reaches
    the primitive arm and collides with the plain value it wraps, both at
    the root and nested inside a list or mapping value."""
    if obj is None or isinstance(obj, (bool, int, str)):    # <-- the defect
        return obj
    t = type(obj)
    if t is bytes:
        return {R._BYTES_TAG: R.base64.b64encode(obj).decode("ascii")}
    if t is dict:
        R._refuse_mapping_keys(obj)
        return {k: _jsonable_open_isinstance_primitives(v)
                for k, v in sorted(obj.items())}
    if t is list:
        return [_jsonable_open_isinstance_primitives(v) for v in obj]
    raise R.SchemaError(f"not canonicalisable at an open position: {t.__name__}")


def _jsonable_open_isinstance_list(obj: Any) -> Any:
    """The container half (§8 item 14): ``list`` dispatch via ``isinstance``
    again, so a ``list`` subclass (the witness is ``EvidenceList`` in the
    property) is silently admitted rather than refused."""
    if obj is None:
        return None
    t = type(obj)
    if t is bool or t is int or t is str:
        return obj
    if t is bytes:
        return {R._BYTES_TAG: R.base64.b64encode(obj).decode("ascii")}
    if t is dict:
        R._refuse_mapping_keys(obj)
        return {k: _jsonable_open_isinstance_list(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):                                # <-- the defect
        return [_jsonable_open_isinstance_list(v) for v in obj]
    raise R.SchemaError(f"not canonicalisable at an open position: {t.__name__}")


def _jsonable_structural_bytes_tag_guards_mappings_only(obj: Any) -> Any:
    """new ``bytes_tag_guards_mappings_only`` (rev 3's original defect,
    re-bound after the positional split): the reserved bytes tag is refused
    as a *mapping key* but not as a *structural dataclass field name*, so a
    hostile dataclass can still spoof the shape real ``bytes`` encodes to."""
    if isinstance(obj, R.enum.Enum):
        return obj.value
    if obj is None:
        return None
    t = type(obj)
    if t is bool or t is int or t is str:
        return obj
    if t is bytes:
        return {R._BYTES_TAG: R.base64.b64encode(obj).decode("ascii")}
    if dataclasses.is_dataclass(obj):
        open_fields = R._STRUCTURAL_OPEN_FIELDS.get(type(obj), frozenset())
        result: Dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            # <-- the defect: no reserved-tag guard on the field name here
            value = getattr(obj, f.name)
            if f.name in open_fields:
                result[f.name] = R._jsonable_evidence_field(value)
            else:
                result[f.name] = _jsonable_structural_bytes_tag_guards_mappings_only(value)
        return result
    if t is dict:
        R._refuse_mapping_keys(obj)
        return {k: _jsonable_structural_bytes_tag_guards_mappings_only(v)
                for k, v in sorted(obj.items())}
    if t is tuple or t is list:
        return [_jsonable_structural_bytes_tag_guards_mappings_only(v) for v in obj]
    raise R.SchemaError(f"not canonicalisable at a structural position: {t.__name__}")


def _jsonable_structural_dataclass_arm_admits_subclasses(obj: Any) -> Any:
    """new ``structural_dataclass_arm_admits_subclasses``: restores
    ``dataclasses.is_dataclass(obj)`` in place of the exact-type
    ``_STRUCTURAL_DATACLASSES`` registry check. ``is_dataclass`` also admits
    any SUBCLASS of a registered type, which then misses
    ``_STRUCTURAL_OPEN_FIELDS``'s own exact-type lookup a few lines below and
    silently loses the open-field routing for ``evidence`` -- an
    ``Observation`` subclass with an ``IntEnum`` evidence value used to
    canonicalise identically to a real ``Observation`` with the plain int."""
    if isinstance(obj, R.enum.Enum):
        return obj.value
    if obj is None:
        return None
    t = type(obj)
    if t is bool or t is int or t is str:
        return obj
    if t is bytes:
        return {R._BYTES_TAG: R.base64.b64encode(obj).decode("ascii")}
    if dataclasses.is_dataclass(obj):                          # <-- the defect
        open_fields = R._STRUCTURAL_OPEN_FIELDS.get(type(obj), frozenset())
        result: Dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            if f.name == R._BYTES_TAG:
                raise R.SchemaError(
                    f"{type(obj).__name__}.{f.name} is named the reserved "
                    f"bytes tag {R._BYTES_TAG!r}"
                )
            value = getattr(obj, f.name)
            if f.name in open_fields:
                result[f.name] = R._jsonable_evidence_field(value)
            else:
                result[f.name] = _jsonable_structural_dataclass_arm_admits_subclasses(value)
        return result
    if t is dict:
        R._refuse_mapping_keys(obj)
        return {k: _jsonable_structural_dataclass_arm_admits_subclasses(v)
                for k, v in sorted(obj.items())}
    if t is tuple or t is list:
        return [_jsonable_structural_dataclass_arm_admits_subclasses(v) for v in obj]
    raise R.SchemaError(f"not canonicalisable at a structural position: {t.__name__}")


def _merge_observations_ignores_values(existing: Sequence[R.Observation],
                                       incoming: Sequence[R.Observation]):
    """new ``observation_dedup_ignores_values``: dedup on ``(at, evidence
    field NAMES)`` rather than the full digest, so two observations at the
    same timestamp with the same field name but genuinely different values
    -- ``size=8`` and ``size=16``, always legal, never confusable -- collapse
    into one."""
    def key(o: R.Observation):
        return (o.at, frozenset(name for name, _ in o.evidence))

    by_key = {key(o): o for o in existing}
    for o in incoming:
        by_key.setdefault(key(o), o)
    return tuple(sorted(by_key.values(), key=lambda o: (o.at, o.digest())))


def _validate_log_shape_only(store: R.FactStore) -> None:
    """Round-3 finding 5: check the *shape* of a log record and nothing else.

    A well-formed record naming a candidate that does not exist, or one filed
    under another key, or a ``supersede`` with no replacement, all pass -- and
    ``resolve`` then honours the pin.
    """
    seen_seq = set()
    for rec in store.resolutions:
        if not isinstance(rec, R.PinRecord):
            raise R.SchemaError("log entry is not a PinRecord")
        if rec.cls not in R._LOG_CLASSES:
            raise R.SchemaError(f"log entry class {rec.cls!r}")
        if isinstance(rec.seq, bool) or not isinstance(rec.seq, int) or rec.seq < 1:
            raise R.SchemaError("log entry seq must be a positive int")
        if rec.seq in seen_seq:
            raise R.SchemaError("duplicate log seq")
        seen_seq.add(rec.seq)
        for field in ("at", "actor", "key"):
            value = getattr(rec, field)
            if not isinstance(value, str) or not value:
                raise R.SchemaError(f"log entry needs a non-empty {field}")


def _validate_conflicts_noop(store: R.FactStore, index) -> None:
    """Round-3 finding 6: leave ``store.conflicts`` unvalidated, so a malformed
    entry survives a merge and surfaces later out of ``canonical_document``."""
    return None


def _supersede_key_only(store: R.FactStore, candidate_id: str, by_candidate_id: str,
                        at: str, reason: str, actor: str) -> None:
    """Round-3 finding 7: require only that the keys match.

    So a candidate about another identity, process, boot or mutually exclusive
    condition set may supersede an unrelated fact -- silently destroying
    something still true.
    """
    replacement = store.by_id(by_candidate_id)
    if replacement is None:
        raise R.StateTransitionError(f"no superseding candidate {by_candidate_id}")
    if by_candidate_id == candidate_id:
        raise R.StateTransitionError("a candidate cannot supersede itself")
    target = store.by_id(candidate_id)
    if target is None:
        raise R.StateTransitionError(f"no candidate {candidate_id}")
    if replacement.key != target.key:
        raise R.StateTransitionError("a supersession is same-key by definition")
    if replacement.state is not R.State.ACTIVE:
        raise R.StateTransitionError("a dead candidate cannot supersede a live one")
    R._transition_candidate(store, candidate_id, "supersede", at, reason, actor,
                            by_candidate_id)


def _classify_pair_value_only(a: R.Candidate, b: R.Candidate):
    """Round-3 finding 8: classify on value difference alone.

    Equal encodings from different identities return ``None``, so ``resolve``
    refuses a pool that no conflict report mentions; and pairs no context can
    make jointly applicable are reported as conflicts nobody can encounter.
    """
    if R.canonical(a.value) == R.canonical(b.value):
        return None
    if {a.provenance, b.provenance} == {R.Provenance.MEASURED, R.Provenance.ASSERTED}:
        return R.ConflictClass.CONTRADICTION_MEASURED_ASSERTED
    order = R.compare_specificity(a, b)
    if order is R.Ordering.EQUAL:
        return R.ConflictClass.EQUALLY_SPECIFIC
    if order is R.Ordering.INCOMPARABLE:
        return R.ConflictClass.INCOMPARABLE
    return R.ConflictClass.DOMINATED


def _validate_context_noop(ctx: Any) -> Any:
    """Round-3 finding 9: do not validate the context, so ``resolve`` leaks
    ``TypeError``/``ValueError`` and silently reads an unknown
    ``identity_mode`` as strict."""
    return ctx


def _validate_store_noop(store: R.FactStore) -> None:
    """The whole invariant boundary removed.

    Every positive control in the suite must stop raising, which is what proves
    the controls are controls rather than descriptions.
    """
    return None


def _applicable_unvalidated(c: R.Candidate, ctx: Any) -> bool:
    """C10's shipped gap: ``applicable`` is a plain predicate that never calls
    ``validate_context``, so a malformed context does not raise at all -- it
    silently returns whichever of True/False the body happens to compute from
    the first field it reads, discarding the caller's malformed input instead
    of refusing it."""
    at = c.applies_to
    if ctx.identity_mode != "none" and at.identity is not None:
        if at.identity not in ctx.identities:
            return False
    if at.scope in R._BOUND_SCOPES and at.binding != ctx.binding_for(at.scope):
        return False
    ctx_conds = ctx.conditions_map()
    return all(ctx_conds.get(k) == v for k, v in at.conditions)


def _candidate_id_index_unchecked(store: R.FactStore) -> Dict[str, R.Candidate]:
    """C8's shipped gap: build the id index with a plain dict comprehension,
    so a later duplicate silently overwrites an earlier one instead of
    raising I6.  This is the one function ``FactStore.by_id`` and
    ``_validate_log`` (and therefore ``current_pins``) both route through, so
    patching it alone reproduces the exact historical divergence: three
    readers of one store, and only ``validate_store`` -- which builds its own
    independent index inline -- still refuses it."""
    return {c.id: c for c in store.all_candidates()}


def _optional_name_type_only(raw: Any, what: str) -> Any:
    """Type-check an optional name but accept ``""`` -- the shipped defect.

    Deliberately the *subtle* form.  It does not disable the check; it restores
    the plausible-looking one that shipped before the round-4 sweep, which
    type-checks correctly and rejects ``7`` while letting ``""`` through.  A
    mutant that deleted the whole check would prove much less, because the type
    half of the rule was never the half that was wrong -- and "mutate to a
    plausible wrong behaviour, not to a disabled one" is the lesson this entry
    exists to honour.
    """
    if raw is not None and not isinstance(raw, str):
        raise R.SchemaError(f"{what} must be a string or null")
    return raw


def _check_declared_shape_unchecked(value: Any, shape: Any, owner: type,
                                     field_name: str) -> None:
    """F2 + F5's shared root cause, restored: a structural position's
    declared type is assumed, never enforced.  Disables BOTH the dataclass
    arm's per-field check (F2: a ``Scope`` member reaching
    ``Observation.at``, declared ``str``) and ``Candidate.project()``'s
    check (F5: an ``Observation`` reaching ``Candidate.applies_to``,
    declared ``AppliesTo``) -- both call this one function, which is why one
    mutant reproduces both findings."""
    return None


def _check_root_admissible_unchecked(obj: Any) -> None:
    """F1's shipped gap: ``canonical()``'s public entry point never enforced
    the declared type at the root, so a bare ``tuple``/``set``/``frozenset``
    canonicalised identically to a ``list``, and a bare ``Enum`` member
    canonicalised identically to its own ``.value``."""
    return None


def _structural_field_types_missing_scope() -> Dict[type, Dict[str, Any]]:
    """A completeness regression in ``_STRUCTURAL_FIELD_TYPES`` itself:
    the same table ``_build_structural_field_types`` produces, except
    ``AppliesTo``'s ``scope`` entry is missing.  ``_check_declared_shape``
    trusts the table it is given, so it cannot self-detect this -- only
    ``prop_P33_structural_field_types_table_is_complete``, which checks the
    table's shape against ``dataclasses.fields``, can.
    """
    table = {cls: dict(fields) for cls, fields in R._STRUCTURAL_FIELD_TYPES.items()}
    table[R.AppliesTo] = {
        name: shape for name, shape in table[R.AppliesTo].items()
        if name != "scope"
    }
    return table


MUTANTS: Dict[str, Mutant] = {
    m.name: m for m in [
        Mutant("merge_supersedes_on_rank", "v3 defect 1", "P1",
               {"merge": _merge_supersedes_on_rank}),
        Mutant("dedup_ignores_provenance", "v3 defect 2", "P14",
               {"dedup_key": _dedup_key_ignores_provenance}),
        Mutant("dedup_matches_terminal", "round-1 finding 3", "P1",
               {"merge": _merge_matches_terminal}),
        Mutant("ids_not_a_function", "round-1 finding 4 (half one)", "P10",
               {"derive_id": _make_ids_not_a_function()}),
        Mutant("ids_by_arrival_order", "round-1 finding 4 (half two)", "P2",
               {"derive_id": _derive_id_by_arrival_order,
                "FactStore": _ArrivalOrderFactStore}),
        Mutant("unsorted_candidate_array", "round-1 finding 4", "P2",
               {"canonical_document": _canonical_document_unsorted,
                "FactStore": _UnsortedFactStore}),
        Mutant("state_allows_resurrection", "terminal-state integrity", "P11",
               {"_TRANSITIONS": _transitions_allow_resurrection()}),
        Mutant("scope_order_missing_member", "v3 defect 4", "P5",
               {"SCOPE_EDGES": (("build", "host"), ("host", "boot"),
                                ("boot", "process"), ("process", "attempt"))}),
        Mutant("scope_order_total", "round-1 finding 6", "P15",
               {"SCOPE_EDGES": (("build", "libc_file"), ("libc_file", "host"),
                                ("host", "boot"), ("boot", "process"),
                                ("process", "attempt"))},
               note="with provenance first this no longer endangers P9, so the "
                    "generated-table gate is what catches it -- which is the "
                    "narrowed claim the byte gate actually earns"),
        Mutant("provenance_fourth", "v4 rev 1 / round-1 finding 5", None,
               {"compare_specificity": _compare_specificity_provenance_fourth},
               note="caught by contradiction_guard, so P9 must still pass -- "
                    "this is the redundancy being demonstrated"),
        Mutant("contradiction_guard_disabled", "belt-and-braces half two", None,
               {"contradiction_guard": _contradiction_guard_noop},
               note="caught by provenance-first ordering, so P9 must still pass"),
        Mutant("provenance_fourth_and_guard_disabled",
               "v4 rev 1 with both safeguards removed", "P9",
               {"compare_specificity": _compare_specificity_provenance_fourth,
                "contradiction_guard": _contradiction_guard_noop},
               note="only when BOTH mechanisms are broken does the operator's "
                    "invariant actually fail"),
        Mutant("provenance_total_rank", "v1", "P4",
               {"compare_provenance": _compare_provenance_total}),
        Mutant("specificity_ties_by_time", "v3", "P18",
               {"compare_specificity": _compare_specificity_ties_by_time}),
        Mutant("digest_includes_observations", "v3 defect 5", "P10",
               {"candidate_digest": _candidate_digest_includes_observations}),
        Mutant("digest_excludes_value", "digest under-coverage", "P10",
               {"candidate_digest": _candidate_digest_excludes_value}),
        Mutant("agreement_ignores_identity", "round-1 finding 8", "P19",
               {"agreeing": _agreeing_ignores_identity}),
        Mutant("resolve_returns_default_on_empty", "the cfi:false failure mode",
               "P12", {"resolve": _resolve_returns_default_on_empty}),
        Mutant("resolve_fabricates_witness", "round-1 finding 11", "P8",
               {"resolve": _resolve_fabricates_witness}),
        Mutant("conflicts_only_incomparable", "round-1 finding 7", "P13",
               {"conflicts": _conflicts_only_incomparable}),
        Mutant("pins_first_wins", "round-1 finding 7", "P16",
               {"current_pins": _current_pins_first_wins}),
        Mutant("tables_from_parallel_constants", "round-1 finding 13", "P15",
               {"emit_tables": _emit_tables_from_parallel_constants}),
        # Round-2 finding 13: six properties had no bound mutant, so "every
        # property is paired" was false.  These six close that, and
        # ``test_every_property_has_a_mutant`` keeps it closed.
        Mutant("validation_not_funnelled", "round-2 finding 1", "P1b",
               {"validate_candidate": _validate_candidate_unfunnelled}),
        Mutant("observations_append_without_dedup", "non-idempotent merge", "P3",
               {"_merge_observations": _merge_observations_appends}),
        Mutant("specificity_reads_value", "unsound symmetry reduction", "P5b",
               {"compare_specificity": _compare_specificity_reads_value}),
        Mutant("resolve_always_refuses", "round-2 finding 12", "P6",
               {"resolve": _resolve_always_refuses},
               note="total and deterministic, therefore passes a codomain check "
                    "and an order-independence check -- P6 must require the "
                    "successes as well"),
        Mutant("maximal_takes_first", "sort-and-take-first selection", "P7",
               {"maximal": _maximal_takes_first}),
        Mutant("staleness_ignores_dead_sources", "v3's four mechanisms", "P17",
               {"is_stale": _is_stale_ignores_dead_sources}),
        Mutant("id_digest_omits_generation", "round-2 finding 2", "P1",
               {"ID_DIGEST_FIELDS": tuple(f for f in R.ID_DIGEST_FIELDS
                                          if f != "generation")},
               note="the shipped defect itself: retract then re-merge and the "
                    "live and terminal siblings collide on one id, so the "
                    "re-observation cannot be stored at all"),
        Mutant("generation_from_caller", "round-3 finding 1", "P20",
               {"merge": _merge_generation_from_caller},
               note="the shipped defect: generation was store-assigned only "
                    "when a terminal sibling existed, so on a fresh store "
                    "arrival order decided the surviving id"),
        Mutant("canonical_coerces_keys", "round-3 finding 3", "P21",
               {"_jsonable_structural": _jsonable_coerces_keys}),
        Mutant("log_shape_only", "round-3 finding 5", "P22",
               {"_validate_log": _validate_log_shape_only}),
        Mutant("conflicts_unvalidated", "round-3 finding 6", "P23",
               {"_validate_conflicts": _validate_conflicts_noop}),
        Mutant("supersede_key_only", "round-3 finding 7", "P24",
               {"supersede": _supersede_key_only}),
        Mutant("classify_value_only", "round-3 finding 8", "P25",
               {"classify_pair": _classify_pair_value_only}),
        Mutant("context_unvalidated", "round-3 finding 9", "P26",
               {"validate_context": _validate_context_noop}),
        Mutant("store_invariants_disabled", "the boundary itself removed", "P27",
               {"validate_store": _validate_store_noop}),
        Mutant("applies_to_allows_empty_names",
               "round-4 self-sweep of round 3's falsey class", "P1b",
               {"_optional_name": _optional_name_type_only},
               note="the shipped defect: identity=\"\" and binding=\"\" were "
                    "accepted, giving a second dedup_key for one proposition, "
                    "and an identity no context can ever satisfy"),
        # Unit 1 (canonicalisation domain closure), C10.
        Mutant("applicable_unvalidated", "C10", "P28",
               {"applicable": _applicable_unvalidated},
               note="the shipped gap: applicable never called "
                    "validate_context, so a malformed context was silently "
                    "decided rather than refused"),
        # Unit 1 (canonicalisation domain closure), C8.
        Mutant("candidate_id_index_diverges", "C8", "P29",
               {"_candidate_id_index": _candidate_id_index_unchecked},
               note="the shipped gap: by_id and current_pins each built "
                    "their own unchecked id index, so a duplicate id that "
                    "validate_store correctly refused was silently accepted "
                    "by both"),
        # Unit 1 (canonicalisation domain closure), §5's mutant table.
        Mutant("canonical_accepts_tuple_as_list", "unit-1 §5", "P21",
               {"_jsonable_open": _jsonable_open_accepts_tuple}),
        Mutant("evidence_gate_type_only", "unit-1 §5, rev 6 un-masked", "P21",
               {"_jsonable_open": _jsonable_open_type_only},
               note="rev 5 registered this breaks=None because a second, "
                    "separately-closed layer still caught the object; after "
                    "the positional split there is one function for both "
                    "the gate and the encoding, so this is no longer masked"),
        Mutant("open_domain_isinstance_primitives", "unit-1 §8 item 8", "P21",
               {"_jsonable_open": _jsonable_open_isinstance_primitives},
               note="isinstance restored for int/bool/str: an IntEnum/"
                    "StrEnum member, root or nested, reaches the primitive "
                    "arm and collides with the plain value it wraps"),
        Mutant("open_domain_isinstance_list", "unit-1 §8 item 14", "P21",
               {"_jsonable_open": _jsonable_open_isinstance_list},
               note="isinstance restored for list: a list subclass "
                    "(EvidenceList in the property) is admitted rather than "
                    "refused"),
        Mutant("bytes_tag_guards_mappings_only", "rev 3, re-bound off P21", "P30",
               {"_jsonable_structural":
                    _jsonable_structural_bytes_tag_guards_mappings_only},
               note="cannot bind to P21 after the positional split -- P21 is "
                    "now an open-domain property and this is a structural-arm "
                    "defect -- so it binds to a helper property with a "
                    "synthetic hostile dataclass"),
        Mutant("observation_dedup_ignores_values", "unit-1 §5", "P31",
               {"_merge_observations": _merge_observations_ignores_values}),
        Mutant("structural_dataclass_arm_admits_subclasses", "unit-1 follow-up", "P32",
               {"_jsonable_structural":
                    _jsonable_structural_dataclass_arm_admits_subclasses},
               note="dataclasses.is_dataclass(obj) restored in place of the "
                    "exact-type _STRUCTURAL_DATACLASSES registry check -- "
                    "today's pre-registry behaviour, and the same defect "
                    "class as evidence_gate_type_only but on the structural "
                    "arm's admission test rather than the open arm's"),
        # Unit 1 review (2026-09-24), F1/F2/F5: a structural position's
        # declared type was assumed, never enforced.
        Mutant("structural_field_type_unchecked", "F2 + F5", "P34",
               {"_check_declared_shape": _check_declared_shape_unchecked},
               note="the shipped gap: neither the dataclass arm nor "
                    "Candidate.project() enforced a position's declared "
                    "type, so a Scope member reached Observation.at "
                    "(declared str) and an Observation reached "
                    "Candidate.applies_to (declared AppliesTo), each "
                    "silently encoded via whichever arm its own runtime "
                    "type happened to match"),
        Mutant("canonical_root_accepts_ambiguous", "F1", "P35",
               {"_check_root_admissible": _check_root_admissible_unchecked},
               note="the shipped gap: canonical()'s public entry point "
                    "bypassed the declared type at the root, so a bare "
                    "tuple canonicalised identically to a list, and a bare "
                    "Enum member canonicalised identically to its own "
                    ".value"),
        Mutant("structural_field_types_missing_a_field",
               "table-completeness regression", "P33",
               {"_STRUCTURAL_FIELD_TYPES": _structural_field_types_missing_scope()},
               note="a hand-edited _STRUCTURAL_FIELD_TYPES entry missing "
                    "AppliesTo.scope -- reproduces a completeness "
                    "regression in _build_structural_field_types itself, "
                    "which _check_declared_shape cannot catch because it "
                    "trusts the table it is given"),
    ]
}
