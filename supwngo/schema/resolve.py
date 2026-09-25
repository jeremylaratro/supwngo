"""Normative merge/resolution semantics for ``supwngo.context/v1``.

This module -- not the plan prose -- is the specification.  Three prose
attempts at these semantics were rejected for defects that are invisible in
English and mechanical in code: non-disjoint case analyses, a comparison
relation with no declared order, and a mutable field inside a content digest.
So the rules live here as data and pure functions, the normative tables in
``docs/reference/context-resolution-tables.md`` are *generated* by calling the
comparators below, and totality/determinism are executable properties in
``tests/test_context_resolve_properties.py``.

Deliberate constraints, because they are what make exhaustive property testing
possible:

* stdlib only, and **no imports from** ``supwngo`` -- this module is reviewable
  and testable on its own,
* no filesystem, no clock, no randomness, no logging: every input is passed in,
* every public function is pure except the five writers -- :func:`merge`,
  :func:`supersede`, :func:`retract`, :func:`pin` and :func:`unpin` -- each of
  which mutates exactly one :class:`FactStore` and does so transactionally.

See ``docs/plans/2026-09-24-standardized-context-schema.md``.
"""

from __future__ import annotations

import base64
import dataclasses
import enum
import hashlib
import json
import re
from typing import (
    Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple,
    Union, get_args, get_origin, get_type_hints,
)

__all__ = [
    "Provenance", "Scope", "State", "Ordering", "MergeDecision", "ConflictClass",
    "SchemaError", "StateTransitionError", "FactUnavailable", "FactUnresolved",
    "FactStale", "PinInapplicable",
    "Absent", "ABSENT",
    "Observation", "Ref", "AppliesTo", "Candidate", "FactStore", "ResolveContext",
    "Selected", "Conflict", "Agreement", "PinRecord",
    "canonical", "derive_id", "candidate_digest", "dedup_key",
    "validate_candidate", "validate_store", "validate_context",
    "merge", "supersede", "retract", "pin", "unpin", "transition",
    "compare_provenance", "compare_scope", "compare_conditions",
    "compare_specificity", "maximal",
    "applicable", "current_pins", "contradiction_guard", "agreeing",
    "resolve", "try_resolve", "conflicts", "context_free_conflicts",
    "agreements", "is_stale", "jointly_satisfiable", "CONFLICT_PRIORITY",
    "canonical_document", "classify_pair", "STORE_INVARIANTS",
    "FACT_KEYS", "spec_for", "emit_tables",
    "ID_DIGEST_FIELDS", "DEP_DIGEST_FIELDS", "DERIVED_FIELDS",
    "PROVENANCE_EDGES", "SCOPE_EDGES", "STATE_EVENTS",
]


# ---------------------------------------------------------------------------
# Vocabularies
# ---------------------------------------------------------------------------


class Provenance(enum.Enum):
    """Where a value came from.  Separate axis from :class:`Scope`.

    ``asserted`` has no counterpart in ``exploit/walkthrough/model.Confidence``
    (which has only measured/derived/assumed/unknown); the plan carries the
    mapping table.  It exists because a human can supply a value supwngo
    cannot measure.
    """

    MEASURED = "measured"
    DERIVED = "derived"
    ASSUMED = "assumed"
    ASSERTED = "asserted"
    UNKNOWN = "unknown"


class Scope(enum.Enum):
    """The domain a value is valid in.  Separate axis from :class:`Provenance`."""

    BUILD = "build"
    LIBC_FILE = "libc_file"
    HOST = "host"
    BOOT = "boot"
    PROCESS = "process"
    ATTEMPT = "attempt"


class State(enum.Enum):
    """Candidate lifecycle.  ``unresolved`` is deliberately absent: it was never
    a property of a candidate, only an outcome of :func:`resolve`."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    RETRACTED = "retracted"


class Ordering(enum.Enum):
    """Result of a comparison in a **partial** order.

    ``INCOMPARABLE`` is the member that makes the operator's rule expressible:
    a total order always picks a winner, so "an ordinary assertion must not
    beat a contradictory measurement" cannot be a rank.
    """

    GREATER = "greater"
    LESS = "less"
    EQUAL = "equal"
    INCOMPARABLE = "incomparable"


class MergeDecision(enum.Enum):
    """Exactly two outcomes.  Validation is a *precondition*, not a case --
    that is what makes the case analysis disjoint."""

    DEDUPED = "deduped"
    APPENDED = "appended"


class ConflictClass(enum.Enum):
    """Ordered partition; :func:`conflicts` assigns the first that holds."""

    CONTRADICTION_MEASURED_ASSERTED = "contradiction_measured_asserted"
    #: Neither dominates because they are equal on every ordered component.
    #: Distinct from INCOMPARABLE, and NOT ``dominated``: ``Ordering`` has four
    #: members, so "dominated" is not the complement of "incomparable", and
    #: labelling an equally-specific disagreement ``dominated`` would tell an
    #: operator that something won when nothing did.
    EQUALLY_SPECIFIC = "equally_specific"
    INCOMPARABLE = "incomparable"
    DOMINATED = "dominated"
    #: Equal *encodings*, different subjects.  ``agreeing()`` deliberately
    #: refuses to call two identities' matching ``0x401234`` a concurrence, so
    #: ``resolve`` refuses such a pool -- but nothing used to *classify* it, so
    #: the refusal appeared in no conflict report at all and an operator had no
    #: record of why the resolution failed.
    AMBIGUOUS_ACROSS_IDENTITIES = "ambiguous_across_identities"
    #: A re-observation after a terminal state.  The two terminal states are
    #: reported separately because they mean different things to an operator: a
    #: retraction was a judgement that the fact was wrong, a supersession was a
    #: judgement that it was stale.  Collapsing them told the operator the wrong
    #: one had happened.
    REOBSERVED_AFTER_RETRACTION = "reobserved_after_retraction"
    REOBSERVED_AFTER_SUPERSESSION = "reobserved_after_supersession"


# ---------------------------------------------------------------------------
# Refusals.  Every exit from resolve() is a Selected or one of these.
# ---------------------------------------------------------------------------


class SchemaError(ValueError):
    """The only exception :func:`validate_candidate` raises on untrusted data."""


class StateTransitionError(RuntimeError):
    """A refused (state, event) pair.  Never a silent no-op."""


class FactUnavailable(LookupError):
    """No applicable active candidate.  Never a default value."""


class FactUnresolved(LookupError):
    """Two or more maximal candidates disagree, and no pin says which."""

    def __init__(self, key: str, witnesses: Sequence["Candidate"], cls: ConflictClass):
        self.key = key
        self.witnesses = tuple(witnesses)
        self.conflict_class = cls
        ids = ", ".join(c.id for c in self.witnesses)
        super().__init__(
            f"{key}: {cls.value} between [{ids}]; resolve with "
            f"`supwngo context pin {key}=<candidate_id>` or "
            f"`supwngo context supersede <candidate_id> --by <candidate_id>`"
        )


class FactStale(LookupError):
    """The selected candidate rests on a source that was superseded, retracted,
    removed, or whose content changed."""


class PinInapplicable(LookupError):
    """A pin names a candidate that is not applicable here.  A pin selects
    against the specificity order; it does not override applicability."""


class Absent:
    """Explicit 'no such fact'.

    ``bool()`` raises rather than returning ``False``, because the whole point
    of the ``_UNMEASURED`` lesson in ``analysis/protections.py`` is that
    *absent* must not be silently representable as *false*.
    """

    __slots__ = ()

    def __bool__(self) -> bool:  # pragma: no cover - exercised via pytest.raises
        raise TypeError(
            "Absent has no truth value: a fact that was never measured is not "
            "False. Handle it explicitly."
        )

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = Absent()


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------


#: Reserved mapping key carrying the base64 encoding of a ``bytes`` value.  It is
#: refused as an ordinary mapping key, which is what makes the encoding injective.
_BYTES_TAG = "__bytes_b64__"


def _refuse_mapping_keys(obj: Mapping) -> None:
    """Shared by both encoders below: keys must already *be* strings, and the
    reserved bytes tag is refused as an ordinary key.

    Coercing keys with ``str(k)`` made ``1`` and ``"1"`` project to the same
    key and tie on the sort, so one overwrote the other and equal mappings
    could canonicalise differently depending on insertion order -- in a
    digest.  The reserved-tag refusal is what stops a real mapping from
    spoofing the single-key shape :func:`bytes` encodes to.
    """
    for k in obj:
        if type(k) is not str:
            raise SchemaError(
                f"mapping keys must be strings, got {type(k).__name__} ({k!r})"
            )
        if k == _BYTES_TAG:
            raise SchemaError(f"{_BYTES_TAG!r} is reserved for the bytes encoding")


def _jsonable_open(obj: Any) -> Any:
    """Project a caller-supplied EVIDENCE VALUE to canonicalisable JSON.

    This is the **open** domain (C2): the type at this position is not fixed
    by the schema, so the encoding must be closed and declared rather than
    guessed at.  Exact type only -- ``type(obj) is ...``, never
    ``isinstance`` -- so a subclass of an admitted type (``IntEnum``,
    ``StrEnum``, ``MyInt``, ``MyStr``, ``MyBytes``, ``MyList``, a custom
    ``dict`` subclass, any other ``Mapping`` that is not exactly ``dict``)
    reaches no arm and is refused by the final ``raise`` below, named by its
    type.  ``bool`` needs no subclass guard: CPython forbids subclassing
    ``bool`` outright, so ``type(obj) is bool`` is already exact by
    construction.

    Refused outright, and deliberately not encoded at all: ``float``,
    ``tuple``, ``set``, ``frozenset``, every ``Enum`` (``IntEnum``/``StrEnum``
    included), every dataclass, and every subclass of an admitted type.  Round
    3's bytes-vs-string collision and this unit's five-plus measured
    collisions (enum-vs-value, tuple-vs-list, set-vs-list, frozenset-vs-list,
    dataclass-vs-mapping, ``IntEnum``-vs-int, ``StrEnum``-vs-str) are all
    instances of the same class: two different Python types projecting to the
    same JSON shape at a position the caller controls.  Refusing everything
    outside a small, closed, exact-type set removes the class instead of
    enumerating its instances.
    """
    if obj is None:
        return None
    t = type(obj)
    if t is bool or t is int or t is str:
        return obj
    if t is bytes:
        return {_BYTES_TAG: base64.b64encode(obj).decode("ascii")}
    if t is dict:
        _refuse_mapping_keys(obj)
        return {k: _jsonable_open(v) for k, v in sorted(obj.items())}
    if t is list:
        return [_jsonable_open(v) for v in obj]
    raise SchemaError(f"not canonicalisable at an open position: {t.__name__}")


#: THE declared open position (§4a/§4b of the unit-1 plan): the one place a
#: structural dataclass field holds caller-supplied evidence rather than a
#: schema-fixed value.  Declared as data -- a mapping from dataclass type to
#: its open field names -- rather than as an ``if`` buried in the dataclass
#: arm below, so a reader (and C7's mechanical check) can enumerate every
#: open position from one place instead of re-deriving it from control flow.
_STRUCTURAL_OPEN_FIELDS: Dict[type, frozenset] = {}

#: THE explicit, closed registry of dataclass types admitted at a structural
#: position (C7/§4b): exact-type membership (``type(obj) in ...``), never
#: ``dataclasses.is_dataclass`` -- the latter also admits any SUBCLASS of a
#: registered type. A subclass reaching this arm would miss
#: ``_STRUCTURAL_OPEN_FIELDS``'s exact-type lookup (silently losing the
#: open-field routing for ``evidence``, so a value that would be refused on a
#: real ``Observation`` canonicalises through the structural encoder instead)
#: -- exactly the admission-vs-routing mismatch this unit closes everywhere
#: else. An unregistered dataclass, subclass or otherwise, reaches no arm and
#: is refused by the final ``raise`` below, named by its type. Populated
#: immediately after each admitted type is defined, same pattern as
#: ``_STRUCTURAL_OPEN_FIELDS`` above.
_STRUCTURAL_DATACLASSES: set = set()


# ---------------------------------------------------------------------------
# Declared per-structural-field types (post-implementation review, F1/F2/F5):
# a structural position's declared type used to be ASSUMED -- the dataclass
# arm below recursed into a field's value unconditionally, so the value's OWN
# runtime type decided which arm of _jsonable_structural applied, never the
# field's DECLARED type.  An enum member reaching Observation.at (declared
# str) was silently encoded as its .value and collided with the genuine
# string "build" (F2); an Observation reaching Candidate.applies_to (declared
# AppliesTo) encoded successfully as itself (F5).  This table and the two
# functions below close that: every non-open field of every registered
# structural dataclass -- plus Candidate's own fields, checked in
# .project() rather than here, since Candidate is never itself passed to
# _jsonable_structural -- is checked against its DECLARED shape before its
# value is allowed to recurse.
# ---------------------------------------------------------------------------


class _Shape:
    """A structural field's declared annotation, resolved to something
    checkable.  Never constructed from untrusted input -- only from
    ``typing.get_type_hints()`` on this module's own dataclasses, at
    import.

    Deliberately plain classes, NOT ``@dataclasses.dataclass``: this
    module's own C7 test discovers "every dataclass defined in
    ``resolve``" by reflection (``vars(R)`` filtered by
    ``dataclasses.is_dataclass``) to check that no two structural
    dataclasses share a field-name set. These ``_Shape`` types are never
    passed to :func:`_jsonable_structural` -- they are the metadata that
    decides what MAY be -- so making them dataclasses would put them in
    that reflection's domain by accident and trip C7's check over an
    internal representation it was never meant to cover.
    """

    __slots__ = ()


class _BareShape(_Shape):
    __slots__ = ("cls",)

    def __init__(self, cls: type) -> None:
        self.cls = cls

    def __repr__(self) -> str:
        return f"_BareShape({self.cls.__name__})"


class _OptionalShape(_Shape):
    __slots__ = ("inner",)

    def __init__(self, inner: "_Shape") -> None:
        self.inner = inner

    def __repr__(self) -> str:
        return f"_OptionalShape({self.inner!r})"


class _TupleShape(_Shape):
    __slots__ = ("inner",)

    def __init__(self, inner: "_Shape") -> None:
        self.inner = inner

    def __repr__(self) -> str:
        return f"_TupleShape({self.inner!r})"


class _PairTupleShape(_Shape):
    __slots__ = ("first", "second")

    def __init__(self, first: "_Shape", second: "_Shape") -> None:
        self.first = first
        self.second = second

    def __repr__(self) -> str:
        return f"_PairTupleShape({self.first!r}, {self.second!r})"


class _AnyShape(_Shape):
    """No declared type to enforce -- ``Candidate.value``, whose type is
    fixed per fact key by ``FACT_KEYS``/I4, not by the dataclass schema."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "_AnyShape()"


def _resolve_field_shape(annotation: Any, owner: type, field_name: str) -> _Shape:
    """Resolve ONE field's ``typing.get_type_hints()`` annotation into a
    :class:`_Shape`.  Handles EXACTLY: a bare class (``str``, ``int``,
    ``bool``, an ``Enum`` class, a registered structural dataclass),
    ``Optional[X]``, ``Tuple[X, ...]``, ``Tuple[Tuple[X, Y], ...]``, and
    ``Any`` -- the annotation shapes this schema actually uses.  Anything
    else is a shape this table cannot enforce -- which is exactly how
    F1/F2/F5 got in -- so it raises at IMPORT rather than silently admitting
    the field unchecked.
    """
    if annotation is Any:
        return _AnyShape()
    origin = get_origin(annotation)
    if origin is None:
        if isinstance(annotation, type) and (
            annotation in (str, int, bool)
            or issubclass(annotation, enum.Enum)
            or annotation in _STRUCTURAL_DATACLASSES
        ):
            return _BareShape(annotation)
        raise SchemaError(
            f"{owner.__name__}.{field_name}: _resolve_field_shape does not "
            f"handle bare annotation {annotation!r}"
        )
    args = get_args(annotation)
    if origin is Union:
        non_none = [a for a in args if a is not type(None)]
        if len(args) != 2 or len(non_none) != 1:
            raise SchemaError(
                f"{owner.__name__}.{field_name}: _resolve_field_shape only "
                f"handles Optional[X], not {annotation!r}"
            )
        return _OptionalShape(_resolve_field_shape(non_none[0], owner, field_name))
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            inner = args[0]
            inner_origin = get_origin(inner)
            if inner_origin is tuple:
                inner_args = get_args(inner)
                if len(inner_args) == 2 and inner_args[1] is not Ellipsis:
                    return _TupleShape(_PairTupleShape(
                        _resolve_field_shape(inner_args[0], owner, field_name),
                        _resolve_field_shape(inner_args[1], owner, field_name),
                    ))
                raise SchemaError(
                    f"{owner.__name__}.{field_name}: _resolve_field_shape "
                    f"only handles Tuple[Tuple[X, Y], ...], not {annotation!r}"
                )
            return _TupleShape(_resolve_field_shape(inner, owner, field_name))
        raise SchemaError(
            f"{owner.__name__}.{field_name}: _resolve_field_shape only "
            f"handles Tuple[X, ...], not {annotation!r}"
        )
    raise SchemaError(
        f"{owner.__name__}.{field_name}: _resolve_field_shape does not "
        f"handle annotation {annotation!r}"
    )


def _check_declared_shape(value: Any, shape: _Shape, owner: type, field_name: str) -> None:
    """Enforce that VALUE actually has the shape declared for THIS position,
    before it is allowed to recurse into :func:`_jsonable_structural`.  This
    is the per-position enforcement F1/F2/F5 named: admission is decided by
    the POSITION's declared type, never by which arm the value's own
    runtime type happens to match.
    """
    if isinstance(shape, _AnyShape):
        return
    if isinstance(shape, _BareShape):
        if type(value) is not shape.cls:
            raise SchemaError(
                f"{owner.__name__}.{field_name}: declared type is "
                f"{shape.cls.__name__}, got {type(value).__name__}"
            )
        return
    if isinstance(shape, _OptionalShape):
        if value is None:
            return
        _check_declared_shape(value, shape.inner, owner, field_name)
        return
    if isinstance(shape, _TupleShape):
        if type(value) is not tuple:
            raise SchemaError(
                f"{owner.__name__}.{field_name}: declared type is a tuple, "
                f"got {type(value).__name__}"
            )
        for element in value:
            _check_declared_shape(element, shape.inner, owner, field_name)
        return
    if isinstance(shape, _PairTupleShape):
        if type(value) is not tuple or len(value) != 2:
            raise SchemaError(
                f"{owner.__name__}.{field_name}: declared type is a pair, "
                f"got {value!r}"
            )
        _check_declared_shape(value[0], shape.first, owner, field_name)
        _check_declared_shape(value[1], shape.second, owner, field_name)
        return
    raise SchemaError(  # pragma: no cover - exhaustive over _Shape subclasses
        f"{owner.__name__}.{field_name}: unresolved shape {shape!r}"
    )


#: Declared per-field type table (F1/F2/F5): dataclass type -> field name ->
#: its resolved annotation shape.  Built ONCE at import, by
#: ``_build_structural_field_types`` -- called only after every
#: ``_STRUCTURAL_DATACLASSES`` member has registered itself, further down
#: this module -- from ``typing.get_type_hints()``.  The declared open
#: fields (``_STRUCTURAL_OPEN_FIELDS``) are the only permitted omissions;
#: ``prop_P33_structural_field_types_table_is_complete`` in
#: ``tests/test_context_resolve_properties.py`` checks that mechanically.
_STRUCTURAL_FIELD_TYPES: Dict[type, Dict[str, _Shape]] = {}


def _build_structural_field_types() -> Dict[type, Dict[str, _Shape]]:
    table: Dict[type, Dict[str, _Shape]] = {}
    for cls in _STRUCTURAL_DATACLASSES:
        hints = get_type_hints(cls)
        open_fields = _STRUCTURAL_OPEN_FIELDS.get(cls, frozenset())
        per_field: Dict[str, _Shape] = {}
        for f in dataclasses.fields(cls):
            if f.name in open_fields:
                continue
            per_field[f.name] = _resolve_field_shape(hints[f.name], cls, f.name)
        table[cls] = per_field
    return table


def _jsonable_evidence_field(value: Any) -> Any:
    """``Observation.evidence``: ``Tuple[Tuple[str, Any], ...]``.

    The OUTER tuple-of-pairs and the str NAMES are structural -- the schema
    fixes that shape, so ``_validate_candidate`` already normalises it before
    an ``Observation`` is ever constructed.  Each VALUE is caller-supplied
    evidence and is the one open position, so it goes through
    :func:`_jsonable_open` rather than :func:`_jsonable_structural`.
    """
    if type(value) is not tuple:
        raise SchemaError(f"evidence must be a tuple of pairs, got {type(value).__name__}")
    out = []
    for pair in value:
        if type(pair) is not tuple or len(pair) != 2:
            raise SchemaError("evidence entries must be (name, value) pairs")
        name, val = pair
        if type(name) is not str:
            raise SchemaError(f"evidence names must be strings, got {type(name).__name__}")
        out.append([name, _jsonable_open(val)])
    return out


def _jsonable_structural(obj: Any) -> Any:
    """Project a SCHEMA-FIXED value to canonicalisable JSON.

    This is the **structural** domain: every position this function is
    called on has its type fixed by the schema (an ``AppliesTo`` field is
    always an ``AppliesTo``, ``conditions`` is always a tuple of ``(str,
    str)`` pairs), so distinctness at these positions follows from the
    *position*, not from this function being injective the way
    :func:`_jsonable_open` must be (C1).  The one exception -- the one open
    position inside an otherwise-structural value -- is
    ``Observation.evidence``, routed through :data:`_STRUCTURAL_OPEN_FIELDS`
    and :func:`_jsonable_evidence_field` rather than recursing here.

    Enum dispatch runs **first**, ahead of the primitive arms, and that
    ordering is load-bearing rather than cosmetic: an ``IntEnum``/``StrEnum``
    member is also an ``int``/``str``, so if the primitive arm ran first it
    would encode the member as a bare int/string and silently collide with an
    unrelated primitive of the same value -- exactly the collision this unit
    closes.  Every other arm dispatches on exact type
    (``type(obj) is ...``), never ``isinstance``, so a primitive subclass
    cannot reach the primitive arm either -- see C7.  ``float``, ``set`` and
    ``frozenset`` reach no arm and fall to the final ``raise``: no structural
    position's declared annotation admits a set (checked mechanically, not
    merely by this suite's silence -- see the dead-arm coverage note in the
    unit-1 plan §4b), and addresses are ints, not floats.
    """
    if isinstance(obj, enum.Enum):            # FIRST -- see the note above.
        return obj.value
    if obj is None:
        return None
    t = type(obj)
    if t is bool or t is int or t is str:
        return obj
    if t is bytes:
        return {_BYTES_TAG: base64.b64encode(obj).decode("ascii")}
    if type(obj) in _STRUCTURAL_DATACLASSES:
        # C7's second clause, enforced here as well as measured statically:
        # a structural dataclass field named the reserved bytes tag would
        # encode identically to real bytes.  Round 3's own fix reserved the
        # tag in the mapping arm only and left this arm unguarded (§2a); this
        # closes it at the one remaining source rather than trusting every
        # future dataclass to avoid the name.
        #
        # Exact-type membership, not ``dataclasses.is_dataclass`` -- the
        # latter also admits any SUBCLASS of a registered type, which would
        # pass this test but then miss ``_STRUCTURAL_OPEN_FIELDS``'s own
        # exact-type lookup below, silently losing the open-field routing for
        # ``evidence`` and reintroducing the collisions this unit closes (an
        # ``Observation`` subclass with an ``IntEnum`` evidence value used to
        # canonicalise identically to the plain int it wraps).  An
        # unregistered dataclass -- including a subclass of a registered one
        # -- reaches no arm here and is refused by the final ``raise`` below.
        open_fields = _STRUCTURAL_OPEN_FIELDS.get(type(obj), frozenset())
        field_shapes = _STRUCTURAL_FIELD_TYPES[type(obj)]
        result: Dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            if f.name == _BYTES_TAG:
                raise SchemaError(
                    f"{type(obj).__name__}.{f.name} is named the reserved "
                    f"bytes tag {_BYTES_TAG!r}"
                )
            value = getattr(obj, f.name)
            if f.name in open_fields:
                result[f.name] = _jsonable_evidence_field(value)
            else:
                # F1/F2/F5: the position's DECLARED type is enforced before
                # the value is allowed to recurse -- never the value's own
                # runtime type, which is what let a Scope member reach
                # Observation.at (declared str) and be encoded as its
                # .value, colliding with a genuine string.
                _check_declared_shape(value, field_shapes[f.name], type(obj), f.name)
                result[f.name] = _jsonable_structural(value)
        return result
    if t is dict:
        _refuse_mapping_keys(obj)
        return {k: _jsonable_structural(v) for k, v in sorted(obj.items())}
    if t is tuple or t is list:
        return [_jsonable_structural(v) for v in obj]
    raise SchemaError(f"not canonicalisable at a structural position: {t.__name__}")


#: Refused ONLY at canonical()'s ROOT (F1): these four Python types are
#: ambiguous with another type this module admits at an undeclared
#: position -- ``tuple``/``set``/``frozenset`` all encode to the same JSON
#: array shape as ``list``, and an ``Enum`` member encodes to its own
#: ``.value``, which collides with a genuine primitive carrying that value.
#: A SCHEMA-FIXED nested position (``AppliesTo.conditions`` is declared
#: ``Tuple[Tuple[str, str], ...]``; ``Candidate.provenance`` is declared
#: ``Provenance``) is unaffected -- distinctness there follows from the
#: position (C1), so this guard runs at the root only.  Every other type
#: canonical()'s callers legitimately pass at the root -- a registered
#: structural dataclass, a projection ``dict``, ``list``, ``None``, exact
#: ``bool``/``int``/``str``, ``bytes`` -- has no OTHER admitted root type
#: whose JSON shape it collides with, so nothing else is refused here.
_ROOT_AMBIGUOUS_TYPES = (tuple, set, frozenset)


def _check_root_admissible(obj: Any) -> None:
    if isinstance(obj, enum.Enum):
        raise SchemaError(
            f"not canonicalisable at the root: a bare {type(obj).__name__} "
            "member would collide with its own .value"
        )
    if type(obj) in _ROOT_AMBIGUOUS_TYPES:
        raise SchemaError(
            f"not canonicalisable at the root: a bare {type(obj).__name__} "
            "would collide with the list it resembles once encoded"
        )


def canonical(obj: Any) -> str:
    """RFC 8785-flavoured canonical JSON: sorted keys, no whitespace.

    Arrays are *not* sorted here -- array order is fixed by the canonical
    array-ordering rule in :func:`canonical_document`, so that order is a
    function of content rather than of insertion order.  Routes to
    :func:`_jsonable_structural`: every call site in this module passes
    either a schema-fixed value or a value (like an ``Observation``) whose
    only open sub-position is handled internally via
    :data:`_STRUCTURAL_OPEN_FIELDS`.

    An UNDECLARED root has no schema-fixed type (F1), so
    :func:`_check_root_admissible` refuses exactly the types that are
    ambiguous with another admitted type at such a position --
    ``canonical((1, 2))`` no longer equals ``canonical([1, 2])``, and
    ``canonical(Scope.BUILD)`` no longer equals ``canonical("build")``.
    """
    _check_root_admissible(obj)
    return json.dumps(_jsonable_structural(obj), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Candidate
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Observation:
    """One sighting of a value.  Append-only, so re-observation neither creates
    a rival candidate nor discards the evidence of the sighting."""

    at: str
    evidence: Tuple[Tuple[str, Any], ...] = ()

    def digest(self) -> str:
        return _sha(canonical(self))


#: THE declared open position (§4a/§4b): Observation.evidence's VALUES are
#: caller-supplied and open; the outer tuple-of-pairs and the names are
#: structural.  Registered here, immediately after the type it describes, so
#: the declaration sits next to what it is about.
_STRUCTURAL_OPEN_FIELDS[Observation] = frozenset({"evidence"})
_STRUCTURAL_DATACLASSES.add(Observation)


@dataclasses.dataclass(frozen=True)
class Ref:
    """A dependency reference.  Structured, not a string, because fact keys
    already contain ``@``; and it carries ``key`` so a dependent can be located
    without scanning every key."""

    key: str
    id: str
    digest: str


_STRUCTURAL_DATACLASSES.add(Ref)


@dataclasses.dataclass(frozen=True)
class AppliesTo:
    identity: Optional[str]
    scope: Scope
    conditions: Tuple[Tuple[str, str], ...] = ()
    #: instance id of the scope, for the scopes that have one
    binding: Optional[str] = None

    def conditions_map(self) -> Dict[str, str]:
        return dict(self.conditions)


_STRUCTURAL_DATACLASSES.add(AppliesTo)


#: 128 bits.  A 48-bit (12 hex) id permitted feasible birthday collisions, and a
#: colliding id makes ``by_id``, pins, dependency lookup and witness selection
#: ambiguous -- so the width is not cosmetic.
_ID_HEX = 32
_ID_RE = re.compile(r"^f_[0-9a-f]{%d}$" % _ID_HEX)
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

#: What makes two candidates *the same assertion*: the dedup key.  Excludes
#: ``generation``, so a re-observation still dedups into its active sibling.
CONTENT_FIELDS: Tuple[str, ...] = (
    "key", "value", "provenance", "applies_to", "derived_from", "method", "by",
)
#: Content-derived id input.  Excludes ``id`` itself, so there is no
#: circularity, and includes ``generation`` so that re-asserting a value after
#: it was retracted produces a *distinct* id.  Without ``generation``, retract
#: + re-merge yielded two candidates with one id, which broke ``by_id``,
#: dependency lookup, the conflict record and candidate ordering all at once.
ID_DIGEST_FIELDS: Tuple[str, ...] = CONTENT_FIELDS + ("generation",)
#: What ``derived_from`` pins.  Includes ``id`` so a dependent records *which*
#: candidate it used.
DEP_DIGEST_FIELDS: Tuple[str, ...] = ID_DIGEST_FIELDS + ("id",)
#: Mutated after creation, therefore in **no** digest.  ``state`` is excluded
#: on purpose: if superseding changed the digest, every dependent's recorded
#: ``Ref.digest`` would stop matching and a legitimate supersession would be
#: indistinguishable from tampering.  That exclusion is only safe because ids
#: uniquely identify immutable candidates, which is what ``generation`` and the
#: 128-bit width above are for.
DERIVED_FIELDS: Tuple[str, ...] = ("observations", "state")


@dataclasses.dataclass(frozen=True)
class Candidate:
    key: str
    value: Any
    provenance: Provenance
    applies_to: AppliesTo
    method: str
    by: str
    observations: Tuple[Observation, ...]
    derived_from: Tuple[Ref, ...] = ()
    state: State = State.ACTIVE
    #: Bumped when this assertion is re-made after an identical one reached a
    #: terminal state, so terminal and live siblings never share an id.
    generation: int = 0
    id: str = ""

    def project(self, fields: Sequence[str]) -> Dict[str, Any]:
        """F5: a ``Candidate`` is never itself passed to
        :func:`_jsonable_structural` -- every canonicalisation of a
        candidate goes through this projected dict -- so this is the one
        place a Candidate's own field values are checked against their
        declared positions (``applies_to`` must be an ``AppliesTo``, not
        e.g. an ``Observation`` reached via a hand-built
        ``dataclasses.replace`` that bypassed :func:`validate_candidate`).
        """
        result: Dict[str, Any] = {}
        for name in fields:
            value = getattr(self, name)
            _check_declared_shape(value, _CANDIDATE_FIELD_TYPES[name], Candidate, name)
            result[name] = value
        return result

    @property
    def last_observed_at(self) -> str:
        """Derived, never stored -- which is why it cannot be order-dependent."""
        return max(o.at for o in self.observations)

    @property
    def first_observed_at(self) -> str:
        return min(o.at for o in self.observations)


def _build_candidate_field_types() -> Dict[str, _Shape]:
    hints = get_type_hints(Candidate)
    return {f.name: _resolve_field_shape(hints[f.name], Candidate, f.name)
            for f in dataclasses.fields(Candidate)}


#: Candidate's own declared field shapes (F5), built the same way as
#: _STRUCTURAL_FIELD_TYPES but kept separate: Candidate is deliberately NOT
#: a _STRUCTURAL_DATACLASSES member (canonicalisation never passes a
#: Candidate instance itself to _jsonable_structural -- only a dict from
#: .project()), so it is enforced in project() above rather than in the
#: dataclass arm.  Buildable immediately: every type Candidate's fields
#: reference (AppliesTo, Observation, Ref, the enums) is already registered
#: by this point in the module.
_CANDIDATE_FIELD_TYPES: Dict[str, _Shape] = _build_candidate_field_types()


def derive_id(c: Candidate) -> str:
    return "f_" + _sha(canonical(c.project(ID_DIGEST_FIELDS)))[:_ID_HEX]


def candidate_digest(c: Candidate) -> str:
    return _sha(canonical(c.project(DEP_DIGEST_FIELDS)))


def dedup_key(c: Candidate) -> str:
    """Every digest-bearing field, so two measured values from *different
    sources* or *different lineages* do not collapse into whichever arrived
    first, and a measured 72 and an asserted 72 stay two candidates.

    ``evidence`` is deliberately excluded: it differs on every run, so
    including it would mean nothing ever dedups.  Evidence is preserved by
    ``observations`` instead, which is strictly better than being a dedup
    component.
    """
    return canonical(c.project(CONTENT_FIELDS))


def _merge_observations(
    existing: Tuple[Observation, ...], incoming: Tuple[Observation, ...]
) -> Tuple[Observation, ...]:
    """Sorted-set union: commutative, so merge order cannot leak into bytes."""
    by_digest = {o.digest(): o for o in existing}
    for o in incoming:
        by_digest.setdefault(o.digest(), o)
    return tuple(sorted(by_digest.values(), key=lambda o: (o.at, o.digest())))


# ---------------------------------------------------------------------------
# Fact-key registry.  ``allowed_scopes`` is invariant I4 and is what stops a
# host-scoped ``libc.system_offset`` existing at all.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class FactSpec:
    value_type: type
    allowed_scopes: frozenset
    depends_on: str
    verification_class: str


def _spec(vt: type, scopes: Iterable[Scope], depends_on: str, vclass: str) -> FactSpec:
    return FactSpec(vt, frozenset(scopes), depends_on, vclass)


#: Exact keys first, then ``prefix.`` families.  Verification state is NOT
#: stored on a candidate -- it is a function of (candidate, loaded binary,
#: available tooling) and is computed at read time.
FACT_KEYS: Dict[str, FactSpec] = {
    "stack.return_offset": _spec(int, [Scope.BUILD], "binary_bytes", "static_offset"),
    "stack.canary_offset": _spec(int, [Scope.BUILD], "binary_bytes", "static_offset"),
    "libc.system_offset": _spec(int, [Scope.LIBC_FILE], "libc_file", "libc_offset"),
    "libc.binsh_offset": _spec(int, [Scope.LIBC_FILE], "libc_file", "libc_offset"),
    "libc.base": _spec(int, [Scope.PROCESS], "runtime", "runtime"),
    "heap.base": _spec(int, [Scope.PROCESS], "runtime", "runtime"),
    "protections.nx": _spec(bool, [Scope.BUILD], "binary_bytes", "unverifiable"),
    "protections.pie": _spec(bool, [Scope.BUILD], "binary_bytes", "unverifiable"),
    "protections.canary": _spec(bool, [Scope.BUILD], "binary_bytes", "unverifiable"),
}
_FACT_PREFIXES: Dict[str, FactSpec] = {
    "gadget.": _spec(int, [Scope.BUILD], "binary_bytes", "instruction_at"),
    "plt.": _spec(int, [Scope.BUILD], "binary_symbols", "instruction_at"),
    "sym.": _spec(int, [Scope.BUILD], "binary_symbols", "symbol_addr"),
    "libc.one_gadget.": _spec(int, [Scope.LIBC_FILE], "libc_file", "libc_offset"),
    "leak.": _spec(int, [Scope.PROCESS], "runtime", "runtime"),
    "env.": _spec(str, [Scope.HOST, Scope.BOOT], "runtime", "runtime"),
    "attempt.": _spec(str, [Scope.ATTEMPT], "runtime", "runtime"),
}


def spec_for(key: str) -> FactSpec:
    if key in FACT_KEYS:
        return FACT_KEYS[key]
    for prefix in sorted(_FACT_PREFIXES, key=len, reverse=True):
        if key.startswith(prefix):
            return _FACT_PREFIXES[prefix]
    raise SchemaError(f"unknown fact key: {key!r}")


#: Scopes that name an instance and therefore require ``applies_to.binding``.
_BOUND_SCOPES = frozenset({Scope.HOST, Scope.BOOT, Scope.PROCESS, Scope.ATTEMPT})


# ---------------------------------------------------------------------------
# Validation.  Hoisted out of merge's case analysis and stated as invariants,
# so merge is a precondition plus P / not-P on one predicate.
# ---------------------------------------------------------------------------


def _as_enum(cls, raw, what: str):
    if isinstance(raw, cls):
        return raw
    try:
        return cls(raw)
    except (ValueError, KeyError):
        raise SchemaError(f"{what}: {raw!r} not one of {[m.value for m in cls]}") from None


_MISSING = object()


def _reject_unknown(raw: Mapping, allowed: Iterable[str], what: str) -> None:
    """Unknown nested fields were *silently discarded*, so a typo in
    ``applies_to``/``observations``/``derived_from`` -- ``"scpoe"``,
    ``"evidnece"`` -- validated clean and produced a candidate that asserted
    something other than what the producer wrote."""
    for k in raw:
        if not isinstance(k, str):
            raise SchemaError(f"{what} field names must be strings, got {k!r}")
    unknown = set(raw) - set(allowed)
    if unknown:
        raise SchemaError(f"unknown {what} fields: {sorted(unknown)}")


def _required_list(data: Mapping, name: str, what: str) -> Sequence[Any]:
    """A list-valued field, absent-or-list only.

    ``data.get(name) or ()`` treated every *falsey* malformed value -- ``0``,
    ``False``, ``""`` -- as "absent", so ``derived_from=0`` and
    ``evidence=0`` validated clean.  Absence is ``None``/missing and nothing
    else.
    """
    raw = data.get(name, _MISSING)
    if raw is _MISSING or raw is None:
        return ()
    if isinstance(raw, (str, bytes, Mapping)) or not isinstance(raw, (list, tuple)):
        raise SchemaError(f"{what} must be a list, got {type(raw).__name__}")
    return raw


def _optional_name(raw: Any, what: str) -> Optional[str]:
    """An ``applies_to`` name that may be absent: ``None``, or a **non-empty** str.

    The empty string is refused rather than normalised to ``None``, for three
    reasons that all point the same way:

    * ``validate_context`` already refuses ``""`` for a context identity and for
      every binding field, so accepting it on the candidate side made the two
      ends of the same field disagree about what a legal name is;
    * ``identity`` and ``binding`` are in ``CONTENT_FIELDS``, so ``""`` and
      ``None`` are **different dedup keys** -- two active candidates for one
      proposition that can never dedup, which is precisely what merge exists to
      prevent;
    * ``""`` was additionally *unsatisfiable* as an identity: context identities
      must be non-empty, so ``"" not in ctx.identities`` always, and such a
      candidate could be stored but never resolved.

    Normalising ``""`` to ``None`` would fix the dedup half by guessing, and
    guessing is how the round-3 ``_jsonable`` key-coercion collision happened.
    ``applicable`` says it out loud a few hundred lines down -- *refuse rather
    than guess*.

    This is one function and not four inline checks because there were four
    sites (identity and binding, on each of the constructed and mapping paths)
    and all four carried the same defect -- the same drift ``_validate_conditions``
    was factored out to prevent.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise SchemaError(f"{what} must be a string or null")
    if not raw:
        raise SchemaError(
            f"{what} must be a non-empty string or null; \"\" is neither a name "
            "nor an absence, and would be a second, never-deduping spelling of "
            "the same proposition"
        )
    return raw


def _validate_conditions(raw: Any) -> Tuple[Tuple[str, str], ...]:
    """Conditions are a sorted tuple of ``(str, str)`` pairs.

    Shared by the mapping and the constructed-``AppliesTo`` paths so the two
    cannot drift; a constructed instance is re-checked because a typed container
    is not a validated one.  Sorting here is what makes
    :func:`compare_conditions`' set algebra and the canonical bytes agree.
    """
    if raw is None or raw is _MISSING:
        return ()
    if isinstance(raw, Mapping):
        items = list(raw.items())
    elif isinstance(raw, (list, tuple)):
        items = []
        for pair in raw:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                items.append((pair[0], pair[1]))
            else:
                raise SchemaError("applies_to.conditions entries must be pairs")
    else:
        raise SchemaError("applies_to.conditions must be a mapping or pairs")
    for name, value in items:
        if not isinstance(name, str) or not name:
            raise SchemaError("condition names must be non-empty strings")
        if not isinstance(value, str):
            raise SchemaError(f"condition {name!r}: value must be a string")
    if len({n for n, _ in items}) != len(items):
        raise SchemaError("applies_to.conditions names a condition twice")
    return tuple(sorted(items))


def validate_candidate(raw: Any) -> Candidate:
    """Validate the **whole** candidate and return it with a derived id.

    The only function permitted to raise on untrusted input, and it raises only
    :class:`SchemaError`.  Totality is enforced **structurally** by the wrapper
    below rather than by having remembered every way a mapping can be
    ill-formed: field-by-field checks alone let ``observations=1`` escape as a
    ``TypeError`` and a heterogeneous key set escape from inside ``sorted()``.
    """
    try:
        return _validate_candidate(raw)
    except SchemaError:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate funnel
        raise SchemaError(
            f"malformed candidate ({type(exc).__name__}: {exc})"
        ) from exc


def _validate_candidate(raw: Any) -> Candidate:
    if isinstance(raw, Candidate):
        data: Dict[str, Any] = {f.name: getattr(raw, f.name) for f in dataclasses.fields(Candidate)}
    elif isinstance(raw, Mapping):
        data = dict(raw)
    else:
        raise SchemaError(f"candidate must be a mapping or Candidate, got {type(raw).__name__}")

    known = {f.name for f in dataclasses.fields(Candidate)}
    if not all(isinstance(k, str) for k in data):
        raise SchemaError("candidate field names must be strings")
    unknown = set(data) - known
    if unknown:
        raise SchemaError(f"unknown candidate fields: {sorted(unknown)}")

    generation = data.get("generation", 0)
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise SchemaError("generation must be a non-negative int")

    key = data.get("key")
    if not isinstance(key, str) or not key:
        raise SchemaError("key must be a non-empty string")
    spec = spec_for(key)

    provenance = _as_enum(Provenance, data.get("provenance"), "provenance")
    state = _as_enum(State, data.get("state", State.ACTIVE), "state")

    at_raw = data.get("applies_to")
    if isinstance(at_raw, AppliesTo):
        # A constructed instance is NOT trusted: its fields are re-checked, or a
        # caller could smuggle a malformed identity/conditions past validation.
        applies_to = AppliesTo(
            _optional_name(at_raw.identity, "applies_to.identity"),
            _as_enum(Scope, at_raw.scope, "scope"),
            _validate_conditions(at_raw.conditions),
            _optional_name(at_raw.binding, "applies_to.binding"),
        )
    elif isinstance(at_raw, Mapping):
        _reject_unknown(at_raw, ("identity", "scope", "conditions", "binding"),
                        "applies_to")
        scope = _as_enum(Scope, at_raw.get("scope"), "scope")
        conds_items = _validate_conditions(at_raw.get("conditions", _MISSING))
        identity = _optional_name(at_raw.get("identity"), "applies_to.identity")
        binding = _optional_name(at_raw.get("binding"), "applies_to.binding")
        applies_to = AppliesTo(identity, scope, conds_items, binding)
    else:
        raise SchemaError("applies_to must be a mapping")

    # I4: value type and per-key allowed scopes.
    value = data.get("value")
    if spec.value_type is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SchemaError(f"{key}: value must be int, got {type(value).__name__}")
        if value < 0:
            raise SchemaError(f"{key}: addresses and offsets are unsigned")
    elif not isinstance(value, spec.value_type):
        raise SchemaError(f"{key}: value must be {spec.value_type.__name__}")
    if applies_to.scope not in spec.allowed_scopes:
        raise SchemaError(
            f"I4 {key}: scope {applies_to.scope.value} not in "
            f"{sorted(s.value for s in spec.allowed_scopes)}"
        )
    # ``is None`` and not truthiness: ``binding=""`` used to be *falsey*, so it
    # slipped past the "takes no binding" check below and was stored as ``""``.
    # ``_optional_name`` now refuses ``""`` outright, and these two say what they
    # mean rather than relying on that refusal holding.
    if applies_to.scope in _BOUND_SCOPES and applies_to.binding is None:
        raise SchemaError(f"{key}: scope {applies_to.scope.value} requires applies_to.binding")
    if applies_to.scope not in _BOUND_SCOPES and applies_to.binding is not None:
        raise SchemaError(f"{key}: scope {applies_to.scope.value} takes no binding")

    method, by = data.get("method"), data.get("by")
    for name, val in (("method", method), ("by", by)):
        if not isinstance(val, str) or not val:
            raise SchemaError(f"{name} must be a non-empty string")

    obs_raw = _required_list(data, "observations", "observations")
    observations: List[Observation] = []
    for o in obs_raw:
        # A constructed Observation is re-checked for the same reason as
        # AppliesTo above: a typed container is not a validated one.
        if isinstance(o, Observation):
            at, ev = o.at, o.evidence
        elif isinstance(o, Mapping):
            _reject_unknown(o, ("at", "evidence"), "observation")
            at, ev = o.get("at"), o.get("evidence", _MISSING)
        else:
            raise SchemaError(
                f"observation must be a mapping or Observation, got {type(o).__name__}")
        if not isinstance(at, str) or not at:
            raise SchemaError("observation.at must be a non-empty string")
        if ev is _MISSING or ev is None:
            ev_pairs: List[Tuple[str, Any]] = []
        elif isinstance(ev, Mapping):
            ev_pairs = list(ev.items())
        elif isinstance(ev, (list, tuple)):
            ev_pairs = []
            for pair in ev:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    raise SchemaError("observation.evidence entries must be pairs")
                ev_pairs.append((pair[0], pair[1]))
        else:
            raise SchemaError(
                f"observation.evidence must be a mapping or pairs, got "
                f"{type(ev).__name__}")
        # Names must *be* strings, not be coercible to strings: ``str(k)``
        # mapped the distinct names ``1`` and ``"1"`` onto one name, and their
        # sort keys then tied, so which one survived depended on input order.
        for name, _ in ev_pairs:
            if not isinstance(name, str) or not name:
                raise SchemaError("observation.evidence names must be non-empty strings")
        if len({n for n, _ in ev_pairs}) != len(ev_pairs):
            raise SchemaError("observation.evidence names a field twice")
        ev_items = tuple(sorted(ev_pairs, key=lambda kv: kv[0]))
        # Evidence VALUES are the one open position (§4a); gate each value
        # individually through the open-domain encoder rather than
        # canonicalising the whole tuple, which is narrower and names the
        # particular value that failed.
        for _, ev_value in ev_items:
            _jsonable_open(ev_value)
        observations.append(Observation(at, ev_items))
    if not observations:
        raise SchemaError("a candidate needs at least one observation")

    refs_raw = _required_list(data, "derived_from", "derived_from")
    refs: List[Ref] = []
    for r in refs_raw:
        if isinstance(r, Ref):
            rkey, rid, rdigest = r.key, r.id, r.digest
        elif isinstance(r, Mapping):
            _reject_unknown(r, ("key", "id", "digest"), "derived_from entry")
            missing = {"key", "id", "digest"} - set(r)
            if missing:
                raise SchemaError(f"derived_from entry missing {sorted(missing)}")
            rkey, rid, rdigest = r["key"], r["id"], r["digest"]
        else:
            raise SchemaError(
                f"derived_from entry must be a mapping, got {type(r).__name__}")
        if not isinstance(rkey, str) or not rkey:
            raise SchemaError("derived_from.key must be a non-empty string")
        spec_for(rkey)
        if not isinstance(rid, str) or not _ID_RE.match(rid):
            raise SchemaError(f"derived_from.id is not a candidate id: {rid!r}")
        if not isinstance(rdigest, str) or not _DIGEST_RE.match(rdigest):
            raise SchemaError(f"derived_from.digest is not a sha256 hex: {rdigest!r}")
        refs.append(Ref(rkey, rid, rdigest))
    if len({(r.key, r.id) for r in refs}) != len(refs):
        raise SchemaError("derived_from names the same candidate twice")

    # A derivation with no source is not a derivation.  ``depends_on`` and the
    # verification classes in the registry are *declarations consumed by the
    # document layer* (Phase 2) and are deliberately NOT enforced here -- this
    # module has no loaded binary and no tooling, so it cannot verify anything
    # and does not pretend to.  This rule is the part that IS enforceable here.
    if provenance is Provenance.DERIVED and not refs:
        raise SchemaError("a derived candidate must name at least one source")

    candidate = Candidate(
        key=key,
        value=value,
        provenance=provenance,
        applies_to=applies_to,
        method=method,
        by=by,
        observations=_merge_observations((), tuple(observations)),
        #: Sorted by the whole triple.  ``(key, id)`` alone is already unique
        #: -- the duplicate check above rejects two refs that share it, whatever
        #: their digests -- so ``digest`` is in the key only to make the sort
        #: total by construction rather than by relying on that check.
        derived_from=tuple(sorted(refs, key=lambda r: (r.key, r.id, r.digest))),
        state=state,
        generation=generation,
    )
    # Two checks used to stand here and **neither could fail**: a
    # ``canonical(candidate.value)`` probe, dead because the per-key value-type
    # check above already restricts every value to ``int`` or ``str``; and an
    # ``_ID_RE`` check on the id we had just derived, dead because
    # ``derive_id``'s shape is fixed.  Both are deleted rather than defended --
    # a gate that cannot go red is worse than no gate, because it reads as
    # coverage.  ``test_value_domain_keeps_the_canonical_gate_dead`` is the
    # tripwire: it fails if the registry ever admits a value type that
    # ``canonical`` could reject, which is when the first check must come back.
    candidate = dataclasses.replace(candidate, id=derive_id(candidate))

    if "id" in data and data["id"] is not None:
        given_id = data["id"]
        if not isinstance(given_id, str):
            raise SchemaError(f"id must be a string, got {type(given_id).__name__}")
        if given_id != candidate.id:
            raise SchemaError(
                f"I2 id {given_id!r} is not derive_id(candidate) ({candidate.id})")
    return candidate


class FactStore:
    """Candidates per fact key, plus the append-only decision log.

    Invariants I1-I6 are checked by :func:`validate_store`; :func:`merge`,
    :func:`supersede` and :func:`retract` preserve them.
    """

    def __init__(self) -> None:
        self._facts: Dict[str, List[Candidate]] = {}
        self.resolutions: List["PinRecord"] = []
        self.conflicts: List["Conflict"] = []

    # -- reads ----------------------------------------------------------
    def keys(self) -> List[str]:
        return sorted(self._facts)

    def candidates(self, key: str) -> Tuple[Candidate, ...]:
        return tuple(self._facts.get(key, ()))

    def active(self, key: str) -> Tuple[Candidate, ...]:
        return tuple(c for c in self.candidates(key) if c.state is State.ACTIVE)

    def all_candidates(self) -> Iterator[Candidate]:
        for key in self.keys():
            yield from self.candidates(key)

    def by_id(self, cid: str) -> Optional[Candidate]:
        """C8: the candidate id space must be a bijection.  A first-match
        linear scan answered this even when a second candidate shared the
        same id, silently returning whichever came first in iteration order
        -- a different, wrong answer from ``validate_store``'s I6, which
        does reject the same store.  Routes through the one checked index
        instead, so a duplicate id is refused here exactly as it is
        everywhere else."""
        return _candidate_id_index(self).get(cid)

    # -- writes ---------------------------------------------------------
    def _bucket(self, key: str) -> List[Candidate]:
        return self._facts.setdefault(key, [])

    def _replace(self, old: Candidate, new: Candidate) -> None:
        bucket = self._bucket(old.key)
        bucket[bucket.index(old)] = new

    def _sorted(self, key: str) -> None:
        self._bucket(key).sort(key=lambda c: c.id)

    def _record_conflict(self, conflict: "Conflict") -> None:
        """Set semantics, so recording the same conflict twice (or from two
        merge orders) cannot change the bytes."""
        self._record_conflicts((conflict,))

    def _record_conflicts(self, new: Iterable["Conflict"]) -> None:
        """Union then sort **once**.

        The per-conflict version did a linear membership scan and a full sort
        for every conflict recorded, so a merge that produced k conflicts against
        n existing ones cost O(k*(n + n log n)) -- quartic overall on a
        conflict-heavy key, for a result that is just a sorted set.
        """
        merged = set(self.conflicts)
        merged.update(new)
        if len(merged) != len(self.conflicts):
            self.conflicts[:] = sorted(
                merged, key=lambda c: (c.key, c.cls.value, c.candidate_ids))

    def _next_seq(self) -> int:
        """Log sequence numbers are assigned by the store, never by a caller,
        and they -- not the free-text ``at`` -- order the log.  ``at`` is an
        operator-supplied string: ``"t10" < "t9"`` lexicographically, so folding
        pins on ``at`` made a *later* pin lose."""
        return 1 + max((r.seq for r in self.resolutions), default=0)

    # -- snapshot/restore, so a failed write leaves nothing behind ------
    def _snapshot(self) -> Tuple[Any, ...]:
        return (
            {k: list(v) for k, v in self._facts.items()},
            list(self.resolutions),
            list(self.conflicts),
        )

    def _restore(self, snap: Tuple[Any, ...]) -> None:
        facts, resolutions, conflicts = snap
        self._facts = {k: list(v) for k, v in facts.items()}
        self.resolutions = list(resolutions)
        self.conflicts = list(conflicts)


#: Every invariant ``validate_store`` enforces, by name.  Each one is an
#: assertion that something is **absent** -- a duplicate, a cycle, a dangling
#: reference, an unlogged state change -- and this project has repeatedly found
#: that absence-assertions are exactly the checks that silently cannot fail.  So
#: the suite carries a positive control per entry and
#: ``test_every_store_invariant_has_a_positive_control`` fails if this tuple
#: grows an entry that nothing can trip.
STORE_INVARIANTS: Tuple[str, ...] = (
    "I1", "I2", "I2b", "I3", "I4", "I5", "I5b", "I6", "I7", "I8", "I9",
)


def validate_store(store: FactStore) -> None:
    """Check I1-I9 transactionally.  An invalid graph is never persisted."""
    seen_ids: Dict[str, Candidate] = {}
    for key in store.keys():
        active_keys: Dict[str, str] = {}
        for c in store.candidates(key):
            # I1 is *equality*, not "validation did not raise".  Checking only
            # that it did not raise ignored the normalised candidate it returns,
            # so a hand-built candidate carrying duplicate or unsorted
            # observations -- which are outside the id digest, so I2 cannot see
            # them -- validated clean and still changed the document bytes.
            normalised = validate_candidate(c)                        # I1
            if normalised != c:
                raise SchemaError(
                    f"I1 {c.id}: candidate is not in canonical form "
                    "(observations or derived_from unnormalised)")
            # There is deliberately **no** separate ``c.id != derive_id(c)``
            # probe here.  I1 above already rejects a mismatched id -- it is
            # ``validate_candidate`` that owns that rule -- so a second check
            # could never fire, which is precisely the kind of reassuring dead
            # gate this module has twice had to delete.  I2 is enforced, and
            # labelled, inside ``_validate_candidate``.
            if c.key != key:                                          # I2b
                raise SchemaError(
                    f"I2b {c.id}: filed under {key!r} but claims {c.key!r}")
            if c.state is State.ACTIVE:                               # I3
                dk = dedup_key(c)
                if dk in active_keys:
                    raise SchemaError(
                        f"I3 {key}: duplicate active dedup key "
                        f"({active_keys[dk]}, {c.id})"
                    )
                active_keys[dk] = c.id
            if c.id in seen_ids:                                      # I6
                raise SchemaError(f"I6 duplicate candidate id {c.id}")
            seen_ids[c.id] = c
    # One shared ``done`` set and one id index.  The walk used to restart a fresh
    # DFS per candidate and rescan every candidate for every edge, which is
    # quartic on a dense dependency DAG -- it made ``merge`` a size-based denial
    # of service against itself.
    done: set = set()
    for c in seen_ids.values():                                       # I5
        _assert_acyclic(seen_ids, c, set(), done)
        for ref in c.derived_from:                                    # I5b
            src = seen_ids.get(ref.id)
            if src is not None and src.key != ref.key:
                raise SchemaError(
                    f"I5b {c.id}: derived_from names {ref.id} under key "
                    f"{ref.key!r} but that candidate is filed under {src.key!r}"
                )
            # A ref whose source is ABSENT is deliberately **not** an invariant
            # violation: a document may legitimately be merged from fragments,
            # and rejecting a partial graph would make a fragment unmergeable.
            # It is handled where it belongs -- ``is_stale`` treats a dangling
            # ref as stale, so nothing is *consumed* on an unresolvable lineage.
    _validate_log(store)                                               # I7, I8
    _validate_conflicts(store, seen_ids)                              # I9


_LOG_CLASSES: Tuple[str, ...] = ("pin", "unpin", "supersede", "retract")

#: Which terminal state each lifecycle class must have produced on its target.
_LOG_TERMINAL: Dict[str, State] = {
    "supersede": State.SUPERSEDED,
    "retract": State.RETRACTED,
}


def _candidate_id_index(store: FactStore) -> Dict[str, Candidate]:
    """C8: the candidate id space is a bijection.  Build the id -> candidate
    index and raise I6 on the first duplicate found, and do it in the one
    place both ``_validate_log`` and :meth:`FactStore.by_id` call -- not as
    two independently hand-rolled lookups that could (and did) disagree with
    ``validate_store`` about whether a given store is even valid.  A dict
    comprehension silently lets a later duplicate overwrite an earlier one;
    this raises instead, the same way ``validate_store``'s own id-uniqueness
    check does.
    """
    index: Dict[str, Candidate] = {}
    for c in store.all_candidates():
        if c.id in index:
            raise SchemaError(f"I6 duplicate candidate id {c.id}")
        index[c.id] = c
    return index


def _validate_log(store: FactStore) -> None:
    """I7: the log is well formed, uniquely sequenced, attributed **and
    referentially sound**.  I8: no terminal state without a record.

    Shape alone was not enough.  A well-shaped record naming a candidate that
    does not exist, or one filed under a different key, or a ``supersede`` with
    no replacement, or a ``pin`` carrying one, all passed -- and ``resolve`` then
    honoured the pin.  An integer ``candidate_id`` did worse: it leaked
    ``TypeError`` out of ``_ID_RE.match`` from inside ``merge``'s pre-write
    validation, so a malformed log broke an unrelated write with the wrong
    exception type.

    What this does **not** do is make the log unforgeable.  A caller holding the
    store can append to ``resolutions`` as easily as it can call :func:`pin`;
    ``seq`` and ``actor`` are as forgeable as any other in-process value.  The
    boundary being defended is the *document*, and what is enforced is that
    every record crossing it is well formed, uniquely sequenced, attributed and
    consistent with the candidate it names.

    The id index used below is built here, via :func:`_candidate_id_index`,
    rather than accepted as a parameter: a caller-supplied index let
    ``current_pins`` build one with a plain dict comprehension that silently
    dropped a duplicate instead of rejecting the store (C8).
    """
    index = _candidate_id_index(store)
    seen_seq = set()
    for rec in store.resolutions:
        if not isinstance(rec, PinRecord):
            raise SchemaError(
                f"I7 log entry is not a PinRecord: {type(rec).__name__}")
        if rec.cls not in _LOG_CLASSES:
            raise SchemaError(
                f"I7 log entry class {rec.cls!r} not in {list(_LOG_CLASSES)}")
        if isinstance(rec.seq, bool) or not isinstance(rec.seq, int) or rec.seq < 1:
            raise SchemaError(
                f"I7 log entry seq must be a positive int, got {rec.seq!r}")
        if rec.seq in seen_seq:
            raise SchemaError(f"I7 duplicate log seq {rec.seq}")
        seen_seq.add(rec.seq)
        for field in ("at", "actor", "key", "reason"):
            value = getattr(rec, field)
            if not isinstance(value, str) or not value:
                raise SchemaError(f"I7 log entry needs a non-empty {field}")
        spec_for(rec.key)
        for field in ("candidate_id", "by_candidate_id"):
            cid = getattr(rec, field)
            if cid is None:
                continue
            if not isinstance(cid, str) or not _ID_RE.match(cid):
                raise SchemaError(
                    f"I7 log entry {field} is not a candidate id: {cid!r}")
            target = index.get(cid)
            if target is None:
                raise SchemaError(f"I7 log entry {field} names no candidate: {cid}")
            if target.key != rec.key:
                raise SchemaError(
                    f"I7 log entry is filed under {rec.key!r} but {field} {cid} "
                    f"is a {target.key!r} candidate")
        if rec.cls == "unpin":
            if rec.candidate_id is not None:
                raise SchemaError("I7 an unpin record names no candidate")
        elif rec.candidate_id is None:
            raise SchemaError(f"I7 a {rec.cls} record must name a candidate")
        if rec.cls == "supersede":
            if rec.by_candidate_id is None:
                raise SchemaError("I7 a supersede record must name its replacement")
            if rec.by_candidate_id == rec.candidate_id:
                raise SchemaError("I7 a supersede record cannot name itself twice")
        elif rec.by_candidate_id is not None:
            raise SchemaError(f"I7 a {rec.cls} record takes no by_candidate_id")
        expected = _LOG_TERMINAL.get(rec.cls)
        if expected is not None and index[rec.candidate_id].state is not expected:
            raise SchemaError(
                f"I7 log records {rec.cls} of {rec.candidate_id} but it is "
                f"{index[rec.candidate_id].state.value}, not {expected.value}")
    # I8, the converse: a terminal state with no record is a state change that
    # happened outside the state machine, which is exactly what the log exists to
    # make impossible to hide.
    logged = {(r.cls, r.candidate_id) for r in store.resolutions}
    for c in index.values():
        for cls, state in _LOG_TERMINAL.items():
            if c.state is state and (cls, c.id) not in logged:
                raise SchemaError(
                    f"I8 {c.id} is {state.value} but no {cls} record says so")


def _validate_conflicts(store: FactStore, index: Mapping[str, Candidate]) -> None:
    """I9: the recorded conflict list is well formed, unique, canonically
    ordered, and points at candidates that exist under the key it names.

    ``store.conflicts`` is as public as ``store.resolutions`` and was validated
    nowhere, so a malformed entry survived a conflict-free merge and surfaced
    later as an exception out of ``canonical_document`` -- at document-build
    time, far from whatever put it there.
    """
    seen = set()
    for rec in store.conflicts:
        if not isinstance(rec, Conflict):
            raise SchemaError(
                f"I9 conflict entry is not a Conflict: {type(rec).__name__}")
        if not isinstance(rec.cls, ConflictClass):
            raise SchemaError(f"I9 conflict class is not a ConflictClass: {rec.cls!r}")
        if not isinstance(rec.key, str) or not rec.key:
            raise SchemaError("I9 conflict needs a non-empty key")
        spec_for(rec.key)
        ids = rec.candidate_ids
        if not isinstance(ids, tuple) or len(ids) != 2:
            raise SchemaError(f"I9 conflict must name exactly two candidates: {ids!r}")
        if not all(isinstance(cid, str) for cid in ids):
            raise SchemaError(f"I9 conflict ids must be strings: {ids!r}")
        if list(ids) != sorted(ids) or ids[0] == ids[1]:
            raise SchemaError(f"I9 conflict ids must be sorted and distinct: {ids!r}")
        for cid in ids:
            target = index.get(cid)
            if target is None:
                raise SchemaError(f"I9 conflict names no such candidate: {cid!r}")
            if target.key != rec.key:
                raise SchemaError(
                    f"I9 conflict is filed under {rec.key!r} but {cid} is a "
                    f"{target.key!r} candidate")
        if rec in seen:
            raise SchemaError(f"I9 duplicate conflict record {rec}")
        seen.add(rec)
    ordered = sorted(store.conflicts,
                     key=lambda c: (c.key, c.cls.value, c.candidate_ids))
    if list(store.conflicts) != ordered:
        raise SchemaError("I9 conflict list is not in canonical order")


def _assert_acyclic(index: Mapping[str, Candidate], c: Candidate,
                    path: set, done: set) -> None:
    if c.id in done:
        return
    if c.id in path:
        raise SchemaError(f"I5 derived_from cycle through {c.id}")
    path.add(c.id)
    for ref in c.derived_from:
        src = index.get(ref.id)
        if src is not None:
            _assert_acyclic(index, src, path, done)
    path.discard(c.id)
    done.add(c.id)


# ---------------------------------------------------------------------------
# Merge: a precondition plus two disjoint cases.  Never picks a winner.
# ---------------------------------------------------------------------------


def merge(store: FactStore, incoming: Any) -> MergeDecision:
    """Append or dedupe.  Never supersedes, never changes an existing state.

    Commutative up to dedup, because (a) ids are content-derived so dedup-equal
    candidates *are* the same candidate, (b) observations union as a sorted
    set, and (c) :func:`canonical_document` sorts every array by a
    content-derived key.

    Transactional: the store is valid before the write, and if the write would
    leave it invalid the snapshot is restored and the error propagates.  Without
    that boundary ``merge`` *asserted* I3 instead of establishing it, and a store
    that already violated I3 was left violating it unless the incoming candidate
    happened to collide.
    """
    candidate = validate_candidate(incoming)            # precondition, not a case

    # The transition table is the only authority on states.  An append yields
    # exactly ``transition(None, "append")``; anything else has to go through
    # supersede()/retract() on a stored candidate.
    appended_state = transition(None, "append")
    if candidate.state is not appended_state:
        raise SchemaError(
            f"merge accepts only state {appended_state.value!r}; got "
            f"{candidate.state.value!r} -- use supersede()/retract() instead"
        )

    validate_store(store)                               # I1-I7 hold BEFORE the write

    key = candidate.key
    dk = dedup_key(candidate)
    matches = [c for c in store.active(key) if dedup_key(c) == dk]
    terminal = [c for c in store.candidates(key)
                if c.state is not appended_state and dedup_key(c) == dk]

    # ``generation`` is assigned by the **store**, unconditionally.  It used to
    # be taken from the caller whenever the store had no terminal sibling, which
    # made merge order-dependent: merging the same assertion at generation 0 and
    # at generation 5 on a fresh store left whichever arrived first, so reversing
    # arrival order changed the document bytes.  Deriving it here from store
    # state alone is what makes the result a function of the *set* of merged
    # candidates.  ``dedup_key`` excludes ``generation``, so the lookups above
    # are themselves generation-independent -- the two facts together are the
    # whole argument for order-independence.
    generation = (matches[0].generation if matches
                  else 1 + max(c.generation for c in terminal) if terminal
                  else 0)
    candidate = _assign_generation(candidate, incoming, generation)

    snap = store._snapshot()
    try:
        if matches:
            existing = matches[0]
            store._replace(
                existing,
                dataclasses.replace(
                    existing,
                    observations=_merge_observations(
                        existing.observations, candidate.observations),
                ),
            )
            store._sorted(key)
            decision = MergeDecision.DEDUPED
        else:
            # Dedup considers ACTIVE candidates only.  Folding a fresh
            # observation into a retracted candidate would silently undo the
            # retraction and leave no active fact at all, so this appends -- at
            # the fresh ``generation`` assigned above, so the live and terminal
            # siblings cannot share an id, and it tells the operator.
            for dead in sorted(terminal, key=lambda c: c.id):
                store._record_conflict(Conflict(
                    key,
                    ConflictClass.REOBSERVED_AFTER_RETRACTION
                    if dead.state is State.RETRACTED
                    else ConflictClass.REOBSERVED_AFTER_SUPERSESSION,
                    tuple(sorted((dead.id, candidate.id))),
                ))
            store._bucket(key).append(candidate)
            store._sorted(key)
            decision = MergeDecision.APPENDED

        # Conflicts are recorded on **every write**, not only on resolve: a
        # producer-only run (``analyze`` with no ``pwn``) never resolves, and
        # without this it accumulated contradictions in silence.
        store._record_conflicts(context_free_conflicts(store, key))

        validate_store(store)                           # I1-I7 hold AFTER it too
    except Exception:
        store._restore(snap)
        raise
    return decision


def _stated(incoming: Any, field: str) -> Any:
    """What the *raw input* asserted for a store-assigned field, if anything.

    A :class:`Candidate` instance states **nothing**: its ``generation`` and
    ``id`` are the store's own earlier assignment, so treating them as an
    assertion made the round trip ``merge(store, validate_candidate(raw))``
    fail whenever the store had moved on -- validation necessarily fills both
    fields in, so there was no way to express "I have no opinion".  Only a
    mapping can assert them, and then only to be checked.
    """
    if isinstance(incoming, Mapping):
        value = incoming.get(field, _MISSING)
        return _MISSING if value is None else value
    return _MISSING


def _assign_generation(candidate: Candidate, incoming: Any, generation: int) -> Candidate:
    stated_gen = _stated(incoming, "generation")
    if stated_gen is not _MISSING and stated_gen != generation:
        raise SchemaError(
            f"{candidate.key}: generation is assigned by the store ({generation} "
            f"here), not by the caller ({stated_gen!r}); merge without it"
        )
    if candidate.generation != generation:
        candidate = dataclasses.replace(candidate, generation=generation)
        candidate = dataclasses.replace(candidate, id=derive_id(candidate))
    stated_id = _stated(incoming, "id")
    if stated_id is not _MISSING and stated_id != candidate.id:
        raise SchemaError(
            f"{candidate.key}: the supplied id {stated_id!r} is not this "
            f"candidate's id at store-assigned generation {generation} "
            f"({candidate.id}); merge it without an id"
        )
    return candidate


# ---------------------------------------------------------------------------
# State machine.  Total over (state, event); terminal states are terminal.
# ---------------------------------------------------------------------------


STATE_EVENTS: Tuple[str, ...] = ("append", "supersede", "retract")

#: ``None`` means REFUSED.  ``None`` key is the absent (not yet stored) state.
_TRANSITIONS: Dict[Tuple[Optional[State], str], Optional[State]] = {
    (None, "append"): State.ACTIVE,
    (None, "supersede"): None,
    (None, "retract"): None,
    (State.ACTIVE, "append"): None,
    (State.ACTIVE, "supersede"): State.SUPERSEDED,
    (State.ACTIVE, "retract"): State.RETRACTED,
    (State.SUPERSEDED, "append"): None,
    (State.SUPERSEDED, "supersede"): None,
    (State.SUPERSEDED, "retract"): None,
    (State.RETRACTED, "append"): None,
    (State.RETRACTED, "supersede"): None,
    (State.RETRACTED, "retract"): None,
}


def transition(state: Optional[State], event: str) -> State:
    """Raise :class:`StateTransitionError` on a refused pair -- never a silent
    no-op, because a resurrected candidate would invalidate every
    ``derived_from`` digest taken while it was dead."""
    if event not in STATE_EVENTS:
        raise StateTransitionError(f"unknown event {event!r}")
    if (state, event) not in _TRANSITIONS:
        # No pragma here (unit-1 §6 follow-up): this branch IS reachable, by
        # a plain string state that is not `None` and not a declared `State`
        # member -- e.g. `transition("active", "append")`. `_TRANSITIONS`'s
        # keys are typed `Optional[State]`, so a plain string never equals
        # one, and the branch above only forbids *known* (state, event)
        # pairs, not arbitrary first arguments. Covered by
        # `test_transition_refuses_a_non_state_first_argument` in
        # tests/test_context_resolve_properties.py.
        raise StateTransitionError(f"undefined transition ({state}, {event})")
    nxt = _TRANSITIONS[(state, event)]
    if nxt is None:
        raise StateTransitionError(
            f"refused: cannot {event} a candidate in state "
            f"{'absent' if state is None else state.value}"
        )
    return nxt


def _require_text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise StateTransitionError(f"{what} must be a non-empty string")
    return value


def _transition_candidate(store: FactStore, cid: str, event: str, at: str,
                          reason: str, actor: str,
                          by_id: Optional[str] = None) -> None:
    """Validate **everything** first, then mutate, then log -- transactionally.

    The previous order mutated the candidate and then built the record, so a bad
    ``at`` changed a state and left the change unlogged.
    """
    c = store.by_id(cid)
    if c is None:
        raise StateTransitionError(f"no candidate {cid}")
    _require_text(at, f"{event} at")
    _require_text(actor, f"{event} actor")
    _require_text(reason, f"{event} reason")
    next_state = transition(c.state, event)             # refuses before mutating
    record = PinRecord(cls=event, key=c.key, candidate_id=cid, at=at,
                       seq=store._next_seq(), actor=actor, reason=reason,
                       by_candidate_id=by_id)
    snap = store._snapshot()
    try:
        store._replace(c, dataclasses.replace(c, state=next_state))
        store._sorted(c.key)
        store.resolutions.append(record)
        validate_store(store)
    except Exception:
        store._restore(snap)
        raise


def supersede(store: FactStore, candidate_id: str, by_candidate_id: str,
              at: str, reason: str, actor: str) -> None:
    """``at`` is an explicit parameter, not read from a clock and not smuggled
    inside ``reason``: this module stays pure, and a record whose sort key came
    out of a magic string in a free-text field is a record whose ordering nobody
    can predict.  Ordering is :attr:`PinRecord.seq`, assigned here.

    A supersession is a claim that one candidate *replaces another for the same
    proposition*, so the three ways that claim can be nonsense are refused
    rather than recorded.
    """
    replacement = store.by_id(by_candidate_id)
    if replacement is None:
        raise StateTransitionError(f"no superseding candidate {by_candidate_id}")
    if by_candidate_id == candidate_id:
        raise StateTransitionError("a candidate cannot supersede itself")
    target = store.by_id(candidate_id)
    if target is None:
        raise StateTransitionError(f"no candidate {candidate_id}")
    if replacement.key != target.key:
        raise StateTransitionError(
            f"cannot supersede {target.key!r} with a candidate for "
            f"{replacement.key!r}: a supersession is same-key by definition"
        )
    if replacement.state is not State.ACTIVE:
        raise StateTransitionError(
            f"{by_candidate_id} is {replacement.state.value}; a dead candidate "
            "cannot supersede a live one"
        )
    # Same key is not the same proposition.  Matching only the key let a
    # candidate about another identity, another process, another boot, another
    # libc file or a mutually exclusive condition set supersede an unrelated
    # fact -- silently destroying something still true.  ``applies_to`` is the
    # subject of the assertion, so replacing a fact requires speaking about the
    # same subject; a *narrower* replacement does not cover the old claim and is
    # therefore not a replacement either.
    if replacement.applies_to != target.applies_to:
        differing = [
            name for name in ("identity", "scope", "binding", "conditions")
            if getattr(replacement.applies_to, name) != getattr(target.applies_to, name)
        ]
        raise StateTransitionError(
            f"cannot supersede {candidate_id} with {by_candidate_id}: they are "
            f"not about the same proposition (applies_to differs in "
            f"{differing}); re-assert the narrower fact instead"
        )
    _transition_candidate(store, candidate_id, "supersede", at, reason, actor,
                          by_candidate_id)


def retract(store: FactStore, candidate_id: str, at: str, reason: str,
            actor: str) -> None:
    _transition_candidate(store, candidate_id, "retract", at, reason, actor)


def pin(store: FactStore, key: str, candidate_id: str, at: str, reason: str,
        actor: str) -> None:
    """The **only** writer for a pin.

    A pin is the single mechanism by which an ``asserted`` value may beat a
    contradictory ``measured`` one, so it is not something a caller may append
    to a public list: it is validated, attributed and sequenced here.
    """
    spec_for(key)
    c = store.by_id(candidate_id)
    if c is None:
        raise StateTransitionError(f"no candidate {candidate_id}")
    if c.key != key:
        raise StateTransitionError(
            f"cannot pin {candidate_id} under {key!r}: it is a {c.key!r} candidate")
    if c.state is not State.ACTIVE:
        raise StateTransitionError(
            f"cannot pin {candidate_id}: it is {c.state.value}")
    _append_log(store, PinRecord(
        cls="pin", key=key, candidate_id=candidate_id, at=_require_text(at, "at"),
        seq=store._next_seq(), actor=_require_text(actor, "actor"),
        reason=_require_text(reason, "reason")))


def unpin(store: FactStore, key: str, at: str, reason: str, actor: str) -> None:
    spec_for(key)
    _append_log(store, PinRecord(
        cls="unpin", key=key, candidate_id=None, at=_require_text(at, "at"),
        seq=store._next_seq(), actor=_require_text(actor, "actor"),
        reason=_require_text(reason, "reason")))


def _append_log(store: FactStore, record: PinRecord) -> None:
    snap = store._snapshot()
    try:
        store.resolutions.append(record)
        validate_store(store)
    except Exception:
        store._restore(snap)
        raise


# ---------------------------------------------------------------------------
# Partial orders, generated from covering edges by transitive closure.
# ---------------------------------------------------------------------------


def _closure(edges: Sequence[Tuple[str, str]], members: Sequence[str]) -> frozenset:
    """Transitive closure of a DAG, so transitivity holds by construction
    rather than by an argument in prose."""
    reach = {(a, b) for a, b in edges}
    changed = True
    while changed:
        changed = False
        for a, b in list(reach):
            for c, d in list(reach):
                if b == c and (a, d) not in reach:
                    reach.add((a, d))
                    changed = True
    for a, b in reach:
        if (b, a) in reach:
            raise SchemaError(f"order is cyclic: {a} <-> {b}")
    unknown = {x for pair in reach for x in pair} - set(members)
    if unknown:
        raise SchemaError(f"edges mention unknown members: {sorted(unknown)}")
    return frozenset(reach)


#: ``(dominates, dominated)``.  ``measured`` and ``asserted`` are deliberately
#: NOT connected: that incomparability is how "an ordinary assertion must not
#: beat a contradictory measurement" is expressed without a rank.
PROVENANCE_EDGES: Tuple[Tuple[str, str], ...] = (
    ("measured", "derived"),
    ("derived", "assumed"),
    ("asserted", "assumed"),
    ("assumed", "unknown"),
)

#: ``(contains, contained)`` over validity domains.  ``libc_file`` hangs off
#: ``process`` rather than sitting in the host chain, because a libc artifact
#: is an independent axis from a host -- a single total order here is
#: semantically false and picked the wrong candidate for ``libc.system_offset``.
SCOPE_EDGES: Tuple[Tuple[str, str], ...] = (
    ("build", "host"),
    ("host", "boot"),
    ("boot", "process"),
    ("process", "attempt"),
    ("libc_file", "process"),
)

#: Memoised on the edge tuple rather than computed once at import, so the
#: closure can never silently diverge from the edges it claims to close over
#: (and so a test that rebinds the edges genuinely changes the comparator).
_CLOSURE_CACHE: Dict[Tuple[Tuple[Tuple[str, str], ...], Tuple[str, ...]], frozenset] = {}


def _closure_of(edges: Sequence[Tuple[str, str]], members: Sequence[str]) -> frozenset:
    ck = (tuple(edges), tuple(members))
    if ck not in _CLOSURE_CACHE:
        _CLOSURE_CACHE[ck] = _closure(edges, members)
    return _CLOSURE_CACHE[ck]


def compare_provenance(a: Provenance, b: Provenance) -> Ordering:
    closure = _closure_of(PROVENANCE_EDGES, [m.value for m in Provenance])
    if a is b:
        return Ordering.EQUAL
    if (a.value, b.value) in closure:
        return Ordering.GREATER
    if (b.value, a.value) in closure:
        return Ordering.LESS
    return Ordering.INCOMPARABLE


def compare_scope(a: Scope, b: Scope) -> Ordering:
    """Specificity is the *reverse* of containment: narrower is more specific."""
    closure = _closure_of(SCOPE_EDGES, [m.value for m in Scope])
    if a is b:
        return Ordering.EQUAL
    if (b.value, a.value) in closure:
        return Ordering.GREATER
    if (a.value, b.value) in closure:
        return Ordering.LESS
    return Ordering.INCOMPARABLE


def compare_conditions(a: AppliesTo, b: AppliesTo) -> Ordering:
    """Strict subset containment, not a count.

    Counting matched conditions is not logical specificity: two unrelated
    single-condition predicates would compare equal, and two redundant
    conditions would beat one stronger one.
    """
    sa, sb = set(a.conditions), set(b.conditions)
    if sa == sb:
        return Ordering.EQUAL
    if sb < sa:
        return Ordering.GREATER
    if sa < sb:
        return Ordering.LESS
    return Ordering.INCOMPARABLE


def _compare_identity_bound(a: AppliesTo, b: AppliesTo) -> Ordering:
    ra, rb = int(a.identity is not None), int(b.identity is not None)
    if ra == rb:
        return Ordering.EQUAL
    return Ordering.GREATER if ra > rb else Ordering.LESS


def compare_specificity(a: Candidate, b: Candidate) -> Ordering:
    """Lexicographic over four components, halting on the first non-``EQUAL``.

    **Provenance is first**, and that placement is load-bearing: with
    provenance fourth, a ``measured`` build-scoped 72 and an ``asserted``
    process-scoped 80 were decided by the *scope* component and 80 won, so the
    ordering written to enforce the operator's rule violated it.  With
    provenance first, every applicable measured/asserted pair is
    ``INCOMPARABLE`` before scope, identity or conditions are consulted.

    Time is deliberately not a component: with equal timestamps a ``>``
    tiebreak returns ``GREATER`` in both directions (antisymmetry gone), and it
    silently resolves the very conflict that must not resolve silently.
    """
    for result in (
        compare_provenance(a.provenance, b.provenance),
        _compare_identity_bound(a.applies_to, b.applies_to),
        compare_scope(a.applies_to.scope, b.applies_to.scope),
        compare_conditions(a.applies_to, b.applies_to),
    ):
        if result is not Ordering.EQUAL:
            return result
    return Ordering.EQUAL


def maximal(pool: Sequence[Candidate]) -> List[Candidate]:
    """Maximal elements, never "sort and take the first" -- maximality is
    order-independent, which is what lets determinism hold under a partial
    order."""
    out = [c for c in pool
           if not any(compare_specificity(o, c) is Ordering.GREATER for o in pool)]
    return sorted(out, key=lambda c: c.id)


# ---------------------------------------------------------------------------
# Applicability, pins, conflicts, resolution
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ResolveContext:
    identities: frozenset = frozenset()
    conditions: Tuple[Tuple[str, str], ...] = ()
    host_id: Optional[str] = None
    boot_id: Optional[str] = None
    process_id: Optional[str] = None
    attempt_id: Optional[str] = None
    #: ``"strict"`` requires the candidate's identity to be live now; ``"none"``
    #: permits selecting across identities and is what ``--target-identity=none``
    #: sets.  It never disables verification.
    identity_mode: str = "strict"

    def binding_for(self, scope: Scope) -> Optional[str]:
        return {
            Scope.HOST: self.host_id,
            Scope.BOOT: self.boot_id,
            Scope.PROCESS: self.process_id,
            Scope.ATTEMPT: self.attempt_id,
        }.get(scope)

    def conditions_map(self) -> Dict[str, str]:
        return dict(self.conditions)


@dataclasses.dataclass(frozen=True)
class Selected:
    key: str
    value: Any
    witness: Candidate
    witnesses: Tuple[Candidate, ...]
    rule: str


@dataclasses.dataclass(frozen=True)
class Conflict:
    key: str
    cls: ConflictClass
    candidate_ids: Tuple[str, ...]


_STRUCTURAL_DATACLASSES.add(Conflict)


@dataclasses.dataclass(frozen=True)
class Agreement:
    key: str
    candidate_ids: Tuple[str, ...]
    value: Any


@dataclasses.dataclass(frozen=True)
class PinRecord:
    """One append-only lifecycle record: a pin, an unpin, a supersession or a
    retraction.

    ``seq`` is store-assigned and is the *only* ordering key.  ``at`` is an
    operator-supplied label kept for human readers; it is not an ordering key
    because nothing constrains it to be monotonic or even parseable.  ``actor``
    is mandatory: a pin is the one mechanism that lets an assertion beat a
    measurement, so an unattributed pin is not an acceptable record of an
    explicit operator decision.
    """

    cls: str
    key: str
    candidate_id: Optional[str]
    at: str
    seq: int
    actor: str
    reason: str = ""
    by_candidate_id: Optional[str] = None

    @property
    def id(self) -> str:
        return _sha(canonical(self))[:_ID_HEX]


_STRUCTURAL_DATACLASSES.add(PinRecord)

#: Built here, only now that every _STRUCTURAL_DATACLASSES member (Observation,
#: Ref, AppliesTo, Conflict, PinRecord) has registered itself above.
_STRUCTURAL_FIELD_TYPES.update(_build_structural_field_types())


#: The two identity modes.  An unknown mode used to be treated as strict, so a
#: typo -- ``"None"``, ``"loose"`` -- silently selected the *stricter* behaviour
#: and the operator's intent was discarded without a word.
IDENTITY_MODES: Tuple[str, ...] = ("strict", "none")


def validate_context(ctx: Any) -> ResolveContext:
    """Validate a :class:`ResolveContext`; raise :class:`SchemaError` if it is
    malformed.

    :func:`resolve` claims that every exit is a :class:`Selected` or one of five
    declared refusals.  That claim was false for a *malformed* context:
    ``identities=None`` leaked ``TypeError`` out of ``applicable``, bad condition
    pairs leaked ``ValueError`` out of ``dict()``, and an unknown
    ``identity_mode`` leaked nothing at all -- it just quietly meant strict.  The
    claim now holds over well-formed contexts, and an ill-formed one is a
    ``SchemaError`` before any of the five refusals can be reached.
    """
    if not isinstance(ctx, ResolveContext):
        raise SchemaError(
            f"context must be a ResolveContext, got {type(ctx).__name__}")
    if not isinstance(ctx.identities, (frozenset, set)):
        raise SchemaError(
            f"context.identities must be a set, got {type(ctx.identities).__name__}")
    for ident in ctx.identities:
        if not isinstance(ident, str) or not ident:
            raise SchemaError("context.identities entries must be non-empty strings")
    _validate_conditions(ctx.conditions)
    for name in ("host_id", "boot_id", "process_id", "attempt_id"):
        value = getattr(ctx, name)
        if value is not None and (not isinstance(value, str) or not value):
            raise SchemaError(f"context.{name} must be a non-empty string or null")
    if ctx.identity_mode not in IDENTITY_MODES:
        raise SchemaError(
            f"context.identity_mode {ctx.identity_mode!r} not in {list(IDENTITY_MODES)}")
    return ctx


def applicable(c: Candidate, ctx: ResolveContext) -> bool:
    """Pure predicate.  A candidate bound to another identity is **not
    demoted** -- its provenance is never rewritten; it is simply inapplicable
    here, and using it elsewhere requires an explicit re-assertion.

    C10: every exported function that consumes a :class:`ResolveContext`
    validates it first.  ``applicable`` was the one exception -- a malformed
    context (``identities`` as a list rather than a set, an empty-string
    identity, a garbage ``identity_mode``) that :func:`validate_context`
    already refuses did not raise here; it silently returned ``True`` or
    ``False`` depending on which malformed field it tripped over first.
    """
    validate_context(ctx)
    at = c.applies_to
    if ctx.identity_mode != "none" and at.identity is not None:
        if at.identity not in ctx.identities:
            return False
    if at.scope in _BOUND_SCOPES and at.binding != ctx.binding_for(at.scope):
        return False
    ctx_conds = ctx.conditions_map()
    # A condition the invocation does not constrain makes the candidate
    # inapplicable: refuse rather than guess.
    return all(ctx_conds.get(k) == v for k, v in at.conditions)


def current_pins(store: FactStore) -> Dict[str, str]:
    """A defined fold over the append-only log, not "if ctx.pins holds one".

    Total and order-independent: for each key take the record with the greatest
    store-assigned ``seq`` among ``pin``/``unpin``; an ``unpin`` yields no entry.

    ``seq`` and not ``at``: ``at`` is operator text, and folding on it made
    ``"t10"`` lose to ``"t9"`` and equal timestamps fall back to whichever
    record had the larger content hash -- a "latest pin" rule that was
    deterministic but not chronological.
    """
    # Validated at **read** time too, not only when a write passes through
    # merge(): a pin is the one mechanism allowed to override a measurement, so
    # the record granting that override is checked at the moment it is honoured.
    # (The in-process trust boundary is not a wall -- a caller holding the store
    # can append to a public list as easily as it can call pin() -- but a
    # forged record must now at least be well formed, uniquely sequenced and
    # *attributed*, and it is in the audit log either way.  The enforceable
    # boundary is the document, and I7 is what guards it.)
    _validate_log(store)
    latest: Dict[str, PinRecord] = {}
    for rec in store.resolutions:
        if rec.cls not in ("pin", "unpin"):
            continue
        cur = latest.get(rec.key)
        if cur is None or rec.seq > cur.seq:
            latest[rec.key] = rec
    return {k: r.candidate_id for k, r in latest.items()
            if r.cls == "pin" and r.candidate_id is not None}


def contradiction_guard(key: str, pool: Sequence[Candidate], pins: Mapping[str, str]) -> None:
    """Enforce "asserted never silently beats measured" a **second time**,
    independently of the component order.

    Resting the invariant on ``compare_specificity`` alone is fragile: one
    reordering breaks it silently, which is exactly what happened in rev 1.
    """
    if key in pins:
        return
    for i, a in enumerate(pool):
        for b in pool[i + 1:]:
            provs = {a.provenance, b.provenance}
            if provs == {Provenance.MEASURED, Provenance.ASSERTED} and \
                    canonical(a.value) != canonical(b.value):
                raise FactUnresolved(
                    key, sorted((a, b), key=lambda c: c.id),
                    ConflictClass.CONTRADICTION_MEASURED_ASSERTED,
                )


def jointly_satisfiable(a: Candidate, b: Candidate) -> bool:
    """Could one invocation find **both** candidates applicable?

    Two candidates bound to different processes, different boots or
    contradictory condition values can never both apply, so a disagreement
    between them is not a conflict anybody can encounter -- reporting it as one
    filled the log with pairs that no context could ever pit against each other.

    Differing *identities* are **not** mutually exclusive: ``identity_mode
    ="none"`` makes both applicable at once, which is exactly the hazard
    :class:`ConflictClass.AMBIGUOUS_ACROSS_IDENTITIES` exists to name.
    """
    at_a, at_b = a.applies_to, b.applies_to
    if at_a.scope is at_b.scope and at_a.scope in _BOUND_SCOPES \
            and at_a.binding != at_b.binding:
        return False
    shared = at_a.conditions_map()
    for name, value in at_b.conditions:
        if name in shared and shared[name] != value:
            return False
    return True


def classify_pair(a: Candidate, b: Candidate) -> Optional[ConflictClass]:
    """The **one** classifier, used by both :func:`resolve` and :func:`conflicts`.

    Factored out because two copies of an ordered partition drift, and a drifted
    partition is how a conflict ends up in two classes or none.  Ordered: the
    first condition that holds wins.

    Returns ``None`` exactly for a pair that is not a conflict: one that cannot
    be jointly applicable, or one that genuinely :func:`agreeing`.  Equal values
    across identities are **not** agreement and are no longer silently dropped.
    """
    if not jointly_satisfiable(a, b):
        return None
    if canonical(a.value) == canonical(b.value):
        return None if agreeing((a, b)) else ConflictClass.AMBIGUOUS_ACROSS_IDENTITIES
    if {a.provenance, b.provenance} == {Provenance.MEASURED, Provenance.ASSERTED}:
        return ConflictClass.CONTRADICTION_MEASURED_ASSERTED
    order = compare_specificity(a, b)
    if order is Ordering.EQUAL:
        return ConflictClass.EQUALLY_SPECIFIC
    if order is Ordering.INCOMPARABLE:
        return ConflictClass.INCOMPARABLE
    return ConflictClass.DOMINATED


#: Which class ``resolve`` reports when a pool exhibits several.  Lower wins.
#: It must cover every class :func:`classify_pair` can return, which
#: ``test_resolve_priority_covers_every_classifiable_conflict`` checks -- the
#: previous code fell through to a hard-coded ``INCOMPARABLE``, which would have
#: mislabelled any class added later instead of failing.
CONFLICT_PRIORITY: Dict[ConflictClass, int] = {
    ConflictClass.CONTRADICTION_MEASURED_ASSERTED: 0,
    ConflictClass.AMBIGUOUS_ACROSS_IDENTITIES: 1,
    ConflictClass.INCOMPARABLE: 2,
    ConflictClass.EQUALLY_SPECIFIC: 3,
    ConflictClass.DOMINATED: 4,
}


def agreeing(candidates: Sequence[Candidate]) -> bool:
    """Equal encodings are not equal propositions.

    Two ``gadget.pop_rdi`` candidates from *different builds* can both hold
    integer ``0x401234`` while referring to different instructions -- a real
    hazard under ``--target-identity=none``.  So agreement is recognised only
    within one identity.
    """
    return (len({canonical(c.value) for c in candidates}) == 1
            and len({c.applies_to.identity for c in candidates}) == 1)


def resolve(store: FactStore, key: str, ctx: ResolveContext) -> Selected:
    """Return one :class:`Selected` or raise one of five declared refusals.

    Never returns a bare value and never accepts a ``default``: a fact that was
    never measured has no candidate, and the caller must handle that.
    """
    spec_for(key)  # unknown keys are a SchemaError, not an absence
    validate_context(ctx)
    # The store is validated on the way *out* as well as on the way in.  A
    # malformed public list -- a forged log record, a hand-appended conflict --
    # used to be honoured by resolution and only surfaced later from
    # ``canonical_document``, i.e. nowhere near whatever put it there.
    validate_store(store)
    pool = [c for c in store.active(key) if applicable(c, ctx)]
    pins = current_pins(store)

    contradiction_guard(key, pool, pins)

    if key in pins:
        pinned = [c for c in pool if c.id == pins[key]]
        if not pinned:
            # Say *which* of the three things went wrong, because the operator's
            # next command differs: unpin, re-pin, or widen the context.  A
            # retracted pin target is not "inapplicable here" and reporting it
            # that way sends the operator looking at the wrong thing.
            held = store.by_id(pins[key])
            if held is None:
                why = "no longer exists in this document"
            elif held.state is not State.ACTIVE:
                why = f"is {held.state.value}; unpin or pin a live candidate"
            else:
                why = "is not applicable in this context"
            raise PinInapplicable(f"{key}: pinned candidate {pins[key]} {why}")
        chosen = Selected(key, pinned[0].value, pinned[0], (pinned[0],), "operator_pin")
        _refuse_if_stale(store, chosen)
        return chosen

    winners = maximal(pool)
    if not winners:
        raise FactUnavailable(f"{key}: no applicable active candidate")
    if not agreeing(winners):
        # Every pair of maximal candidates is EQUAL or INCOMPARABLE -- if one
        # dominated the other the loser would not be maximal -- so DOMINATED is
        # unreachable here, and reporting it would have been a lie.
        classes = {classify_pair(a, b) for a, b in _pairwise(winners)}
        classes.discard(None)
        # ``winners`` is a maximal set that does not agree, so some pair differs
        # in value or in identity, so ``classes`` is non-empty -- and every
        # member is in ``CONFLICT_PRIORITY`` by the coverage test.  There is no
        # fallback branch to be wrong.
        raise FactUnresolved(key, winners, min(classes, key=CONFLICT_PRIORITY.__getitem__))

    # ``witnesses`` is the whole maximal set; ``witness`` is the representative.
    # It is well defined rather than arbitrary: past ``agreeing()`` every winner
    # carries the same value *and* the same identity, so any of them answers the
    # question identically, and ``maximal()`` sorts by a 128-bit content-derived
    # id so the representative is also stable across runs.
    chosen = Selected(
        key, winners[0].value, winners[0], tuple(winners),
        "unique_maximal" if len(winners) == 1 else "agreed_value",
    )
    _refuse_if_stale(store, chosen)
    return chosen


def _refuse_if_stale(store: FactStore, chosen: Selected) -> None:
    for c in chosen.witnesses:
        if is_stale(store, c):
            raise FactStale(f"{chosen.key}: {c.id} rests on a source that changed")


def try_resolve(store: FactStore, key: str, ctx: ResolveContext):
    """``Selected`` or :data:`ABSENT`.  Only :class:`FactUnavailable` is
    softened -- an unresolved conflict or a stale fact still raises."""
    try:
        return resolve(store, key, ctx)
    except FactUnavailable:
        return ABSENT


def _pairwise(pool: Sequence[Candidate]) -> Iterator[Tuple[Candidate, Candidate]]:
    for i, a in enumerate(pool):
        for b in pool[i + 1:]:
            yield a, b


def conflicts(store: FactStore, ctx: ResolveContext) -> List[Conflict]:
    """Conflicts *in a given context* -- the resolve-time view."""
    validate_context(ctx)
    out: List[Conflict] = []
    for key in store.keys():
        pool = [c for c in store.active(key) if applicable(c, ctx)]
        for a, b in _pairwise(pool):
            cls = classify_pair(a, b)
            if cls is not None:
                out.append(Conflict(key, cls, tuple(sorted((a.id, b.id)))))
    return sorted(out, key=lambda c: (c.key, c.cls.value, c.candidate_ids))


def context_free_conflicts(store: FactStore, key: Optional[str] = None) -> List[Conflict]:
    """Conflicts visible **without** a resolve context; what :func:`merge` records.

    A producer-only workflow (``analyze`` with no ``pwn``) never calls
    :func:`resolve` and has no ``ResolveContext``, so a context-scoped conflict
    report would never run and contradictions would accumulate in silence.  This
    view is deliberately over-inclusive: it reports pairs that some future
    context may render inapplicable, which is the safe direction.
    """
    out: List[Conflict] = []
    for k in ([key] if key is not None else store.keys()):
        for a, b in _pairwise(store.active(k)):
            cls = classify_pair(a, b)
            if cls is not None:
                out.append(Conflict(k, cls, tuple(sorted((a.id, b.id)))))
    return sorted(out, key=lambda c: (c.key, c.cls.value, c.candidate_ids))


def agreements(store: FactStore, ctx: ResolveContext) -> List[Agreement]:
    """Same-value pairs are not conflicts; recording them makes "two
    authorities concurred" visible rather than inferred.

    Agreement is decided by :func:`agreeing`, the same predicate
    :func:`resolve` uses.  Testing equal *values* alone reported two different
    builds' ``0x401234`` as concurrence, which contradicted both ``agreeing()``
    and P19.
    """
    validate_context(ctx)
    out: List[Agreement] = []
    for key in store.keys():
        pool = [c for c in store.active(key) if applicable(c, ctx)]
        for a, b in _pairwise(pool):
            if agreeing((a, b)):
                out.append(Agreement(key, tuple(sorted((a.id, b.id))), a.value))
    return sorted(out, key=lambda a: (a.key, a.candidate_ids))


def is_stale(store: FactStore, c: Candidate, _seen: Optional[set] = None) -> bool:
    """The **one** staleness mechanism: computed, never persisted.

    There is no ``stale`` field, no invalidation event and no transactional
    closure update, because supersession and pinning invalidate dependents
    automatically -- the source stops being ``ACTIVE`` and this predicate sees
    it on the next read.  The visited set makes it terminate even on a cyclic
    input that validation somehow let through.
    """
    seen = set() if _seen is None else _seen
    if c.id in seen:
        return False
    seen.add(c.id)
    for ref in c.derived_from:
        src = store.by_id(ref.id)
        if src is None:
            return True
        # ``Ref.key`` is part of the reference, so a reference that names the
        # right id under the wrong key is structurally false and therefore
        # stale.  Ignoring it let a false reference read as fresh.
        if src.key != ref.key:
            return True
        if src.state is not State.ACTIVE:
            return True
        if candidate_digest(src) != ref.digest:
            return True
        if is_stale(store, src, seen):
            return True
    return False


# ---------------------------------------------------------------------------
# Canonical document: array order is a function of content, never of
# insertion order, so the digest is permutation-invariant with no second
# projection to keep in step.
# ---------------------------------------------------------------------------


def canonical_document(store: FactStore) -> str:
    validate_store(store)
    facts = {}
    for key in store.keys():
        facts[key] = [
            {
                "id": c.id,
                "key": c.key,
                "value": _jsonable_structural(c.value),
                "provenance": c.provenance.value,
                "applies_to": _jsonable_structural(c.applies_to),
                "derived_from": _jsonable_structural(c.derived_from),
                "method": c.method,
                "by": c.by,
                "state": c.state.value,
                "generation": c.generation,
                "observations": _jsonable_structural(
                    sorted(c.observations, key=lambda o: (o.at, o.digest()))
                ),
            }
            for c in sorted(store.candidates(key), key=lambda c: c.id)
        ]
    doc = {
        "schema_version": "supwngo.context/v1",
        "facts": facts,
        # ``seq`` is unique by I7, so this total order needs no tiebreak and
        # cannot depend on a free-text ``at``.
        "resolutions": _jsonable_structural(sorted(store.resolutions, key=lambda r: r.seq)),
        "conflicts": _jsonable_structural(
            sorted(store.conflicts, key=lambda c: (c.key, c.cls.value, c.candidate_ids))
        ),
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Table generation.  Every cell is produced by CALLING the runtime comparator.
# A generator backed by parallel constants would agree with itself byte for
# byte while disagreeing with resolution, which is the one thing a byte gate
# cannot catch -- so there are no constants here.
# ---------------------------------------------------------------------------


_SYM = {
    Ordering.GREATER: "≻",       # succeeds
    Ordering.LESS: "≺",          # precedes
    Ordering.EQUAL: "=",
    Ordering.INCOMPARABLE: "∥",  # parallel / incomparable
}


def _matrix(title: str, members: Sequence[Any], label, cmp) -> List[str]:
    heads = [label(m) for m in members]
    lines = [f"### {title}", "",
             "| row ≻ col? | " + " | ".join(heads) + " |",
             "|---" * (len(heads) + 1) + "|"]
    for a in members:
        cells = [_SYM[cmp(a, b)] for b in members]
        lines.append(f"| **{label(a)}** | " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def emit_tables() -> str:
    """Render the normative tables by exercising the real comparators."""
    out: List[str] = [
        "# Context resolution: normative tables",
        "",
        "**Generated** by `python -m supwngo.schema.resolve --emit-tables`.",
        "Do not hand-edit: `tests/test_context_resolve_properties.py` asserts this",
        "file is byte-identical to freshly generated output, and every cell below is",
        "produced by calling the runtime comparator rather than read from a table.",
        "",
        "Legend: `≻` row dominates column, `≺` column dominates row,",
        "`=` equal, `∥` incomparable (neither dominates -- resolution refuses).",
        "",
    ]
    out += _matrix("Provenance precedence", list(Provenance), lambda m: m.value,
                   compare_provenance)
    out += _matrix("Scope specificity", list(Scope), lambda m: m.value, compare_scope)

    out += ["### Candidate state transitions", "",
            "| state | " + " | ".join(STATE_EVENTS) + " |",
            "|---" * (len(STATE_EVENTS) + 1) + "|"]
    for st in [None] + list(State):
        cells = []
        for ev in STATE_EVENTS:
            try:
                cells.append(transition(st, ev).value)
            except StateTransitionError:
                cells.append("REFUSED")
        out.append(f"| **{'absent' if st is None else st.value}** | " + " | ".join(cells) + " |")
    out.append("")

    out += ["### Merge decisions", "",
            "| store already holds | decision |", "|---|---|"]
    for scenario, decision in _merge_scenarios():
        out.append(f"| {scenario} | `{decision}` |")
    out.append("")

    out += ["### Per-key allowed scopes", "",
            "`allowed scopes` is **enforced** by validation (invariant I4).",
            "`depends_on` and `verification class` are **declarations for the",
            "Phase-2 document layer**: this module has no loaded binary and no",
            "tooling, so it performs no verification and does not pretend to.",
            "They are listed here so the declaration is reviewable, not because",
            "resolution consults them.",
            "",
            "| fact key | allowed scopes | depends_on | verification class (declared) |",
            "|---|---|---|---|"]
    for key, spec in sorted(FACT_KEYS.items()):
        out.append(f"| `{key}` | {', '.join(sorted(s.value for s in spec.allowed_scopes))} "
                   f"| `{spec.depends_on}` | `{spec.verification_class}` |")
    for prefix, spec in sorted(_FACT_PREFIXES.items()):
        out.append(f"| `{prefix}*` | {', '.join(sorted(s.value for s in spec.allowed_scopes))} "
                   f"| `{spec.depends_on}` | `{spec.verification_class}` |")
    out.append("")
    return "\n".join(out)


def _merge_scenarios() -> List[Tuple[str, str]]:
    """Exercise the real merge() against synthesised stores, so the merge table
    is observed behaviour rather than a restatement of intent."""
    def cand(value=72, prov=Provenance.MEASURED, method="m1", at="t1"):
        return {
            "key": "stack.return_offset", "value": value, "provenance": prov,
            "applies_to": {"identity": "t_main", "scope": Scope.BUILD},
            "method": method, "by": "supwngo offset",
            "observations": [{"at": at}],
        }

    rows: List[Tuple[str, str]] = []

    s = FactStore()
    rows.append(("nothing", merge(s, cand()).value))

    s = FactStore(); merge(s, cand())
    rows.append(("an active candidate with the same dedup key", merge(s, cand(at="t2")).value))

    s = FactStore(); merge(s, cand())
    rows.append(("an active candidate, same value, different provenance",
                 merge(s, cand(prov=Provenance.ASSERTED)).value))

    s = FactStore(); merge(s, cand())
    rows.append(("an active candidate, same value, different method",
                 merge(s, cand(method="m2")).value))

    s = FactStore(); merge(s, cand())
    rows.append(("an active candidate with a different value", merge(s, cand(value=80)).value))

    s = FactStore(); merge(s, cand())
    retract(s, s.active("stack.return_offset")[0].id, "t0", "wrong", "operator")
    rows.append(("only a **retracted** candidate with the same dedup key",
                 merge(s, cand(at="t3")).value))

    s = FactStore(); merge(s, cand())
    try:
        merge(s, dict(cand(at="t4"), state=State.RETRACTED))
        rows.append(("anything, and the incoming state is not active", "unreachable"))
    except SchemaError:
        rows.append(("anything, and the incoming state is not `active`",
                     "SchemaError (only the state machine changes states)"))

    s = FactStore()
    try:
        merge(s, cand(value=-1))
        rows.append(("anything, and the incoming value is invalid", "unreachable"))
    except SchemaError:
        rows.append(("anything, and the incoming candidate fails validation",
                     "SchemaError (precondition, not a case)"))
    return rows


def _main(argv: Sequence[str]) -> int:  # pragma: no cover - CLI shim
    if "--emit-tables" in argv:
        print(emit_tables(), end="")
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(_main(sys.argv[1:]))
