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
* every public function is pure except :func:`merge`, :func:`supersede` and
  :func:`retract`, which mutate exactly one :class:`FactStore`.

See ``docs/plans/2026-09-24-standardized-context-schema.md``.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import re
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "Provenance", "Scope", "State", "Ordering", "MergeDecision", "ConflictClass",
    "SchemaError", "StateTransitionError", "FactUnavailable", "FactUnresolved",
    "FactStale", "PinInapplicable",
    "Absent", "ABSENT",
    "Observation", "Ref", "AppliesTo", "Candidate", "FactStore", "ResolveContext",
    "Selected", "Conflict", "Agreement", "PinRecord",
    "canonical", "derive_id", "candidate_digest", "dedup_key",
    "validate_candidate", "validate_store",
    "merge", "supersede", "retract", "transition",
    "compare_provenance", "compare_scope", "compare_conditions",
    "compare_specificity", "maximal",
    "applicable", "current_pins", "contradiction_guard", "agreeing",
    "resolve", "try_resolve", "conflicts", "agreements", "is_stale",
    "canonical_document", "classify_pair",
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


def _jsonable(obj: Any) -> Any:
    """Project to a JSON-canonicalisable form.  Raises for anything else, so a
    non-canonicalisable value is a validation failure rather than a surprise
    inside a digest."""
    if obj is None or isinstance(obj, (bool, int, str)):
        return obj
    if isinstance(obj, float):
        raise SchemaError("floats are not canonicalisable; addresses are ints")
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, bytes):
        return "b64:" + __import__("base64").b64encode(obj).decode("ascii")
    if isinstance(obj, Mapping):
        return {str(k): _jsonable(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (frozenset, set)):
        return sorted((_jsonable(v) for v in obj), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if dataclasses.is_dataclass(obj):
        return {f.name: _jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    raise SchemaError(f"not canonicalisable: {type(obj).__name__}")


def canonical(obj: Any) -> str:
    """RFC 8785-flavoured canonical JSON: sorted keys, no whitespace.

    Arrays are *not* sorted here -- array order is fixed by the canonical
    array-ordering rule in :func:`canonical_document`, so that order is a
    function of content rather than of insertion order.
    """
    return json.dumps(_jsonable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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


@dataclasses.dataclass(frozen=True)
class Ref:
    """A dependency reference.  Structured, not a string, because fact keys
    already contain ``@``; and it carries ``key`` so a dependent can be located
    without scanning every key."""

    key: str
    id: str
    digest: str


@dataclasses.dataclass(frozen=True)
class AppliesTo:
    identity: Optional[str]
    scope: Scope
    conditions: Tuple[Tuple[str, str], ...] = ()
    #: instance id of the scope, for the scopes that have one
    binding: Optional[str] = None

    def conditions_map(self) -> Dict[str, str]:
        return dict(self.conditions)


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
        return {name: getattr(self, name) for name in fields}

    @property
    def last_observed_at(self) -> str:
        """Derived, never stored -- which is why it cannot be order-dependent."""
        return max(o.at for o in self.observations)

    @property
    def first_observed_at(self) -> str:
        return min(o.at for o in self.observations)


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


def _validate_conditions(raw: Any) -> Tuple[Tuple[str, str], ...]:
    """Conditions are a sorted tuple of ``(str, str)`` pairs.

    Shared by the mapping and the constructed-``AppliesTo`` paths so the two
    cannot drift; a constructed instance is re-checked because a typed container
    is not a validated one.  Sorting here is what makes
    :func:`compare_conditions`' set algebra and the canonical bytes agree.
    """
    if raw is None:
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
            at_raw.identity, _as_enum(Scope, at_raw.scope, "scope"),
            _validate_conditions(at_raw.conditions), at_raw.binding,
        )
        if applies_to.identity is not None and not isinstance(applies_to.identity, str):
            raise SchemaError("applies_to.identity must be a string or null")
        if applies_to.binding is not None and not isinstance(applies_to.binding, str):
            raise SchemaError("applies_to.binding must be a string or null")
    elif isinstance(at_raw, Mapping):
        scope = _as_enum(Scope, at_raw.get("scope"), "scope")
        conds_items = _validate_conditions(at_raw.get("conditions") or ())
        identity = at_raw.get("identity")
        if identity is not None and not isinstance(identity, str):
            raise SchemaError("applies_to.identity must be a string or null")
        binding = at_raw.get("binding")
        if binding is not None and not isinstance(binding, str):
            raise SchemaError("applies_to.binding must be a string or null")
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
            f"{key}: scope {applies_to.scope.value} not in "
            f"{sorted(s.value for s in spec.allowed_scopes)}"
        )
    if applies_to.scope in _BOUND_SCOPES and not applies_to.binding:
        raise SchemaError(f"{key}: scope {applies_to.scope.value} requires applies_to.binding")
    if applies_to.scope not in _BOUND_SCOPES and applies_to.binding:
        raise SchemaError(f"{key}: scope {applies_to.scope.value} takes no binding")

    method, by = data.get("method"), data.get("by")
    for name, val in (("method", method), ("by", by)):
        if not isinstance(val, str) or not val:
            raise SchemaError(f"{name} must be a non-empty string")

    obs_raw = data.get("observations") or ()
    if isinstance(obs_raw, (str, bytes, Mapping)) or not isinstance(obs_raw, (list, tuple)):
        raise SchemaError("observations must be a list")
    observations: List[Observation] = []
    for o in obs_raw:
        # A constructed Observation is re-checked for the same reason as
        # AppliesTo above: a typed container is not a validated one.
        at = o.at if isinstance(o, Observation) else (
            o.get("at") if isinstance(o, Mapping) else None)
        if not isinstance(at, str) or not at:
            raise SchemaError("observation.at must be a non-empty string")
        ev = (o.evidence if isinstance(o, Observation)
              else (o.get("evidence") or ()))
        if isinstance(ev, Mapping):
            ev_items = tuple(sorted((str(k), v) for k, v in ev.items()))
        elif isinstance(ev, (list, tuple)):
            ev_items = tuple(sorted((str(k), v) for k, v in ev))
        else:
            raise SchemaError("observation.evidence must be a mapping or pairs")
        canonical(ev_items)
        observations.append(Observation(at, ev_items))
    if not observations:
        raise SchemaError("a candidate needs at least one observation")

    refs_raw = data.get("derived_from") or ()
    if isinstance(refs_raw, (str, bytes, Mapping)) or \
            not isinstance(refs_raw, (list, tuple)):
        raise SchemaError("derived_from must be a list")
    refs: List[Ref] = []
    for r in refs_raw:
        if isinstance(r, Ref):
            rkey, rid, rdigest = r.key, r.id, r.digest
        elif isinstance(r, Mapping):
            missing = {"key", "id", "digest"} - set(r)
            if missing:
                raise SchemaError(f"derived_from entry missing {sorted(missing)}")
            rkey, rid, rdigest = r["key"], r["id"], r["digest"]
        else:
            raise SchemaError("derived_from entry must be a mapping")
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
        #: ``digest`` is in the sort key: two refs to the same ``(key, id)`` with
        #: different digests are different facts, and omitting it left their
        #: order dependent on input order.
        derived_from=tuple(sorted(refs, key=lambda r: (r.key, r.id, r.digest))),
        state=state,
        generation=generation,
    )
    canonical(candidate.value)  # raises SchemaError if not canonicalisable
    candidate = dataclasses.replace(candidate, id=derive_id(candidate))

    given_id = data.get("id") or ""
    if given_id and given_id != candidate.id:
        raise SchemaError(f"id {given_id!r} is not derive_id(candidate) ({candidate.id})")
    if not _ID_RE.match(candidate.id):  # pragma: no cover - derive_id shape is fixed
        raise SchemaError(f"malformed id: {candidate.id}")
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
        for c in self.all_candidates():
            if c.id == cid:
                return c
        return None

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
        if conflict not in self.conflicts:
            self.conflicts.append(conflict)
        self.conflicts.sort(key=lambda c: (c.key, c.cls.value, c.candidate_ids))

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


def validate_store(store: FactStore) -> None:
    """Check I1-I7 transactionally.  An invalid graph is never persisted."""
    seen_ids: Dict[str, Candidate] = {}
    for key in store.keys():
        active_keys: Dict[str, str] = {}
        for c in store.candidates(key):
            validate_candidate(c)                                     # I1
            if c.id != derive_id(c):                                  # I2
                raise SchemaError(f"{c.id}: id is not a function of content")
            if c.key != key:
                raise SchemaError(f"{c.id}: filed under {key!r} but claims {c.key!r}")
            if c.state is State.ACTIVE:                               # I3
                dk = dedup_key(c)
                if dk in active_keys:
                    raise SchemaError(
                        f"{key}: duplicate active dedup key ({active_keys[dk]}, {c.id})"
                    )
                active_keys[dk] = c.id
            if c.id in seen_ids:                                      # I6
                raise SchemaError(f"duplicate candidate id {c.id}")
            seen_ids[c.id] = c
    for c in seen_ids.values():                                       # I5
        _assert_acyclic(store, c, set(), set())
        for ref in c.derived_from:                                    # I5b
            src = seen_ids.get(ref.id)
            if src is not None and src.key != ref.key:
                raise SchemaError(
                    f"{c.id}: derived_from names {ref.id} under key {ref.key!r} "
                    f"but that candidate is filed under {src.key!r}"
                )
    _validate_log(store)                                              # I7


_LOG_CLASSES: Tuple[str, ...] = ("pin", "unpin", "supersede", "retract")


def _validate_log(store: FactStore) -> None:
    """I7: the append-only log is well formed and totally ordered by ``seq``.

    Without this the log was a public list of unvalidated records, and
    :func:`current_pins` -- the one thing that can override a measurement --
    folded over whatever a caller had appended.
    """
    seen_seq = set()
    for rec in store.resolutions:
        if not isinstance(rec, PinRecord):
            raise SchemaError(f"log entry is not a PinRecord: {type(rec).__name__}")
        if rec.cls not in _LOG_CLASSES:
            raise SchemaError(f"log entry class {rec.cls!r} not in {list(_LOG_CLASSES)}")
        if isinstance(rec.seq, bool) or not isinstance(rec.seq, int) or rec.seq < 1:
            raise SchemaError(f"log entry seq must be a positive int, got {rec.seq!r}")
        if rec.seq in seen_seq:
            raise SchemaError(f"duplicate log seq {rec.seq}")
        seen_seq.add(rec.seq)
        if not isinstance(rec.at, str) or not rec.at:
            raise SchemaError("log entry needs a non-empty at")
        if not isinstance(rec.actor, str) or not rec.actor:
            raise SchemaError("log entry needs a non-empty actor")
        if not isinstance(rec.key, str) or not rec.key:
            raise SchemaError("log entry needs a non-empty key")
        for field in ("candidate_id", "by_candidate_id"):
            cid = getattr(rec, field)
            if cid is not None and not _ID_RE.match(cid):
                raise SchemaError(f"log entry {field} is not a candidate id: {cid!r}")
        if rec.cls != "unpin" and rec.candidate_id is None:
            raise SchemaError(f"a {rec.cls} record must name a candidate")


def _assert_acyclic(store: FactStore, c: Candidate, path: set, done: set) -> None:
    if c.id in done:
        return
    if c.id in path:
        raise SchemaError(f"derived_from cycle through {c.id}")
    path.add(c.id)
    for ref in c.derived_from:
        src = store.by_id(ref.id)
        if src is not None:
            _assert_acyclic(store, src, path, done)
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
            # a fresh ``generation``, so the live and terminal siblings cannot
            # share an id, and it tells the operator.
            terminal = [c for c in store.candidates(key)
                        if c.state is not appended_state and dedup_key(c) == dk]
            if terminal:
                generation = 1 + max(c.generation for c in terminal)
                if candidate.generation != generation:
                    if _carries_explicit_id(incoming):
                        raise SchemaError(
                            f"{key}: generation is assigned by the store "
                            f"({generation} here), so the supplied id is stale; "
                            "merge the candidate without an id"
                        )
                    candidate = dataclasses.replace(candidate, generation=generation)
                    candidate = dataclasses.replace(candidate, id=derive_id(candidate))
                for t in sorted(terminal, key=lambda c: c.id):
                    store._record_conflict(Conflict(
                        key,
                        ConflictClass.REOBSERVED_AFTER_RETRACTION
                        if t.state is State.RETRACTED
                        else ConflictClass.REOBSERVED_AFTER_SUPERSESSION,
                        tuple(sorted((t.id, candidate.id))),
                    ))
            store._bucket(key).append(candidate)
            store._sorted(key)
            decision = MergeDecision.APPENDED

        # Conflicts are recorded on **every write**, not only on resolve: a
        # producer-only run (``analyze`` with no ``pwn``) never resolves, and
        # without this it accumulated contradictions in silence.
        for conflict in context_free_conflicts(store, key):
            store._record_conflict(conflict)

        validate_store(store)                           # I1-I7 hold AFTER it too
    except Exception:
        store._restore(snap)
        raise
    return decision


def _carries_explicit_id(incoming: Any) -> bool:
    if isinstance(incoming, Candidate):
        return bool(incoming.id)
    if isinstance(incoming, Mapping):
        return bool(incoming.get("id"))
    return False


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
    if (state, event) not in _TRANSITIONS:  # pragma: no cover - P11 forbids
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


def applicable(c: Candidate, ctx: ResolveContext) -> bool:
    """Pure predicate.  A candidate bound to another identity is **not
    demoted** -- its provenance is never rewritten; it is simply inapplicable
    here, and using it elsewhere requires an explicit re-assertion."""
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


def classify_pair(a: Candidate, b: Candidate) -> Optional[ConflictClass]:
    """The **one** classifier, used by both :func:`resolve` and :func:`conflicts`.

    Factored out because two copies of an ordered partition drift, and a drifted
    partition is how a conflict ends up in two classes or none.  Ordered: the
    first condition that holds wins, and the four cases are exhaustive over
    differing-value pairs because :class:`Ordering` has exactly four members.

    Returns ``None`` for a pair whose values agree -- those are agreements, not
    conflicts.
    """
    if canonical(a.value) == canonical(b.value):
        return None
    if {a.provenance, b.provenance} == {Provenance.MEASURED, Provenance.ASSERTED}:
        return ConflictClass.CONTRADICTION_MEASURED_ASSERTED
    order = compare_specificity(a, b)
    if order is Ordering.EQUAL:
        return ConflictClass.EQUALLY_SPECIFIC
    if order is Ordering.INCOMPARABLE:
        return ConflictClass.INCOMPARABLE
    return ConflictClass.DOMINATED


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
    pool = [c for c in store.active(key) if applicable(c, ctx)]
    pins = current_pins(store)

    contradiction_guard(key, pool, pins)

    if key in pins:
        pinned = [c for c in pool if c.id == pins[key]]
        if not pinned:
            raise PinInapplicable(
                f"{key}: pinned candidate {pins[key]} is not applicable here"
            )
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
        classes = {classify_pair(a, b) for a in winners for b in winners
                   if a is not b}
        classes.discard(None)
        for preferred in (ConflictClass.CONTRADICTION_MEASURED_ASSERTED,
                          ConflictClass.INCOMPARABLE,
                          ConflictClass.EQUALLY_SPECIFIC):
            if preferred in classes:
                raise FactUnresolved(key, winners, preferred)
        raise FactUnresolved(key, winners, ConflictClass.INCOMPARABLE)

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
    facts = {}
    for key in store.keys():
        facts[key] = [
            {
                "id": c.id,
                "key": c.key,
                "value": _jsonable(c.value),
                "provenance": c.provenance.value,
                "applies_to": _jsonable(c.applies_to),
                "derived_from": _jsonable(c.derived_from),
                "method": c.method,
                "by": c.by,
                "state": c.state.value,
                "generation": c.generation,
                "observations": _jsonable(
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
        "resolutions": _jsonable(sorted(store.resolutions, key=lambda r: r.seq)),
        "conflicts": _jsonable(
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
