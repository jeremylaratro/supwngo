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


def _make_random_ids() -> Callable[[R.Candidate], str]:
    """Round-1 finding 4: non-content-derived ids make merge order-dependent."""
    counter = {"n": 0}

    def derive_id(c: R.Candidate) -> str:
        counter["n"] += 1
        return "f_" + format(counter["n"], "012x")

    return derive_id


def _canonical_document_unsorted(store: R.FactStore) -> str:
    """Round-1 finding 4: canonical JSON does not sort arrays, so insertion
    order leaks into the document digest."""
    import json

    facts = {
        key: [{"id": c.id, "value": R._jsonable(c.value),
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


MUTANTS: Dict[str, Mutant] = {
    m.name: m for m in [
        Mutant("merge_supersedes_on_rank", "v3 defect 1", "P1",
               {"merge": _merge_supersedes_on_rank}),
        Mutant("dedup_ignores_provenance", "v3 defect 2", "P14",
               {"dedup_key": _dedup_key_ignores_provenance}),
        Mutant("dedup_matches_terminal", "round-1 finding 3", "P1",
               {"merge": _merge_matches_terminal}),
        Mutant("random_ids", "round-1 finding 4", "P2",
               {"derive_id": _make_random_ids()}),
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
    ]
}
