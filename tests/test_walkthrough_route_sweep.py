"""The whole-corpus route sweep: which family wins on each of the 15 targets.

``test_walkthrough_families.py`` pins the route for the five targets whose
walkthroughs were followed by hand, and each second-wave family pins its own
two.  Neither catches the failure mode that adding a family actually has: a NEW
family quietly outscoring an EXISTING one on a target that belongs to neither
of them.  That is invisible in a diff, invisible in the new family's tests (they
only look at the targets it means to win) and invisible in the old family's
tests (they still pass -- the old family still *proposes*, it just stops
winning).  The only way to see it is to check all 15 at once, which is what this
does.

Two properties are asserted, and they are different:

* the winning **family** per target, which is the routing decision, and
* that a target's winner is a *strict* maximum -- no runner-up shares its score.

The second is the local form of the global invariant in
``test_walkthrough_scores.py``.  The global test proves no two routes anywhere
share a score; this one proves it for the routes that actually co-occur on a
real binary, which is where a tie would do its damage.

``probe=True`` deliberately, because that is the default for ``supwngo explain``
and the only mode in which the measuring families (``fmtstr``, ``integer``) can
speak.  Under ``--no-probe`` the same corpus routes very differently and that is
correct by design: nothing has been measured, so ``stack_bof``'s ret2win stays
on the table for any target carrying a ``win``-ish symbol.  A test written
against the cheaper mode would therefore assert the wrong thing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

CORPUS = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"

#: ``directory -> (binary name, winning family)`` for all 15 round-1 targets,
#: as measured after consolidating the ``fmtstr`` and ``integer`` families onto
#: the walkthrough engine.
#:
#: The three ``triage`` entries are not filler -- they are the abstention design
#: working.  04 (canary leak) and 08 (ret2dlresolve) have no family yet; 13 is an
#: off-by-one whose single overwritten byte no shipped family claims.  Each is a
#: target a family could plausibly capture by accident, which is exactly why
#: they are pinned.
#:
#: 11 and 12 moved from ``triage`` to ``heap`` when the heap family landed, and
#: they are the only two entries that moved.  That is the whole point of pinning
#: all fifteen: a detection-only family scoring 0.25 sits just above the triage
#: floor, so the risk it carries is not that it loses -- it is that it quietly
#: outbids a *real* technique on some target that merely calls ``malloc``.  The
#: thirteen unmoved rows are the evidence it did not.
EXPECTED: dict[str, tuple[str, str]] = {
    "01_shellcode_stack": ("shellcode_stack", "stack_bof"),
    "02_ret2plt_system": ("ret2plt_system", "rop_chain"),
    "03_pie_leak_ret2libc": ("pie_leak_ret2libc", "rop_chain"),
    "04_canary_leak_bypass": ("canary_leak_bypass", "triage"),
    "05_fmtstr_arbread": ("fmtstr_arbread", "fmtstr"),
    "06_fmtstr_arbwrite": ("fmtstr_arbwrite", "fmtstr"),
    "07_ret2libc_leak": ("ret2libc_leak", "rop_chain"),
    "08_ret2dlresolve": ("ret2dlresolve", "triage"),
    "09_srop": ("srop", "syscall"),
    "10_int_overflow": ("int_overflow", "integer"),
    "11_heap_uaf_leak": ("heap_uaf_leak", "heap"),
    "12_heap_tcache_poison": ("heap_tcache_poison", "heap"),
    "13_off_by_one": ("off_by_one", "triage"),
    "14_negative_index": ("negative_index", "integer"),
    "15_win_function": ("win_function", "stack_bof"),
}

#: A substring of the route name each target must select, where the family alone
#: is not specific enough.  ``rop_chain`` owns two routes and ``stack_bof`` two,
#: so a change that swapped ret2shellcode for ret2win would otherwise pass.
EXPECTED_ROUTE_SUBSTRING: dict[str, str] = {
    "01_shellcode_stack": "ret2shellcode",
    "02_ret2plt_system": "ret2plt",
    "03_pie_leak_ret2libc": "ret2libc",
    "05_fmtstr_arbread": "arbitrary read",
    "06_fmtstr_arbwrite": "arbitrary write",
    "07_ret2libc_leak": "ret2libc",
    "09_srop": "SROP",
    "10_int_overflow": "truncation",
    "14_negative_index": "negative index",
    "15_win_function": "ret2win",
}


def _winner(directory: str, name: str):
    """``(family name, route, all proposed routes)`` for one corpus target."""
    from supwngo.exploit.walkthrough.facts import collect_facts
    from supwngo.exploit.walkthrough.registry import propose_routes

    path = CORPUS / directory / name
    if not path.exists():
        pytest.skip(f"benchmark corpus not built: {path} (run benchmark/build_all.sh)")

    facts = collect_facts(str(path), probe=True)
    proposals = propose_routes(facts)
    viable = [(family, route) for family, route in proposals if route.applicable]
    assert viable, (
        f"{directory} has no applicable route at all. triage is meant to be "
        "unconditionally applicable, so this means it stopped proposing."
    )
    family, route = max(viable, key=lambda pair: pair[1].score)
    return family.NAME, route, [r for _f, r in viable]


@pytest.mark.parametrize("directory", sorted(EXPECTED), ids=sorted(EXPECTED))
def test_winning_family_per_target(directory):
    name, expected_family = EXPECTED[directory]
    family_name, route, _viable = _winner(directory, name)
    assert family_name == expected_family, (
        f"{directory} now routes to {family_name!r} ({route.name!r} @ "
        f"{route.score}) instead of {expected_family!r}. A family has captured a "
        "target that was not its own -- check the score table in "
        "tests/test_walkthrough_scores.py before changing this expectation."
    )
    substring = EXPECTED_ROUTE_SUBSTRING.get(directory)
    if substring is not None:
        assert substring.lower() in route.name.lower(), (
            f"{directory} stayed in {family_name!r} but switched route to "
            f"{route.name!r}; expected one containing {substring!r}."
        )


@pytest.mark.parametrize("directory", sorted(EXPECTED), ids=sorted(EXPECTED))
def test_winner_is_a_strict_maximum(directory):
    """No runner-up ties the winner, so list order never decides the outcome."""
    name, _expected_family = EXPECTED[directory]
    _family_name, route, viable = _winner(directory, name)
    tied = [r for r in viable if r is not route and r.score == route.score]
    assert not tied, (
        f"{directory}: {route.name!r} won at {route.score} but "
        f"{[r.name for r in tied]} scored identically. The winner is then "
        "whichever family happens to sit earlier in registry._families(), which "
        "is not a decision anyone made."
    )


# ---------------------------------------------------------------------------
# within-family selection
#
# The two tests above are the CROSS-family invariant: they compare routes from
# different families and never look inside one. That blind spot shipped a defect
# -- `heap` ranked two of its own routes, both scored 0.0, `max()` kept the first
# and the other became unreachable -- and the same shape was latent in `fmtstr`
# (keyed on `(applicable, score)`) and in `integer` (fell through to
# `candidates[0]`). Four families declare two or more routes at 0.0, so the
# exemption that makes the cross-family check tractable is exactly where
# within-family ties live.
#
# `tests/test_walkthrough_scores.py` covers the structural half with no binaries.
# This is the behavioural half: run every family against every target with the
# shared selector's input reversed, and demand the same answer.
# ---------------------------------------------------------------------------


def _all_families() -> list:
    from supwngo.exploit.walkthrough.families import (
        fmtstr,
        heap,
        integer,
        rop_chain,
        stack_bof,
        syscall,
        triage,
    )

    return [rop_chain, syscall, integer, stack_bof, fmtstr, heap, triage]


def _facts_for(directory: str, name: str):
    from supwngo.exploit.walkthrough.facts import collect_facts

    path = CORPUS / directory / name
    if not path.exists():
        pytest.skip(f"benchmark corpus not built: {path} (run benchmark/build_all.sh)")
    return collect_facts(str(path), probe=True)


@pytest.mark.parametrize("directory", sorted(EXPECTED), ids=sorted(EXPECTED))
def test_no_family_changes_its_answer_when_candidates_are_reversed(directory, monkeypatch):
    """Reverse every family's candidate list; every family must still agree.

    Patching `common.select_route` reaches every family that selects, which is
    the point of having one selector: a per-family patch would have to know which
    families rank and would miss the next one added.
    """
    from supwngo.exploit.walkthrough import common

    name, _expected = EXPECTED[directory]
    facts = _facts_for(directory, name)

    before = {}
    for module in _all_families():
        route = module.propose(facts)
        before[module.NAME] = route.name if route is not None else None

    real = common.select_route
    monkeypatch.setattr(
        common, "select_route", lambda candidates: real(list(candidates)[::-1])
    )

    for module in _all_families():
        route = module.propose(facts)
        now = route.name if route is not None else None
        assert now == before[module.NAME], (
            f"{directory}: {module.NAME} returned {before[module.NAME]!r} normally "
            f"and {now!r} with its candidates reversed, so the route it proposes "
            "depends on the order the candidates happen to be listed in."
        )


@pytest.mark.parametrize("directory", sorted(EXPECTED), ids=sorted(EXPECTED))
def test_a_family_that_does_not_select_builds_at_most_one_route(directory):
    """The other way to be order-independent: never have a choice to make.

    `syscall`, `stack_bof`, `rop_chain` and `triage` return from a branch, and
    `heap` partitions on ``any_present`` -- so at most one Route is constructed
    per call and nothing is discarded. That is stronger than selecting well, and
    it is worth pinning: a family that starts building a second candidate without
    routing it through `common.select_route` would otherwise pick by position
    again, silently.
    """
    from supwngo.exploit.walkthrough import common

    name, _expected = EXPECTED[directory]
    facts = _facts_for(directory, name)

    selectors = set()
    real = common.select_route

    for module in _all_families():
        made = []
        real_route = module.Route

        def recording(*args, _made=made, _real=real_route, **kwargs):
            route = _real(*args, **kwargs)
            _made.append(route)
            return route

        used_selector = []

        def watched(candidates, _used=used_selector):
            _used.append(True)
            return real(candidates)

        module.Route = recording
        common.select_route = watched
        try:
            module.propose(facts)
        finally:
            module.Route = real_route
            common.select_route = real

        if used_selector:
            selectors.add(module.NAME)
            continue
        assert len(made) <= 1, (
            f"{directory}: {module.NAME} built {len(made)} routes "
            f"({[r.score for r in made]}) without calling common.select_route, so "
            "whichever one it returns was chosen by position."
        )

    # Not an assertion about which families select -- just a guard that the
    # branch above is reachable, so this test cannot pass by never selecting.
    assert selectors <= {"fmtstr", "integer"}, (
        f"a new family started selecting routes: {sorted(selectors)}. Check its "
        "selection goes through common.select_route."
    )
