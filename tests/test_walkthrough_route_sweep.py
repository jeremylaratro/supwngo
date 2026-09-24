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
#: The five ``triage`` entries are not filler -- they are the abstention design
#: working.  04 (canary leak) and 08 (ret2dlresolve) have no family yet; 11 and
#: 12 are heap targets and the heap family is the next one to land; 13 is an
#: off-by-one whose single overwritten byte no shipped family claims.  Each is a
#: target a family could plausibly capture by accident, which is exactly why
#: they are pinned.
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
    "11_heap_uaf_leak": ("heap_uaf_leak", "triage"),
    "12_heap_tcache_poison": ("heap_tcache_poison", "triage"),
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
