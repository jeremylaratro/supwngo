"""The env-PATH-hijack walkthrough family, pinned where it actually matters.

WHY THIS FILE EXISTS, AND WHAT IT CAUGHT
----------------------------------------
`env_path_hijack` solves `benchmark/corpus_envpath/` 4/4 and HTB `sabotage`. Before
this family existed, `supwngo explain` on those same five binaries selected
**`triage`** -- "go and discover the facts yourself" -- on a category where the
pipeline already derives every fact it needs.

The first draft of the family scored 0.89 and passed every test that existed,
including the corpus sweep, because on the corpus no other family proposes an
applicable route. It was still wrong: HTB `sabotage` imports `srand`/`time`/`rand`,
so `weak_prng` proposes at 0.94 and **took the real target**. A PRNG replay on
`sabotage` stops short of a shell, so the artifact was a followable-but-incomplete
walkthrough -- the same failure class as `fnptr_11_stack_struct` winning
`stack_bof`'s ret2win route.

So the load-bearing assertion here is not "the family works on its corpus". It is
**the walkthrough and the pipeline agree about the same binary**, asserted on the
real target, because that is the check the corpus could not make.

Every test states which of the three things it pins:
  (a) the family is selected where the pipeline solves,
  (b) the family DECLINES where the pipeline declines,
  (c) the artifact is usable (renders, parses, no pasted shell transcript).
"""

from __future__ import annotations

import ast
import glob
import os

import pytest

from supwngo.exploit.walkthrough.families import env_path
from supwngo.exploit.walkthrough.registry import walkthrough_for_binary
from supwngo.exploit.walkthrough.render import render_script

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(REPO, "benchmark", "corpus_envpath")

POSITIVES = [
    "envpath_10_putenv_heap_anchor",
    "envpath_11_heap_cmd_string",
    "envpath_12_late_putenv_buffer",
    "envpath_13_setenv_value_buffer",
]
CONTROL = "envpath_90_neg_bounded"


def _target(slug: str) -> str:
    path = os.path.join(CORPUS, slug, slug)
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        pytest.skip(f"{slug} not built; run benchmark/build_all.sh")
    return path


def _sabotage() -> str:
    """The REAL target, found by search rather than a pinned UUID path."""
    hits = [
        p
        for p in glob.glob(os.path.join(REPO, "tests", "htb-targets", "*", "*", "sabotage"))
        if os.path.isfile(p)
    ]
    if not hits:
        pytest.skip("HTB sabotage not present in tests/htb-targets/")
    return hits[0]


# --------------------------------------------------------------------------
# (a) selected where the pipeline solves
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_is_taught_by_this_family(slug: str) -> None:
    w = walkthrough_for_binary(_target(slug))
    assert w.family == env_path.NAME, (
        f"{slug} is solved by the env_path_hijack executor but explain teaches "
        f"{w.family!r}. A walkthrough that names a different route than the one the "
        "tool flies is worse than none: the reader follows it and it does not work."
    )
    assert w.taught_route == env_path.PLANT_AND_REPATH


def test_the_real_target_agrees_with_the_pipeline() -> None:
    """The assertion the corpus could not make, and the one that caught the bug.

    `sabotage` is where a 0.89 score silently lost the target to `weak_prng`. Pinning
    it here means the next family to arrive cannot repeat that without a red test.
    """
    w = walkthrough_for_binary(_sabotage())
    assert w.family == env_path.NAME, (
        "HTB sabotage is solved by env_path_hijack (measured: 3/3 reps SHELL_ACCESS, "
        f"and again in the 6/6 echo audit) but explain teaches {w.family!r}. This is "
        "exactly the regression a corpus-only sweep cannot see."
    )


def test_this_family_outranks_every_other_applicable_route_on_the_real_target() -> None:
    """Pins the REASON, not just the outcome.

    Without this, the test above could stay green because a competing family
    stopped applying -- which would hide the ordering problem rather than fix it.
    So assert that competitors DO still apply and are still outranked.
    """
    from supwngo.exploit.walkthrough import registry
    from supwngo.exploit.walkthrough.facts import collect_facts

    facts = collect_facts(_sabotage())
    proposals = registry.propose_routes(facts)
    applicable = {
        getattr(fam, "NAME", "?"): route.score
        for fam, route in proposals
        if route.applicable
    }

    assert env_path.NAME in applicable, "this family must propose on the real target"
    others = {k: v for k, v in applicable.items() if k != env_path.NAME}
    assert others, (
        "no competing family applies any more, so this test has stopped measuring "
        "the ordering it was written for -- re-derive it rather than deleting it"
    )
    assert applicable[env_path.NAME] == max(applicable.values()), (
        f"outranked on the real target: {applicable}. A tie or a loss here hands "
        "sabotage to a route that does not reach a shell."
    )


# --------------------------------------------------------------------------
# (b) declines where the pipeline declines
# --------------------------------------------------------------------------


def test_the_control_is_not_claimed() -> None:
    """The negative half. Without it, "always applicable" would pass (a) fully."""
    w = walkthrough_for_binary(_target(CONTROL))
    assert w.family != env_path.NAME, (
        "the control's system() argument is ABSOLUTE ('/bin/panel'), so $PATH cannot "
        "redirect it and this route must abstain. Claiming it would teach a route "
        "that provably cannot work on that binary."
    )


def test_the_declining_route_says_why_and_stays_checkable() -> None:
    """A refusal has to name the missing fact, not shrug.

    Asserted on content because an abstention with an empty rationale is the same
    dead end as no route at all, from the reader's side.
    """
    from supwngo.exploit.walkthrough.facts import collect_facts

    route = env_path.propose(collect_facts(_target(CONTROL)))
    assert route is not None and route.applicable is False
    assert route.score == 0.0, "a non-applicable route must not carry a live score"
    assert route.rationale.strip(), "an abstention with no reason is a shrug"
    assert route.becomes_viable_if, (
        "the reader needs to know what would change the answer, or the abstention "
        "is a dead end"
    )


# --------------------------------------------------------------------------
# (c) the artifact is usable (the I-23 discipline)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_walkthrough_renders_and_is_valid_python(slug: str) -> None:
    """`I-23`: three families once shipped unable to render while the suite was
    396 green, because selection and scoring never exercise the renderer."""
    w = walkthrough_for_binary(_target(slug))
    source = render_script(w)
    ast.parse(source)  # raises on the pasted-shell-transcript defect


@pytest.mark.parametrize("slug", POSITIVES)
def test_no_step_body_is_a_pasted_shell_transcript(slug: str) -> None:
    """The specific `I-23` shape: a `$ cmd` line as a Python statement."""
    w = walkthrough_for_binary(_target(slug))
    for step in w.steps:
        for line in step.code.splitlines():
            assert not line.strip().startswith("$ "), (
                f"step {step.id!r} pastes a shell transcript into Python: "
                f"{line.strip()!r}. Use common.shell_transcript(), which RUNS the "
                "command instead of commenting it out."
            )


def test_the_offset_fact_is_dropped_not_left_unknown() -> None:
    """This route has no offset, so carrying OFFSET as UNKNOWN would send the
    reader hunting for a number that does not exist in this binary."""
    w = walkthrough_for_binary(_target(POSITIVES[0]))
    names = {c.name for c in w.constants}
    assert "OFFSET" not in names, (
        "nothing is overflowed toward a saved return address on this route, so "
        f"there is no offset to measure; constants were {sorted(names)}"
    )
