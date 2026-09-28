"""The strlen-off-by-N walkthrough family, pinned where it actually matters.

WHY THIS FILE EXISTS, AND WHAT IT CAUGHT
----------------------------------------
`heap_strlen_ofb1` solves `benchmark/corpus_bon` 3/3 and HTB `bon-nie-appetit`
at 3/3 reps `SHELL_ACCESS`. Before this family existed, those four binaries
selected `triage` (corpus) and **`rop_chain` at 0.6** (the real target) -- and
the second is worse than the first: it teaches a stack-ROP hunt on a binary whose
bug is a heap off-by-N, so the reader follows it into a canaried frame.

The first draft of the family gated on `fixed_alloc_sizes(path)` being non-empty,
reasoning that a buffer can only be filled to exactly its own length if that
length is a constant the program chose. **All three corpus positives have a fixed
size, so that gate passed 3/3 and looked correct.** HTB `bon-nie-appetit` has
none -- its order option asks US for the size -- so the gate declined the one
target the family exists for, and the walkthrough kept teaching `rop_chain`.

That is the same failure shape as `env_path`'s 0.89 score: a corpus cannot catch
a gate that is wrong only on the real target. So the load-bearing assertion here
is on the real target, and there is a test devoted to the register-sized case
specifically, so that this gate cannot tighten again without a red test.

Every test states which of three things it pins:
  (a) the family is selected where the pipeline solves,
  (b) the family DECLINES where the pipeline declines,
  (c) the artifact is usable, and models its own uncertainty honestly.
"""

from __future__ import annotations

import ast
import glob
import os

import pytest

from supwngo.exploit.pipeline.executors import heap_strlen_ofb1_techniques as hso
from supwngo.exploit.walkthrough.families import heap_strlen
from supwngo.exploit.walkthrough.model import Confidence
from supwngo.exploit.walkthrough.registry import walkthrough_for_binary
from supwngo.exploit.walkthrough.render import render_script

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(REPO, "benchmark", "corpus_bon")

POSITIVES = [
    "bon_10_reach_size_lsb",
    "bon_11_reach_size_byte1",
    "bon_12_reach_neighbour_data",
]
CONTROL = "bon_90_neg_clamped_len"


def _target(slug: str) -> str:
    path = os.path.join(CORPUS, slug, slug)
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        pytest.skip(f"{slug} not built; run benchmark/build_all.sh")
    return path


def _real() -> str:
    """HTB `bon-nie-appetit`, found by search rather than a pinned UUID path."""
    hits = [
        p
        for p in glob.glob(
            os.path.join(REPO, "tests", "htb-targets", "*", "*", "bon-nie-appetit")
        )
        if os.path.isfile(p)
    ]
    if not hits:
        pytest.skip("HTB bon-nie-appetit not present in tests/htb-targets/")
    return hits[0]


# --------------------------------------------------------------------------
# (a) selected where the pipeline solves
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_is_taught_by_this_family(slug: str) -> None:
    w = walkthrough_for_binary(_target(slug))
    assert w.family == heap_strlen.NAME, (
        f"{slug} is solved by the heap_strlen_ofb1 executor but explain teaches "
        f"{w.family!r}. A walkthrough that names a different route than the one the "
        "tool flies is worse than none."
    )


def test_the_real_target_agrees_with_the_pipeline() -> None:
    """The assertion the corpus could not make, and the one that caught the bug."""
    w = walkthrough_for_binary(_real())
    assert w.family == heap_strlen.NAME, (
        "HTB bon-nie-appetit is solved by heap_strlen_ofb1 (measured: 3/3 reps "
        f"SHELL_ACCESS at 21.5-21.6 s) but explain teaches {w.family!r}."
    )


def test_the_register_sized_case_is_claimed_not_declined() -> None:
    """The specific bug: an absent malloc immediate is NOT a decline.

    Pinned separately from the selection test above because it pins the REASON.
    The real target has no fixed allocation size, and the first gate treated that
    as disqualifying -- so this asserts BOTH halves: that the premise holds (there
    really is no immediate) and that the family claims it anyway. Without the
    first half, a build that started emitting immediates would make this test pass
    while measuring nothing.
    """
    real = _real()
    assert hso.fixed_alloc_sizes(real) == [], (
        "the premise is gone: this target now has a fixed malloc immediate, so it "
        "no longer exercises the register-sized path. Find another target for this "
        "test rather than deleting it"
    )

    a = heap_strlen._Analysis(real)
    assert a.size_is_ours is True
    assert a.complete is True, (
        f"declined the register-sized case: {a.reason!r}. An absent immediate means "
        "the target asks US for the size, which makes filling the buffer exactly "
        "EASIER, not impossible. The executor's own fallback is "
        "`list(static_sizes) or [0x18]`"
    )
    assert a.order_size == heap_strlen._Analysis.CHOSEN_SIZE


def test_this_family_outranks_every_other_applicable_route_on_the_real_target() -> None:
    """Pins the REASON, not just the outcome.

    Without this, the selection test could stay green because `rop_chain` stopped
    applying -- which would hide the ordering question rather than settle it.
    """
    from supwngo.exploit.walkthrough import registry
    from supwngo.exploit.walkthrough.facts import collect_facts

    facts = collect_facts(_real())
    applicable = {
        getattr(fam, "NAME", "?"): route.score
        for fam, route in registry.propose_routes(facts)
        if route.applicable
    }
    assert heap_strlen.NAME in applicable
    others = {k: v for k, v in applicable.items() if k != heap_strlen.NAME}
    assert others, (
        "no competing family applies any more, so this test has stopped measuring "
        "the ordering it was written for -- re-derive it rather than deleting it"
    )
    assert applicable[heap_strlen.NAME] == max(applicable.values()), (
        f"outranked on the real target: {applicable}"
    )


# --------------------------------------------------------------------------
# (b) declines where the pipeline declines
# --------------------------------------------------------------------------


def test_the_control_is_not_claimed() -> None:
    """The negative half. The control keeps the READ and removes only the WRITE."""
    w = walkthrough_for_binary(_target(CONTROL))
    assert w.family != heap_strlen.NAME, (
        "the control clamps the strlen result against the size recorded at "
        "allocation, so the copy length can never exceed the buffer. Claiming it "
        "would teach a route that provably cannot work on that binary."
    )


def test_the_declining_route_says_why_and_stays_checkable() -> None:
    from supwngo.exploit.walkthrough.facts import collect_facts

    route = heap_strlen.propose(collect_facts(_target(CONTROL)))
    assert route is not None and route.applicable is False
    assert route.score == 0.0, "a non-applicable route must not carry a live score"
    assert "clamp" in route.becomes_viable_if.lower(), (
        "the abstention must name the CLAMP, because that is the one thing the "
        "reader would have to change; a generic 'no bug found' is a shrug"
    )


def test_the_gate_stays_narrow() -> None:
    """A 0.89 score is only safe if the gate is narrow, so assert the gate.

    The gate LOOSENED during development (the fixed-size requirement was removed),
    and a looser gate on a high score is how a new family silently steals a target
    from an existing route. Swept over every corpus binary rather than argued.
    """
    claimed = []
    for pattern in ("benchmark/corpus*/*/*", "tests/htb-targets/*/*/*"):
        for path in sorted(glob.glob(os.path.join(REPO, pattern))):
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                continue
            with open(path, "rb") as handle:
                if handle.read(4) != b"\x7fELF":
                    continue
            if heap_strlen._Analysis(path).complete:
                claimed.append(os.path.basename(path))

    assert claimed, "the gate opens on nothing at all, so it is measuring nothing"
    outside = [
        c for c in claimed if not c.startswith("bon_") and c != "bon-nie-appetit"
    ]
    assert not outside, (
        f"the gate claims targets outside its own family: {sorted(outside)}. At "
        "0.89 this family outranks most of the tree, so each of those is a target "
        "stolen from the route that actually solves it."
    )


# --------------------------------------------------------------------------
# (c) the artifact is usable and honest about what it does not know
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_walkthrough_renders_and_is_valid_python(slug: str) -> None:
    """`I-23`: three families once shipped unable to render while the suite was
    396 green, because selection and scoring never exercise the renderer."""
    ast.parse(render_script(walkthrough_for_binary(_target(slug))))


@pytest.mark.parametrize("slug", POSITIVES)
def test_no_step_body_is_a_pasted_shell_transcript(slug: str) -> None:
    """The specific `I-23` shape: a `$ cmd` line as a Python statement."""
    for step in walkthrough_for_binary(_target(slug)).steps:
        for line in step.code.splitlines():
            assert not line.strip().startswith("$ "), (
                f"step {step.id!r} pastes a shell transcript into Python: "
                f"{line.strip()!r}. Use common.shell_transcript(), which RUNS the "
                "command instead of commenting it out."
            )


def test_the_reach_is_unknown_and_names_the_step_that_measures_it() -> None:
    """The honesty requirement, and the one most tempting to violate.

    REACH depends on what the allocator placed after the chunk at the moment of
    the call, so it is a property of the RUN and cannot be read out of the image.
    A family that filled in 1 (the most common value) would be coherent and wrong
    on the first target whose allocator disagreed -- and would look identical to a
    measured one in the artifact.
    """
    w = walkthrough_for_binary(_target(POSITIVES[0]))
    reach = next((c for c in w.constants if c.name == "REACH"), None)
    assert reach is not None, "REACH must be carried, not omitted"
    assert reach.confidence is Confidence.UNKNOWN, (
        f"REACH is {reach.confidence}; it cannot be derived from the image at any "
        "effort, so any other confidence is a claim the family cannot support"
    )
    assert reach.value is None, "an UNKNOWN fact must not also carry a value"
    assert reach.resolved_by == "measure_the_reach"
    assert reach.plausible, "the reader needs to know what values are likely"
    assert any(s.id == "measure_the_reach" for s in w.steps), (
        "REACH names a resolving step that does not exist, which sends the reader "
        "to a step they cannot find"
    )


def test_the_chosen_size_is_assumed_not_measured_on_the_real_target() -> None:
    """A size WE pick is not a measurement, and the artifact must not imply it is.

    Three epistemic states are kept apart on purpose: MEASURED (one immediate in
    the image), UNKNOWN (several, and which one over-reads is a live question),
    ASSUMED (none, so we choose). Collapsing the third into MEASURED would tell
    the reader the binary demanded 0x18 when nothing of the sort is true.
    """
    w = walkthrough_for_binary(_real())
    order_sz = next((c for c in w.constants if c.name == "ORDER_SZ"), None)
    assert order_sz is not None
    assert order_sz.confidence is Confidence.ASSUMED, (
        f"ORDER_SZ is {order_sz.confidence} on a target with no malloc immediate. "
        "It was chosen, not observed."
    )
    assert order_sz.value == heap_strlen._Analysis.CHOSEN_SIZE


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_offset_fact_is_dropped_not_left_unknown(slug: str) -> None:
    """This route has no offset, so carrying OFFSET as UNKNOWN would send the
    reader hunting for a number that does not exist in this binary."""
    names = {c.name for c in walkthrough_for_binary(_target(slug)).constants}
    assert "OFFSET" not in names, (
        "nothing is overflowed toward a saved return address on this route, so "
        f"there is no offset to measure; constants were {sorted(names)}"
    )


def test_the_finisher_branches_on_the_release_not_on_symbol_presence() -> None:
    """The silent-failure guard.

    `__free_hook` is still an EXPORTED symbol on glibc >= 2.34, where it is never
    called. A family that branched on symbol presence would pick a dead hook on
    exactly the releases where the write lands and nothing happens -- the failure
    mode with no error message at all. The corpus is pinned to the host's 2.35 and
    the real target ships 2.27, so both arms are covered by real binaries.
    """
    corpus = heap_strlen._Analysis(_target(POSITIVES[0]))
    real = heap_strlen._Analysis(_real())

    assert corpus.release is not None and real.release is not None
    assert real.release <= (2, 33) < corpus.release, (
        f"the two arms have stopped differing (corpus {corpus.release}, real "
        f"{real.release}), so this test no longer covers both finishers"
    )
    assert "free@got.plt" in corpus.finisher
    assert corpus.finisher != real.finisher
    assert "__free_hook" in real.finisher
