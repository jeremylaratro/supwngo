"""Every walkthrough the engine can select must render to Python that parses.

WHY THIS FILE EXISTS, precisely
-------------------------------
Three families (``subprocess_injection``, ``weak_prng``, ``scanf_scalar``) shipped
with shell transcripts pasted into ``Step.code``::

    $ objdump -R prng_10_time_seed_token | grep -E "rand|random"

``Step.code`` is emitted verbatim as a Python function body, so that is a
``SyntaxError`` and ``render_script`` refuses the whole walkthrough. Which means
``supwngo explain`` **raised** on every target those families claimed -- and the
walkthrough suite was 396 green at the time, because a family can be selected,
scored, and route-swept without anything ever *rendering* its script.

That is the exact shape this repo keeps relearning: a gate that cannot fail. The
selection tests asserted the right family won; none of them asserted the artifact
was usable. So this file closes the gap at the only place it can be closed --
between "a family was chosen" and "a reader can run what came out".

Two obligations, both here:

1. **Positive:** every corpus target on disk renders and parses.
2. **RED-proof:** a deliberately malformed step is shown to make the gate fail.
   Without (2), a change that made ``render_script`` stop compiling its output
   would turn this whole file green-and-worthless, which is the same defect one
   level up.
"""

from __future__ import annotations

import ast
import glob
import os

import pytest

from supwngo.exploit.walkthrough import registry
from supwngo.exploit.walkthrough.facts import collect_facts
from supwngo.exploit.walkthrough.model import (
    Confidence,
    Evidence,
    Fact,
    Route,
    Step,
    Walkthrough,
    WalkthroughError,
    dedent_code,
)
from supwngo.exploit.walkthrough.render import render_script

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _corpus_targets() -> list[str]:
    """Every built corpus binary: the file named exactly like its directory.

    Binaries are gitignored and rebuilt, so this discovers rather than pins. The
    count is asserted below instead of being hardcoded here -- a pinned list would
    silently stop covering a corpus added later, and a bare `glob` with no floor
    would pass vacuously on a tree where nothing is built.
    """
    found = []
    for directory in sorted(glob.glob(os.path.join(REPO, "benchmark", "corpus*", "*/"))):
        slug = os.path.basename(directory.rstrip("/"))
        candidate = os.path.join(directory, slug)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            found.append(candidate)
    return found


TARGETS = _corpus_targets()


@pytest.mark.skipif(not TARGETS, reason="no corpus binaries built; run benchmark/build_all.sh")
@pytest.mark.parametrize("target", TARGETS, ids=lambda p: os.path.basename(p))
def test_selected_walkthrough_renders_and_parses(target: str) -> None:
    """The artifact a reader receives must be valid Python.

    Asserting on ``ast.parse`` of the rendered text rather than trusting
    ``render_script``'s own internal ``compile`` -- if that check were ever
    removed, this test still fails, where a test that only called the renderer
    would go green.
    """
    walkthrough = registry.generate_walkthrough(collect_facts(target, probe=False))
    source = render_script(walkthrough)

    assert source.strip(), f"{target}: rendered an empty script"
    ast.parse(source)  # raises SyntaxError on the defect this file was written for

    # A script that parses but contains an unexecuted shell transcript would slip
    # through `ast.parse` if it sat inside a docstring. Check the step bodies the
    # reader is told to run, specifically.
    for step in walkthrough.steps:
        for line in step.code.splitlines():
            stripped = line.strip()
            assert not stripped.startswith("$ "), (
                f"{target}: step {step.id!r} has a raw shell line in its body: "
                f"{stripped!r}. Use common.shell_transcript() -- it runs the "
                "command instead of pasting it."
            )


@pytest.mark.skipif(not TARGETS, reason="no corpus binaries built")
def test_the_sweep_actually_covered_something() -> None:
    """Guard against the whole file passing on an empty target list.

    A parametrized sweep over an empty sequence reports success. The floor is set
    to 20 because the three families this file was written for own 20 targets
    between them; the real corpus is larger, so this is a floor and not a pin.
    """
    assert len(TARGETS) >= 20, (
        f"only {len(TARGETS)} corpus binaries found -- the sweep would pass "
        "without covering the families it exists to cover. Build the corpora."
    )


def _walkthrough_with(step_code: str) -> Walkthrough:
    """A minimal valid walkthrough whose single step carries ``step_code``."""
    return Walkthrough(
        binary_path="/bin/true",
        family="probe",
        title="probe",
        strategy="probe",
        protections=(),
        constants=(
            Fact(
                name="PROBE",
                value=1,
                kind="int",
                confidence=Confidence.MEASURED,
                description="probe",
                evidence=Evidence(method="authored for this test", detail="probe"),
            ),
        ),
        steps=(
            Step(
                id="probe_step",
                title="probe",
                why="probe",
                code=step_code,
                expect="probe",
                verify="probe",
            ),
        ),
        helpers="",
        final_exploit="return True",
        # A walkthrough must record the routes it considered -- the model rejects
        # an empty tuple, because the decision tree is what a reader falls back on
        # when the primary route fails. One route is enough for this fixture.
        routes=(
            Route(
                name="probe route",
                score=0.5,
                applicable=True,
                rationale="authored for this test",
            ),
        ),
        taught_route="probe route",
        success_criteria="probe",
        provenance=(),
        automation_failure=None,
    )


def test_render_rejects_a_shell_transcript_in_a_step_body() -> None:
    """The RED-proof: the gate must fail on the real defect, not merely pass.

    The mutation is WRONG-BUT-PRESENT rather than absent -- a plausible-looking
    authored block, exactly what shipped -- because a check that only rejects
    obvious garbage does not prove it would have caught this.
    """
    bad = _walkthrough_with(
        dedent_code(
            '''
            # Relocations, not a disassembly grep: an import is a fact.
            $ objdump -R target | grep -E "rand|random"
            '''
        )
    )
    with pytest.raises(WalkthroughError, match="not valid Python"):
        render_script(bad)


def test_render_accepts_the_same_block_through_the_helper() -> None:
    """The positive half of the control: the helper's output must survive.

    Paired with the test above on purpose. A rejection test alone cannot tell
    "the gate catches shell transcripts" from "the gate rejects everything", and
    the second would make the helper useless while both tests stayed green.
    """
    from supwngo.exploit.walkthrough import common

    good = _walkthrough_with(
        common.shell_transcript(
            '''
            # Relocations, not a disassembly grep: an import is a fact.
            $ objdump -R target | grep -E "rand|random"
            '''
        )
    )
    source = render_script(good)
    ast.parse(source)
    assert "subprocess.run" in source, (
        "the helper is supposed to RUN the command, not comment it out -- a "
        "commented command turns a runnable step into prose"
    )
