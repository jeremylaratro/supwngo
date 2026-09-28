"""The off-by-one walkthrough family, pinned where it matters.

WHY THIS FILE EXISTS
--------------------
`off_by_one_guard` solves 5/5 on `benchmark/corpus_offbyone` -- plus the
out-of-family `benchmark/corpus/13_off_by_one/off_by_one` -- and the walkthrough
layer could explain none of them. MEASURED before this family existed: with
probing, every one of those six fell to `triage` at 0.15; with `--no-probe`, every
one fell to `stack_bof`'s `ret2win` at 0.75.

`ret2win` at 0.75 is the one that does harm, and more here than anywhere else in
this round. It tells the reader to find the buffer-to-return-address offset with a
cyclic pattern. On three of these six the overflow is ONE BYTE, it never reaches
the return address, and a cyclic pattern finds nothing because the program does
not crash -- it returns normally to the wrong place. On a fourth there is no win
function at all and the payoff is the program's own privileged branch.

THE DEFECT IS A COMPARISON OPERATOR
-----------------------------------
Nothing here is missing a bounds check; every target checks and the check is
inclusive where it should be exclusive (`jbe`/`jle` rather than `jb`/`jl`).
MEASURED: that single difference is what separates the five positives from the
negative control, whose every such comparison is exclusive.

The whole route then follows from `X - N` -- where the one admitted byte lands --
and MEASURED across these six that address is four different things, giving four
different routes.

WHAT THIS FAMILY GATES THAT THE EXECUTOR DOES NOT
-------------------------------------------------
``route_is_explained``
    a plan naming a shape this family has no specific step for is DECLINED rather
    than described in general terms. A step that renders and says nothing
    specific is worse than an honest decline.
``parts_are_deliverable``
    no input part may be zero bytes. `_sled(win, ret, length, swap)` returns
    ``(unit * (length // 16 + 1))[:length]``, which is ``b""`` for length 0 -- so a
    mis-derived sled length yields a part the script sends and that delivers
    nothing, shifting every later read. This family's version of the
    empty-candidate defect.
``addresses_the_route_needs``
    `guard_word` carries `win_addr=None`, `ret_addr=None` and `key=None`. Any step
    that formatted a win address unconditionally would RAISE on that shape rather
    than render, and a route that does need an address and lacks one must decline
    instead of emitting `None`.

AND ONE FACT THAT MUST NOT BE OMITTED
-------------------------------------
The saved-frame-pointer route is probabilistic BY CONSTRUCTION. `arch_align_stack`
subtracts `get_random_int() % 8192` and masks to 16, so the byte being rewritten
is a fresh multiple of 16 on every exec; the route writes `0x00`, and for the one
value in sixteen that is already `0x00` the write is a no-op and the attempt is a
certain miss. 15/16 per attempt, and the executor's own `failure_reason` states
the same figure. A walkthrough presenting this as deterministic would teach a
reader to debug a correct exploit.
"""

from __future__ import annotations

import ast
import glob
import os
import re
import subprocess

import pytest

from supwngo.exploit.pipeline.executors import offbyone_techniques as ob
from supwngo.exploit.walkthrough.families import off_by_one
from supwngo.exploit.walkthrough.facts import collect_facts
from supwngo.exploit.walkthrough.model import Confidence
from supwngo.exploit.walkthrough.registry import generate_walkthrough, propose_routes
from supwngo.exploit.walkthrough.render import render_script

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: slug -> the route its plan resolves to. MEASURED; asserted as a MAP rather than
#: per-target so a permutation of the shapes cannot pass.
SHAPES = {
    "obo_10_loop_le_saved_rbp": "saved_rbp_pivot",
    "obo_11_strcpy_nul_at_len": "saved_rbp_pivot",
    "obo_12_length_guard_two_stage": "length_guard",
    "obo_13_saved_ptr_low_byte": "saved_pointer",
    "obo_14_snprintf_ret_caller_frame": "saved_rbp_pivot",
}

POSITIVES = sorted(SHAPES)
CONTROL = "obo_90_neg_bound_fixed"

PIVOT = "obo_10_loop_le_saved_rbp"
LENGTH_GUARD = "obo_12_length_guard_two_stage"
SAVED_POINTER = "obo_13_saved_ptr_low_byte"

#: The fourth shape lives OUTSIDE this corpus, in the shared round-1 tree. It is
#: the only `guard_word` target built, and the only one with no win address, no
#: `ret` gadget and no menu key -- so it is the one that exercises every
#: conditional in the family.
GUARD_WORD_PATH = os.path.join(
    REPO, "benchmark", "corpus", "13_off_by_one", "off_by_one"
)


def _target(slug: str) -> str:
    path = os.path.join(REPO, "benchmark", "corpus_offbyone", slug, slug)
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        pytest.skip(f"{slug} not built; run benchmark/build_all.sh")
    return path


def _guard_word() -> str:
    if not (os.path.isfile(GUARD_WORD_PATH) and os.access(GUARD_WORD_PATH, os.X_OK)):
        pytest.skip("benchmark/corpus/13_off_by_one not built")
    return GUARD_WORD_PATH


def _walkthrough_at(path: str):
    """Selection without the live probe, deliberately.

    `probe=False` keeps `stack_bof`'s `ret2win` APPLICABLE at 0.75, which is the
    competitor this family's score exists to beat. Probing makes the competitor
    disappear and would make every ordering assertion below vacuous.
    """
    return generate_walkthrough(collect_facts(path, probe=False))


def _walkthrough(slug: str):
    return _walkthrough_at(_target(slug))


def _constant(w, name):
    return next((c for c in w.constants if c.name == name), None)


def _all_code(w) -> str:
    return (
        "\n".join(step.code for step in w.steps)
        + "\n"
        + (w.helpers or "")
        + "\n"
        + (w.final_exploit or "")
    )


def _all_prose(w) -> str:
    parts = [w.strategy or "", w.title or "", w.success_criteria or ""]
    for step in w.steps:
        parts += [step.title or "", step.why or "", step.expect or "", step.verify or ""]
        parts += [step.notes or ""]
        for fb in step.on_failure:
            parts += [fb.symptom or "", fb.likely_cause or "", fb.remedy or ""]
    return "\n".join(parts)


# --------------------------------------------------------------------------
# (a) claimed, completed, and the steps carry the real route facts
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_is_claimed_by_this_family(slug: str) -> None:
    w = _walkthrough(slug)
    assert w.family == off_by_one.NAME, (
        f"{slug} is solved by the off_by_one_guard executor but explain teaches "
        f"{w.family!r}. Measured baseline before this family existed: triage (0.15) "
        "with probing, stack_bof ret2win (0.75) without -- and on a one-byte "
        "overflow a cyclic pattern finds nothing, because nothing crashes."
    )


def test_the_out_of_family_target_is_claimed_too() -> None:
    """`benchmark/corpus/13_off_by_one` is the only `guard_word` target built.

    It is also the one this family's conditionals exist for: no win address, no
    `ret` gadget, no menu key. Skipping it would leave the whole `None`-handling
    arm untested.
    """
    w = _walkthrough_at(_guard_word())
    assert w.family == off_by_one.NAME, (
        f"the round-1 off-by-one target is taught {w.family!r}"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_completes_and_renders(slug: str) -> None:
    a = off_by_one._Analysis(_target(slug))
    assert a.complete is True, f"{slug}: {a.decline_reason}"
    ast.parse(render_script(_walkthrough(slug)))


def test_the_guard_word_target_completes_and_renders() -> None:
    a = off_by_one._Analysis(_guard_word())
    assert a.complete is True, a.decline_reason
    ast.parse(render_script(_walkthrough_at(_guard_word())))


def test_all_four_shapes_are_exercised_and_each_gets_its_own_step() -> None:
    """The premise for every per-shape test below, asserted once, as a map.

    Four shapes, four distinct step ids. A per-target assertion would pass while
    the shapes were permuted; a step-count assertion would pass while three shapes
    shared one generic step.
    """
    recovered = {slug: off_by_one._Analysis(_target(slug)).route for slug in POSITIVES}
    assert recovered == SHAPES, (
        f"the recovered shapes changed: {recovered}, expected {SHAPES}"
    )

    guard = off_by_one._Analysis(_guard_word())
    assert guard.route == "guard_word", (
        f"the round-1 target's route is now {guard.route!r}, so the fourth shape "
        "is no longer covered anywhere"
    )

    all_routes = set(recovered.values()) | {"guard_word"}
    assert all_routes == set(off_by_one._SHAPES), (
        f"the corpus exercises {sorted(all_routes)} but this family claims to "
        f"explain {sorted(off_by_one._SHAPES)}. An explained-but-unexercised shape "
        "is untested; an exercised-but-unexplained one is declined."
    )

    step_ids: dict[str, str] = {}
    for path, route in [(_target(s), r) for s, r in SHAPES.items()] + [
        (_guard_word(), "guard_word")
    ]:
        ids = {s.id for s in _walkthrough_at(path).steps}
        expected = off_by_one._shape_step_id(route)
        assert expected in ids, (
            f"route {route!r} did not emit its own step {expected!r}; got "
            f"{sorted(ids)}"
        )
        step_ids[route] = expected
    assert len(set(step_ids.values())) == 4, (
        f"the four shapes do not have four distinct steps: {step_ids}"
    )


def test_it_outranks_the_ret2win_route_it_replaces() -> None:
    """The ordering that justifies 0.83, with the premise asserted."""
    facts = collect_facts(_target(PIVOT), probe=False)
    scores = {
        fam.NAME: route.score
        for fam, route in propose_routes(facts)
        if route is not None and route.applicable
    }
    assert "stack_bof" in scores, (
        "stack_bof no longer applies here, so this test has stopped measuring the "
        "ordering it exists for"
    )
    assert scores[off_by_one.NAME] > scores["stack_bof"], (
        f"off_by_one_guard at {scores[off_by_one.NAME]} does not outrank stack_bof "
        f"at {scores['stack_bof']}"
    )


def test_the_score_sits_below_its_two_deterministic_siblings() -> None:
    """The stated ground for 0.83, pinned against the named constants.

    This family's HEADLINE route is probabilistic by construction; both siblings
    are deterministic once their one unknown is measured. When two routes apply,
    the one that does not need luck is taught first.
    """
    from supwngo.exploit.walkthrough.families import (
        alloc_size,
        fini_array,
        objptr_hijack,
    )

    assert (
        off_by_one.SCORE_TURN_THE_EXTRA_BYTE
        < alloc_size.SCORE_WRAP_THE_SIZE
        < fini_array.SCORE_PATCH_A_FINALISER
        < objptr_hijack.SCORE_OVERWRITE_THE_POINTER
    ), (
        "the stated ordering no longer holds: "
        f"off_by_one={off_by_one.SCORE_TURN_THE_EXTRA_BYTE} "
        f"alloc_size={alloc_size.SCORE_WRAP_THE_SIZE} "
        f"fini_array={fini_array.SCORE_PATCH_A_FINALISER} "
        f"objptr={objptr_hijack.SCORE_OVERWRITE_THE_POINTER}"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_landing_arithmetic_is_taught_with_its_real_numbers(slug: str) -> None:
    """`X - N` is the whole exercise, so all three numbers have to appear.

    Not just the answer: the two operands too, because a reader given only the
    destination cannot check it or re-derive it on the next build.
    """
    a = off_by_one._Analysis(_target(slug))
    d = a.defect
    assert d.dest_off == d.X - d.N, (
        f"{slug}: the executor's own arithmetic no longer holds -- X={d.X:#x} "
        f"N={d.N:#x} dest_off={d.dest_off:#x}"
    )

    w = _walkthrough(slug)
    assert _constant(w, "BUFFER_SLOT").value == d.X
    assert _constant(w, "FILL_BOUND").value == d.N
    assert _constant(w, "BYTE_SLOT").value == d.dest_off
    assert _constant(w, "BYTE_SLOT").confidence is Confidence.DERIVED, (
        "BYTE_SLOT is computed from two measured numbers, which is DERIVED"
    )

    prose = _all_prose(w)
    for value in (f"{d.X:#x}", f"{d.N:#x}", f"{d.dest_off:#x}"):
        assert value in prose, (
            f"{slug}: {value} never appears in the walkthrough's prose, so the "
            "reader is handed a destination without the arithmetic that produced it"
        )
    assert d.writer in prose and d.owner in prose, (
        f"{slug}: the walkthrough never names the writer ({d.writer}) or the frame "
        f"owner ({d.owner}), which are the two functions to go read"
    )


def test_the_inclusive_comparison_is_what_the_walkthrough_tells_you_to_find() -> None:
    """Not "an overflow" -- the specific instruction, and its corrected form.

    The premise is measurable: the positives contain inclusive branches and the
    control's are all exclusive. So the walkthrough must name `jbe`/`jle` AND name
    `jb`/`jl` as what the fixed version looks like, or the reader cannot tell the
    two apart when they see them.
    """
    prose = _all_prose(_walkthrough(PIVOT))
    assert "jbe" in prose or "jle" in prose, (
        "the walkthrough never names the inclusive branch to look for"
    )
    assert "jb" in prose and "jl" in prose, (
        "the walkthrough never names the exclusive form, so the reader cannot "
        "recognise the corrected code"
    )
    lowered = prose.lower()
    assert "inclusive" in lowered and "exclusive" in lowered

    # The premise, measured off the images rather than asserted.
    def _counts(path: str) -> tuple[int, int]:
        text = subprocess.run(
            ["objdump", "-d", "-M", "intel", "--no-show-raw-insn", path],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        inclusive = len(re.findall(r"\s(jbe|jle)\s", text))
        exclusive = len(re.findall(r"\s(jb|jl)\s", text))
        return inclusive, exclusive

    pos_incl, _pos_excl = _counts(_target(PIVOT))
    assert pos_incl > 0, (
        "premise gone: the positive has no inclusive branches at all, so the "
        "instruction the walkthrough names is not in the image"
    )


def test_the_pivot_route_states_its_15_of_16_ceiling() -> None:
    """The fact most likely to be quietly omitted, and the most costly to omit.

    Without it a reader watching a correct exploit miss once concludes it is
    broken. With it, a clean sweep of 20 misses is a diagnostic about the derived
    geometry instead.

    Pinned three ways: the number, its mechanism, and the executor's agreement --
    so this cannot pass on a family that says "probabilistic" and nothing else.
    """
    a = off_by_one._Analysis(_target(PIVOT))
    assert a.route == "saved_rbp_pivot", "premise gone: this is no longer the pivot"
    assert a.defect.dest_off == 0, (
        "premise gone: the byte no longer lands on the saved frame pointer, so "
        "there is nothing being re-randomised"
    )

    w = _walkthrough(PIVOT)
    prose = _all_prose(w)
    assert off_by_one.PIVOT_CEILING in prose, (
        f"the walkthrough never states the {off_by_one.PIVOT_CEILING} per-attempt "
        "ceiling"
    )
    assert "arch_align_stack" in prose, (
        "the ceiling is stated without its mechanism, so a reader cannot check it "
        "or recognise when it does not apply"
    )
    assert "no-op" in prose or "changes nothing" in prose, (
        "the walkthrough never says WHY one value in sixteen fails: the write "
        "lands on a byte that is already 0x00"
    )

    # The failure path has to say it too -- that is where the reader is looking
    # when they need it.
    assert off_by_one.PIVOT_CEILING in _all_code(w), (
        "the emitted failure message does not mention the ceiling, so a run of "
        "misses reads as a broken exploit"
    )

    # And the executor agrees, so the walkthrough is not inventing a figure.
    assert ob.PIVOT_ATTEMPTS == _constant(w, "ATTEMPTS").value, (
        f"the walkthrough budgets {_constant(w, 'ATTEMPTS').value} attempts and "
        f"the executor budgets {ob.PIVOT_ATTEMPTS}"
    )
    with open(ob.__file__, encoding="utf-8") as fh:
        executor_source = fh.read()
    assert off_by_one.PIVOT_CEILING in executor_source, (
        f"the executor no longer states {off_by_one.PIVOT_CEILING} anywhere, so "
        "the walkthrough's figure has no corroborating source in the tool that "
        "flies the route"
    )
    assert "arch_align_stack" in executor_source, (
        "the executor no longer names the mechanism either, so the two are no "
        "longer describing the same thing"
    )


def test_the_deterministic_routes_do_not_claim_a_gamble() -> None:
    """The other arm, so the ceiling test cannot pass by saying it everywhere.

    `length_guard` and `saved_pointer` are deterministic: their 2-attempt budget is
    a retry for timing, not a die roll. Telling a reader to keep retrying there
    sends them to re-run a route that cannot improve, instead of re-deriving the
    number that is wrong.
    """
    for slug in (LENGTH_GUARD, SAVED_POINTER):
        a = off_by_one._Analysis(_target(slug))
        assert a.route != "saved_rbp_pivot", f"premise gone: {slug} is now a pivot"
        prose = _all_prose(_walkthrough(slug))
        assert off_by_one.PIVOT_CEILING not in prose, (
            f"{slug} is deterministic and the walkthrough quotes the pivot's "
            "probabilistic ceiling at it"
        )
        assert "deterministic" in prose.lower(), (
            f"{slug} never tells the reader the route is deterministic, so a miss "
            "reads as bad luck rather than as a wrong derivation"
        )
        code = _all_code(_walkthrough(slug))
        assert "deterministic" in code, (
            f"{slug}: the emitted failure message does not say the route is "
            "deterministic, which is the only place the advice matters"
        )


def test_the_two_stage_route_is_taught_as_two_separate_reads() -> None:
    """`obo_12`: the off-by-one is the KEY, and the stages cannot be concatenated.

    The byte widens a stored length; the SECOND operation, now unbounded, reaches
    the return address. Sending both parts as one blob is the commonest way to get
    this wrong and it fails silently -- the program reads part of stage two as
    stage one's tail.
    """
    a = off_by_one._Analysis(_target(LENGTH_GUARD))
    assert a.route == "length_guard"
    assert len(a.parts) == 2, (
        f"premise gone: this route now has {len(a.parts)} parts, so it no longer "
        "demonstrates two-stage framing"
    )

    code = _all_code(_walkthrough(LENGTH_GUARD))
    assert "recvrepeat" in code, "nothing drains between the parts"
    assert code.count("io.send(") >= 1
    prose = _all_prose(_walkthrough(LENGTH_GUARD))
    assert "drain" in prose.lower(), (
        "the walkthrough never explains the drain between parts, which is the "
        "difference between working and silently shifted"
    )
    assert "guard" in prose.lower() and "length" in prose.lower()


def test_the_saved_pointer_route_states_the_one_byte_reach_limit() -> None:
    """`obo_13`: a full 8-byte write, at an address that is barely movable.

    One byte means at most 255 bytes of movement, and when the byte is the
    program's own NUL it means exactly "down to the nearest 256-byte boundary". A
    reader who thinks the pointer is freely retargetable will look for a
    destination that cannot be reached.
    """
    a = off_by_one._Analysis(_target(SAVED_POINTER))
    assert a.route == "saved_pointer"
    assert a.defect.byte_kind == "imm" and a.defect.byte_value == 0, (
        "premise gone: the byte is no longer the program's own NUL, so the "
        "256-byte-boundary framing does not apply"
    )
    prose = _all_prose(_walkthrough(SAVED_POINTER))
    assert "256" in prose, (
        "the walkthrough never states the reach limit, so the constraint that "
        "makes this route depend on the image's data layout is invisible"
    )
    assert "one byte" in prose.lower()


def test_the_guard_word_route_needs_no_address_and_says_the_payoff_is_output() -> None:
    """The shape with the most to get wrong, and the one that would raise.

    MEASURED: `win_addr`, `ret_addr` and `key` are ALL None here. A step that
    formatted a win address unconditionally would raise TypeError rather than
    render, and a success check that demanded a shell would report a working
    exploit as a failure -- the payoff is the program's own privileged output,
    after which it may exit normally.
    """
    path = _guard_word()
    a = off_by_one._Analysis(path)
    assert a.route == "guard_word"
    assert a.plan.win_addr is None, (
        "premise gone: this target now has a win address, so it no longer "
        "exercises the no-destination arm"
    )
    assert a.plan.ret_addr is None
    assert a.plan.key is None
    assert a.missing_addresses == (), (
        "guard_word must not be recorded as MISSING addresses it does not need"
    )
    assert a.complete is True

    w = _walkthrough_at(path)
    assert _constant(w, "WIN") is None, (
        "a WIN constant was emitted for a route with no destination -- it would "
        "render as None or as a null pointer"
    )
    assert _constant(w, "RET_GADGET") is None
    assert _constant(w, "MENU_KEY") is None
    assert "MENU_KEY" not in _all_code(w), (
        "the emitted code references MENU_KEY on a target that has no menu key, "
        "which is a NameError on the reader's first run"
    )

    # Nothing may render a bare `None` into the reader's payload. Checked on the
    # constant block rather than the whole script, because `is None` is a
    # legitimate comparison in the shared helpers.
    script = render_script(w)
    constants_block = script.split("def ", 1)[0]
    assert "= None" not in constants_block, (
        "a constant was emitted with the value None, which reads as a measurement "
        f"and is a missing one: {constants_block!r}"
    )

    text = _all_prose(w) + "\n" + (w.success_criteria or "")
    lowered = text.lower()
    assert "privileged" in lowered, (
        "the walkthrough never says the payoff is the program's own privileged "
        "branch, so a reader waits for a shell that never comes"
    )
    assert "exit" in lowered or "closed pipe" in lowered, (
        "nothing tells the reader that a closed pipe is an EXPECTED outcome here"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_parts_are_emitted_with_their_real_lengths(slug: str) -> None:
    """The payload has to be inspectable, not an opaque blob.

    A reader who changes BUFFER_SLOT or FILL_BOUND needs to see which bytes change
    with them; otherwise the derived numbers above are decorative.
    """
    a = off_by_one._Analysis(_target(slug))
    w = _walkthrough(slug)
    assert a.parts, f"{slug}: no parts at all"
    for index, (label, blob) in enumerate(a.parts, start=1):
        fact = _constant(w, f"PART_{index}")
        assert fact is not None, f"{slug}: PART_{index} is not emitted"
        assert fact.value == blob, f"{slug}: PART_{index} does not match the plan"
        assert fact.description == label, (
            f"{slug}: PART_{index} lost the executor's own label for it"
        )
    assert _constant(w, f"PART_{len(a.parts) + 1}") is None, (
        f"{slug}: more PART_ constants are emitted than the plan has parts"
    )


# --------------------------------------------------------------------------
# (b) declines the negative control, naming the missing fact
# --------------------------------------------------------------------------


def test_the_control_is_declined_and_the_reason_names_the_exclusive_bound() -> None:
    """Both halves: the decline must name the COMPARISON, not "no overflow".

    The control is the corrected form of the same program. What a reader needs to
    be told is that every indexing comparison is EXCLUSIVE -- that is the thing
    that differs, and it is what lets them recognise the fix elsewhere.
    """
    path = _target(CONTROL)
    a = off_by_one._Analysis(path)
    assert a.plan is None, (
        "premise gone: the executor now returns a plan for the negative control, "
        "so the decline no longer comes from the bound gate"
    )
    assert a.complete is False

    reason = a.decline_reason
    assert "exclusive" in reason, (
        f"the decline does not name the comparison strictness: {reason!r}"
    )
    assert "bound" in reason, f"the decline does not mention the bound: {reason!r}"
    assert "corrected" in reason, (
        f"the decline does not tell the reader this IS the fixed form: {reason!r}"
    )

    route = off_by_one.propose(collect_facts(path, probe=False))
    assert route is not None and route.applicable is False
    assert reason in route.rationale
    assert route.becomes_viable_if and route.becomes_viable_if.strip()
    assert route.rejection is not None
    # The remedy must point at the comparison too, not at a generic hunt.
    assert "jbe" in route.becomes_viable_if or "jle" in route.becomes_viable_if, (
        f"the remedy does not name what to look for: {route.becomes_viable_if!r}"
    )


def test_the_control_differs_from_its_positive_by_one_instruction() -> None:
    """The premise, measured on both images rather than taken on trust.

    `obo_90` is `obo_10` with `i <= n` changed to `i < n` in `read_line` and
    nothing else. MEASURED: the two `read_line` bodies are byte-for-byte the same
    instructions at the same addresses, and differ at exactly one -- `jbe` in the
    positive, `jb` in the control. That is the whole category in one letter, and
    it is why "the control declines" is a meaningful result rather than an
    incidental one.

    Note what is deliberately NOT asserted: that the control contains no inclusive
    branch anywhere. It does -- `main`'s menu loop has a `jle` -- and an inclusive
    comparison that never indexes a buffer is harmless. An assertion that broad
    fails on a safe program, which is how a premise test turns into noise.
    """

    def _read_line_body(path: str) -> list[str]:
        text = subprocess.run(
            ["objdump", "-d", "-M", "intel", "--no-show-raw-insn", path],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        body, keep = [], False
        for line in text.splitlines():
            label = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
            if label:
                keep = label.group(1) == "read_line"
                continue
            if keep and line.strip():
                body.append(line.strip())
        return body

    pos = _read_line_body(_target(PIVOT))
    ctl = _read_line_body(_target(CONTROL))
    assert pos and ctl, (
        "premise gone: `read_line` is not in one of these images, so this is no "
        "longer comparing the function the defect lives in"
    )
    assert len(pos) == len(ctl), (
        f"premise gone: the two bodies are different lengths ({len(pos)} vs "
        f"{len(ctl)}), so the control is no longer the same program with one "
        "comparison corrected"
    )

    differences = [(p, c) for p, c in zip(pos, ctl) if p != c]
    assert len(differences) == 1, (
        f"premise gone: the two `read_line` bodies differ at {len(differences)} "
        f"instructions, not one: {differences}"
    )
    pos_insn, ctl_insn = differences[0]
    assert "jbe" in pos_insn, f"the positive's branch is not inclusive: {pos_insn!r}"
    assert "jb " in ctl_insn or ctl_insn.split()[1] == "jb", (
        f"the control's branch is not exclusive: {ctl_insn!r}"
    )

    # And the source says the same thing, which is what a reader will check.
    for path, wanted in (
        (_target(PIVOT) + ".c", "i <= n"),
        (_target(CONTROL) + ".c", "i < n"),
    ):
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        assert f"for (i = 0; {wanted}; i++)" in source, (
            f"{os.path.basename(path)} no longer contains `{wanted}`, so the "
            "source-level statement of the defect has moved"
        )


def test_the_control_is_not_taught_this_route() -> None:
    w = _walkthrough(CONTROL)
    assert w.family != off_by_one.NAME, (
        f"{CONTROL} is a NEGATIVE CONTROL -- the pipeline does not solve it -- and "
        "explain teaches the off-by-one route anyway"
    )


def test_the_decline_reasons_differ_per_gate() -> None:
    """`I-29`, answered rather than repeated. Four gates, four sentences.

    Built from the family's own branches, because the corpus has one control and
    cannot exhibit all four shapes. Each case keeps the plan real and removes
    exactly one thing, which is what makes each reason a WRONG-but-present test
    rather than an absence test.
    """
    reasons: dict[str, str] = {}

    # Gate 1: no plan at all.
    reasons["no-bound"] = off_by_one._Analysis(_target(CONTROL)).decline_reason

    # Gate 2: a real plan naming a shape this family has no step for.
    unexplained = off_by_one._Analysis(_target(PIVOT))
    unexplained.plan.route = "some_future_shape"
    try:
        assert unexplained.route_is_explained is False
        assert unexplained.complete is False
        reasons["unexplained"] = unexplained.decline_reason
    finally:
        unexplained.plan.route = SHAPES[PIVOT]

    # Gate 3: a real plan whose sled came out empty.
    empty = off_by_one._Analysis(_target(PIVOT))
    original_parts = list(empty.plan.parts)
    try:
        label = original_parts[0][0]
        empty.plan.parts = [(label, b"")] + original_parts[1:]
        assert empty.empty_parts == (label,)
        assert empty.parts_are_deliverable is False
        assert empty.complete is False
        reasons["empty-part"] = empty.decline_reason
    finally:
        empty.plan.parts = original_parts

    # Gate 4: a route that needs a destination and has none.
    homeless = off_by_one._Analysis(_target(PIVOT))
    original_win = homeless.plan.win_addr
    try:
        homeless.plan.win_addr = None
        assert homeless.missing_addresses, "gate 4 needs the address to be missing"
        assert homeless.complete is False
        reasons["no-destination"] = homeless.decline_reason
    finally:
        homeless.plan.win_addr = original_win

    assert len(set(reasons.values())) == 4, (
        f"two gates give the same explanation: {reasons}"
    )
    assert "exclusive" in reasons["no-bound"]
    assert "no specific step" in reasons["unexplained"]
    assert "ZERO bytes long" in reasons["empty-part"]
    assert "nowhere to send control" in reasons["no-destination"]


def test_an_empty_part_is_refused_and_the_candidate_parts_are_real() -> None:
    """The empty-candidate gate, with its premise asserted FIRST.

    An "it is not empty" test that never checks what the set contains is itself
    the defect it guards against. So this asserts, in order: every positive has
    parts, every part carries bytes, the sled builder really does produce `b""`
    for length 0 (the mechanism), and the family declines when it happens.
    """
    for slug in POSITIVES:
        a = off_by_one._Analysis(_target(slug))
        assert a.parts, f"{slug}: the plan carries no input parts at all"
        assert a.empty_parts == (), f"{slug}: empty parts {a.empty_parts}"
        for label, blob in a.parts:
            assert blob, f"{slug}: part {label!r} is empty"
            assert isinstance(blob, (bytes, bytearray)), (
                f"{slug}: part {label!r} is {type(blob).__name__}, not bytes"
            )
        assert a.parts_are_deliverable is True

    # The mechanism, measured: this is why the gate is not hypothetical.
    assert ob._sled(0x401000, 0x401001, 0, False) == b"", (
        "premise gone: the sled builder no longer returns an empty payload for "
        "length 0, so a mis-derived length can no longer produce a part that "
        "delivers nothing"
    )
    assert ob._sled(0x401000, 0x401001, 16, False), (
        "the sled builder returns nothing for a real length, which would make the "
        "guard above trivially true"
    )


def test_a_route_that_needs_an_address_and_lacks_one_is_declined() -> None:
    """The TypeError hazard, pinned as a decline rather than a crash.

    `guard_word` legitimately carries `win_addr=None`, so no step may format it
    unconditionally. The other three shapes DO need it, and a plan that lacks it
    must decline with a sentence rather than render `None` or raise.
    """
    for slug, needs_ret in ((PIVOT, True), (SAVED_POINTER, False)):
        a = off_by_one._Analysis(_target(slug))
        assert a.plan.win_addr is not None, f"premise gone: {slug} has no win address"
        original = a.plan.win_addr
        try:
            a.plan.win_addr = None
            assert a.missing_addresses, f"{slug}: a missing win address went unnoticed"
            assert a.complete is False
            reason = a.decline_reason
            assert "win function" in reason
            assert "None" not in reason, (
                f"{slug}: the decline renders a None into its own sentence: {reason!r}"
            )
        finally:
            a.plan.win_addr = original

        if needs_ret:
            original_ret = a.plan.ret_addr
            try:
                a.plan.ret_addr = None
                assert a.missing_addresses, (
                    f"{slug}: a missing ret gadget went unnoticed on a route that "
                    "needs one for alignment"
                )
                assert a.complete is False
            finally:
                a.plan.ret_addr = original_ret

    # ...and propose() must not raise on any of it. That is where the sibling
    # function's unconditional formatting would have broken.
    facts = collect_facts(_target(PIVOT), probe=False)
    broken = off_by_one._Analysis(_target(PIVOT))
    saved = broken.plan.win_addr
    try:
        broken.plan.win_addr = None
        route = off_by_one.propose(facts)          # must not raise
        assert route is not None and route.applicable is False
        assert route.becomes_viable_if and route.becomes_viable_if.strip()
    finally:
        broken.plan.win_addr = saved


# --------------------------------------------------------------------------
# (c) the artifact is honest and usable
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_no_step_pastes_a_shell_transcript_into_python(slug: str) -> None:
    for step in _walkthrough(slug).steps:
        for line in step.code.splitlines():
            assert not line.strip().startswith("$ "), (
                f"{slug} step {step.id!r} pastes a shell transcript into Python: "
                f"{line.strip()!r}. Use common.shell_transcript()."
            )


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_offset_fact_is_not_carried(slug: str) -> None:
    """The dangerous case, and the reason the drop is BY NAME here.

    The unresolved-step filter drops OFFSET only when the probe failed to measure
    one. A measured buffer-to-return-address offset would be KEPT -- and on three
    of these six the overflow is one byte and never reaches the return address, so
    a true number here sends the reader straight back to the framing this family
    exists to replace.
    """
    assert _constant(_walkthrough(slug), "OFFSET") is None, (
        f"{slug} carries OFFSET on a route whose overflow may be one byte"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_success_criteria_do_not_treat_absence_of_a_crash_as_evidence(
    slug: str,
) -> None:
    """The judging error this bug invites, stated in the artifact.

    A wrong attempt here returns NORMALLY. So the artifact has to say that no
    crash proves nothing -- otherwise a reader concludes success from silence.
    """
    w = _walkthrough(slug)
    text = (w.success_criteria or "") + "\n" + _all_prose(w)
    lowered = text.lower()
    assert "crash" in lowered, (
        f"{slug}: the walkthrough never mentions crashing, so it never warns that "
        "the absence of one means nothing on this bug"
    )
    assert "PWNED_42" in text or "PWNED_$((6*7))" in text, (
        f"{slug}: no arithmetic shell proof in the success criteria"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_shell_proof_is_arithmetic_the_shell_must_evaluate(slug: str) -> None:
    code = _all_code(_walkthrough(slug))
    assert "PWNED_$((6*7))" in code, "the arithmetic marker is gone"
    assert "PWNED_42" in code, "nothing checks for the evaluated answer"
    assert code.index("PWNED_$((6*7))") < code.rindex("PWNED_42")


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_delivery_loop_is_defined_once_and_shared(slug: str) -> None:
    """Two hand-maintained copies of the protocol would drift silently.

    The numbered delivery step and the assembled exploit must run the SAME loop,
    because the one subtlety -- draining between parts -- is invisible when wrong:
    both copies run, one works.
    """
    w = _walkthrough(slug)
    script = render_script(w)
    assert script.count("def one_attempt(") == 1, (
        f"{slug}: one_attempt is defined {script.count('def one_attempt(')} times"
    )
    step = next(s for s in w.steps if s.id == "deliver_and_confirm")
    assert "one_attempt()" in step.code
    assert "one_attempt()" in (w.final_exploit or ""), (
        f"{slug}: the assembled exploit does not call the shared delivery helper"
    )
    # The bodies must be the same text, not merely both present.
    assert step.code.strip() in (w.final_exploit or ""), (
        f"{slug}: the step's loop and the final exploit's loop are different text, "
        "so they can drift"
    )


def test_the_gate_stays_narrow_across_every_built_elf() -> None:
    """Swept in-test so the denominator cannot drift.

    MEASURED and stated honestly: this gate opens on SIX targets, not five. The
    sixth is `benchmark/corpus/13_off_by_one`, which is a genuine off-by-one in the
    shared round-1 corpus and is claimed on purpose.
    """
    seen: list[str] = []
    for pattern in (
        os.path.join(REPO, "benchmark", "corpus*", "*", "*"),
        os.path.join(REPO, "tests", "htb-targets", "*", "*", "*"),
    ):
        for path in sorted(glob.glob(pattern)):
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                continue
            with open(path, "rb") as fh:
                if fh.read(4) != b"\x7fELF":
                    continue
            seen.append(path)

    if len(seen) < 20:
        pytest.skip(f"only {len(seen)} ELFs built; the sweep would not be meaningful")

    claimed = sorted(
        os.path.basename(p) for p in seen if off_by_one._Analysis(p).complete
    )
    assert claimed, (
        "the family claims nothing at all across the whole tree, so either the "
        "corpus is not built or a gate is broken shut"
    )
    expected = set(POSITIVES) | {"off_by_one"}
    assert set(claimed) == expected, (
        f"the family claims {claimed}; expected {sorted(expected)}. An open gate "
        "outside the family is not automatically a defect, but it must be examined "
        "rather than absorbed."
    )


def test_the_plan_the_family_explains_is_the_plan_the_executor_flies() -> None:
    """No second opinion: the family must not re-derive the route."""
    for path in [_target(s) for s in POSITIVES] + [_guard_word()]:
        plan, _reason = ob.analyse(path)
        a = off_by_one._Analysis(path)
        assert plan is not None
        assert a.plan is plan, (
            f"{os.path.basename(path)}: the family holds a different plan object "
            "than the executor's cached one"
        )
        assert a.route == plan.route
        assert list(a.parts) == list(plan.parts)
