"""The finaliser-table-write walkthrough family, pinned where it matters.

WHY THIS FILE EXISTS
--------------------
`fini_array_write` solves 5/5 on `benchmark/corpus_finiarray` and the walkthrough
layer could explain none of them. MEASURED before this family existed: with
probing, every one of the five fell to `triage` at 0.15; with `--no-probe` every
one fell to `stack_bof`'s `ret2win` at 0.75.

`ret2win` at 0.75 is the one that matters, because it is followable and wrong.
Nothing in this family overflows a frame -- the write is a BOUNDED index store
into a global array, the bound is honoured, and no return address is involved.
A reader sent to measure a buffer-to-return-address offset with a cyclic pattern
here is measuring a frame the route never touches.

`fini_12_init_array_reload` is the target named in the brief: it is also the
target `objptr_hijack` rendered `for k in ():` for, because it genuinely does
call indirectly through `.init_array` but the write that reaches that table is a
bounded scalar store 81 slots away rather than an indexed fill.

WHAT THIS FAMILY GATES THAT THE EXECUTOR DOES NOT
-------------------------------------------------
Two things, and every gate here is tested in BOTH halves -- the premise (the
shape being tested is still the shape) and the behaviour (the family does the
right thing about it). Without the premise half a corpus rebuild could leave
these tests green while measuring nothing.

``reachable_entries``
    the empty-candidate gate. A destination with no entry inside the store's
    bound renders a loop over an empty list: it parses, it runs, it reports
    nothing, and it teaches nothing.
``teachable_entries``
    the shadow gate. `fini_14`'s walker compares `plugin_hooks[i]` against
    `expected_hooks[i]` before calling it, so an entry whose shadow copy is out
    of reach is an entry this route cannot use even though the table is in reach.

And one honesty requirement: which entry is LOAD-BEARING is not statically
decidable. `fini_11`'s first-walked finaliser fires and still loses, because it
un-masks the string the win depends on. So with more than one candidate the index
is UNKNOWN and swept, never stated.
"""

from __future__ import annotations

import ast
import glob
import os

import pytest
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

from supwngo.exploit.pipeline.executors import finiarray_techniques as fini
from supwngo.exploit.walkthrough.families import fini_array
from supwngo.exploit.walkthrough.facts import collect_facts
from supwngo.exploit.walkthrough.model import Confidence
from supwngo.exploit.walkthrough.registry import generate_walkthrough, propose_routes
from supwngo.exploit.walkthrough.render import render_script

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

POSITIVES = [
    "fini_10_fini_array_ret",
    "fini_11_fini_array_multi",
    "fini_12_init_array_reload",
    "fini_13_hook_table_exit",
    "fini_14_fullrelro_whitelist",
]

CONTROL = "fini_90_neg_fullrelro_notable"

#: The only positive with exactly ONE reachable entry, so the index is DERIVED
#: rather than swept. Keeps both arms of the index presentation covered.
SINGLE_ENTRY = "fini_10_fini_array_ret"
#: More than one entry AND walked backwards by the loader.
REVERSE_MULTI = "fini_11_fini_array_multi"
#: Walked FORWARD by the program itself, and the target named in the brief.
FORWARD_RELOAD = "fini_12_init_array_reload"
#: Full RELRO, and the only one whose table has a shadow copy to mirror.
SHADOWED = "fini_14_fullrelro_whitelist"


def _target(slug: str) -> str:
    path = os.path.join(REPO, "benchmark", "corpus_finiarray", slug, slug)
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        pytest.skip(f"{slug} not built; run benchmark/build_all.sh")
    return path


def _walkthrough(slug: str):
    """Selection without the live probe.

    `probe=False` is deliberate and is not a weakening: it makes `stack_bof`'s
    `ret2win` APPLICABLE at 0.75, which is the competitor this family's score
    exists to beat. Probing instead makes the competition vanish, which would
    make every selection assertion below easier and less meaningful.
    """
    return generate_walkthrough(collect_facts(_target(slug), probe=False))


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


# --------------------------------------------------------------------------
# (a) claimed, completed, and the steps carry the real route facts
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_is_claimed_by_this_family(slug: str) -> None:
    w = _walkthrough(slug)
    assert w.family == fini_array.NAME, (
        f"{slug} is solved by the fini_array_write executor but explain teaches "
        f"{w.family!r}. Measured baseline before this family existed: triage (0.15) "
        "with probing, stack_bof ret2win (0.75) without -- and ret2win teaches a "
        "cyclic-pattern offset hunt for a route that never touches a frame."
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_completes_and_renders(slug: str) -> None:
    a = fini_array._Analysis(_target(slug))
    assert a.complete is True, f"{slug}: {a.decline_reason}"
    ast.parse(render_script(_walkthrough(slug)))


def test_it_outranks_the_ret2win_route_it_replaces() -> None:
    """The ordering that justifies 0.86, with its premise asserted.

    Without the `stack_bof in scores` assertion this would keep passing after
    `stack_bof` stopped applying -- which would be a regression in ITS gate
    reported as a win for this one.
    """
    facts = collect_facts(_target(FORWARD_RELOAD), probe=False)
    scores = {
        fam.NAME: route.score
        for fam, route in propose_routes(facts)
        if route is not None and route.applicable
    }
    assert "stack_bof" in scores, (
        "stack_bof no longer applies to fini_12, so this test has stopped "
        "measuring the ordering it exists for"
    )
    assert scores[fini_array.NAME] > scores["stack_bof"], (
        f"fini_array_write at {scores[fini_array.NAME]} does not outrank "
        f"stack_bof at {scores['stack_bof']}"
    )


def test_the_score_stays_below_objptr_hijack() -> None:
    """The upper bound, pinned against the named constant rather than a literal.

    `objptr_hijack`'s gate opens on `fini_12` -- that is how it came to render
    `for k in ():` there. Scoring above it would send this family reaching into
    `corpus_objptr` on any image where both gates open.
    """
    from supwngo.exploit.walkthrough.families import objptr_hijack

    assert (
        fini_array.SCORE_PATCH_A_FINALISER
        < objptr_hijack.SCORE_OVERWRITE_THE_POINTER
    ), (
        f"fini_array={fini_array.SCORE_PATCH_A_FINALISER} would outrank "
        f"objptr_hijack={objptr_hijack.SCORE_OVERWRITE_THE_POINTER}"
    )


def test_the_brief_target_is_taught_the_real_geometry_not_a_generality() -> None:
    """`fini_12`, with every number it teaches checked against the image.

    MEASURED: the store is `do_patch`, base 0x403560, stride 8, index bounded
    -4096..4096 -- a 0x8000-byte reach expressed as an element count, which is
    why it reads as a bounds check. `.init_array` is at 0x4032d8, which is
    0x4032d8 - 0x403560 = -0x288 = -648 bytes = -81 slots below the store's base,
    so entry 0 is store index -81. Those are the numbers a reader needs and they
    are the numbers that must appear.
    """
    a = fini_array._Analysis(_target(FORWARD_RELOAD))
    assert a.complete is True

    # Premise: the geometry is still what the assertions below describe.
    assert a.write.base == 0x403560, f"store base moved to {a.write.base:#x}"
    assert a.write.scale == 8
    assert (a.write.lo, a.write.hi) == (-4096, 4096)
    assert a.dest.base == 0x4032D8, f"table moved to {a.dest.base:#x}"
    assert a.dest.entries == 3
    assert a.dest.walk == "forward", (
        "this target is the FORWARD-walked one; if that changed it no longer "
        "covers the program-walks-its-own-table arm"
    )
    assert a.reachable_entries == ((0, -81), (1, -80), (2, -79)), (
        f"the recovered entries changed: {a.reachable_entries}"
    )

    w = _walkthrough(FORWARD_RELOAD)
    assert _constant(w, "STORE_BASE").value == 0x403560
    assert _constant(w, "STORE_STRIDE").value == 8
    assert _constant(w, "TABLE").value == 0x4032D8
    assert _constant(w, "TABLE_ENTRIES").value == 3
    # The arithmetic, not just the two endpoints: -648 is what makes -81 land.
    assert _constant(w, "TABLE_DISTANCE").value == -648
    assert _constant(w, "STORE_SPAN_BYTES").value == 0x8000

    code = _all_code(w)
    for slot in ("-81", "-80", "-79"):
        assert slot in code, (
            f"the emitted code never names store index {slot}, so the reader is "
            "not told which index reaches which entry"
        )
    assert "0x4032d8" in code.lower() or "4207320" in code, (
        "the emitted code never names the table address it patches"
    )


def test_the_candidate_table_is_literal_and_non_empty_on_every_positive() -> None:
    """The anti-`for k in ():` test, asserting the candidates EXIST first.

    An "the loop is not empty" assertion that never checks the candidate set is
    itself the defect it is guarding against, so this asserts three things in
    order: the analysis found candidates, every candidate is a real reachable
    entry, and the emitted code iterates something with those numbers in it.
    """
    for slug in POSITIVES:
        a = fini_array._Analysis(_target(slug))
        assert a.reachable_entries, (
            f"{slug}: no entry of the chosen table lands inside the store's bound, "
            "so there is no candidate to sweep and this target can no longer "
            "exercise the route at all"
        )
        assert a.teachable_entries, (
            f"{slug}: every reachable entry was filtered out by the shadow gate, "
            "so the emitted sweep would be empty"
        )
        for index, slot in a.teachable_entries:
            addr = a.dest.base + index * a.write.scale
            assert a.write.reaches(addr), (
                f"{slug}: candidate entry {index} at {addr:#x} is outside the "
                "store's own bound"
            )
            assert a.slot_of(addr) == slot, (
                f"{slug}: candidate entry {index} claims store index {slot} but "
                f"the geometry says {a.slot_of(addr)}"
            )

        code = _all_code(_walkthrough(slug))
        assert "for k in ()" not in code and "in ():" not in code, (
            f"{slug}: the emitted code iterates an empty literal -- the exact "
            "defect that made objptr_hijack render `for k in ():` on fini_12"
        )
        for _index, slot in a.teachable_entries:
            assert str(slot) in code, (
                f"{slug}: store index {slot} is a candidate but never appears in "
                "the emitted code"
            )


def test_the_backwards_walk_is_stated_where_it_applies() -> None:
    """glibc's `call_fini()` walks `.fini_array` BACKWARDS, and that decides order.

    Getting this wrong is not cosmetic: on a multi-entry `.fini_array` the entry
    that runs FIRST is the last one, so a reader sweeping forward tries the
    candidates in the opposite order to the one that matters. Premise asserted
    both ways -- one target walked reverse, one walked forward.
    """
    rev = fini_array._Analysis(_target(REVERSE_MULTI))
    assert rev.dest.walk == "reverse", (
        "premise gone: this target is no longer the reverse-walked one"
    )
    assert rev.dest.entries > 1, (
        "premise gone: a single-entry table cannot show a walk ORDER at all"
    )
    assert rev.walks_backwards is True
    # The walk order is the evidence: highest index first.
    assert [i for i, _s in rev.reachable_entries] == [3, 2, 1, 0], (
        f"the reverse walk order changed: {rev.reachable_entries}"
    )

    text = " ".join(
        [s.why or "" for s in _walkthrough(REVERSE_MULTI).steps]
        + [_walkthrough(REVERSE_MULTI).strategy or ""]
    ).lower()
    assert "backwards" in text, (
        "the walkthrough never tells the reader that .fini_array is walked "
        "backwards, which is the fact that decides which entry fires first"
    )

    fwd = fini_array._Analysis(_target(FORWARD_RELOAD))
    assert fwd.walks_backwards is False, (
        "both arms now report a backwards walk, so the distinction is untested"
    )
    assert [i for i, _s in fwd.reachable_entries] == [0, 1, 2]


def test_the_shadow_table_is_written_too() -> None:
    """`fini_14`: one hijack, two writes, because the walker validates.

    `run_plugin_hooks` compares `plugin_hooks[i]` against `expected_hooks[i]` and
    refuses when they differ, so writing only the table produces the program's own
    refusal message rather than a crash -- the most misleading possible outcome.
    Premise asserted: the mirror really is there and really is in reach.
    """
    a = fini_array._Analysis(_target(SHADOWED))
    assert a.dest.mirrors, (
        "premise gone: this target's table no longer has a shadow copy, so it no "
        "longer exercises the mirror gate"
    )
    assert a.dest.mirrors == [0x4040A0], f"the shadow moved: {a.dest.mirrors}"
    assert a.dest.base == 0x404080
    assert a.mirrors_covered(0) is True
    assert a.teachable_entries == ((0, 8), (1, 9), (2, 10), (3, 11))

    # Every candidate's shadow slot must be emitted alongside it: 12..15.
    w = _walkthrough(SHADOWED)
    code = _all_code(w)
    for index, slot in a.teachable_entries:
        shadows = [s for _addr, s in a.mirror_slots(index)]
        assert shadows, f"entry {index} lost its shadow slot"
        for shadow in shadows:
            assert str(shadow) in code, (
                f"entry {index} needs its shadow at store index {shadow} written "
                "too, and that index never appears in the emitted code"
            )
    assert _constant(w, "SHADOW_INDICES") is not None, (
        "the shadowed target carries no SHADOW_INDICES constant"
    )


def test_writability_is_computed_from_segments_not_section_flags() -> None:
    """The measured fact a plausible one would get wrong.

    On `fini_14` the `.fini_array` SECTION HEADER carries `WA` -- writable, by its
    own flags -- and it is nonetheless read-only at runtime, because it lies
    inside `PT_GNU_RELRO` and the loader `mprotect`s that range. MEASURED on this
    host: `.fini_array` at 0x403d98, `PT_GNU_RELRO` 0x403d90 + 0x270, so
    0x403d98 is inside it.

    A family that trusted the section flag would teach a write to a page that
    faults. So the plan must pick the table in `.data` -- `plugin_hooks` at
    0x404080, inside the `PF_W PT_LOAD` and past the end of the RELRO range --
    and this asserts both the lie and the correct choice.
    """
    path = _target(SHADOWED)
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        fini_sec = elf.get_section_by_name(".fini_array")
        assert fini_sec is not None, "premise gone: no .fini_array section"
        flag_says_writable = bool(fini_sec["sh_flags"] & SH_FLAGS.SHF_WRITE)
        fini_addr = fini_sec["sh_addr"]

        relro = [s for s in elf.iter_segments() if s["p_type"] == "PT_GNU_RELRO"]
        assert relro, (
            "premise gone: this target has no PT_GNU_RELRO, so it is no longer "
            "the Full RELRO arm and the section flag does not lie here"
        )
        lo = relro[0]["p_vaddr"]
        hi = lo + relro[0]["p_memsz"]

    assert flag_says_writable is True, (
        "premise gone: .fini_array's section header no longer claims WA, so this "
        "test no longer demonstrates that the flag can lie"
    )
    assert lo <= fini_addr < hi, (
        f"premise gone: .fini_array at {fini_addr:#x} is outside PT_GNU_RELRO "
        f"[{lo:#x},{hi:#x}), so it really is writable here"
    )

    a = fini_array._Analysis(path)
    assert a.dest.base != fini_addr, (
        f"the plan chose .fini_array at {fini_addr:#x} as its destination, which "
        "the section header calls writable and the loader makes read-only"
    )
    assert a.dest.base >= hi, (
        f"the chosen table at {a.dest.base:#x} is inside PT_GNU_RELRO "
        f"[{lo:#x},{hi:#x}) and will fault on the first store"
    )


# --------------------------------------------------------------------------
# (b) declines the negative control, naming the missing fact
# --------------------------------------------------------------------------


def test_the_control_is_declined_and_the_reason_names_the_relro_segment() -> None:
    """Both halves: the write primitive IS there, and the TABLE is what is missing.

    The distinction is the whole value of the message. This control is Full RELRO
    and has no program-owned table, so a reader must be told "no writable,
    reached table", not "no write primitive" -- it has one, identical to its
    positives'.
    """
    path = _target(CONTROL)
    a = fini_array._Analysis(path)
    assert a.plan is None, (
        "premise gone: the executor now returns a plan for the negative control, "
        "so the decline no longer comes from the table gate"
    )
    assert a.complete is False

    reason = a.decline_reason
    assert "write primitive is present" in reason, (
        "the decline does not say the store WAS found, so a reader will go "
        f"looking for the wrong missing thing: {reason!r}"
    )
    assert "PT_GNU_RELRO" in reason, (
        f"the decline does not name the segment that closed the gate: {reason!r}"
    )
    assert "writable" in reason and "reached" in reason, (
        f"the decline names neither half of the table requirement: {reason!r}"
    )

    # And the Route carries it, without raising. `propose` and `decline_reason`
    # are separate functions and the sibling one is where the TypeError lives.
    route = fini_array.propose(collect_facts(path, probe=False))
    assert route is not None and route.applicable is False
    assert reason in route.rationale
    assert route.becomes_viable_if and route.becomes_viable_if.strip()
    assert route.rejection is not None


def test_the_control_is_not_taught_this_route() -> None:
    w = _walkthrough(CONTROL)
    assert w.family != fini_array.NAME, (
        f"{CONTROL} is a NEGATIVE CONTROL -- the pipeline does not solve it -- and "
        "explain teaches the finaliser-write route anyway"
    )


def test_the_control_differs_from_its_positives_only_in_the_table() -> None:
    """The premise that makes the decline meaningful rather than incidental.

    `fini_14` and `fini_90` are both Full RELRO. The difference is that `fini_14`
    has a program-owned hook table in `.data`, outside the RELRO range, and
    `fini_90` does not. If `fini_90` ever stopped having a write primitive at all,
    this decline would be testing nothing.
    """
    ctl = fini_array._Analysis(_target(CONTROL))
    pos = fini_array._Analysis(_target(SHADOWED))
    assert pos.complete is True
    assert ctl.plan is None

    with open(_target(CONTROL), "rb") as fh:
        ctl_relro = [
            s for s in ELFFile(fh).iter_segments() if s["p_type"] == "PT_GNU_RELRO"
        ]
    assert ctl_relro, (
        "premise gone: the control is no longer RELRO-protected, so it is no "
        "longer the same shape as its positive with the table removed"
    )
    # The executor's own reason is the evidence that the store survived.
    assert "write primitive is present" in ctl.reason


def test_the_decline_reasons_differ_per_gate() -> None:
    """`I-29`, answered rather than repeated.

    Three gates, three sentences. The failure mode being guarded against is
    handing every decline the FIRST gate's explanation, which sends a reader with
    an unreachable table off looking for a write primitive they already have.

    Built from the family's own branches by construction, because the corpus has
    only one control and cannot exhibit all three shapes. Each stub keeps the
    plan real and removes exactly one thing.
    """

    class _NoDest:
        walk = "forward"

    real = fini_array._Analysis(_target(SHADOWED))
    assert real.complete is True

    # Gate 1: no plan at all -> the executor's own reason.
    gate1 = fini_array._Analysis(_target(CONTROL)).decline_reason

    # Gate 2: a plan and a table, but no entry inside the bound.
    gate2 = fini_array._Analysis(_target(SHADOWED))
    original_reaches = gate2.write.reaches
    try:
        gate2.write.reaches = lambda _addr: False  # type: ignore[assignment]
        assert gate2.reachable_entries == ()
        gate2_reason = gate2.decline_reason
    finally:
        gate2.write.reaches = original_reaches  # type: ignore[assignment]

    # Gate 3: entries in reach, but no shadow slot in reach.
    gate3 = fini_array._Analysis(_target(SHADOWED))
    original_mirrors = list(gate3.dest.mirrors)
    try:
        gate3.dest.mirrors = [original_mirrors[0] + 0x10000000]
        assert gate3.reachable_entries, "gate 3 needs the entries still in reach"
        assert gate3.teachable_entries == ()
        gate3_reason = gate3.decline_reason
    finally:
        gate3.dest.mirrors = original_mirrors

    reasons = {"no-plan": gate1, "no-reach": gate2_reason, "no-shadow": gate3_reason}
    assert len(set(reasons.values())) == 3, (
        f"two gates give the same explanation: {reasons}"
    )
    assert "PT_GNU_RELRO" in reasons["no-plan"]
    assert "no entry lands inside" in reasons["no-reach"]
    assert "shadow copy" in reasons["no-shadow"]


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


def test_a_swept_index_is_UNKNOWN_and_names_its_resolving_step() -> None:
    """The honesty requirement, and the one most tempting to violate.

    Which finaliser is load-bearing is NOT in the image. `fini_11`'s reverse walk
    starts at index 3, and index 3 is the finaliser that un-XORs the command
    string the win depends on -- so the first-walked entry fires and loses, and
    the answer is index 2. A family that stated an index would look identical to
    a measured one in the artifact and be wrong on the first table whose entries
    differed.
    """
    a = fini_array._Analysis(_target(REVERSE_MULTI))
    assert len(a.teachable_entries) > 1, (
        "premise gone: this target now has a single candidate, so there is "
        "nothing to sweep and no UNKNOWN to carry"
    )
    assert a.index_is_swept is True
    assert a.chosen is None, "a swept index must not resolve to a single guess"

    w = _walkthrough(REVERSE_MULTI)
    idx = _constant(w, "TABLE_INDEX")
    assert idx is not None
    assert idx.confidence is Confidence.UNKNOWN, (
        f"TABLE_INDEX is {idx.confidence} with value {idx.value!r}; it is swept, "
        "so a stated value is a fabrication"
    )
    assert idx.value is None
    assert idx.unknown_reason and idx.unknown_reason.strip()
    step_ids = {s.id for s in w.steps}
    assert idx.resolved_by in step_ids, (
        f"TABLE_INDEX names {idx.resolved_by!r}, which is not among "
        f"{sorted(step_ids)}"
    )


def test_a_single_candidate_is_DERIVED_not_swept() -> None:
    """The other arm, so the UNKNOWN test above cannot pass vacuously.

    `fini_10`'s `.fini_array` has exactly one entry. There is nothing to sweep,
    the index is 0 by construction, and carrying it as UNKNOWN would be a
    different dishonesty -- refusing to state a value that IS derivable.
    """
    a = fini_array._Analysis(_target(SINGLE_ENTRY))
    assert a.dest.entries == 1, (
        f"premise gone: this target now has {a.dest.entries} entries, so it no "
        "longer exercises the single-candidate arm"
    )
    assert len(a.teachable_entries) == 1
    assert a.index_is_swept is False
    assert a.chosen == (0, -80), f"the single candidate changed: {a.chosen}"

    w = _walkthrough(SINGLE_ENTRY)
    idx = _constant(w, "TABLE_INDEX")
    assert idx is not None and idx.confidence is Confidence.DERIVED
    assert idx.value == 0
    slot = _constant(w, "STORE_INDEX")
    assert slot is not None and slot.value == -80, (
        "the single-candidate arm must state the store index it derived"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_offset_fact_is_not_carried(slug: str) -> None:
    """A measured-but-irrelevant number is the dangerous case.

    Nothing on this route touches a return address, so a buffer-to-RIP offset --
    even a correctly measured one -- invites the reader back to the cyclic-pattern
    framing this family exists to replace.
    """
    assert _constant(_walkthrough(slug), "OFFSET") is None, (
        f"{slug} carries OFFSET on a route that never touches a frame"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_shell_proof_is_arithmetic_the_shell_must_evaluate(slug: str) -> None:
    """A literal token cannot separate 'executed' from 'reflected'.

    It matters here because a wrong entry usually leaves the program exiting
    normally rather than crashing, so the absence of a crash is not evidence of
    anything and a weak proof would look like a working one.

    Two halves. The family's own code must go through the shared `confirm_shell`
    rather than inventing its own literal check -- that is the assertion about
    THIS family. And the rendered artifact must actually contain the arithmetic
    and the check for its answer -- that is the assertion that `confirm_shell`
    still means what the name says, so this cannot pass by the shared helper
    being weakened underneath it.
    """
    w = _walkthrough(slug)
    code = _all_code(w)
    assert "confirm_shell(" in code, (
        f"{slug} does not use the shared arithmetic prover; a bespoke literal "
        "check cannot tell an executed shell from a reflected echo"
    )

    script = render_script(w)
    assert "PWNED_$((6*7))" in script, "the arithmetic marker is gone"
    assert "PWNED_42" in script, "nothing checks for the evaluated answer"
    assert "def confirm_shell(" in script, (
        "confirm_shell is called and never defined in the rendered artifact"
    )
    assert script.index("def confirm_shell(") < script.index("confirm_shell(io"), (
        "confirm_shell is used before it is defined"
    )


def test_the_gate_stays_narrow_across_every_built_elf() -> None:
    """Swept in-test so the denominator cannot drift.

    A gate is only narrow relative to what it was offered, and a number pasted
    into a comment stops being true the moment a corpus family is added.
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
        os.path.basename(p) for p in seen if fini_array._Analysis(p).complete
    )
    assert claimed, (
        "the gate claims nothing at all across the whole tree, so either the "
        "corpus is not built or the gate is broken shut"
    )
    assert set(claimed) == set(POSITIVES), (
        f"the gate claims {claimed} but this family's positives are {POSITIVES}. "
        "An open gate outside the family is not automatically a defect, but it "
        "must be examined rather than absorbed."
    )


def test_the_plan_the_family_explains_is_the_plan_the_executor_flies() -> None:
    """No second opinion. The family must not re-derive the route.

    Two analyses of the same binary that disagree produce a walkthrough naming a
    different route than the tool flies, which is worse than no walkthrough.
    """
    for slug in POSITIVES:
        path = _target(slug)
        plan, _reason = fini.analyse(path)
        a = fini_array._Analysis(path)
        assert plan is not None
        assert a.plan is plan, (
            f"{slug}: the family holds a different plan object than the "
            "executor's cached one"
        )
        assert a.dest is plan.dests[0], (
            f"{slug}: the family teaches a destination other than the one the "
            "executor would try first"
        )
