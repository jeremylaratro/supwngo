"""The allocation-size-overflow walkthrough family, pinned where it matters.

WHY THIS FILE EXISTS
--------------------
`alloc_size_overflow` solves 5/5 on `benchmark/corpus_allocsize` and the
walkthrough layer could explain none of them. MEASURED before this family
existed: with probing, every one of the five fell to `heap` at 0.25 -- the
allocator-characterisation family, which describes what the primitive IS and
claims no route to execution; with `--no-probe`, every one fell to `stack_bof`'s
`ret2win` at 0.75, which sends a reader hunting a buffer-to-return-address offset
for a bug that overflows a HEAP chunk and never touches a frame.

THE BUG IS AN ARITHMETIC DISAGREEMENT, NOT A MISSING CHECK
----------------------------------------------------------
Two sizes come from one input. Exactly one of them wraps. The allocation shrinks,
the transfer length does not, and the copy then runs off the end of a chunk that
is correctly bounded by the number it was handed. The transfer clamp
(`if (want > CAP) want = CAP`) only ever SHORTENS -- it never reconciles the two
numbers -- so it looks like a bounds check and is not one.

WHAT THIS FAMILY GATES THAT THE EXECUTOR DOES NOT
-------------------------------------------------
The executor's static gate opens on all SIX targets in this corpus, INCLUDING the
negative control: `alloc_90_neg_checked_multiply` has the same size expression as
`alloc_14`, so every plan field matches. The executor separates them only by
failing at run time, which a walkthrough cannot do -- it just gets read.

So this family adds a gate the executor lacks: is any reachable wrap left
UNGUARDED? A candidate `C` closes a wrap `W` when `C >= W - 1`, which is what
`alloc_90`'s `cmp rax, 0xfffffffffffffff` does to `W = 2**60` and what
`alloc_12`'s and `alloc_14`'s `cmp ..., 0x10` transfer clamps do not.

Recovering that compare is the part an obvious implementation gets wrong: gcc
emits the 60-bit constant as `movabs rdx, 0xfffffffffffffff` followed by
`cmp rax, rdx`, so an immediate-only scan of `cmp reg, imm` finds nothing and the
gate stays open on the control. That is pinned below.

Every gate here is tested in BOTH halves -- the premise (the shape being tested is
still the shape) and the behaviour -- so a corpus rebuild cannot leave these green
while measuring nothing.
"""

from __future__ import annotations

import ast
import glob
import importlib.util
import os

import pytest

from supwngo.exploit.pipeline.executors import allocsize_techniques as az
from supwngo.exploit.walkthrough.families import alloc_size
from supwngo.exploit.walkthrough.facts import collect_facts
from supwngo.exploit.walkthrough.model import Confidence
from supwngo.exploit.walkthrough.registry import generate_walkthrough, propose_routes
from supwngo.exploit.walkthrough.render import render_script

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

POSITIVES = [
    "alloc_10_mul_wrap_u32",
    "alloc_11_add_wrap_sizemax",
    "alloc_12_signed_count_two_faces",
    "alloc_13_realloc_shrink_wrap",
    "alloc_14_shl_wrap_u64",
]

CONTROL = "alloc_90_neg_checked_multiply"

#: Same size expression as the control, so it is the target the control must be
#: compared against for the decline to mean anything.
CONTROL_TWIN = "alloc_14_shl_wrap_u64"
#: The one whose wrap is NEGATIVE, reached through a 16-bit narrowing, and whose
#: width-based windows are dead ends. The hardest arm to get right.
NARROWED = "alloc_12_signed_count_two_faces"
#: `realloc` shrinks a live block in place, so the distance is 0x70 rather than
#: the 0x30 the four malloc variants share -- which is why DISTANCE is UNKNOWN.
REALLOC = "alloc_13_realloc_shrink_wrap"


def _reference():
    """The independently-authored ground truth for this corpus.

    `benchmark/reference_exploits/allocsize_variants_reference.py` was written
    before the executor and is validated by its own positive/negative controls.
    Cross-checking the taught numbers against it is the strongest assertion
    available here: it is a different author's measurement of the same fact, so
    agreement is evidence rather than a tautology.
    """
    path = os.path.join(
        REPO, "benchmark", "reference_exploits", "allocsize_variants_reference.py"
    )
    if not os.path.isfile(path):
        pytest.skip("the allocsize reference exploit is not present")
    spec = importlib.util.spec_from_file_location("_allocsize_ref", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _target(slug: str) -> str:
    path = os.path.join(REPO, "benchmark", "corpus_allocsize", slug, slug)
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        pytest.skip(f"{slug} not built; run benchmark/build_all.sh")
    return path


def _walkthrough(slug: str):
    """Selection without the live probe, deliberately.

    `probe=False` keeps `stack_bof`'s `ret2win` APPLICABLE at 0.75, which is the
    competitor this family's score exists to beat. Probing makes the competition
    vanish and would make the ordering assertions below easier and emptier.
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
# (a) claimed, completed, and the steps carry the real arithmetic
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_is_claimed_by_this_family(slug: str) -> None:
    w = _walkthrough(slug)
    assert w.family == alloc_size.NAME, (
        f"{slug} is solved by the alloc_size_overflow executor but explain teaches "
        f"{w.family!r}. Measured baseline before this family existed: heap (0.25) "
        "with probing, stack_bof ret2win (0.75) without."
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_completes_and_renders(slug: str) -> None:
    a = alloc_size._Analysis(_target(slug))
    assert a.complete is True, f"{slug}: {a.decline_reason}"
    ast.parse(render_script(_walkthrough(slug)))


def test_it_outranks_the_ret2win_route_it_replaces() -> None:
    """The ordering that justifies 0.84, with the premise asserted.

    Without the `stack_bof in scores` assertion this would stay green after
    `stack_bof` stopped applying, which would be a regression in ITS gate
    reported as a win for this one.
    """
    facts = collect_facts(_target(CONTROL_TWIN), probe=False)
    scores = {
        fam.NAME: route.score
        for fam, route in propose_routes(facts)
        if route is not None and route.applicable
    }
    assert "stack_bof" in scores, (
        "stack_bof no longer applies here, so this test has stopped measuring the "
        "ordering it exists for"
    )
    assert scores[alloc_size.NAME] > scores["stack_bof"]


def test_the_score_is_between_off_by_one_and_fini_array() -> None:
    """The stated ordering, pinned against the named constants.

    Below `fini_array_write` (0.86) and `objptr_hijack` (0.87); above
    `off_by_one_guard` (0.83), whose headline route is probabilistic. Pinned by
    constant rather than literal so a change to either side is caught here.
    """
    from supwngo.exploit.walkthrough.families import (
        fini_array,
        objptr_hijack,
        off_by_one,
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
def test_the_taught_wrap_matches_the_reference_exploit(slug: str) -> None:
    """The assertion that makes the rest worth having.

    A walkthrough that names a wrapping count the target does not actually wrap on
    is followable and wrong, and there is nothing in the artifact to reveal it.
    The reference exploit's `VARIANTS` table is a separate author's measurement of
    the same number, taken from each target's own source; agreeing with it is
    evidence.

    The taught wrap also has to be the FIRST window, because the emitted script
    tries them in order and a reader reads them in order.
    """
    ref = _reference()
    expected = ref.VARIANTS[slug][0]

    a = alloc_size._Analysis(_target(slug))
    assert a.open_wraps, f"{slug}: no unguarded wrap survives the guard gate"
    taught = a.open_wraps[0][0]
    assert taught == expected, (
        f"{slug}: this family teaches wrapping count {taught}, the reference "
        f"exploit uses {expected}. A wrong count is accepted by the target on some "
        "of these variants and transfers nothing, so the script runs and the reader "
        "learns the method does not work."
    )

    w = _walkthrough(slug)
    assert _constant(w, "WRAP_COUNT").value == expected

    # Two halves, because the artifact is where a reader meets the number: it has
    # to be DECLARED as that exact decimal literal (the target's scanf reads
    # decimal, so a hex spelling would be a different number), and the step that
    # sends it has to REFERENCE the constant rather than restating a literal that
    # could drift from it.
    script = render_script(w)
    assert f"WRAP_COUNT = {expected}" in script, (
        f"{slug}: the artifact does not declare WRAP_COUNT as the decimal literal "
        f"{expected}, which is what the target's scanf must receive"
    )
    assert "WRAP_COUNT" in _all_code(w), (
        f"{slug}: WRAP_COUNT is declared and never used, so nothing sends the "
        "wrapping count"
    )


def test_the_narrowing_window_is_taught_before_the_width_windows() -> None:
    """`alloc_12`, and the defect this caught in review.

    MEASURED: `alloc_12`'s count is narrowed to 16 bits BEFORE the multiply, so
    the wrap is -65536 -- negative, and reached through the truncation. An
    earlier version emitted the width-based window (2**60) first, because the
    multiplier-derived windows were generated before the narrowing one.

    2**60 is not merely suboptimal there: the target ACCEPTS it, `scanf("%d")`
    truncates it to 0, and that zeroes the transfer length too -- so the attempt
    is a dead end that produces no error, and the executor burns four probes on
    it. The window list also has to DROP width-based windows whose largest
    post-truncation product cannot reach the span, which is why 2**60 is gone
    rather than merely demoted.
    """
    ref = _reference()
    a = alloc_size._Analysis(_target(NARROWED))

    assert a.site.narrow == 16, (
        f"premise gone: the site no longer narrows ({a.site.narrow!r}), so this "
        "target no longer exercises the truncation arm"
    )
    assert a.site.mults, (
        "premise gone: the site has no multiplier, so there are no width-based "
        "windows for the narrowing one to have to outrank"
    )

    assert a.wrap_windows, "no wrap window at all on the hardest positive"
    assert a.wrap_windows[0][0] == -65536 == ref.VARIANTS[NARROWED][0]
    assert all(wrap < 0 for wrap, _why in a.wrap_windows), (
        f"a width-based window survived alongside the narrowing one: "
        f"{a.wrap_windows}. After a 16-bit truncation the largest product this "
        "arithmetic can reach is far below the span, so those windows are dead "
        "ends the reader would try first."
    )
    assert 1152921504606846976 not in [wrap for wrap, _why in a.wrap_windows], (
        "2**60 is back in the window list; the target accepts it, truncates it to "
        "0, and transfers nothing"
    )

    # The arithmetic argument has to be IN the walkthrough, not only in a comment
    # in the family source: the reader is the one who has to believe it.
    why = " ".join(s.why or "" for s in _walkthrough(NARROWED).steps)
    assert "16" in why and "narrow" in why.lower(), (
        "the walkthrough never explains that the count is narrowed before the "
        "multiply, which is the whole reason the wrap is negative"
    )


def test_the_signed_guard_is_named_where_one_exists() -> None:
    """The second half of `alloc_12`: the guard the negative count PASSES.

    `cmp eax, 0x10` followed by `jle` is a SIGNED comparison, so -65536 satisfies
    it. A reader who reads it as `count <= 16` and stops has found the guard and
    missed the bug. Asserted both ways: present here, absent on a target with no
    signed bound, so this cannot pass by the detector firing everywhere.
    """
    a = alloc_size._Analysis(_target(NARROWED))
    assert a.signed_bound is not None, (
        "premise gone: this target no longer has a signed bound, so the "
        "signed-versus-unsigned lesson has nowhere to live"
    )
    bound, mnemonic = a.signed_bound
    assert (bound, mnemonic) == (16, "jle"), f"the signed bound changed: {a.signed_bound}"
    assert _constant(_walkthrough(NARROWED), "SIGNED_BOUND").value == 16
    assert _constant(_walkthrough(NARROWED), "NARROW_BITS").value == 16

    other = alloc_size._Analysis(_target("alloc_10_mul_wrap_u32"))
    assert other.signed_bound is None, (
        "the signed-bound detector now fires on a target with no signed guard, so "
        "the assertion above no longer distinguishes anything"
    )
    assert _constant(_walkthrough("alloc_10_mul_wrap_u32"), "SIGNED_BOUND") is None


def test_the_menu_options_are_read_from_the_jump_table_not_guessed() -> None:
    """A walkthrough cannot probe, so these had to come out of the image.

    At -O0 gcc compiles the dispatcher's dense `switch` into a jump table with
    4-byte self-relative offsets, NOT an if/else chain. The first derivation here
    -- "the last `cmp` before a `call`" -- returned option 7 for every handler,
    which is coherent, wrong, and produces a script that talks to the wrong menu
    entry.

    MEASURED against the live-probed ground truth on all six targets: identical.
    Asserted as a whole map, because a per-role assertion would pass while the
    roles were permuted.
    """
    expected = {"vec": 2, "record": 1, "fill": 3, "show": 5, "invoke": 6}
    for slug in POSITIVES + [CONTROL]:
        a = alloc_size._Analysis(_target(slug))
        assert a.cases, (
            f"{slug}: no switch cases recovered at all, so the option numbers "
            "cannot have come from the jump table"
        )
        assert a.options == expected, (
            f"{slug}: the recovered option map is {a.options}, expected {expected}"
        )
        assert a.options_are_complete is True


def test_the_prompts_are_read_from_rodata_including_the_shared_helper() -> None:
    """The index prompt lives in a DIFFERENT function than the one that asks.

    `new_vec` does not print `index: ` itself; it calls a shared `ask_index`
    helper. A prompt scan confined to the handler's own body returned only
    `count: `, so the emitted script waited for a prompt that never came and hung
    on the first send. Following one level of direct call into the image's own
    functions is what fixes it, and this pins that the fix is still in place.
    """
    for slug in POSITIVES:
        a = alloc_size._Analysis(_target(slug))
        assert a.prompts_are_complete is True, f"{slug}: prompts incomplete"
        assert a.menu_prompt == b"> ", f"{slug}: menu prompt {a.menu_prompt!r}"
        assert a.index_prompt == b"index: ", (
            f"{slug}: the index prompt is {a.index_prompt!r}. It is printed by a "
            "helper the handler CALLS, so losing it means the call-following was "
            "removed"
        )
        assert a.count_prompt == b"count: "
        assert a.data_prompt == b"data: "

        w = _walkthrough(slug)
        code = _all_code(w)
        for name in ("MENU_PROMPT", "INDEX_PROMPT", "COUNT_PROMPT", "DATA_PROMPT"):
            fact = _constant(w, name)
            assert fact is not None, f"{slug}: {name} is not emitted"
            assert fact.confidence is Confidence.MEASURED, (
                f"{slug}: {name} is {fact.confidence}; it was read out of .rodata"
            )
            assert name in code, (
                f"{slug}: {name} is declared and never used, so nothing waits for "
                "that prompt"
            )


def test_the_transfer_cap_and_the_record_layout_agree_with_the_reference() -> None:
    """Cross-checked against the independently-authored oracle.

    These are the numbers that decide how many bytes the copy can move and where
    the handler pointer sits inside the neighbouring record. Getting the cap wrong
    makes the ladder too short to reach; getting the handler offset wrong writes a
    pointer into the wrong field and the program keeps running.
    """
    ref = _reference()
    for slug in POSITIVES:
        a = alloc_size._Analysis(_target(slug))
        w = _walkthrough(slug)
        assert a.cap == ref.COPYCAP, f"{slug}: cap {a.cap} != {ref.COPYCAP}"
        assert a.record_size == ref.RECORD_SZ
        assert a.neighbour_chunk == ref.JOB_CHUNK
        assert _constant(w, "TRANSFER_CAP").value == ref.COPYCAP
        assert _constant(w, "RECORD_SZ").value == ref.RECORD_SZ
        assert _constant(w, "NEIGHBOUR_CHUNK").value == ref.JOB_CHUNK
        assert _constant(w, "HANDLER_OFF").value == ref.HANDLER_OFF
        assert _constant(w, "BENIGN_COUNT").value == ref.BENIGN


# --------------------------------------------------------------------------
# (b) declines the negative control, naming the missing fact
# --------------------------------------------------------------------------


def test_the_executor_gate_alone_claims_the_negative_control() -> None:
    """The PREMISE for the extra gate. Without this it looks gratuitous.

    If the executor ever starts declining `alloc_90` on its own, this goes red and
    the guard gate can be reconsidered -- which is the intent. It must not be
    weakened into "the family declines it", because that is a different test.
    """
    gate, reason = az.analyse(_target(CONTROL))
    assert gate is not None, (
        f"az.analyse now declines the control on its own ({reason!r}). The guard "
        "gate in this family exists precisely because it did NOT -- re-examine "
        "whether it is still needed rather than deleting this test."
    )


def test_the_control_is_plan_identical_to_its_twin() -> None:
    """The discrimination no plan field can make, so the premise IS the test.

    `alloc_90` and `alloc_14` compute the same size the same way. Every field the
    executor records matches. The difference is one source line -- a checked
    multiply -- which gcc emits as a compare, and a compare is not a plan field.
    """
    ctl = alloc_size._Analysis(_target(CONTROL))
    pos = alloc_size._Analysis(_target(CONTROL_TWIN))
    assert ctl.site is not None and pos.site is not None

    assert (ctl.site.width, ctl.site.mults, ctl.site.addends, ctl.site.narrow) == (
        pos.site.width,
        pos.site.mults,
        pos.site.addends,
        pos.site.narrow,
    ), (
        "premise gone: the control's size site now differs from its twin's, so "
        "this no longer tests a discriminator that plan fields cannot make"
    )
    assert ctl.wrap_windows == pos.wrap_windows, (
        f"premise gone: the derived wrap windows now differ -- ctl "
        f"{ctl.wrap_windows} vs pos {pos.wrap_windows}"
    )
    assert (ctl.cap, ctl.record_size, ctl.options) == (
        pos.cap,
        pos.record_size,
        pos.options,
    )

    # ...and the family separates them anyway.
    assert pos.complete is True
    assert ctl.complete is False


def test_the_control_is_declined_and_the_reason_names_the_compare() -> None:
    """The decline must name the compare, its value, and the wrap it closes.

    "No unguarded wrap" would be true and useless. What a reader needs is WHICH
    constant blocks WHICH wrap, because that is the thing to go look at, and
    because the numbers are the evidence that the gate did the arithmetic rather
    than pattern-matching a `cmp`.
    """
    path = _target(CONTROL)
    a = alloc_size._Analysis(path)
    assert a.complete is False
    assert a.open_wraps == (), f"the control has an unguarded wrap: {a.open_wraps}"
    assert a.blocked_wraps, (
        "the control declines with no blocked wrap recorded, so the reason cannot "
        "name what closed the gate"
    )
    wrap, closer = a.blocked_wraps[0]
    assert (wrap, closer) == (1152921504606846976, 0xFFFFFFFFFFFFFFF), (
        f"the blocked pair changed: wrap={wrap} closer={closer:#x}"
    )

    reason = a.decline_reason
    assert str(wrap) in reason, f"the decline does not name the wrap: {reason!r}"
    assert str(closer) in reason or hex(closer) in reason, (
        f"the decline does not name the constant that closes it: {reason!r}"
    )
    assert "checked" in reason or "BEFORE" in reason, (
        f"the decline does not say the multiply is checked before it is performed: "
        f"{reason!r}"
    )

    route = alloc_size.propose(collect_facts(path, probe=False))
    assert route is not None and route.applicable is False
    assert reason in route.rationale
    assert route.becomes_viable_if and route.becomes_viable_if.strip()
    assert route.rejection is not None


def test_the_control_is_not_taught_this_route() -> None:
    w = _walkthrough(CONTROL)
    assert w.family != alloc_size.NAME, (
        f"{CONTROL} is a NEGATIVE CONTROL -- the pipeline does not solve it -- and "
        "explain teaches the wrap route anyway"
    )


def test_the_guard_scan_sees_a_movabs_loaded_constant() -> None:
    """The defect an obvious implementation ships, pinned directly.

    gcc cannot encode 0xfffffffffffffff as a `cmp` immediate, so it emits
    `movabs rdx, 0xfffffffffffffff` then `cmp rax, rdx`. An immediate-only scan of
    `cmp reg, imm` therefore finds nothing on the control, the gate stays open, and
    the family teaches the wrap route for a target that refuses it.

    Asserted structurally: the blocking constant must be in `compared_immediates`
    AND must not be present as a `cmp reg, <imm>` immediate anywhere in the
    disassembly, so the only way it can be there is via the register form.
    """
    import re
    import subprocess

    path = _target(CONTROL)
    a = alloc_size._Analysis(path)
    assert 0xFFFFFFFFFFFFFFF in a.compared_immediates, (
        f"the 60-bit guard constant is missing from {[hex(c) for c in a.compared_immediates]}; "
        "the scan is immediate-only again and the gate will stay open on the control"
    )

    disasm = subprocess.run(
        ["objdump", "-d", "-M", "intel", "--no-show-raw-insn", path],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert re.search(r"movabs\s+\w+,0xfffffffffffffff\b", disasm), (
        "premise gone: this target no longer loads the guard constant with movabs, "
        "so an immediate-only scan would find it and this test proves nothing"
    )
    assert not re.search(r"cmp\s+\w+,0xfffffffffffffff\b", disasm), (
        "premise gone: the constant now appears as a cmp immediate too, so the "
        "register-form scan is no longer load-bearing"
    )


def test_a_transfer_clamp_is_not_mistaken_for_an_overflow_check() -> None:
    """The floor that keeps the gate from closing on the positives.

    `alloc_12` and `alloc_14` both compare against 0x10. If "any compare closes
    any wrap" were the rule, those clamps would close their wraps and this family
    would decline two of its own positives. The `C >= W - 1` floor is what stops
    that, and this asserts both the premise (the small compare IS there) and the
    behaviour (it closes nothing).
    """
    for slug in (NARROWED, CONTROL_TWIN):
        a = alloc_size._Analysis(_target(slug))
        assert 0x10 in a.compared_immediates, (
            f"premise gone: {slug} no longer compares against 0x10, so it no "
            "longer exercises the small-compare case"
        )
        assert a.open_wraps, (
            f"{slug}: a transfer clamp compared against 0x10 was treated as an "
            "overflow check and closed this target's wrap -- the C >= W - 1 floor "
            "is gone"
        )
        assert a.blocked_wraps == (), (
            f"{slug}: {a.blocked_wraps} was recorded as blocked on a positive"
        )


def test_the_decline_reasons_differ_per_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """`I-29`, answered rather than repeated.

    The failure mode is handing every decline the FIRST gate's explanation, so a
    binary whose allocations are all constant-sized gets a guard-flavoured refusal
    and the reader goes looking for a compare that is not the problem.

    Built from the family's own branches, because the corpus has one control and
    cannot exhibit every shape. Each case keeps everything else real.
    """
    reasons: dict[str, str] = {}

    # Gate: an unguarded wrap exists but every wrap is closed (the real control).
    reasons["guarded"] = alloc_size._Analysis(_target(CONTROL)).decline_reason

    # Gate: no size site is computed at all -- every allocation is a constant.
    # `gate.computed` is a PROPERTY that filters `gate.sites` on each call, so
    # clearing the list it returns changes nothing; the kind has to be rewritten
    # on the sites themselves. WRONG-but-present rather than absent: each site
    # stays real and only its classification moves.
    no_site = alloc_size._Analysis(_target(CONTROL_TWIN))
    originals = [(site, site.kind) for site in no_site.gate.sites]
    assert any(kind == "computed" for _site, kind in originals), (
        "premise gone: this target has no computed site to reclassify"
    )
    try:
        for site, _kind in originals:
            site.kind = "immediate"
        assert no_site.site is None, (
            "reclassifying every site left one computed, so the branch under test "
            "was not reached"
        )
        reasons["constant-sizes"] = no_site.decline_reason
    finally:
        for site, kind in originals:
            site.kind = kind
    assert alloc_size._Analysis(_target(CONTROL_TWIN)).complete is True, (
        "the reclassification was not restored, which would poison every later test"
    )

    # Gate: no destination to hijack.
    #
    # `win_offset` is a PROPERTY, which is a data descriptor -- assigning into the
    # instance `__dict__` does not shadow it and the mutation silently does
    # nothing, leaving a green test that exercised the wrong branch. Patching the
    # class is the only way to reach this arm, and monkeypatch restores it.
    monkeypatch.setattr(
        alloc_size._Analysis, "win_offset", property(lambda _self: None)
    )
    no_win = alloc_size._Analysis(_target(CONTROL_TWIN))
    assert no_win.win_offset is None, "the class patch did not take effect"
    assert no_win.complete is False, (
        "a target with no destination was still claimed complete"
    )
    reasons["no-win"] = no_win.decline_reason
    monkeypatch.undo()
    assert alloc_size._Analysis(_target(CONTROL_TWIN)).win_offset is not None, (
        "the patch was not undone, which would poison every later test"
    )

    assert len(set(reasons.values())) == 3, (
        f"two gates give the same explanation: {reasons}"
    )
    assert "compile-time-constant" in reasons["constant-sizes"]
    assert "checked" in reasons["guarded"]
    assert len(reasons["no-win"]) > 20


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
def test_the_distance_is_UNKNOWN_and_measured_at_run_time(slug: str) -> None:
    """The one number that cannot come out of the image, and is not invented.

    MEASURED: four of the five variants put the neighbouring record 0x30 bytes
    away; `alloc_13` puts it at 0x70, because `realloc` shrinks the live block IN
    PLACE, returns the same pointer, and frees the 0x40 remainder into tcache.
    So the commonest value is 0x30 and stating it would be right four times out of
    five and silently wrong on the fifth -- which is exactly the shape of a
    fabricated constant.
    """
    w = _walkthrough(slug)
    dist = _constant(w, "DISTANCE")
    assert dist is not None
    assert dist.confidence is Confidence.UNKNOWN, (
        f"{slug}: DISTANCE is {dist.confidence} with value {dist.value!r}. The "
        "heap layout is not in the image; a stated value is a guess that is wrong "
        "on alloc_13."
    )
    assert dist.value is None
    assert dist.unknown_reason and dist.unknown_reason.strip()
    assert dist.plausible and dist.plausible.strip(), (
        "an UNKNOWN with no plausible range gives the reader nothing to start from"
    )
    step_ids = {s.id for s in w.steps}
    assert dist.resolved_by in step_ids, (
        f"{slug}: DISTANCE names {dist.resolved_by!r}, not among {sorted(step_ids)}"
    )
    resolver = next(s for s in w.steps if s.id == dist.resolved_by)
    assert resolver.produces, (
        "the step that resolves DISTANCE produces nothing, so it measures nothing"
    )


def test_the_realloc_variant_is_the_reason_distance_cannot_be_stated() -> None:
    """The premise for the test above, from the reference exploit's own table.

    If every variant ever had the same distance, carrying DISTANCE as UNKNOWN
    would be over-caution rather than honesty. This asserts the disagreement is
    real and still present.
    """
    ref = _reference()
    distances = {slug: ref.VARIANTS[slug][1] for slug in POSITIVES}
    assert len(set(distances.values())) > 1, (
        f"every variant now has the same distance {distances}, so DISTANCE could "
        "be derived and carrying it as UNKNOWN is no longer justified"
    )
    assert distances[REALLOC] != distances[CONTROL_TWIN], (
        f"the realloc variant no longer disagrees: {distances}"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_the_offset_fact_is_not_carried(slug: str) -> None:
    """A measured-but-irrelevant number is the dangerous case.

    This overflow runs off the end of a heap chunk. A buffer-to-return-address
    offset -- even a correct one -- invites the reader back to the cyclic-pattern
    framing that `ret2win` was going to teach them.
    """
    assert _constant(_walkthrough(slug), "OFFSET") is None, (
        f"{slug} carries OFFSET on a route that never touches a frame"
    )


@pytest.mark.parametrize("slug", POSITIVES)
def test_no_helper_is_defined_inside_one_step_and_called_from_another(
    slug: str,
) -> None:
    """The dead-code defect, stated precisely instead of by whitelist.

    A helper defined inside a step's own function body is invisible from every
    other step and from `exploit()`. `ast.parse` accepts it happily -- it is a
    NameError at run time, in the artifact a reader is most likely to run whole.

    The shape is checked structurally rather than by comparing called names
    against a list of builtins: every nested `def` is found, and its name is then
    looked for OUTSIDE the function that contains it. That reports the actual
    defect and cannot go green by a name being added to a whitelist.
    """
    script = render_script(_walkthrough(slug))
    tree = ast.parse(script)

    top_level = {
        node.name for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    offenders: list[tuple[str, str]] = []
    for outer in [n for n in tree.body if isinstance(n, ast.FunctionDef)]:
        nested = {
            inner.name
            for child in outer.body
            for inner in ast.walk(child)
            if isinstance(inner, ast.FunctionDef)
        }
        for name in nested - top_level:
            # Calls to this name anywhere OUTSIDE the function that defines it.
            for other in [n for n in tree.body if isinstance(n, ast.FunctionDef)]:
                if other is outer:
                    continue
                for node in ast.walk(other):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == name
                    ):
                        offenders.append((name, other.name))

    assert not offenders, (
        f"{slug}: {offenders} -- each of these helpers is defined inside one "
        "step's body and called from a different function, which is a NameError "
        "the moment that other function runs."
    )

    # The premise: the artifact really does define module-level helpers, so the
    # scan above has something to be right about.
    assert top_level, f"{slug}: the rendered script defines no functions at all"


def test_the_gate_stays_narrow_across_every_built_elf() -> None:
    """Swept in-test so the denominator cannot drift.

    MEASURED and stated honestly: this gate opens on all six targets in its own
    corpus INCLUDING the control -- that is the whole reason the guard gate exists
    -- and the assertion is therefore on what the family CLAIMS (`complete`), not
    on what the executor's gate admits.
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
        os.path.basename(p) for p in seen if alloc_size._Analysis(p).complete
    )
    assert claimed, (
        "the family claims nothing at all across the whole tree, so either the "
        "corpus is not built or a gate is broken shut"
    )
    assert set(claimed) == set(POSITIVES), (
        f"the family claims {claimed}; its positives are {POSITIVES}"
    )


def test_the_plan_the_family_explains_is_the_plan_the_executor_flies() -> None:
    """No second opinion: the family must not re-derive the route."""
    for slug in POSITIVES + [CONTROL]:
        path = _target(slug)
        gate, _reason = az.analyse(path)
        a = alloc_size._Analysis(path)
        assert gate is not None
        assert a.gate is gate, (
            f"{slug}: the family holds a different gate object than the executor's "
            "cached one"
        )
