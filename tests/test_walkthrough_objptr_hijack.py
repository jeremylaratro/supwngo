"""The indirect-call-hijack walkthrough family, pinned where it actually matters.

WHY THIS FILE EXISTS
--------------------
`objptr_hijack` is the executor that solves HTB `auth-or-out` -- the seventh and
last HTB target -- plus 10/10 on `benchmark/corpus_objptr` and 6/6 on
`benchmark/corpus_objptr_libc`. Before this family existed, `explain` taught
`rop_chain` at 0.6 on the real target and `triage` on most of the corpus. On
`fnptr_11_stack_struct` it taught **`stack_bof` at 0.75** -- MEASURED, not
assumed -- which is the worst of the three: that route sends the reader hunting a
buffer-to-return-address offset with a cyclic pattern, on a canaried frame where
every wrong length produces the identical abort, for a bug that never touches a
return address at all.

WHAT THIS FAMILY DOES THAT THE EXECUTOR DOES NOT
------------------------------------------------
It DECLINES more. `build_plan()` returns a plan for both negative controls in
this family's own corpus, and so does the executor's `is_applicable()` -- they
decline those targets only by failing at runtime. A walkthrough cannot fail at
runtime; it just gets read. So this family adds two gates the executor lacks,
and the tests below pin BOTH halves of each: that the control really is
plan-identical to its positive (the premise), and that the family declines it
anyway (the behaviour). Without the premise half, a corpus rebuild that changed
the controls would leave these tests green while measuring nothing.

Every test states which of three things it pins:
  (a) the family is selected where the pipeline solves,
  (b) the family DECLINES where the route does not exist,
  (c) the artifact is usable, and models its own uncertainty honestly.
"""

from __future__ import annotations

import ast
import glob
import os

import pytest

from supwngo.core.binary import Binary
from supwngo.exploit.pipeline.executors import objptr_hijack_techniques as oph
from supwngo.exploit.walkthrough.families import objptr_hijack
from supwngo.exploit.walkthrough.model import Confidence
from supwngo.exploit.walkthrough.registry import propose_routes, walkthrough_for_binary
from supwngo.exploit.walkthrough.render import render_script
from supwngo.exploit.walkthrough.facts import collect_facts

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: 17 positives across three groups, one group per plan shape family.
POSITIVES = [
    # single_read / table_index -- no allocator, no libc
    "fnptr_10_heap_struct_baseline",
    "fnptr_11_stack_struct",
    "fnptr_12_bss_struct",
    "fnptr_13_unchecked_table_index",
    "fnptr_14_no_win_function",
    # menu / menu_leak -- a record manager and size arithmetic that wraps
    "objptr_20_add_wrap_local_arena",
    "objptr_21_align_wrap_bss_arena",
    "objptr_22_int_truncation_local_arena",
    "objptr_23_mul_overflow_bss_arena",
    "objptr_25_pie_leak_first",
    # menu_libc -- NO destination in the image at all
    "reclibc_30_anchor_jumptable",
    "reclibc_31_ifchain_menu",
    "reclibc_32_table_call_site",
    "reclibc_33_wide_members",
    "reclibc_34_align_wrap",
    "reclibc_35_leak_first_member",
]

CONTROLS = [
    "fnptr_90_neg_bounded_read",
    "objptr_91_neg_size_check",
    "reclibc_90_neg_bounded_leak",
    "reclibc_91_neg_no_libc_slot",
    "reclibc_92_neg_no_delete",
]

TABLE_SHAPE = "fnptr_13_unchecked_table_index"
LIBC_SHAPE = "reclibc_30_anchor_jumptable"
WIN_SHAPE = "fnptr_10_heap_struct_baseline"
#: The target whose frame yields a REAL buffer-to-RIP offset, so the OFFSET fact
#: arrives MEASURED rather than UNKNOWN. Measured, and the reason the drop is by
#: name rather than by the unresolved-step filter.
MEASURED_OFFSET_TARGET = "fnptr_11_stack_struct"


def _target(slug: str) -> str:
    for group in ("corpus_objptr", "corpus_objptr_libc"):
        path = os.path.join(REPO, "benchmark", group, slug, slug)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    pytest.skip(f"{slug} not built; run benchmark/build_all.sh")


def _real() -> str:
    """HTB `auth-or-out`, found by search rather than a pinned UUID path."""
    hits = [
        p
        for p in glob.glob(
            os.path.join(REPO, "tests", "htb-targets", "*", "*", "auth-or-out")
        )
        if os.path.isfile(p)
    ]
    if not hits:
        pytest.skip("HTB auth-or-out not present in tests/htb-targets/")
    return hits[0]


def _constant(w, name):
    return next((c for c in w.constants if c.name == name), None)


def _all_code(w) -> str:
    return "\n".join(step.code for step in w.steps) + "\n" + (w.final_exploit or "")


# --------------------------------------------------------------------------
# (a) selected where the pipeline solves
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_every_positive_is_taught_by_this_family(slug: str) -> None:
    w = walkthrough_for_binary(_target(slug))
    assert w.family == objptr_hijack.NAME, (
        f"{slug} is solved by the objptr_hijack executor but explain teaches "
        f"{w.family!r}. A walkthrough naming a different route than the one the "
        "tool flies is worse than none."
    )


def test_the_real_target_agrees_with_the_pipeline() -> None:
    """The assertion the corpus cannot make.

    HTB `auth-or-out` is the target this whole category exists for: measured 3/3
    reps SHELL_ACCESS via `objptr_hijack` at 23.4-35.1 s.
    """
    w = walkthrough_for_binary(_real())
    assert w.family == objptr_hijack.NAME, (
        f"HTB auth-or-out is solved by objptr_hijack but explain teaches {w.family!r}."
    )


def test_this_family_outranks_every_other_applicable_route_on_the_real_target() -> None:
    """Pins the REASON, not just the outcome.

    Without the second assertion this could stay green because every competitor
    stopped applying -- which would be a regression in THEIR gates dressed up as
    a win for this one. Measured on auth-or-out: rop_chain 0.6 and triage 0.15
    both still apply.
    """
    facts = collect_facts(_real())
    applicable = {
        getattr(fam, "NAME", "?"): route.score
        for fam, route in propose_routes(facts)
        if route is not None and route.applicable
    }
    assert "objptr_hijack" in applicable
    others = {k: v for k, v in applicable.items() if k != "objptr_hijack"}
    assert others, (
        "no other family applies to auth-or-out any more, so this test no longer "
        "measures an ordering. Re-establish a competitor or delete the test -- do "
        "not let it pass vacuously"
    )
    assert applicable["objptr_hijack"] > max(others.values()), (
        f"objptr_hijack at {applicable['objptr_hijack']} does not outrank {others}"
    )


def test_it_outranks_stack_bof_where_stack_bof_also_applies() -> None:
    """The measured case that justifies the score, not the asserted one.

    `fnptr_11_stack_struct` is the target where `stack_bof` genuinely applies at
    0.75 alongside this family. That competitor teaches the cyclic-pattern offset
    hunt on a canaried frame, so it is followable and wrong; being ABOVE it is the
    whole argument for 0.87. Asserting stack_bof still applies is what keeps this
    from going vacuous.
    """
    facts = collect_facts(_target(MEASURED_OFFSET_TARGET))
    scores = {
        getattr(fam, "NAME", "?"): route.score
        for fam, route in propose_routes(facts)
        if route is not None and route.applicable
    }
    assert "stack_bof" in scores, (
        "stack_bof no longer applies to fnptr_11_stack_struct, so this test stopped "
        "measuring the ordering it exists for"
    )
    assert scores["objptr_hijack"] > scores["stack_bof"]


def test_the_score_stays_below_scanf_scalar() -> None:
    """The upper bound that MATTERS, found by the gate sweep rather than by design.

    This family's gate legitimately opens on three `corpus_scanf` positives --
    `scanf_10_fnptr_struct` and friends genuinely do call through a struct member
    -- but those targets are solved by `scanf_scalar_overwrite`, not by
    `objptr_hijack`. So 0.87 has to stay under scanf_scalar's 0.93 or this family
    would take three targets whose route it would then describe wrongly.

    Pinned against the named constant rather than a literal so a change to either
    score is caught here. `stack_bof` has no named constant (it passes 0.75
    inline), so its side of the ordering is pinned live by
    `test_it_outranks_stack_bof_where_stack_bof_also_applies` instead.
    """
    from supwngo.exploit.walkthrough.families import heap_strlen, scanf_scalar

    assert (
        objptr_hijack.SCORE_OVERWRITE_THE_POINTER < scanf_scalar.SCORE_LEAK_THEN_WRITE
    ), (
        f"objptr={objptr_hijack.SCORE_OVERWRITE_THE_POINTER} would outrank "
        f"scanf_scalar={scanf_scalar.SCORE_LEAK_THEN_WRITE} on the three scanf "
        "targets where both gates open"
    )
    assert (
        objptr_hijack.SCORE_OVERWRITE_THE_POINTER < heap_strlen.SCORE_FORGE_AND_OVERLAP
    ), "the stated ordering below heap_strlen_ofb1 no longer holds"


# --------------------------------------------------------------------------
# (b) declines where the route does not exist
# --------------------------------------------------------------------------


def test_build_plan_alone_claims_both_negative_controls() -> None:
    """The PREMISE for the two extra gates. Without this they look gratuitous.

    If a future executor change starts declining these itself, this test goes red
    and the gates can be reconsidered -- which is the intent. It must not be
    weakened to "the family declines them", because that is the other test.
    """
    for slug in ("fnptr_90_neg_bounded_read", "objptr_91_neg_size_check"):
        plan, reason = oph.build_plan(Binary.load(_target(slug)), None)
        assert plan is not None, (
            f"build_plan now declines {slug} on its own ({reason!r}). The two extra "
            "gates in this family exist precisely because it did NOT -- re-examine "
            "whether they are still needed rather than deleting this test"
        )


def test_the_bounded_read_control_is_declined_and_the_reason_names_the_bound() -> None:
    """Both halves: the read really is short, and that is what closes the gate."""
    a = objptr_hijack._Analysis(_target("fnptr_90_neg_bounded_read"))
    assert a.plan is not None
    assert a.plan.read_len is not None and a.plan.read_len <= a.distance, (
        f"premise gone: read_len={a.plan.read_len} distance={a.distance}. This "
        "target no longer exercises the short-read path; find another rather than "
        "deleting the test"
    )
    assert a.reach_is_possible is False
    assert a.complete is False
    reason = a.decline_reason
    assert "bounded" in reason and hex(a.plan.read_len) in reason, (
        f"the decline reason does not name the read bound: {reason!r}. `I-29` is the "
        "logged defect of handing every decline the FIRST gate's explanation"
    )


def test_the_size_check_control_is_declined_though_its_plan_is_identical() -> None:
    """The control `build_plan` cannot separate -- so the premise is the test.

    Every plan field here matches `objptr_20_add_wrap_local_arena` except the site
    address. The repair is one source line, `if (sz + 1 < sz) reject`, which gcc
    emits as a compare against the wrapping value itself.
    """
    ctl = objptr_hijack._Analysis(_target("objptr_91_neg_size_check"))
    pos = objptr_hijack._Analysis(_target("objptr_20_add_wrap_local_arena"))
    assert ctl.plan is not None and pos.plan is not None

    assert (ctl.plan.shape, ctl.plan.wrap_sizes, ctl.plan.copy_cap) == (
        pos.plan.shape,
        pos.plan.wrap_sizes,
        pos.plan.copy_cap,
    ), (
        "premise gone: the control's plan now differs from its positive's, so this "
        "no longer tests a discriminator that plan fields cannot make"
    )
    assert ctl.distance == pos.distance

    assert pos.wrap_is_available is True, "the positive's wrap must stay available"
    assert ctl.wrap_is_available is False
    assert ctl.complete is False
    assert "wrapping window" in ctl.decline_reason


@pytest.mark.parametrize("slug", CONTROLS)
def test_every_control_falls_back_to_triage(slug: str) -> None:
    w = walkthrough_for_binary(_target(slug))
    assert w.family != objptr_hijack.NAME, (
        f"{slug} is a NEGATIVE CONTROL -- the pipeline does not solve it -- but "
        "explain teaches the hijack route anyway"
    )


def test_the_decline_reasons_are_distinct_per_gate() -> None:
    """`I-29`, answered rather than repeated.

    `env_path_techniques.analyse()` hands 81 of 82 non-family targets the same
    first-gate heap reason, so a binary with no heap gets a heap-flavoured
    refusal. Three gates here means three reasons, and this asserts they differ.
    """
    reasons = {
        slug: objptr_hijack._Analysis(_target(slug)).decline_reason
        for slug in ("fnptr_90_neg_bounded_read", "objptr_91_neg_size_check",
                     "reclibc_91_neg_no_libc_slot")
    }
    assert len(set(reasons.values())) == 3, (
        f"two gates give the same explanation: {reasons}"
    )
    assert "bounded" in reasons["fnptr_90_neg_bounded_read"]
    assert "wrapping window" in reasons["objptr_91_neg_size_check"]
    assert "libc" in reasons["reclibc_91_neg_no_libc_slot"]


def a_decline(path: str) -> str:
    """The gate's own sentence, so a test can assert the Route carries it."""
    return objptr_hijack._Analysis(path).decline_reason


def test_declining_also_EXPLAINS_itself_without_raising() -> None:
    """The gap that shipped a `TypeError` into the not-applicable path.

    This suite proved the gate CLOSES on every control by asserting
    `_Analysis.complete is False`, and never once called `propose()` -- so it
    never built the `Route` that carries the explanation. `_becomes_viable_if`
    formatted `plan.read_len` unconditionally, and that value is None on the whole
    scanf-width arm of the reach gate, so `propose()` raised `TypeError` on
    `scanf_90_neg_bounded`. `decline_reason` had always handled both arms; the
    sibling function had not, and nothing here compared them.

    Found by `test_walkthrough_render_all.py`, which selects for real. That is the
    `I-23` class again: selection and scoring never touch the thing that breaks.
    """
    from supwngo.exploit.walkthrough.facts import collect_facts as _collect

    targets = [_target(slug) for slug in CONTROLS]
    scanf_ctl = os.path.join(REPO, "benchmark", "corpus_scanf",
                             "scanf_90_neg_bounded", "scanf_90_neg_bounded")
    if os.path.isfile(scanf_ctl):
        targets.append(scanf_ctl)

    for path in targets:
        name = os.path.basename(path)
        facts = _collect(path, probe=False)
        route = objptr_hijack.propose(facts)          # must not raise
        assert route is not None, f"{name}: no route object at all"
        assert route.applicable is False, (
            f"{name} is a NEGATIVE CONTROL and this family claims it"
        )
        # The reason and the remedy are separate strings built by separate
        # functions, and the bug was in the second one. Assert BOTH are real.
        assert route.rejection is not None, f"{name}: declined with no rejection kind"
        assert a_decline(path) in route.rationale, (
            f"{name}: the rationale does not carry this gate's own reason"
        )
        assert route.becomes_viable_if and route.becomes_viable_if.strip(), (
            f"{name}: declined with no statement of what would reopen it"
        )


def test_the_gate_stays_narrow() -> None:
    """Swept in-test over every built ELF, so the denominator cannot drift.

    A gate is only narrow relative to what it was offered. Counting inside the
    test means a new corpus family grows the denominator automatically instead of
    silently invalidating a number pasted into a comment.
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

    claimed = [p for p in seen if objptr_hijack._Analysis(p).complete]
    expected = set(POSITIVES) | {"auth-or-out"}
    outside = sorted(p for p in claimed if os.path.basename(p) not in expected)

    # An open gate outside the family is not automatically a defect, and pretending
    # otherwise would have forced a wrong fix. MEASURED: the gate legitimately
    # opens on three `corpus_scanf` positives, because `scanf_10_fnptr_struct` and
    # its siblings really do call through a struct member -- the shape is there.
    # What must not happen is WINNING them, because the pipeline solves them with
    # `scanf_scalar_overwrite` and this family would describe the wrong route.
    #
    # So the assertion is on selection, not on the gate. It runs full selection
    # only on the few targets the gate claimed outside the family, which is what
    # keeps this affordable: full selection over all 116 would take hours.
    for path in outside:
        winner = walkthrough_for_binary(path).family
        assert winner != objptr_hijack.NAME, (
            f"{os.path.basename(path)} is outside this family and objptr_hijack "
            f"WON it across a {len(seen)}-ELF sweep. Either its score is too high "
            "or a gate is too loose -- a walkthrough here would teach a route the "
            "pipeline does not fly."
        )

    # The negative control in that neighbouring family is called out separately,
    # because it is the case that actually went wrong: `scanf_90_neg_bounded` is
    # plan-identical to `scanf_10_fnptr_struct` and differs only by carrying
    # `%31s` where the positive has a bare `%s`. Before the scanf-width arm of the
    # reach gate existed, this family WON that control at 0.87.
    ctl = os.path.join(REPO, "benchmark", "corpus_scanf",
                       "scanf_90_neg_bounded", "scanf_90_neg_bounded")
    if os.path.isfile(ctl):
        a = objptr_hijack._Analysis(ctl)
        assert a.plan is not None, (
            "premise gone: build_plan no longer finds a site in scanf_90_neg_bounded, "
            "so it no longer exercises the format-width arm of the reach gate"
        )
        assert a.complete is False, (
            "the gate claims scanf_90_neg_bounded, a NEGATIVE CONTROL whose scanf "
            "field width stops one byte short of the pointer"
        )


# --------------------------------------------------------------------------
# (c) the artifact is honest and usable
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", [WIN_SHAPE, TABLE_SHAPE, "objptr_20_add_wrap_local_arena",
                                 "objptr_25_pie_leak_first", LIBC_SHAPE])
def test_the_walkthrough_renders_and_is_valid_python(slug: str) -> None:
    """One per shape. `I-23`: three families once shipped unable to render while
    the suite was green, because selection and scoring never touch the renderer.

    This caught two real defects in this family: a `log.failure('...` string split
    across three physical lines in the libc branch, and the shell-proof block
    landing after the table branch's `return`.
    """
    ast.parse(render_script(walkthrough_for_binary(_target(slug))))


def test_the_real_target_renders_and_is_valid_python() -> None:
    ast.parse(render_script(walkthrough_for_binary(_real())))


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


def test_the_offset_fact_is_dropped_even_when_it_was_measured() -> None:
    """The dangerous case: a TRUE number that is irrelevant here.

    On `fnptr_11_stack_struct` the probe measures a real buffer-to-RIP offset, so
    the unresolved-step filter would KEEP it -- nothing about it looks wrong. It
    still has to go: carrying it invites the reader back to the cyclic-pattern
    framing, and on this canaried frame that hunt reports the first length that
    trips the canary as if it were the answer.

    Asserts the premise first, or a build that stopped measuring an offset would
    make this pass while testing nothing.
    """
    facts = collect_facts(_target(MEASURED_OFFSET_TARGET))
    base = {c.name: c for c in __import__(
        "supwngo.exploit.walkthrough.common", fromlist=["x"]
    ).base_constants(facts)}
    assert "OFFSET" in base, "premise gone: base_constants no longer yields OFFSET"
    assert base["OFFSET"].confidence is not Confidence.UNKNOWN, (
        "premise gone: OFFSET is UNKNOWN on this target now, so the unresolved-step "
        "filter would drop it anyway and this test no longer pins the by-name drop"
    )

    w = walkthrough_for_binary(_target(MEASURED_OFFSET_TARGET))
    assert _constant(w, "OFFSET") is None, (
        "OFFSET is carried on a route that never touches a return address"
    )


def test_the_member_distance_is_derived_from_the_two_folds() -> None:
    """Not swept, and labelled as the derivation it is."""
    w = walkthrough_for_binary(_target(WIN_SHAPE))
    dist = _constant(w, "MEMBER_DISTANCE")
    assert dist is not None
    assert dist.confidence is Confidence.DERIVED, (
        f"MEMBER_DISTANCE is {dist.confidence}; it is computed from two recovered "
        "member offsets, which is DERIVED, not MEASURED"
    )
    a = objptr_hijack._Analysis(_target(WIN_SHAPE))
    site = a.plan.site
    assert dist.value == (
        site.delta if site.delta is not None else site.ptr_fold - site.arg_fold
    )


def test_the_table_shape_does_not_teach_a_zero_length_payload() -> None:
    """The defect rendering all five shapes caught.

    A table site has `delta is None` and `ptr_fold - arg_fold == 0`, so the
    member-distance framing produces `b"A" * 0` -- a payload that renders, parses,
    and teaches nothing. Asserts the premise (the distance really is 0) so this
    cannot pass by the geometry changing.
    """
    a = objptr_hijack._Analysis(_target(TABLE_SHAPE))
    assert a.is_table is True
    assert a.distance == 0, (
        f"premise gone: the table site now reports distance {a.distance}, so it no "
        "longer exercises the zero-distance path"
    )

    w = walkthrough_for_binary(_target(TABLE_SHAPE))
    assert _constant(w, "MEMBER_DISTANCE") is None, (
        "the table shape carries MEMBER_DISTANCE, which is 0 here and means "
        "'write nothing'"
    )
    for name in ("TABLE_SCALE", "TABLE_BIAS", "TABLE_INDEX"):
        assert _constant(w, name) is not None, f"the table shape lacks {name}"

    code = _all_code(w)
    assert 'b"A" * 0x0' not in code and 'b"A" * 0 ' not in code, (
        "a zero-length filler survived into the emitted code"
    )


def test_a_table_call_site_inside_a_menu_route_follows_the_menu() -> None:
    """The case where the site flag and the route disagree.

    `reclibc_32_table_call_site` reads its function pointer out of a table -- so
    `site.is_table` is True -- but its SHAPE is `menu_libc`, and the executor
    dispatches on shape: `_rungs_table_index` is reached only for
    `shape == "table_index"`. Keying this family on the site flag made it teach a
    fresh-process index sweep for a target whose route needs a live menu session,
    throwing away the menu state between attempts.

    Asserts the premise (the flag really is True) so this cannot pass by the
    executor stopping to set it.
    """
    a = objptr_hijack._Analysis(_target("reclibc_32_table_call_site"))
    assert a.plan is not None
    assert a.plan.site.is_table is True, (
        "premise gone: this target's site no longer reads a table, so it no longer "
        "exercises the flag-versus-shape disagreement"
    )
    assert a.plan.shape == "menu_libc"
    assert a.is_table is False, (
        "the family followed site.is_table instead of the shape, so it teaches an "
        "index sweep for a menu-driven route"
    )

    w = walkthrough_for_binary(_target("reclibc_32_table_call_site"))
    assert _constant(w, "MEMBER_DISTANCE") is not None
    assert _constant(w, "TABLE_INDEX") is None
    assert "drive_the_object" in {s.id for s in w.steps}, (
        "a menu_libc target must still be taught the menu-driving step"
    )


def test_the_table_index_is_unknown_and_names_the_step_that_resolves_it() -> None:
    """The honesty requirement, and the one most tempting to violate.

    Where the buffer sits relative to the table is not in the image. A family
    that filled in -1 (the commonest value) would be coherent, would look
    identical to a measured one in the artifact, and would be wrong on the first
    build whose bias differed.
    """
    w = walkthrough_for_binary(_target(TABLE_SHAPE))
    idx = _constant(w, "TABLE_INDEX")
    assert idx is not None
    assert idx.confidence is Confidence.UNKNOWN, (
        f"TABLE_INDEX is {idx.confidence} with value {idx.value!r}. It is swept, "
        "one attempt per candidate -- a stated value here is a fabrication"
    )
    assert idx.value is None
    step_ids = {s.id for s in w.steps}
    assert idx.resolved_by in step_ids, (
        f"TABLE_INDEX names {idx.resolved_by!r} as its resolving step, which is not "
        f"among {sorted(step_ids)}"
    )


def test_the_table_indices_come_from_the_geometry_not_a_fixed_list() -> None:
    """A hardcoded 1..4 would be right here and wrong on a different bias.

    Recomputes the filter independently from the plan's own numbers and asserts
    the family agrees, so the list cannot quietly become a constant.
    """
    a = objptr_hijack._Analysis(_target(TABLE_SHAPE))
    scale, bias, buf = a.table_scale, a.table_bias_bytes, a.table_buf_len
    expected = tuple(k for k in (1, 2, 3, 4) if 0 <= bias - k * scale <= buf - 8)
    assert a.table_indices == expected
    assert a.table_indices, (
        "no candidate index lands in the buffer, so this target cannot exercise "
        "the table route at all"
    )
    for k in a.table_indices:
        slot = bias - k * scale
        assert slot + 8 <= buf, (
            f"index -{k} writes a pointer past the buffer end, which calls a "
            "half-overwritten address"
        )


def test_the_libc_shape_has_no_destination_in_the_image() -> None:
    """The most interesting shape, and the one with the most to get wrong.

    No win function and no `system@plt`, so DESTINATION must be UNKNOWN and name
    its resolving step, and LIBC_BASE must be produced at run time rather than
    carried as a constant. A hardcoded libc address would work once.
    """
    a = objptr_hijack._Analysis(_target(LIBC_SHAPE))
    assert a.needs_libc is True
    assert a.plan.targets and a.plan.targets[0].kind == "libc-system"

    # The premise, and the defect this caught: the plan DOES carry a target here,
    # a placeholder `CallTarget(label="libc:system", addr=0x0,
    # kind="libc-system")`. It is a NAME, not an address. Branching on
    # `plan.targets` truthiness emitted `DESTINATION = 0x0` as MEASURED on every
    # menu_libc target including HTB auth-or-out -- a fact that renders as a real
    # address, reads as measured, and is a null pointer.
    assert a.plan.targets, "premise gone: the plan carries no placeholder target"
    assert a.plan.targets[0].kind == "libc-system"
    assert a.plan.targets[0].addr == 0, (
        "premise gone: the placeholder now carries a real address, so this no "
        "longer tests the name-versus-address confusion"
    )
    assert a.in_image_targets == [], (
        "in_image_targets counted the libc placeholder as an in-image destination"
    )

    w = walkthrough_for_binary(_target(LIBC_SHAPE))
    dest = _constant(w, "DESTINATION")
    assert dest is not None
    assert dest.confidence is Confidence.UNKNOWN, (
        f"DESTINATION is {dest.confidence} with value {dest.value!r}. There is no "
        "destination in this image at all; a stated value here is a null pointer "
        "dressed as a measurement"
    )
    assert dest.value is None
    assert dest.resolved_by in {s.id for s in w.steps}

    produced = {f.name for step in w.steps for f in step.produces}
    assert "LIBC_BASE" in produced, (
        "the libc shape produces no LIBC_BASE, so nothing recomputes libc's base "
        "per run"
    )


def test_the_win_function_shape_carries_a_measured_destination() -> None:
    """The other arm, so both stay covered.

    Without this, the libc test above could pass while every shape took the libc
    path.
    """
    a = objptr_hijack._Analysis(_target(WIN_SHAPE))
    assert a.needs_libc is False
    assert a.plan.targets, "premise gone: this target has no in-image destination"

    w = walkthrough_for_binary(_target(WIN_SHAPE))
    dest = _constant(w, "DESTINATION")
    assert dest is not None
    assert dest.confidence is Confidence.MEASURED
    assert dest.value == a.plan.targets[0].addr
    produced = {f.name for step in w.steps for f in step.produces}
    assert "LIBC_BASE" not in produced, (
        "a shape with a destination in the image still teaches a libc resolution"
    )


@pytest.mark.parametrize("slug", [WIN_SHAPE, TABLE_SHAPE, LIBC_SHAPE])
def test_the_shell_proof_is_arithmetic_the_shell_must_evaluate(slug: str) -> None:
    """A literal token cannot separate 'executed' from 'reflected'.

    It matters more on this route than most: a wrong destination here usually
    leaves the program running normally rather than crashing, so the absence of a
    crash is not evidence of anything.
    """
    code = _all_code(walkthrough_for_binary(_target(slug)))
    assert "SH$((6*7))OK" in code, "the arithmetic marker is gone"
    assert "SH42OK" in code, "nothing checks for the evaluated answer"
    assert code.index("SH$((6*7))OK") < code.rindex("SH42OK")


@pytest.mark.parametrize("slug", [WIN_SHAPE, TABLE_SHAPE, LIBC_SHAPE])
def test_the_proof_helper_is_defined_before_it_is_used(slug: str) -> None:
    """The dead-code defect, pinned.

    The first version appended the proof block after each branch's body, which on
    the table shape put it past a `return` -- so `proved_shell` was called in the
    loop and defined nowhere. `ast.parse` accepts that happily; only ordering
    catches it.
    """
    code = _all_code(walkthrough_for_binary(_target(slug)))
    if "proved_shell(" not in code:
        pytest.skip(f"{slug} does not use the proof helper")
    assert "def proved_shell(" in code, (
        "`proved_shell` is called but never defined in the emitted code"
    )
    assert code.index("def proved_shell(") < code.index("if proved_shell(") if (
        "if proved_shell(" in code
    ) else True
    assert code.index("def proved_shell(") < code.rindex("proved_shell("), (
        "`proved_shell` is used before it is defined"
    )
