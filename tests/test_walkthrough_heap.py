"""Tests for the heap walkthrough family (detection and characterisation).

This family is unusual and the tests are shaped by it: **its primary output is
an absence claim**.  Every other family says "here is the technique, here is the
payload"; this one frequently says "there is no use-after-free here" or "I could
not tell".  A family whose deliverable is a negative needs its negatives proven,
because the cheapest possible implementation -- one that reports "nothing found"
whenever a probe hiccups -- passes every test that only checks the positive path.

So the suite is organised around three claims, in descending order of how much
damage a silent regression would do:

1. **A probe that did not complete must never become an absence.**  A hung or
   erroring probe yields ``UNKNOWN`` with a ``resolved_by``, and the rendered
   walkthrough must say so in words that read differently from a measured
   negative.  Proven by making runs genuinely fail -- a real timeout and a real
   spawn error -- not by asserting on a hand-built ``Observation``.
2. **The route must not claim what it has not demonstrated.**  Detection scores
   above ``triage`` and below every technique family, carries an explicitly
   unmet "control of execution" requirement, and the generated script neither
   builds a payload nor opens an interactive shell.
3. **The generated script must run.**  Rendering is not verification.  Two
   defects in this family -- an inline ``splice()`` placeholder printed
   verbatim, and verdict labels truncated mid-word and duplicated -- were
   invisible in source review and obvious on the first execution.

Covers ``docs/plans/2026-09-24-walkthrough-heap-family.md``.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
from pathlib import Path

import pytest

from supwngo.exploit.walkthrough import heap_probe
from supwngo.exploit.walkthrough.facts import collect_facts
from supwngo.exploit.walkthrough.families import heap
from supwngo.exploit.walkthrough.heap_probe import (
    Observation,
    RunOutcome,
    RunResult,
    State,
)
from supwngo.exploit.walkthrough.registry import generate_walkthrough, propose_routes
from supwngo.exploit.walkthrough.render import render_script

CORPUS = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"

#: Target 11 exposes a use-after-free READ (it has a show operation, no edit).
UAF_READ_TARGET = CORPUS / "11_heap_uaf_leak" / "heap_uaf_leak"
#: Target 12 exposes a use-after-free WRITE (it has an edit operation, no show).
#: The two are deliberately complementary: between them every probe in the
#: module reaches both its PRESENT and its UNKNOWN branch on a real binary.
UAF_WRITE_TARGET = CORPUS / "12_heap_tcache_poison" / "heap_tcache_poison"

#: Every corpus target, as ``(directory, binary-name)``.
ALL_TARGETS = [
    ("01_shellcode_stack", "shellcode_stack"),
    ("02_ret2plt_system", "ret2plt_system"),
    ("03_pie_leak_ret2libc", "pie_leak_ret2libc"),
    ("04_canary_leak_bypass", "canary_leak_bypass"),
    ("05_fmtstr_arbread", "fmtstr_arbread"),
    ("06_fmtstr_arbwrite", "fmtstr_arbwrite"),
    ("07_ret2libc_leak", "ret2libc_leak"),
    ("08_ret2dlresolve", "ret2dlresolve"),
    ("09_srop", "srop"),
    ("10_int_overflow", "int_overflow"),
    ("11_heap_uaf_leak", "heap_uaf_leak"),
    ("12_heap_tcache_poison", "heap_tcache_poison"),
    ("13_off_by_one", "off_by_one"),
    ("14_negative_index", "negative_index"),
    ("15_win_function", "win_function"),
]

#: The only two targets the heap family may win.
HEAP_TARGETS = {"heap_uaf_leak", "heap_tcache_poison"}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _require(path: Path) -> str:
    if not path.exists():
        pytest.skip(f"{path.name} not built -- run benchmark/build_all.sh")
    return str(path)


@pytest.fixture(scope="module")
def read_facts():
    """Facts for target 11, probed for real. Cached: the probe runs the binary."""
    return collect_facts(_require(UAF_READ_TARGET), probe=True)


@pytest.fixture(scope="module")
def write_facts():
    """Facts for target 12, probed for real."""
    return collect_facts(_require(UAF_WRITE_TARGET), probe=True)


def _script_for(facts, directory: Path) -> Path:
    script = directory / "wt.py"
    script.write_text(render_script(generate_walkthrough(facts)))
    return script


def _run(script: Path, cwd: Path) -> tuple[str, int]:
    env = dict(os.environ, TERM="xterm", PWNLIB_NOTERM="1")
    done = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
    )
    return done.stdout + done.stderr, done.returncode


@pytest.fixture(scope="module")
def read_run(read_facts, tmp_path_factory):
    script = _script_for(read_facts, tmp_path_factory.mktemp("heap_read"))
    return _run(script, Path(read_facts.path).parent)


@pytest.fixture(scope="module")
def write_run(write_facts, tmp_path_factory):
    script = _script_for(write_facts, tmp_path_factory.mktemp("heap_write"))
    return _run(script, Path(write_facts.path).parent)


def _heap_route(facts):
    for family, route in propose_routes(facts):
        if family.NAME == "heap":
            return route
    return None


# ---------------------------------------------------------------------------
# 1. a probe that did not complete is never an absence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "outcome",
    [RunOutcome.TIMED_OUT, RunOutcome.BUDGET_EXHAUSTED, RunOutcome.ERROR],
)
def test_no_failed_run_outcome_can_produce_an_absence(outcome):
    """``from_failed_run`` is UNKNOWN for every non-completed outcome.

    Parametrized over the whole enum rather than one example, so adding a new
    failure mode without wiring it here fails loudly.
    """
    obs = Observation.from_failed_run(
        RunResult(outcome, b"", detail="detail"),
        what="whether the pointer survives free()",
        resolved_by="heap_primitives",
    )
    assert obs.state is State.UNKNOWN
    assert obs.resolved_by == "heap_primitives"
    assert obs.reason and outcome.value in obs.reason


def test_from_failed_run_refuses_a_completed_run():
    """The guard that keeps the honest path from being used dishonestly."""
    with pytest.raises(AssertionError):
        Observation.from_failed_run(
            RunResult(RunOutcome.COMPLETED, b"output"),
            what="anything",
            resolved_by="heap_primitives",
        )


def test_absence_is_refused_without_a_passing_positive_control():
    """The single most important line in ``heap_probe``.

    A probe that never demonstrated it can see the thing has not established an
    absence.  Without this, "found nothing" and "cannot see anything" collapse
    into the same verdict and the family's negatives become worthless.
    """
    control = Observation.unknown(
        summary="could not determine: whether contents can be read back",
        reason="the menu offers no show operation",
        resolved_by="heap_primitives",
    )
    obs = Observation.absent(
        "the pointer does not survive free()",
        command="./t # 1,0,96 -> 2,0 -> 3,0",
        method="differential read after free",
        positive_control=control,
        control_description="the read-back control did not pass",
    )
    assert obs.state is State.UNKNOWN, "an unproven probe must not claim an absence"
    assert obs.resolved_by == "heap_primitives"


def test_absence_is_allowed_once_the_positive_control_passes():
    """The other half: the gate must not be unconditional, or nothing is ever
    reported absent and the tri-state degenerates to two states."""
    control = Observation.present(
        "contents can be read back through the program's own show operation",
        command="./t # 1,0,96 -> 3,0",
        method="differential read while live",
    )
    obs = Observation.absent(
        "the pointer does not survive free()",
        command="./t # 1,0,96 -> 2,0 -> 3,0",
        method="differential read after free",
        positive_control=control,
        control_description="the read-back control passed",
    )
    assert obs.state is State.ABSENT


def test_a_real_timeout_makes_every_fact_undetermined(tmp_path):
    """Drive the real probe with a timeout it cannot meet.

    No mocking: ``collect`` runs the actual binary, every run is genuinely
    killed, and the question is what the module concludes.  The answer must be
    "nothing", not "no heap bug here".

    This also proves the timeout parameter *takes effect* rather than merely
    being accepted -- the failure this family was specifically warned about,
    because the pre-existing discovery probes hardcode their own timeouts and
    silently ignore the one the caller passes.  If ``timeout`` were dropped on
    the floor the runs would succeed and this test would fail.

    ``0.0``, not a small non-zero value: at 0.001s the target wins the race
    roughly five times out of six (measured), so the obvious version of this
    test is flaky in the direction that hides the bug.  Zero makes
    ``communicate`` expire before it waits at all.
    """
    path = _require(UAF_WRITE_TARGET)
    provenance: list[str] = []
    facts = heap_probe.collect(path, None, _Empty(), provenance, timeout=0.0)

    absent = {
        name: obs.summary
        for name, obs in facts.observations.items()
        if obs.state is State.ABSENT
    }
    assert not absent, (
        "a probe that never completed reported a measured absence: "
        f"{absent}. This is the failure mode the tri-state exists to prevent."
    )
    for name, obs in facts.observations.items():
        if name in facts.HOST_WIDE:
            continue  # read from the host's glibc, not from a run of the target
        assert obs.state is State.UNKNOWN, f"{name} was decided without a usable run"
        assert obs.resolved_by, f"{name} is UNKNOWN with no way to resolve it"
        assert obs.reason, f"{name} is UNKNOWN without saying why"


def _unspawnable_copy(tmp_path: Path) -> str:
    """A real, valid ELF that genuinely cannot be executed.

    Deliberately not a monkeypatched ``Popen``: patching the module-global would
    also break the ELF loader and pwntools, so the test would be measuring the
    patch rather than the probe.  Stripping the execute bit makes the *real*
    ``Popen`` raise ``PermissionError`` on the real code path, which is the same
    ``RunOutcome.ERROR`` an unreadable or missing target produces.
    """
    source = Path(_require(UAF_WRITE_TARGET))
    copy = tmp_path / source.name
    copy.write_bytes(source.read_bytes())
    copy.chmod(0o644)
    return str(copy)


def _broken_heap_facts(tmp_path: Path) -> heap_probe.HeapFacts:
    """``HeapFacts`` from a probe whose every run genuinely failed to spawn."""
    return heap_probe.collect(_unspawnable_copy(tmp_path), None, _Empty(), [])


def test_a_spawn_error_makes_every_fact_undetermined(tmp_path):
    """The other real failure: the process cannot be started at all.

    Modelled on an actual bug -- a relative binary path plus ``cwd=`` in the
    child made every spawn raise ``FileNotFoundError``.  The tri-state caught
    it: every fact came back "the probe run error", so the bug could not
    masquerade as "this target has no heap primitives".  That behaviour is the
    thing being pinned here.
    """
    provenance: list[str] = []
    facts = _broken_heap_facts(tmp_path)

    for name, obs in facts.observations.items():
        if name in facts.HOST_WIDE:
            continue
        assert obs.state is State.UNKNOWN, f"{name} was decided with no process at all"
        assert obs.reason, f"{name} is UNKNOWN without saying why"

    # The interface probe is the one that actually attempted a spawn, so it is
    # the one that must name the run failure.  The downstream probes correctly
    # blame the missing interface instead: a cascade that reported "the probe run
    # error" for a sequence it never even attempted would be inventing
    # provenance.
    assert "error" in facts.menu.observation.reason
    for name in ("read_control", "uaf_read", "uaf_write", "tcache_reuse"):
        reason = facts.observations[name].reason
        assert "never located" in reason or "no " in reason, (
            f"{name} should blame the undiscovered interface, not a run it never "
            f"made: {reason!r}"
        )


def test_an_undrivable_target_is_not_reported_as_having_no_heap_bug(
    tmp_path, write_facts
):
    """The route-level consequence of the above.

    When nothing could be measured the family must go non-applicable with a
    rationale that distinguishes "the interface is not drivable" from "the probe
    never completed" -- the reader's next action differs (try another family vs.
    raise the budget and retry this one).

    Real binary facts, real (failed) heap probe: only the ``heap`` field is
    swapped, so the binary still imports an allocator and the family cannot
    abstain its way out of answering.
    """
    facts = dataclasses.replace(write_facts, heap=_broken_heap_facts(tmp_path))
    route = heap.propose(facts)

    assert route is not None, "the binary imports an allocator; abstaining hides this"
    assert not route.applicable
    lowered = route.rationale.lower()
    assert "absence of a measurement" in lowered or "could not establish" in lowered, (
        "the rationale must name the missing measurement rather than implying "
        f"there is no heap bug: {route.rationale!r}"
    )
    assert route.becomes_viable_if, "an UNKNOWN verdict must name what would settle it"


def test_undetermined_facts_render_as_not_determined_in_words(read_run):
    """The distinction has to survive into the output, not just the data model.

    Target 11 has no edit operation, so ``uaf_write`` cannot be measured.  The
    generated script must say that in a shape a reader cannot mistake for "no
    use-after-free write exists".
    """
    output, rc = read_run
    assert rc == 0, output
    assert "[NOT DETERMINED] use-after-free WRITE" in output
    assert "this is NOT a clean result" in output
    assert "Nothing was measured either way" in output
    # And it must not simultaneously report the same fact as a measured negative.
    assert "[NOT OBSERVED]   use-after-free WRITE" not in output


def test_the_final_summary_lists_what_could_not_be_determined(read_run, write_run):
    """The undetermined list is the useful output of an honest detection pass."""
    read_output, _ = read_run
    write_output, _ = write_run
    assert "Could not determine: tcache_reuse, uaf_write" in read_output
    assert "Could not determine: read_control, uaf_read" in write_output
    for output in (read_output, write_output):
        assert "absences of measurement, not clean results" in output


def test_a_present_fact_is_not_reported_as_undetermined(write_run):
    """The complement: the two targets were chosen so that each one's UNKNOWN is
    the other's OBSERVED.  Without this, a probe that returned UNKNOWN for
    everything would pass every test above."""
    output, rc = write_run
    assert rc == 0, output
    assert "[OBSERVED]       use-after-free WRITE" in output
    assert "[OBSERVED]       freed chunk handed straight back" in output
    assert "[NOT DETERMINED] use-after-free WRITE" not in output


# ---------------------------------------------------------------------------
# 1b. roll-up invariants that no corpus target currently exercises
#
# Both tests below exist because a mutation of the code they cover came back
# GREEN against the whole corpus.  Neither mutation is harmless -- each was inert
# only by coincidence, so each is pinned directly rather than left to a future
# target to catch:
#
#   * ``HOST_WIDE`` is reachable whenever ``libc_path`` resolves but the menu
#     does not: ``safe_linking`` is read from the host glibc alone, so it would be
#     the single PRESENT fact and would make the family applicable on a binary it
#     learned nothing about.  Today no corpus target is in that state (the two
#     heap targets have a usable menu; target 14 imports four allocator functions
#     but resolves no ``libc_path``), which is exactly why it needs a unit test.
#   * ``HeapFacts.uaf`` preferring the write over the read is unobservable on
#     this corpus because no target offers both a show and an edit operation, so
#     no target has both directions PRESENT at once.
# ---------------------------------------------------------------------------


def _facts_from(**overrides) -> heap_probe.HeapFacts:
    """A ``HeapFacts`` in a hand-specified state, for the roll-up properties."""
    unknown = Observation.unknown(
        summary="not probed in this test", reason="fixture", resolved_by="heap_primitives"
    )
    base = dict(
        menu=heap_probe.MenuFacts({}, unknown),
        read_control=unknown,
        uaf_read=unknown,
        uaf_write=unknown,
        tcache_reuse=unknown,
        allocator={"tcache": unknown, "safe_linking": unknown},
    )
    base.update(overrides)
    return heap_probe.HeapFacts(**base)


def test_a_host_wide_fact_alone_does_not_make_the_family_applicable():
    """safe-linking is a property of the host's glibc, not of the target.

    It is PRESENT on this machine for every binary ever analysed here, including
    ones with no allocator at all.  Counting it as a binary-specific observation
    would let the family claim it characterised a target it never drove.
    """
    present_host_fact = Observation.present(
        "glibc 2.35 mangles tcache freelist pointers",
        command="strings libc.so.6 | grep -m1 'release version'",
        method="glibc version string",
    )
    facts = _facts_from(
        allocator={
            "safe_linking": present_host_fact,
            "tcache": Observation.unknown(
                summary="whether allocations land in tcache",
                reason="the create operation was never located",
                resolved_by="heap_primitives",
            ),
        }
    )
    assert facts.observations["safe_linking"].is_present, "fixture is not set up"
    # Behaviour first: a mutation that empties HOST_WIDE should be reported as
    # "the family became applicable", not as "a set lost a member".
    assert not facts.any_present, (
        "a fact read from the host glibc made the heap family applicable to a "
        "binary nothing was measured on"
    )
    assert "safe_linking" in facts.HOST_WIDE, "the excluded name was renamed"


def test_a_binary_specific_fact_does_make_the_family_applicable():
    """The complement, so the gate cannot be satisfied by rejecting everything."""
    facts = _facts_from(
        uaf_write=Observation.present(
            "the stored pointer survives free()",
            command="./t # 1,0,96 -> 2,0 -> 3,0",
            method="differential write after free",
        )
    )
    assert facts.any_present


def test_uaf_prefers_the_write_when_both_directions_were_observed():
    """A write is what escalates, so it must lead.

    Unobservable on this corpus: target 11 has a show and no edit, target 12 an
    edit and no show, so neither has both directions PRESENT.
    """
    read = Observation.present(
        "the marker is still readable after free (use-after-free READ)",
        command="./t # read",
        method="differential read after free",
    )
    write = Observation.present(
        "an edit of the freed index is still accepted (use-after-free WRITE)",
        command="./t # write",
        method="differential write after free",
    )
    facts = _facts_from(uaf_read=read, uaf_write=write)
    assert facts.uaf is write, "the read was reported over the write"


def test_uaf_is_none_when_neither_direction_was_observed():
    """``None`` means "not observed", which is NOT "ruled out" -- the whole point
    of keeping the per-direction observations alongside this roll-up."""
    assert _facts_from().uaf is None


# ---------------------------------------------------------------------------
# 2. the route does not claim what it has not demonstrated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["read_facts", "write_facts"])
def test_heap_targets_select_the_detection_route(fixture, request):
    facts = request.getfixturevalue(fixture)
    walkthrough = generate_walkthrough(facts)
    assert walkthrough.family == "heap"
    route = _heap_route(facts)
    assert route is not None and route.applicable
    assert route.score == heap.SCORE_DETECTION == 0.25


@pytest.mark.parametrize("directory, name", ALL_TARGETS, ids=[d for d, _ in ALL_TARGETS])
def test_heap_never_wins_a_target_that_is_not_a_heap_target(directory, name):
    """A detection-only route sits just above the triage floor, so the risk it
    carries is not losing -- it is quietly outbidding a real technique on any
    target that merely links ``malloc``."""
    path = CORPUS / directory / name
    if not path.exists():
        pytest.skip(f"{name} not built -- run benchmark/build_all.sh")
    facts = collect_facts(str(path), probe=True)
    walkthrough = generate_walkthrough(facts)
    if name in HEAP_TARGETS:
        assert walkthrough.family == "heap"
    else:
        assert walkthrough.family != "heap", (
            f"{directory} was captured by the heap family. Detection must lose "
            "to every technique family."
        )


def test_detection_route_carries_an_explicitly_unmet_execution_requirement(read_facts):
    """The honesty is structural, not just prose: a reader scanning requirements
    sees control of execution listed and unsatisfied."""
    route = _heap_route(read_facts)
    unmet = [r.text for r in route.requires if not r.satisfied]
    assert any("control of execution" in text.lower() for text in unmet), (
        f"no unmet execution requirement among {[r.text for r in route.requires]}"
    )
    assert "does not claim a shell it has not demonstrated" in route.rationale


def test_detection_scores_below_every_technique_family_and_above_triage():
    """Pinned here as well as in the cross-family table, because this is the
    invariant that makes a detection family safe to ship at all."""
    from supwngo.exploit.walkthrough.families import (
        fmtstr,
        integer,
        rop_chain,
        stack_bof,
        syscall,
        triage,
    )

    technique_scores = []
    for module in (rop_chain, syscall, integer, stack_bof, fmtstr):
        technique_scores += [
            value
            for name, value in vars(module).items()
            if name.startswith("SCORE_") and isinstance(value, float) and value > 0
        ]
    assert technique_scores, "no technique scores found -- the scan stopped working"
    assert heap.SCORE_DETECTION < min(technique_scores)
    assert heap.SCORE_DETECTION > triage.TRIAGE_SCORE


@pytest.mark.parametrize("fixture", ["read_run", "write_run"])
def test_the_script_never_opens_a_shell_or_claims_one(fixture, request):
    output, rc = request.getfixturevalue(fixture)
    assert rc == 0, output
    assert "has not claimed, and" in output
    assert "has not attempted, control of execution" in output
    # A detection walkthrough that dropped into a shell would be the regression
    # this family's whole scope exists to prevent.
    assert "$ " not in output.replace("[*] $ ", "")


@pytest.mark.parametrize("fixture", ["read_run", "write_run"])
def test_both_escalation_invariants_appear_in_full(fixture, request):
    """The two facts the brief requires any heap exploitation text to carry.

    Both are "silent" failures -- the exploit is correct and does nothing -- so
    a reader who does not know them debugs the wrong thing for hours.
    """
    output, _ = request.getfixturevalue(fixture)
    assert "counts[tc_idx] > 0" in output
    assert "BEFORE following the pointer you overwrote" in output
    assert "loads rbp, not rsp" in output
    assert "SECOND pass" in output


# ---------------------------------------------------------------------------
# 3. the generated script runs, and says what it was generated from
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["read_run", "write_run"])
def test_the_generated_script_runs_end_to_end(fixture, request):
    output, rc = request.getfixturevalue(fixture)
    assert rc == 0, output
    for step in ("STEP 1", "STEP 2", "STEP 3", "STEP 4"):
        assert step in output, f"{step} did not run:\n{output}"


@pytest.mark.parametrize("fixture", ["read_run", "write_run"])
def test_no_unsubstituted_placeholder_reaches_the_output(fixture, request):
    """A real defect, found by executing rather than reading.

    ``splice()`` placeholders are whole-line; an inline one was substituted by
    nothing and missed by the leftover check, so ``Characterisation of @@NAME@@``
    printed verbatim.  ``splice()`` now raises on any leftover, and this asserts
    the end result independently of that fix.
    """
    output, _ = request.getfixturevalue(fixture)
    assert "@@" not in output, f"an unspliced placeholder survived:\n{output}"


@pytest.mark.parametrize("fixture", ["read_run", "write_run"])
def test_verdict_labels_are_short_and_not_duplicated_into_their_detail(
    fixture, request
):
    """The other execution-only defect.

    Labels were ``summary[:60]`` while the detail was the whole summary, so
    every line printed the same sentence twice with the first copy cut off
    mid-word.  Each label must now be a known short label, and must not be a
    prefix of its own detail.
    """
    output, _ = request.getfixturevalue(fixture)
    labels = set(heap.OBSERVATION_LABELS.values())
    seen = 0
    for line in output.splitlines():
        for marker in ("[OBSERVED]", "[NOT OBSERVED]", "[NOT DETERMINED]"):
            if marker not in line:
                continue
            body = line.split(marker, 1)[1].strip()
            label, _, detail = body.partition(": ")
            if label not in labels:
                continue  # a verdict from another step's own vocabulary
            seen += 1
            assert not detail.startswith(label), (
                f"label duplicated into its detail: {line!r}"
            )
            assert len(label) < 60, f"label looks truncated: {label!r}"
    assert seen >= 4, f"expected several labelled verdicts, saw {seen}"


@pytest.mark.parametrize("fixture", ["read_run", "write_run"])
def test_every_measured_verdict_carries_a_reproducing_command(fixture, request):
    """Provenance per fact, which is what separates this from a guess."""
    output, _ = request.getfixturevalue(fixture)
    lines = output.splitlines()
    observed = [i for i, line in enumerate(lines) if "[OBSERVED]" in line]
    assert observed, "no observed facts at all"
    for i in observed:
        window = " ".join(lines[i : i + 3])
        assert "reproduce:" in window, f"no reproducing command for: {lines[i]!r}"


def test_the_characterisation_header_names_the_actual_binary(read_run, write_run):
    read_output, _ = read_run
    write_output, _ = write_run
    assert "Characterisation of heap_uaf_leak" in read_output
    assert "Characterisation of heap_tcache_poison" in write_output


# ---------------------------------------------------------------------------
# 4. the inferred-vs-observed discrepancy verdict
# ---------------------------------------------------------------------------


def test_inferred_tcache_is_marked_inferred_only_when_reuse_was_not_observed(
    read_facts,
):
    """Target 11 prints no addresses, so LIFO reuse cannot be observed and the
    tcache verdict rests on the size being under glibc's 0x408 ceiling -- an
    inference.  Saying "tcache: in play" without that caveat would present an
    inference as an observation."""
    walkthrough = generate_walkthrough(read_facts)
    by_name = {v.name: v for v in walkthrough.protections}
    verdict = by_name.get("tcache evidence: inferred vs observed")
    assert verdict is not None, sorted(by_name)
    assert verdict.state == "INFERRED ONLY"
    assert "not an observation of this allocator" in verdict.implication
    assert verdict.forces and "gdb" in verdict.forces


def test_observed_tcache_reuse_is_marked_observed(write_facts):
    """Target 12 does print addresses, so the same verdict must upgrade.  Two
    targets, two branches: a verdict hardcoded to either string fails one."""
    walkthrough = generate_walkthrough(write_facts)
    by_name = {v.name: v for v in walkthrough.protections}
    verdict = by_name["tcache evidence: inferred vs observed"]
    assert verdict.state == "OBSERVED"
    assert "agree" in verdict.implication


@pytest.mark.parametrize("fixture", ["read_facts", "write_facts"])
def test_undetermined_uaf_verdicts_tell_the_reader_not_to_bank_them(fixture, request):
    facts = request.getfixturevalue(fixture)
    walkthrough = generate_walkthrough(facts)
    undetermined = [
        v for v in walkthrough.protections if v.state == "NOT DETERMINED"
    ]
    assert undetermined, "both targets have at least one undetermined uaf direction"
    for verdict in undetermined:
        assert verdict.forces and "do not record this as a clean result" in verdict.forces


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _Empty:
    """Minimal stand-in for ``TargetFacts`` when calling ``heap_probe.collect``
    directly, so the probe-level tests do not pay for full fact collection."""

    plt: dict = {}
    symbols: dict = {}
    libc_path = None
