"""Tests for the integer walkthrough family.

Two layers, and the split is the point.

The **unit** layer pins the discriminators the family's honesty rests on: which
edge of a signed branch accepts, how strictness changes the largest accepted
value, and the requirement that the guarded value came from ``scanf``.  Each of
these was chosen because getting it wrong produces a walkthrough that renders
perfectly and teaches something false, so each test is written to fail if the
discriminator is removed rather than merely to pass today.

The **execution** layer does what rendering cannot: it runs every generated
walkthrough.  ``python3 wt.py steps``, then every step by number, then the
complete exploit -- against the real corpus binaries, under hard timeouts.  The
verdict is the generated script's own exit status, and that script judges itself
by a differential against two controls (a benign input and one the target's own
bounds check refuses).  Nothing here searches output for a flag: a target that
printed its flag for an unrelated reason would pass such a test, and a target
whose flag file was missing would fail it while the exploit worked.

Covers `docs/plans/2026-09-24-walkthrough-integer-family.md`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from supwngo.exploit.walkthrough.families import integer
from supwngo.exploit.walkthrough.model import Confidence
from supwngo.exploit.walkthrough.render import render_markdown, render_script

CORPUS = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"

#: The two round-1 targets this family was built for, and the route each must
#: select.  A scoring or detector change that silently reroutes one fails here.
TARGETS = {
    "10_int_overflow": ("int_overflow", integer.TRUNCATION),
    "14_negative_index": ("negative_index", integer.NEGATIVE_INDEX),
}

#: Addresses read out of ``objdump -d --disassemble=vuln -M intel`` on the
#: committed sources' build.  Used only to make failures legible: every
#: assertion below that depends on a specific build is guarded by a digest-free
#: structural check first, and skips rather than fails on a different build.
GROUND_TRUTH = {
    "int_overflow": {
        "guard": 0x401267,      # cmp eax,0x40
        "branch": 0x40126A,     # jle 0x40127d  -- accepts on the TAKEN edge
        "accept_at": 0x40127D,
        "cast": 0x401280,       # mov BYTE PTR [rbp-0x1],al
        "sink": 0x4012B6,       # call read@plt
    },
    "negative_index": {
        "guard": 0x401BF0,      # cmp eax,0x7
        "branch": 0x401BF3,     # jg 0x401c0f -- accepts on the FALL-THROUGH
        "accept_at": 0x401BF5,
        "signext": 0x401BFC,    # cdqe
        "store": 0x401BFE,      # mov QWORD PTR [rbp+rax*8-0x48],rdx
    },
}

#: Generous enough for a GDB probe on a loaded machine, finite enough that a
#: hang is a failure rather than a stuck suite.  Required rather than tidy: the
#: two-phase send this family teaches fails by HANGING when it is collapsed
#: into one write, so a test without a timeout would not report that defect, it
#: would become it.
STEP_TIMEOUT = 300
EXPLOIT_TIMEOUT = 300


def _binary(directory: str) -> Path:
    name = TARGETS[directory][0]
    path = CORPUS / directory / name
    if not path.exists():
        pytest.skip(f"benchmark corpus not built: {path} (run benchmark/build_all.sh)")
    return path


def _facts(directory: str):
    from supwngo.exploit.walkthrough.facts import collect_facts

    return collect_facts(str(_binary(directory)), probe=False)


def _analysis(directory: str):
    analysis = integer._analyse(_facts(directory))
    if analysis.empty:
        pytest.skip(
            f"no integer arithmetic found in {directory}; objdump may be missing"
        )
    return analysis


def _walkthrough(directory: str):
    from supwngo.exploit.walkthrough.registry import walkthrough_for_binary

    return walkthrough_for_binary(str(_binary(directory)), probe=False)


# ---------------------------------------------------------------------------
# the discriminators
# ---------------------------------------------------------------------------


def test_accept_max_distinguishes_strict_from_non_strict():
    """``jle 0x40`` accepts 64; ``jl 0x40`` accepts 63.

    One off-by-one here and the walkthrough's identity table claims an input the
    guard refuses, which renders fine and fails only when someone runs it.
    """
    table = integer._SIGNED_BRANCHES
    assert table["jle"][2] == 0, "jle accepts values equal to the immediate"
    assert table["jl"][2] == -1, "jl accepts values strictly below it"
    assert table["jg"][2] == 0, "jg falls through on <=, so equal is accepted"
    assert table["jge"][2] == -1, "jge falls through on <, so equal is rejected"


def test_every_signed_branch_maps_to_its_unsigned_counterpart():
    """The fix this family teaches is 'use the unsigned form', so the mapping
    has to be complete and has to be the actual counterpart."""
    pairs = {name: spec[0] for name, spec in integer._SIGNED_BRANCHES.items()}
    assert pairs["jl"] == "jb" and pairs["jle"] == "jbe"
    assert pairs["jg"] == "ja" and pairs["jge"] == "jae"
    for signed, unsigned in pairs.items():
        assert unsigned not in integer._SIGNED_BRANCHES, (
            f"{unsigned} is listed as an unsigned counterpart but also as a "
            "signed branch; one of the two is wrong"
        )


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_accepting_edge_is_computed_from_the_mnemonic(directory):
    """The accepting edge differs between the two targets, so a family that
    assumed either one would be wrong about the other.

    Target 10's ``jle`` jumps TO the accepted path; target 14's ``jg`` jumps to
    the REJECTED path and accepts by falling through.  Scanning from the wrong
    address finds either nothing or the wrong instructions.
    """
    analysis = _analysis(directory)
    name = TARGETS[directory][0]
    truth = GROUND_TRUTH[name]
    sites = analysis.truncations + analysis.negative_indexes
    assert sites, f"no site found in {directory}"
    guard = sites[0].guard
    if guard.address != truth["guard"]:
        pytest.skip(f"different build: guard at {guard.address:#x}")
    assert guard.branch_address == truth["branch"]
    assert guard.accept_at == truth["accept_at"], (
        f"{name}: `{guard.branch}` accepts at {truth['accept_at']:#x}, the "
        f"family computed {guard.accept_at:#x}"
    )
    if guard.branch == "jle":
        assert guard.accept_at != guard.branch_address + 2, (
            "jle accepts on the taken edge; the fall-through is the rejected path"
        )
    if guard.branch == "jg":
        assert guard.accept_at == guard.branch_address + 2, (
            "jg jumps to the rejected path; the accepted path is the fall-through"
        )


def test_initialisation_loop_is_not_mistaken_for_the_vulnerability():
    """``for (i = 0; i < 8; i++) arr[i] = 0;`` has every syntactic feature of
    the bug: a signed compare against 7, a ``cdqe``, and the same scaled store.

    The only thing it lacks is an index the attacker supplied, so requiring the
    guarded slot to have been written by ``scanf`` is the whole discriminator.
    Without it this family reports two negative-index sites in target 14 and
    teaches whichever it happens to find first.
    """
    analysis = _analysis("14_negative_index")
    assert len(analysis.negative_indexes) == 1, (
        "expected exactly one attacker-controlled indexed store, found "
        f"{len(analysis.negative_indexes)}: the scanf-taint requirement is not "
        "discriminating"
    )
    site = analysis.negative_indexes[0]
    truth = GROUND_TRUTH["negative_index"]
    if site.guard.address != truth["guard"]:
        pytest.skip(f"different build: guard at {site.guard.address:#x}")
    assert site.store_address == truth["store"]
    assert site.value_slot is not None, (
        "the stored value must be traced to a scanf slot; without that the "
        "route cannot claim an attacker-chosen write"
    )


def test_truncation_requires_the_sinks_own_count_register():
    """A large number reaching some register before ``read()`` is not the same
    claim as ``read()`` being told to copy that many bytes."""
    assert integer._SIZE_SINKS["read"] == "rdx"
    assert integer._SIZE_SINKS["malloc"] == "rdi", (
        "malloc takes its size in RDI; a shared hardcoded RDX would either miss "
        "wrapped allocations or accept unrelated ones"
    )
    site = _analysis("10_int_overflow").truncations[0]
    assert site.size_register == integer._SIZE_SINKS[site.sink_name]
    assert site.buffer_slot < 0, "the destination must be a local stack buffer"


def test_trigger_value_satisfies_both_clauses_of_the_identity():
    """The input this family recommends must pass the guard AND produce a count
    that reaches the saved return address.  Either alone is useless."""
    analysis = _analysis("10_int_overflow")
    site = analysis.truncations[0]
    trigger, count = integer._trigger_value(site)
    offset = integer._derived_offset(analysis, site)
    assert offset is not None, "target 10 has a frame-pointer prologue"
    assert trigger <= site.guard.accept_max, "the recommended input is refused"
    assert count == (trigger & site.mask), "the count is not the truncation"
    assert count >= offset + 8, (
        f"count {count} does not reach the saved return address {offset + 8} "
        "bytes away"
    )


def test_unwind_symbols_are_not_treated_as_win_functions():
    """A statically linked binary exports ``_Unwind_Resume``, which the shared
    substring matcher reports as a win function.  Returning into it crashes."""
    for bad in ("_Unwind_Resume", "unwind_frame", "GetWindowSize", "rewind"):
        assert integer._NOT_WIN.search(bad), f"{bad} should be filtered out"
    assert not integer._NOT_WIN.search("win")
    assert not integer._NOT_WIN.search("give_flag")


def test_canary_verdict_is_corrected_from_the_function_itself():
    """``facts.py`` reports a canary whenever ``__stack_chk_fail`` is linked in,
    which is true of every statically linked glibc binary.  Target 14's
    ``vuln()`` has no canary, and a family that believed otherwise would abstain
    from a bug it can teach."""
    facts = _facts("14_negative_index")
    analysis = _analysis("14_negative_index")
    assert facts.protections.canary, (
        "this test exists because the image-wide check is a false positive here; "
        "if it stopped reporting a canary, the correction is now untested"
    )
    assert not analysis.canary_in_function, (
        f"{analysis.function}() contains no fs:0x28 and no __stack_chk_fail"
    )
    assert not integer._canary_blocks(facts, analysis)
    corrected = integer._corrected_protections(facts, analysis)
    assert corrected.canary is False
    # And the correction is never silent: it is recorded, and the walkthrough
    # says so rather than just disagreeing with its own preflight output.
    assert integer._protection_correction_provenance(facts, analysis)
    verdicts = integer._protection_verdicts(facts, analysis)
    assert any("image-wide" in verdict.name for verdict in verdicts)


def test_correction_only_ever_turns_the_canary_claim_off():
    """Weakening a protection verdict is only ever honest in one direction."""
    facts = _facts("10_int_overflow")
    analysis = _analysis("10_int_overflow")
    corrected = integer._corrected_protections(facts, analysis)
    if not facts.protections.canary:
        assert corrected.canary is False
    for field in ("nx", "pie", "relro"):
        assert getattr(corrected, field) == getattr(facts.protections, field), (
            f"{field} must not be rewritten by this family"
        )


# ---------------------------------------------------------------------------
# abstention and selection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "directory,name",
    [
        ("01_shellcode_stack", "shellcode_stack"),
        ("02_ret2plt_system", "ret2plt_system"),
        ("15_win_function", "win_function"),
    ],
)
def test_abstains_on_targets_without_the_arithmetic(directory, name):
    """Abstention is first-class: "no integer overflow detected" is true of
    almost every binary and teaches nobody anything."""
    from supwngo.exploit.walkthrough.facts import collect_facts

    path = CORPUS / directory / name
    if not path.exists():
        pytest.skip(f"benchmark corpus not built: {path}")
    assert integer.propose(collect_facts(str(path), probe=False)) is None


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_selected_route_is_the_integer_one(directory):
    expected = TARGETS[directory][1]
    wt = _walkthrough(directory)
    assert wt.family == integer.NAME
    assert wt.taught_route == expected


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_propose_is_deterministic_and_leaves_the_binary_alone(directory):
    """``propose`` runs for every family on every binary, so it must be cheap,
    repeatable and incapable of touching the target."""
    import hashlib

    path = _binary(directory)
    facts = _facts(directory)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    first = integer.propose(facts)
    second = integer.propose(facts)
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    assert before == after, "propose modified the binary"
    assert first is not None and second is not None
    assert (first.name, first.score, first.applicable) == (
        second.name,
        second.score,
        second.applicable,
    )


# ---------------------------------------------------------------------------
# what the walkthrough may and may not claim
# ---------------------------------------------------------------------------


def test_negative_index_walkthrough_never_mentions_an_offset():
    """This route does not touch the saved return address, so an OFFSET
    constant would be a fact the walkthrough neither uses nor establishes -- and
    when the probe fails it would be an UNKNOWN whose resolving step does not
    exist here.  Model validation only catches undeclared ``G_*`` names, so this
    has to be asserted directly."""
    wt = _walkthrough("14_negative_index")
    assert not any(fact.name == "OFFSET" for fact in wt.constants)
    text = render_script(wt)
    for lineno, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0]
        assert "OFFSET" not in code, f"OFFSET referenced in code at line {lineno}"


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_every_constant_carries_provenance(directory):
    wt = _walkthrough(directory)
    for fact in wt.constants:
        assert fact.evidence is not None, f"{fact.name}: no evidence"
        assert fact.evidence.method.strip(), f"{fact.name}: empty method"
        assert fact.confidence in (
            Confidence.MEASURED,
            Confidence.DERIVED,
            Confidence.ASSUMED,
            Confidence.UNKNOWN,
        )


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_addresses_are_measured_and_computations_are_derived(directory):
    """Provenance is a real type, not decoration.  An instruction address was
    read out of the binary; an index computed from two displacements was not."""
    wt = _walkthrough(directory)
    by_name = {fact.name: fact for fact in wt.constants}
    for name in ("GUARD_ADDR", "STORE_ADDR", "CAST_ADDR", "SINK_ADDR", "CHECK_ADDR"):
        if name in by_name:
            assert by_name[name].confidence is Confidence.MEASURED, name
    for name in ("TARGET_INDEX", "GUARD_MAX", "TRIGGER_VALUE", "TRIGGER_COUNT",
                 "CAST_MASK", "OFFSET"):
        if name in by_name:
            assert by_name[name].confidence is Confidence.DERIVED, name


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_guard_max_is_never_described_as_a_buffer_size(directory):
    """The disassembly establishes the bound the CHECK enforces.  It does not
    establish the capacity of the destination object, and claiming it does would
    be teaching a false inference from a true observation."""
    wt = _walkthrough(directory)
    by_name = {fact.name: fact for fact in wt.constants}
    assert "GUARD_MAX" in by_name
    detail = (by_name["GUARD_MAX"].evidence.detail or "").lower()
    description = by_name["GUARD_MAX"].description.lower()
    for claim in ("buffer size", "size of the buffer", "byte buffer"):
        assert claim not in description, f"GUARD_MAX described as {claim!r}"
    if wt.taught_route == integer.TRUNCATION:
        assert "not a claim about the size of the destination" in detail


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_renders_to_valid_python_and_markdown(directory):
    wt = _walkthrough(directory)
    text = render_script(wt)
    compile(text, f"<{directory}>", "exec")
    assert "TODO" not in text
    assert "@@" not in text, "an unspliced placeholder survived into the output"
    assert render_markdown(wt).strip()


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_no_absolute_breakpoint_addresses_in_gdb_commands(directory):
    """``break *0x401267`` is right for a no-PIE binary and wrong for a PIE one.
    ``break *(vuln+0x57)`` is right for both, because GDB resolves the symbol
    after relocation."""
    text = render_script(_walkthrough(directory))
    import re

    for match in re.finditer(r'"break \*[^"]*"', text):
        assert "+" in match.group(0), (
            f"absolute breakpoint would be wrong under PIE: {match.group(0)}"
        )


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_verdict_is_a_differential_against_more_than_one_control(directory):
    """A single control is not enough: an input the bounds check REFUSES also
    produces output the benign run does not, so comparing against the benign run
    alone scores the check working correctly as a successful exploit."""
    import ast

    text = render_script(_walkthrough(directory))
    assert "def differential(controls, exploited)" in text

    tree = ast.parse(text)
    # Every list literal assigned in the script, so a call that passes its
    # controls by name can still be checked.  Checking the call sites rather
    # than the presence of a helper is the point: a single-control call reads
    # perfectly and accepts the target's own rejection message as success.
    lists: dict[str, ast.List] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.List)
        ):
            lists[node.targets[0].id] = node.value

    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "differential"
    ]
    assert calls, "the script never calls differential()"
    for call in calls:
        controls = call.args[0]
        if isinstance(controls, ast.Name):
            controls = lists.get(controls.id)
        assert isinstance(controls, ast.List), (
            f"differential() at line {call.lineno} is not passed a list of controls"
        )
        assert len(controls.elts) >= 2, (
            f"differential() at line {call.lineno} is given "
            f"{len(controls.elts)} control run(s); a refused input also produces "
            "output the benign run does not, so one control is not a verdict"
        )

    # And one of those controls has to be the refused input specifically.
    names = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    assert names & {"REJECTED_VALUE", "REJECTED_INDEX"}, (
        "no refused-input control is referenced anywhere in the script"
    )


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_no_flag_string_appears_in_any_executable_literal(directory):
    """``b"flag" in out`` is prohibited as a verdict, so no executable string
    literal in the generated script may mention one.

    Checked over the AST rather than the text: the word appears legitimately in
    ``differential``'s docstring, which explains why self-scoring is banned, and
    a grep would either flag that or be loosened until it flagged nothing.
    """
    import ast

    tree = ast.parse(render_script(_walkthrough(directory)))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or id(node) in docstrings:
            continue
        if isinstance(node.value, (str, bytes)):
            value = (
                node.value
                if isinstance(node.value, str)
                else node.value.decode("latin-1")
            )
            assert "flag" not in value.lower(), (
                f"executable literal {value!r} at line {node.lineno} mentions a "
                "flag; the verdict must be a differential, not a search"
            )


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_instruction_verifier_runs_in_the_complete_exploit_too(directory):
    """``--exploit`` calls ``exploit()`` directly and runs no steps, so a check
    performed only by a diagnostic step is a check the real run skips."""
    wt = _walkthrough(directory)
    assert "def verify_instructions(claims)" in wt.helpers
    assert "CLAIMS = [" in wt.helpers
    assert "verify_instructions(CLAIMS)" in wt.final_exploit


# ---------------------------------------------------------------------------
# literal execution -- rendering is not verification
# ---------------------------------------------------------------------------


def _generate(tmp_path: Path, directory: str) -> Path:
    from supwngo.exploit.walkthrough import explain_binary

    _walkthrough, text = explain_binary(str(_binary(directory)), probe=False)
    script = tmp_path / f"wt_{directory}.py"
    script.write_text(text)
    return script


def _run(script: Path, *args: str, timeout: int = STEP_TIMEOUT):
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(script.parent),
    )


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_generated_walkthrough_lists_its_steps(tmp_path, directory):
    script = _generate(tmp_path, directory)
    done = _run(script, "steps", timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "preflight" in done.stdout


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_every_step_of_the_generated_walkthrough_succeeds(tmp_path, directory):
    """Run each step by number, exactly as the walkthrough tells a reader to.

    Each step decides its own verdict and returns a boolean the runner turns
    into an exit status, so a step that printed reassuring text while proving
    nothing fails here.
    """
    if not _have("gdb"):
        pytest.skip("gdb is required: the wrap and landing steps are GDB probes")
    script = _generate(tmp_path, directory)
    count = len(_walkthrough(directory).steps)
    failures = []
    for number in range(1, count + 1):
        done = _run(script, str(number))
        if done.returncode != 0:
            failures.append(
                f"--- step {number} exited {done.returncode} ---\n"
                + (done.stdout or "")[-3000:]
                + (done.stderr or "")[-2000:]
            )
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("directory", sorted(TARGETS))
def test_complete_exploit_of_the_generated_walkthrough_succeeds(tmp_path, directory):
    """The whole point: the walkthrough is executed, not admired.

    The script's own verdict is a differential against a benign control and a
    refused control, so a zero exit status means it produced output that neither
    control run produced.
    """
    script = _generate(tmp_path, directory)
    done = _run(script, timeout=EXPLOIT_TIMEOUT)
    assert done.returncode == 0, (
        f"the generated exploit failed:\n{(done.stdout or '')[-4000:]}"
        f"\n{(done.stderr or '')[-2000:]}"
    )
    assert "no control run produced this" in done.stdout, (
        "the exploit reported success without a differential gain"
    )


def _have(tool: str) -> bool:
    import shutil

    return shutil.which(tool) is not None
