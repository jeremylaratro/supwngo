"""
Tests for I3 -- candidate provenance on `VariableOverwriteExecutor`.

Plan: docs/plans/2026-09-24-pipeline-instrumentation-pass.md §4 I3, §4.4
Class 1/Class 2, §5, gated per M4/M10.

`VariableOverwriteExecutor` (supwngo/exploit/pipeline/executors/
stack_techniques.py) wins 0 of 17 credited R1/R2 targets and returns FAILED
on all 12 target-runs where it executes, so no existing corpus target
exercises a swept SUCCESS -- a provenance gate written against real R1/R2
data cannot be proven red on anything. These tests build two small,
purpose-made, genuinely vulnerable C targets (tests/fixtures/
i3_candidate_provenance/) instead:

- Fixture A: the gate constant IS one of the nine MAGIC_VALUES, so the sweep
  genuinely wins and provenance must read "literal_magic_list" (the
  positive control).
- Fixture B: the gate constant is deliberately NOT in MAGIC_VALUES, so the
  sweep provably cannot win it (the vulnerability is real -- sending the
  correct value at the correct offset does win it, verified below -- but no
  MAGIC_VALUES entry will ever produce that value). This is what makes
  "swept" a provable claim rather than a label applied regardless of what
  happened.

Both fixtures' (buffer_size, magic) hit set was established empirically
against the compiled binaries (not assumed) during authoring; the tests
below re-derive it themselves rather than trusting that record.
"""
from __future__ import annotations

import dataclasses
import struct
import subprocess
from pathlib import Path

import pytest

from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import (
    CANDIDATE_SOURCE_LITERAL_MAGIC_LIST,
    AttemptOutcome,
    AttemptRecord,
)
from supwngo.exploit.pipeline.executors.stack_techniques import (
    MAGIC_VALUES,
    VariableOverwriteExecutor,
)
from supwngo.exploit.pipeline.verifier import PipelineVerifier

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "i3_candidate_provenance"
FIXTURE_A_SRC = FIXTURE_DIR / "fixture_a_magic_in_list.c"
FIXTURE_B_SRC = FIXTURE_DIR / "fixture_b_magic_not_in_list.c"

# Ground truth for the compiled fixtures -- the offset/magic the sweep is
# expected to hit for A, and the (real, but un-swept) gate value for B. Kept
# here rather than only inside the .c comments so the tests assert against a
# value independent of the source file's prose.
FIXTURE_A_WIN_OFFSET = 60
FIXTURE_A_WIN_MAGIC = 0xCAFEBABE
FIXTURE_B_GATE_VALUE = 0x12345678

CC_FLAGS = ["-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", "-g"]


def _compile(src: Path, out: Path) -> Path:
    subprocess.run(
        ["gcc", *CC_FLAGS, "-o", str(out), str(src)],
        check=True, capture_output=True, text=True,
    )
    assert out.is_file(), f"gcc did not produce {out}"
    return out


@pytest.fixture(scope="module")
def fixture_a_binary(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("i3_fixture_a")
    return _compile(FIXTURE_A_SRC, d / "fixture_a")


@pytest.fixture(scope="module")
def fixture_b_binary(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("i3_fixture_b")
    return _compile(FIXTURE_B_SRC, d / "fixture_b")


def _run_target_directly(binary: Path, payload: bytes) -> str:
    """Bypass the executor entirely -- run the compiled target with a raw
    payload, exactly as VerificationLevel's OUTPUT_MATCH check would see it.
    Used to independently re-derive ground truth rather than trusting the
    docstring's claim."""
    r = subprocess.run([str(binary)], input=payload, capture_output=True, timeout=5)
    return (r.stdout + r.stderr).decode("latin-1", "ignore")


def _attempt_variable_overwrite(binary: Path) -> AttemptRecord:
    """Run the real, unmodified VariableOverwriteExecutor against a compiled
    fixture through the real PipelineVerifier -- no mocking of the
    executor's sweep or the verifier's success determination.

    Expensive: every non-winning payload falls through
    ExploitVerifier._verify_with_pwntools (supwngo/exploit/verification.py),
    which carries ~0.8s of fixed time.sleep() per attempt. A full 126-combo
    sweep (fixture B, which never wins) costs minutes. Callers MUST go
    through the module-scoped `record_a`/`record_b` fixtures below rather
    than calling this directly, so each fixture is attempted exactly once
    for the whole test module.
    """
    context = ExploitContext()
    verifier = PipelineVerifier(str(binary), timeout=5.0, static_preflight=False)
    return VariableOverwriteExecutor().attempt(context, verifier)


@pytest.fixture(scope="module")
def record_a(fixture_a_binary) -> AttemptRecord:
    return _attempt_variable_overwrite(fixture_a_binary)


@pytest.fixture(scope="module")
def record_b(fixture_b_binary) -> AttemptRecord:
    return _attempt_variable_overwrite(fixture_b_binary)


class TestFixturesAreGenuineVulnerabilities:
    """Independent re-derivation of each fixture's ground truth, run before
    trusting the executor's own verdict on them."""

    def test_fixture_a_is_won_by_exactly_one_sweep_combination(self, fixture_a_binary):
        hits = []
        for buf_size in [32, 40, 48, 56, 60, 64, 72, 80, 96, 100, 104, 112, 120, 128]:
            for magic in MAGIC_VALUES:
                payload = b"A" * buf_size + struct.pack("<I", magic) + b"\n"
                if "win" in _run_target_directly(fixture_a_binary, payload).lower():
                    hits.append((buf_size, magic))
        assert hits == [(FIXTURE_A_WIN_OFFSET, FIXTURE_A_WIN_MAGIC)], (
            "fixture A must be won by exactly the documented (offset, magic) "
            f"pair and nothing else in the 14x9 sweep space; got {hits}")

    def test_fixture_b_real_vulnerability_but_unreachable_by_the_sweep(
            self, fixture_b_binary):
        # The bug is real: the correct (un-swept) value does win it.
        control_payload = (b"A" * FIXTURE_A_WIN_OFFSET
                           + struct.pack("<I", FIXTURE_B_GATE_VALUE) + b"\n")
        assert "win" in _run_target_directly(fixture_b_binary, control_payload).lower(), (
            "fixture B must be a genuine, winnable overflow -- otherwise a "
            "sweep failing on it proves nothing")
        # But no MAGIC_VALUES entry reaches it.
        assert FIXTURE_B_GATE_VALUE not in MAGIC_VALUES
        for buf_size in [32, 40, 48, 56, 60, 64, 72, 80, 96, 100, 104, 112, 120, 128]:
            for magic in MAGIC_VALUES:
                payload = b"A" * buf_size + struct.pack("<I", magic) + b"\n"
                assert "win" not in _run_target_directly(fixture_b_binary, payload).lower(), (
                    f"fixture B was won by a swept (offset={buf_size}, "
                    f"magic={hex(magic)}) pair -- it must be un-winnable by "
                    f"the fixed MAGIC_VALUES sweep for this fixture to work "
                    f"as a negative control")


class _StubReceipt:
    def __init__(self, success: bool) -> None:
        self.success = success


class _WinsOnOneCandidateVerifier:
    """A `verify_payload` double that succeeds for exactly one
    (buffer_size, magic) combination.

    Complementary to the real-binary fixtures above, not a replacement:
    those prove genuineness end-to-end through the real, unmodified
    verifier; this proves the NARROWER claim that
    `record.candidate_provenance.value` tracks whichever candidate the
    sweep actually won on, without paying ExploitVerifier's
    ~0.8s-per-attempt pwntools fallback (supwngo/exploit/verification.py)
    for every one of the up to 126 combinations tried before it.
    """

    def __init__(self, winning_buf_size: int, winning_magic: int) -> None:
        self.winning_buf_size = winning_buf_size
        self.winning_magic = winning_magic

    def verify_payload(self, technique: str, payload: bytes):
        # payload shape from VariableOverwriteExecutor.attempt():
        # b'A' * buf_size + struct.pack('<I', magic) + b'\n'
        body = payload[:-1]  # drop the trailing '\n'
        buf_size = len(body) - 4
        magic = struct.unpack("<I", body[buf_size:buf_size + 4])[0]
        return _StubReceipt(
            success=(buf_size == self.winning_buf_size and magic == self.winning_magic))


class TestCandidateProvenanceTracksWhicheverCandidateWon:
    """§5 I3 proof: 'assert the record names the winning candidate and its
    source, and that a DIFFERENT candidate yields a different record.'

    Fast (in-process, no subprocess spawned) complement to the real-binary
    tests below -- a hardcoded provenance value would pass a single-fixture
    check but fail this differential, which is exactly this project's
    signature "instrument present but measures nothing" defect shape.
    """

    @pytest.mark.parametrize("buf_size,magic", [
        (32, MAGIC_VALUES[0]),
        (128, MAGIC_VALUES[-1]),
    ])
    def test_recorded_value_matches_whichever_candidate_won(self, buf_size, magic):
        context = ExploitContext()
        verifier = _WinsOnOneCandidateVerifier(winning_buf_size=buf_size,
                                               winning_magic=magic)
        record = VariableOverwriteExecutor().attempt(context, verifier)

        assert record.outcome == AttemptOutcome.SUCCESS
        assert record.offset == buf_size
        assert record.candidate_provenance is not None
        assert record.candidate_provenance.source == CANDIDATE_SOURCE_LITERAL_MAGIC_LIST
        assert record.candidate_provenance.value == magic

    def test_two_different_winning_candidates_yield_different_provenance(self):
        r1 = VariableOverwriteExecutor().attempt(
            ExploitContext(),
            _WinsOnOneCandidateVerifier(winning_buf_size=32, winning_magic=MAGIC_VALUES[0]))
        r2 = VariableOverwriteExecutor().attempt(
            ExploitContext(),
            _WinsOnOneCandidateVerifier(winning_buf_size=128, winning_magic=MAGIC_VALUES[-1]))

        assert r1.candidate_provenance.value == MAGIC_VALUES[0]
        assert r2.candidate_provenance.value == MAGIC_VALUES[-1]
        assert r1.candidate_provenance.value != r2.candidate_provenance.value
        assert r1.offset != r2.offset


class TestCandidateProvenanceOnRealAttempts:
    """The actual I3 assertions: run the real executor and check
    candidate_provenance -- both in-process and at the to_dict()/artifact
    level (M6)."""

    def test_fixture_a_success_records_literal_magic_list_provenance(
            self, record_a):
        record = record_a

        assert record.outcome == AttemptOutcome.SUCCESS
        assert record.offset == FIXTURE_A_WIN_OFFSET
        assert record.candidate_provenance is not None, (
            "a genuine swept SUCCESS must carry provenance")
        assert record.candidate_provenance.source == CANDIDATE_SOURCE_LITERAL_MAGIC_LIST
        assert record.candidate_provenance.value == FIXTURE_A_WIN_MAGIC

    def test_fixture_a_provenance_reaches_to_dict_and_survives_json(
            self, record_a):
        """M6: a field not in to_dict() never reaches
        autopwn_json_probe.parsed.attempts in report.json. Assert at the
        artifact level, round-tripped through json, not only on the
        in-memory object."""
        import json

        d = record_a.to_dict()
        assert "candidate_provenance" in d
        # Simulate the artifact boundary: this dict is exactly what
        # supwngo.cli's --json path serialises into
        # autopwn_json_probe.parsed.attempts[].
        rehydrated = json.loads(json.dumps(d))
        prov = rehydrated["candidate_provenance"]
        assert prov is not None
        assert prov["source"] == CANDIDATE_SOURCE_LITERAL_MAGIC_LIST
        assert prov["value"] == hex(FIXTURE_A_WIN_MAGIC)

    def test_fixture_b_sweep_fails_and_carries_no_provenance(self, record_b):
        record = record_b

        assert record.outcome == AttemptOutcome.FAILED
        assert record.candidate_provenance is None
        # Nothing to attribute: the sweep exhausted every candidate it has.
        assert record.payload == b""

    def test_fixture_b_to_dict_provenance_is_null_not_omitted(self, record_b):
        d = record_b.to_dict()
        assert "candidate_provenance" in d, (
            "the key must always be present (null when absent), so a "
            "consumer reading report.json can distinguish 'no provenance' "
            "from 'field does not exist in this schema version'")
        assert d["candidate_provenance"] is None


class TestProvenanceNeverEntersNotesOrRenderedScripts:
    """§4.4 Class 2 invariant: new instrument values go into structured
    fields and to_dict() only, never into `notes`/`failure_reason`, which
    `templates.py` renders into generated exploit scripts that
    `rep_divergence.py` hashes per rep."""

    def test_success_notes_do_not_contain_the_provenance_source_label(
            self, record_a):
        joined_notes = " ".join(record_a.notes)
        assert CANDIDATE_SOURCE_LITERAL_MAGIC_LIST not in joined_notes
        assert "candidate_provenance" not in joined_notes

    def test_failure_reason_is_unaffected(self, record_a, record_b):
        assert record_a.failure_reason == ""
        assert CANDIDATE_SOURCE_LITERAL_MAGIC_LIST not in record_b.failure_reason

    def test_templates_render_path_does_not_touch_candidate_provenance(self):
        """Structural guard: templates.py's generated-script rendering reads
        only failure_reason/offset/target_addr/notes off a record (see
        templates.py:38,141,143,145) -- candidate_provenance must not be
        added to that surface."""
        templates_src = Path(__file__).resolve().parent.parent / \
            "supwngo" / "exploit" / "pipeline" / "templates.py"
        text = templates_src.read_text()
        assert "candidate_provenance" not in text, (
            "templates.py must never read candidate_provenance -- doing so "
            "would put swept-value text into a generated script that "
            "rep_divergence.py hashes per rep, exactly the Class 2 hazard "
            "this instrument must not reintroduce")


# ---------------------------------------------------------------------------
# The required-provenance gate (M4), conditioned per M10/Class 1: never
# asserted on an attempt that neither succeeded nor produced a payload.
# ---------------------------------------------------------------------------

def _provenance_gate(records: dict, expected_by_target: dict) -> None:
    """Assert provenance on attempts that occurred.

    `expected_by_target[target]` is the required CandidateProvenance.source,
    or None if that target's attempt is expected to carry no provenance.
    A target whose attempt never reached SUCCESS and never produced a
    payload is skipped entirely -- variable_overwrite FAILs on all 12
    target-runs where it executes across R1/R2 with no payload produced, and
    an unconditional gate would red all 13 R1 targets (M10).
    """
    for target, record in records.items():
        attempted = (record.outcome == AttemptOutcome.SUCCESS
                    or len(record.payload) > 0)
        if not attempted:
            continue
        expected_source = expected_by_target[target]
        actual_source = (record.candidate_provenance.source
                         if record.candidate_provenance else None)
        assert actual_source == expected_source, (
            f"{target}: provenance {'missing' if actual_source is None else 'mismatch'} "
            f"-- expected {expected_source!r}, got {actual_source!r}")


class TestRequiredProvenanceGate:
    def test_gate_passes_against_both_real_fixtures(self, record_a, record_b):
        records = {"fixture_a": record_a, "fixture_b": record_b}
        expected = {"fixture_a": CANDIDATE_SOURCE_LITERAL_MAGIC_LIST,
                    "fixture_b": None}
        _provenance_gate(records, expected)  # must not raise

    def test_gate_is_never_asserted_across_attempts_that_never_occurred(self):
        """The R1-scale check: 13 variable_overwrite attempts that all FAILed
        with no payload (matching the real R1 corpus) must not red an
        unconditional gate -- and here `expected` doesn't even carry an
        entry for them, proving the gate never looks."""
        records = {
            f"target_{i:02d}": AttemptRecord(
                technique="variable_overwrite", outcome=AttemptOutcome.FAILED)
            for i in range(13)
        }
        _provenance_gate(records, expected_by_target={})  # must not KeyError/raise

    def test_gate_reds_on_missing_provenance(self, record_a, record_b):
        """Red-proof 1: delete provenance from fixture A's success.

        Copies record_a rather than mutating the shared module-scoped
        fixture (which other tests in this module also read).
        """
        a = dataclasses.replace(record_a, candidate_provenance=None)
        records = {"fixture_a": a, "fixture_b": record_b}
        expected = {"fixture_a": CANDIDATE_SOURCE_LITERAL_MAGIC_LIST,
                    "fixture_b": None}
        with pytest.raises(AssertionError, match="missing"):
            _provenance_gate(records, expected)

    def test_gate_reds_on_mismatched_expected_source(self, record_a, record_b):
        """Red-proof 2: swap fixture A's and B's expected sources."""
        records = {"fixture_a": record_a, "fixture_b": record_b}
        correct_expected = {"fixture_a": CANDIDATE_SOURCE_LITERAL_MAGIC_LIST,
                            "fixture_b": None}
        swapped_expected = {
            "fixture_a": correct_expected["fixture_b"],
            "fixture_b": correct_expected["fixture_a"],
        }
        with pytest.raises(AssertionError, match="mismatch"):
            _provenance_gate(records, swapped_expected)
