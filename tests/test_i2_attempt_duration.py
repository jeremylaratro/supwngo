"""
Tests for I2 -- per-attempt duration and profiling-prologue timing.

Plan: docs/plans/2026-09-24-pipeline-instrumentation-pass.md §4 I2, §4.2,
§4.4 Class 2, §5.

Two claims are made by I2 and both need to be shown false-if-broken, per
§5(a): "revert the instrument" catches absence only, so every proof below
also has a *wrong-but-present* counterpart (a hardcoded constant survives
an absence check but must still be caught).

- `AttemptRecord.duration_sec` is wall-clock around the orchestrator's
  `executor.attempt()` call only -- never anything inside an executor's own
  internal loop (`_attempt_techniques` in
  `supwngo/exploit/pipeline/orchestrator.py`). Proven with a two-executor
  differential (§5's m1): a deliberately slow executor's recorded duration
  must exceed a fast one's in the *same* run, not just be nonzero.
- The three profiling-prologue stages (`_run_prologue`, timing what used to
  be inline at `orchestrator.py:186-188`) are timed and attributed
  *separately*, not folded into one number. Proven with three
  distinguishably-slow stages.

Class 1 (docs/plans .../§4.4): both legs here are naturally occurring --
every attempted technique and every run exercises both instruments, so no
induced fixture is needed (contrast I5 below, whose subject never occurs
naturally).

Class 2 (docs/plans .../§4.4): new instrument values must never reach
`record.notes`/`failure_reason` or any text `templates.py` renders into a
generated script, because `benchmark/rep_divergence.py` hashes those
scripts per rep and a duration is not masked by its normaliser. Covered by
`TestDurationNeverEntersNotesOrRenderedScripts` below, mirroring
`tests/test_i3_candidate_provenance.py`'s equivalent guard for candidate
provenance.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import (
    AttemptOutcome, AttemptRecord, Stage, TechniqueExecutor,
)
from supwngo.exploit.pipeline.orchestrator import CanonicalAutopwnEngine
from supwngo.exploit.pipeline.registry import ExecutorRegistry
from supwngo.exploit.pipeline.templates import generate_success_script, generate_universal_template

REPO_ROOT = Path(__file__).resolve().parents[1]


def _bare_engine() -> CanonicalAutopwnEngine:
    """Construct a `CanonicalAutopwnEngine` without running `__init__`'s
    binary-loading/verifier-construction machinery, mirroring
    `tests/test_pipeline_orchestrator.py`'s `_engine()` helper. `run()`'s
    prologue and attempt-loop were split into `_run_prologue()`/
    `_attempt_techniques()` specifically so each half can be driven directly
    like this, without needing a real compiled binary just to exercise the
    orchestrator's own timing/bookkeeping code."""
    engine = CanonicalAutopwnEngine.__new__(CanonicalAutopwnEngine)
    engine.context = ExploitContext()
    engine.successful = False
    engine.technique_used = ""
    engine.final_payload = b""
    engine.exploit_script = ""
    engine.exploit_template = ""
    engine.receipt = None
    engine.best_partial_technique = None
    engine.static_analysis_duration_sec = None
    engine.dynamic_profile_duration_sec = None
    engine.leak_acquisition_duration_sec = None
    return engine


# ---------------------------------------------------------------------------
# Per-attempt duration: two-executor differential (§5 "I2" row, m1)
# ---------------------------------------------------------------------------

class _InstantExecutor(TechniqueExecutor):
    name = "instant_dummy"

    def attempt(self, context, verifier) -> AttemptRecord:
        return AttemptRecord(technique=self.name, outcome=AttemptOutcome.FAILED)


class _SleepingExecutor(TechniqueExecutor):
    """A `TechniqueExecutor` whose `attempt()` deliberately takes
    `sleep_s` wall-clock seconds -- the "one executor is deliberately
    slowed" half of the required differential."""

    def __init__(self, name: str, sleep_s: float) -> None:
        self.name = name
        self.sleep_s = sleep_s

    def attempt(self, context, verifier) -> AttemptRecord:
        time.sleep(self.sleep_s)
        return AttemptRecord(technique=self.name, outcome=AttemptOutcome.FAILED)


def _run_two_executor_differential(sleep_s: float) -> tuple:
    registry = ExecutorRegistry()
    registry.register(_InstantExecutor())
    slow = _SleepingExecutor("slow_dummy", sleep_s)
    registry.register(slow)

    engine = _bare_engine()
    engine.registry = registry
    engine._verifier = None  # the dummy executors never touch it

    engine._attempt_techniques(["instant_dummy", "slow_dummy"])

    by_name = {a.technique: a for a in engine.context.attempts}
    return by_name["instant_dummy"], by_name["slow_dummy"]


class TestPerAttemptDurationDifferential:
    """§5 m1: 'assert two executors in the same run record *different*
    durations and that the sleeping one's exceeds the other's. A single
    whole-run duration stamped onto every record fails this.'"""

    def test_two_executors_in_the_same_run_record_different_durations(self):
        fast, slow = _run_two_executor_differential(sleep_s=0.2)

        assert fast.duration_sec is not None
        assert slow.duration_sec is not None
        assert slow.duration_sec > fast.duration_sec, (
            f"deliberately slowed executor ({slow.duration_sec}s) did not "
            f"exceed the fast one ({fast.duration_sec}s) -- a stamped "
            f"whole-run constant would pass the presence check but fail "
            f"exactly this comparison")
        # The slow executor's recorded time must actually reflect its sleep,
        # not merely be "some bigger number" -- rules out e.g. a duration
        # that scales with attempt *index* rather than wall time.
        assert slow.duration_sec >= 0.2
        assert fast.duration_sec < 0.1

    def test_a_longer_deliberate_sleep_yields_a_larger_recorded_duration(self):
        """Second, independent magnitude check: not just 'slow > fast' once,
        but that the recorded value tracks the actual sleep duration across
        two different sleep lengths -- a constant 'big number' for any slow
        executor would pass the first test but fail this one."""
        _, slow_short = _run_two_executor_differential(sleep_s=0.1)
        _, slow_long = _run_two_executor_differential(sleep_s=0.35)

        assert slow_long.duration_sec > slow_short.duration_sec

    def test_applicability_check_alone_never_produces_a_duration(self):
        """A SKIPPED record (is_applicable() False, attempt() never called)
        must carry no duration -- duration_sec is specifically wall-clock
        around attempt(), not around the whole per-technique iteration."""
        class _NeverApplicable(TechniqueExecutor):
            name = "never_applicable"

            def is_applicable(self, context) -> bool:
                return False

            def attempt(self, context, verifier) -> AttemptRecord:
                raise AssertionError("attempt() must not be called")

        registry = ExecutorRegistry()
        registry.register(_NeverApplicable())
        engine = _bare_engine()
        engine.registry = registry
        engine._verifier = None
        engine._attempt_techniques(["never_applicable"])

        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.SKIPPED
        assert record.duration_sec is None

    def test_an_error_raising_executor_still_gets_a_duration(self):
        """`attempt()` raising is caught by the orchestrator and turned into
        an ERROR record (contracts.py's documented contract) -- the timer
        must still have been running around the call that raised, not
        skipped because the happy path didn't complete."""
        class _Raises(TechniqueExecutor):
            name = "raises_dummy"

            def attempt(self, context, verifier) -> AttemptRecord:
                time.sleep(0.05)
                raise RuntimeError("boom")

        registry = ExecutorRegistry()
        registry.register(_Raises())
        engine = _bare_engine()
        engine.registry = registry
        engine._verifier = None
        engine._attempt_techniques(["raises_dummy"])

        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.ERROR
        assert record.duration_sec is not None
        assert record.duration_sec >= 0.05


# ---------------------------------------------------------------------------
# Profiling-prologue timing: three distinguishable, separately-attributed
# stages (§5 "prologue time is non-zero and separately attributed")
# ---------------------------------------------------------------------------

class TestPrologueTiming:
    def test_three_stages_are_timed_separately_and_track_their_own_cost(
            self, monkeypatch):
        """A hardcoded/constant duration for all three stages would pass a
        bare 'non-zero' check; this asserts each stage's recorded duration
        tracks *that stage's own* injected cost, ordered fast -> slow ->
        slower, which a shared constant cannot reproduce."""
        import supwngo.exploit.pipeline.orchestrator as orch_mod

        def fake_static_analysis(context):
            time.sleep(0.05)

        def fake_dynamic_profile(context, timeout=2.0):
            time.sleep(0.15)

        def fake_acquire_leaks(context):
            time.sleep(0.30)

        monkeypatch.setattr(orch_mod, "run_static_analysis", fake_static_analysis)
        monkeypatch.setattr(orch_mod, "run_dynamic_profile", fake_dynamic_profile)
        monkeypatch.setattr(orch_mod, "acquire_leaks", fake_acquire_leaks)

        engine = _bare_engine()
        engine.timeout = 5.0
        engine._run_prologue()

        assert engine.static_analysis_duration_sec is not None
        assert engine.dynamic_profile_duration_sec is not None
        assert engine.leak_acquisition_duration_sec is not None

        # Non-zero (the weak check the previous revision over-relied on)...
        assert engine.static_analysis_duration_sec > 0
        assert engine.dynamic_profile_duration_sec > 0
        assert engine.leak_acquisition_duration_sec > 0

        # ...but also tracking each stage's own injected cost, and therefore
        # distinct from one another -- the mutation this catches that a bare
        # non-zero check would not: all three set to the same constant.
        assert engine.static_analysis_duration_sec >= 0.05
        assert engine.dynamic_profile_duration_sec >= 0.15
        assert engine.leak_acquisition_duration_sec >= 0.30
        assert (engine.static_analysis_duration_sec
                < engine.dynamic_profile_duration_sec
                < engine.leak_acquisition_duration_sec)

    def test_prologue_precedes_and_is_independent_of_any_attempt_duration(
            self, monkeypatch):
        """I2's scope correction (§4 I2, M5): prologue timing exists
        specifically because it precedes the first attempt() and therefore
        cannot be derived from per-attempt durations. Confirm the two are
        independent fields, not aliases of one another."""
        import supwngo.exploit.pipeline.orchestrator as orch_mod

        monkeypatch.setattr(orch_mod, "run_static_analysis",
                             lambda context: time.sleep(0.02))
        monkeypatch.setattr(orch_mod, "run_dynamic_profile",
                             lambda context, timeout=2.0: time.sleep(0.02))
        monkeypatch.setattr(orch_mod, "acquire_leaks",
                             lambda context: time.sleep(0.02))

        registry = ExecutorRegistry()
        registry.register(_SleepingExecutor("slow_dummy", 0.2))
        engine = _bare_engine()
        engine.timeout = 5.0
        engine.registry = registry
        engine._verifier = None

        engine._run_prologue()
        engine._attempt_techniques(["slow_dummy"])

        prologue_total = (engine.static_analysis_duration_sec
                           + engine.dynamic_profile_duration_sec
                           + engine.leak_acquisition_duration_sec)
        attempt_duration = engine.context.attempts[0].duration_sec

        # The attempt's 0.2s sleep must not have leaked into the ~0.06s
        # prologue total, and vice versa -- they are recorded independently.
        assert prologue_total < 0.15
        assert attempt_duration >= 0.2


# ---------------------------------------------------------------------------
# Artifact-level assertions (M6): a field not in to_dict() never reaches
# autopwn_json_probe.parsed.attempts in report.json.
# ---------------------------------------------------------------------------

class TestDurationReachesToDictAndSurvivesJson:
    def test_duration_present_and_round_trips_through_json(self):
        record = AttemptRecord(
            technique="ret2win", outcome=AttemptOutcome.SUCCESS,
            stage_reached=Stage.VERIFICATION, duration_sec=1.234567,
        )
        d = record.to_dict()
        assert "duration_sec" in d

        rehydrated = json.loads(json.dumps(d))
        assert rehydrated["duration_sec"] == pytest.approx(1.234567)

    def test_absent_duration_serialises_as_null_key_still_present(self):
        """A SKIPPED record (attempt() never called) has duration_sec=None
        -- the key must still exist (M6: to_dict() is an explicit dict
        literal), distinguishing 'no duration' from 'field does not exist
        in this schema version', same standard as I3's equivalent test."""
        record = AttemptRecord(technique="x", outcome=AttemptOutcome.SKIPPED)
        d = record.to_dict()
        assert "duration_sec" in d
        assert d["duration_sec"] is None
        rehydrated = json.loads(json.dumps(d))
        assert rehydrated["duration_sec"] is None

    def test_real_orchestrator_attempt_record_serialises_its_duration(self):
        """End-to-end through the real orchestrator loop (not a hand-built
        AttemptRecord), same standard test_i3 holds its real-executor path
        to."""
        registry = ExecutorRegistry()
        registry.register(_SleepingExecutor("slow_dummy", 0.05))
        engine = _bare_engine()
        engine.registry = registry
        engine._verifier = None
        engine._attempt_techniques(["slow_dummy"])

        record = engine.context.attempts[0]
        d = record.to_dict()
        rehydrated = json.loads(json.dumps(d))
        assert rehydrated["duration_sec"] >= 0.05


# ---------------------------------------------------------------------------
# Class 2 invariant (§4.4): duration must never enter notes/failure_reason
# or any templates.py-rendered text.
# ---------------------------------------------------------------------------

def _fake_binary(bits: int = 64) -> SimpleNamespace:
    return SimpleNamespace(path=Path("/tmp/vuln"), bits=bits)


class TestDurationNeverEntersNotesOrRenderedScripts:
    def test_templates_source_never_reads_duration_sec(self):
        """Structural guard mirroring test_i3_candidate_provenance.py's
        equivalent: templates.py must never read AttemptRecord.duration_sec,
        because doing so would put timing text into a generated script that
        rep_divergence.py hashes per rep -- exactly the Class 2 hazard this
        instrument must not reintroduce."""
        templates_src = (REPO_ROOT / "supwngo" / "exploit" / "pipeline"
                          / "templates.py").read_text()
        assert "duration_sec" not in templates_src

    def test_generate_success_script_output_is_unaffected_by_duration(self):
        ctx = SimpleNamespace(binary=_fake_binary())
        base = dict(technique="ret2win", outcome=AttemptOutcome.SUCCESS,
                    payload=b"A" * 8, offset=40, notes=["target=win offset=40"])
        record_no_duration = AttemptRecord(**base, duration_sec=None)
        record_with_duration = AttemptRecord(**base, duration_sec=987.654321)

        script_a = generate_success_script(ctx, record_no_duration)
        script_b = generate_success_script(ctx, record_with_duration)

        assert script_a == script_b, (
            "a generated script changed based only on duration_sec -- this "
            "is exactly the per-rep divergence hazard §4.4 Class 2 exists "
            "to prevent")
        assert "987.654321" not in script_b
        assert "duration" not in script_b.lower()

    def test_generate_universal_template_output_is_unaffected_by_duration(self):
        def _fake_context(duration):
            binary = SimpleNamespace(
                path=Path("/tmp/vuln"), bits=64,
                protections=SimpleNamespace(nx=True, canary=True, pie=True, relro="full"),
            )
            return SimpleNamespace(
                binary=binary, win_function=None, leaks={}, gadgets={},
                profile_prompts=[], offset=None,
                attempts=[AttemptRecord(technique="ret2win",
                                        outcome=AttemptOutcome.FAILED,
                                        duration_sec=duration)],
            )

        template_no_duration = generate_universal_template(_fake_context(None))
        template_with_duration = generate_universal_template(_fake_context(42.5))

        assert template_no_duration == template_with_duration
        assert "42.5" not in template_with_duration


# ---------------------------------------------------------------------------
# Class 2 red-proof (§4.4): if a duration DID leak into `notes`, prove
# rep_divergence.py would actually catch it. Complements the structural
# guard above with the "prove it can go red" requirement, using the real
# rendering path (generate_success_script) rather than asserting on the
# tool in the abstract -- run_bench.py itself is untouched, per §9.1.
# ---------------------------------------------------------------------------

class TestClass2RedProofIfDurationLeakedIntoNotes:
    def test_a_duration_string_in_notes_would_make_rep_divergence_fire(
            self, tmp_path):
        import subprocess
        import sys

        ctx = SimpleNamespace(binary=_fake_binary())
        rep_durations = [12.473, 14.892, 13.001]
        results_dir = tmp_path
        (results_dir / "report.json").write_text(
            '{"reps": 3, "results": [{"slug": "t_dur", "status": "FAILED"}]}')
        for i, dur in enumerate(rep_durations, start=1):
            rep_dir = results_dir / f"rep{i}"
            rep_dir.mkdir()
            record = AttemptRecord(
                technique="variable_overwrite", outcome=AttemptOutcome.FAILED,
                payload=b"A" * 40,
                # Simulates the counterfactual this test exists to rule out:
                # a duration folded into `notes` (never done by the real
                # I2 code -- see the structural guard above).
                notes=[f"duration={dur}"],
            )
            script = generate_success_script(ctx, record)
            (rep_dir / "t_dur_generated.py").write_text(script)

        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "benchmark" / "rep_divergence.py"),
             str(results_dir)],
            capture_output=True, text=True,
        )
        assert "DIVERGENT" in proc.stdout, proc.stdout
        assert proc.returncode == 1, (
            "a per-rep duration string in notes must be caught as "
            f"divergent -- this is what protects the real invariant that "
            f"I2 keeps duration_sec OUT of notes entirely:\n{proc.stdout}")
