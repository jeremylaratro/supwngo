"""
Tests for the structured hand-off report (Phase 4 of
docs/plans/2026-09-23-effectiveness-and-usability.md).

Covers `supwngo/exploit/pipeline/handoff.py`: the `AttemptDetail`/
`BestPartial`/`SuggestedStep`/`HandoffReport` dataclasses, blocking-unknown
derivation grounded in actual `ExploitContext` state + attempted
techniques, and `build_handoff_report()` assembling all of it from a
finished engine run.
"""

from types import SimpleNamespace

import pytest

from supwngo.core.binary import Protections
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import AttemptOutcome, AttemptRecord, Stage
from supwngo.exploit.pipeline.handoff import (
    AttemptDetail,
    BestPartial,
    HandoffReport,
    SuggestedStep,
    build_handoff_report,
    derive_blocking_unknowns,
)
from supwngo.exploit.strategy import ExploitApproach, ExploitStrategy, StrategyReport


class TestAttemptDetail:
    def test_to_dict(self):
        detail = AttemptDetail(
            technique="ret2win",
            outcome="FAILED",
            stage_reached="DELIVERY",
            failure_reason="offset unknown",
            notes=["tried common offsets"],
        )
        d = detail.to_dict()
        assert d["technique"] == "ret2win"
        assert d["outcome"] == "FAILED"
        assert d["stage_reached"] == "DELIVERY"
        assert d["failure_reason"] == "offset unknown"
        assert d["notes"] == ["tried common offsets"]


class TestDeriveBlockingUnknowns:
    def _context(self, **protection_overrides) -> ExploitContext:
        ctx = ExploitContext(protections=Protections(**protection_overrides))
        return ctx

    def test_no_attempts_no_unknowns(self):
        ctx = self._context(pie=True, canary=True)
        assert derive_blocking_unknowns(ctx) == []

    def test_pie_unleaked_flagged_when_relevant_technique_attempted(self):
        ctx = self._context(pie=True)
        ctx.attempts.append(AttemptRecord(
            technique="ret2win", outcome=AttemptOutcome.FAILED,
            stage_reached=Stage.DELIVERY,
        ))
        unknowns = derive_blocking_unknowns(ctx)
        assert "PIE base not leaked" in unknowns

    def test_pie_unleaked_not_flagged_when_only_skipped(self):
        ctx = self._context(pie=True)
        ctx.attempts.append(AttemptRecord(
            technique="ret2win", outcome=AttemptOutcome.SKIPPED,
            failure_reason="not applicable to this target",
        ))
        assert derive_blocking_unknowns(ctx) == []

    def test_pie_leaked_not_flagged(self):
        ctx = self._context(pie=True)
        ctx.leaks["pie"] = 0x555555554000
        ctx.attempts.append(AttemptRecord(
            technique="ret2win", outcome=AttemptOutcome.FAILED,
        ))
        assert "PIE base not leaked" not in derive_blocking_unknowns(ctx)

    def test_libc_unleaked_flagged_for_ret2libc(self):
        ctx = self._context()
        ctx.attempts.append(AttemptRecord(
            technique="ret2libc", outcome=AttemptOutcome.PARTIAL,
        ))
        assert "libc base not leaked" in derive_blocking_unknowns(ctx)

    def test_libc_not_flagged_for_static_binary(self):
        ctx = self._context()
        ctx.binary = SimpleNamespace(protections=SimpleNamespace(static=True))
        ctx.attempts.append(AttemptRecord(
            technique="ret2libc", outcome=AttemptOutcome.PARTIAL,
        ))
        assert "libc base not leaked" not in derive_blocking_unknowns(ctx)

    def test_canary_unknown_flagged(self):
        ctx = self._context(canary=True)
        ctx.attempts.append(AttemptRecord(
            technique="ret2win", outcome=AttemptOutcome.FAILED,
        ))
        assert "stack canary value unknown" in derive_blocking_unknowns(ctx)

    def test_offset_missing_flagged(self):
        ctx = self._context()
        ctx.attempts.append(AttemptRecord(
            technique="direct_shellcode", outcome=AttemptOutcome.FAILED,
        ))
        assert "buffer-to-return-address offset not determined" in derive_blocking_unknowns(ctx)

    def test_offset_known_not_flagged(self):
        ctx = self._context()
        ctx.offset = 72
        ctx.attempts.append(AttemptRecord(
            technique="direct_shellcode", outcome=AttemptOutcome.FAILED,
        ))
        assert "buffer-to-return-address offset not determined" not in derive_blocking_unknowns(ctx)

    def test_format_string_technique_irrelevant_to_offset_fact(self):
        # format_string isn't in the offset fact's relevant-technique set -
        # its own PARTIAL shouldn't spuriously report a missing offset.
        ctx = self._context()
        ctx.attempts.append(AttemptRecord(
            technique="format_string", outcome=AttemptOutcome.PARTIAL,
        ))
        assert derive_blocking_unknowns(ctx) == []


class TestHandoffReportSchema:
    def test_to_dict_has_frozen_top_level_keys(self):
        report = HandoffReport(binary_path="/bin/x", success=False)
        d = report.to_dict()
        assert set(d.keys()) == {
            "schema_version", "binary_path", "success", "verification_level",
            "flag", "technique_used", "attempts_detail", "blocking_unknowns",
            "best_partial", "suggested_next_steps", "strategy_warnings",
        }
        assert d["schema_version"] == 1
        assert d["best_partial"] is None
        assert d["attempts_detail"] == []

    def test_best_partial_to_dict(self):
        bp = BestPartial(source="attempt:ret2win", technique="ret2win",
                          kind="exploit_script", content="print('x')")
        assert bp.to_dict() == {
            "source": "attempt:ret2win", "technique": "ret2win",
            "kind": "exploit_script", "content": "print('x')",
        }

    def test_suggested_step_to_dict(self):
        step = SuggestedStep(
            approach="RET2WIN", priority=1, confidence=0.9,
            description="desc", requirements=["r1"], notes=["n1"], steps=["s1"],
        )
        d = step.to_dict()
        assert d["approach"] == "RET2WIN"
        assert d["related_attempt_failure_reason"] is None


class _FakeEngine:
    """Minimal stand-in for `CanonicalAutopwnEngine` exposing exactly the
    attributes `build_handoff_report` reads, so these tests don't need a
    real compiled binary/ELF to load."""

    def __init__(self, context, strategy_report=None, successful=False,
                 technique_used="", exploit_script="", exploit_template="",
                 best_partial_technique=None):
        self.binary = SimpleNamespace(path="/bin/x")
        self.context = context
        self.strategy_report = strategy_report
        self.successful = successful
        self.technique_used = technique_used
        self.exploit_script = exploit_script
        self.exploit_template = exploit_template
        self.best_partial_technique = best_partial_technique


class TestBuildHandoffReport:
    def test_successful_run_has_no_extras(self):
        ctx = ExploitContext()
        ctx.attempts.append(AttemptRecord(technique="ret2win", outcome=AttemptOutcome.SUCCESS))
        engine = _FakeEngine(ctx, successful=True, technique_used="ret2win")
        report = build_handoff_report(engine)
        assert report.success is True
        assert report.blocking_unknowns == []
        assert report.best_partial is None
        assert report.suggested_next_steps == []
        assert len(report.attempts_detail) == 1

    def test_failed_run_prefers_attempt_script_over_template(self):
        ctx = ExploitContext(protections=Protections(pie=True))
        ctx.attempts.append(AttemptRecord(
            technique="ret2libc", outcome=AttemptOutcome.PARTIAL,
            partial_artifacts={"exploit_script": "# partial script"},
        ))
        strategy = ExploitStrategy(
            approach=ExploitApproach.ROP_SYSTEM, priority=1, confidence=0.7,
            description="ret2libc", requirements=["libc leak"], notes=["note"],
            steps=["step1"],
        )
        report_obj = StrategyReport(
            binary_path="/bin/x", arch="amd64", bits=64,
            protections_summary="", strategies=[strategy],
        )
        engine = _FakeEngine(
            ctx, strategy_report=report_obj, successful=False,
            exploit_script="# partial script", exploit_template="# universal",
            best_partial_technique="ret2libc",
        )
        report = build_handoff_report(engine)
        assert report.success is False
        assert report.best_partial.kind == "exploit_script"
        assert report.best_partial.technique == "ret2libc"
        assert report.best_partial.content == "# partial script"
        assert "PIE base not leaked" in report.blocking_unknowns
        assert len(report.suggested_next_steps) == 1
        assert report.suggested_next_steps[0].approach == "ROP_SYSTEM"
        assert report.suggested_next_steps[0].requirements == ["libc leak"]
        assert report.suggested_next_steps[0].related_attempt_failure_reason is None

    def test_failed_run_falls_back_to_universal_template(self):
        ctx = ExploitContext()
        ctx.attempts.append(AttemptRecord(technique="ret2win", outcome=AttemptOutcome.FAILED))
        engine = _FakeEngine(ctx, successful=False, exploit_script="", exploit_template="# fallback")
        report = build_handoff_report(engine)
        assert report.best_partial.kind == "universal_template"
        assert report.best_partial.source == "universal_template"
        assert report.best_partial.content == "# fallback"

    def test_json_round_trip(self):
        ctx = ExploitContext()
        ctx.attempts.append(AttemptRecord(technique="ret2win", outcome=AttemptOutcome.FAILED))
        engine = _FakeEngine(ctx, successful=False, exploit_template="# fallback")
        report = build_handoff_report(engine)
        import json
        serialized = json.dumps(report.to_dict())
        restored = json.loads(serialized)
        assert restored["schema_version"] == 1
        assert restored["success"] is False
