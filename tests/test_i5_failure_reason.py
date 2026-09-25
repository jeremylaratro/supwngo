"""
Tests for I5 -- `failure_reason` at the two swallowing sites.

Plan: docs/plans/2026-09-24-pipeline-instrumentation-pass.md §4 I5, §4.4
Class 1, §5.

Two sites, three legs:

- `VariableOverwriteExecutor.attempt()` (`stack_techniques.py`) exhausting
  its 14x9 sweep and returning FAILED with `failure_reason` unset -- the
  recorded cause for 11 of 11 R2 failures. **Naturally occurring**: 12
  FAILED attempts across the real R1/R2 corpora (§4.4 census), so this leg
  needs no induced fixture; exercised here with a fast stub verifier rather
  than a real 126-combination sweep (mirrors
  tests/test_i3_candidate_provenance.py's own fast/differential tests,
  which use the same style of stub for the same reason -- the real sweep
  against a losing target costs minutes per test_i3's own docstring).

- `ScanfCanaryBypassExecutor.attempt()` (`heap_and_bypass.py`) swallowing
  two ways: an `except Exception` leaving no `failure_reason`, and
  `_test_scanf_bypass()` returning `False` leaving the record PARTIAL with
  no reason at all. **Neither leg occurs naturally**: `scanf_canary_bypass`
  is SKIPPED on all 12 occurrences across both benchmark runs and never
  executes (§4.4 census), so both require an INDUCED fixture -- a real
  canary + scanf target that actually reaches `attempt()`
  (tests/fixtures/i5_scanf_canary_bypass/scanf_canary_target.c). The
  probe-false leg is induced by the fixture's shape alone (it doesn't
  implement the "add grades" menu protocol `_test_scanf_bypass()` assumes,
  so the probe genuinely fails); the exception leg is induced by monkeypatch
  a collaborator to genuinely raise (`generate_scanf_bypass_script`) rather
  than being reachable from any input to this target -- exceptions are not
  something a target's I/O can be shaped to trigger on demand, so a
  controlled fault injection is the only way to reach that branch for real.

Also covered:

- The script-audit vocabulary constraint: `templates.py:38` interpolates
  `failure_reason` into generated scripts, and `run_bench.py`'s
  `_SCRAPES_BINARY_RE` routes any occurrence of `strings`/`objdump`/
  `readelf`/`xxd` to a cheat verdict. Comment-stripping already covers this
  (§4.3), but the plan requires a repo-wide test regardless
  (`TestNoFailureReasonLiteralMatchesAuditVocabulary`).
- The pre-declared `handoff.py:292` precedence change (m4): the handoff
  today falls back from an unset `failure_reason` to `record.error`; after
  I5 the new `failure_reason` wins. Genuinely reachable for
  `variable_overwrite` (mapped via `ExploitApproach.VARIABLE_OVERWRITE` in
  `orchestrator.APPROACH_TO_TECHNIQUE`). **Correction to the plan's
  framing, found while writing this test**: `scanf_canary_bypass` has no
  `ExploitApproach` entry in `APPROACH_TO_TECHNIQUE` at all (it's reached
  only via `orchestrator.UNMODELED_TECHNIQUES`, which never populates
  `StrategyReport.strategies`), so `handoff.py:292` -- which only ever
  looks at `report.strategies[0]`'s mapped technique -- can never actually
  select a `scanf_canary_bypass` record. The precedence *expression* is
  still real and still changes behaviour for any record it does reach
  (proven here via `variable_overwrite`); its reachability for
  `scanf_canary_bypass` specifically is not what the plan described, so
  that leg is covered by exercising the expression directly instead.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import AttemptOutcome, AttemptRecord
from supwngo.exploit.pipeline.executors.heap_and_bypass import ScanfCanaryBypassExecutor
from supwngo.exploit.pipeline.executors.stack_techniques import (
    MAGIC_VALUES,
    VariableOverwriteExecutor,
)
from supwngo.exploit.pipeline.handoff import build_handoff_report, _derive_suggested_next_steps
from supwngo.exploit.pipeline.profile_stage import run_static_analysis
from supwngo.exploit.pipeline.verifier import PipelineVerifier
from supwngo.exploit.strategy import ExploitApproach, ExploitStrategy, StrategyReport

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "i5_scanf_canary_bypass"
FIXTURE_SRC = FIXTURE_DIR / "scanf_canary_target.c"

CC_FLAGS = ["-m64", "-O0", "-fstack-protector-all", "-D_FORTIFY_SOURCE=0", "-g"]


def _compile(src: Path, out: Path) -> Path:
    subprocess.run(
        ["gcc", *CC_FLAGS, "-o", str(out), str(src)],
        check=True, capture_output=True, text=True,
    )
    assert out.is_file(), f"gcc did not produce {out}"
    return out


@pytest.fixture(scope="module")
def fixture_binary(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("i5_scanf_canary_fixture")
    return _compile(FIXTURE_SRC, d / "scanf_canary_target")


@pytest.fixture(scope="module")
def fixture_context(fixture_binary) -> ExploitContext:
    """A real, loaded `Binary` + a context with `win_function` populated by
    the real `run_static_analysis()` -- not hand-wired -- so this reaches
    `ScanfCanaryBypassExecutor.attempt()` exactly as a live pipeline run
    would."""
    binary = Binary.load(str(fixture_binary))
    context = ExploitContext.from_binary(binary)
    run_static_analysis(context)
    return context


class TestFixtureIsGenuine:
    """Independent confirmation that the fixture actually exercises the
    real detection path this executor depends on, before trusting the
    executor's own verdict on it -- same standard as test_i3's
    `TestFixturesAreGenuineVulnerabilities`."""

    def test_canary_is_enabled(self, fixture_context):
        assert fixture_context.protections.canary is True

    def test_a_scanf_variant_is_in_the_plt(self, fixture_context):
        scanf_funcs = ScanfCanaryBypassExecutor.SCANF_FUNCS
        assert any(f in fixture_context.binary.plt for f in scanf_funcs)

    def test_win_function_is_found_by_real_static_analysis(self, fixture_context):
        assert fixture_context.win_function is not None
        name, addr = fixture_context.win_function
        assert name == "win"
        assert addr > 0

    def test_is_applicable_returns_true(self, fixture_context):
        assert ScanfCanaryBypassExecutor().is_applicable(fixture_context) is True

    def test_canary_bypass_detector_finds_a_scanf_skip_opportunity(self, fixture_context):
        from supwngo.vulns.canary_bypass import CanaryBypassDetector, CanaryBypassType

        vulns = CanaryBypassDetector(fixture_context.binary).detect()
        scanf_bypasses = [
            v for v in vulns
            if v.details.get("bypass_type") == CanaryBypassType.SCANF_SKIP.name
        ]
        assert len(scanf_bypasses) == 1


# ---------------------------------------------------------------------------
# Leg 1 (stack_techniques.py): sweep exhaustion. Naturally occurring on 12
# real target-runs (§4.4 census) -- exercised here with a fast stub verifier
# that never succeeds, matching test_i3's own fast-differential style,
# rather than paying for a real 126-combination sweep against a losing
# target (test_i3's docstring: "costs minutes").
# ---------------------------------------------------------------------------

class _NeverWinsVerifier:
    def verify_payload(self, technique: str, payload: bytes):
        return SimpleNamespace(success=False)


class TestVariableOverwriteSweepExhaustionFailureReason:
    def test_failure_reason_is_set_and_states_what_was_tried(self):
        record = VariableOverwriteExecutor().attempt(ExploitContext(), _NeverWinsVerifier())

        assert record.outcome == AttemptOutcome.FAILED
        assert record.failure_reason != ""
        assert "14" in record.failure_reason  # buffer_sizes count
        assert str(len(MAGIC_VALUES)) in record.failure_reason
        assert "no combination was confirmed" in record.failure_reason

    def test_failure_reason_reaches_to_dict(self):
        record = VariableOverwriteExecutor().attempt(ExploitContext(), _NeverWinsVerifier())
        d = record.to_dict()
        assert d["failure_reason"] == record.failure_reason
        assert d["failure_reason"] != ""


# ---------------------------------------------------------------------------
# Legs 2 and 3 (heap_and_bypass.py): induced via the real fixture.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def record_leg3_probe_unconfirmed(fixture_context, fixture_binary) -> AttemptRecord:
    """Leg 3, real end-to-end: detection, script generation, and the real
    menu-driven probe subprocess all run for real against the compiled
    fixture. The probe genuinely returns False because this fixture's I/O
    doesn't match the "add grades" menu protocol the probe assumes -- not
    because anything is mocked. Module-scoped: the real probe costs ~40s
    (36 elements x up to 1-2s of timeout each), so it runs exactly once for
    the whole module, mirroring test_i3's `record_a`/`record_b` fixtures."""
    verifier = PipelineVerifier(str(fixture_binary), timeout=5.0, static_preflight=False)
    return ScanfCanaryBypassExecutor().attempt(fixture_context, verifier)


@pytest.fixture(scope="module")
def record_leg2_exception(fixture_context, fixture_binary) -> AttemptRecord:
    """Leg 2, induced fault: the real detector and real fixture are used
    up to script generation, at which point `generate_scanf_bypass_script`
    (imported locally inside `attempt()`, so patching the module attribute
    before the call is picked up) is made to genuinely raise. This never
    reaches the slow probe, so it's fast."""
    import supwngo.exploit.canary_bypass as cb_mod

    def _raise(*args, **kwargs):
        raise RuntimeError("induced fault for I5 leg 2 (test-only)")

    original = cb_mod.generate_scanf_bypass_script
    cb_mod.generate_scanf_bypass_script = _raise
    try:
        verifier = PipelineVerifier(str(fixture_binary), timeout=5.0, static_preflight=False)
        return ScanfCanaryBypassExecutor().attempt(fixture_context, verifier)
    finally:
        cb_mod.generate_scanf_bypass_script = original


class TestScanfCanaryBypassLeg3ProbeUnconfirmed:
    def test_outcome_is_partial_not_failed(self, record_leg3_probe_unconfirmed):
        # A script WAS generated (the executor got that far) -- PARTIAL is
        # the correct outcome, distinct from leg 2's FAILED.
        assert record_leg3_probe_unconfirmed.outcome == AttemptOutcome.PARTIAL

    def test_failure_reason_is_set_and_distinct_from_unset(self, record_leg3_probe_unconfirmed):
        assert record_leg3_probe_unconfirmed.failure_reason != ""
        assert "probe" in record_leg3_probe_unconfirmed.failure_reason.lower()
        assert "did not confirm" in record_leg3_probe_unconfirmed.failure_reason

    def test_no_exception_was_recorded(self, record_leg3_probe_unconfirmed):
        assert record_leg3_probe_unconfirmed.error == ""


class TestScanfCanaryBypassLeg2Exception:
    def test_outcome_is_failed(self, record_leg2_exception):
        assert record_leg2_exception.outcome == AttemptOutcome.FAILED

    def test_failure_reason_is_set_and_does_not_leak_raw_exception_text(
            self, record_leg2_exception):
        assert record_leg2_exception.failure_reason != ""
        # The raw exception message goes in `.error` (never rendered by
        # templates.py); failure_reason is a fixed, hand-written string so
        # an arbitrary exception message can never accidentally introduce
        # an audited word into rendered script text.
        assert "induced fault" not in record_leg2_exception.failure_reason

    def test_raw_exception_text_is_preserved_in_error(self, record_leg2_exception):
        assert "induced fault for I5 leg 2" in record_leg2_exception.error


class TestLegsAreMutuallyDistinguishable:
    """§5 I5: the whole point of this instrument is that legs 2 and 3 --
    'today indistinguishable' per the plan -- become genuine positive
    controls once failure_reason is populated."""

    def test_three_way_failure_reason_differential(
            self, record_leg2_exception, record_leg3_probe_unconfirmed):
        leg1 = VariableOverwriteExecutor().attempt(ExploitContext(), _NeverWinsVerifier())

        reasons = {
            "leg1_sweep_exhaust": leg1.failure_reason,
            "leg2_exception": record_leg2_exception.failure_reason,
            "leg3_probe_unconfirmed": record_leg3_probe_unconfirmed.failure_reason,
        }
        assert all(r != "" for r in reasons.values()), reasons
        assert len(set(reasons.values())) == 3, (
            f"expected three distinct failure_reason strings, got: {reasons}")

    def test_leg2_and_leg3_outcomes_also_differ(
            self, record_leg2_exception, record_leg3_probe_unconfirmed):
        assert record_leg2_exception.outcome != record_leg3_probe_unconfirmed.outcome


# ---------------------------------------------------------------------------
# Artifact-level: both new failure_reason values reach to_dict().
# ---------------------------------------------------------------------------

class TestScanfCanaryBypassFailureReasonReachesToDict:
    def test_leg2_reaches_to_dict(self, record_leg2_exception):
        d = record_leg2_exception.to_dict()
        assert d["failure_reason"] == record_leg2_exception.failure_reason

    def test_leg3_reaches_to_dict(self, record_leg3_probe_unconfirmed):
        d = record_leg3_probe_unconfirmed.to_dict()
        assert d["failure_reason"] == record_leg3_probe_unconfirmed.failure_reason


# ---------------------------------------------------------------------------
# Script-audit vocabulary constraint: no failure_reason literal anywhere in
# supwngo/ may match run_bench.py's _SCRAPES_BINARY_RE.
# ---------------------------------------------------------------------------

def _load_run_bench():
    spec = importlib.util.spec_from_file_location(
        "run_bench_i5_audit_test", REPO_ROOT / "benchmark" / "run_bench.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_bench_i5_audit_test"] = mod
    spec.loader.exec_module(mod)
    return mod


rb = pytest.importorskip("yaml") and _load_run_bench()


def _literal_text(node):
    """Best-effort extraction of the literal text of a string/f-string/
    string-concatenation AST node. Interpolated (`{...}`) holes in an
    f-string are replaced with a space so a word can never accidentally
    merge across one. Returns None when the value can't be determined
    statically (used to decide whether a same-file constant needs
    resolving)."""
    import ast

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append(" ")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_text(node.left), _literal_text(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _collect_failure_reason_literals():
    """Walk every .py file under supwngo/ and return (path, lineno, text)
    for every statically-determinable string assigned to something named
    `failure_reason`, plus module/class-level `FAILURE_REASON_*`-style
    constants (resolving simple `self.CONST`/`Name.CONST`/bare `CONST`
    references on the assignment's right-hand side against same-file
    constants)."""
    import ast

    results = []
    for py_file in sorted((REPO_ROOT / "supwngo").rglob("*.py")):
        try:
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
        except SyntaxError:
            continue

        constants = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                text = _literal_text(node.value)
                if text is None:
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = text

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
            else:
                continue
            for target in targets:
                attr_name = (target.attr if isinstance(target, ast.Attribute)
                            else target.id if isinstance(target, ast.Name)
                            else None)
                if attr_name != "failure_reason":
                    continue
                text = _literal_text(node.value)
                if text is None and isinstance(node.value, ast.Attribute):
                    text = constants.get(node.value.attr)
                if text is None and isinstance(node.value, ast.Name):
                    text = constants.get(node.value.id)
                if text:
                    results.append((str(py_file.relative_to(REPO_ROOT)), node.lineno, text))
    return results


class TestNoFailureReasonLiteralMatchesAuditVocabulary:
    def test_scanner_found_a_nonzero_number_of_literals(self):
        """Sanity: if this returns zero, the scanner itself is broken
        (e.g. AST shapes changed) -- a green result from an empty set
        would be a validation that cannot fail."""
        literals = _collect_failure_reason_literals()
        assert len(literals) >= 5, (
            f"expected several failure_reason literals across supwngo/, "
            f"found {len(literals)} -- the scanner may be broken")

    def test_positive_control_the_regex_itself_still_flags_audited_words(self):
        """Proves the regex used below can go red before trusting the
        all-clear on the real literals."""
        assert rb._SCRAPES_BINARY_RE.search("ran objdump over the binary")
        assert rb._SCRAPES_BINARY_RE.search("used strings to find it")
        assert not rb._SCRAPES_BINARY_RE.search("no scanf canary bypass detected")

    def test_no_failure_reason_literal_in_supwngo_matches_the_audit_regex(self):
        literals = _collect_failure_reason_literals()
        offenders = [(p, l, t) for p, l, t in literals if rb._SCRAPES_BINARY_RE.search(t)]
        assert offenders == [], (
            f"failure_reason literal(s) match run_bench.py's script-cheat "
            f"audit vocabulary and would VOID an honest result:\n{offenders}")

    def test_the_two_new_i5_literals_specifically_are_clean(
            self, record_leg2_exception, record_leg3_probe_unconfirmed):
        """Belt-and-suspenders: the two new literals this task adds,
        checked directly against the regex (not just via the static scan)."""
        assert not rb._SCRAPES_BINARY_RE.search(record_leg2_exception.failure_reason)
        assert not rb._SCRAPES_BINARY_RE.search(record_leg3_probe_unconfirmed.failure_reason)
        leg1 = VariableOverwriteExecutor().attempt(ExploitContext(), _NeverWinsVerifier())
        assert not rb._SCRAPES_BINARY_RE.search(leg1.failure_reason)


# ---------------------------------------------------------------------------
# m4: handoff.py:292's pre-declared precedence change.
# ---------------------------------------------------------------------------

class _FakeEngine:
    """Same minimal stand-in as tests/test_pipeline_handoff.py's own
    `_FakeEngine`, duplicated here rather than imported so this file has no
    cross-test-file coupling."""

    def __init__(self, context, strategy_report=None):
        self.binary = SimpleNamespace(path="/bin/x")
        self.context = context
        self.strategy_report = strategy_report
        self.successful = False
        self.technique_used = ""
        self.exploit_script = ""
        self.exploit_template = ""
        self.best_partial_technique = None


class TestHandoffPrecedenceChangeForVariableOverwrite:
    """variable_overwrite IS reachable through handoff.py:292: it has a real
    ExploitApproach.VARIABLE_OVERWRITE entry in orchestrator.
    APPROACH_TO_TECHNIQUE, so a top-ranked VARIABLE_OVERWRITE strategy makes
    `_derive_suggested_next_steps` look up its AttemptRecord and apply the
    `failure_reason or error or None` precedence for real."""

    def _report_with_variable_overwrite_top_strategy(self, record: AttemptRecord) -> StrategyReport:
        strategy = ExploitStrategy(
            approach=ExploitApproach.VARIABLE_OVERWRITE, priority=1, confidence=0.5,
            description="variable overwrite sweep",
        )
        return StrategyReport(
            binary_path="/bin/x", arch="amd64", bits=64,
            protections_summary="", strategies=[strategy],
        )

    def test_before_i5_shape_falls_through_to_none(self):
        """Pre-I5 shape: failure_reason unset AND error unset (the sweep
        never raises) -- the precedence chain bottoms out at None. Confirms
        the OLD behaviour this change moves away from, so the next test's
        delta is meaningful rather than assumed."""
        ctx = ExploitContext()
        ctx.attempts.append(AttemptRecord(
            technique="variable_overwrite", outcome=AttemptOutcome.FAILED,
            failure_reason="", error="",
        ))
        engine = _FakeEngine(ctx, self._report_with_variable_overwrite_top_strategy(
            ctx.attempts[0]))
        steps = _derive_suggested_next_steps(engine)
        assert steps[0].related_attempt_failure_reason is None

    def test_after_i5_the_new_failure_reason_wins(self):
        ctx = ExploitContext()
        record = VariableOverwriteExecutor().attempt(ExploitContext(), _NeverWinsVerifier())
        ctx.attempts.append(record)
        engine = _FakeEngine(ctx, self._report_with_variable_overwrite_top_strategy(record))
        steps = _derive_suggested_next_steps(engine)
        assert steps[0].related_attempt_failure_reason == record.failure_reason
        assert steps[0].related_attempt_failure_reason is not None

    def test_end_to_end_through_build_handoff_report(self):
        ctx = ExploitContext()
        record = VariableOverwriteExecutor().attempt(ExploitContext(), _NeverWinsVerifier())
        ctx.attempts.append(record)
        engine = _FakeEngine(ctx, self._report_with_variable_overwrite_top_strategy(record))
        report = build_handoff_report(engine)
        assert report.suggested_next_steps[0].related_attempt_failure_reason == record.failure_reason


class TestHandoffPrecedenceExpressionForScanfCanaryBypass:
    """scanf_canary_bypass has NO ExploitApproach mapping (it's reached only
    via orchestrator.UNMODELED_TECHNIQUES, which never populates
    StrategyReport.strategies), so handoff.py:292 can never actually select
    a scanf_canary_bypass record through `_derive_suggested_next_steps` --
    `APPROACH_TO_TECHNIQUE.get(top.approach)` can never equal
    "scanf_canary_bypass" for any real ExploitApproach member. This is
    verified directly below, then the underlying precedence expression
    itself (the actual behaviour the plan's m4 note cares about) is
    exercised directly against a scanf_canary_bypass-shaped record, since
    the integration point the plan named cannot exercise it."""

    def test_scanf_canary_bypass_has_no_approach_to_technique_entry(self):
        from supwngo.exploit.pipeline.orchestrator import APPROACH_TO_TECHNIQUE

        assert "scanf_canary_bypass" not in APPROACH_TO_TECHNIQUE.values()

    def test_precedence_expression_directly_leg2_exception_shape(self):
        """Mirrors handoff.py:292 exactly: `record.failure_reason or
        record.error or None`. Pre-I5 shape (failure_reason unset, error
        set from the caught exception) resolved to the exception text;
        post-I5 shape (both set) resolves to the new failure_reason."""
        pre_i5_record = AttemptRecord(
            technique="scanf_canary_bypass", outcome=AttemptOutcome.FAILED,
            failure_reason="", error="some caught exception text",
        )
        assert (pre_i5_record.failure_reason or pre_i5_record.error or None) \
            == "some caught exception text"

        post_i5_record = AttemptRecord(
            technique="scanf_canary_bypass", outcome=AttemptOutcome.FAILED,
            failure_reason=ScanfCanaryBypassExecutor.FAILURE_REASON_EXCEPTION,
            error="some caught exception text",
        )
        assert (post_i5_record.failure_reason or post_i5_record.error or None) \
            == ScanfCanaryBypassExecutor.FAILURE_REASON_EXCEPTION

    def test_real_leg2_record_satisfies_the_new_precedence(self, record_leg2_exception):
        resolved = (record_leg2_exception.failure_reason
                    or record_leg2_exception.error or None)
        assert resolved == record_leg2_exception.failure_reason
        assert resolved != record_leg2_exception.error
