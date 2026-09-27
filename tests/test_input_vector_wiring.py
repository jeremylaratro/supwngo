"""
Tests for the Sprint 2' input-vector WIRING layer (W1-W5,
docs/plans/2026-09-26-sprint2prime-input-vector-plan.md, REVISION 3/4/5 and
the "New obligation for the wiring layer" section).

This is the SPINE that carries an operator-declared `DeliverySpec`
(supwngo/exploit/pipeline/contracts.py - fully built, S1) from the CLI
through `CanonicalAutopwnEngine` to `ExploitContext`, makes it observable by
`PipelineVerifier` at call time, and enforces a central refusal gate in
`_attempt_techniques` before any executor is invoked. It deliberately does
NOT touch `pipeline/delivery.py`, `exploit/verification.py`, or
`pipeline/templates.py` (a later wave's scope) - those are the actual
argv-building/file-materializing spawn sites, and this suite proves the spine
without depending on them.

Four hard constraints from the task, each with its own test group below:

1. The vector is OPERATOR-DECLARED, never probe-decided (`vector_probe.py`'s
   `classify_input_vector()` is never called by any code under test here).
2. The spec is resolved at CALL TIME (`PipelineVerifier.resolve_delivery_spec()`),
   not cached in a constructor - `TestConstraint2CallTimeResolution`.
3. The refusal gate is NOT bypassable by `--force-all`/`--strategy` -
   `TestConstraint3RefusalGate`.
4. Default behavior (no operator option) is byte-identical to today -
   `TestConstraint4DefaultUnchanged`.

Plus W4 (`build_argv()` `ValueError` containment) and W5 (CLI flags).
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from supwngo.cli import cli
from supwngo.core.binary import Protections
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import (
    AttemptOutcome,
    AttemptRecord,
    DeliverySpec,
    SINK_ARGV,
    SINK_FILE_ARGV,
    SINK_FILE_FIXED,
    SINK_STDIN,
    TechniqueExecutor,
)
from supwngo.exploit.pipeline.orchestrator import (
    FILE_DELIVERY_ALLOWLIST,
    CanonicalAutopwnEngine,
)
from supwngo.exploit.pipeline.registry import ExecutorRegistry
from supwngo.exploit.pipeline.verifier import PipelineVerifier


def _fake_binary() -> SimpleNamespace:
    """A `Binary`-shaped stub with everything
    `CanonicalAutopwnEngine.__init__`/`ExploitContext.from_binary` read, but
    no real ELF parsing - avoids needing a compiled fixture for tests whose
    subject is the wiring, not exploitation itself."""
    return SimpleNamespace(
        path=Path("/tmp/supwngo_wiring_test_vuln"),
        arch="amd64",
        bits=64,
        endian="little",
        protections=Protections(),
        detect_shipped_libc=lambda: None,
        libc_env=lambda: None,
    )


def _bare_engine(context=None, verifier=None, binary=None) -> CanonicalAutopwnEngine:
    """Construct a `CanonicalAutopwnEngine` without running `__init__`'s
    binary-loading machinery, mirroring `tests/test_i2_attempt_duration.py`'s
    `_bare_engine()` - `_attempt_techniques()` is exercised directly."""
    engine = CanonicalAutopwnEngine.__new__(CanonicalAutopwnEngine)
    engine.context = context if context is not None else ExploitContext()
    engine.binary = binary if binary is not None else _fake_binary()
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
    engine._strategy = None
    engine._force_all = False
    engine._verifier = verifier
    engine.registry = ExecutorRegistry()
    return engine


class _RecordingExecutor(TechniqueExecutor):
    """Spy: records whether `attempt()` was actually invoked - the
    constraint-3 negative test needs to assert the executor was NOT called,
    not merely that the outcome looks like a refusal."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.called = False

    def attempt(self, context, verifier) -> AttemptRecord:
        self.called = True
        return AttemptRecord(technique=self.name, outcome=AttemptOutcome.FAILED)


# ---------------------------------------------------------------------------
# Constraint 4: default behavior is byte-identical to today.
# ---------------------------------------------------------------------------

class TestConstraint4DefaultUnchanged:
    def test_default_context_has_no_delivery_spec(self):
        assert ExploitContext().delivery_spec is None

    def test_default_delivery_spec_reproduces_todays_argv(self):
        spec = DeliverySpec()
        assert spec.sink == SINK_STDIN
        assert spec.build_argv("/bin/vuln") == ["/bin/vuln"]

    def test_verifier_with_no_context_resolves_to_default_spec(self):
        verifier = PipelineVerifier("/bin/vuln")
        assert verifier.resolve_delivery_spec() == DeliverySpec()

    def test_verifier_with_context_but_no_declared_vector_resolves_to_default(self):
        ctx = ExploitContext()
        verifier = PipelineVerifier("/bin/vuln", context=ctx)
        assert verifier.resolve_delivery_spec() == DeliverySpec()

    def test_engine_construction_without_input_vector_leaves_context_spec_none(self):
        engine = CanonicalAutopwnEngine(_fake_binary(), static_preflight=False)
        assert engine.context.delivery_spec is None

    def test_gate_is_a_no_op_for_the_default_spec_every_technique_still_attempted(self):
        """Direct proof at the exact insertion point (W3's gate): with no
        vector declared, a technique that is NOT in FILE_DELIVERY_ALLOWLIST
        still has its executor.attempt() called - the new gate must not
        affect any existing spawn site's behavior when no operator option
        was given."""
        assert "format_string" not in FILE_DELIVERY_ALLOWLIST
        ctx = ExploitContext()
        verifier = PipelineVerifier("/bin/vuln", context=ctx)
        executor = _RecordingExecutor("format_string")
        engine = _bare_engine(context=ctx, verifier=verifier)
        engine.registry.register(executor)

        engine._attempt_techniques(["format_string"])

        assert executor.called is True
        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.FAILED


# ---------------------------------------------------------------------------
# Constraint 2: resolved at CALL TIME, not cached in a constructor.
# ---------------------------------------------------------------------------

class TestConstraint2CallTimeResolution:
    def test_spec_set_after_construction_is_observed(self):
        """The load-bearing test: a spec assigned to the context AFTER
        `PipelineVerifier.__init__` has already returned must still be
        visible through `resolve_delivery_spec()`. A constructor-carried
        implementation (copying `context.delivery_spec` once, at
        `__init__` time) fails this exact assertion - see
        test_reverting_to_constructor_capture_fails_this_test's docstring
        for the actual failure recorded when this was verified RED."""
        ctx = ExploitContext()
        verifier = PipelineVerifier("/bin/vuln", context=ctx)

        assert verifier.resolve_delivery_spec().sink == SINK_STDIN

        new_spec = DeliverySpec(
            sink=SINK_FILE_ARGV,
            argv_template=("{payload_file}",),
            payload_filename="input.bmp",
        )
        ctx.delivery_spec = new_spec  # assigned AFTER verifier construction

        resolved = verifier.resolve_delivery_spec()
        assert resolved is new_spec
        assert resolved.sink == SINK_FILE_ARGV
        assert resolved.payload_filename == "input.bmp"

    def test_engine_order_matches_the_real_orchestrator_and_still_observes_late_writes(self):
        """Mirrors the real ordering constraint 2 exists for:
        `PipelineVerifier` is constructed inside
        `CanonicalAutopwnEngine.__init__` (orchestrator.py) strictly before
        `_run_prologue()` would ever run - yet a value written to
        `engine.context.delivery_spec` well after `__init__` returns (e.g. by
        a caller mirroring the CLI's `engine.context.offset = offset`
        pattern) is still observed by the SAME verifier instance."""
        engine = CanonicalAutopwnEngine(_fake_binary(), static_preflight=False)
        assert engine._verifier.resolve_delivery_spec() == DeliverySpec()

        engine.context.delivery_spec = DeliverySpec(
            sink=SINK_FILE_FIXED, payload_filename="x.dat",
        )
        resolved = engine._verifier.resolve_delivery_spec()
        assert resolved.sink == SINK_FILE_FIXED
        assert resolved.payload_filename == "x.dat"


# ---------------------------------------------------------------------------
# Constraint 3: central refusal gate, independent of --force-all/--strategy.
# ---------------------------------------------------------------------------

class TestConstraint3RefusalGate:
    def _make(self, sink, technique_name, force_all=False, strategy=None,
              payload_filename="in.bmp", argv_template=None):
        ctx = ExploitContext()
        if argv_template is None:
            argv_template = ("{payload_file}",) if sink == SINK_FILE_ARGV else ()
        ctx.delivery_spec = DeliverySpec(
            sink=sink, argv_template=argv_template, payload_filename=payload_filename,
        )
        verifier = PipelineVerifier("/bin/vuln", context=ctx)
        executor = _RecordingExecutor(technique_name)
        engine = _bare_engine(context=ctx, verifier=verifier)
        engine._force_all = force_all
        engine._strategy = strategy
        engine.registry.register(executor)
        return engine, executor

    def test_file_sink_non_allowlisted_technique_is_refused(self):
        assert "format_string" not in FILE_DELIVERY_ALLOWLIST
        engine, executor = self._make(SINK_FILE_ARGV, "format_string")

        engine._attempt_techniques(["format_string"])

        assert executor.called is False
        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.SKIPPED
        # Wave 2 REVISION 2 Class 1 (closes C1 + M1): the gate's wording
        # generalized from "file delivery" to "non-stdin delivery" because
        # it now covers SINK_ARGV too, not only the two file sinks.
        assert "non-stdin delivery" in record.failure_reason
        assert "format_string" in record.failure_reason

    def test_file_sink_non_allowlisted_technique_is_refused_even_with_force_all(self):
        """The bypass (`--force-all`) must NOT reach this gate."""
        engine, executor = self._make(SINK_FILE_ARGV, "format_string", force_all=True)

        engine._attempt_techniques(["format_string"])

        assert executor.called is False, (
            "--force-all reached the delivery-refusal gate and invoked the "
            "executor anyway"
        )
        assert engine.context.attempts[0].outcome == AttemptOutcome.SKIPPED

    def test_file_sink_non_allowlisted_technique_is_refused_even_with_strategy(self):
        """The other bypass path (`--strategy NAME`) must ALSO not reach
        this gate."""
        engine, executor = self._make(
            SINK_FILE_ARGV, "format_string", strategy="format_string",
        )

        engine._attempt_techniques(["format_string"])

        assert executor.called is False, (
            "--strategy reached the delivery-refusal gate and invoked the "
            "executor anyway"
        )
        assert engine.context.attempts[0].outcome == AttemptOutcome.SKIPPED

    def test_file_sink_allowlisted_technique_is_not_refused(self):
        """Positive control (explicitly required): a file sink with an
        ALLOWLISTED technique must NOT be refused - otherwise the gate could
        refuse every technique unconditionally and still pass every negative
        test above."""
        assert "ret2win" in FILE_DELIVERY_ALLOWLIST
        engine, executor = self._make(SINK_FILE_ARGV, "ret2win")

        engine._attempt_techniques(["ret2win"])

        assert executor.called is True
        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.FAILED  # _RecordingExecutor's own outcome
        assert "unsupported" not in (record.failure_reason or "")

    def test_stdin_sink_never_triggers_the_gate(self):
        """SINK_STDIN is the only sink the gate must leave every technique
        alone for - same as the pure default.

        Wave 2 REVISION 2 Class 1 (docs/plans/2026-09-26-wave2-impl-review-r2-daybreak.md,
        closes C1 + M1) REPLACES the old `test_non_file_sink_never_triggers_the_gate`,
        which also asserted this for SINK_ARGV - that assertion encoded the
        exact defect the review found: SINK_ARGV passed through untouched,
        so a technique that delivers over stdin regardless of the declared
        vector (any `verify_script()`-based executor) could report SUCCESS
        under `--input-vector argv` without ever using argv. See
        `test_argv_sink_non_allowlisted_technique_is_refused` below for the
        corrected behavior."""
        engine, executor = self._make(SINK_STDIN, "format_string", argv_template=(), payload_filename="")
        engine._attempt_techniques(["format_string"])
        assert executor.called is True, "SINK_STDIN incorrectly triggered the delivery-refusal gate"

    def test_argv_sink_non_allowlisted_technique_is_refused(self):
        """Wave 2 REVISION 2 Class 1 positive fix: SINK_ARGV must be gated
        exactly like a file sink for a technique that never consults the
        delivery spec at all - otherwise it silently delivers over stdin
        under a declared argv vector."""
        engine, executor = self._make(
            SINK_ARGV, "format_string", argv_template=("{payload_arg}",), payload_filename="",
        )
        engine._attempt_techniques(["format_string"])
        assert executor.called is False
        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.SKIPPED
        assert "non-stdin delivery" in record.failure_reason
        assert "format_string" in record.failure_reason

    def test_argv_sink_allowlisted_technique_is_not_refused(self):
        """Positive control for the above: an ALLOWLISTED technique under
        SINK_ARGV must still be attempted, not refused."""
        assert "ret2win" in FILE_DELIVERY_ALLOWLIST
        engine, executor = self._make(
            SINK_ARGV, "ret2win", argv_template=("{payload_arg}",), payload_filename="",
        )
        engine._attempt_techniques(["ret2win"])
        assert executor.called is True
        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.FAILED  # _RecordingExecutor's own outcome
        assert "unsupported" not in (record.failure_reason or "")

    def test_unrecognized_sink_is_refused_before_classification(self):
        """Wave 2 REVISION 2 Class 1, step 1 (closes M1): an unrecognized/
        typoed sink reaching the gate (e.g. a late-bound
        `context.delivery_spec` assigned directly rather than through the
        CLI/engine constructor's own validation) must be refused loudly,
        never silently treated as stdin."""
        engine, executor = self._make(
            "typo-sink", "format_string", argv_template=(), payload_filename="",
        )
        engine._attempt_techniques(["format_string"])
        assert executor.called is False
        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.SKIPPED
        assert "unrecognized" in record.failure_reason
        assert "typo-sink" in record.failure_reason


# ---------------------------------------------------------------------------
# W4: build_argv() ValueError containment.
# ---------------------------------------------------------------------------

class TestW4BuildArgvContainment:
    def test_malformed_spec_on_an_allowlisted_technique_is_refused_not_raised(self):
        """SINK_FILE_ARGV with NO '{payload_file}' token is one of
        build_argv()'s five documented raise conditions (the realistic
        operator-typo case: --input-vector file-argv given, --input-name
        given, but the underlying spec's template is wrong/missing) - the
        gate must catch it and record it as THIS technique's failure_reason,
        never let it propagate."""
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(
            sink=SINK_FILE_ARGV, argv_template=(), payload_filename="in.bmp",
        )
        verifier = PipelineVerifier("/bin/vuln", context=ctx)
        allowlisted = _RecordingExecutor("ret2win")
        engine = _bare_engine(context=ctx, verifier=verifier)
        engine.registry.register(allowlisted)

        engine._attempt_techniques(["ret2win"])  # must not raise

        record = engine.context.attempts[0]
        assert record.outcome == AttemptOutcome.SKIPPED
        assert "delivery spec invalid" in record.failure_reason
        assert allowlisted.called is False

    def test_run_completes_and_other_techniques_still_report_their_own_outcomes(self):
        """(a) the run completes, (b) the technique that hits the malformed
        spec names the delivery problem in its failure_reason, (c) other
        techniques attempted in the SAME run still get their own,
        distinctly-worded AttemptRecord rather than the run aborting."""
        ctx = ExploitContext()
        ctx.delivery_spec = DeliverySpec(
            sink=SINK_FILE_ARGV, argv_template=(), payload_filename="in.bmp",
        )
        verifier = PipelineVerifier("/bin/vuln", context=ctx)
        ret2win = _RecordingExecutor("ret2win")       # allowlisted -> hits build_argv()
        variable_ow = _RecordingExecutor("variable_overwrite")  # allowlisted -> hits build_argv() too
        other = _RecordingExecutor("srop")             # NOT allowlisted -> refused earlier, never reaches build_argv()

        engine = _bare_engine(context=ctx, verifier=verifier)
        for ex in (ret2win, variable_ow, other):
            engine.registry.register(ex)

        engine._attempt_techniques(["ret2win", "variable_overwrite", "srop"])  # must not raise

        by_name = {a.technique: a for a in engine.context.attempts}
        assert len(by_name) == 3, "the run lost attempt records for other techniques"

        assert by_name["ret2win"].outcome == AttemptOutcome.SKIPPED
        assert "delivery spec invalid" in by_name["ret2win"].failure_reason

        assert by_name["srop"].outcome == AttemptOutcome.SKIPPED
        assert "non-stdin delivery" in by_name["srop"].failure_reason
        # Distinct reason from ret2win's -- srop never reached build_argv()
        # at all, so it must not also say "delivery spec invalid".
        assert "delivery spec invalid" not in by_name["srop"].failure_reason

        assert ret2win.called is False
        assert variable_ow.called is False
        assert other.called is False


# ---------------------------------------------------------------------------
# W5: CLI flags.
# ---------------------------------------------------------------------------

class TestW5CLIFlags:
    def test_input_vector_and_input_name_appear_in_autopwn_help(self):
        result = CliRunner().invoke(cli, ["autopwn", "--help"])
        assert result.exit_code == 0
        assert "--input-vector" in result.output
        assert "--input-name" in result.output

    def test_input_vector_and_input_name_appear_in_solve_help(self):
        result = CliRunner().invoke(cli, ["solve", "--help"])
        assert result.exit_code == 0
        assert "--input-vector" in result.output
        assert "--input-name" in result.output

    def test_invalid_input_vector_value_errors_clearly_listing_choices(self):
        result = CliRunner().invoke(
            cli, ["autopwn", "--input-vector", "bogus", "/bin/ls"],
        )
        assert result.exit_code != 0
        assert "Invalid value for '--input-vector'" in result.output
        for choice in ("stdin", "argv", "file-argv", "file-fixed"):
            assert choice in result.output

    def test_valid_input_vector_value_is_accepted_by_the_parser(self):
        """Confirms parsing succeeds (no UsageError) for every valid choice
        on both commands - uses a nonexistent binary path deliberately so
        `click.Path(exists=True)` fails FIRST and fast, before any real
        binary-loading work, while still proving the `--input-vector`/
        `--input-name` options themselves parsed without complaint (a
        parser-level rejection of them would surface as a DIFFERENT usage
        error, naming the offending option)."""
        for command in ("autopwn", "solve"):
            for value in ("stdin", "argv", "file-argv", "file-fixed"):
                result = CliRunner().invoke(
                    cli, [command, "--input-vector", value, "--input-name", "x.bin",
                          "/nonexistent/binary/path"],
                )
                assert result.exit_code != 0
                assert "--input-vector" not in result.output
                assert "'/nonexistent/binary/path'" in result.output

    def test_valid_input_vector_reaches_the_engine_option(self):
        """Engine-level check of the CLI->engine mapping itself (not routed
        through CliRunner, which would need a real, loadable binary)."""
        engine = CanonicalAutopwnEngine(
            _fake_binary(), static_preflight=False,
            input_vector="file-argv", input_name="input.bmp",
        )
        spec = engine.context.delivery_spec
        assert spec.sink == SINK_FILE_ARGV
        assert spec.payload_filename == "input.bmp"
        assert spec.build_argv("/bin/vuln", payload_value="/tmp/input.bmp") == [
            "/bin/vuln", "/tmp/input.bmp",
        ]

    def test_all_four_sink_values_map_to_the_matching_sink_constant(self):
        # input_name is only passed for the two sinks that can use it -- T5
        # (docs/plans/2026-09-26-sprint2prime-input-vector-plan.md, Wave 2
        # REVISION 1, finding M3) now rejects input_name for stdin/argv
        # rather than silently ignoring it, so passing it unconditionally
        # here (as this test did before T5) would raise for those two.
        cases = {
            "stdin": (SINK_STDIN, None),
            "argv": (SINK_ARGV, None),
            "file-argv": (SINK_FILE_ARGV, "payload.bin"),
            "file-fixed": (SINK_FILE_FIXED, "payload.bin"),
        }
        for cli_value, (expected_sink, input_name) in cases.items():
            engine = CanonicalAutopwnEngine(
                _fake_binary(), static_preflight=False,
                input_vector=cli_value, input_name=input_name,
            )
            assert engine.context.delivery_spec.sink == expected_sink

    def test_engine_rejects_an_unknown_input_vector_value_directly(self):
        """Backstop for any direct/API caller that bypasses click.Choice
        entirely (e.g. a future non-CLI caller) - the engine validates too."""
        with pytest.raises(ValueError):
            CanonicalAutopwnEngine(
                _fake_binary(), static_preflight=False, input_vector="bogus",
            )

    def test_absent_flag_leaves_engine_default_untouched(self):
        engine = CanonicalAutopwnEngine(_fake_binary(), static_preflight=False)
        assert engine.context.delivery_spec is None


class TestGuidedFallbackDoesNotDropTheDeclaredVector:
    """`solve --interactive` retries through `_guided_fallback`, which builds a
    FRESH `CanonicalAutopwnEngine`. If that construction omits the operator's
    declared vector, the retry silently reverts to stdin -- the exact silent
    stdin fallback the delivery design forbids, and which `--input-vector`'s own
    help text promises does not happen.

    Found by sweeping every `CanonicalAutopwnEngine(` construction in cli.py
    rather than only the ones the flag was added to: there are three, and the
    third (the guided-retry path) was missed.
    """

    def test_guided_fallback_forwards_input_vector_and_name(self):
        """Signature-level gate. `_guided_fallback` is interactive (it calls
        click.prompt), so rather than drive it end to end we assert the
        contract that was actually broken: the retry constructor must receive
        the vector. Paired with the source-level check below so neither can go
        vacuous alone."""
        import inspect
        from supwngo import cli

        params = inspect.signature(cli._guided_fallback).parameters
        assert "input_vector" in params, (
            "_guided_fallback cannot forward a vector it does not accept")
        assert "input_name" in params

    def test_the_guided_retry_constructor_actually_passes_them(self):
        """Positive control for the above: accepting the parameters proves
        nothing if the fresh engine is still built without them. Asserts the
        retry's own construction site forwards both."""
        import inspect
        from supwngo import cli

        src = inspect.getsource(cli._guided_fallback)
        assert "CanonicalAutopwnEngine(" in src, (
            "the subject of this search must exist -- if the retry stops "
            "constructing an engine, rewrite this gate rather than deleting it")
        assert "input_vector=input_vector" in src, (
            "the guided retry builds a fresh engine WITHOUT the declared "
            "vector, so a declared file sink silently reverts to stdin")
        assert "input_name=input_name" in src

    def test_every_engine_construction_in_cli_is_accounted_for(self):
        """The sweep itself, kept as a gate. If a FOURTH construction site is
        added later it must be reviewed for vector forwarding rather than
        quietly inheriting stdin."""
        from pathlib import Path
        from supwngo import cli

        src = Path(cli.__file__).read_text()
        sites = src.count("CanonicalAutopwnEngine(")
        assert sites == 3, (
            f"expected the 3 known CanonicalAutopwnEngine construction sites "
            f"(autopwn, _guided_fallback, solve), found {sites}. A new site "
            f"must declare whether it forwards input_vector/input_name -- "
            f"omitting it silently reverts that path to stdin.")
