"""
Foundation-layer gates for Sprint 2' input-vector abstraction (S1, S2, S7).

Gap analysis: docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md B-2
Plan: docs/plans/2026-09-26-sprint2prime-input-vector-plan.md, REVISION 3
(the section that governs -- the probe is advisory only, the vector is
operator-declared; no wiring into the pipeline happens in this file's scope).

This covers only the foundation layer:
  - S1: `DeliverySpec` (contracts.py) -- pure, no target needed.
  - S2: `classify_input_vector()` (analysis/vector_probe.py) -- exercised
    against the nine purpose-built fixtures, compiled at test time.
  - S7: the dead `"argv"` entry removed from `INPUT_SOURCES`
    (analysis/static.py).

No wiring (delivery.py/verification.py/verifier.py/orchestrator.py/
templates.py/script_builder.py/profile_stage.py) is touched or tested here --
that is a separate task's scope.

This file assumes the fixtures themselves are valid (solvable, and each
genuinely uses the transport its name claims) -- that is proven separately
and is NOT duplicated here; see
`tests/test_input_vector_fixture_validation.py`. This file's job is
`DeliverySpec` and the probe.
"""
from __future__ import annotations

import inspect
import subprocess
from pathlib import Path
from typing import Dict

import pytest

from supwngo.analysis.static import INPUT_SOURCES
from supwngo.analysis.vector_probe import classify_input_vector
from supwngo.exploit.pipeline.contracts import (
    DeliverySpec,
    SINK_ARGV,
    SINK_FILE_ARGV,
    SINK_FILE_FIXED,
    SINK_STDIN,
    is_file_sink,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SRC_DIR = REPO_ROOT / "tests" / "fixtures" / "input_vector"

GCC_FLAGS = ["-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", "-w"]

FIXTURE_NAMES = [
    "file_vector_gate",
    "mech_open_read_argv",
    "mech_line_text",
    "mech_flag_style",
    "mech_fixed_path",
    "mech_argv_payload",
    "neg_nondeterministic",
    "neg_argc_banner",
    "neg_argv_config_stdin_payload",
]

#: MEASURED verdicts (per-fixture positive/negative controls proven able to
#: go red live in tests/test_input_vector_fixture_validation.py; the probe
#: verdicts against those same binaries are measured here).
EXPECTED_VERDICTS = {
    "file_vector_gate": "file-candidate",
    "mech_open_read_argv": "file-candidate",
    "mech_line_text": "file-candidate",
    # Deliberate, EXPECTED false negatives -- do not "fix" these into
    # file-candidate. The probe classifies purely on argv-driven behavioral
    # differences with a bare path; it cannot see a flag-gated path
    # (mech_flag_style needs "-f PATH", not a bare PATH) or a fixed,
    # hardcoded path the target never takes from argv at all
    # (mech_fixed_path). Both therefore look identical to a pure stdin
    # target under this probe and route to "stdin" -- which is safe (today's
    # behavior), not a regression. This is exactly why a positive verdict
    # is advisory-only and a negative one is not treated as proof of
    # absence: the explicit operator option is what makes these two
    # solvable, not the probe.
    "mech_flag_style": "stdin",
    "mech_fixed_path": "stdin",
    "mech_argv_payload": "argv-only-not-opened",
    "neg_nondeterministic": "inconclusive-nondeterministic",
    "neg_argc_banner": "argv-only-not-opened",
    "neg_argv_config_stdin_payload": "argv-only-config",
}

#: The only fixtures that genuinely are file-vector targets. Kept as its own
#: constant (rather than re-deriving it from EXPECTED_VERDICTS at the call
#: site) so the load-bearing "no unsafe false positive" assertion reads as
#: a single, auditable set literal.
TRUE_FILE_CANDIDATES = {"file_vector_gate", "mech_open_read_argv", "mech_line_text"}


@pytest.fixture(scope="module")
def compiled_fixtures(tmp_path_factory) -> Dict[str, Path]:
    """Compile the nine C fixtures fresh, matching the style and flags of
    tests/test_variable_overwrite_budget.py (and
    tests/test_input_vector_fixture_validation.py), rather than relying on
    any prebuilt binary that might be sitting in the fixtures directory."""
    d = tmp_path_factory.mktemp("input_vector_bin")
    binaries: Dict[str, Path] = {}
    for name in FIXTURE_NAMES:
        src = FIXTURE_SRC_DIR / f"{name}.c"
        assert src.is_file(), f"missing fixture source: {src}"
        out = d / name
        subprocess.run(
            ["gcc", *GCC_FLAGS, "-o", str(out), str(src)],
            check=True, capture_output=True, text=True,
        )
        assert out.is_file()
        binaries[name] = out
    return binaries


# --------------------------------------------------------------------------
# T1: DeliverySpec.build_argv default + positive control
# --------------------------------------------------------------------------

class TestBuildArgvDefault:
    def test_default_spec_yields_binary_path_only(self):
        assert DeliverySpec().build_argv("/bin/x") == ["/bin/x"]

    def test_default_spec_ignores_a_supplied_payload_path(self):
        """Even if a caller passes a payload value, the default (empty
        argv_template) spec must still yield only the binary path -- proves
        the "empty template" branch, not merely a coincidentally-unused
        argument."""
        assert DeliverySpec().build_argv("/bin/x", "/tmp/payload.bin") == ["/bin/x"]

    def test_build_argv_actually_substitutes_when_a_template_is_present(self):
        """Positive control (required by the plan): a build_argv that
        ignored its argv_template/payload_value entirely would still pass
        the two tests above. This proves substitution really happens."""
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
                             payload_filename="payload.bin")
        assert spec.build_argv("/bin/x", "/tmp/payload.bin") == [
            "/bin/x", "/tmp/payload.bin",
        ]

    def test_build_argv_substitutes_only_the_placeholder_token(self):
        """Further positive control: a template with a flag ahead of the
        placeholder must leave the flag untouched and substitute only the
        placeholder token."""
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("-f", "{payload_file}"),
                             payload_filename="payload.bin")
        assert spec.build_argv("/bin/x", "/tmp/p.bin") == [
            "/bin/x", "-f", "/tmp/p.bin",
        ]


class TestBuildArgvPerSink:
    """build_argv for each of the four sinks, including flag-style and
    non-first-position templates, asserting exact argv lists."""

    def test_sink_stdin_with_no_template(self):
        spec = DeliverySpec(sink=SINK_STDIN)
        assert spec.build_argv("/bin/x") == ["/bin/x"]

    def test_sink_stdin_with_a_non_placeholder_template_still_substitutes(self):
        """Proves stdin and argv are orthogonal, not mutually exclusive: a
        stdin-delivery target may still need an unrelated config arg."""
        spec = DeliverySpec(sink=SINK_STDIN, argv_template=("--config", "static.cfg"))
        assert spec.build_argv("/bin/x", "/tmp/payload.bin") == [
            "/bin/x", "--config", "static.cfg",
        ]

    def test_sink_argv_flag_style_template(self):
        spec = DeliverySpec(sink=SINK_ARGV, argv_template=("-p", "{payload_arg}"))
        assert spec.build_argv("/bin/x", "PAYLOADVALUE") == [
            "/bin/x", "-p", "PAYLOADVALUE",
        ]

    def test_sink_argv_bare_positional_template(self):
        spec = DeliverySpec(sink=SINK_ARGV, argv_template=("{payload_arg}",))
        assert spec.build_argv("/bin/x", "PAYLOADVALUE") == [
            "/bin/x", "PAYLOADVALUE",
        ]

    def test_sink_file_argv_named_option_non_first_position(self):
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("mode", "{payload_file}"),
                             payload_filename="payload.bin")
        assert spec.build_argv("/bin/x", "/tmp/p.bin") == [
            "/bin/x", "mode", "/tmp/p.bin",
        ]

    def test_sink_file_argv_at_at_alias_flag_style(self):
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("-f", "@@"),
                             payload_filename="payload.bin")
        assert spec.build_argv("/bin/x", "/tmp/p.bin") == [
            "/bin/x", "-f", "/tmp/p.bin",
        ]

    def test_sink_file_fixed_with_no_argv_template(self):
        """The normal/expected shape for SINK_FILE_FIXED: no argv token at
        all, because the target opens a path it already knows."""
        spec = DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="dropped.cfg")
        assert spec.build_argv("/bin/x") == ["/bin/x"]

    def test_sink_file_fixed_with_an_unrelated_template_still_substitutes_it(self):
        spec = DeliverySpec(sink=SINK_FILE_FIXED, argv_template=("--verbose",),
                             payload_filename="dropped.cfg")
        assert spec.build_argv("/bin/x") == ["/bin/x", "--verbose"]


class TestAtAtAliasIsIdenticalToPayloadFileToken:
    def test_at_at_and_payload_file_produce_identical_argv(self):
        spec_atat = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("-f", "@@"),
                                  payload_filename="payload.bin")
        spec_token = DeliverySpec(sink=SINK_FILE_ARGV,
                                   argv_template=("-f", "{payload_file}"),
                                   payload_filename="payload.bin")
        assert (
            spec_atat.build_argv("/bin/x", "/tmp/p.bin")
            == spec_token.build_argv("/bin/x", "/tmp/p.bin")
        )


class TestBuildArgvRaisesOnUndeliverablePayload:
    def test_sink_file_argv_missing_placeholder_raises(self):
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("--config", "static.cfg"),
                             payload_filename="payload.bin")
        with pytest.raises(ValueError):
            spec.build_argv("/bin/x", "/tmp/payload.bin")

    def test_sink_file_fixed_containing_placeholder_raises(self):
        spec = DeliverySpec(sink=SINK_FILE_FIXED, argv_template=("{payload_file}",),
                             payload_filename="dropped.cfg")
        with pytest.raises(ValueError):
            spec.build_argv("/bin/x", "/tmp/payload.bin")

    def test_sink_argv_missing_payload_arg_placeholder_raises(self):
        spec = DeliverySpec(sink=SINK_ARGV, argv_template=("--flag", "static"))
        with pytest.raises(ValueError):
            spec.build_argv("/bin/x", "PAYLOADVALUE")

    def test_file_sink_with_empty_payload_filename_raises(self):
        """Required (non-empty) for BOTH file sinks -- tested against
        SINK_FILE_ARGV here; the SINK_FILE_FIXED case is covered by
        test_sink_file_fixed_with_empty_payload_filename_also_raises below,
        since the two sinks reach the check by different branches."""
        spec = DeliverySpec(sink=SINK_FILE_ARGV, argv_template=("{payload_file}",),
                             payload_filename="")
        with pytest.raises(ValueError):
            spec.build_argv("/bin/x", "/tmp/payload.bin")

    def test_sink_file_fixed_with_empty_payload_filename_also_raises(self):
        spec = DeliverySpec(sink=SINK_FILE_FIXED, payload_filename="")
        with pytest.raises(ValueError):
            spec.build_argv("/bin/x")

    def test_sink_stdin_without_placeholder_does_not_raise(self):
        """Paired negative: the raise rules above are specific to the file
        and argv sinks, not to "template lacks a placeholder" in general --
        an argv-only config target (sink stays SINK_STDIN) must NOT raise."""
        spec = DeliverySpec(sink=SINK_STDIN, argv_template=("--config", "static.cfg"))
        assert spec.build_argv("/bin/x", "/tmp/payload.bin") == [
            "/bin/x", "--config", "static.cfg",
        ]


class TestIsFileSink:
    def test_is_file_sink_true_for_exactly_the_two_file_sinks(self):
        assert is_file_sink(SINK_FILE_ARGV) is True
        assert is_file_sink(SINK_FILE_FIXED) is True

    def test_is_file_sink_false_for_the_other_two_sinks(self):
        assert is_file_sink(SINK_STDIN) is False
        assert is_file_sink(SINK_ARGV) is False


# --------------------------------------------------------------------------
# T2: DeliverySpec.materialize
# --------------------------------------------------------------------------

class TestMaterialize:
    def test_materialize_joins_multiple_parts_without_separators(self):
        assert DeliverySpec().materialize([b"ab", b"cd"]) == b"abcd"

    def test_materialize_single_part(self):
        assert DeliverySpec().materialize([b"solo"]) == b"solo"

    def test_materialize_does_not_insert_a_trailing_newline(self):
        joined = DeliverySpec().materialize([b"a", b"b"])
        assert joined == b"ab"
        assert not joined.endswith(b"\n")


# --------------------------------------------------------------------------
# T4 / T5: the probe itself, against the four adversarial fixtures
# --------------------------------------------------------------------------

class TestProbeTruePositive:
    def test_file_vector_gate_classifies_file_candidate(self, compiled_fixtures):
        result = classify_input_vector(str(compiled_fixtures["file_vector_gate"]))
        assert result.verdict == "file-candidate"


class TestProbeAdversarialNegatives:
    @pytest.mark.parametrize(
        "fixture_name,expected_verdict",
        sorted(EXPECTED_VERDICTS.items()),
    )
    def test_fixture_classifies_as_expected(
            self, compiled_fixtures, fixture_name, expected_verdict):
        result = classify_input_vector(str(compiled_fixtures[fixture_name]))
        assert result.verdict == expected_verdict, (
            f"{fixture_name}: expected {expected_verdict!r}, got "
            f"{result.verdict!r}; evidence={result.evidence}"
        )

    def test_exactly_the_true_file_vector_fixtures_are_unsafe_file_candidate(
            self, compiled_fixtures):
        """The load-bearing gate: a false positive here is the one failure
        mode that can regress a working stdin target (see the module
        docstring on vector_probe.py). Assert the set of fixtures the probe
        calls "file-candidate" is EXACTLY the fixtures that really are one
        -- no more (would suppress a working stdin/argv target), no fewer
        (would hide a real capability the fixture-validation suite proved
        genuine)."""
        verdicts = {
            name: classify_input_vector(str(path)).verdict
            for name, path in compiled_fixtures.items()
        }
        file_candidates = {
            name for name, v in verdicts.items() if v == "file-candidate"
        }
        assert file_candidates == TRUE_FILE_CANDIDATES, (
            f"unsafe false positive/negative: expected exactly "
            f"{TRUE_FILE_CANDIDATES}, got {file_candidates}; "
            f"full verdicts={verdicts}"
        )

    def test_mech_flag_style_and_mech_fixed_path_are_documented_safe_false_negatives(
            self, compiled_fixtures):
        """These two are EXPECTED to classify "stdin" even though they are
        genuinely file-vector targets (proven solvable via their real
        transport in test_input_vector_fixture_validation.py). Do NOT "fix"
        this into a file-candidate: the probe structurally cannot observe a
        flag-gated path or a fixed hardcoded path via argv-differential
        behavior, and misclassifying either as file-candidate here would
        only paper over the probe's real blind spot rather than close it --
        the explicit operator option is what actually makes these two
        solvable, not the probe. See EXPECTED_VERDICTS' comment above."""
        for name in ("mech_flag_style", "mech_fixed_path"):
            result = classify_input_vector(str(compiled_fixtures[name]))
            assert result.verdict == "stdin", (
                f"{name}: expected the documented safe false negative "
                f"'stdin', got {result.verdict!r} -- if this ever changes, "
                f"verify it is a genuine probe improvement, not accidental "
                f"drift, before updating this expectation"
            )


# --------------------------------------------------------------------------
# T-advisory: the probe cannot mutate context because it never sees one
# --------------------------------------------------------------------------

class TestProbeIsAdvisoryOnly:
    def test_classify_input_vector_is_actually_defined(self):
        """Positive control paired with the checks below: without this, a
        rename of classify_input_vector would make the "no context"
        assertions vacuously true."""
        import supwngo.analysis.vector_probe as vp
        assert hasattr(vp, "classify_input_vector")
        assert callable(vp.classify_input_vector)

    def test_classify_input_vector_signature_takes_no_context_parameter(self):
        sig = inspect.signature(classify_input_vector)
        params = set(sig.parameters)
        assert "context" not in params
        assert "ctx" not in params
        assert "exploit_context" not in params

    def test_module_does_not_import_exploit_context_at_runtime(self):
        import supwngo.analysis.vector_probe as vp
        assert "ExploitContext" not in vp.__dict__


# --------------------------------------------------------------------------
# S7: dead "argv" INPUT_SOURCES entry removed
# --------------------------------------------------------------------------

class TestInputSourcesDeadEntryRemoved:
    def test_argv_is_not_in_input_sources(self):
        assert "argv" not in INPUT_SOURCES

    def test_input_sources_is_still_populated_with_a_known_good_key(self):
        """Paired positive check: without this, the assertion above would
        pass vacuously if INPUT_SOURCES were emptied entirely rather than
        having only the dead entry removed."""
        assert len(INPUT_SOURCES) > 0
        assert "gets" in INPUT_SOURCES
