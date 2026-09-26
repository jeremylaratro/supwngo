"""
Foundation-layer gates for Sprint 2' input-vector abstraction (S1, S2, S7).

Gap analysis: docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md B-2
Plan: docs/plans/2026-09-26-sprint2prime-input-vector-plan.md, REVISION 3
(the section that governs -- the probe is advisory only, the vector is
operator-declared; no wiring into the pipeline happens in this file's scope).

This covers only the foundation layer:
  - S1: `DeliverySpec` (contracts.py) -- pure, no target needed.
  - S2: `classify_input_vector()` (analysis/vector_probe.py) -- exercised
    against the twelve purpose-built fixtures, compiled at test time.
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
import os
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
    "neg_slow_config_stdin_payload",
    # REVISION 4 (D1 pathname-confound fix, T4): two adversarial fixtures
    # copied from the peer review's counterexamples.
    "neg_argv_echo_no_open",
    "neg_fast_cfg_stdin_payload",
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
    # MEASURED false positive, deliberately kept in the suite. Its payload
    # channel is stdin; argv carries only a config file. It is nonetheless
    # classified "file-candidate" because stage 3 compares a 32-byte against a
    # 4096-byte file and this target does work proportional to config size, so
    # the large run TIMES OUT (32B -> 0.43s, 4096B -> 20.00s) and the timeout
    # itself becomes the "difference". Harmless: the probe is advisory and can
    # never commit a DeliverySpec (Sprint 2' REVISION 3). Pinned here so the
    # limitation stays measured rather than latent.
    "neg_slow_config_stdin_payload": "file-candidate",
    # REVISION 4 (T4/T5): MEASURED after the D1 pathname-confound fix (one
    # reused probe_input<ext> path across stages 1-3, instead of three
    # different basenames). This fixture only ever varied on the BASENAME
    # (its printf("target=%s\n", argv[1]) never opens the file at all), so
    # once the basename is held constant across stages, stage 2 sees no
    # difference and the probe correctly stops at "argv-only-not-opened"
    # instead of reaching stage 3. BEFORE the D1 fix this was measured
    # file-candidate/stage3_basis='output' -- a genuine false positive that
    # the D1 fix resolves. See the fixture's own header comment for both
    # measurements side by side.
    "neg_argv_echo_no_open": "argv-only-not-opened",
    # REVISION 4 (T4/T5): MEASURED file-candidate BOTH before and after the
    # D1 fix -- this false positive is NOT caused by the pathname confound.
    # The target genuinely opens argv[1] and its output genuinely depends
    # on the file's size (a real 'output' basis, not a timeout artifact),
    # it just uses that file as config rather than as the payload sink
    # (payload arrives on stdin). Kept in KNOWN_OUTPUT_BASIS_FALSE_POSITIVES
    # below because it refutes the stronger claim that a strong
    # (output/returncode) stage3_basis implies a genuine file sink -- it
    # does not; see the corrected test that replaces
    # test_stage3_basis_is_trustworthy_only_in_the_strong_direction.
    "neg_fast_cfg_stdin_payload": "file-candidate",
}

#: The only fixtures that genuinely are file-vector targets. Kept as its own
#: constant (rather than re-deriving it from EXPECTED_VERDICTS at the call
#: site) so the load-bearing "no unsafe false positive" assertion reads as
#: a single, auditable set literal.
TRUE_FILE_CANDIDATES = {"file_vector_gate", "mech_open_read_argv", "mech_line_text"}

#: Fixtures the probe calls "file-candidate" even though they are NOT file
#: targets. This set exists because the original form of this suite asserted
#: the file-candidate set was EXACTLY `TRUE_FILE_CANDIDATES`, which was green
#: only because no counterexample was in `FIXTURE_NAMES` -- adding one turned
#: the gate red. Enumerating the known miss keeps the gate meaningful (a NEW
#: false positive still fails) instead of either lying or being deleted.
#:
#: This bucket's members land on stage3_basis == "timeout" specifically. Do
#: NOT read that basis as a discriminator -- mech_line_text (a genuine file
#: sink, in TRUE_FILE_CANDIDATES) ALSO lands on "timeout", which is exactly
#: what the corrected test below (replacing
#: test_stage3_basis_is_trustworthy_only_in_the_strong_direction) pins.
KNOWN_TIMEOUT_FALSE_POSITIVES = {"neg_slow_config_stdin_payload"}

#: REVISION 4 (T4/T5) addition, measured: fixtures the probe calls
#: "file-candidate" on a "output"/"returncode" stage3_basis, even though
#: they are NOT genuine file sinks. This set is the direct refutation of
#: this suite's earlier (wrong) claim that a "strong" basis
#: (output/returncode, as opposed to the ambiguous "timeout" basis above)
#: could only ever occur for a real sink -- neg_fast_cfg_stdin_payload
#: proves that claim false: it opens argv[1] purely as size-gated config,
#: takes its real payload from stdin, and still reports basis='output'.
#: See the fixture's own header comment and the corrected test below.
KNOWN_OUTPUT_BASIS_FALSE_POSITIVES = {"neg_fast_cfg_stdin_payload"}


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

    def test_materialize_preserves_a_newline_that_is_part_of_the_payload(self):
        """Replaces an earlier `assert joined == b"ab"` followed by
        `assert not joined.endswith(b"\\n")`, which was TAUTOLOGICAL -- the
        equality already settled the suffix, so the second assertion could
        never fail independently and added no coverage.

        This case is not subsumed by the join tests above: it distinguishes an
        implementation that *preserves* payload bytes from one that strips or
        normalizes trailing whitespace. That matters because delivery must be
        byte-exact -- a stripped newline changes the offset of everything after
        it."""
        assert DeliverySpec().materialize([b"a\n"]) == b"a\n"
        assert DeliverySpec().materialize([b"a\n", b"\nb"]) == b"a\n\nb"

    def test_materialize_of_no_parts_is_empty_not_an_error(self):
        assert DeliverySpec().materialize([]) == b""


# --------------------------------------------------------------------------
# T4 / T5: the probe itself, against the adversarial fixtures
# --------------------------------------------------------------------------

class TestProbeTruePositive:
    def test_file_vector_gate_classifies_file_candidate(self, compiled_fixtures):
        result = classify_input_vector(str(compiled_fixtures["file_vector_gate"]))
        assert result.verdict == "file-candidate"


class TestExpectedVerdictsCoversEveryFixture:
    """T6(a): closes a test-vacuity gap. Before this, a fixture added only to
    FIXTURE_NAMES (e.g. by a future contributor extending the suite) silently
    got NO expected-verdict test at all: TestProbeAdversarialNegatives.
    test_fixture_classifies_as_expected only ever parametrizes over
    EXPECTED_VERDICTS.items(), so a name present in FIXTURE_NAMES but absent
    from EXPECTED_VERDICTS would simply never be checked -- a silent gap, not
    a failure. This test makes that gap loud."""

    def test_every_fixture_name_has_an_expected_verdict_and_vice_versa(self):
        assert set(EXPECTED_VERDICTS) == set(FIXTURE_NAMES), (
            f"FIXTURE_NAMES and EXPECTED_VERDICTS have drifted apart -- "
            f"only in FIXTURE_NAMES: {set(FIXTURE_NAMES) - set(EXPECTED_VERDICTS)}; "
            f"only in EXPECTED_VERDICTS: {set(EXPECTED_VERDICTS) - set(FIXTURE_NAMES)}"
        )


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
        expected = TRUE_FILE_CANDIDATES | KNOWN_TIMEOUT_FALSE_POSITIVES | KNOWN_OUTPUT_BASIS_FALSE_POSITIVES
        assert file_candidates == expected, (
            f"unsafe false positive/negative: expected exactly "
            f"{expected}, got "
            f"{file_candidates}; full verdicts={verdicts}"
        )

    def test_stage3_basis_is_diagnostic_only_never_a_discriminator(
            self, compiled_fixtures):
        """REPLACES test_stage3_basis_is_trustworthy_only_in_the_strong_direction,
        which asserted a REFUTED claim and has been removed rather than kept
        green by construction.

        That earlier test claimed a STRONG stage3_basis ('output' or
        'returncode', as opposed to the ambiguous 'timeout' basis) could only
        ever occur for a genuine file sink -- i.e. `strong <= TRUE_FILE_CANDIDATES`.
        MEASUREMENT refutes this: `neg_fast_cfg_stdin_payload` is not a file
        sink at all (its payload channel is stdin; argv only ever carries a
        size-gated config file), yet it reports stage3_basis == 'output', the
        supposedly-strong basis. (A second candidate counterexample,
        `neg_argv_echo_no_open`, existed only as an artifact of the D1
        pathname confound and is resolved by the D1 fix -- it no longer even
        reaches stage 3, see its own fixture header comment for both
        measurements.)

        The corrected, honest claim: `stage3_basis` is diagnostic metadata
        recording WHY stage 3 fired. It is NOT a discriminator in either
        direction -- neither 'timeout' nor 'output'/'returncode' may be read
        as evidence for or against a genuine file sink. This test pins that
        BOTH classes contain both a genuine sink and a non-sink, so a future
        reader cannot re-derive either the old refuted claim or a new
        unmeasured one."""
        basis_by_name = {}
        for name, path in compiled_fixtures.items():
            r = classify_input_vector(str(path))
            if r.verdict == "file-candidate":
                basis_by_name[name] = r.evidence.get("stage3_basis")

        strong = {n for n, b in basis_by_name.items()
                  if b in ("output", "returncode")}
        weak = {n for n, b in basis_by_name.items() if b == "timeout"}

        # Strong basis: measured to contain BOTH a genuine sink...
        assert strong & TRUE_FILE_CANDIDATES, (
            f"expected at least one GENUINE sink on a strong basis (measured: "
            f"file_vector_gate/mech_open_read_argv); bases={basis_by_name}")
        # ...and a non-sink -- this is the refutation of the old claim.
        assert strong & KNOWN_OUTPUT_BASIS_FALSE_POSITIVES, (
            f"expected at least one NON-sink on a strong basis (measured: "
            f"neg_fast_cfg_stdin_payload); if this stops holding, re-verify "
            f"before reintroducing any 'strong basis implies genuine sink' "
            f"claim; bases={basis_by_name}")
        # Weak (timeout) basis: already known to be ambiguous the same way.
        assert weak & TRUE_FILE_CANDIDATES, (
            f"expected at least one GENUINE sink on the weak basis (measured: "
            f"mech_line_text); bases={basis_by_name}")
        assert weak & KNOWN_TIMEOUT_FALSE_POSITIVES, (
            f"expected at least one NON-sink on the weak basis (measured: "
            f"neg_slow_config_stdin_payload); bases={basis_by_name}")

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
# T3 (D3): a launch error (OSError) past stage 0 must be labelled
# "launch-error", never conflated with a real subprocess.TimeoutExpired
# ("timeout"). None of the compiled fixtures naturally produce an OSError
# (their argv[0] is always executable and present), so this uses a
# monkeypatch of vector_probe._run to inject a real PermissionError
# deterministically on the stage-3 (4096-byte) run only -- the exact
# scenario D3 fixes.
# --------------------------------------------------------------------------

class TestStage3DistinguishesLaunchErrorFromTimeout:
    def test_oserror_on_large_run_reports_launch_error_not_timeout(
            self, compiled_fixtures, monkeypatch):
        import supwngo.analysis.vector_probe as vp

        binary = str(compiled_fixtures["mech_open_read_argv"])
        orig_run = vp._run

        def fake_run(argv, timeout, env):
            probe_path = argv[-1] if len(argv) > 1 else None
            if (probe_path and os.path.isfile(probe_path)
                    and os.path.getsize(probe_path) == 4096):
                raise PermissionError(13, "Permission denied (injected for test)")
            return orig_run(argv, timeout, env)

        monkeypatch.setattr(vp, "_run", fake_run)
        r = vp.classify_input_vector(binary, timeout=2.0)
        assert r.evidence.get("stage3_basis") == "launch-error", (
            f"an injected OSError on the large-file run must report "
            f"stage3_basis=='launch-error', not be conflated with a real "
            f"timeout; got {r.evidence.get('stage3_basis')!r}; "
            f"evidence={r.evidence}"
        )
        assert "LAUNCH ERROR" in r.evidence["large_file_run"]["output"], (
            "the injected OSError's evidence text must be distinguishable "
            f"from a timeout; got {r.evidence['large_file_run']!r}"
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

    def test_classify_input_vector_signature_is_exactly_the_expected_parameter_set(self):
        """T6(b): closes a test-vacuity gap. The prior form of this test only
        blocklisted three specific parameter NAMES ("context", "ctx",
        "exploit_context"). A caller adding, say, `state=None` and quietly
        mutating through it would keep this gate green forever -- the
        blocklist can never anticipate every name a future mutation might
        use. Asserting the full parameter set EQUALS exactly the expected
        set instead means ANY new parameter -- named anything at all --
        fails the gate, not just the three names anticipated here."""
        sig = inspect.signature(classify_input_vector)
        assert set(sig.parameters) == {"binary_path", "timeout", "env"}

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


class TestStage0RecordsWhichFailureCauseItSaw:
    """Found by a sweep answering the review's sentinel-conflation class, not by
    the review itself: stage 0 returns `inconclusive-launch` for BOTH a launch
    failure and a timeout, which is correct -- neither lets a later difference
    be attributed -- but it recorded both under an `evidence["launch_error"]`
    key, asserting a process never started when it may have started and hung.
    Same mislabel class as stage 3 reporting a PermissionError as "timeout".
    The shared verdict is deliberate; only the audit record is split."""

    def _probe(self, monkeypatch, exc):
        import supwngo.analysis.vector_probe as vp

        def boom(argv, timeout, env):
            raise exc
        monkeypatch.setattr(vp, "_run", boom)
        return vp.classify_input_vector("/bin/true")

    def test_a_launch_failure_is_recorded_as_a_launch_error(self, monkeypatch):
        r = self._probe(monkeypatch, PermissionError(13, "denied"))
        assert r.verdict == "inconclusive-launch"
        assert r.evidence["stage0_failure_cause"] == "launch-error"
        assert "launch_error" in r.evidence

    def test_a_timeout_is_not_recorded_as_a_launch_error(self, monkeypatch):
        r = self._probe(
            monkeypatch, subprocess.TimeoutExpired(cmd="/bin/true", timeout=5.0))
        assert r.verdict == "inconclusive-launch", (
            "the VERDICT must stay shared -- splitting it would change "
            "classification behavior, which is not what this fixes")
        assert r.evidence["stage0_failure_cause"] == "timeout"
        assert "launch_error" not in r.evidence, (
            "a timeout must not be filed as a launch error -- the process did "
            "start")
