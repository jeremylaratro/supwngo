"""Tests for the analysis-to-report adapter.

``reporting/`` shipped unreachable from the CLI because nothing converted the
``Vulnerability`` objects the detectors emit into the ``VulnerabilityReport``
the writers consume. These tests cover that adapter, and in particular the two
ways a generated report could lie:

- reporting "no vulnerabilities" when the detectors never ran, and
- rendering unmeasured protections as disabled protections.

Each such test carries its converse as a positive control in the same test, so
it cannot pass by measuring nothing: the assertion that a failure *is* recorded
sits next to the assertion that a clean run records *no* failure.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from supwngo.core.binary import Binary
from supwngo.reporting.adapter import (
    DetectorFailure,
    binary_info,
    build_report,
    detect_all,
    finding_from_vulnerability,
    parse_failure_reason,
    static_detectors,
)
from supwngo.reporting.cvss import CVSSCalculator
from supwngo.vulns.detector import Vulnerability, VulnSeverity, VulnType

GCC_AVAILABLE = shutil.which("gcc") is not None

SOURCE = """
#include <stdio.h>
#include <unistd.h>
int main(void) { char buf[64]; read(0, buf, 512); printf(buf); return 0; }
"""


@pytest.fixture(scope="module")
def real_binary(tmp_path_factory) -> Path:
    if not GCC_AVAILABLE:
        pytest.skip("gcc not on PATH")
    d = tmp_path_factory.mktemp("adapter_target")
    src = d / "target.c"
    src.write_text(SOURCE)
    out = d / "target"
    subprocess.run(
        ["gcc", "-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0",
         "-o", str(out), str(src)],
        check=True, capture_output=True, text=True,
    )
    assert out.is_file(), "gcc did not produce the fixture target"
    return out


def _stub_binary(tmp_path: Path) -> Binary:
    """A Binary over a real file, without invoking the ELF loaders."""
    path = tmp_path / "stub"
    path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return Binary(path=path, arch="amd64", bits=64)


class _Boom:
    """A detector that always raises."""

    name = "boom_detector"

    def __init__(self, binary):
        self.binary = binary

    def detect(self, crash=None):
        raise RuntimeError("detector exploded")


class _Finds:
    """A detector that always reports one finding."""

    name = "finds_detector"

    def __init__(self, binary):
        self.binary = binary

    def detect(self, crash=None):
        return [
            Vulnerability(
                vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                severity=VulnSeverity.HIGH,
                address=0x401136,
                function="main",
                description="stub finding",
            )
        ]


class TestDetectAll:
    def test_a_raising_detector_is_recorded_and_does_not_lose_the_others(self, tmp_path):
        """A failure must surface as a failure, and must not cost the findings
        of the detectors that did work. Both halves asserted together: if the
        collection logic silently dropped everything, the second assertion
        would fail, and if it swallowed the exception, the first would."""
        binary = _stub_binary(tmp_path)
        vulns, failures = detect_all(binary, detectors=[_Boom, _Finds])

        assert len(failures) == 1, f"the raising detector was not recorded: {failures}"
        assert failures[0].detector == "boom_detector"
        assert "RuntimeError" in failures[0].error
        assert "detector exploded" in failures[0].error

        assert len(vulns) == 1, "the working detector's finding was lost"
        assert vulns[0].function == "main"

    def test_a_clean_run_records_no_failure(self, tmp_path):
        """Positive control for the test above: the same machinery must report
        zero failures when nothing fails, otherwise 'failures were recorded'
        proves nothing."""
        binary = _stub_binary(tmp_path)
        vulns, failures = detect_all(binary, detectors=[_Finds])
        assert failures == []
        assert len(vulns) == 1

    @pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not on PATH")
    def test_the_default_detectors_all_honour_the_no_arg_detect_contract(self, real_binary):
        """Every class in ``static_detectors()`` must be callable as
        ``detect()``. This is the guard behind excluding UAFDetector and
        OffByOneDetector: because ``detect_all`` collects exceptions rather than
        raising, a signature mismatch would otherwise show up only as a
        detector that mysteriously always fails."""
        binary = Binary.load(str(real_binary))
        _, failures = detect_all(binary)
        signature_errors = [f for f in failures if "TypeError" in f.error]
        assert not signature_errors, (
            f"detector(s) do not honour detect(crash=None): {signature_errors}"
        )


class TestBuildReport:
    def test_zero_findings_with_a_failed_detector_does_not_read_as_clean(self, tmp_path):
        """The report a reader treats as evidence. With no findings *and* a
        failed detector it must state the run was incomplete."""
        binary = _stub_binary(tmp_path)
        doc = build_report(
            binary, [], failures=[DetectorFailure("boom_detector", "RuntimeError: x")]
        )

        assert doc.metadata["complete"] is False
        assert doc.metadata["detectors_failed"] == 1
        assert doc.metadata["detector_failures"][0]["detector"] == "boom_detector"
        assert "incomplete" in doc.summary.lower(), (
            f"summary does not disclose the failed detector: {doc.summary!r}"
        )
        assert "boom_detector" in doc.summary

    def test_zero_findings_with_no_failures_does_read_as_clean(self, tmp_path):
        """Positive control: the incompleteness disclosure must be absent when
        the run really was complete, or the assertion above is vacuous."""
        binary = _stub_binary(tmp_path)
        doc = build_report(binary, [], failures=[])

        assert doc.metadata["complete"] is True
        assert doc.metadata["detectors_failed"] == 0
        assert "incomplete" not in doc.summary.lower()

    def test_findings_are_converted_and_counted(self, tmp_path):
        binary = _stub_binary(tmp_path)
        vulns, _ = detect_all(binary, detectors=[_Finds])
        doc = build_report(binary, vulns)

        assert len(doc.findings) == 1
        assert doc.get_severity_counts()["high"] == 1
        assert doc.get_overall_risk() == "High"

    def test_title_defaults_to_the_binary_name(self, tmp_path):
        binary = _stub_binary(tmp_path)
        assert "stub" in build_report(binary, []).title
        assert build_report(binary, [], title="Custom").title == "Custom"


class TestParseFailure:
    """A file no loader could parse must not produce a clean-looking report.

    This is the same defect class as a swallowed detector failure, one level
    up: the detectors do not fail, they run against an empty ``Binary`` and
    truthfully find nothing. Caught by running `report` against a text file,
    which produced "0 findings, risk Informational, complete: true".
    """

    def test_an_unparsed_binary_is_reported_as_a_parse_failure(self, tmp_path):
        path = tmp_path / "not_an_elf.txt"
        path.write_text("this is not an executable")
        binary = Binary(path=path)  # arch stays "" -- nothing identified it

        reason = parse_failure_reason(binary)
        assert reason is not None
        assert "not_an_elf.txt" in reason

    def test_a_parsed_binary_is_not_flagged(self, tmp_path):
        """Positive control: the check keys on a missing arch, so a binary that
        did parse must come back clean, or the guard would reject everything."""
        binary = _stub_binary(tmp_path)  # constructed with arch="amd64"
        assert parse_failure_reason(binary) is None

    @pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not on PATH")
    def test_a_real_loaded_binary_is_not_flagged(self, real_binary):
        """The control that matters most: a genuinely loaded ELF must pass, or
        the guard would block every real analysis."""
        assert parse_failure_reason(Binary.load(str(real_binary))) is None

    def test_an_unparsed_binary_makes_the_report_incomplete(self, tmp_path):
        """Zero findings plus zero detector failures must still not read as
        complete when the target was never parsed."""
        path = tmp_path / "not_an_elf.txt"
        path.write_text("this is not an executable")
        doc = build_report(Binary(path=path), [], failures=[])

        assert doc.metadata["binary_parsed"] is False
        assert doc.metadata["complete"] is False, (
            "an unparsed target produced a report marked complete"
        )
        assert doc.metadata["detectors_failed"] == 0, (
            "the parse failure should not be miscounted as a detector failure"
        )
        assert "never parsed" in doc.summary

    def test_a_parsed_binary_with_no_findings_is_complete(self, tmp_path):
        """Positive control: `complete` must still be reachable, otherwise the
        assertion above passes on a field that is always False."""
        doc = build_report(_stub_binary(tmp_path), [], failures=[])
        assert doc.metadata["binary_parsed"] is True
        assert doc.metadata["complete"] is True


class TestBinaryInfo:
    def test_unmeasured_protections_are_not_rendered_as_disabled(self, tmp_path):
        """``nx: false`` is a claim that NX is off. When detection never ran,
        the flags must be omitted rather than defaulted, because the reader
        cannot tell the two apart."""
        binary = _stub_binary(tmp_path)
        binary.protections_measured = False

        info = binary_info(binary)
        assert info.protections["measured"] is False
        for flag in ("nx", "canary", "pie", "relro"):
            assert flag not in info.protections, (
                f"{flag} was reported despite protections never being measured"
            )
        assert "note" in info.protections

    def test_measured_protections_are_reported(self, tmp_path):
        """Positive control: when protections *were* measured the flags must be
        present, otherwise the omission above could come from a broken branch
        rather than from the measured/unmeasured distinction."""
        binary = _stub_binary(tmp_path)
        binary.protections_measured = True
        binary.protections.nx = True

        info = binary_info(binary)
        assert info.protections["measured"] is True
        assert info.protections["nx"] is True
        assert "canary" in info.protections

    def test_header_carries_identity_and_hash(self, tmp_path):
        binary = _stub_binary(tmp_path)
        info = binary_info(binary)
        assert info.name == "stub"
        assert info.architecture == "amd64"
        assert info.bits == 64
        assert len(info.file_hash) == 64, "sha256 not propagated to the report header"
        assert info.file_size > 0


class TestFindingConversion:
    def test_finding_carries_a_cvss_score_and_vector(self):
        finding = finding_from_vulnerability(
            Vulnerability(
                vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                severity=VulnSeverity.CRITICAL,
                address=0x401136,
                function="vuln",
                description="overflow in vuln()",
            )
        )
        assert finding.vuln_type == "stack_buffer_overflow"
        assert finding.severity == "critical"
        assert finding.location == "vuln"
        assert finding.cvss_score > 0.0
        assert finding.cvss_vector.startswith("CVSS:3.1/")

    def test_remote_flag_raises_the_attack_vector(self):
        """``--remote`` must actually change the score, not just be accepted."""
        vuln = Vulnerability(
            vuln_type=VulnType.STACK_BUFFER_OVERFLOW, severity=VulnSeverity.HIGH
        )
        local = finding_from_vulnerability(vuln, remote=False)
        remote = finding_from_vulnerability(vuln, remote=True)
        assert "AV:N" in remote.cvss_vector
        assert "AV:N" not in local.cvss_vector

    def test_location_falls_back_to_the_address(self):
        finding = finding_from_vulnerability(
            Vulnerability(
                vuln_type=VulnType.FORMAT_STRING,
                severity=VulnSeverity.HIGH,
                address=0x401200,
            )
        )
        assert finding.location == "0x401200"

    @pytest.mark.parametrize("vuln_type", list(VulnType))
    def test_every_vuln_type_converts(self, vuln_type):
        """No VulnType may be dropped. Types without a dedicated CVSS vector
        must still score against the default vector rather than raise."""
        finding = finding_from_vulnerability(
            Vulnerability(vuln_type=vuln_type, severity=VulnSeverity.MEDIUM)
        )
        assert finding.vuln_type == vuln_type.name.lower()
        assert finding.cvss_vector.startswith("CVSS:3.1/")

    def test_the_set_of_vuln_types_without_a_cvss_vector_is_the_known_set(self):
        """Pins which VulnTypes fall back to the default vector. Adding a new
        VulnType without giving it a vector fails here, so the fallback stays a
        decision rather than an accident."""
        keys = set(CVSSCalculator.VULN_VECTORS)
        unmapped = {v.name.lower() for v in VulnType} - keys
        assert unmapped == {"integer_underflow", "null_pointer_deref", "unknown"}, (
            f"VulnType/CVSS coverage changed: {unmapped}"
        )
