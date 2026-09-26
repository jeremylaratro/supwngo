"""Tests for the `supwngo report` command.

The whole point of this command is the wiring -- ``reporting/`` was fully
implemented but unreachable from the CLI -- so these tests drive the real
``CliRunner`` invocation rather than calling ``build_report`` directly. A test
that called the library function would pass even if the command were never
registered, which is precisely the defect being fixed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

import supwngo
from supwngo.cli import _report_format_from_extension, _report_output_path, cli

GCC_AVAILABLE = shutil.which("gcc") is not None

SOURCE = """
#include <stdio.h>
#include <unistd.h>
int main(void) { char buf[64]; read(0, buf, 512); printf(buf); return 0; }
"""


@pytest.fixture(scope="module")
def target(tmp_path_factory) -> Path:
    if not GCC_AVAILABLE:
        pytest.skip("gcc not on PATH")
    d = tmp_path_factory.mktemp("report_target")
    src = d / "target.c"
    src.write_text(SOURCE)
    out = d / "target"
    subprocess.run(
        ["gcc", "-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0",
         "-o", str(out), str(src)],
        check=True, capture_output=True, text=True,
    )
    return out


class TestRegistration:
    def test_report_is_a_registered_command(self):
        """The defect was 'implemented but unreachable'; this is the direct
        assertion that it is reachable."""
        assert "report" in cli.commands

    def test_help_is_reachable(self):
        result = CliRunner().invoke(cli, ["report", "--help"])
        assert result.exit_code == 0, result.output
        assert "--format" in result.output


class TestOutputPathHelpers:
    def test_format_is_inferred_from_the_output_extension(self):
        assert _report_format_from_extension("out.sarif") == "sarif"
        assert _report_format_from_extension("out.md") == "markdown"
        assert _report_format_from_extension("out.html") == "html"
        assert _report_format_from_extension("out.htm") == "html"
        assert _report_format_from_extension("out.json") == "json"

    def test_an_unknown_extension_infers_nothing(self):
        """Positive control for the above: the helper must return None rather
        than guessing, or 'inferred correctly' would be unfalsifiable."""
        assert _report_format_from_extension("out.bin") is None
        assert _report_format_from_extension(None) is None

    def test_explicit_output_wins_over_the_default_path(self):
        assert _report_output_path("/x/vuln", "/tmp/custom.sarif", "sarif") == Path("/tmp/custom.sarif")

    def test_default_path_uses_the_binary_name_and_format_extension(self):
        assert _report_output_path("/x/vuln", None, "sarif").name == "vuln_report.sarif"
        assert _report_output_path("/x/vuln", None, "markdown").name == "vuln_report.md"


@pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not on PATH")
class TestEndToEnd:
    def test_sarif_output_is_valid_and_stamped_with_the_package_version(self, target, tmp_path):
        """Also the regression guard for the SARIF exporter's hardcoded
        "1.0.0": the tool version in real output must track the package."""
        out = tmp_path / "r.sarif"
        result = CliRunner().invoke(cli, ["report", str(target), "-o", str(out)])
        assert result.exit_code == 0, result.output
        assert out.is_file(), "no report file was written"

        doc = json.loads(out.read_text())
        assert doc["version"] == "2.1.0"
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "supwngo"
        assert driver["version"] == supwngo.__version__, (
            f"SARIF claims tool version {driver['version']!r} but the package is "
            f"{supwngo.__version__!r}"
        )

    def test_findings_reach_the_sarif_results(self, target, tmp_path):
        """The fixture reads 512 bytes into a 64-byte buffer and passes user
        input to printf, so a report with zero results would mean the detectors
        are not being run at all."""
        out = tmp_path / "r.sarif"
        result = CliRunner().invoke(cli, ["report", str(target), "-o", str(out)])
        assert result.exit_code == 0, result.output

        doc = json.loads(out.read_text())
        results = doc["runs"][0]["results"]
        assert results, "no SARIF results; the detectors did not run or were not converted"
        assert all(r["ruleId"] for r in results)
        assert doc["runs"][0]["tool"]["driver"]["rules"], "results carry no rule definitions"

    @pytest.mark.parametrize(
        "fmt,suffix", [("markdown", ".md"), ("json", ".json"), ("html", ".html"), ("text", ".txt")]
    )
    def test_every_advertised_format_writes_content(self, target, tmp_path, fmt, suffix):
        out = tmp_path / f"r{suffix}"
        result = CliRunner().invoke(cli, ["report", str(target), "--format", fmt, "-o", str(out)])
        assert result.exit_code == 0, result.output
        assert out.is_file() and out.stat().st_size > 0, f"{fmt} produced no content"

    def test_json_output_reports_completeness(self, target, tmp_path):
        out = tmp_path / "r.sarif"
        result = CliRunner().invoke(
            cli, ["report", str(target), "-o", str(out), "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{"):])
        assert payload["report"] == str(out)
        assert payload["format"] == "sarif"
        assert payload["detectors_attempted"] > 0
        assert payload["complete"] is True
        assert payload["detectors_failed"] == 0
        assert payload["detector_failures"] == []

    def test_missing_binary_is_rejected(self, tmp_path):
        result = CliRunner().invoke(cli, ["report", str(tmp_path / "nope")])
        assert result.exit_code != 0

    def test_json_output_reports_that_the_binary_parsed(self, target, tmp_path):
        out = tmp_path / "r.sarif"
        result = CliRunner().invoke(cli, ["report", str(target), "-o", str(out), "--json"])
        payload = json.loads(result.output[result.output.index("{"):])
        assert payload["binary_parsed"] is True


class TestUnparsableInput:
    def test_a_non_elf_is_refused_and_no_report_is_written(self, tmp_path):
        """Found by running the command against a text file: it emitted "0
        findings, risk Informational, complete: true" and exit 0 -- a clean bill
        of health for a file neither loader had parsed."""
        src = tmp_path / "notelf.txt"
        src.write_text("this is not an executable")
        out = tmp_path / "r.sarif"

        result = CliRunner().invoke(cli, ["report", str(src), "-o", str(out)])

        assert result.exit_code == 1, result.output
        assert not out.exists(), (
            "a report was written for a file that could not be parsed"
        )
        assert "Cannot analyse this file" in result.output
        assert "never parsed" in result.output

    @pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not on PATH")
    def test_a_real_binary_is_not_refused(self, target, tmp_path):
        """Positive control for the refusal above: it must be specific to
        unparsable input, not a blanket rejection."""
        out = tmp_path / "r.sarif"
        result = CliRunner().invoke(cli, ["report", str(target), "-o", str(out)])
        assert result.exit_code == 0, result.output
        assert out.is_file()


@pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not on PATH")
class TestFailureDisclosure:
    def test_all_detectors_failing_exits_nonzero_and_writes_nothing(
        self, target, tmp_path, monkeypatch
    ):
        """A report generated when nothing could be analysed would be a
        document asserting a clean binary on no evidence. The command must
        refuse to produce it."""
        from supwngo.reporting import adapter

        def all_fail(binary, detectors=None):
            names = [getattr(c, "name", c.__name__) for c in adapter.static_detectors()]
            return [], [adapter.DetectorFailure(n, "RuntimeError: injected") for n in names]

        monkeypatch.setattr(adapter, "detect_all", all_fail)

        out = tmp_path / "r.sarif"
        result = CliRunner().invoke(cli, ["report", str(target), "-o", str(out)])

        assert result.exit_code == 1, result.output
        assert not out.exists(), "a report was written even though nothing was analysed"
        assert "Every detector failed" in result.output

    def test_partial_failure_still_reports_but_discloses_it(
        self, target, tmp_path, monkeypatch
    ):
        """Positive control for the test above: one failure out of many must
        NOT block the report, so the exit-1 behaviour is specific to 'nothing
        ran' rather than to 'any failure'."""
        from supwngo.reporting import adapter

        real = adapter.detect_all

        def one_fails(binary, detectors=None):
            vulns, failures = real(binary, detectors)
            return vulns, list(failures) + [
                adapter.DetectorFailure("injected_detector", "RuntimeError: injected")
            ]

        monkeypatch.setattr(adapter, "detect_all", one_fails)

        out = tmp_path / "r.sarif"
        result = CliRunner().invoke(cli, ["report", str(target), "-o", str(out)])

        assert result.exit_code == 0, result.output
        assert out.is_file(), "a partial failure should not suppress the report"
        assert "Incomplete" in result.output
        assert "injected_detector" in result.output
