"""Tests for the walkthrough CLI surface: `explain` and `solve --walkthrough`.

Split the same way as ``test_solve_command.py``:

- Fast unit tests for the CLI-layer helpers (``_walkthrough_output_path``) and
  for option wiring, which need no binary.
- ``gcc``-gated end-to-end tests that compile a tiny real vulnerable target and
  drive ``explain`` through ``CliRunner``, asserting the written artifact is a
  runnable, stub-free walkthrough -- including the degraded ``--no-probe`` case,
  which is the one that used to produce ``offset = 0  # TODO``.

Targets are compiled here rather than taken from ``benchmark/corpus/`` so these
tests do not depend on the corpus being built, and so the assertions are about
the CLI rather than about any one corpus target.

Covers `docs/plans/2026-09-23-walkthrough-engine.md`.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from supwngo.cli import DEFAULT_WALKTHROUGH_OUTPUT_DIR, _walkthrough_output_path, cli

GCC_AVAILABLE = shutil.which("gcc") is not None

#: A ret2win target: one overflowing read() and a function worth reaching.
#: Deliberately minimal so a compile failure is obviously the compiler's fault.
VULN_SOURCE = textwrap.dedent(
    """
    #include <stdio.h>
    #include <unistd.h>

    void win(void) {
        puts("WIN REACHED");
        fflush(stdout);
    }

    void vuln(void) {
        char buf[32];
        printf("Input: ");
        fflush(stdout);
        read(0, buf, 256);
    }

    int main(void) {
        setvbuf(stdout, NULL, _IONBF, 0);
        vuln();
        return 0;
    }
    """
)


@pytest.fixture(scope="module")
def compiled_target(tmp_path_factory):
    if not GCC_AVAILABLE:
        pytest.skip("gcc not available")
    workdir = tmp_path_factory.mktemp("walkthrough-cli")
    source = workdir / "vuln.c"
    source.write_text(VULN_SOURCE)
    binary = workdir / "vuln"
    result = subprocess.run(
        [
            "gcc",
            "-fno-stack-protector",
            "-no-pie",
            "-z",
            "noexecstack",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:  # pragma: no cover - toolchain problem
        pytest.skip(f"gcc could not build the fixture: {result.stderr}")
    return binary


class TestWalkthroughOutputPath:
    def test_defaults_under_the_walkthrough_output_dir(self):
        path = _walkthrough_output_path("/some/dir/challenge", None, False)
        assert path == Path(DEFAULT_WALKTHROUGH_OUTPUT_DIR) / "challenge_walkthrough.py"

    def test_markdown_gets_a_md_suffix(self):
        path = _walkthrough_output_path("./vuln", None, True)
        assert path.name == "vuln_walkthrough.md"

    def test_explicit_output_is_honoured_verbatim(self):
        path = _walkthrough_output_path("./vuln", "/tmp/elsewhere.py", False)
        assert path == Path("/tmp/elsewhere.py")

    def test_binary_name_is_kept_whole_not_stemmed(self):
        """Unlike `solve`, the extension is part of the name here: `vuln.elf`
        and `vuln` are different files and may need different walkthroughs."""
        path = _walkthrough_output_path("./vuln.elf", None, False)
        assert path.name == "vuln.elf_walkthrough.py"


class TestExplainOptionWiring:
    def test_explain_is_registered(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["explain", "--help"])
        assert result.exit_code == 0
        for option in (
            "--family",
            "--offset",
            "--no-probe",
            "--libc",
            "--remote",
            "--markdown",
            "--json",
        ):
            assert option in result.output

    def test_solve_advertises_walkthrough(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["solve", "--help"])
        assert result.exit_code == 0
        assert "--walkthrough" in result.output

    def test_missing_binary_is_rejected_before_any_work(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["explain", "/nonexistent/binary"])
        assert result.exit_code != 0
        assert "does not exist" in result.output


@pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not available")
class TestExplainEndToEnd:
    def _run(self, compiled_target, tmp_path, *extra):
        out = tmp_path / "wt.py"
        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", str(compiled_target), "-o", str(out), *extra]
        )
        return result, out

    def test_writes_a_runnable_walkthrough(self, compiled_target, tmp_path):
        result, out = self._run(compiled_target, tmp_path)
        assert result.exit_code == 0, result.output
        assert out.exists()
        text = out.read_text()
        compile(text, str(out), "exec")
        assert text.startswith("#!/usr/bin/env python3")

    def test_never_writes_a_placeholder_stub(self, compiled_target, tmp_path):
        """The specific artifact this feature exists to eliminate."""
        _result, out = self._run(compiled_target, tmp_path)
        text = out.read_text()
        assert "TODO" not in text
        assert "offset = 0" not in text

    def test_reports_the_route_it_chose(self, compiled_target, tmp_path):
        result, _out = self._run(compiled_target, tmp_path)
        assert "Family" in result.output
        assert "Route" in result.output
        assert "Steps" in result.output

    def test_no_probe_degrades_honestly_rather_than_guessing(
        self, compiled_target, tmp_path
    ):
        """With the binary never executed the offset cannot be measured.

        The contract is that the tool says so -- naming the value, why it is
        unknown, a plausible range, and the numbered step that resolves it --
        and that the artifact refuses to run with a fake value rather than
        substituting one.
        """
        result, out = self._run(compiled_target, tmp_path, "--no-probe")
        assert result.exit_code == 0, result.output
        assert "could NOT determine" in result.output
        assert "OFFSET" in result.output
        assert "plausible range" in result.output
        assert "resolve by running: step" in result.output

        text = out.read_text()
        compile(text, str(out), "exec")
        assert "TODO" not in text
        assert "offset = 0" not in text
        # The UNKNOWN sentinel raises on use; it is not a zero in disguise.
        assert "_unknown('OFFSET'" in text or '_unknown("OFFSET"' in text

    def test_supplied_offset_is_used_as_given(self, compiled_target, tmp_path):
        result, out = self._run(compiled_target, tmp_path, "--offset", "40")
        assert result.exit_code == 0, result.output
        assert "could NOT determine" not in result.output
        assert "OFFSET = 40" in out.read_text()

    def test_forced_family_is_the_family_reported(self, compiled_target, tmp_path):
        """`--family triage` must not report the best-scoring route.

        Printing `Family: triage` above `Route: ret2plt / ret2system` tells the
        reader they are reading something they are not.
        """
        result, out = self._run(compiled_target, tmp_path, "--family", "triage")
        assert result.exit_code == 0, result.output
        assert "triage" in result.output
        route_line = next(
            line for line in result.output.splitlines() if "Route" in line
        )
        assert "triage" in route_line.lower()
        compile(out.read_text(), str(out), "exec")

    def test_unknown_family_fails_loudly(self, compiled_target, tmp_path):
        result, _out = self._run(compiled_target, tmp_path, "--family", "nope")
        assert result.exit_code != 0

    def test_markdown_render_writes_markdown(self, compiled_target, tmp_path):
        out = tmp_path / "wt.md"
        runner = CliRunner()
        result = runner.invoke(
            cli, ["explain", str(compiled_target), "-o", str(out), "--markdown"]
        )
        assert result.exit_code == 0, result.output
        text = out.read_text()
        assert text.lstrip().startswith("#")
        assert "TODO" not in text

    def test_remote_target_is_templated_in(self, compiled_target, tmp_path):
        _result, out = self._run(
            compiled_target, tmp_path, "--remote", "chal.example.com:1337"
        )
        text = out.read_text()
        assert "chal.example.com" in text
        assert "1337" in text
        compile(text, str(out), "exec")

    def test_json_output_is_machine_readable(self, compiled_target, tmp_path):
        import json

        runner = CliRunner()
        result = runner.invoke(cli, ["explain", str(compiled_target), "--json"])
        assert result.exit_code == 0, result.output
        # console.print_json reformats, so locate the object and parse it.
        start = result.output.index("{")
        data = json.loads(result.output[start:])
        assert data["family"]
        assert data["steps"]
        for step in data["steps"]:
            assert step["expect"]
            assert step["verify"]

    def test_every_step_runs_standalone(self, compiled_target, tmp_path):
        """The self-containment claim, executed rather than asserted.

        Each step is invoked on its own, in a fresh interpreter, from the
        target's directory -- exactly as a reader would. A step that only works
        as part of a full run is not a step.
        """
        _result, out = self._run(compiled_target, tmp_path)
        listing = subprocess.run(
            ["python3", str(out), "steps"],
            capture_output=True,
            text=True,
            cwd=compiled_target.parent,
            timeout=300,
        )
        assert listing.returncode == 0, listing.stderr
        numbers = [
            line.split()[0]
            for line in listing.stdout.splitlines()
            if line.strip()[:1].isdigit()
        ]
        assert numbers, listing.stdout

        for number in numbers:
            run = subprocess.run(
                ["python3", str(out), number],
                capture_output=True,
                text=True,
                cwd=compiled_target.parent,
                timeout=300,
            )
            combined = run.stdout + run.stderr
            # A step may legitimately report failure (the reader is meant to
            # read the troubleshooting block); it may not crash.
            assert "Traceback" not in combined, f"step {number} crashed:\n{combined}"
            assert "NameError" not in combined, f"step {number} crashed:\n{combined}"
