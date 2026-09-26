"""
Tests for the `solve` CLI command (Phase 6 of
docs/plans/2026-09-23-effectiveness-and-usability.md - "unified end-to-end
command").

Split into two groups:

- Fast, no-binary-needed unit tests for the small CLI-layer helpers
  (`_default_solve_output_path`, `_parse_remote_target`,
  `_fill_remote_placeholders`) and flag-validation behavior
  (`--json`/`--interactive` mutual exclusivity, `--remote` parsing).
- Slower, `gcc`-gated end-to-end tests that compile a tiny real ret2win
  target and drive `solve` through `CliRunner`, mirroring the manual smoke
  tests recorded in the branch's final report: a plain success case (no
  `--interactive` needed) and a guided-fallback case (offset not
  auto-discoverable; `--interactive` supplies it and resumes to SUCCESS).
  Skipped when `gcc` isn't on PATH, matching this repo's existing
  `TEST_BINARIES`-not-found skip pattern for binary-dependent tests.
"""

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from supwngo.cli import (
    _default_solve_output_path,
    _fill_remote_placeholders,
    _parse_remote_target,
    cli,
)

GCC_AVAILABLE = shutil.which("gcc") is not None


class TestDefaultSolveOutputPath:
    def test_uses_binary_stem_under_solve_output_dir(self):
        path = _default_solve_output_path("/some/dir/challenge")
        assert path == Path("./solve_output/challenge_exploit.py")

    def test_strips_extension_from_binary_name(self):
        path = _default_solve_output_path("./vuln.elf")
        assert path.name == "vuln_exploit.py"


class TestParseRemoteTarget:
    def test_valid_host_port(self):
        host, port = _parse_remote_target("chal.example.com:1337")
        assert host == "chal.example.com"
        assert port == 1337

    def test_ipv4_host_port(self):
        host, port = _parse_remote_target("10.0.0.5:4444")
        assert host == "10.0.0.5"
        assert port == 4444

    def test_missing_port_raises(self):
        with pytest.raises(Exception):
            _parse_remote_target("chal.example.com")

    def test_non_integer_port_raises(self):
        with pytest.raises(Exception):
            _parse_remote_target("chal.example.com:notaport")

    def test_empty_host_raises(self):
        with pytest.raises(Exception):
            _parse_remote_target(":1337")


class TestFillRemotePlaceholders:
    def test_fills_both_placeholders(self):
        script = 'REMOTE_HOST = ""\nREMOTE_PORT = 0\n'
        filled = _fill_remote_placeholders(script, "chal.example.com", 1337)
        assert 'REMOTE_HOST = "chal.example.com"' in filled
        assert "REMOTE_PORT = 1337" in filled

    def test_no_host_leaves_script_unchanged(self):
        script = 'REMOTE_HOST = ""\nREMOTE_PORT = 0\n'
        assert _fill_remote_placeholders(script, None, None) == script

    def test_empty_script_returns_empty(self):
        assert _fill_remote_placeholders("", "host", 1) == ""


class TestSolveFlagValidation:
    def test_json_and_interactive_are_mutually_exclusive(self, tmp_path):
        # A dummy (non-ELF) file satisfies click.Path(exists=True) - the
        # --json/--interactive check runs before Binary.load(), so this
        # never needs a real binary.
        dummy = tmp_path / "not_a_binary"
        dummy.write_text("not an elf")

        runner = CliRunner()
        result = runner.invoke(cli, ["solve", str(dummy), "--json", "--interactive"])

        assert result.exit_code != 0
        assert "--interactive" in result.output and "--json" in result.output

    def test_bad_remote_format_rejected(self, tmp_path):
        dummy = tmp_path / "not_a_binary"
        dummy.write_text("not an elf")

        runner = CliRunner()
        result = runner.invoke(cli, ["solve", str(dummy), "--remote", "no-port-here"])

        assert result.exit_code != 0

    def test_solve_command_registered(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert "solve" in result.output


RET2WIN_SOURCE = textwrap.dedent(r"""
    #include <stdio.h>
    #include <stdlib.h>

    void win() {
        system("/bin/sh");
    }

    void vuln() {
        char buf[32];
        printf("Enter data: ");
        fflush(stdout);
        gets(buf);
        printf("You entered: %s\n", buf);
    }

    int main() {
        setvbuf(stdout, NULL, _IONBF, 0);
        vuln();
        return 0;
    }
""")

# A larger buffer pushes the real offset past ret2win's COMMON_RET_OFFSETS
# fallback list (see supwngo/exploit/pipeline/executors/stack_techniques.py),
# so a plain `solve` run FAILS with "buffer-to-return-address offset not
# determined" in blocking_unknowns - exactly the guided-fallback scenario
# --interactive exists for.
HARD_OFFSET_SOURCE = RET2WIN_SOURCE.replace("char buf[32];", "char buf[277];")


def _compile(source: str, out_path: Path, extra_flags=()) -> None:
    src_path = out_path.with_suffix(".c")
    src_path.write_text(source)
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", *extra_flags, "-w", "-o", str(out_path), str(src_path)],
        check=True, capture_output=True,
    )


def _run_solve(*args: str, input_text: str = "") -> subprocess.CompletedProcess:
    """Drive `solve` via a REAL subprocess (`python3 -m supwngo.cli solve
    ...`), not `click.testing.CliRunner`. `CliRunner` replaces
    `sys.stdin`/`sys.stdout` with objects that have no usable `fileno()`,
    which breaks pwntools' `process()`/`ELF()` internals deep inside the
    pipeline's technique executors (observed independently of this
    command: `ret2win`'s executor came back `AttemptOutcome.ERROR` and
    `direct_shellcode` failed with "could not spawn process for delivery"
    under `CliRunner`, even though the exact same binary/flags succeed
    from a real shell - this is a test-harness/pwntools-fileno interaction,
    not a `solve` bug). A real subprocess gives pwntools genuine
    (pipe-backed, `fileno()`-capable) stdio, matching how `solve` is
    actually invoked and matching the manual verification in this
    branch's final report."""
    return subprocess.run(
        ["python3", "-m", "supwngo.cli", "solve", *args],
        input=input_text, capture_output=True, text=True, timeout=90,
    )


@pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not available")
class TestSolveEndToEnd:
    """Real compiled-binary smoke tests, not mocks - mirrors the manual
    verification performed for this branch's final report. Drives `solve`
    as a real subprocess (see `_run_solve`), not `CliRunner`."""

    def test_ret2win_reaches_verified_success_and_writes_script(self, tmp_path):
        binary = tmp_path / "ret2win"
        _compile(RET2WIN_SOURCE, binary)
        output = tmp_path / "exploit.py"

        result = _run_solve(str(binary), "-o", str(output))

        assert result.returncode == 0, result.stdout + result.stderr
        assert "SUCCESS" in result.stdout
        assert output.exists()
        content = output.read_text()
        assert content.strip() != ""
        assert "def exploit():" in content
        assert "ret2win" in content

    def test_remote_flag_templates_generated_script(self, tmp_path):
        binary = tmp_path / "ret2win"
        _compile(RET2WIN_SOURCE, binary)
        output = tmp_path / "exploit.py"

        result = _run_solve(str(binary), "-o", str(output), "--remote", "chal.example.com:1337")

        assert result.returncode == 0, result.stdout + result.stderr
        content = output.read_text()
        assert 'REMOTE_HOST = "chal.example.com"' in content
        assert "REMOTE_PORT = 1337" in content

    def test_guided_fallback_resumes_to_success_with_supplied_offset(self, tmp_path):
        binary = tmp_path / "hardoffset"
        _compile(HARD_OFFSET_SOURCE, binary)

        # First, a plain (non-interactive) run must NOT reach SUCCESS and
        # must flag the offset as a blocking unknown - this is the
        # precondition for the guided-fallback scenario being real, not
        # assumed.
        plain_output = tmp_path / "plain_exploit.py"
        plain_result = _run_solve(str(binary), "-o", str(plain_output))
        assert plain_result.returncode == 1, (
            f"expected rc=1 for a failed solve, got {plain_result.returncode}"
        )
        assert "Result: SUCCESS" not in plain_result.stdout
        assert "buffer-to-return-address offset not determined" in plain_result.stdout

        # Discover the real offset the same way a human/PoC would, to
        # supply to the guided-fallback prompt.
        offset_script = textwrap.dedent(f"""
            from pwn import cyclic, cyclic_find, context, process
            context.log_level = "error"
            p = process([{str(binary)!r}])
            p.sendlineafter(b":", cyclic(400))
            p.wait()
            print(cyclic_find(p.corefile.fault_addr))
        """)
        offset_result = subprocess.run(
            ["python3", "-c", offset_script], capture_output=True, text=True, timeout=30,
        )
        assert offset_result.returncode == 0, offset_result.stderr
        offset = int(offset_result.stdout.strip().splitlines()[-1])

        guided_output = tmp_path / "guided_exploit.py"
        # Prompt 1: pick the (only) blocking unknown -> "1". Prompt 2: its value.
        guided_result = _run_solve(
            str(binary), "-o", str(guided_output), "--interactive",
            input_text=f"1\n{offset}\n",
        )

        assert guided_result.returncode == 0, guided_result.stdout + guided_result.stderr
        assert "Guided fallback reached verified SUCCESS." in guided_result.stdout
        assert guided_output.exists()
        assert "ret2win" in guided_output.read_text()
