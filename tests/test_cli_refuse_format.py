"""CLI tests: ``pwn``, ``template`` and ``offset`` refuse non-ELF targets (SP-01b, V-8).

A PE used to be half-parsed into a fabricated analysis: ``pwn`` returned
SHELLCODE at 0.9 with exit 0, and ``template`` wrote an exploit script. Each
command now detects the format first, before ``Binary.load`` and before any
output file exists.

Exit 2 is also click's usage-error code, and a usage error prints text rather
than JSON, so every JSON case here asserts the document (``error_code``, and
``error`` for ``pwn`` and ``template``) as well as the exit code (V-13).

Most cases run the real command on the real S0-PE fixtures. The ordering cases
patch ``Binary.load`` with a sentinel that fails the run if it is reached, which
keeps them independent of pwntools, angr and Ghidra.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parent))
from passcard_support import REPO_ROOT, tiny_elf  # noqa: E402

from supwngo.cli import _reset_console, cli  # noqa: E402
from supwngo.core.binary import Binary  # noqa: E402
from supwngo.exploit import offset_finder  # noqa: E402

PE_DIR = REPO_ROOT / "benchmark" / "fixtures" / "s0pe"
COMMANDS = ["pwn", "template", "offset"]

# name -> (bytes, or None to use the committed fixture, detected format)
TARGETS = {
    "pe_sym": (None, "pe"),
    "pe_strip": (None, "pe"),
    "text": (b"#!/bin/sh\nexit 0\n", "unknown"),
    "empty": (b"", "unknown"),
}


class Reached(Exception):
    """Raised by a patched ``Binary.load``: the command got past the format gate."""


@pytest.fixture(autouse=True)
def _restore_console():
    yield
    _reset_console()


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """An empty current directory, so a stray ``exploit_*.py`` shows up."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return cwd


@pytest.fixture(params=sorted(TARGETS))
def target(request, tmp_path):
    """``(path, detected format)`` for a PE fixture or a non-executable file."""
    data, detected = TARGETS[request.param]
    if data is None:
        return PE_DIR / (request.param + ".exe"), detected
    path = tmp_path / "targets" / request.param
    path.parent.mkdir()
    path.write_bytes(data)
    path.chmod(0o755)
    return path, detected


@pytest.fixture
def load_sentinel(monkeypatch):
    """Make ``Binary.load`` raise ``Reached``; the list records each call."""
    calls = []

    def load(path, *args, **kwargs):
        calls.append(path)
        raise Reached(path)

    monkeypatch.setattr(Binary, "load", staticmethod(load))
    return calls


def invoke(*args):
    return CliRunner(mix_stderr=False).invoke(cli, [str(a) for a in args])


def one_document(result):
    """Parse all of stdout as a single JSON document."""
    return json.loads(result.stdout)


def command_args(command, path, *flags):
    """``template`` is given an explicit output path under the test's cwd."""
    extra = ["-o", "out.py"] if command == "template" else []
    return [command, path, *extra, *flags]


# --- JSON mode -------------------------------------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_json_refusal_is_one_document_with_exit_2(command, target, workdir):
    """RED on the base: ``pwn`` exits 0 with a fabricated analysis, ``template``
    exits 0 and writes a script, ``offset`` has no ``error_code``."""
    path, detected = target
    result = invoke(*command_args(command, path, "--json"))
    assert result.exit_code == 2, (result.exit_code, result.output, result.exception)
    doc = one_document(result)
    assert doc["error_code"] == "unsupported_format", doc
    if command == "offset":
        assert doc["success"] is False
        assert doc["offset"] is None
        assert doc["error"]
        assert detected in doc["error"]
        assert doc["kind"] == "buf_to_ret"
    else:
        assert doc == {
            "error": "Unsupported binary format: " + detected,
            "error_code": "unsupported_format",
        }


@pytest.mark.parametrize("command", COMMANDS)
def test_json_refusal_does_not_touch_stdout_with_anything_else(
    command, target, workdir
):
    """The document is the whole of stdout; diagnostics, if any, go to stderr."""
    path, _ = target
    result = invoke(*command_args(command, path, "--json"))
    assert result.exit_code == 2, (result.exit_code, result.output, result.exception)
    assert result.stdout.lstrip().startswith("{")
    assert result.stdout.rstrip().endswith("}")
    assert "Traceback" not in result.stdout + result.stderr


# --- human mode ------------------------------------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_human_refusal_is_a_stderr_diagnostic_with_exit_2(command, target, workdir):
    """RED on the base: exit 0 (``pwn``, ``template``) or no diagnostic."""
    path, detected = target
    result = invoke(*command_args(command, path))
    assert result.exit_code == 2, (result.exit_code, result.output, result.exception)
    assert "Unsupported binary format: " + detected in result.stderr
    assert str(path) in result.stderr
    assert result.stdout == ""
    with pytest.raises(ValueError):
        json.loads(result.stderr)


# --- ordering: before Binary.load, before any output file -------------------


@pytest.mark.parametrize("json_flag", [["--json"], []], ids=["json", "human"])
@pytest.mark.parametrize("command", COMMANDS)
def test_detection_runs_before_the_binary_is_loaded(
    command, json_flag, target, workdir, load_sentinel
):
    """RED on the base: the command reaches ``Binary.load`` (exit 1, ``Reached``)."""
    path, _ = target
    result = invoke(*command_args(command, path, *json_flag))
    assert result.exit_code == 2, (
        result.exit_code,
        result.output,
        repr(result.exception),
    )
    assert load_sentinel == []


def test_offset_never_constructs_a_finder_for_a_refused_target(
    target, workdir, monkeypatch
):
    """RED on the base: it constructs a finder (after loading the binary)."""
    constructed = []

    class Recorder:
        def __init__(self, *args, **kwargs):
            constructed.append(args)

        def find_offset(self, *args, **kwargs):
            raise AssertionError("the finder must not run for a refused target")

    monkeypatch.setattr(offset_finder, "OffsetFinder", Recorder)
    monkeypatch.setattr(
        Binary, "load", staticmethod(lambda *a, **k: SimpleNamespace(bits=64))
    )
    path, _ = target
    result = invoke("offset", path, "--json")
    assert result.exit_code == 2, (
        result.exit_code,
        result.output,
        repr(result.exception),
    )
    assert constructed == []


@pytest.mark.parametrize("json_flag", [["--json"], []], ids=["json", "human"])
def test_template_with_an_output_path_writes_no_file(
    target, workdir, tmp_path, json_flag
):
    """RED on the base: ``template`` writes the requested file."""
    path, _ = target
    out = tmp_path / "elsewhere" / "exploit.py"
    out.parent.mkdir()
    result = invoke("template", path, "-o", out, *json_flag)
    assert result.exit_code == 2, (result.exit_code, result.output, result.exception)
    assert not out.exists()
    assert list(out.parent.iterdir()) == []


@pytest.mark.parametrize("json_flag", [["--json"], []], ids=["json", "human"])
def test_template_with_the_default_output_name_writes_no_file(
    target, workdir, json_flag
):
    """RED on the base: ``template`` writes ``exploit_<stem>.py`` in the cwd."""
    path, _ = target
    result = invoke("template", path, *json_flag)
    assert result.exit_code == 2, (result.exit_code, result.output, result.exception)
    assert list(workdir.iterdir()) == []


# --- what is not refused ---------------------------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_an_elf_gets_past_the_gate(command, tmp_path, workdir, load_sentinel):
    """A control: a (header-only) ELF reaches ``Binary.load``, the first thing
    each command does after the gate."""
    elf = tmp_path / "elf"
    elf.write_bytes(tiny_elf())
    result = invoke(*command_args(command, elf, "--json"))
    assert isinstance(result.exception, Reached), (
        result.exit_code,
        result.output,
        repr(result.exception),
    )
    assert load_sentinel == [str(elf)]


@pytest.mark.parametrize("name", ["pe_sym.exe", "pe_strip.exe"])
def test_decompile_on_a_pe_is_not_gated(name, monkeypatch):
    """``decompile`` keeps working on a PE: it reaches the decompiler and prints
    its code. (A control: it passes on the base and must keep passing.)"""
    from supwngo.analysis import decompile as decompile_module

    function = SimpleNamespace(
        name="main",
        address=0x401000,
        return_type="int",
        parameters=[],
        calls=["puts"],
        code='int main(void) { return puts("hi"); }',
    )
    loaded = []

    class FakeDecompiler:
        analysis_backend = "ghidra"
        angr_budget_exceeded = False

        def __init__(self, bin_obj, angr_timeout=None):
            self.decompiled_functions = {}

        def get_available_decompilers(self):
            return ["ghidra"]

        def decompile(self, **kwargs):
            return function

        def find_vulnerabilities_in_decompiled(self):
            return []

    def load(path, *args, **kwargs):
        loaded.append(path)
        return SimpleNamespace(symbols={})

    monkeypatch.setattr(decompile_module, "Decompiler", FakeDecompiler)
    monkeypatch.setattr(Binary, "load", staticmethod(load))
    path = PE_DIR / name
    result = invoke("decompile", path, "--json")
    assert result.exit_code == 0, (result.exit_code, result.output, result.exception)
    doc = one_document(result)
    assert doc["code"] == function.code
    assert "error_code" not in doc
    assert loaded == [str(path)]
