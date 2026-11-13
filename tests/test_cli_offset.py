"""CLI tests for ``supwngo offset`` (SP-01b, 4.1).

``--json`` must print exactly one JSON document and exit 2 on ``success: false``.
Exit 2 is kept even though it is also click's usage-error code: a usage error
prints text, not JSON, so each negative case here asserts the document's
``error_code`` as well as the exit code.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parent))
from offset_support import (  # noqa: E402
    CRASH_OFFSET,
    EOF_SPIN_C,
    build_asm_crash,
    build_c,
    fast_budgets,
    kill_all,
    needs_gdb,
    pids_with,
    wait_until,
)
from passcard_support import needs_bwrap, needs_gcc  # noqa: E402

from supwngo.cli import _reset_console, cli  # noqa: E402
from supwngo.exploit import offset_finder  # noqa: E402
from supwngo.exploit.offset_finder import OffsetResult  # noqa: E402


@pytest.fixture(autouse=True)
def _restore_console(monkeypatch):
    monkeypatch.delenv("SUPWNGO_OUTER_SANDBOX", raising=False)
    monkeypatch.delenv("SUPWNGO_HOST_PIDNS", raising=False)
    yield
    _reset_console()


def invoke(*args):
    return CliRunner(mix_stderr=False).invoke(cli, list(args))


def one_document(result):
    """Parse all of stdout as a single JSON document."""
    return json.loads(result.stdout)


@pytest.fixture
def crash_binary(tmp_path):
    return build_asm_crash(tmp_path / "bin")


def fake_finder(monkeypatch, result):
    """Replace the finder with one that returns ``result``; record its kwargs."""
    constructed = []

    class Fake:
        def __init__(self, binary_path, bits=64, **kwargs):
            constructed.append(kwargs)

        def find_offset(self, max_length=2048, input_method="stdin", args=None):
            return result

    monkeypatch.setattr(offset_finder, "OffsetFinder", Fake)
    return constructed


# --- exit codes and the document -------------------------------------------


@needs_gcc
def test_json_failure_exits_2_with_one_document(crash_binary, monkeypatch):
    """RED on the base: it exits 0 on ``success: false``."""
    fake_finder(monkeypatch, OffsetResult(success=False, error="boom"))
    result = invoke("offset", str(crash_binary), "--json")
    assert result.exit_code == 2, (result.exit_code, result.output)
    doc = one_document(result)
    assert doc["success"] is False
    assert doc["error"] == "boom"


@needs_gcc
def test_json_success_exits_0(crash_binary, monkeypatch):
    fake_finder(
        monkeypatch, OffsetResult(offset=40, method="GDB - RIP overwrite", success=True)
    )
    result = invoke("offset", str(crash_binary), "--json")
    assert result.exit_code == 0, (result.exit_code, result.output)
    assert one_document(result)["offset"] == 40


@needs_gcc
def test_human_mode_failure_is_unchanged(crash_binary, monkeypatch):
    fake_finder(monkeypatch, OffsetResult(success=False, error="boom"))
    result = invoke("offset", str(crash_binary))
    assert result.exit_code == 0, (result.exit_code, result.output)
    assert "boom" in result.output


@needs_gcc
@pytest.mark.parametrize("flags, expected", [([], True), (["--no-sandbox"], False)])
def test_no_sandbox_reaches_the_finder(crash_binary, monkeypatch, flags, expected):
    """RED on the base: ``--no-sandbox`` is not an option."""
    constructed = fake_finder(monkeypatch, OffsetResult(offset=8, success=True))
    result = invoke("offset", str(crash_binary), "--json", *flags)
    assert result.exit_code == 0, (result.exit_code, result.output)
    assert constructed == [{"use_sandbox": expected}]


# --- real runs -------------------------------------------------------------


@needs_gcc
@needs_gdb
@needs_bwrap
def test_json_reports_the_isolation_method_and_offset(crash_binary):
    """RED on the base: no ``isolation``, ``kind`` or ``error_code`` fields."""
    result = invoke("offset", str(crash_binary), "--json", "-m", "256")
    assert result.exit_code == 0, (result.exit_code, result.output)
    doc = one_document(result)
    assert doc["isolation"] == "bwrap"
    assert doc["method"].startswith("GDB - ")
    assert doc["offset"] == CRASH_OFFSET
    assert doc["kind"] == "buf_to_ret"
    assert doc["error_code"] == ""
    assert doc["success"] is True


@needs_gcc
@needs_gdb
def test_no_sandbox_runs_unsandboxed_and_says_so(crash_binary):
    """RED on the base: ``--no-sandbox`` is not an option."""
    result = invoke("offset", str(crash_binary), "--json", "-m", "256", "--no-sandbox")
    assert result.exit_code == 0, (result.exit_code, result.output)
    doc = one_document(result)
    assert doc["isolation"] == "none"
    assert doc["offset"] == CRASH_OFFSET


@needs_gcc
def test_unrunnable_target_exits_2_with_its_preflight_code(tmp_path):
    """RED on the base: "Could not determine offset with any method", exit 0."""
    binary = build_asm_crash(tmp_path / "bin", interp="./nope/ld.so")
    result = invoke("offset", str(binary), "--json")
    assert result.exit_code == 2, (result.exit_code, result.output)
    doc = one_document(result)
    assert doc["success"] is False
    assert doc["error_code"] == "target_not_executable"
    assert "interp_missing" in doc["error"]
    assert "./nope/ld.so" in doc["error"]


@needs_gcc
@needs_bwrap
def test_eof_spin_gives_one_document_exit_2_and_a_timeout(tmp_path, monkeypatch):
    """RED on the base: exit 0 and no ``error_code``, after about 95 s of
    waiting (these budgets are shortened here)."""
    unique = "eofspin-" + uuid.uuid4().hex
    binary = build_c(tmp_path / unique, "eof_spin", EOF_SPIN_C)
    fast_budgets(monkeypatch, binary, 1.5)
    try:
        result = invoke("offset", str(binary), "--json", "-m", "64")
        assert result.exit_code == 2, (result.exit_code, result.output)
        doc = one_document(result)
        assert doc["success"] is False
        assert doc["error_code"] == "timeout"
        assert wait_until(lambda: not pids_with(unique), seconds=10.0)
    finally:
        kill_all(unique)
