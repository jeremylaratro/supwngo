"""SP-01b 4.2 / V-7: the angr decompile worker returns a tagged union.

The worker used to return ``{"found": True, ..., "code": "// Decompilation
failed ..."}`` whenever angr produced no pseudo-C, and the parent accepted that
sentinel as a function. Worse, ``CFGFast`` was built without ``normalize=True``,
so on this host angr's ``Decompiler`` got a non-normalised function and the
fallback never produced code at all.

The contract under test:

* worker reply: ``{"status": "ok" | "missing_function" | "decompiler_failed" |
  "exception", ...}``; only ``ok`` carries ``code``;
* parent: adds ``timeout``, validates the union, records the status and returns
  ``None`` on every non-``ok`` status; a reply that is not the union (the legacy
  ``found`` shape, a sentinel body) is never a function;
* ``decompile --json`` failure exits 2.

Mechanics (plan V-12): the worker is exercised through a fake angr project, so
the three failure statuses are deterministic; the parent is exercised by
patching ``run_angr_op``; the sentinel RED feeds the *legacy* worker reply; the
CLI test uses ``CliRunner(mix_stderr=False)`` because it parses ``--json`` stdout.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

import supwngo.analysis._angr_subprocess as sub
from supwngo.analysis.decompile import Decompiler

GCC = shutil.which("gcc")
FIXTURE_SRC = Path(__file__).parent / "fixtures" / "angr_callgraph" / "two_funcs.c"
SENTINEL = "// Decompilation failed for leaf_helper"
LEGACY_SENTINEL_REPLY = {
    "found": True,
    "name": "leaf_helper",
    "address": 0x401136,
    "return_type": "void",
    "code": SENTINEL,
    "calls": ["printf"],
}


# --------------------------------------------------------------------------- #
# Worker: tagged union, via a fake angr project
# --------------------------------------------------------------------------- #


class _FakeFunc:
    def __init__(self, name="leaf_helper", addr=0x401136):
        self.name = name
        self.addr = addr


class _FakeCodegen:
    def __init__(self, text):
        self.text = text


def _fake_project(monkeypatch, *, decompiler, funcs=None, record=None):
    """Make ``_load_project`` return a project whose angr analyses are fakes."""
    funcs = {0x401136: _FakeFunc()} if funcs is None else funcs
    cfg = types.SimpleNamespace(kb=types.SimpleNamespace(functions=funcs))

    def cfgfast(**kwargs):
        if record is not None:
            record.update(kwargs)
        return cfg

    analyses = types.SimpleNamespace(CFGFast=cfgfast, Decompiler=decompiler)
    proj = types.SimpleNamespace(analyses=analyses)
    monkeypatch.setattr(sub, "_load_project", lambda path: proj)
    # The worker lists callees through iter_callees; the fakes have none.
    monkeypatch.setattr(
        "supwngo.analysis._angr_callgraph.iter_callees", lambda func, funcs: []
    )
    return proj


def _decompiler_returning(codegen):
    def make(func, cfg=None):
        return types.SimpleNamespace(codegen=codegen)

    return make


def _decompiler_raising(exc):
    def make(func, cfg=None):
        raise exc

    return make


def test_worker_builds_a_normalised_cfg(monkeypatch):
    seen = {}
    _fake_project(
        monkeypatch,
        decompiler=_decompiler_returning(_FakeCodegen("int f(void)\n{ return 0; }")),
        record=seen,
    )
    sub._op_decompile("x", func_name="leaf_helper")
    assert seen.get("normalize") is True


def test_worker_ok_carries_code_and_status(monkeypatch):
    _fake_project(
        monkeypatch,
        decompiler=_decompiler_returning(_FakeCodegen("int f(void)\n{ return 0; }")),
    )
    reply = sub._op_decompile("x", func_name="leaf_helper")
    assert reply["status"] == "ok"
    assert reply["code"].startswith("int f")
    assert reply["name"] == "leaf_helper"


def test_worker_missing_function_has_no_code(monkeypatch):
    _fake_project(monkeypatch, decompiler=_decompiler_returning(None))
    reply = sub._op_decompile("x", func_name="no_such_function")
    assert reply["status"] == "missing_function"
    assert "code" not in reply


@pytest.mark.parametrize("codegen", [None, _FakeCodegen(""), _FakeCodegen("  \n")])
def test_worker_decompiler_failed_has_no_code(monkeypatch, codegen):
    _fake_project(monkeypatch, decompiler=_decompiler_returning(codegen))
    reply = sub._op_decompile("x", func_name="leaf_helper")
    assert reply["status"] == "decompiler_failed"
    assert "code" not in reply
    assert reply["error"]


def test_worker_exception_has_no_code(monkeypatch):
    _fake_project(monkeypatch, decompiler=_decompiler_raising(ValueError("boom")))
    reply = sub._op_decompile("x", func_name="leaf_helper")
    assert reply["status"] == "exception"
    assert "code" not in reply
    assert "ValueError" in reply["error"] and "boom" in reply["error"]


# --------------------------------------------------------------------------- #
# Parent: validates the union, records the status, returns None on failure
# --------------------------------------------------------------------------- #


def _decompiler(tmp_path):
    d = Decompiler(types.SimpleNamespace(path=str(tmp_path / "target")))
    d._ghidra_path = None
    d._retdec_path = None
    return d


def _patch_op(monkeypatch, reply=None, raises=None):
    def fake(binary_path, op, seconds, **kwargs):
        if raises is not None:
            raise raises
        return reply

    monkeypatch.setattr(sub, "run_angr_op", fake)


OK_REPLY = {
    "status": "ok",
    "name": "leaf_helper",
    "address": 0x401136,
    "return_type": "void",
    "code": 'int leaf_helper(int a0)\n{\n    printf("leaf:%d\\n", a0);\n    return a0 + 1;\n}',
    "calls": ["printf"],
}


def test_parent_returns_the_function_on_ok(tmp_path, monkeypatch):
    d = _decompiler(tmp_path)
    _patch_op(monkeypatch, OK_REPLY)
    result = d._decompile_angr("leaf_helper", None)
    assert result is not None and "printf" in result.code
    assert d.angr_status == "ok"
    assert d.analysis_backend == "angr"


def test_parent_five_cases_give_five_distinct_statuses_and_none(tmp_path, monkeypatch):
    cases = {
        "ok": dict(reply=OK_REPLY),
        "missing_function": dict(reply={"status": "missing_function"}),
        "decompiler_failed": dict(
            reply={"status": "decompiler_failed", "error": "no pseudo-C"}
        ),
        "exception": dict(reply={"status": "exception", "error": "ValueError: boom"}),
        "timeout": dict(raises=sub.AnalysisBudgetExceeded("over budget")),
    }
    seen = {}
    for expected, kwargs in cases.items():
        d = _decompiler(tmp_path)
        _patch_op(monkeypatch, **kwargs)
        result = d._decompile_angr("leaf_helper", None)
        seen[expected] = d.angr_status
        if expected == "ok":
            assert result is not None and result.code.strip()
        else:
            assert result is None, expected
    assert seen == {name: name for name in cases}
    assert len(set(seen.values())) == 5


def test_parent_child_crash_is_an_exception_status(tmp_path, monkeypatch):
    d = _decompiler(tmp_path)
    _patch_op(monkeypatch, raises=sub.AngrSubprocessError("child died"))
    assert d._decompile_angr("leaf_helper", None) is None
    assert d.angr_status == "exception"
    assert "child died" in d.angr_error


def test_parent_rejects_the_legacy_sentinel_reply(tmp_path, monkeypatch):
    """RED on the base: the legacy worker reply (``found`` plus a sentinel body)
    was returned as a DecompiledFunction whose ``code`` is the sentinel."""
    d = _decompiler(tmp_path)
    _patch_op(monkeypatch, dict(LEGACY_SENTINEL_REPLY))
    assert d._decompile_angr("leaf_helper", None) is None
    assert d.angr_status == "exception"


@pytest.mark.parametrize(
    "reply",
    [
        None,
        "not a dict",
        {"status": "weird"},
        {"status": "ok"},  # ok without the fields a function needs
        {**OK_REPLY, "code": ""},
        {**OK_REPLY, "code": SENTINEL},  # a sentinel is never ``ok``
        {**OK_REPLY, "calls": "printf"},
    ],
)
def test_parent_rejects_a_reply_that_is_not_the_union(tmp_path, monkeypatch, reply):
    d = _decompiler(tmp_path)
    _patch_op(monkeypatch, reply)
    assert d._decompile_angr("leaf_helper", None) is None
    assert d.angr_status in ("exception", "decompiler_failed")


# --------------------------------------------------------------------------- #
# CLI: --json failure exits 2 with one document
# --------------------------------------------------------------------------- #


def test_cli_json_failure_exits_two_with_one_document(tmp_path, monkeypatch):
    """RED on the base: ``decompile --json`` printed the failure and exited 0."""
    from supwngo.cli import cli

    target = tmp_path / "target"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.setattr(Decompiler, "_find_ghidra", lambda self: None)
    monkeypatch.setattr(Decompiler, "_find_retdec", lambda self: None)
    monkeypatch.setattr(
        "supwngo.core.binary.Binary.load",
        staticmethod(
            lambda path: types.SimpleNamespace(path=path, symbols={}, bits=64)
        ),
    )
    _patch_op(monkeypatch, {"status": "decompiler_failed", "error": "no pseudo-C"})

    result = CliRunner(mix_stderr=False).invoke(
        cli, ["decompile", str(target), "--angr", "-f", "main", "--json"]
    )

    assert result.exit_code == 2, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert doc["error"]
    assert doc["angr_status"] == "decompiler_failed"
    assert "code" not in doc


def test_cli_json_success_still_exits_zero(tmp_path, monkeypatch):
    from supwngo.cli import cli

    target = tmp_path / "target"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.setattr(Decompiler, "_find_ghidra", lambda self: None)
    monkeypatch.setattr(Decompiler, "_find_retdec", lambda self: None)
    monkeypatch.setattr(
        "supwngo.core.binary.Binary.load",
        staticmethod(
            lambda path: types.SimpleNamespace(path=path, symbols={}, bits=64)
        ),
    )
    _patch_op(monkeypatch, OK_REPLY)

    result = CliRunner(mix_stderr=False).invoke(
        cli, ["decompile", str(target), "--angr", "-f", "leaf_helper", "--json"]
    )

    assert result.exit_code == 0, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert "printf" in doc["code"]


# --------------------------------------------------------------------------- #
# Real angr on a real fixture (V-7)
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(120)
def test_real_angr_worker_returns_code_naming_the_fixture_call(tmp_path):
    """RED on the base: ``CFGFast()`` without ``normalize=True`` leaves angr's
    ``Decompiler`` with no code generator, so the worker returned the sentinel."""
    binary = tmp_path / "two_funcs"
    built = subprocess.run(
        [
            GCC,
            "-no-pie",
            "-fno-stack-protector",
            "-O0",
            "-o",
            str(binary),
            str(FIXTURE_SRC),
        ],
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr

    reply = sub.run_angr_op(str(binary), "decompile", 90, func_name="leaf_helper")

    assert reply["status"] == "ok", reply
    assert "Decompilation failed" not in reply["code"]
    assert "printf" in reply["code"]
    assert reply["name"] == "leaf_helper"
