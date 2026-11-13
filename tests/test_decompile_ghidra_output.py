"""S5: ``decompile`` returns real Ghidra pseudo-C, not a silent angr fallthrough (RT-03).

RT-03 (2026-09-26 retest): ``decompile`` "fails 7/7" because
``Decompiler._decompile_ghidra`` silently returned ``None`` -- it wrote a ``.py``
GhidraScript (Ghidra 12.x has no PyGhidra), never passed ``-scriptPath``, and
ignored the result -- so the command fell through to the angr path and emitted a
``// Decompilation failed`` sentinel with ``analysis_backend == "angr"``.

RED proof (pre-fix tree, measured via the real CLI):
``supwngo decompile <bin> --ghidra --json`` returns ``analysis_backend == "angr"``
and sentinel code even though Ghidra is installed -- it never reaches Ghidra
provenance. The opt-in integration tests below assert the *fixed* behaviour
(``analysis_backend == "ghidra"`` with non-empty pseudo-C) and therefore fail on
the old tree.

Two layers of coverage:

* **Hermetic** tests (always run) monkeypatch the subprocess/output-file seams
  (``_run_ghidra_headless`` / ``_read_ghidra_output``) so the backend-selection,
  degradation, and process-group kill/reap logic is exercised without a real
  Ghidra install.
* **Integration** tests (opt-in: ``SUPWNGO_GHIDRA_TESTS=1`` and a real
  ``analyzeHeadless``) drive the end-to-end decompile on a gcc fixture and a real
  HTB target. They are heavyweight (tens of seconds of JVM + analysis each), so
  they do not run in the normal suite.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

import supwngo.analysis.decompile as decompile_mod
from supwngo.analysis.decompile import Decompiler
from supwngo.core.proc import ProcState


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _make_decompiler(tmp_path):
    """A Decompiler over a stub binary with a (fake) Ghidra path present.

    The seams are monkeypatched in each test, so the Ghidra path only needs to be
    truthy to pass the availability guard; it is never executed.
    """
    stub_binary = types.SimpleNamespace(path=str(tmp_path / "target"))
    d = Decompiler(stub_binary)
    d._ghidra_path = Path("/opt/ghidra/support/analyzeHeadless")
    return d


def _ran_ok():
    """A GhidraRun for a process that ran to an end (the seam's old ``True``)."""
    return decompile_mod.GhidraRun(state=ProcState.EXITED, rc=0)


def _killed_on_timeout():
    """A GhidraRun for a timeout kill (the seam's old ``False``)."""
    return decompile_mod.GhidraRun(state=ProcState.TIMEOUT, timeout_s=0.01)


GHIDRA_BIN = (
    shutil.which("analyzeHeadless")
    or next(
        (
            p
            for p in (
                "/opt/ghidra/support/analyzeHeadless",
                "/usr/share/ghidra/support/analyzeHeadless",
            )
            if Path(p).exists()
        ),
        None,
    )
)
GHIDRA_OPT_IN = bool(os.environ.get("SUPWNGO_GHIDRA_TESTS"))
GCC = shutil.which("gcc")
FIXTURE_SRC = Path(__file__).parent / "fixtures" / "angr_callgraph" / "two_funcs.c"
HTB_TARGET = Path(__file__).parent / "htb-targets" / "organized" / "bon-nie-appetit"

_GHIDRA_REASON = "opt-in Ghidra integration test (set SUPWNGO_GHIDRA_TESTS=1)"


# --------------------------------------------------------------------------- #
# Pure helpers: selector + timeout validation (B5, B7)
# --------------------------------------------------------------------------- #

def test_selector_name_takes_precedence_over_address():
    # decompile_all() passes both; a name must win and be tagged.
    assert Decompiler._ghidra_selector("main", 0x401187) == "name:main"


def test_selector_address_only_is_tagged_and_zero_is_honoured():
    assert Decompiler._ghidra_selector(None, 0x401187) == "addr:0x401187"
    # func_addr == 0 must still select by address (is-not-None, not truthiness).
    assert Decompiler._ghidra_selector(None, 0) == "addr:0x0"


def test_selector_empty_when_nothing_requested():
    assert Decompiler._ghidra_selector(None, None) == ""


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, 180.0),
        ("45", 45.0),
        (45, 45.0),
        ("0", 180.0),
        ("-5", 180.0),
        ("nan", 180.0),
        ("inf", 180.0),
        ("abc", 180.0),
        ("", 180.0),
        ("99999", 900.0),  # clamped to the hard max
    ],
)
def test_resolve_ghidra_timeout_is_finite_positive_and_capped(raw, expected):
    assert decompile_mod._resolve_ghidra_timeout(raw) == expected


# --------------------------------------------------------------------------- #
# Output-file validation (B3)
# --------------------------------------------------------------------------- #

def test_read_ghidra_output_missing_file_is_none(tmp_path):
    assert Decompiler._read_ghidra_output(tmp_path / "nope.json") is None


def test_read_ghidra_output_empty_file_is_none(tmp_path):
    f = tmp_path / "out.json"
    f.write_text("   \n")
    assert Decompiler._read_ghidra_output(f) is None


def test_read_ghidra_output_malformed_is_none(tmp_path):
    f = tmp_path / "out.json"
    f.write_text("{not json")
    assert Decompiler._read_ghidra_output(f) is None


def test_read_ghidra_output_non_list_is_none(tmp_path):
    f = tmp_path / "out.json"
    f.write_text('{"name": "main"}')
    assert Decompiler._read_ghidra_output(f) is None


def test_read_ghidra_output_empty_list_is_distinguished_from_failure(tmp_path):
    f = tmp_path / "out.json"
    f.write_text("[]")
    # Valid array, empty -> an empty list (ran, found nothing), NOT None.
    assert Decompiler._read_ghidra_output(f) == []


def test_read_ghidra_output_parses_escaped_control_chars(tmp_path):
    """The Python side of the interchange must round-trip the Java escaper's
    output: quotes, backslashes, newlines, tabs, and a control char."""
    f = tmp_path / "out.json"
    code = 'void main(void)\n{\n\tputs("a\\"b\\\\c");\n\x01\n}'
    f.write_text(json.dumps([{"name": "main", "address": 1,
                              "return_type": "void", "code": code}]))
    data = Decompiler._read_ghidra_output(f)
    assert isinstance(data, list) and data[0]["code"] == code


# --------------------------------------------------------------------------- #
# Backend selection / degradation (B2, B3) via the seams
# --------------------------------------------------------------------------- #

def test_ghidra_happy_path_sets_backend_and_returns_code(tmp_path, monkeypatch):
    d = _make_decompiler(tmp_path)
    canned = [{
        "name": "main", "address": 0x401187, "backend_base": 0x400000,
        "return_type": "undefined",
        "code": "\nvoid main(void)\n\n{\n  entry_main();\n  return;\n}\n",
    }]
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: _ran_ok())
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: canned)

    result = d._decompile_ghidra("main", None)

    assert result is not None
    assert result.code.strip()
    assert result.name == "main"
    assert d.analysis_backend == "ghidra"


def test_ghidra_empty_list_degrades_to_fallback(tmp_path, monkeypatch):
    d = _make_decompiler(tmp_path)
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: _ran_ok())
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: [])

    assert d._decompile_ghidra("main", None) is None
    assert d.analysis_backend == "angr"  # provenance not claimed


def test_ghidra_empty_object_without_code_degrades(tmp_path, monkeypatch):
    """`[{}]` parses to a function with empty pseudo-C -> must NOT be reported as
    a Ghidra success (B2)."""
    d = _make_decompiler(tmp_path)
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: _ran_ok())
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: [{}])

    assert d._decompile_ghidra("main", None) is None
    assert d.analysis_backend == "angr"


def test_ghidra_whitespace_only_code_degrades(tmp_path, monkeypatch):
    d = _make_decompiler(tmp_path)
    canned = [{"name": "f", "address": 1, "return_type": "int", "code": "  \n\t "}]
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: _ran_ok())
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: canned)

    assert d._decompile_ghidra("f", None) is None
    assert d.analysis_backend == "angr"


def test_ghidra_malformed_output_returns_none(tmp_path, monkeypatch):
    d = _make_decompiler(tmp_path)
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: _ran_ok())
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: None)

    assert d._decompile_ghidra("main", None) is None
    assert d.analysis_backend == "angr"


def test_ghidra_timeout_returns_none(tmp_path, monkeypatch):
    d = _make_decompiler(tmp_path)
    # _run_ghidra_headless reports a timeout/launch failure as a run that did not
    # finish.
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: _killed_on_timeout())
    called = {"read": False}

    def _spy_read(path):
        called["read"] = True
        return None

    monkeypatch.setattr(d, "_read_ghidra_output", _spy_read)

    assert d._decompile_ghidra("main", None) is None
    assert d.analysis_backend == "angr"
    assert called["read"] is False  # no output read after a failed run


def test_ghidra_missing_script_returns_none_without_launch(tmp_path, monkeypatch):
    """A missing packaged ``.java`` degrades immediately -- no 180 s Ghidra launch
    (B4)."""
    d = _make_decompiler(tmp_path)
    empty_dir = tmp_path / "ghidra_scripts_empty"
    empty_dir.mkdir()
    monkeypatch.setattr(d, "_ghidra_scripts_dir", lambda: empty_dir)

    launched = {"ran": False}

    def _spy_run(cmd, timeout):
        launched["ran"] = True
        return _ran_ok()

    monkeypatch.setattr(d, "_run_ghidra_headless", _spy_run)

    assert d._decompile_ghidra("main", None) is None
    assert launched["ran"] is False


def test_ghidra_no_path_returns_none(tmp_path, monkeypatch):
    d = _make_decompiler(tmp_path)
    d._ghidra_path = None
    # Even if the seam would succeed, no Ghidra path -> None, no launch.
    monkeypatch.setattr(d, "_run_ghidra_headless",
                        lambda cmd, timeout: pytest.fail("should not launch"))
    assert d._decompile_ghidra("main", None) is None


# --------------------------------------------------------------------------- #
# Process lifecycle (B1): the seam reports how the run ended. The structured
# result, the bounded tails and the group kill are in
# tests/test_decompile_ghidra_diagnostics.py and tests/test_proc.py.
# --------------------------------------------------------------------------- #

def test_run_ghidra_headless_timeout_is_a_run_that_did_not_finish(tmp_path):
    d = _make_decompiler(tmp_path)
    script = tmp_path / "analyzeHeadless"
    script.write_text("#!/bin/sh\nsleep 300\n")
    script.chmod(0o755)

    run = d._run_ghidra_headless([str(script)], timeout=0.5)

    assert run.state is ProcState.TIMEOUT
    assert run.finished is False


def test_run_ghidra_headless_launch_failure_is_a_run_that_did_not_finish(tmp_path):
    d = _make_decompiler(tmp_path)

    run = d._run_ghidra_headless([str(tmp_path / "missing")], timeout=5)

    assert run.state is ProcState.SPAWN_ERROR
    assert run.finished is False


# --------------------------------------------------------------------------- #
# Opt-in real-Ghidra integration (heavyweight; set SUPWNGO_GHIDRA_TESTS=1)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not GHIDRA_OPT_IN, reason=_GHIDRA_REASON)
@pytest.mark.skipif(not GHIDRA_BIN, reason="analyzeHeadless not installed")
@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.skipif(not FIXTURE_SRC.exists(), reason="two_funcs.c fixture missing")
def test_real_ghidra_decompiles_fixture(tmp_path):
    from supwngo.core.binary import Binary

    binary = tmp_path / "two_funcs"
    build = subprocess.run(
        ["gcc", "-no-pie", "-fno-stack-protector", "-O0",
         "-o", str(binary), str(FIXTURE_SRC)],
        capture_output=True, text=True,
    )
    if build.returncode != 0:  # pragma: no cover - toolchain problem
        pytest.skip(f"gcc could not build the fixture: {build.stderr}")

    d = Decompiler(Binary(str(binary)))
    result = d._decompile_ghidra("main", None)

    assert result is not None
    assert result.code and result.code.strip()
    assert d.analysis_backend == "ghidra"


@pytest.mark.skipif(not GHIDRA_OPT_IN, reason=_GHIDRA_REASON)
@pytest.mark.skipif(not GHIDRA_BIN, reason="analyzeHeadless not installed")
@pytest.mark.skipif(not HTB_TARGET.exists(), reason="bon-nie-appetit target absent (gitignored)")
def test_real_ghidra_decompiles_htb_target():
    from supwngo.core.binary import Binary

    d = Decompiler(Binary(str(HTB_TARGET)))
    result = d._decompile_ghidra("main", None)

    assert result is not None
    assert result.code and result.code.strip()
    assert d.analysis_backend == "ghidra"
