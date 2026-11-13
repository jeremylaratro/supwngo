"""SP-01b V-11: a Ghidra failure is surfaced instead of discarded.

``Decompiler._run_ghidra_headless`` returned a Boolean and threw stdout away, so
a Ghidra run that died ("Path element starting with '.' is not permitted") was
indistinguishable from "Ghidra is not installed": the command quietly fell to
angr, and when angr failed too the user saw only "Decompilation failed".

The seam now returns a structured :class:`GhidraRun` with the ``ProcResult``
state, bounded stdout/stderr tails and the first ``ERROR`` line of stdout. The
diagnostic is kept on the ``Decompiler`` through the RetDec and angr fallbacks
and is put in the JSON ``error`` only when the whole operation fails.

Hermetic tests use a fake ``analyzeHeadless`` script. The tool-tier tests
(``SUPWNGO_REQUIRE_GHIDRA=1``) use the real thing with a dot-component project
path, which is the measured cause of the silent 0/7 (plan V-1).
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))
from ghidra_support import need_ghidra  # noqa: E402

import supwngo.analysis._angr_subprocess as sub  # noqa: E402
import supwngo.analysis.decompile as decompile_mod  # noqa: E402
from supwngo.analysis.decompile import Decompiler  # noqa: E402
from supwngo.core.proc import ProcState  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CONTROL_ELF = REPO / "benchmark" / "fixtures" / "ghidra_control" / "ghidra_control.elf"
DOT_ERROR = (
    "ERROR Abort due to Headless analyzer error: Path element starting with '.' "
    "is not permitted (HeadlessAnalyzer) java.lang.IllegalArgumentException: "
    "Path element starting with '.' is not permitted"
)
NEEDLE = "Path element starting with '.'"


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fake_ghidra(tmp_path: Path, body: str) -> Path:
    return _script(tmp_path / "analyzeHeadless", body)


def _decompiler() -> Decompiler:
    d = Decompiler(types.SimpleNamespace(path="/nonexistent/target"))
    d._retdec_path = None
    return d


# --------------------------------------------------------------------------- #
# The seam: _run_ghidra_headless returns a structured result
# --------------------------------------------------------------------------- #


def test_seam_reports_state_rc_tails_and_the_first_error_line(tmp_path):
    fake = _fake_ghidra(
        tmp_path,
        f'echo "INFO  startup complete"\necho "{DOT_ERROR}"\n'
        'echo "to stderr" >&2\nexit 1\n',
    )

    run = _decompiler()._run_ghidra_headless([str(fake)], timeout=30)

    assert run.state is ProcState.EXITED
    assert run.rc == 1
    assert run.first_error.startswith("ERROR Abort due to Headless analyzer error")
    assert NEEDLE in run.error
    assert "INFO  startup complete" in run.stdout_tail
    assert run.stderr_tail.strip() == "to stderr"


def test_seam_first_error_comes_from_all_of_stdout_not_just_the_tail(tmp_path):
    flood = (
        f'echo "{DOT_ERROR}"\n'
        'i=0\nwhile [ $i -lt 4000 ]; do echo "INFO  filler line $i"; '
        "i=$((i+1)); done\nexit 1\n"
    )
    fake = _fake_ghidra(tmp_path, flood)

    run = _decompiler()._run_ghidra_headless([str(fake)], timeout=30)

    assert NEEDLE in run.first_error
    assert NEEDLE not in run.stdout_tail  # the tail is bounded
    assert len(run.stdout_tail) <= decompile_mod.GHIDRA_TAIL_CHARS


def test_seam_clean_exit_has_no_error(tmp_path):
    fake = _fake_ghidra(tmp_path, 'echo "INFO  all good"\nexit 0\n')

    run = _decompiler()._run_ghidra_headless([str(fake)], timeout=30)

    assert run.state is ProcState.EXITED and run.rc == 0
    assert run.first_error == "" and run.error == ""


def test_seam_non_zero_exit_without_an_error_line_still_explains_itself(tmp_path):
    fake = _fake_ghidra(tmp_path, 'echo "boom" >&2\nexit 3\n')

    run = _decompiler()._run_ghidra_headless([str(fake)], timeout=30)

    assert run.rc == 3
    assert "3" in run.error and "boom" in run.error


def test_seam_timeout_kills_the_whole_process_group(tmp_path):
    pidfile = tmp_path / "sleeper.pid"
    fake = _fake_ghidra(tmp_path, f'sleep 300 &\necho $! > "{pidfile}"\nwait\n')

    run = _decompiler()._run_ghidra_headless([str(fake)], timeout=2)

    assert run.state is ProcState.TIMEOUT
    assert "timed out" in run.error
    sleeper = int(pidfile.read_text())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(sleeper, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(sleeper, 9)
        pytest.fail("the descendant of the killed run is still alive")


def test_seam_spawn_error_is_reported_not_raised(tmp_path):
    run = _decompiler()._run_ghidra_headless(
        [str(tmp_path / "no-such-analyzeHeadless")], timeout=5
    )

    assert run.state is ProcState.SPAWN_ERROR
    assert "launch" in run.error


# --------------------------------------------------------------------------- #
# _decompile_ghidra keeps the diagnostic through the fallbacks
# --------------------------------------------------------------------------- #


def _failed_run(**kw):
    base = dict(state=ProcState.EXITED, rc=1, first_error=DOT_ERROR)
    base.update(kw)
    return decompile_mod.GhidraRun(**base)


def _ghidra_decompiler(monkeypatch, run) -> Decompiler:
    d = _decompiler()
    d._ghidra_path = Path("/opt/ghidra/support/analyzeHeadless")
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: run)
    return d


def test_failed_ghidra_run_is_recorded_on_the_decompiler(monkeypatch):
    run = _failed_run()
    d = _ghidra_decompiler(monkeypatch, run)

    assert d._decompile_ghidra("main", None) is None
    assert d.ghidra_run is run
    assert NEEDLE in d.ghidra_error


def test_diagnostic_survives_a_successful_angr_fallback(monkeypatch):
    d = _ghidra_decompiler(monkeypatch, _failed_run())
    reply = {
        "status": "ok",
        "name": "main",
        "address": 0x401136,
        "backend_base": 0x400000,
        "return_type": "void",
        "code": 'int main(void)\n{\n    return puts("x");\n}',
        "calls": ["puts"],
    }
    monkeypatch.setattr(sub, "run_angr_op", lambda *a, **k: reply)

    result = d.decompile(func_name="main")

    assert result is not None and d.analysis_backend == "angr"
    assert NEEDLE in d.ghidra_error


def test_diagnostic_is_cleared_when_ghidra_later_succeeds(monkeypatch):
    d = _ghidra_decompiler(monkeypatch, _failed_run())
    assert d._decompile_ghidra("main", None) is None and d.ghidra_error

    ok = decompile_mod.GhidraRun(state=ProcState.EXITED, rc=0)
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: ok)
    canned = [
        {
            "name": "main",
            "address": 1,
            "backend_base": 0,
            "return_type": "int",
            "code": "int main(void)\n{\n  return 0;\n}",
        }
    ]
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: canned)

    assert d._decompile_ghidra("main", None) is not None
    assert d.ghidra_error == ""


def test_a_run_that_produced_nothing_reports_why(monkeypatch):
    # Ghidra exited 0 but wrote no usable output: the reason still has to say so.
    ok = decompile_mod.GhidraRun(state=ProcState.EXITED, rc=0)
    d = _ghidra_decompiler(monkeypatch, ok)
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: None)

    assert d._decompile_ghidra("main", None) is None
    assert d.ghidra_error


# --------------------------------------------------------------------------- #
# CLI: the diagnostic is in `error` only when the whole operation fails
# --------------------------------------------------------------------------- #


def _cli_env(monkeypatch, tmp_path, *, ghidra_home=None):
    """Make ``decompile`` see a stub ELF, no RetDec, and (optionally) a Ghidra."""
    target = tmp_path / "target"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.setattr(Decompiler, "_find_retdec", lambda self: None)
    monkeypatch.setattr(
        "supwngo.core.binary.Binary.load",
        staticmethod(
            lambda path: types.SimpleNamespace(path=path, symbols={}, bits=64)
        ),
    )
    if ghidra_home is not None:
        monkeypatch.setenv("GHIDRA_HOME", str(ghidra_home))
    return target


def _invoke(target, *extra):
    from supwngo.cli import cli

    return CliRunner(mix_stderr=False).invoke(
        cli, ["decompile", str(target), "-f", "main", "--json", *extra]
    )


def test_cli_whole_failure_puts_the_ghidra_error_in_error(tmp_path, monkeypatch):
    """RED on the base: the JSON ``error`` was the bare "Decompilation failed"."""
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    _script(home / "support" / "analyzeHeadless", f'echo "{DOT_ERROR}"\nexit 1\n')
    target = _cli_env(monkeypatch, tmp_path, ghidra_home=home)
    # The angr fallback is forced into a tagged failure, so a successful
    # fallback cannot make this vacuous.
    monkeypatch.setattr(
        sub,
        "run_angr_op",
        lambda *a, **k: {"status": "decompiler_failed", "error": "no pseudo-C"},
    )

    result = _invoke(target)

    assert result.exit_code == 2, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert NEEDLE in doc["error"]
    assert doc["angr_status"] == "decompiler_failed"
    assert "code" not in doc


def test_cli_success_through_a_fallback_has_no_error_key(tmp_path, monkeypatch):
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    _script(home / "support" / "analyzeHeadless", f'echo "{DOT_ERROR}"\nexit 1\n')
    target = _cli_env(monkeypatch, tmp_path, ghidra_home=home)
    reply = {
        "status": "ok",
        "name": "main",
        "address": 0x401136,
        "backend_base": 0x400000,
        "return_type": "void",
        "code": 'int main(void)\n{\n    return puts("x");\n}',
        "calls": ["puts"],
    }
    monkeypatch.setattr(sub, "run_angr_op", lambda *a, **k: reply)

    result = _invoke(target)

    assert result.exit_code == 0, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert doc["analysis_backend"] == "angr"
    assert "error" not in doc


# --------------------------------------------------------------------------- #
# Tool tier (SUPWNGO_REQUIRE_GHIDRA=1): the real Ghidra on a dot-component path
# --------------------------------------------------------------------------- #


def test_real_ghidra_dot_component_path_error_reaches_the_seam(tmp_path):
    """The seam, run against real Ghidra with a project path that has a
    ``.``-prefixed component, reports Ghidra's own error. RED on the base: the
    seam returned ``True`` and the message was discarded."""
    analyze = need_ghidra()
    project = tmp_path / ".hidden" / "project"
    project.parent.mkdir()
    d = _decompiler()
    d._ghidra_path = analyze
    cmd = [
        str(analyze),
        str(project),
        "SupwngoTmp",
        "-import",
        str(CONTROL_ELF),
        "-deleteProject",
    ]

    run = d._run_ghidra_headless(cmd, timeout=300)

    assert run.state is ProcState.EXITED
    assert NEEDLE in run.error, run.stdout_tail[-1500:]


def test_real_ghidra_cli_failure_surfaces_the_dot_path_error(tmp_path, monkeypatch):
    """CLI level, real Ghidra: the project path is made to contain a dot
    component, RetDec is forced unavailable and the angr worker is forced into a
    tagged failure, so no fallback can succeed and the Ghidra error is the only
    place the cause can come from."""
    need_ghidra()
    dot_tmp = tmp_path / ".scratch"
    dot_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(dot_tmp))
    monkeypatch.setattr(Decompiler, "_find_retdec", lambda self: None)
    monkeypatch.setattr(
        sub,
        "run_angr_op",
        lambda *a, **k: {"status": "decompiler_failed", "error": "forced"},
    )

    from supwngo.cli import cli

    result = CliRunner(mix_stderr=False).invoke(
        cli, ["decompile", str(CONTROL_ELF), "-f", "ghidra_control", "--json"]
    )

    assert result.exit_code == 2, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert NEEDLE in doc["error"], doc
    assert doc["angr_status"] == "decompiler_failed"
