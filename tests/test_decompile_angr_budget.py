"""S4b-i: ``decompile --angr`` runs angr under a budget and degrades visibly (RT-05).

``Decompiler._decompile_angr`` built an in-process ``CFGFast`` *and* ran angr's
``Decompiler`` analysis -- either of which can run unbounded C-level work on a
large static binary (snow_scan), so the command wedged until the harness cut.
S4b-i runs the whole fallback in a single budgeted subprocess op; on a blow-out
the child's process group is killed and the command returns ``None`` (the prior
failure behaviour) while recording the degradation (``analysis_backend`` ==
``"none"`` + ``angr_budget_exceeded``).

Determinism: the forced-timeout tests use a sub-millisecond ``--angr-timeout`` on
a tiny gcc fixture and drive the real CLI with a hard ``subprocess.run(timeout=)``
so a reintroduced hang fails rather than wedges.

RED proof (base tree ``b77870f``): ``decompile`` has no ``--angr-timeout`` option
(it exits non-zero, "No such option") and ``Decompiler.__init__`` takes no
``angr_timeout`` argument, so both the CLI marker assertions and the in-process
provenance assertions fail. Post-fix: the angr fallback is budgeted, the backend
switches to ``none`` on timeout, and ``angr_budget_exceeded`` is true.

The angr ``Decompiler`` backend may emit only a ``// Decompilation failed``
sentinel for a tiny ``-O0`` function (version-dependent), so the happy-path test
asserts on provenance and function identity, not on exact pseudo-C text.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

GCC = shutil.which("gcc")
FIXTURE_SRC = Path(__file__).parent / "fixtures" / "angr_callgraph" / "two_funcs.c"


def _cli_argv():
    exe = shutil.which("supwngo")
    if exe:
        return [exe]
    return [sys.executable, "-m", "supwngo.cli"]


def _retdec_would_preempt_angr() -> bool:
    """``decompile(use_ghidra=False)`` still tries RetDec before angr; if RetDec
    is installed it never reaches the budgeted angr path, so the CLI-driven
    forced-timeout tests would not fire. ``--angr`` already disables Ghidra."""
    if os.environ.get("RETDEC_PATH"):
        return True
    if shutil.which("retdec-decompiler"):
        return True
    for p in (
        "/usr/bin/retdec-decompiler",
        "/usr/local/bin/retdec-decompiler",
        str(Path.home() / ".local" / "bin" / "retdec-decompiler"),
    ):
        if Path(p).exists():
            return True
    return False


@pytest.fixture(scope="module")
def tiny_binary(tmp_path_factory):
    if not GCC:
        pytest.skip("gcc not available")
    if not FIXTURE_SRC.exists():
        pytest.skip("two_funcs.c fixture missing")
    workdir = tmp_path_factory.mktemp("decompile-budget")
    binary = workdir / "two_funcs"
    res = subprocess.run(
        [GCC, "-no-pie", "-fno-stack-protector", "-O0", "-o", str(binary), str(FIXTURE_SRC)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:  # pragma: no cover - toolchain problem
        pytest.skip(f"gcc could not build the fixture: {res.stderr}")
    return binary


# --- Happy path: angr subprocess used, a function is returned -----------------

@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(90)
def test_decompile_angr_happy_path_uses_subprocess_and_returns_function(tiny_binary):
    """A generous budget must route through the angr subprocess and return a
    DecompiledFunction for the requested name (backend = angr, not degraded).

    Calls ``_decompile_angr`` directly so the assertion is independent of whether
    Ghidra/RetDec happen to be installed on the host."""
    from supwngo.core.binary import Binary
    from supwngo.analysis.decompile import Decompiler

    decomp = Decompiler(Binary.load(str(tiny_binary)), angr_timeout=60)
    result = decomp._decompile_angr("leaf_helper", None)

    assert result is not None, "angr subprocess should have returned a function"
    assert result.name == "leaf_helper"
    assert decomp.analysis_backend == "angr"
    assert decomp.angr_budget_exceeded is False


# --- Forced-timeout degradation via the real CLI ------------------------------

@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.skipif(_retdec_would_preempt_angr(), reason="RetDec preempts the angr path")
@pytest.mark.timeout(60)
def test_decompile_forced_timeout_degrades_to_none_json(tiny_binary):
    """A sub-ms budget forces the angr timeout path (JSON markers = none/true)."""
    proc = subprocess.run(
        _cli_argv() + ["decompile", str(tiny_binary), "--angr", "-f", "leaf_helper",
                       "--angr-timeout", "0.001", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"decompile exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    data = json.loads(proc.stdout)
    assert data["angr_budget_exceeded"] is True
    assert data["analysis_backend"] == "none"
    assert data.get("error") == "Decompilation failed"


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.skipif(_retdec_would_preempt_angr(), reason="RetDec preempts the angr path")
@pytest.mark.timeout(60)
def test_decompile_forced_timeout_prints_a_human_degradation_note(tiny_binary):
    proc = subprocess.run(
        _cli_argv() + ["decompile", str(tiny_binary), "--angr", "-f", "leaf_helper",
                       "--angr-timeout", "0.001"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"decompile exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    blob = proc.stdout + proc.stderr
    assert "exceeded" in blob, f"expected a visible degradation note; got:\n{blob[-2000:]}"


# --- Guarded RT-05 acceptance evidence (secondary to the committed tests) -----

_SNOW = Path(__file__).parent / "htb-targets" / "organized" / "snow_scan"


@pytest.mark.skipif(not _SNOW.exists(), reason="snow_scan target absent (gitignored)")
@pytest.mark.skipif(_retdec_would_preempt_angr(), reason="RetDec preempts the angr path")
@pytest.mark.timeout(120)
def test_decompile_snow_scan_returns_instead_of_hanging():
    """The real RT-05 case for ``decompile``: the big static binary now returns.

    CFGFast on snow_scan cannot finish in a short budget, so the command must
    bound itself and report the degradation rather than being killed at the cut
    with no output."""
    start = time.monotonic()
    proc = subprocess.run(
        _cli_argv() + ["decompile", str(_SNOW), "--angr", "-f", "main",
                       "--angr-timeout", "10", "--json"],
        capture_output=True, text=True, timeout=90,
    )
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, f"decompile exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    data = json.loads(proc.stdout)
    assert data["angr_budget_exceeded"] is True
    assert data["analysis_backend"] == "none"
    assert elapsed < 55, f"decompile took {elapsed:.1f}s; the budget did not bound it under the cut"
