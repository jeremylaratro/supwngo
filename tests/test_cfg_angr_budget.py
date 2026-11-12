"""S4b-i: ``cfg`` runs angr under a budget and degrades visibly (RT-05).

The CFG command used to call ``CFGFast`` in-process; on a large static binary
(e.g. snow_scan) that C-level build never returns and the command was killed
with no output. S4b-i isolates the build in a budgeted subprocess: on timeout it
falls back to capstone linear disassembly *and records that it did so*, so the
degradation is machine-visible.

Determinism (MAJOR-6 of the review): the forced-timeout tests use a
sub-millisecond ``--angr-timeout`` on a tiny gcc fixture, so the timeout path
fires on any host without depending on a slow/gitignored binary. They drive the
real CLI as a subprocess with a hard ``subprocess.run(timeout=...)`` so a
regression that reintroduces a hang fails the test rather than wedging it.

RED proof (base tree ``b77870f``): the ``cfg`` command has no ``--angr-timeout``
option, so the forced-timeout invocation exits non-zero ("No such option") with
no JSON -- the marker/backend-switch assertions fail. Post-fix: rc=0, backend
switches to capstone, and ``angr_budget_exceeded`` is true.
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


@pytest.fixture(scope="module")
def tiny_binary(tmp_path_factory):
    if not GCC:
        pytest.skip("gcc not available")
    if not FIXTURE_SRC.exists():
        pytest.skip("two_funcs.c fixture missing")
    workdir = tmp_path_factory.mktemp("cfg-budget")
    binary = workdir / "two_funcs"
    res = subprocess.run(
        [GCC, "-no-pie", "-fno-stack-protector", "-O0", "-o", str(binary), str(FIXTURE_SRC)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:  # pragma: no cover - toolchain problem
        pytest.skip(f"gcc could not build the fixture: {res.stderr}")
    return binary


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(90)
def test_cfg_happy_path_uses_angr_and_recovers_the_call_edge(tiny_binary):
    """A generous budget must use angr and recover a real direct-call edge."""
    from supwngo.core.binary import Binary
    from supwngo.analysis.cfg import CFGAnalyzer

    analyzer = CFGAnalyzer(Binary.load(str(tiny_binary)), angr_timeout=60)
    analyzer.build_cfg()

    assert analyzer.analysis_backend == "angr", "angr should have produced the CFG"
    assert analyzer.angr_budget_exceeded is False
    # entry_main -> leaf_helper is a plain direct call only angr's function kb
    # recovers; the capstone fallback cannot, so this pins a non-degraded build.
    assert "leaf_helper" in analyzer.call_graph.get("entry_main", []), (
        f"missing entry_main->leaf_helper edge; call_graph={dict(analyzer.call_graph)}"
    )


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(60)
def test_cfg_forced_timeout_degrades_to_capstone_in_json(tiny_binary):
    """A sub-ms budget forces the timeout path deterministically (JSON markers)."""
    proc = subprocess.run(
        _cli_argv() + ["cfg", str(tiny_binary), "--angr-timeout", "0.001", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"cfg exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    data = json.loads(proc.stdout)
    assert data["angr_budget_exceeded"] is True
    assert data["analysis_backend"] == "capstone"


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(60)
def test_cfg_forced_timeout_prints_a_human_degradation_note(tiny_binary):
    proc = subprocess.run(
        _cli_argv() + ["cfg", str(tiny_binary), "--angr-timeout", "0.001"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"cfg exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    blob = proc.stdout + proc.stderr
    assert "exceeded" in blob and "incomplete" in blob, (
        f"expected a visible degradation note; got:\n{blob[-2000:]}"
    )


# --- Guarded RT-05 acceptance evidence (secondary to the committed tests) -----

_SNOW = Path(__file__).parent / "htb-targets" / "organized" / "snow_scan"


@pytest.mark.skipif(not _SNOW.exists(), reason="snow_scan target absent (gitignored)")
@pytest.mark.timeout(120)
def test_cfg_snow_scan_returns_instead_of_hanging():
    """The real RT-05 case: the big static binary that used to hang now returns.

    With a real (short) budget the command must complete well under the 60s
    retest cut and report the degradation, rather than being killed at 60s with
    no output.
    """
    start = time.monotonic()
    proc = subprocess.run(
        _cli_argv() + ["cfg", str(_SNOW), "--angr-timeout", "10", "--json"],
        capture_output=True, text=True, timeout=90,
    )
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, f"cfg exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    data = json.loads(proc.stdout)
    assert data["angr_budget_exceeded"] is True
    assert data["analysis_backend"] == "capstone"
    assert elapsed < 55, f"cfg took {elapsed:.1f}s; the budget did not bound it under the harness cut"
