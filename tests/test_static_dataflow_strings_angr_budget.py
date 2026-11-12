"""S4b-i: ``analyze``/``dataflow``/``strings-analysis`` run angr under a budget (RT-05).

These three commands backed the same RT-05 hang as ``cfg``: each built a
``CFGFast`` in-process, so a large static binary (snow_scan) wedged them until
the 60 s retest cut killed them with no output. S4b-i routes each through the
budgeted subprocess in :mod:`supwngo.analysis._angr_subprocess` and records the
degradation (``analysis_backend`` + ``angr_budget_exceeded``), so a blow-out is
machine-visible instead of a silent kill.

This module pins, for commit 2 of the sprint:

* **the forced-timeout degradation** of all three commands, deterministically,
  via a sub-millisecond ``--angr-timeout`` on a tiny gcc fixture (no dependence
  on a slow/gitignored binary), driving the real CLI with a hard
  ``subprocess.run(timeout=...)`` so a reintroduced hang fails rather than wedges;
* **the per-command backend values** -- ``symbols`` (static), ``capstone``
  (dataflow), ``no_xrefs`` (strings) -- which the human note and ``--json`` both
  carry;
* **the N+1 fix**: ``StaticAnalyzer._find_callers`` no longer spawns an angr
  subprocess (it used to pay for a whole ``CFGFast`` per dangerous PLT entry),
  and a full ``analyze()`` issues exactly one ``static_functions`` op;
* **the happy path**: a generous budget uses angr and recovers a real direct
  call edge.

RED proof (base tree ``b77870f``): none of these commands has an
``--angr-timeout`` option, so each forced-timeout invocation exits non-zero
("No such option") with no JSON -- the marker/backend assertions fail. The
in-process tests fail at construction, because base ``StaticAnalyzer``/
``DataFlowAnalyzer``/``StringAnalyzer`` ``__init__`` take no ``angr_timeout``
argument and the classes never route through ``run_angr_op``. Post-fix: rc=0,
backends switch as above, ``angr_budget_exceeded`` is true, and ``analyze()``
makes exactly one subprocess op.
"""

from __future__ import annotations

import json
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
    workdir = tmp_path_factory.mktemp("sds-budget")
    binary = workdir / "two_funcs"
    res = subprocess.run(
        [GCC, "-no-pie", "-fno-stack-protector", "-O0", "-o", str(binary), str(FIXTURE_SRC)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:  # pragma: no cover - toolchain problem
        pytest.skip(f"gcc could not build the fixture: {res.stderr}")
    return binary


# --- Happy path: angr used, direct-call edge recovered ------------------------

@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(90)
def test_static_analyze_happy_path_uses_angr_and_recovers_call_edge(tiny_binary):
    """A generous budget must use angr and recover entry_main -> leaf_helper."""
    from supwngo.core.binary import Binary
    from supwngo.analysis.static import StaticAnalyzer

    analyzer = StaticAnalyzer(Binary.load(str(tiny_binary)), angr_timeout=60)
    results = analyzer.analyze()

    assert analyzer.analysis_backend == "angr", "angr should have produced the summary"
    assert analyzer.angr_budget_exceeded is False
    # entry_main -> leaf_helper is a plain direct call only angr's function kb
    # recovers; the symbol-table fallback has empty `calls`, so this pins a
    # non-degraded build.
    entry = results["functions"].get("entry_main")
    assert entry is not None, f"entry_main missing; functions={list(results['functions'])}"
    assert "leaf_helper" in entry["calls"], (
        f"missing entry_main->leaf_helper edge; calls={entry['calls']}"
    )


# --- N+1 fix: _find_callers spawns nothing; analyze() issues one op -----------

@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(30)
def test_find_callers_makes_no_subprocess_call(tiny_binary, monkeypatch):
    """_find_callers must return [] without spawning an angr subprocess.

    The old body built a whole CFGFast per dangerous PLT entry (the dominant
    hang on a large static binary's ``analyze``); the fix replaces it with
    ``return []``. Any call into ``run_angr_op`` here is a regression.
    """
    import supwngo.analysis._angr_subprocess as sub
    from supwngo.core.binary import Binary
    from supwngo.analysis.static import StaticAnalyzer

    def boom(*a, **k):  # pragma: no cover - only runs on regression
        raise AssertionError("_find_callers must not spawn an angr subprocess")

    monkeypatch.setattr(sub, "run_angr_op", boom)
    analyzer = StaticAnalyzer(Binary.load(str(tiny_binary)))
    assert analyzer._find_callers(0x401000) == []


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(30)
def test_analyze_issues_exactly_one_static_functions_op(tiny_binary, monkeypatch):
    """A full analyze() must route through exactly one subprocess op.

    The fixture's PLT holds a dangerous function (printf), so the base code would
    have built one CFGFast per such entry inside ``_find_callers`` *plus* one for
    the function summary. Post-fix the only op is the single ``static_functions``
    call in ``_analyze_functions``; ``_find_callers`` spawns nothing.
    """
    import supwngo.analysis._angr_subprocess as sub
    from supwngo.core.binary import Binary
    from supwngo.analysis.static import StaticAnalyzer

    ops = []

    def counting_run(binary_path, op, seconds=None, **kw):
        ops.append(op)
        if op == "static_functions":
            return {}  # empty summary keeps the angr branch without real angr
        raise AssertionError(f"unexpected op {op!r}")

    monkeypatch.setattr(sub, "run_angr_op", counting_run)
    StaticAnalyzer(Binary.load(str(tiny_binary))).analyze()
    assert ops == ["static_functions"], f"expected one static_functions op, got {ops}"


# --- Forced-timeout degradation of each CLI command (deterministic) -----------

@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(60)
def test_analyze_forced_timeout_degrades_to_symbols_json(tiny_binary):
    """A sub-ms budget forces the static timeout path (JSON markers = symbols)."""
    proc = subprocess.run(
        _cli_argv() + ["analyze", str(tiny_binary), "--angr-timeout", "0.001", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"analyze exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    data = json.loads(proc.stdout)
    assert data["angr_budget_exceeded"] is True
    assert data["analysis_backend"] == "symbols"


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(60)
def test_dataflow_forced_timeout_degrades_to_capstone_json(tiny_binary):
    """A sub-ms budget forces the data-flow timeout path (JSON markers = capstone)."""
    proc = subprocess.run(
        _cli_argv() + ["dataflow", str(tiny_binary), "--angr-timeout", "0.001", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"dataflow exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    data = json.loads(proc.stdout)
    assert data["angr_budget_exceeded"] is True
    assert data["analysis_backend"] == "capstone"


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(60)
def test_strings_analysis_forced_timeout_degrades_to_no_xrefs_json(tiny_binary):
    """A sub-ms budget forces the string-xref timeout path (JSON markers = no_xrefs)."""
    proc = subprocess.run(
        _cli_argv() + ["strings-analysis", str(tiny_binary), "--angr-timeout", "0.001", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, (
        f"strings-analysis exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    )
    data = json.loads(proc.stdout)
    assert data["angr_budget_exceeded"] is True
    assert data["analysis_backend"] == "no_xrefs"


@pytest.mark.skipif(not GCC, reason="gcc not available")
@pytest.mark.timeout(60)
def test_analyze_forced_timeout_prints_a_human_degradation_note(tiny_binary):
    proc = subprocess.run(
        _cli_argv() + ["analyze", str(tiny_binary), "--angr-timeout", "0.001"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"analyze exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    blob = proc.stdout + proc.stderr
    assert "exceeded" in blob, f"expected a visible degradation note; got:\n{blob[-2000:]}"


# --- Guarded RT-05 acceptance evidence (secondary to the committed tests) -----

_SNOW = Path(__file__).parent / "htb-targets" / "organized" / "snow_scan"


@pytest.mark.skipif(not _SNOW.exists(), reason="snow_scan target absent (gitignored)")
@pytest.mark.timeout(120)
def test_analyze_snow_scan_returns_instead_of_hanging():
    """The real RT-05 case for ``analyze``: the big static binary now returns.

    With a short real budget the command must complete well under the 60 s retest
    cut and report the degradation, rather than being killed at 60 s with no
    output.
    """
    start = time.monotonic()
    proc = subprocess.run(
        _cli_argv() + ["analyze", str(_SNOW), "--angr-timeout", "10", "--json"],
        capture_output=True, text=True, timeout=90,
    )
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, f"analyze exited {proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    data = json.loads(proc.stdout)
    assert data["angr_budget_exceeded"] is True
    assert data["analysis_backend"] == "symbols"
    assert elapsed < 55, f"analyze took {elapsed:.1f}s; the budget did not bound it under the cut"
