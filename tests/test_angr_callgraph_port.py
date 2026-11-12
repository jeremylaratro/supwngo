"""S4a: port of the removed angr ``Function.functions_called()`` to the
supported ``get_call_sites`` API via ``supwngo.analysis._angr_callgraph``.

Two layers:

* fast unit tests of ``iter_callees`` against hand-built stand-ins (no angr), to
  pin the resolve / skip / de-dupe semantics;
* a RED-proof that drives the real ``CFGAnalyzer.build_cfg()`` on a committed,
  compiled-at-test-time fixture and asserts the exact ``entry_main ->
  leaf_helper`` edge AND that the capstone fallback was *not* taken. On base
  ``5ef210a`` ``functions_called()`` raises ``AttributeError`` inside
  ``_build_cfg_angr``; the broad ``except`` swallows it into the capstone
  fallback, so both assertions fail. After the port the angr path succeeds.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from supwngo.analysis._angr_callgraph import iter_callees

REPO = Path(__file__).resolve().parent.parent
FIXTURE_SRC = REPO / "tests" / "fixtures" / "angr_callgraph" / "two_funcs.c"

#: No PIE / no canary so calls are plain direct relocations angr resolves,
#: not PLT thunks or PIE-relative indirects.
_CFLAGS = ["-no-pie", "-fno-stack-protector", "-O0"]


# --------------------------------------------------------------------------- #
# Unit layer: iter_callees semantics, angr-free.
# --------------------------------------------------------------------------- #

class _FakeFunc:
    """Duck-typed stand-in for an angr ``Function``."""

    def __init__(self, name, addr, sites):
        # sites: {call_site_addr: resolved_target_addr_or_None}
        self.name = name
        self.addr = addr
        self._sites = sites

    def get_call_sites(self):
        return list(self._sites.keys())

    def get_call_target(self, site):
        return self._sites[site]


class _FakeKb:
    """Duck-typed stand-in for ``cfg.kb.functions`` (a FunctionManager)."""

    def __init__(self, funcs):
        self._funcs = funcs  # {addr: Function}

    def get(self, addr):
        return self._funcs.get(addr)


def test_iter_callees_yields_resolved_callee():
    callee = _FakeFunc("target", 0x2000, {})
    kb = _FakeKb({0x2000: callee})
    caller = _FakeFunc("caller", 0x1000, {0x1010: 0x2000})
    assert list(iter_callees(caller, kb)) == [callee]


def test_iter_callees_skips_unresolved_indirect_target():
    kb = _FakeKb({})
    # get_call_target returns None for an indirect/unresolved call.
    caller = _FakeFunc("caller", 0x1000, {0x1010: None})
    assert list(iter_callees(caller, kb)) == []


def test_iter_callees_skips_target_absent_from_kb():
    # A resolved address that is not a known function (e.g. a data thunk) is
    # dropped, matching the old method's "callees that are Functions" set.
    kb = _FakeKb({})  # 0x2000 resolves but is not in the kb
    caller = _FakeFunc("caller", 0x1000, {0x1010: 0x2000})
    assert list(iter_callees(caller, kb)) == []


def test_iter_callees_dedupes_repeated_target():
    callee = _FakeFunc("target", 0x2000, {})
    kb = _FakeKb({0x2000: callee})
    # Same target called from two sites -> yielded once (unique-callee set).
    caller = _FakeFunc("caller", 0x1000, {0x1010: 0x2000, 0x1020: 0x2000})
    assert list(iter_callees(caller, kb)) == [callee]


def test_iter_callees_preserves_call_site_order():
    a = _FakeFunc("a", 0x2000, {})
    b = _FakeFunc("b", 0x3000, {})
    kb = _FakeKb({0x2000: a, 0x3000: b})
    caller = _FakeFunc("caller", 0x1000, {0x1010: 0x3000, 0x1020: 0x2000})
    # Yields in call-site iteration order: b (0x3000) then a (0x2000).
    assert list(iter_callees(caller, kb)) == [b, a]


# --------------------------------------------------------------------------- #
# RED proof: real angr CFG on the committed fixture.
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def built_fixture(tmp_path_factory):
    """Compile the committed fixture. Source is committed; the ELF is not."""
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc not available to build the call-graph fixture")
    out = tmp_path_factory.mktemp("angr_callgraph") / "two_funcs"
    subprocess.run(
        [gcc, *_CFLAGS, "-o", str(out), str(FIXTURE_SRC)],
        check=True, capture_output=True, text=True,
    )
    return out


def test_build_cfg_recovers_direct_call_edge_without_falling_back(
    built_fixture, monkeypatch
):
    pytest.importorskip("angr")
    from supwngo.analysis.cfg import CFGAnalyzer
    from supwngo.core.binary import Binary

    analyzer = CFGAnalyzer(Binary.load(str(built_fixture)))

    # Spy on the capstone fallback: angr can analyze this trivial static binary,
    # so the fallback must NOT run. On base it does (functions_called raises ->
    # broad except -> fallback), which is exactly what this asserts against.
    seen = {"capstone": False}
    original = analyzer._build_cfg_capstone

    def _spy(*args, **kwargs):
        seen["capstone"] = True
        return original(*args, **kwargs)

    monkeypatch.setattr(analyzer, "_build_cfg_capstone", _spy)

    analyzer.build_cfg()

    assert seen["capstone"] is False, (
        "capstone fallback was taken: the angr call-graph path still breaks "
        "(functions_called() AttributeError swallowed into the fallback)"
    )
    # The exact, known edge -- not merely a non-empty graph.
    assert "leaf_helper" in analyzer.call_graph.get("entry_main", []), (
        "expected the entry_main -> leaf_helper edge from the real angr CFG; "
        f"got call_graph={dict(analyzer.call_graph)}"
    )
    # And the reverse edge, since cfg.py populates both directions.
    assert "entry_main" in analyzer.reverse_call_graph.get("leaf_helper", [])
