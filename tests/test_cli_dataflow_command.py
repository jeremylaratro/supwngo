"""Regression tests for the `supwngo dataflow` command's entry-point fallback.

The defect: when the target has no ``main`` symbol (e.g. a stripped binary) and
no ``-f/--function`` is given, ``dataflow`` fell back to ``bin_obj.elf.entry``.
``Binary`` has no ``.elf`` attribute (the pwntools handle is the private
``_elf``; the public entry address is ``entry_point``), so the command crashed
with ``AttributeError: 'Binary' object has no attribute 'elf'`` on exactly the
stripped-binary case it was meant to handle.

These tests isolate the entry-point *resolution* logic from the heavy data-flow
analysis by faking ``Binary.load`` and ``DataFlowAnalyzer``, so they are
hermetic (no gcc/strip needed) and fast. ``DataFlowAnalyzer`` is imported inside
the command body, so it is patched at its source module.
"""
from __future__ import annotations

import types

from click.testing import CliRunner

import supwngo.core.binary as binmod
import supwngo.analysis.dataflow as dfmod
from supwngo.cli import cli


def _install_fakes(monkeypatch, *, symbols, entry_point):
    """Make ``dataflow`` resolve against a stub Binary and capture the address
    the analyzer is actually asked to analyze."""
    fake_bin = types.SimpleNamespace(symbols=symbols, entry_point=entry_point)
    monkeypatch.setattr(
        binmod.Binary, "load", classmethod(lambda cls, path: fake_bin)
    )

    captured = {}

    class FakeAnalyzer:
        def __init__(self, _binary, angr_timeout=None):
            # S4b-i added the budgeted-subprocess provenance channel: the command
            # passes ``angr_timeout=`` and reads these markers after analysis.
            captured["angr_timeout"] = angr_timeout
            self.analysis_backend = "angr"
            self.angr_budget_exceeded = False

        def analyze_function(self, addr):
            captured["addr"] = addr
            return {}

    monkeypatch.setattr(dfmod, "DataFlowAnalyzer", FakeAnalyzer)
    return captured


def test_dataflow_without_main_symbol_falls_back_to_entry_point(monkeypatch, tmp_path):
    """The regression guard: no ``main`` symbol, no ``-f`` -> the command must
    fall back to ``entry_point``. Before the fix this raised
    ``AttributeError: 'Binary' object has no attribute 'elf'`` and exited non-zero."""
    target = tmp_path / "stripped"
    target.write_bytes(b"\x7fELF")  # only needs to exist for click's Path(exists=True)

    captured = _install_fakes(monkeypatch, symbols={}, entry_point=0x401234)

    result = CliRunner().invoke(cli, ["dataflow", str(target)])

    assert result.exit_code == 0, (result.output, result.exception)
    assert "has no attribute 'elf'" not in result.output
    assert captured.get("addr") == 0x401234


def test_dataflow_prefers_main_symbol_over_entry_point(monkeypatch, tmp_path):
    """Positive control: when a ``main`` symbol exists it wins, so the fallback
    above is specific to the no-``main`` case rather than always using
    ``entry_point``."""
    target = tmp_path / "withmain"
    target.write_bytes(b"\x7fELF")

    symbols = {"main": types.SimpleNamespace(address=0x401500)}
    captured = _install_fakes(monkeypatch, symbols=symbols, entry_point=0x401234)

    result = CliRunner().invoke(cli, ["dataflow", str(target)])

    assert result.exit_code == 0, (result.output, result.exception)
    assert captured.get("addr") == 0x401500
