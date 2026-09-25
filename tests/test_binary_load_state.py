"""Tests for Binary's tri-state pwntools-load tracking.

``supwngo/core/binary.py`` used to convert "pwntools failed to load this ELF"
into "this binary has no symbols / no protections" via two broad ``except``
handlers in ``_load_with_pwntools()`` plus a ``_detect_protections()`` with no
``else`` branch. A caller had no way to tell a genuinely symbol-less binary
from one where the loader simply blew up.

These tests prove the fix: a failed or skipped pwntools load now surfaces as
its own structured, inspectable state (``Binary.pwntools_load_state`` /
``Binary.pwntools_load_error``), and ``_detect_protections()`` records whether
it ever actually measured anything (``Binary.protections_measured``), which is
distinct from "measured, and everything happens to be False".
"""

from __future__ import annotations

import logging
import sys

import pytest

from supwngo.core.binary import Binary, PwntoolsLoadState

CORPUS_BINARY = "benchmark/corpus/15_win_function/win_function"


@pytest.fixture(scope="module", autouse=True)
def _require_pwnlib():
    pytest.importorskip("pwn")


class _FakeElf:
    """Minimal stand-in for pwntools' ``ELF``, exposing only what
    ``_detect_protections()`` reads from it."""

    def __init__(self, canary=False, nx=False, pie=False, relro=False):
        self.canary = canary
        self.nx = nx
        self.pie = pie
        self.relro = relro


# ---------------------------------------------------------------------------
# Positive control -- must pass, and prove pwntools actually ran, before any
# failure-arm assertion below means anything.
# ---------------------------------------------------------------------------


def test_positive_control_real_binary_loads_and_reports_success():
    """A real corpus ELF loads cleanly: state is SUCCESS with real symbols.

    If this does not pass, the failure-arm tests below cannot be trusted --
    they would be indistinguishable from a success path that never worked
    in the first place.
    """
    binary = Binary.load(CORPUS_BINARY)

    assert binary.pwntools_load_state == PwntoolsLoadState.SUCCESS
    assert binary.pwntools_load_error is None
    assert binary.symbols, "expected a real ELF to yield non-empty symbols"
    assert binary.plt, "expected a real ELF to yield a non-empty PLT"
    assert binary.protections_measured is True


# ---------------------------------------------------------------------------
# The two failure arms, asserted separately.
# ---------------------------------------------------------------------------


def test_generic_pwntools_failure_reports_load_failed_not_success(monkeypatch):
    """A pwntools ``ELF()`` exception must surface as LOAD_FAILED.

    Forces the ``except Exception`` arm in ``_load_with_pwntools()``
    specifically (not ``ImportError``) and asserts the exception text is
    preserved in the structured field, and that the failure does not
    masquerade as a real "no symbols" binary.
    """

    def _raise(*_args, **_kwargs):
        raise RuntimeError("boom: corrupt ELF header")

    monkeypatch.setattr("pwn.ELF", _raise)

    binary = Binary(path=CORPUS_BINARY)
    binary._load_with_pwntools()

    assert binary.pwntools_load_state == PwntoolsLoadState.LOAD_FAILED
    assert binary.pwntools_load_state != PwntoolsLoadState.SUCCESS
    assert binary.pwntools_load_error is not None
    assert "boom: corrupt ELF header" in binary.pwntools_load_error
    assert binary.symbols == {}


def test_pwntools_unavailable_reports_its_own_distinct_state(monkeypatch):
    """An ``ImportError`` (pwntools not installed) is its own state.

    Setting ``sys.modules["pwn"] = None`` reproduces a real ``ImportError``
    on ``from pwn import ELF, context`` without needing pwntools to actually
    be uninstalled. This must land in a state distinct from both SUCCESS and
    the generic LOAD_FAILED arm above.
    """
    monkeypatch.setitem(sys.modules, "pwn", None)

    binary = Binary(path=CORPUS_BINARY)
    binary._load_with_pwntools()

    assert binary.pwntools_load_state == PwntoolsLoadState.PWNTOOLS_UNAVAILABLE
    assert binary.pwntools_load_state != PwntoolsLoadState.LOAD_FAILED
    assert binary.pwntools_load_state != PwntoolsLoadState.SUCCESS
    assert binary.pwntools_load_error


def test_load_failure_arms_log_at_error_not_warning(monkeypatch, caplog):
    """Both failure arms must log loudly (error), matching the brief's "make
    it loud" requirement -- a `warning` is exactly what let this collapse
    hide in production logs before."""

    def _raise(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("pwn.ELF", _raise)
    binary = Binary(path=CORPUS_BINARY)
    with caplog.at_level(logging.DEBUG, logger="supwngo.core.binary"):
        binary._load_with_pwntools()

    assert caplog.records, "expected the failed load to produce a log record"
    assert all(
        record.levelno >= logging.ERROR for record in caplog.records
    ), f"expected only ERROR+ records, got: {[r.levelname for r in caplog.records]}"


def test_never_attempted_load_state_is_not_success():
    """A Binary that never ran ``_load_with_pwntools()`` must not read as a
    successful load -- the field's initial value must not be the success
    constant."""
    binary = Binary(path=CORPUS_BINARY)
    assert binary.pwntools_load_state == PwntoolsLoadState.NOT_ATTEMPTED
    assert binary.pwntools_load_state != PwntoolsLoadState.SUCCESS


# ---------------------------------------------------------------------------
# Protections: "never measured" vs. "measured and all false".
# ---------------------------------------------------------------------------


def test_protections_never_measured_is_distinguishable_from_all_false():
    """The exact trap called out in the brief: a test that only asserts
    ``protections.canary is False`` would pass in BOTH "never measured" and
    "measured and everything is off" worlds. ``protections_measured`` is
    what actually tells them apart.
    """
    # World 1: no ELF was ever loaded (e.g. after a failed pwntools load) --
    # no measurement was ever attempted.
    unmeasured = Binary(path=CORPUS_BINARY)
    unmeasured._elf = None
    unmeasured._detect_protections()

    # World 2: an ELF loaded and genuinely has every protection disabled.
    measured_all_false = Binary(path=CORPUS_BINARY)
    measured_all_false._elf = _FakeElf(canary=False, nx=False, pie=False, relro=False)
    measured_all_false._detect_protections()

    # The trap: this alone is true in both worlds and proves nothing about
    # which one actually happened.
    assert unmeasured.protections.canary is False
    assert measured_all_false.protections.canary is False

    # What actually distinguishes "never measured" from "measured, all off":
    assert unmeasured.protections_measured is False
    assert measured_all_false.protections_measured is True


def test_detect_protections_sets_measured_false_when_measurement_itself_raises(
    monkeypatch,
):
    """If constructing ``Protections`` blows up partway through, that is
    still "never measured", not a silent success."""
    binary = Binary(path=CORPUS_BINARY)
    broken_elf = _FakeElf(canary=False, nx=False, pie=False, relro=False)
    binary._elf = broken_elf

    def _boom(*_args, **_kwargs):
        raise RuntimeError("relro detection exploded")

    monkeypatch.setattr(binary, "_relro_str", _boom)
    binary._detect_protections()

    assert binary.protections_measured is False
