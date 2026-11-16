"""Sprint-B2 new-behavior tests: UAFDetector and OffByOneDetector, now wired
into the reporting adapter, actually emit their dedicated VULN families on known
positives, stay silent on the matched controls, and honour the detector contract.

These pin the *specific* behavior the B2 bounded fix added:
  * UAFDetector emits VulnType.USE_AFTER_FREE (not a custom broken type);
  * OffByOneDetector emits VulnType.OFF_BY_ONE and NEVER the generic
    STACK/HEAP overflow types it used to emit (precision guard);
  * both accept ``detect(crash=None)`` and expose ``get_exploit_primitive``;
  * both never raise, even when disassembly is impossible (adapter contract).

Recall is partial by design (the cheap body-level signal fires on one shape per
family); these tests assert the confirmed-positive shapes, not full recall.
Corpus binaries are build artifacts -> a missing one skips, never fails.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from supwngo.core.binary import Binary
from supwngo.vulns.detector import ExploitPrimitive, VulnType
from supwngo.vulns.off_by_one import OffByOneDetector
from supwngo.vulns.uaf import UAFDetector

BENCH = Path(__file__).resolve().parents[1] / "benchmark"

# Confirmed-positive and matched-control binaries (see the B2 vuln-ident scorer).
UAF_POS = "corpus_uafread/uafr_10_show_after_free/uafr_10_show_after_free"
UAF_NEG = "corpus_uafread/uafr_90_neg_cleared_on_free/uafr_90_neg_cleared_on_free"
OBO_POS = "corpus_offbyone/obo_14_snprintf_ret_caller_frame/obo_14_snprintf_ret_caller_frame"
OBO_NEG = "corpus_offbyone/obo_90_neg_bound_fixed/obo_90_neg_bound_fixed"


def _load(rel: str) -> Binary:
    p = BENCH / rel
    if not p.exists():
        pytest.skip(f"corpus binary not built: {rel}")
    return Binary.load(str(p))


def _types(vulns):
    return {v.vuln_type for v in vulns}


# --- UAF -------------------------------------------------------------------

def test_uaf_detector_emits_use_after_free_on_known_positive():
    vulns = UAFDetector(_load(UAF_POS)).detect()
    assert VulnType.USE_AFTER_FREE in _types(vulns), (
        "UAFDetector must emit USE_AFTER_FREE on uafr_10 (free-without-null shape)"
    )


def test_uaf_detector_is_silent_on_cleared_on_free_control():
    vulns = UAFDetector(_load(UAF_NEG)).detect()
    assert VulnType.USE_AFTER_FREE not in _types(vulns), (
        "control NULLs the freed pointer -> must not be flagged as UAF (0 FP)"
    )


# --- off-by-one ------------------------------------------------------------

def test_off_by_one_detector_emits_off_by_one_on_known_positive():
    vulns = OffByOneDetector(_load(OBO_POS)).detect()
    assert VulnType.OFF_BY_ONE in _types(vulns), (
        "OffByOneDetector must emit OFF_BY_ONE on obo_14 (calls snprintf)"
    )


def test_off_by_one_detector_never_emits_generic_overflow_types():
    """Precision guard: the old detector polluted stack_bof/heap_overflow. The
    rewrite maps exclusively to OFF_BY_ONE."""
    vulns = OffByOneDetector(_load(OBO_POS)).detect()
    emitted = _types(vulns)
    assert VulnType.STACK_BUFFER_OVERFLOW not in emitted
    assert VulnType.HEAP_BUFFER_OVERFLOW not in emitted


def test_off_by_one_detector_is_silent_on_bounded_control():
    vulns = OffByOneDetector(_load(OBO_NEG)).detect()
    assert VulnType.OFF_BY_ONE not in _types(vulns), (
        "control calls no length-terminating copy -> must not be flagged (0 FP)"
    )


# --- contract --------------------------------------------------------------

@pytest.mark.parametrize("cls,rel", [(UAFDetector, UAF_POS), (OffByOneDetector, OBO_POS)])
def test_detectors_accept_crash_kwarg_and_expose_primitive(cls, rel):
    det = cls(_load(rel))
    vulns = det.detect(crash=None)  # base contract: detect(crash=None)
    assert isinstance(vulns, list)
    if vulns:
        prim = det.get_exploit_primitive(vulns[0])
        assert isinstance(prim, ExploitPrimitive)
        assert prim.primitive_type == "write"


@pytest.mark.parametrize("cls", [UAFDetector, OffByOneDetector])
def test_detectors_return_empty_for_pathless_binary(cls):
    """A binary that was never parsed (no path) yields [] rather than raising;
    the adapter reports that parse failure separately."""
    stub = SimpleNamespace(path=None)
    assert cls(stub).detect() == []


# --- honesty: objdump genuinely unavailable is a failure, not a clean pass ----

# Every way objdump can fail to actually run: absent, not executable (or other
# launch OSError), and timed out. None may read back as "analyzed, found nothing".
_LAUNCH_FAILURES = [
    ("not_installed", lambda *_a, **_k: (_ for _ in ()).throw(FileNotFoundError("objdump"))),
    ("not_executable", lambda *_a, **_k: (_ for _ in ()).throw(PermissionError(13, "Permission denied"))),
    ("timeout", lambda *_a, **_k: (_ for _ in ()).throw(__import__("subprocess").TimeoutExpired("objdump", 20))),
]


@pytest.mark.parametrize("label,boom", _LAUNCH_FAILURES, ids=[f[0] for f in _LAUNCH_FAILURES])
def test_objdump_launch_failure_raises_disassembly_unavailable(monkeypatch, label, boom):
    """objdump that cannot run must raise, not return [] -- otherwise "could not
    analyze" is indistinguishable from "analyzed, found nothing"."""
    from supwngo.vulns import _disasm

    monkeypatch.setattr(_disasm.subprocess, "run", boom)
    with pytest.raises(_disasm.DisassemblyUnavailable):
        _disasm.objdump_intel(_load(UAF_POS))


@pytest.mark.parametrize("label,boom", _LAUNCH_FAILURES, ids=[f[0] for f in _LAUNCH_FAILURES])
def test_detect_all_marks_report_incomplete_when_objdump_cannot_run(monkeypatch, label, boom):
    """The whole point of the raise: a host where objdump cannot run produces an
    *incomplete* report (failures recorded), never a clean complete one."""
    from supwngo.vulns import _disasm
    from supwngo.reporting.adapter import build_report, detect_all

    monkeypatch.setattr(_disasm.subprocess, "run", boom)
    binary = _load(UAF_POS)
    found, failures = detect_all(binary, detectors=[UAFDetector, OffByOneDetector])
    assert len(failures) == 2
    assert all("DisassemblyUnavailable" in f.error for f in failures)
    report = build_report(binary, found, failures)
    assert report.metadata["complete"] is False
    assert report.metadata["detectors_failed"] == 2
