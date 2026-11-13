"""Tests for the W-1 payoff ranker (``supwngo.analysis.payoff``).

Commit 1 covers the address-normalization primitive: the corpus-truth RVA
convention ``rva = address - image_base`` across PIE, ET_EXEC and PE, and the
contrast with the link-time VADDR that ``_to_file_address`` yields (the bug the
primitive exists to prevent). These tests are load-free (no backend) and always
run; a corpus cross-check runs only when the dev corpus has been built.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from supwngo.analysis import payoff
from supwngo.analysis.decompile import Decompiler

# (format, backend_base/image_base, backend_addr/vaddr, expected truth rva)
# PIE: image base 0 -> vaddr == rva. ET_EXEC: 0x400000. PE: 0x140000000.
_FORMAT_CASES = [
    ("pie", 0x0, 0x11C9, 0x11C9),
    ("et_exec", 0x400000, 0x4013B9, 0x13B9),
    ("pe", 0x140000000, 0x140001500, 0x1500),
]


@pytest.mark.parametrize("fmt,base,addr,expected", _FORMAT_CASES)
def test_to_corpus_rva_matches_truth_convention(fmt, base, addr, expected):
    assert payoff.to_corpus_rva(addr, base) == expected


@pytest.mark.parametrize("fmt,base,addr,expected", _FORMAT_CASES)
def test_to_file_address_is_vaddr_not_rva(fmt, base, addr, expected):
    """Guards the fix: ``_to_file_address`` is the VADDR and equals the truth rva
    only for PIE. For non-PIE it is off by ``image_base`` — using it directly
    would fail the gate, which is why ``to_corpus_rva`` exists."""
    vaddr = Decompiler._to_file_address(addr, base, base)
    assert vaddr == addr  # file_base == backend_base here, so it returns the addr
    if base == 0:
        assert vaddr == expected
    else:
        assert vaddr != expected
        # ...and subtracting file_base recovers the rva, matching to_corpus_rva.
        assert vaddr - base == payoff.to_corpus_rva(addr, base)


def test_to_corpus_rva_rejects_bool():
    with pytest.raises(TypeError):
        payoff.to_corpus_rva(True, 0)
    with pytest.raises(TypeError):
        payoff.to_corpus_rva(0x1000, False)


def test_to_corpus_rva_rejects_non_int():
    with pytest.raises(TypeError):
        payoff.to_corpus_rva("0x1000", 0)
    with pytest.raises(TypeError):
        payoff.to_corpus_rva(0x1000, None)


def test_to_corpus_rva_rejects_address_below_base():
    with pytest.raises(ValueError):
        payoff.to_corpus_rva(0x400000, 0x401000)


def test_to_corpus_rva_rejects_negative():
    with pytest.raises(ValueError):
        payoff.to_corpus_rva(-1, 0)
    with pytest.raises(ValueError):
        payoff.to_corpus_rva(0x1000, -1)


# --- corpus cross-check (only if the dev corpus is built) --------------------

_BUILD = Path(__file__).resolve().parents[1] / "benchmark" / "gen" / "payoff" / "build"


def _truth_files():
    truth = _BUILD / "truth"
    if not truth.is_dir():
        return []
    return sorted(truth.glob("*.json"))


@pytest.mark.skipif(not _truth_files(), reason="dev payoff corpus not built")
def test_to_corpus_rva_reproduces_every_truth_payoff_rva():
    """For every corpus unit with a payoff, ``to_corpus_rva(payoff_vaddr,
    image_base)`` reproduces the stored ``payoff_rva`` — across PIE, ET_EXEC and
    PE, which is exactly the normalization the ranker performs on backend output."""
    checked = 0
    for jf in _truth_files():
        d = json.loads(jf.read_text())
        if d.get("payoff_rva") is None or d.get("payoff_vaddr") is None:
            continue
        assert (
            payoff.to_corpus_rva(d["payoff_vaddr"], d["image_base"]) == d["payoff_rva"]
        ), jf.name
        checked += 1
    assert checked > 0


# =========================================================================== #
# Commit 2 — evidence model (scorer, disqualifiers, invariant, canonicalizers)
# =========================================================================== #
from supwngo.analysis.payoff import (  # noqa: E402
    ATOM_EXEC_CONST,
    ATOM_FILE_FIXED,
    ATOM_NO_SINK,
    ATOM_TARGET_IS_PARAM,
    ATOM_UNREFERENCED,
    CompletionMarker,
    FunctionEvidence,
    SinkObservation,
    TargetTrace,
    canonical_import,
    display_name,
    marker_is_complete,
    rank_candidates,
    score_function,
)


def _const(value="/etc/hosts", address=0x402047):
    return TargetTrace(TargetTrace.CONST_STRING, address=address, value=value)


def _param():
    return TargetTrace(TargetTrace.PARAM, address=None, value=None)


def _unknown():
    return TargetTrace(TargetTrace.UNKNOWN)


def _payoff_exec(rva=5049, unref=True):
    return FunctionEvidence(
        rva=rva,
        name=None,
        sinks=(SinkObservation("execve", _const("/bin/dash")),),
        unreferenced=unref,
    )


def _payoff_file(rva=5049, unref=True):
    return FunctionEvidence(
        rva=rva,
        name="reazus_kainruk",
        sinks=(SinkObservation("fopen", _const("/etc/hosts")),),
        has_read=True,
        has_stdout_output=True,
        unreferenced=unref,
    )


def _decoy_filecopy(rva=5102):
    # same read-to-stdout body, but the path is a PARAMETER (called "/dev/null")
    return FunctionEvidence(
        rva=rva,
        name="temflel_tibla",
        sinks=(SinkObservation("fopen", _param()),),
        has_read=True,
        has_stdout_output=True,
        unreferenced=False,
    )


def _decoy_compare(rva=4598):
    return FunctionEvidence(
        rva=rva, name="glasfliom_game", sinks=(), unreferenced=False
    )


def _filler(rva=4688, unref=True):
    return FunctionEvidence(
        rva=rva, name="klouvut_hekrios", sinks=(), unreferenced=unref
    )


def test_payoff_exec_is_exec_const_candidate():
    ev = score_function(_payoff_exec())
    assert ATOM_EXEC_CONST in ev.atoms
    assert ev.sink_api == "execve"


def test_payoff_file_is_file_fixed_candidate():
    ev = score_function(_payoff_file())
    assert ATOM_FILE_FIXED in ev.atoms


def test_decoy_filecopy_param_target_is_not_a_candidate():
    ev = score_function(_decoy_filecopy())
    assert ATOM_TARGET_IS_PARAM in ev.atoms
    assert ATOM_FILE_FIXED not in ev.atoms and ATOM_EXEC_CONST not in ev.atoms


def test_decoy_compare_and_filler_are_no_sink():
    for fe in (_decoy_compare(), _filler()):
        ev = score_function(fe)
        assert ATOM_NO_SINK in ev.atoms
        assert ATOM_FILE_FIXED not in ev.atoms and ATOM_EXEC_CONST not in ev.atoms


def test_unknown_target_never_yields_a_fixed_atom():
    """Fail-closed: a sink whose path provenance is unknown is not a candidate."""
    fe = FunctionEvidence(
        rva=1,
        name=None,
        sinks=(SinkObservation("fopen", _unknown()),),
        has_read=True,
        has_stdout_output=True,
    )
    ev = score_function(fe)
    assert ATOM_FILE_FIXED not in ev.atoms
    fe2 = FunctionEvidence(
        rva=2, name=None, sinks=(SinkObservation("execve", _unknown()),)
    )
    assert ATOM_EXEC_CONST not in score_function(fe2).atoms


def test_file_const_without_disclosure_is_not_file_fixed():
    fe = FunctionEvidence(
        rva=1,
        name=None,
        sinks=(SinkObservation("fopen", _const("/etc/passwd")),),
        has_read=False,
        has_stdout_output=False,
    )
    assert ATOM_FILE_FIXED not in score_function(fe).atoms


def test_unreferenced_is_rank_only_not_a_gate():
    """An uncalled filler with no sink is still not a candidate (R3)."""
    ev = score_function(_filler(unref=True))
    assert ATOM_UNREFERENCED in ev.atoms
    assert ev.rank_key[0] == 0  # no sink


def test_rank_candidates_picks_the_unique_payoff_from_a_mixed_unit():
    unit = [
        _decoy_compare(),
        _filler(),
        _decoy_filecopy(),
        _payoff_file(rva=5049),
        _filler(rva=5362, unref=False),
    ]
    cands = rank_candidates(unit)
    assert len(cands) == 1
    assert cands[0].rva == 5049


def test_rank_orders_by_unreferenced_then_rva():
    # two hypothesis-tier functions: the unreferenced one ranks first
    called = _payoff_exec(rva=0x2000, unref=False)
    uncalled = _payoff_exec(rva=0x3000, unref=True)
    cands = rank_candidates([called, uncalled])
    assert [c.rva for c in cands] == [0x3000, 0x2000]
    # tie on (sink, unreferenced): lower rva first
    a = _payoff_exec(rva=0x3000, unref=True)
    b = _payoff_exec(rva=0x1000, unref=True)
    assert [c.rva for c in rank_candidates([a, b])] == [0x1000, 0x3000]


def test_canonical_import_resolves_plt_iat_and_underscore_forms():
    assert canonical_import("fopen@GLIBC_2.2.5") == "fopen"
    assert canonical_import("execve@plt") == "execve"
    assert canonical_import("__imp_fopen") == "fopen"
    assert canonical_import("_system") == "system"
    assert canonical_import("system") == "system"
    assert canonical_import("") == ""


def test_canonical_api_form_still_matches_family_in_scorer():
    fe = FunctionEvidence(
        rva=1,
        name=None,
        sinks=(SinkObservation("fopen@GLIBC_2.2.5", _const("/etc/hosts")),),
        has_read=True,
        has_stdout_output=True,
    )
    assert ATOM_FILE_FIXED in score_function(fe).atoms


def test_display_name_suppresses_synthetic_labels():
    assert display_name("FUN_00401234") is None
    assert display_name("SUB_1500") is None
    assert display_name("LAB_deadbeef") is None
    assert display_name("risbles_rim") == "risbles_rim"
    assert display_name("") is None
    assert display_name(None) is None


def test_marker_is_complete_enforces_the_invariant():
    assert marker_is_complete(CompletionMarker(enumerated=10, analyzed=10, failed=0))
    assert not marker_is_complete(None)
    assert not marker_is_complete(
        CompletionMarker(enumerated=10, analyzed=9, failed=0)
    )  # not all analyzed
    assert not marker_is_complete(
        CompletionMarker(enumerated=10, analyzed=10, failed=1)
    )  # a failure
    assert not marker_is_complete(
        CompletionMarker(enumerated=-1, analyzed=-1, failed=0)
    )  # malformed
