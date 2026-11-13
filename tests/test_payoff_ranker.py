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


# =========================================================================== #
# Commit 3 — cache: serialization envelope, versioned table, clear_cache
# =========================================================================== #
from supwngo.analysis.payoff import (  # noqa: E402
    CACHE_ENVELOPE_VERSION,
    PayoffCandidate,
    PayoffEvidence,
    PayoffReport,
    PayoffStatus,
    SCRIPT_VERSION,
    angr_version,
    backend_version,
    ghidra_version,
    report_from_json,
    report_to_json,
)
from supwngo.core.database import Database  # noqa: E402


def _sample_report(status=PayoffStatus.COMPLETE):
    ev = PayoffEvidence(
        atoms=(ATOM_FILE_FIXED, ATOM_UNREFERENCED),
        sink_api="fopen",
        target=TargetTrace(
            TargetTrace.CONST_STRING, address=0x402051, value="/etc/hosts"
        ),
        rank_key=(1, 1),
        score=110,
    )
    cand = PayoffCandidate(rva=5049, name=None, evidence=ev)
    return PayoffReport(
        status=status,
        candidates=(cand,),
        backend="ghidra",
        attempts=({"backend": "ghidra", "outcome": "complete"},),
        counts={"enumerated": 13, "analyzed": 13, "failed": 0},
        elapsed_s=4.2,
        budget_s=180.0,
        from_cache=False,
    )


def test_report_json_roundtrip_preserves_everything():
    report = _sample_report()
    back = report_from_json(report_to_json(report))
    assert back is not None
    assert back.status is PayoffStatus.COMPLETE
    assert back.backend == "ghidra"
    assert back.counts == {"enumerated": 13, "analyzed": 13, "failed": 0}
    assert back.elapsed_s == 4.2 and back.budget_s == 180.0
    assert len(back.candidates) == 1
    c = back.candidates[0]
    assert c.rva == 5049 and c.name is None
    assert c.evidence.atoms == (ATOM_FILE_FIXED, ATOM_UNREFERENCED)
    assert c.evidence.target.value == "/etc/hosts"
    assert c.evidence.rank_key == (1, 1)
    assert back.from_cache is True  # set on read


def test_report_from_json_rejects_corrupt_and_wrong_version():
    assert report_from_json(None) is None
    assert report_from_json("") is None
    assert report_from_json("{not json") is None
    assert report_from_json(json.dumps({"envelope_version": 999, "report": {}})) is None
    assert report_from_json(json.dumps({"report": {"status": "complete"}})) is None
    # right envelope, structurally broken body -> miss, never a half-built report
    assert (
        report_from_json(
            json.dumps({"envelope_version": CACHE_ENVELOPE_VERSION, "report": {"x": 1}})
        )
        is None
    )


def test_payoff_cache_table_roundtrip_and_version_key(tmp_path):
    db = Database(db_path=str(tmp_path / "t.db"))
    sha = "a" * 64
    db.save_payoff_analysis(
        sha, SCRIPT_VERSION, "ghidra-11.0", report_to_json(_sample_report())
    )
    # exact key hits
    hit = report_from_json(db.get_payoff_analysis(sha, SCRIPT_VERSION, "ghidra-11.0"))
    assert hit is not None and hit.candidates[0].rva == 5049
    # a different script/backend version is a miss (invalidation by key)
    assert db.get_payoff_analysis(sha, "w0.9", "ghidra-11.0") is None
    assert db.get_payoff_analysis(sha, SCRIPT_VERSION, "ghidra-10.0") is None


def test_payoff_cache_coexists_and_clear_cache_covers_it(tmp_path):
    db = Database(db_path=str(tmp_path / "t.db"))
    sha = "b" * 64
    db.save_binary_analysis("/bin/x", sha, "amd64", 64, {"nx": True}, {"foo": 1})
    db.save_payoff_analysis(
        sha, SCRIPT_VERSION, "ghidra-11.0", report_to_json(_sample_report())
    )
    # writing payoff did not disturb the binaries row
    assert db.get_binary_analysis(sha)["analysis_data"] == {"foo": 1}
    assert db.get_payoff_analysis(sha, SCRIPT_VERSION, "ghidra-11.0") is not None
    # scoped payoff-only invalidation leaves the binaries row intact
    db.clear_payoff_analysis(sha)
    assert db.get_payoff_analysis(sha, SCRIPT_VERSION, "ghidra-11.0") is None
    assert db.get_binary_analysis(sha) is not None


def test_clear_cache_both_branches_drop_payoff(tmp_path):
    for scoped in (True, False):
        db = Database(db_path=str(tmp_path / f"c{scoped}.db"))
        sha = "c" * 64
        db.save_payoff_analysis(
            sha, SCRIPT_VERSION, "gv", report_to_json(_sample_report())
        )
        db.clear_cache(sha if scoped else None)
        assert db.get_payoff_analysis(sha, SCRIPT_VERSION, "gv") is None


def test_version_discovery_is_stringy_and_processfree():
    assert isinstance(ghidra_version(), str)
    assert isinstance(angr_version(), str)
    assert backend_version("ghidra") == ghidra_version()
    assert backend_version("angr") == angr_version()
    assert backend_version("bogus") == "unknown"
    assert isinstance(SCRIPT_VERSION, str) and SCRIPT_VERSION
