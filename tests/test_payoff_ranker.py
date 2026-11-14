"""Tests for the W-1 payoff ranker (``supwngo.analysis.payoff``).

Commit 1 covers the address-normalization primitive: the corpus-truth RVA
convention ``rva = address - image_base`` across PIE, ET_EXEC and PE, and the
contrast with the link-time VADDR that ``_to_file_address`` yields (the bug the
primitive exists to prevent). These tests are load-free (no backend) and always
run; a corpus cross-check runs only when the dev corpus has been built.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

import supwngo.analysis.decompile as decompile_mod
from supwngo.analysis import payoff
from supwngo.analysis.decompile import Decompiler, GhidraRun
from supwngo.core.proc import ProcState

sys.path.insert(0, str(Path(__file__).parent))
from ghidra_support import need_ghidra  # noqa: E402

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


# --------------------------------------------------------------------------- #
# Commit 4a: additive env= threading through _run_ghidra_headless
# (round-2 BLOCKER 2). The payoff driver delivers a writable JVM user.home to
# Ghidra's launcher via JAVA_TOOL_OPTIONS; that env must reach proc.run.
# --------------------------------------------------------------------------- #


def _fake_proc_result():
    return types.SimpleNamespace(
        state=ProcState.EXITED,
        rc=0,
        signal=None,
        errno=None,
        stdout=b"INFO  startup complete\n",
        stderr=b"",
        wall_s=0.1,
    )


def _spy_decompiler():
    return Decompiler(types.SimpleNamespace(path="/nonexistent/target"))


def test_run_ghidra_headless_threads_env_to_proc_run(monkeypatch):
    seen = {}

    def _spy_run(cmd, *, cwd, timeout, env=None):
        seen["env"] = env
        return _fake_proc_result()

    monkeypatch.setattr(decompile_mod.proc, "run", _spy_run)
    merged = {"JAVA_TOOL_OPTIONS": "-Duser.home=/tmp/jvmhome"}
    _spy_decompiler()._run_ghidra_headless(["analyzeHeadless"], timeout=1, env=merged)

    assert seen["env"] is merged
    assert seen["env"]["JAVA_TOOL_OPTIONS"] == "-Duser.home=/tmp/jvmhome"


def test_run_ghidra_headless_env_defaults_to_none_unchanged(monkeypatch):
    """Existing callers pass no env; proc.run must still see env=None (the
    byte-for-byte current behaviour)."""
    seen = {}

    def _spy_run(cmd, *, cwd, timeout, env=None):
        seen["env"] = env
        return _fake_proc_result()

    monkeypatch.setattr(decompile_mod.proc, "run", _spy_run)
    _spy_decompiler()._run_ghidra_headless(["analyzeHeadless"], timeout=1)

    assert seen["env"] is None


# =========================================================================== #
# Commit 5 — corpus tests (real Ghidra). Each names its binary id. Gated by
# need_ghidra(): a gate run sets SUPWNGO_REQUIRE_GHIDRA=1, otherwise they skip
# (each costs a JVM start). A shared module cache DB means a binary tested by
# more than one case runs Ghidra once; most run exactly once.
# =========================================================================== #


def _index_entries():
    idx = _BUILD / "index.json"
    if not idx.is_file():
        return []
    return json.loads(idx.read_text()).get("entries", [])


def _entries_of(*kinds):
    return [e for e in _index_entries() if e["kind"] in kinds]


def _truth_for(entry):
    return json.loads((_BUILD / entry["truth"]).read_text())


def _bin_for(entry):
    return _BUILD / entry["binary"]


def _ids(entries):
    return [e["id"] for e in entries]


_PAYOFF_ENTRIES = _entries_of("positive", "rename_twin", "strip_twin", "pe")
_NEGATIVE_ENTRIES = _entries_of("negative")


@pytest.fixture(scope="module")
def corpus_db(tmp_path_factory):
    """One cache DB shared by every corpus test in this module, so a binary
    referenced by more than one test spawns Ghidra at most once."""
    from supwngo.core.database import Database

    return Database(db_path=str(tmp_path_factory.mktemp("payoff_cache") / "c.db"))


@pytest.mark.skipif(not _PAYOFF_ENTRIES, reason="dev payoff corpus not built")
@pytest.mark.parametrize("entry", _PAYOFF_ENTRIES, ids=_ids(_PAYOFF_ENTRIES))
def test_payoff_corpus_top1_is_truth_and_no_decoy(entry, corpus_db):
    """Positives, rename/strip twins and PE: a COMPLETE pass with a non-empty
    candidate list whose top-1 RVA equals the truth payoff_rva, and whose top-1
    is never one of the three decoy RVAs (Done-when: 32 + 16 + 16 + 8)."""
    need_ghidra()
    truth = _truth_for(entry)
    report = payoff.rank_payoffs(str(_bin_for(entry)), db=corpus_db)

    assert report.status is payoff.PayoffStatus.COMPLETE, (entry["id"], report.attempts)
    assert report.backend == "ghidra"
    assert report.candidates, f"{entry['id']}: abstained on a payoff-bearing binary"
    top1 = report.candidates[0].rva
    assert top1 == truth["payoff_rva"], (entry["id"], top1, truth["payoff_rva"])
    decoy_rvas = set((truth.get("decoys") or {}).values())
    assert top1 not in decoy_rvas, (entry["id"], "top-1 is a decoy", top1, decoy_rvas)


@pytest.mark.skipif(not _NEGATIVE_ENTRIES, reason="dev payoff corpus not built")
@pytest.mark.parametrize("entry", _NEGATIVE_ENTRIES, ids=_ids(_NEGATIVE_ENTRIES))
def test_payoff_corpus_negative_is_complete_and_empty(entry, corpus_db):
    """A negative is a *successful complete* empty pass, not a failure in
    disguise: COMPLETE, empty candidates, ghidra backend, and the completion
    invariant on the counts (failed == 0, analyzed == enumerated)."""
    need_ghidra()
    report = payoff.rank_payoffs(str(_bin_for(entry)), db=corpus_db)

    assert report.status is payoff.PayoffStatus.COMPLETE, (entry["id"], report.attempts)
    assert report.candidates == ()
    assert report.backend == "ghidra"
    assert report.counts["failed"] == 0
    assert report.counts["analyzed"] == report.counts["enumerated"]
    assert report.counts["enumerated"] > 0


# =========================================================================== #
# W-2 step 1 -- falsifier + fixture corpus categories (design doc §3a, §6 T12/T13)
#
# These are structural checks on the generator's output (index.json + truth
# files), not real-Ghidra extraction -- they confirm the corpus itself has the
# shape the design specifies, before the extractor exists to be tested
# against it (T4/T12/T13 in later steps run the real extractor against this
# same corpus). Always-run (no need_ghidra()).
# =========================================================================== #

# (args_status, args_reason) truth per the §3a table. required_args is always
# () except gate_negeq, whose seed-drawn literal is checked for shape only
# here (position == 1, an int value) -- the exact value vs. the extractor's
# output is T4's job, not step 1's.
_FALSIFIER_TRUTH = {
    "decoy_sink": ("known", None),
    "gate_audit": ("known", None),
    "gate_relaudit": ("known", None),
    "gate_invert": ("unknown", "avoidance_gate"),
    "gate_disj": ("unknown", "unresolved_gate"),
    "gate_disjineq": ("unknown", "unresolved_gate"),
    "gate_relational": ("unknown", "relational_gate"),
    "gate_arith": ("unknown", "ambiguous_gate"),
    "gate_mixed": ("unknown", "unresolved_gate"),
    "gate_bool": ("unknown", "bool_compose"),
    "gate_boolnongate": ("known", None),
    "gate_boolor": ("unknown", "unresolved_gate"),
    "gate_reload": ("unknown", "ambiguous_gate"),
    "gate_nonconst": ("unknown", "nonconst_gate"),
    "gate_paramcmp": ("unknown", "nonconst_gate"),
    "gate_multieq": ("unknown", "ambiguous_gate"),
    "gate_abistack": ("unknown", "abi_class"),
    "gate_loop": ("unknown", "unresolved_gate"),
    "gate_negeq": ("known", None),
    "gate_neginv": ("unknown", "avoidance_gate"),
    "gate_nonconst_copy": ("unknown", "nonconst_gate"),
    "gate_u8_pair": ("unknown", "unresolved_gate"),
    "gate_u8_full": ("known", None),
    "gate_u16_sparse": ("unknown", "unresolved_gate"),
    "gate_u64_sparse": ("unknown", "unresolved_gate"),
}

_FALSIFIER_ARG_BEARING_SHAPES = {"gate_negeq"}


@pytest.mark.skipif(not _index_entries(), reason="dev payoff corpus not built")
def test_falsifier_corpus_has_27_units_with_table_truth():
    """Sec 3a: 25 falsifier shapes + the gate_disj strip twin + the gate_disj
    PE variant = 27 role:"falsifier" index entries, each with the exact
    (args_status, required_args-shape, args_reason) the sec 3a table specifies."""
    entries = _entries_of("falsifier", "falsifier_strip_twin", "falsifier_pe")
    role_entries = [e for e in _index_entries() if e.get("role") == "falsifier"]
    assert len(role_entries) == 27, _ids(role_entries)
    assert len(entries) == 27, _ids(entries)
    assert {e["id"] for e in entries} == {e["id"] for e in role_entries}

    by_shape = {}
    for e in entries:
        truth = _truth_for(e)
        assert truth["role"] == "falsifier", e["id"]
        by_shape.setdefault(truth["shape"], []).append(truth)

    assert set(by_shape) == set(_FALSIFIER_TRUTH), set(by_shape) ^ set(_FALSIFIER_TRUTH)
    for shape, truths in by_shape.items():
        status, reason = _FALSIFIER_TRUTH[shape]
        for truth in truths:
            assert truth["args_status"] == status, (truth["id"], shape)
            assert truth["args_reason"] == reason, (truth["id"], shape)
            if shape in _FALSIFIER_ARG_BEARING_SHAPES:
                assert len(truth["required_args"]) == 1, truth["id"]
                assert truth["required_args"][0]["position"] == 1, truth["id"]
                assert isinstance(truth["required_args"][0]["value"], int), truth["id"]
            else:
                assert truth["required_args"] == [], (truth["id"], shape)

    # gate_disj's strip twin and PE variant carry the base shape's truth
    # unchanged (only id/kind/stripped/binary/twin_of/built_from differ).
    disj_truths = by_shape["gate_disj"]
    assert len(disj_truths) == 3  # base ELF + strip twin + PE
    assert {t["kind"] for t in disj_truths} == {
        "falsifier",
        "falsifier_strip_twin",
        "falsifier_pe",
    }


@pytest.mark.skipif(not _index_entries(), reason="dev payoff corpus not built")
def test_fixture_corpus_has_3_units_with_table_truth():
    """Sec 6 T12/T13: the two overflowable ret2win e2e fixtures and the mixed
    float/int ABI positive are present with the exact truth the design
    specifies (ret offset, required regs, required args)."""
    entries = [e for e in _index_entries() if e.get("role") == "fixture"]
    assert len(entries) == 3, _ids(entries)
    by_fixture = {_truth_for(e)["fixture"]: _truth_for(e) for e in entries}
    assert set(by_fixture) == {"e2e_arg1", "e2e_arg3", "abimix"}

    arg1 = by_fixture["e2e_arg1"]
    assert arg1["required_args"] == [{"position": 1, "value": 0x1337}]
    assert arg1["required_regs"] == ["rdi"]
    assert arg1["ret_offset"] == 88
    assert arg1["gadgets"]["gadget_stub_rva"] is not None

    arg3 = by_fixture["e2e_arg3"]
    assert arg3["required_args"] == [
        {"position": 1, "value": 0x1111},
        {"position": 2, "value": 0x2222},
        {"position": 3, "value": 0x3333},
    ]
    assert arg3["required_regs"] == ["rdi", "rsi", "rdx"]
    assert arg3["ret_offset"] == 88
    assert arg3["gadgets"]["gadget_stub_rva"] is not None

    abimix = by_fixture["abimix"]
    assert abimix["required_args"] == [{"position": 2, "value": 0x4242}]
    assert abimix["required_regs"] == ["rdi"]
    assert abimix["ret_offset"] is None
    assert abimix["gadgets"] is None


def _extract_envelope(bin_path):
    """Run the real extractor and return its parsed envelope, reusing the
    driver's own JVM-home and envelope-reading helpers (only the command list is
    assembled here). Used by the real-param test to inspect raw evidence."""
    import tempfile

    d = Decompiler(types.SimpleNamespace(path=Path(bin_path)))
    file_format, entry_rva = d._entry_info()
    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp) / "project"
        proj.mkdir()
        out = Path(tmp) / "payoff.json"
        home = Path(tmp) / "home"
        home.mkdir()
        cmd = [
            str(d._ghidra_path),
            str(proj),
            "T",
            "-import",
            str(bin_path),
            "-scriptPath",
            str(d._ghidra_scripts_dir()),
            "-postScript",
            payoff.GHIDRA_PAYOFF_SCRIPT,
            str(out),
            "none" if entry_rva is None else hex(entry_rva),
            file_format,
            "-deleteProject",
        ]
        d._run_ghidra_headless(cmd, 180, env=payoff._merged_jvm_env(str(home)))
        return payoff._read_payoff_envelope(out)


@pytest.mark.skipif(not _PAYOFF_ENTRIES, reason="dev payoff corpus not built")
def test_real_param_atom_derived_for_decoy_filecopy():
    """The extractor derives TARGET_IS_PARAM from a real binary (not hand-fed):
    on a positive whose truth lists a filecopy decoy, the evidence at that decoy
    RVA carries the param disqualifier, which is why the decoy is never a
    candidate even though its body mirrors a file-reading payoff (plan R2)."""
    need_ghidra()
    entry = next(
        (
            e
            for e in _entries_of("positive")
            if (_truth_for(e).get("decoys") or {}).get("filecopy")
        ),
        None,
    )
    assert entry is not None, "no positive with a filecopy decoy in the corpus"
    truth = _truth_for(entry)
    decoy_rva = truth["decoys"]["filecopy"]

    envelope = _extract_envelope(str(_bin_for(entry)))
    assert envelope is not None, entry["id"]
    fes = payoff._evidence_from_envelope(envelope)
    by_rva = {fe.rva: fe for fe in fes}
    assert decoy_rva in by_rva, (entry["id"], "decoy not enumerated", decoy_rva)
    ev = payoff.score_function(by_rva[decoy_rva])
    assert payoff.ATOM_TARGET_IS_PARAM in ev.atoms, (entry["id"], ev.atoms)
    assert payoff.ATOM_FILE_FIXED not in ev.atoms  # param target is not a candidate


# ---------------------------------------------------------------------------
# Commit 6/7: failure-injection, cache-safety and cache-integration.
#
# These patch the Ghidra seam (``Decompiler._run_ghidra_headless``) to write a
# crafted envelope and return a canned run, so the driver's trust logic is
# exercised without launching Ghidra. They are fast and always run. The binary
# only needs a real header (for ``_entry_info``) and a stable digest, so a
# corpus positive is used when the dev corpus is built, else a ubiquitous
# system ELF.
# ---------------------------------------------------------------------------


def _mock_binary():
    if _PAYOFF_ENTRIES:
        return str(_bin_for(_PAYOFF_ENTRIES[0]))
    for cand in ("/bin/true", "/usr/bin/true", "/bin/ls", sys.executable):
        if cand and Path(cand).is_file():
            return cand
    return None


_MOCK_BIN = _mock_binary()


def _envelope(*, enumerated=2, analyzed=2, failed=0, with_payoff=True, marker=True):
    """A real-shaped extractor envelope (mirrors SupwngoPayoff.java w2.0 output,
    including the per-record ``args_status``/``args_reason``/``required_args``)."""
    records = [
        {
            "address": 0x1000,
            "name": "main",
            "sinks": [],
            "has_read": False,
            "has_stdout_output": False,
            "unreferenced": False,
            "args_status": "known",
            "args_reason": None,
            "required_args": [],
        }
    ]
    if with_payoff:
        records.append(
            {
                "address": 0x1234,
                "name": "win",
                "sinks": [
                    {
                        "api": "system",
                        "target": {
                            "kind": "const_string",
                            "address": 0x2000,
                            "value": "/bin/sh",
                        },
                    }
                ],
                "has_read": False,
                "has_stdout_output": False,
                "unreferenced": True,
                "args_status": "known",
                "args_reason": None,
                "required_args": [],
            }
        )
    body = {"script_version": payoff.SCRIPT_VERSION, "backend_base": 0}
    if marker:
        body.update(enumerated=enumerated, analyzed=analyzed, failed=failed)
    body["records"] = records
    return json.dumps(body)


def _out_path_from_cmd(cmd):
    return Path(cmd[cmd.index("-postScript") + 2])


def _patch_extractor(
    monkeypatch, *, envelope=None, counter=None, mutate=None, raw=None
):
    """Make ``Decompiler`` believe Ghidra is present and have the driver's
    ``_run_ghidra_headless`` call write ``envelope`` (or ``raw`` bytes, or
    nothing) to the out-file and return a clean EXITED run, without launching
    Ghidra. ``counter`` (a list) records one entry per spawn; ``mutate`` runs
    mid-call to exercise the TOCTOU guard."""
    if envelope is None and raw is None:
        envelope = _envelope()
    monkeypatch.setattr(
        Decompiler, "_find_ghidra", lambda self: Path("/fake/analyzeHeadless")
    )

    def fake(self, cmd, timeout, *, env=None):
        if counter is not None:
            counter.append(env)
        out = _out_path_from_cmd(cmd)
        if raw is not None:
            out.write_text(raw, encoding="utf-8")
        elif envelope is not None:
            out.write_text(envelope, encoding="utf-8")
        if mutate is not None:
            mutate()
        return GhidraRun(
            state=ProcState.EXITED,
            rc=0,
            signal=None,
            errno=None,
            stdout_tail="",
            stderr_tail="",
            first_error="",
            wall_s=0.01,
            timeout_s=float(timeout),
        )

    monkeypatch.setattr(Decompiler, "_run_ghidra_headless", fake)


def _key(bin_path):
    sha = payoff._sha256_of(bin_path)
    return sha, payoff.SCRIPT_VERSION, payoff.backend_version("ghidra")


skip_no_bin = pytest.mark.skipif(not _MOCK_BIN, reason="no binary for mocked driver")


@skip_no_bin
def test_missing_marker_is_error_and_not_cached(monkeypatch, tmp_path):
    """An envelope with no completion marker is untrustworthy: ERROR, and
    nothing is written to the cache."""
    from supwngo.core.database import Database

    _patch_extractor(monkeypatch, envelope=_envelope(marker=False))
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.ERROR
    assert report.candidates == ()
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@skip_no_bin
def test_failed_count_is_degraded_not_complete_and_not_cached(monkeypatch, tmp_path):
    """``failed > 0`` means the pass is incomplete: DEGRADED (never a COMPLETE
    negative), no candidates, and not cached — even though a payoff record is
    present, trust is withheld."""
    from supwngo.core.database import Database

    _patch_extractor(
        monkeypatch, envelope=_envelope(enumerated=3, analyzed=2, failed=1)
    )
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.DEGRADED
    assert report.candidates == ()
    assert report.counts == {"enumerated": 3, "analyzed": 2, "failed": 1}
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@skip_no_bin
def test_unaccounted_functions_are_degraded_not_complete(monkeypatch, tmp_path):
    """``analyzed != enumerated`` (with failed == 0) is still not COMPLETE: a
    function went unaccounted for, so the empty/negative verdict is not trusted."""
    from supwngo.core.database import Database

    _patch_extractor(
        monkeypatch, envelope=_envelope(enumerated=5, analyzed=2, failed=0)
    )
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.DEGRADED
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@skip_no_bin
@pytest.mark.parametrize("raw", ["", "{ this is not json", "[1, 2, 3]", "42"])
def test_malformed_or_nonobject_output_is_error_and_not_cached(
    monkeypatch, tmp_path, raw
):
    """Empty, non-JSON, or non-object extractor output is ERROR and uncached:
    the driver fails closed rather than inventing a verdict."""
    from supwngo.core.database import Database

    _patch_extractor(monkeypatch, raw=raw)
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.ERROR
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@skip_no_bin
def test_absent_output_file_is_error_and_not_cached(monkeypatch, tmp_path):
    """If the extractor writes no file at all, the driver reports ERROR."""
    from supwngo.core.database import Database

    # A clean run that writes nothing to the out-file.
    monkeypatch.setattr(
        Decompiler, "_find_ghidra", lambda self: Path("/fake/analyzeHeadless")
    )
    monkeypatch.setattr(
        Decompiler,
        "_run_ghidra_headless",
        lambda self, cmd, timeout, *, env=None: GhidraRun(
            state=ProcState.EXITED,
            rc=0,
            signal=None,
            errno=None,
            stdout_tail="",
            stderr_tail="",
            first_error="",
            wall_s=0.01,
            timeout_s=float(timeout),
        ),
    )
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.ERROR
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@skip_no_bin
def test_timeout_is_timeout_status_and_not_cached(monkeypatch, tmp_path):
    """A timed-out (not finished) run yields TIMEOUT, not ERROR, and no cache
    write."""
    from supwngo.core.database import Database

    monkeypatch.setattr(
        Decompiler, "_find_ghidra", lambda self: Path("/fake/analyzeHeadless")
    )
    monkeypatch.setattr(
        Decompiler,
        "_run_ghidra_headless",
        lambda self, cmd, timeout, *, env=None: GhidraRun(
            state=ProcState.TIMEOUT,
            rc=None,
            signal=None,
            errno=None,
            stdout_tail="",
            stderr_tail="",
            first_error="",
            wall_s=float(timeout),
            timeout_s=float(timeout),
        ),
    )
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.TIMEOUT
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@skip_no_bin
def test_digest_change_mid_run_blocks_cache_write(monkeypatch, tmp_path):
    """TOCTOU guard: if the file digest changes during the pass, the result is
    still a valid COMPLETE report, but it is NOT cached under any key — a stale
    binary must never poison the cache."""
    from supwngo.core.database import Database

    target = tmp_path / "target.bin"
    target.write_bytes(Path(_MOCK_BIN).read_bytes())
    orig_key = _key(str(target))

    def mutate():
        with open(target, "ab") as fh:
            fh.write(b"\x00")

    _patch_extractor(monkeypatch, mutate=mutate)
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(str(target), db=db)

    assert report.status is payoff.PayoffStatus.COMPLETE
    new_key = _key(str(target))
    assert db.get_payoff_analysis(*orig_key) is None
    assert db.get_payoff_analysis(*new_key) is None
    outcomes = {a["outcome"] for a in report.attempts if a["backend"] == "cache"}
    assert "skipped" in outcomes


class _BrokenDB:
    """A cache whose every access raises — a broken cache must degrade to
    uncached analysis, never suppress it."""

    def get_payoff_analysis(self, *a, **k):
        raise RuntimeError("read boom")

    def save_payoff_analysis(self, *a, **k):
        raise RuntimeError("write boom")


@skip_no_bin
def test_broken_injected_cache_still_runs_uncached(monkeypatch):
    """An injected DB that raises on read and write does not stop the analysis:
    COMPLETE, not from cache, with both failures recorded in attempts."""
    _patch_extractor(monkeypatch)
    report = payoff.rank_payoffs(_MOCK_BIN, db=_BrokenDB())

    assert report.status is payoff.PayoffStatus.COMPLETE
    assert report.from_cache is False
    outcomes = {a["outcome"] for a in report.attempts if a["backend"] == "cache"}
    assert "read_error" in outcomes
    assert "write_error" in outcomes


@skip_no_bin
def test_default_cache_construction_failure_runs_uncached(monkeypatch):
    """When no DB is injected and the default ``Database()`` cannot be built
    (e.g. an unwritable home), analysis still runs COMPLETE and records the
    cache as unavailable (round-2 MAJOR 3)."""
    import supwngo.core.database as dbmod

    def boom(self, *a, **k):
        raise OSError("read-only home")

    monkeypatch.setattr(dbmod.Database, "__init__", boom)
    _patch_extractor(monkeypatch)
    report = payoff.rank_payoffs(_MOCK_BIN)  # db=None -> default path -> fails

    assert report.status is payoff.PayoffStatus.COMPLETE
    outcomes = {a["outcome"] for a in report.attempts if a["backend"] == "cache"}
    assert "unavailable" in outcomes


@skip_no_bin
def test_use_cache_false_never_touches_the_db(monkeypatch, tmp_path):
    """``use_cache=False`` bypasses the cache entirely: no read, no write, and
    a second call re-runs the extractor."""
    from supwngo.core.database import Database

    calls = []
    _patch_extractor(monkeypatch, counter=calls)
    db = Database(db_path=str(tmp_path / "c.db"))

    r1 = payoff.rank_payoffs(_MOCK_BIN, db=db, use_cache=False)
    r2 = payoff.rank_payoffs(_MOCK_BIN, db=db, use_cache=False)

    assert r1.status is payoff.PayoffStatus.COMPLETE
    assert r2.from_cache is False
    assert len(calls) == 2
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@skip_no_bin
def test_first_call_runs_extractor_once_second_is_cache_hit(monkeypatch, tmp_path):
    """Cache integration: the first call spawns exactly one extractor pass and
    caches it; the second returns from cache with zero spawns and the same
    candidate RVAs."""
    from supwngo.core.database import Database

    calls = []
    _patch_extractor(monkeypatch, counter=calls)
    db = Database(db_path=str(tmp_path / "c.db"))

    r1 = payoff.rank_payoffs(_MOCK_BIN, db=db)
    r2 = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert len(calls) == 1
    assert r1.from_cache is False and r2.from_cache is True
    assert r1.status is payoff.PayoffStatus.COMPLETE
    assert r2.status is payoff.PayoffStatus.COMPLETE
    assert r1.candidates, "mocked payoff envelope should yield a candidate"
    assert [c.rva for c in r1.candidates] == [c.rva for c in r2.candidates]


@skip_no_bin
def test_budget_is_the_configured_limit_on_miss_and_hit(monkeypatch, tmp_path):
    """``budget_s`` is the resolved limit on both the miss and the subsequent
    cache hit; ``elapsed_s`` is non-negative."""
    from supwngo.core.database import Database

    _patch_extractor(monkeypatch)
    db = Database(db_path=str(tmp_path / "c.db"))

    r1 = payoff.rank_payoffs(_MOCK_BIN, db=db, ghidra_timeout=123.0)
    r2 = payoff.rank_payoffs(_MOCK_BIN, db=db, ghidra_timeout=123.0)

    assert r1.budget_s == 123.0
    assert r2.budget_s == 123.0
    assert r1.elapsed_s >= 0.0
    assert r2.from_cache is True


@pytest.mark.skipif(not _PAYOFF_ENTRIES, reason="dev payoff corpus not built")
def test_jvm_user_home_override_reaches_runner_and_completes(monkeypatch):
    """End-to-end with REAL Ghidra: the per-call JVM ``user.home`` override is
    threaded all the way to ``proc.run``, and the pass completes on Ghidra (a
    silent degrade to a different backend would fail the backend assertion).

    ``use_cache=False`` forces a fresh Ghidra pass so the spy always fires,
    independent of whether another test already cached this binary."""
    need_ghidra()
    captured = {}
    real = Decompiler._run_ghidra_headless

    def spy(self, cmd, timeout, *, env=None):
        captured["env"] = env
        return real(self, cmd, timeout, env=env)

    monkeypatch.setattr(Decompiler, "_run_ghidra_headless", spy)
    report = payoff.rank_payoffs(str(_bin_for(_PAYOFF_ENTRIES[0])), use_cache=False)

    assert report.status is payoff.PayoffStatus.COMPLETE
    assert report.backend == "ghidra"
    assert captured.get("env") is not None
    assert "-Duser.home=" in captured["env"].get("JAVA_TOOL_OPTIONS", "")


# ---------------------------------------------------------------------------
# Commit 8: angr fallback (Ghidra absent). Never authoritative, never cached.
# An angr-only result lacks a backend_base, so it can never meet the Done-when
# gate and is DEGRADED at best (§3.2).
# ---------------------------------------------------------------------------

_HAS_ANGR = importlib.util.find_spec("angr") is not None


def _patch_no_ghidra(monkeypatch):
    monkeypatch.setattr(Decompiler, "_find_ghidra", lambda self: None)


@skip_no_bin
def test_angr_absent_is_no_backend_and_uncached(monkeypatch, tmp_path):
    """Ghidra absent AND angr not installed -> NO_BACKEND (backend 'none'),
    empty, uncached. Forcing find_spec('angr') to None also proves the fallback
    returns before importing angr."""
    from supwngo.core.database import Database

    _patch_no_ghidra(monkeypatch)
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a, **k: (
            None if name == "angr" else real_find_spec(name, *a, **k)
        ),
    )
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.NO_BACKEND
    assert report.backend == "none"
    assert report.candidates == ()
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None
    assert {a["outcome"] for a in report.attempts if a["backend"] == "angr"} == {
        "no_backend"
    }


@pytest.mark.skipif(
    not (_HAS_ANGR and _MOCK_BIN), reason="needs angr installed and a binary"
)
def test_angr_cfg_error_is_error_and_uncached(monkeypatch, tmp_path):
    """A failing angr pass (Ghidra absent) is ERROR, empty, and uncached."""
    from supwngo.core.database import Database
    import supwngo.analysis._angr_subprocess as angr_sub

    _patch_no_ghidra(monkeypatch)

    def boom(path, op, seconds, **k):
        raise angr_sub.AngrSubprocessError("cfg blew up")

    monkeypatch.setattr(angr_sub, "run_angr_op", boom)
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.ERROR
    assert report.backend == "angr"
    assert report.candidates == ()
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@pytest.mark.skipif(
    not (_HAS_ANGR and _MOCK_BIN), reason="needs angr installed and a binary"
)
def test_angr_cfg_timeout_is_timeout_and_uncached(monkeypatch, tmp_path):
    """An angr pass that exceeds its budget (Ghidra absent) is TIMEOUT, uncached."""
    from supwngo.core.database import Database
    import supwngo.analysis._angr_subprocess as angr_sub

    _patch_no_ghidra(monkeypatch)

    def slow(path, op, seconds, **k):
        raise angr_sub.AnalysisBudgetExceeded("cfg exceeded budget")

    monkeypatch.setattr(angr_sub, "run_angr_op", slow)
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)

    assert report.status is payoff.PayoffStatus.TIMEOUT
    assert report.backend == "angr"
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@pytest.mark.skipif(
    not (_HAS_ANGR and _PAYOFF_ENTRIES),
    reason="needs angr installed and the dev corpus built",
)
def test_angr_only_real_pass_is_degraded_never_authoritative(monkeypatch, tmp_path):
    """End-to-end with REAL angr and Ghidra forced absent: a parseable binary
    yields DEGRADED (never COMPLETE, never a top-1), empty candidates, and is
    not cached -- the W-1 gate can never be met on angr."""
    from supwngo.core.database import Database

    _patch_no_ghidra(monkeypatch)
    bin_path = str(_bin_for(_PAYOFF_ENTRIES[0]))
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(bin_path, db=db)

    assert report.status is payoff.PayoffStatus.DEGRADED
    assert report.backend == "angr"
    assert report.candidates == ()
    assert db.get_payoff_analysis(*_key(bin_path)) is None
    reasons = [a["reason"] for a in report.attempts if a["backend"] == "angr"]
    assert reasons and "binary parsed" in reasons[0]


# ---------------------------------------------------------------------------
# T14a (design doc 2026-11-13-w2-required-args-design.md, Rev 11, §7 step 2):
# an always-run, Ghidra-free pure-Python mirror of the parity seam
# SupwngoPayoff.java's flipParity/edgeMeansEqual implement. It exists purely as
# a spec change-detector: the expected column below is written by hand from
# design §2.2's "edge XOR negateParity==1 XOR cmpOp==INT_NOTEQUAL" rule, not
# derived from the mirror function itself, so an unintentional drift in either
# the Java's XOR semantics or this mirror's reimplementation of them shows up
# here in milliseconds -- well before the slow, gated real-Ghidra T14b
# self-test (SupwngoPayoffSelfTest.java, driven by test_w2_self_test_parity_
# seam_passes_in_real_ghidra below) would catch it.
# ---------------------------------------------------------------------------


def _mirror_flip_parity(parity):
    """Pure-Python mirror of SupwngoPayoff.flipParity: one parity flip."""
    return parity ^ 1


def _mirror_edge_means_equal(is_true_edge, negate_parity, cmp_is_notequal):
    """Pure-Python mirror of SupwngoPayoff.edgeMeansEqual: whether traversing
    the given edge implies the gated parameter equals the compared constant."""
    return bool(is_true_edge) ^ (negate_parity == 1) ^ bool(cmp_is_notequal)


# (is_true_edge, negate_parity, cmp_is_notequal, expected) -- all 2x2x2 = 8
# combinations of {op} x {parity} x {edge}.
_EDGE_MEANS_EQUAL_CASES = [
    (True, 0, False, True),
    (True, 0, True, False),
    (True, 1, False, False),
    (True, 1, True, True),
    (False, 0, False, False),
    (False, 0, True, True),
    (False, 1, False, True),
    (False, 1, True, False),
]


@pytest.mark.parametrize(
    "is_true_edge,negate_parity,cmp_is_notequal,expected", _EDGE_MEANS_EQUAL_CASES
)
def test_edge_means_equal_mirror_matches_design_truth_table(
    is_true_edge, negate_parity, cmp_is_notequal, expected
):
    assert (
        _mirror_edge_means_equal(is_true_edge, negate_parity, cmp_is_notequal)
        == expected
    )


def test_flip_parity_mirror_round_trips_0_1_0():
    """flipParity(0) -> 1 -> 0: one BOOL_NEGATE flips parity, two cancel."""
    assert _mirror_flip_parity(0) == 1
    assert _mirror_flip_parity(_mirror_flip_parity(0)) == 0


# =========================================================================== #
# W-2 Step 3 -- Python model (design 2026-11-13-w2-required-args-design.md,
# Rev 11, sec 4 + sec 6 T7-T10): RequiredArg, the cross-field validator, the
# args fields on FunctionEvidence/PayoffEvidence, cache envelope v2 and the
# required_args_for/required_arg_regs accessors. All always-run (mock/unit).
# Attribute access goes through ``payoff.`` so a RED run fails per test rather
# than at collection.
# =========================================================================== #

# sec 2.2 reason precedence, highest first -- written out by hand from the
# design, not derived from the module under test.
_DESIGN_REASON_ORDER = (
    "irreducible_cflow",
    "analysis_exception",
    "conflict",
    "abi_class",
    "bool_compose",
    "bool_fanout",
    "ambiguous_gate",
    "nonconst_gate",
    "avoidance_gate",
    "relational_gate",
    "unresolved_gate",
)

# benchmark/gen/payoff/payoff_source.py CONST_RANGE = (0x1000, 0x7FFFFFFF)
_CONST_RANGE_MAX = 0x7FFFFFFF


def _ra_kwargs(**over):
    """Kwargs for a valid sec 2.4 RequiredArg (arg1 of the e2e fixture shape)."""
    kw = dict(
        position=1,
        value=0x1111,
        slot=0,
        width_bits=64,
        src_width_bits=64,
        terminal="HighParam",
        reg="rdi",
        op="INT_EQUAL",
        op_addr=0x401216,
        sink_addrs=(0x401251,),
        transform=(),
    )
    kw.update(over)
    return kw


def _ra(**over):
    return payoff.RequiredArg(**_ra_kwargs(**over))


def _ra_json(**over):
    """The same arg as the extractor's JSON object (lists, not tuples)."""
    kw = _ra_kwargs(**over)
    for k in ("sink_addrs", "transform"):
        if isinstance(kw[k], tuple):
            kw[k] = list(kw[k])
    return kw


def _arg2(**over):
    base = dict(
        position=2,
        value=0x2222,
        slot=1,
        width_bits=32,
        src_width_bits=32,
        reg="rsi",
        op_addr=0x401226,
        sink_addrs=(0x401251, 0x401260),
        transform=("COPY", "INT_SEXT"),
    )
    base.update(over)
    return base


# (id, overrides) -- each is individually invalid per sec 4's RequiredArg list.
_BAD_ARG_OVERRIDES = [
    ("position_zero", dict(position=0)),
    ("slot_negative", dict(position=0, slot=-1)),
    ("position_ne_slot_plus_1", dict(position=2, slot=0)),
    ("width_zero", dict(width_bits=0)),
    ("width_negative", dict(width_bits=-64)),
    ("width_is_bytes_not_bits", dict(width_bits=4)),
    ("src_width_zero", dict(src_width_bits=0)),
    ("src_width_is_bytes_not_bits", dict(src_width_bits=4)),
    ("op_relational", dict(op="INT_LESS")),
    ("op_not_str", dict(op=None)),
    ("reg_xmm", dict(reg="xmm0")),
    ("reg_none", dict(reg=None)),
    ("reg_subregister", dict(reg="edi")),
    ("reg_uppercase", dict(reg="RDI")),
    ("sink_addrs_empty", dict(sink_addrs=())),
    ("sink_addrs_negative", dict(sink_addrs=(-1,))),
    ("sink_addrs_not_int", dict(sink_addrs=("0x401251",))),
    ("op_addr_negative", dict(op_addr=-1)),
    ("terminal_not_highparam", dict(terminal="HighLocal")),
    ("transform_not_value_preserving", dict(transform=("COPY", "BOOL_NEGATE"))),
    ("transform_not_str", dict(transform=(1,))),
    ("value_float", dict(value=1.5)),
    ("value_str", dict(value="4369")),
    # bool is an int subclass: True/False would pass every range check below,
    # so only the explicit bool rejection (the W-1 guard) catches these.
    ("bool_position", dict(position=True)),
    ("bool_value", dict(value=True)),
    ("bool_slot", dict(slot=False)),
    ("bool_width_bits", dict(width_bits=True)),
    ("bool_src_width_bits", dict(src_width_bits=True)),
    ("bool_op_addr", dict(op_addr=True)),
    ("bool_sink_addr", dict(sink_addrs=(True,))),
]


def test_required_arg_valid_baseline_constructs_and_is_frozen():
    a = _ra()
    assert (a.position, a.value, a.slot, a.reg) == (1, 0x1111, 0, "rdi")
    assert a.sink_addrs == (0x401251,) and a.transform == ()
    with pytest.raises(Exception):  # frozen dataclass
        a.value = 2  # type: ignore[misc]


@pytest.mark.parametrize("over", [o for _, o in _BAD_ARG_OVERRIDES],
                         ids=[i for i, _ in _BAD_ARG_OVERRIDES])
def test_t7_required_arg_rejects_malformed_with_valueerror(over):
    """ValueError specifically -- never a bare ``assert`` (AssertionError is not
    in the envelope try's except tuple, so it would escape rank_payoffs)."""
    with pytest.raises(ValueError):
        _ra(**over)


@pytest.mark.parametrize("nbytes", [1, 2, 4, 8])
def test_t8_provenance_widths_are_bits_eight_times_byte_size(nbytes):
    a = _ra(width_bits=8 * nbytes, src_width_bits=8 * nbytes, value=0xFF)
    assert a.width_bits == 8 * nbytes and a.src_width_bits == 8 * nbytes


def test_t7_cross_field_validator_accepts_the_valid_shapes():
    v = payoff._validate_required_args
    assert v("known", None, ()) is None
    assert v("known", None, (_ra(), _ra(**_arg2()))) is None
    for reason in _DESIGN_REASON_ORDER:
        assert v("unknown", reason, ()) is None


_BAD_CROSS_FIELD = [
    ("unknown_nonempty", ("unknown", "unresolved_gate", lambda: (_ra(),))),
    ("unknown_reason_none", ("unknown", None, lambda: ())),
    ("unknown_reason_empty", ("unknown", "", lambda: ())),
    ("unknown_reason_unlisted", ("unknown", "made_up_reason", lambda: ())),
    ("known_with_reason", ("known", "unresolved_gate", lambda: ())),
    ("status_invalid", ("maybe", None, lambda: ())),
    ("status_none", (None, None, lambda: ())),
    ("duplicate_position", ("known", None, lambda: (_ra(), _ra()))),
    ("same_slot_value_conflict",
     ("known", None, lambda: (_ra(), _ra(value=0x9999)))),
    ("element_not_required_arg", ("known", None, lambda: ({"position": 1},))),
    ("args_not_tuple", ("known", None, lambda: [_ra()])),
]


@pytest.mark.parametrize("case", [c for _, c in _BAD_CROSS_FIELD],
                         ids=[i for i, _ in _BAD_CROSS_FIELD])
def test_t7_cross_field_validator_raises_valueerror(case):
    status, reason, make_args = case
    with pytest.raises(ValueError):
        payoff._validate_required_args(status, reason, make_args())


def test_t7_function_evidence_post_init_enforces_the_invariant():
    ok = payoff.FunctionEvidence(rva=1, name=None)  # defaults stay W-1 compatible
    assert ok.required_args == () and ok.args_status == "known"
    assert ok.args_reason is None
    good = payoff.FunctionEvidence(
        rva=1, name=None, required_args=(_ra(),), args_status="known"
    )
    assert good.required_args[0].value == 0x1111
    with pytest.raises(ValueError):
        payoff.FunctionEvidence(
            rva=1, name=None, args_status="unknown", args_reason=None
        )
    with pytest.raises(ValueError):
        payoff.FunctionEvidence(
            rva=1, name=None, required_args=(_ra(), _ra()), args_status="known"
        )
    with pytest.raises(ValueError):
        payoff.FunctionEvidence(
            rva=1,
            name=None,
            required_args=(_ra(),),
            args_status="unknown",
            args_reason="unresolved_gate",
        )


def test_score_function_passes_args_through_to_payoff_evidence():
    fe = payoff.FunctionEvidence(
        rva=0x1234,
        name="win",
        sinks=(SinkObservation("system", _const("/bin/sh")),),
        unreferenced=True,
        required_args=(_ra(), _ra(**_arg2())),
        args_status="known",
    )
    ev = score_function(fe)
    assert ev.required_args == fe.required_args
    assert (ev.args_status, ev.args_reason) == ("known", None)
    (cand,) = rank_candidates([fe])
    # candidate reads the evidence through
    assert cand.required_args == fe.required_args
    assert cand.args_status == "known" and cand.args_reason is None

    fu = payoff.FunctionEvidence(
        rva=0x1234,
        name="win",
        sinks=(SinkObservation("system", _const("/bin/sh")),),
        args_status="unknown",
        args_reason="relational_gate",
    )
    (cu,) = rank_candidates([fu])
    assert (cu.args_status, cu.args_reason, cu.required_args) == (
        "unknown",
        "relational_gate",
        (),
    )


def test_args_do_not_change_ranking_or_score():
    base = _payoff_exec()
    with_args = payoff.FunctionEvidence(
        rva=base.rva,
        name=base.name,
        sinks=base.sinks,
        unreferenced=base.unreferenced,
        required_args=(_ra(),),
    )
    a, b = score_function(base), score_function(with_args)
    assert (a.rank_key, a.score, a.atoms) == (b.rank_key, b.score, b.atoms)


def test_versions_are_bumped_for_w2():
    assert payoff.SCRIPT_VERSION == "w2.0"
    assert payoff.CACHE_ENVELOPE_VERSION == 2


def test_t10_reason_precedence_constant_matches_design_and_java_source():
    """The Python closed set/order is the design's sec 2.2 order AND the Java
    extractor's REASON_PRECEDENCE (a cross-language change-detector)."""
    import re

    assert tuple(payoff.ARGS_REASON_PRECEDENCE) == _DESIGN_REASON_ORDER
    java = (
        Path(payoff.__file__).parent / "ghidra_scripts" / "SupwngoPayoff.java"
    ).read_text(encoding="utf-8")
    m = re.search(r"REASON_PRECEDENCE\s*=\s*Arrays\.asList\((.*?)\);", java, re.S)
    assert m, "REASON_PRECEDENCE not found in SupwngoPayoff.java"
    assert tuple(re.findall(r'"([a-z_]+)"', m.group(1))) == _DESIGN_REASON_ORDER
    sv = re.search(r'SCRIPT_VERSION\s*=\s*"([^"]+)"', java)
    assert sv and sv.group(1) == payoff.SCRIPT_VERSION
    regs = re.search(r"SYSV_INT_BASE_REGS\s*=\s*setOf\((.*?)\);", java, re.S)
    assert regs
    assert {r.lower() for r in re.findall(r'"(\w+)"', regs.group(1))} == set(
        payoff._SYSV_INT_BASE_REGS
    )


def test_t10_abi_class_outranks_unresolved_gate_in_the_ordering():
    order = payoff.ARGS_REASON_PRECEDENCE
    assert order.index("abi_class") < order.index("unresolved_gate")
    assert order.index("irreducible_cflow") == 0
    assert order.index("unresolved_gate") == len(order) - 1


# ---- envelope path (live): rank_payoffs through the mocked extractor ----------


def _win_env(mutate=None):
    """The mock envelope as a dict, with ``mutate(win_record)`` applied."""
    env = json.loads(_envelope())
    if mutate is not None:
        mutate(env["records"][1])
    return env


def _set_args(status="known", reason=None, args=()):
    def apply(rec):
        rec["args_status"] = status
        rec["args_reason"] = reason
        rec["required_args"] = list(args)

    return apply


def _arg_over(**over):
    return _set_args(args=[_ra_json(**over)])


def _drop(key):
    return lambda rec: rec.pop(key)


def _bad_arg_dict_missing_reg(rec):
    arg = _ra_json()
    arg.pop("reg")
    _set_args(args=[arg])(rec)


_BAD_ENVELOPE_RECORDS = (
    [(f"arg_{i}", _arg_over(**o)) for i, o in _BAD_ARG_OVERRIDES]
    + [
        ("dup_position", _set_args(args=[_ra_json(), _ra_json()])),
        ("same_slot_conflict", _set_args(args=[_ra_json(), _ra_json(value=0x9)])),
        ("unknown_nonempty",
         _set_args("unknown", "unresolved_gate", [_ra_json()])),
        ("unknown_missing_reason", _set_args("unknown", None, [])),
        ("unknown_unlisted_reason", _set_args("unknown", "no_such_reason", [])),
        ("known_with_reason", _set_args("known", "unresolved_gate", [])),
        ("status_invalid", _set_args("maybe", None, [])),
        ("missing_args_status", _drop("args_status")),
        ("missing_args_reason", _drop("args_reason")),
        ("missing_required_args", _drop("required_args")),
        ("required_args_not_list",
         lambda rec: rec.update(required_args={"position": 1})),
        ("required_args_elem_not_dict",
         lambda rec: rec.update(required_args=[7])),
        ("arg_missing_key", _bad_arg_dict_missing_reg),
    ]
)


@skip_no_bin
@pytest.mark.parametrize("mutate", [m for _, m in _BAD_ENVELOPE_RECORDS],
                         ids=[i for i, _ in _BAD_ENVELOPE_RECORDS])
def test_t7_malformed_envelope_record_is_error_not_raised(monkeypatch, mutate):
    _patch_extractor(monkeypatch, envelope=json.dumps(_win_env(mutate)))
    # use_cache=False: no sqlite fsync per case; the never-cached property is
    # asserted once, DB-backed, in the next test.
    report = payoff.rank_payoffs(_MOCK_BIN, use_cache=False)  # must not raise
    assert report.status is PayoffStatus.ERROR
    assert report.candidates == ()
    assert "malformed record" in report.attempts[-1]["reason"]


@skip_no_bin
def test_t7_malformed_envelope_record_is_never_cached(monkeypatch, tmp_path):
    _patch_extractor(
        monkeypatch, envelope=json.dumps(_win_env(_set_args("unknown", None, [])))
    )
    db = Database(db_path=str(tmp_path / "c.db"))
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)
    assert report.status is PayoffStatus.ERROR
    assert db.get_payoff_analysis(*_key(_MOCK_BIN)) is None


@skip_no_bin
def test_t7_valid_args_record_is_complete_and_yields_the_args(monkeypatch):
    """The control for the malformed matrix above: the same shape, valid."""
    arg2 = _arg2()
    _patch_extractor(
        monkeypatch,
        envelope=json.dumps(
            _win_env(_set_args(args=[_ra_json(), _ra_json(**arg2)]))
        ),
    )
    report = payoff.rank_payoffs(_MOCK_BIN, use_cache=False)
    assert report.status is PayoffStatus.COMPLETE
    (cand,) = report.candidates
    assert cand.rva == 0x1234
    assert cand.required_args == (_ra(), _ra(**arg2))
    assert cand.args_status == "known" and cand.args_reason is None


# ---- cache path: report_from_json builds PayoffEvidence directly --------------


def _args_report(status="known", reason=None, args=None):
    if args is None and status == "known":
        args = (_ra(), _ra(**_arg2()))
    ev = payoff.PayoffEvidence(
        atoms=(ATOM_EXEC_CONST, ATOM_UNREFERENCED),
        sink_api="system",
        target=TargetTrace(TargetTrace.CONST_STRING, address=0x402000, value="/bin/sh"),
        rank_key=(1, 1),
        score=110,
        required_args=tuple(args or ()),
        args_status=status,
        args_reason=reason,
    )
    return PayoffReport(
        status=PayoffStatus.COMPLETE,
        candidates=(PayoffCandidate(rva=0x1234, name="win", evidence=ev),),
        backend="ghidra",
        attempts=(),
        counts={"enumerated": 2, "analyzed": 2, "failed": 0},
        elapsed_s=1.0,
        budget_s=180.0,
        from_cache=False,
    )


def _mutated_cache_text(mutate, report=None):
    d = json.loads(report_to_json(report or _args_report()))
    mutate(d["report"]["candidates"][0]["evidence"], d)
    return json.dumps(d)


def _cache_set(**kv):
    return lambda ev, d: ev.update(kv)


def _cache_arg(index, **kv):
    return lambda ev, d: ev["required_args"][index].update(kv)


_BAD_CACHE_ROWS = [
    ("bad_op", _cache_arg(0, op="INT_LESS")),
    ("bad_reg", _cache_arg(0, reg="xmm0")),
    ("bad_terminal", _cache_arg(0, terminal="HighLocal")),
    ("bool_op_addr", _cache_arg(0, op_addr=True)),
    ("position_ne_slot_plus_1", _cache_arg(0, position=3)),
    ("empty_sink_addrs", _cache_arg(0, sink_addrs=[])),
    # cross-field breaches that bypass FunctionEvidence entirely:
    ("same_position_twice",
     lambda ev, d: ev.update(required_args=[ev["required_args"][0]] * 2)),
    ("same_slot_value_conflict",
     lambda ev, d: ev["required_args"].append(
         dict(ev["required_args"][0], value=0x7777))),
    ("unknown_with_nonempty_list",
     _cache_set(args_status="unknown", args_reason="unresolved_gate")),
    ("unknown_without_reason", _cache_set(args_status="unknown", args_reason=None,
                                          required_args=[])),
    ("known_with_reason", _cache_set(args_reason="unresolved_gate")),
    ("missing_args_status", lambda ev, d: ev.pop("args_status")),
    ("missing_required_args", lambda ev, d: ev.pop("required_args")),
    ("v1_envelope", lambda ev, d: d.update(envelope_version=1)),
]


def test_t7_cache_control_unmutated_row_parses():
    back = report_from_json(report_to_json(_args_report()))
    assert back is not None
    assert back.candidates[0].required_args == (_ra(), _ra(**_arg2()))


@pytest.mark.parametrize("mutate", [m for _, m in _BAD_CACHE_ROWS],
                         ids=[i for i, _ in _BAD_CACHE_ROWS])
def test_t7_malformed_cache_row_is_a_miss_never_error_or_hit(mutate):
    assert report_from_json(_mutated_cache_text(mutate)) is None


@skip_no_bin
def test_t7_malformed_cache_row_misses_then_reruns_extractor(monkeypatch, tmp_path):
    """Through rank_payoffs: a poisoned cache row is a miss (extractor runs,
    COMPLETE result), not an ERROR and not a silently-wrong hit."""
    calls = []
    _patch_extractor(monkeypatch, counter=calls)
    db = Database(db_path=str(tmp_path / "c.db"))
    poisoned = _mutated_cache_text(_BAD_CACHE_ROWS[6][1])  # same position twice
    db.save_payoff_analysis(*_key(_MOCK_BIN), poisoned)
    report = payoff.rank_payoffs(_MOCK_BIN, db=db)
    assert report.status is PayoffStatus.COMPLETE
    assert report.from_cache is False
    assert len(calls) == 1


# ---- T9: cache round trip ------------------------------------------------------


def test_t9_roundtrip_preserves_args_with_full_provenance():
    rep = _args_report()
    back = report_from_json(report_to_json(rep))
    assert back is not None
    want = rep.candidates[0].evidence
    got = back.candidates[0].evidence
    assert got.required_args == want.required_args
    assert (got.args_status, got.args_reason) == ("known", None)
    a0, a1 = got.required_args
    assert a1.reg == "rsi" and a1.sink_addrs == (0x401251, 0x401260)
    assert a1.transform == ("COPY", "INT_SEXT")
    assert (a1.width_bits, a1.src_width_bits, a1.terminal) == (32, 32, "HighParam")
    assert a0.op == "INT_EQUAL" and a0.op_addr == 0x401216


def test_t9_roundtrip_preserves_unknown_reason_and_known_empty():
    unk = report_from_json(
        report_to_json(_args_report("unknown", "relational_gate", ()))
    )
    c = unk.candidates[0]
    assert (c.args_status, c.args_reason, c.required_args) == (
        "unknown",
        "relational_gate",
        (),
    )
    empty = report_from_json(report_to_json(_args_report("known", None, ())))
    c = empty.candidates[0]
    assert (c.args_status, c.args_reason, c.required_args) == ("known", None, ())


def test_t9_a_v1_row_misses():
    v1 = json.loads(report_to_json(_args_report()))
    v1["envelope_version"] = 1
    assert report_from_json(json.dumps(v1)) is None
    # a genuine W-1 shaped v1 row (no args fields at all) also misses
    legacy = json.loads(report_to_json(_sample_report()))
    legacy["envelope_version"] = 1
    for c in legacy["report"]["candidates"]:
        for k in ("args_status", "args_reason", "required_args"):
            c["evidence"].pop(k, None)
    assert report_from_json(json.dumps(legacy)) is None


@skip_no_bin
def test_t9_miss_then_hit_preserves_all_three_fields(monkeypatch, tmp_path):
    arg2 = _arg2()
    calls = []
    _patch_extractor(
        monkeypatch,
        counter=calls,
        envelope=json.dumps(_win_env(_set_args(args=[_ra_json(), _ra_json(**arg2)]))),
    )
    db = Database(db_path=str(tmp_path / "c.db"))
    r1 = payoff.rank_payoffs(_MOCK_BIN, db=db)
    r2 = payoff.rank_payoffs(_MOCK_BIN, db=db)
    assert len(calls) == 1
    assert r1.from_cache is False and r2.from_cache is True
    want = (_ra(), _ra(**arg2))
    for r in (r1, r2):
        (c,) = r.candidates
        assert c.required_args == want
        assert (c.args_status, c.args_reason) == ("known", None)


@skip_no_bin
def test_t9_unknown_survives_miss_then_hit(monkeypatch, tmp_path):
    calls = []
    _patch_extractor(
        monkeypatch,
        counter=calls,
        envelope=json.dumps(_win_env(_set_args("unknown", "avoidance_gate", []))),
    )
    db = Database(db_path=str(tmp_path / "c.db"))
    r1 = payoff.rank_payoffs(_MOCK_BIN, db=db)
    r2 = payoff.rank_payoffs(_MOCK_BIN, db=db)
    assert r2.from_cache is True and len(calls) == 1
    for r in (r1, r2):
        (c,) = r.candidates
        assert (c.args_status, c.args_reason, c.required_args) == (
            "unknown",
            "avoidance_gate",
            (),
        )


# ---- T10: every reason code round-trips exactly; report status is untouched ----


@skip_no_bin
@pytest.mark.parametrize("reason", _DESIGN_REASON_ORDER)
def test_t10_each_unknown_reason_is_carried_exactly_and_report_stays_complete(
    monkeypatch, reason
):
    """An args-pass failure (e.g. analysis_exception) is per-record: the report
    stays COMPLETE (only a *decompile* failure degrades it, tested below)."""
    _patch_extractor(
        monkeypatch,
        envelope=json.dumps(_win_env(_set_args("unknown", reason, []))),
    )
    report = payoff.rank_payoffs(_MOCK_BIN, use_cache=False)
    assert report.status is PayoffStatus.COMPLETE
    (c,) = report.candidates
    assert (c.args_status, c.args_reason, c.required_args) == ("unknown", reason, ())
    back = report_from_json(report_to_json(report))
    assert back.candidates[0].args_reason == reason


@skip_no_bin
def test_t10_decompile_failure_degrades_the_report_with_no_candidates(monkeypatch):
    """A W-1 decompile failure is failed>0 -> DEGRADED; the surviving record's
    args are not surfaced as an authoritative result."""
    env = _win_env(_set_args(args=[_ra_json()]))
    env.update(enumerated=3, analyzed=2, failed=1)
    _patch_extractor(monkeypatch, envelope=json.dumps(env))
    report = payoff.rank_payoffs(_MOCK_BIN, use_cache=False)
    assert report.status is PayoffStatus.DEGRADED
    assert report.candidates == ()


# ---- T8 (mock half): un-truncated 31-bit constants through both paths ---------


@skip_no_bin
@pytest.mark.parametrize("width", [32, 64])
def test_t8_const_range_value_is_reported_untruncated(monkeypatch, width):
    value = _CONST_RANGE_MAX
    arg = _ra_json(
        value=value,
        width_bits=width,
        src_width_bits=width,
        transform=["INT_SEXT"] if width == 32 else [],
    )
    _patch_extractor(
        monkeypatch, envelope=json.dumps(_win_env(_set_args(args=[arg])))
    )
    r1 = payoff.rank_payoffs(_MOCK_BIN, use_cache=False)
    r2 = report_from_json(report_to_json(r1))  # the cache half, no sqlite fsync
    assert r2 is not None and r2.from_cache is True
    for r in (r1, r2):
        a = r.candidates[0].required_args[0]
        assert a.value == value == 0x7FFFFFFF
        assert a.width_bits == width


# ---- required_args_for / required_arg_regs -------------------------------------


def _cand(rva, status="known", reason=None, args=()):
    ev = payoff.PayoffEvidence(
        atoms=(ATOM_EXEC_CONST,),
        sink_api="system",
        target=None,
        rank_key=(1, 1),
        score=110,
        required_args=tuple(args),
        args_status=status,
        args_reason=reason,
    )
    return PayoffCandidate(rva=rva, name=None, evidence=ev)


def _report_of(*cands, status=PayoffStatus.COMPLETE):
    return PayoffReport(status=status, candidates=tuple(cands), backend="ghidra")


def test_required_args_for_returns_position_value_pairs_for_known():
    rep = _report_of(_cand(0x10, args=(_ra(), _ra(**_arg2()))), _cand(0x20))
    assert payoff.required_args_for(rep) == ((1, 0x1111), (2, 0x2222))
    assert payoff.required_args_for(rep, rva=0x10) == ((1, 0x1111), (2, 0x2222))
    assert payoff.required_args_for(rep, rva=0x20) == ()  # known, empty


def test_required_arg_regs_exposes_the_recorded_register():
    rep = _report_of(_cand(0x10, args=(_ra(), _ra(**_arg2()))))
    assert payoff.required_arg_regs(rep) == ((1, "rdi"), (2, "rsi"))
    assert payoff.required_arg_regs(rep, rva=0x10) == ((1, "rdi"), (2, "rsi"))
    assert payoff.required_arg_regs(rep, rva=0x99) is None


def test_required_args_for_none_for_unknown_rva_miss_and_non_complete():
    unk = _report_of(_cand(0x10, "unknown", "unresolved_gate"))
    assert payoff.required_args_for(unk) is None
    assert payoff.required_arg_regs(unk) is None
    known = _report_of(_cand(0x10, args=(_ra(),)))
    assert payoff.required_args_for(known, rva=0x77) is None  # rva miss
    assert payoff.required_args_for(_report_of()) is None  # no candidates
    for status in (
        PayoffStatus.DEGRADED,
        PayoffStatus.TIMEOUT,
        PayoffStatus.ERROR,
        PayoffStatus.NO_BACKEND,
    ):
        rep = _report_of(_cand(0x10, args=(_ra(),)), status=status)
        assert payoff.required_args_for(rep) is None, status
        assert payoff.required_arg_regs(rep) is None, status
