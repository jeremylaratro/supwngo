"""Tests for the W-1 payoff ranker (``supwngo.analysis.payoff``).

Commit 1 covers the address-normalization primitive: the corpus-truth RVA
convention ``rva = address - image_base`` across PIE, ET_EXEC and PE, and the
contrast with the link-time VADDR that ``_to_file_address`` yields (the bug the
primitive exists to prevent). These tests are load-free (no backend) and always
run; a corpus cross-check runs only when the dev corpus has been built.
"""

from __future__ import annotations

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
    """A real-shaped extractor envelope (mirrors SupwngoPayoff.java output)."""
    records = [
        {
            "address": 0x1000,
            "name": "main",
            "sinks": [],
            "has_read": False,
            "has_stdout_output": False,
            "unreferenced": False,
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
def test_jvm_user_home_override_reaches_runner_and_completes(monkeypatch, corpus_db):
    """End-to-end with REAL Ghidra: the per-call JVM ``user.home`` override is
    threaded all the way to ``proc.run``, and the pass completes on Ghidra (a
    silent degrade to a different backend would fail the backend assertion)."""
    need_ghidra()
    captured = {}
    real = Decompiler._run_ghidra_headless

    def spy(self, cmd, timeout, *, env=None):
        captured["env"] = env
        return real(self, cmd, timeout, env=env)

    monkeypatch.setattr(Decompiler, "_run_ghidra_headless", spy)
    report = payoff.rank_payoffs(str(_bin_for(_PAYOFF_ENTRIES[0])), db=corpus_db)

    assert report.status is payoff.PayoffStatus.COMPLETE
    assert report.backend == "ghidra"
    assert captured["env"] is not None
    assert "-Duser.home=" in captured["env"].get("JAVA_TOOL_OPTIONS", "")
