"""Proofs for benchmark/r1_technique_gate.py -- the R1 per-target technique-map gate.

Plan: docs/plans/2026-09-24-pipeline-instrumentation-pass.md (§2.1, §6 step 1, §9.1,
§9.2, and §5's "every instrument must be shown to report the negative").

This project's signature defect is validation that cannot fail. A gate that only ever
passes measures nothing, so these tests establish the gate can go RED for every distinct
failure shape it claims to catch, not just that it passes on good data:

  * positive control -- the gate PASSES against the real archived R1 report
  * a SWAP of two targets' expected techniques is caught (a multiset/count gate cannot
    see this; a per-target map is the only shape that can)
  * a MISSING target is caught, and the message names the missing slug
  * VOID LEAKAGE is caught if the by-name VOID exclusion is bypassed -- proving
    requirement 3 (exclude 11_heap_uaf_leak and 13_off_by_one BY NAME) is load-bearing,
    not incidentally true. 13_off_by_one is VOID but its structured technique field is
    still "ret2win", so a naive "every slug with a technique" filter yields 14 rows.

The archived artifact under test is benchmark/results/20260924-172232Z/report.json,
treated as read-only (other agents hold corpus_lock and may be running the harness
concurrently against other artifacts).
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "benchmark" / "r1_technique_gate.py"
REPORT = REPO_ROOT / "benchmark" / "results" / "20260924-172232Z" / "report.json"


def _load_gate():
    spec = importlib.util.spec_from_file_location("r1_technique_gate_under_test", GATE)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: the module's own @dataclass decorator resolves
    # annotations via sys.modules[cls.__module__], which requires the module
    # to already be registered (same fix as tests/test_bench_harness_soundness.py).
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


gate_mod = _load_gate()


def _real_results() -> list[dict]:
    data = json.loads(REPORT.read_text())
    return copy.deepcopy(data["results"])


def _drop(results: list[dict], slug: str) -> list[dict]:
    return [r for r in results if r["slug"] != slug]


def _technique_of(row: dict) -> str:
    return row["autopwn_json_probe"]["parsed"]["technique"]


def _set_technique(row: dict, technique: str) -> None:
    row["autopwn_json_probe"]["parsed"]["technique"] = technique


class TestPositiveControl:
    """The gate PASSES against the real archived R1 report, and asserts a
    13-row per-target map, not a count."""

    def test_real_r1_report_passes(self):
        result = gate_mod.gate(_real_results())
        assert result.ok, result.errors
        assert len(result.observed) == 13
        assert result.observed == gate_mod.EXPECTED_TECHNIQUE

    def test_the_map_has_exactly_13_rows_and_matches_plan_2_1(self):
        """Sanity on the constant itself: 15-target corpus minus the 2 VOID
        slugs, and 05 is pinned to canary_leak_ret2win per plan §2.1 point 2."""
        assert len(gate_mod.EXPECTED_TECHNIQUE) == 13
        assert gate_mod.VOID_SLUGS == {"11_heap_uaf_leak", "13_off_by_one"}
        assert gate_mod.EXPECTED_TECHNIQUE["05_fmtstr_arbread"] == "canary_leak_ret2win"

    def test_cli_exits_zero_on_the_real_report(self, capsys):
        rc = gate_mod.main([str(REPORT)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "PASS" in out
        assert "13/13" in out


class TestRedOnSwap:
    """A multiset/count gate cannot catch a swap between two targets' expected
    techniques. The per-target map must."""

    def test_swapping_two_targets_techniques_fails(self):
        results = _real_results()
        row_02 = next(r for r in results if r["slug"] == "02_ret2plt_system")
        row_03 = next(r for r in results if r["slug"] == "03_pie_leak_ret2libc")
        t02, t03 = _technique_of(row_02), _technique_of(row_03)
        assert t02 != t03, "fixture precondition: the two techniques must differ"

        _set_technique(row_02, t03)
        _set_technique(row_03, t02)

        result = gate_mod.gate(results)
        assert not result.ok
        # Count is unaffected by a swap -- a count-only gate would pass this.
        # The per-target map must still flag both mismatched rows by name.
        joined = "\n".join(result.errors)
        assert "02_ret2plt_system" in joined
        assert "03_pie_leak_ret2libc" in joined

    def test_a_count_only_check_would_have_missed_the_swap(self):
        """Demonstrates *why* a per-target map is required: the swap above
        leaves the credited count at exactly 13."""
        results = _real_results()
        row_02 = next(r for r in results if r["slug"] == "02_ret2plt_system")
        row_03 = next(r for r in results if r["slug"] == "03_pie_leak_ret2libc")
        t02, t03 = _technique_of(row_02), _technique_of(row_03)
        _set_technique(row_02, t03)
        _set_technique(row_03, t02)

        observed = gate_mod._observed_techniques(results)
        assert len(observed) == 13, "count alone is unchanged by a swap"


class TestRedOnMissingRow:
    def test_removing_one_expected_target_fails_and_names_it(self):
        results = _drop(_real_results(), "09_srop")
        result = gate_mod.gate(results)
        assert not result.ok
        assert any("09_srop" in err for err in result.errors), result.errors
        assert any("missing target" in err for err in result.errors), result.errors

    def test_cli_reports_failure_on_missing_row(self, tmp_path, capsys):
        results = _drop(_real_results(), "09_srop")
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"results": results}))
        rc = gate_mod.main([str(report_path)])
        assert rc == 1
        out = capsys.readouterr().out
        assert "FAIL" in out
        assert "09_srop" in out


class TestRedOnVoidLeakage:
    """Proves requirement 3 is actually enforced: if the by-name VOID
    exclusion is removed, 13_off_by_one's real technique ("ret2win") leaks
    into the observed set, yielding 14 rows instead of 13, and the gate must
    fail rather than pass vacuously."""

    def test_bypassing_the_void_exclusion_yields_14_rows_and_fails(self, monkeypatch):
        results = _real_results()

        # Confirm the fixture precondition the plan calls out explicitly:
        # 13_off_by_one is VOID yet still reports a technique.
        row_13 = next(r for r in results if r["slug"] == "13_off_by_one")
        assert row_13["status"] == "VOID"
        assert _technique_of(row_13) == "ret2win"

        monkeypatch.setattr(gate_mod, "VOID_SLUGS", frozenset())

        observed = gate_mod._observed_techniques(results)
        assert len(observed) == 14, (
            "with the VOID exclusion bypassed: 13 correct rows + "
            "13_off_by_one's leaked 'ret2win' = 14. 11_heap_uaf_leak still "
            "drops out on its own (technique is '', not a VOID-exclusion "
            "effect), which is exactly the '14, not 13' the plan names."
        )
        assert "13_off_by_one" in observed
        assert observed["13_off_by_one"] == "ret2win"

        result = gate_mod.gate(results)
        assert not result.ok, (
            "VOID leakage must fail the gate -- a 14-row observed set does not "
            "match the 13-row §2.1 map"
        )
        joined = "\n".join(result.errors)
        assert "13_off_by_one" in joined
        assert "14" in joined


class TestMutationGuard:
    """Structural guard against the gate itself being trivially satisfiable.

    Full mutation ('stub gate() to always return success and confirm every
    test above goes red') is run manually and reported in the task summary,
    since it requires editing the module under test in place. This test
    instead pins the shape any correct implementation must have: gate()
    must be sensitive to its `results` argument, not constant-valued.
    """

    def test_gate_result_is_not_constant_across_different_inputs(self):
        real = gate_mod.gate(_real_results())
        broken = gate_mod.gate(_drop(_real_results(), "09_srop"))
        assert real.ok != broken.ok
