"""Regression tests for I2b: the two `duration_sec` fields run_one() adds to
the harness's `autopwn_json_probe` and `autopwn_script_generation` wrappers.

Per docs/plans/2026-09-24-pipeline-instrumentation-pass.md §4 I2b: `elapsed =
time.time() - t0` at run_bench.py:949 spans TWO full pipeline invocations (the
--json probe and the -o script-generation run), so a single duration field
would misattribute a whole second pipeline run to "harness overhead". Both
wrappers need their own duration_sec, and each must be a live, differential
measurement rather than a constant stand-in (a hardcoded `duration_sec = 1.0`
must fail these tests, not just an absent field).

These are pure harness-logic tests: run_supwngo(), negative_control(),
inspect_generated_script() and independent_verify() are monkeypatched so no
real compilation or autopwn invocation happens. classify()/script_cheat_reason
are exercised for real (unmodified), matching the plan's §9.1 allowlist.
"""
import importlib.util
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_BENCH = REPO_ROOT / "benchmark" / "run_bench.py"


def _load_run_bench():
    spec = importlib.util.spec_from_file_location(
        "run_bench_duration_test", RUN_BENCH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_bench_duration_test"] = mod
    spec.loader.exec_module(mod)
    return mod


rb = pytest.importorskip("yaml") and _load_run_bench()

SLUG = "01_target"
CLEAN_AUDIT = {"present": True, "contains_flag_literal": False,
               "reads_flag_file_directly": False,
               "spawns_local_flag_reader": False,
               "scrapes_binary_with_tooling": False}
NO_FLAG = {"flag_found": False, "shell_proven": False, "ran": True}


def _make_corpus(tmp_path):
    root = tmp_path / "corpus"
    target_dir = root / SLUG
    target_dir.mkdir(parents=True)
    binary_name = rb.Corpus.binary_name(SLUG)
    (target_dir / binary_name).write_bytes(b"\x7fELF")
    (target_dir / "flag.txt").write_text("FLAG{" + "a" * 32 + "}")
    manifest = tmp_path / "corpus.yaml"
    manifest.write_text("targets: []\n")
    return rb.Corpus(root=root, manifest=manifest)


def _run_with_sleeps(monkeypatch, tmp_path, probe_sleep, scriptgen_sleep,
                     run_tag=""):
    """Run run_one() end-to-end with the pipeline invocation itself faked out
    by a controllable sleep, so probe vs script-generation cost is a known,
    live quantity rather than something we merely assert exists."""
    corpus = _make_corpus(tmp_path / f"run{run_tag}")
    target = {"slug": SLUG, "technique": "stack_shellcode", "difficulty": "easy",
              "protections": {}}

    monkeypatch.setattr(rb, "build_with_secret", lambda *a, **k: None)
    monkeypatch.setattr(
        rb, "negative_control",
        lambda *a, **k: {"flag_leaked_without_exploit": []})
    monkeypatch.setattr(
        rb, "inspect_generated_script", lambda *a, **k: dict(CLEAN_AUDIT))
    monkeypatch.setattr(
        rb, "independent_verify", lambda *a, **k: dict(NO_FLAG))

    def fake_run_supwngo(binary_abs, timeout, extra_args, tmpdir=None):
        if "--json" in extra_args:
            time.sleep(probe_sleep)
            return 0, '{"success": false, "attempts": []}', "", False
        time.sleep(scriptgen_sleep)
        return 0, "", "", False

    monkeypatch.setattr(rb, "run_supwngo", fake_run_supwngo)

    results_dir = tmp_path / f"results{run_tag}"
    results_dir.mkdir()
    return rb.run_one(corpus, target, timeout=5.0, results_dir=results_dir,
                      echo=False)


class TestDurationSecPresenceAndBounds:
    """§5 proof (a): present, non-zero, and less than the target's overall
    elapsed_sec -- for BOTH wrappers (M11)."""

    def test_probe_duration_present_nonzero_and_bounded(
            self, monkeypatch, tmp_path):
        result = _run_with_sleeps(monkeypatch, tmp_path,
                                  probe_sleep=0.15, scriptgen_sleep=0.15)
        probe = result["autopwn_json_probe"]
        assert "duration_sec" in probe
        assert probe["duration_sec"] > 0
        assert probe["duration_sec"] < result["elapsed_sec"], (
            "a single pipeline invocation must not consume the whole "
            "two-invocation elapsed_sec span")

    def test_script_generation_duration_present_nonzero_and_bounded(
            self, monkeypatch, tmp_path):
        result = _run_with_sleeps(monkeypatch, tmp_path,
                                  probe_sleep=0.15, scriptgen_sleep=0.15)
        gen = result["autopwn_script_generation"]
        assert "duration_sec" in gen
        assert gen["duration_sec"] > 0
        assert gen["duration_sec"] < result["elapsed_sec"], (
            "the script-generation invocation alone must not consume the "
            "whole two-invocation elapsed_sec span -- this is exactly M11's "
            "failure mode: one field cannot settle row 2")


class TestDurationSecIsLiveNotConstant:
    """§5 proof (b): a deliberately slowed invocation must move ITS OWN
    duration_sec and must NOT move the other wrapper's duration_sec. A
    constant-valued instrument (`duration_sec = 1.0` hardcoded) survives an
    absence check but fails this differential -- this is the mutation this
    project's signature defect looks like."""

    def test_slowing_the_probe_moves_only_the_probe_duration(
            self, monkeypatch, tmp_path):
        fast = _run_with_sleeps(monkeypatch, tmp_path,
                                probe_sleep=0.02, scriptgen_sleep=0.02,
                                run_tag="_fast")
        slow = _run_with_sleeps(monkeypatch, tmp_path,
                                probe_sleep=0.3, scriptgen_sleep=0.02,
                                run_tag="_slow")

        assert (slow["autopwn_json_probe"]["duration_sec"] >
                fast["autopwn_json_probe"]["duration_sec"]), (
            "a deliberately slowed probe must move its own duration_sec")
        assert abs(slow["autopwn_script_generation"]["duration_sec"] -
                  fast["autopwn_script_generation"]["duration_sec"]) < 0.2, (
            "slowing the probe must not move the OTHER wrapper's duration -- "
            "this is the M11 distinction: one field cannot report for both "
            "invocations")

    def test_slowing_script_generation_moves_only_that_duration(
            self, monkeypatch, tmp_path):
        fast = _run_with_sleeps(monkeypatch, tmp_path,
                                probe_sleep=0.02, scriptgen_sleep=0.02,
                                run_tag="_fast2")
        slow = _run_with_sleeps(monkeypatch, tmp_path,
                                probe_sleep=0.02, scriptgen_sleep=0.3,
                                run_tag="_slow2")

        assert (slow["autopwn_script_generation"]["duration_sec"] >
                fast["autopwn_script_generation"]["duration_sec"]), (
            "a deliberately slowed script-generation invocation must move "
            "its own duration_sec")
        assert abs(slow["autopwn_json_probe"]["duration_sec"] -
                  fast["autopwn_json_probe"]["duration_sec"]) < 0.2, (
            "slowing script generation must not move the probe's duration")
