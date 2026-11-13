"""The HTB solve-column gate must pass a clean run and fail every regression.

``scripts/check_htb_rescore.py`` is the gate that lets a regression check -- not a
human reading stdout -- decide whether the seven-target solve column still holds.
These tests pin its contract: a perfect report passes, and each of the regressions
the owner named (6/7 score, 20/21 shell_proven, a timeout, a hard error, an
over-budget rep) fails with a non-zero exit. The Done-when for this W-0 piece is
exactly "the checker fails on a doctored report (6/7, 20/21, a timeout)"; the
hard-error and budget cases are the same gate's remaining columns.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_htb_rescore.py"

_spec = importlib.util.spec_from_file_location("check_htb_rescore", SCRIPT)
assert _spec and _spec.loader
check_htb_rescore = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_htb_rescore)

TARGETS = [
    "ancient_interface",
    "auth-or-out",
    "bon-nie-appetit",
    "rocket_blaster_xxx",
    "sabotage",
    "sick_rop",
    "snow_scan",
]


def good_report(*, reps: int = 3, elapsed: float = 5.0) -> dict:
    """A clean 7-target report: every rep a proven shell, no timeout, no error."""
    targets = {}
    for slug in TARGETS:
        targets[slug] = {
            "verdict": "SOLVED",
            "reps": [
                {
                    "slug": slug,
                    "elapsed_sec": elapsed,
                    "timed_out": False,
                    "returncode": 0,
                    "level": "SHELL_ACCESS",
                    "technique": "demo",
                    "secret_reproduced": True,
                    "shell_confirmed": True,
                    "shell_proven": True,
                    "echo_ambiguous": False,
                    "parse_error": False,
                    "hard_error": None,
                }
                for _ in range(reps)
            ],
        }
    return {
        "run": "20261113T000000Z",
        "reps": reps,
        "timeout": 300,
        "targets": targets,
        "solved": len(TARGETS),
        "score": f"{len(TARGETS)}/{len(TARGETS)}",
        "hard_errors": [],
    }


# --- check(): the clean report passes -------------------------------------


def test_good_report_passes():
    assert check_htb_rescore.check(good_report(), reps=3, max_wall_sec=None) == []


def test_good_report_passes_within_budget():
    rep = good_report(elapsed=5.0)
    assert check_htb_rescore.check(rep, reps=3, max_wall_sec=300.0) == []


# --- check(): each doctored variant fails ---------------------------------


def test_six_of_seven_fails():
    rep = good_report()
    # One target not solved: drop its score and mark the verdict.
    rep["solved"] = 6
    rep["score"] = "6/7"
    rep["targets"]["snow_scan"]["verdict"] = "NOT_SOLVED"
    for r in rep["targets"]["snow_scan"]["reps"]:
        r.update(
            shell_proven=False,
            shell_confirmed=False,
            secret_reproduced=False,
            level="CLAIMED_UNATTRIBUTED",
        )
    failures = check_htb_rescore.check(rep, reps=3, max_wall_sec=None)
    assert failures
    assert any("score" in f for f in failures)
    assert any("shell_proven" in f for f in failures)


def test_twenty_of_twentyone_fails():
    rep = good_report()
    # Score still perfect, but one single rep did not prove a shell.
    rep["targets"]["sick_rop"]["reps"][1]["shell_proven"] = False
    failures = check_htb_rescore.check(rep, reps=3, max_wall_sec=None)
    assert failures
    assert any("shell_proven 20/21" in f for f in failures)


def test_timeout_fails():
    rep = good_report()
    rep["targets"]["auth-or-out"]["reps"][0]["timed_out"] = True
    failures = check_htb_rescore.check(rep, reps=3, max_wall_sec=None)
    assert failures
    assert any("timeout" in f.lower() for f in failures)


def test_hard_error_toplevel_fails():
    rep = good_report()
    rep["hard_errors"] = ["sabotage: executor crashed"]
    failures = check_htb_rescore.check(rep, reps=3, max_wall_sec=None)
    assert any("hard error" in f.lower() for f in failures)


def test_hard_error_per_rep_fails():
    rep = good_report()
    rep["targets"]["sabotage"]["reps"][2]["hard_error"] = "parse failure"
    failures = check_htb_rescore.check(rep, reps=3, max_wall_sec=None)
    assert any("hard error" in f.lower() for f in failures)


def test_over_budget_rep_fails():
    rep = good_report(elapsed=5.0)
    rep["targets"]["bon-nie-appetit"]["reps"][0]["elapsed_sec"] = 450.0
    # Without a budget it passes; with one it must fail.
    assert check_htb_rescore.check(rep, reps=3, max_wall_sec=None) == []
    failures = check_htb_rescore.check(rep, reps=3, max_wall_sec=300.0)
    assert any("budget" in f.lower() for f in failures)


def test_short_rep_count_fails():
    rep = good_report(reps=3)
    rep["targets"]["snow_scan"]["reps"].pop()  # only 2 reps now
    failures = check_htb_rescore.check(rep, reps=3, max_wall_sec=None)
    assert any("rep count" in f.lower() for f in failures)


# --- CLI: exit codes via --report -----------------------------------------


def _run_cli(report_path: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--report", str(report_path), *extra],
        capture_output=True,
        text=True,
    )


def test_cli_passes_on_good_report(tmp_path):
    p = tmp_path / "good.json"
    p.write_text(json.dumps(good_report()))
    res = _run_cli(p)
    assert res.returncode == 0, res.stderr
    assert "PASS" in res.stdout


def test_cli_fails_on_doctored_report(tmp_path):
    rep = good_report()
    rep["score"] = "6/7"
    rep["targets"]["snow_scan"]["reps"][0]["shell_proven"] = False
    rep["targets"]["auth-or-out"]["reps"][0]["timed_out"] = True
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(rep))
    res = _run_cli(p)
    assert res.returncode == 2
    assert "FAIL" in res.stderr


def test_cli_errors_on_missing_report(tmp_path):
    res = _run_cli(tmp_path / "nope.json")
    assert res.returncode == 3
    assert "CHECK ERROR" in res.stderr


def test_cli_errors_on_non_report_json(tmp_path):
    p = tmp_path / "junk.json"
    p.write_text(json.dumps({"hello": "world"}))
    res = _run_cli(p)
    assert res.returncode == 3
