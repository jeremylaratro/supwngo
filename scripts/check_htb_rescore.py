#!/usr/bin/env python3
"""Regression gate for the HTB solve column (directive W, W-6).

``scripts/htb_rescore.py`` records a JSON report of the canonical pipeline run
against the seven HTB challenges. This checker turns that report into a pass/fail
verdict so a gate -- not a human eyeballing stdout -- decides whether the solve
column still holds. It fails loudly on exactly the regressions the owner cares
about: fewer than all targets solved, any rep that did not prove a shell, any
timeout, any hard (harness) error, and -- when a budget is given -- any rep that
ran longer than the budget.

Two modes:

* ``--report PATH`` validates an existing report (used by the unit test and by a
  CI step that ingests a prior run).
* ``--run`` invokes ``scripts/htb_rescore.py`` itself, then validates the report
  it writes.

Exit status is the verdict: ``0`` all checks passed, ``2`` at least one failed
(every failure is printed, most important first), ``3`` the report could not be
read. The report schema is the one ``htb_rescore.main`` writes: a top-level
``score`` ``"<solved>/<targets>"``, ``reps`` count, ``hard_errors`` list, and a
``targets`` map of ``{verdict, reps:[{shell_proven, timed_out, hard_error,
elapsed_sec, ...}]}``.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
HTB_RESCORE = REPO / "scripts" / "htb_rescore.py"


class ReportError(Exception):
    """The report could not be read or is not the expected shape."""


def load_report(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text())
    except FileNotFoundError as exc:
        raise ReportError(f"report not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"report unreadable ({path}): {exc}") from exc
    if not isinstance(data, dict) or "targets" not in data or "score" not in data:
        raise ReportError(f"not an htb_rescore report: {path}")
    return data


def run_rescore(reps: int, timeout: int) -> dict[str, Any]:
    """Run ``htb_rescore`` and return the report it writes.

    The report path is read from the tool's ``report: <path>`` stdout line, so a
    changing timestamped filename is never guessed.
    """
    argv = [
        sys.executable,
        "-B",
        str(HTB_RESCORE),
        "--reps",
        str(reps),
        "--timeout",
        str(timeout),
    ]
    proc = subprocess.run(argv, cwd=str(REPO), capture_output=True, text=True)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    match = None
    for line in proc.stdout.splitlines():
        m = re.match(r"report:\s*(.+)$", line.strip())
        if m:
            match = m.group(1).strip()
    if not match:
        raise ReportError("htb_rescore printed no 'report:' path")
    return load_report(Path(match))


def check(
    report: dict[str, Any], *, reps: int, max_wall_sec: float | None
) -> list[str]:
    """Return the list of failures (empty means the gate passes)."""
    failures: list[str] = []
    targets = report.get("targets", {})
    n_targets = len(targets)

    # 1. Hard (harness) errors poison the whole run: a broken measurement must
    #    never read as a pass, whatever the score says.
    top_hard = report.get("hard_errors") or []
    rep_hard = [
        f"{slug} rep{i + 1}: {rep.get('hard_error')}"
        for slug, body in targets.items()
        for i, rep in enumerate(body.get("reps", []))
        if rep.get("hard_error")
    ]
    if top_hard or rep_hard:
        failures.append(
            "hard errors present: " + "; ".join(map(str, top_hard or rep_hard))
        )

    # 2. Any timeout.
    timed_out = [
        f"{slug} rep{i + 1}"
        for slug, body in targets.items()
        for i, rep in enumerate(body.get("reps", []))
        if rep.get("timed_out")
    ]
    if timed_out:
        failures.append("timeouts: " + ", ".join(timed_out))

    # 3. Perfect score: every target solved.
    score = report.get("score")
    expected_score = f"{n_targets}/{n_targets}"
    if score != expected_score:
        failures.append(f"score {score!r}, expected {expected_score!r}")

    # 4. Every rep of every target proved a shell. The denominator is
    #    reps x targets (21 for the default 3 x 7).
    total_reps = 0
    proven = 0
    short_reps = []
    for slug, body in targets.items():
        rs = body.get("reps", [])
        if len(rs) != reps:
            short_reps.append(f"{slug} has {len(rs)} reps, expected {reps}")
        for rep in rs:
            total_reps += 1
            if rep.get("shell_proven") is True:
                proven += 1
    if short_reps:
        failures.append("rep count: " + "; ".join(short_reps))
    expected_proven = reps * n_targets
    if proven != expected_proven or proven != total_reps:
        failures.append(
            f"shell_proven {proven}/{total_reps} "
            f"(expected {expected_proven}/{expected_proven})"
        )

    # 5. Wall-time budget, only when asked.
    if max_wall_sec is not None:
        slow = [
            f"{slug} rep{i + 1}={rep.get('elapsed_sec')}s"
            for slug, body in targets.items()
            for i, rep in enumerate(body.get("reps", []))
            if isinstance(rep.get("elapsed_sec"), (int, float))
            and rep["elapsed_sec"] > max_wall_sec
        ]
        if slow:
            failures.append(f"over wall budget {max_wall_sec}s: " + ", ".join(slow))

    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--report", type=Path, help="validate an existing report JSON")
    src.add_argument(
        "--run", action="store_true", help="run htb_rescore, then validate its report"
    )
    ap.add_argument("--reps", type=int, default=3, help="expected reps per target")
    ap.add_argument(
        "--timeout", type=int, default=300, help="per-rep timeout passed to --run"
    )
    ap.add_argument(
        "--max-wall-sec",
        type=float,
        default=None,
        help="fail if any rep ran longer than this (budget); off by default",
    )
    args = ap.parse_args()

    try:
        report = (
            run_rescore(args.reps, args.timeout)
            if args.run
            else load_report(args.report)
        )
    except ReportError as exc:
        print(f"CHECK ERROR: {exc}", file=sys.stderr)
        return 3

    failures = check(report, reps=args.reps, max_wall_sec=args.max_wall_sec)
    run = report.get("run", "?")
    if failures:
        print(f"FAIL htb_rescore gate (run {run}):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 2
    n = len(report.get("targets", {}))
    print(f"PASS htb_rescore gate (run {run}): {n}/{n}, {args.reps * n} shell_proven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
