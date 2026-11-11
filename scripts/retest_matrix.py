#!/usr/bin/env python3
"""Re-run the 26 SEP 2026 retest's analysis-command matrix and classify each cell.

    python3 scripts/retest_matrix.py                      # default 7 HTB binaries
    python3 scripts/retest_matrix.py --jobs 3 --timeout 60 --out benchmark/results_retest/<tag>

The original harness (`tests/htb-targets/run_all_commands.sh`, gitignored) ran
every command with `--json`, wrote stdout to a file, and a human read the files
to fill in `docs/reports/2026-09-26-comprehensive-feature-retest.md`. This
script does the same runs and classifies them mechanically, so a before/after
comparison uses one rule instead of two readings.

Only the analysis commands are run. The exploitation commands (autopwn, solve,
exploit, offset) are measured by `benchmark/` and `scripts/htb_rescore.py`.

CELL STATES
    OK        stdout parses as JSON and is not an error object
    ERROR     stdout parses as JSON and carries a top-level "error" key
    BAD_JSON  stdout is non-empty but does not parse as JSON
    EMPTY     the command exited and printed nothing
    TIMEOUT   killed at --timeout seconds
    MISSING   the binary path does not exist (the run is INCONCLUSIVE for it)

EXIT CODES
    0  every binary existed and every cell was classified
    2  at least one binary was MISSING -- the matrix is incomplete, not "worse"
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import time

_REPO = pathlib.Path(__file__).resolve().parent.parent
_HTB = _REPO / "tests" / "htb-targets" / "organized"

BINARIES = [
    "sick_rop",
    "rocket_blaster_xxx",
    "snow_scan",
    "auth-or-out",
    "sabotage",
    "bon-nie-appetit",
    "ancient_interface",
]

# The retest harness's BINARY_COMMANDS plus `pwn`, in its order.
COMMANDS = [
    "analyze",
    "checksec",
    "rop",
    "cfg",
    "dataflow",
    "strings-analysis",
    "heap-analysis",
    "integer-analysis",
    "imports",
    "addresses",
    "leaks",
    "report",
    "template",
    "decompile",
    "explain",
    "pwn",
]


def classify(stdout: str, timed_out: bool) -> str:
    if timed_out:
        return "TIMEOUT"
    text = stdout.strip()
    if not text:
        return "EMPTY"
    try:
        data = json.loads(text)
    except ValueError:
        return "BAD_JSON"
    if isinstance(data, dict) and "error" in data:
        return "ERROR"
    return "OK"


def run_cell(binary: pathlib.Path, command: str, timeout: float, out_dir: pathlib.Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    started = time.time()
    timed_out = False
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "supwngo.cli", command, str(binary), "--json"],
            capture_output=True,
            timeout=timeout,
            cwd=str(_REPO),
            env=env,
            start_new_session=True,
        )
        stdout = proc.stdout.decode(errors="replace")
        stderr = proc.stderr.decode(errors="replace")
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or b"").decode(errors="replace")
        stderr = (exc.stderr or b"").decode(errors="replace")
        rc = None
    elapsed = time.time() - started
    cell_dir = out_dir / binary.name
    cell_dir.mkdir(parents=True, exist_ok=True)
    (cell_dir / f"{command}.json").write_text(stdout)
    (cell_dir / f"{command}.stderr").write_text(stderr)
    return {
        "binary": binary.name,
        "command": command,
        "state": classify(stdout, timed_out),
        "rc": rc,
        "bytes": len(stdout.encode()),
        "elapsed": round(elapsed, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--out", type=pathlib.Path, default=None)
    ap.add_argument("--commands", nargs="*", default=COMMANDS)
    ap.add_argument("--binaries", nargs="*", default=BINARIES)
    args = ap.parse_args()

    out_dir = args.out or (_REPO / "benchmark" / "results_retest" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    out_dir.mkdir(parents=True, exist_ok=True)

    missing = [b for b in args.binaries if not (_HTB / b).exists()]
    present = [_HTB / b for b in args.binaries if (_HTB / b).exists()]

    cells: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(run_cell, b, c, args.timeout, out_dir) for b in present for c in args.commands]
        for fut in concurrent.futures.as_completed(futures):
            cells.append(fut.result())
    for b in missing:
        for c in args.commands:
            cells.append({"binary": b, "command": c, "state": "MISSING", "rc": None, "bytes": 0, "elapsed": 0.0})

    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=_REPO).stdout.strip()
    summary = {
        "head": head,
        "timeout": args.timeout,
        "jobs": args.jobs,
        "cells": sorted(cells, key=lambda r: (r["command"], r["binary"])),
    }
    (out_dir / "matrix.json").write_text(json.dumps(summary, indent=2))

    by = {(r["command"], r["binary"]): r for r in cells}
    width = max(len(b) for b in args.binaries)
    print(f"retest matrix  head={head}  timeout={args.timeout:.0f}s  jobs={args.jobs}  out={out_dir}")
    print(f"{'command':<18}" + "".join(f"{b[:width]:>{width + 2}}" for b in args.binaries))
    for c in args.commands:
        print(f"{c:<18}" + "".join(f"{by[(c, b)]['state']:>{width + 2}}" for b in args.binaries))
    ok = sum(1 for r in cells if r["state"] == "OK")
    print(f"OK cells: {ok}/{len(cells)}")
    if missing:
        print(f"INCONCLUSIVE: missing binaries {missing}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
