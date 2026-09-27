#!/usr/bin/env python3
"""Re-score the canonical pipeline against the 7 HTB challenges (gate T-1).

Why this is not `benchmark/run_bench.py`: that harness rebuilds every target
with a fresh secret flag mid-run, and the per-run secret is the entire basis of
its attribution. HTB binaries have no source and no controllable flag, so there
is nothing for it to act on -- wrapping them would mean weakening attribution to
fit the targets. See docs/plans/2026-09-27-htb-rescore-and-variation-plan.md.

What this harness keeps from that one: the secret must POSTDATE the run. Each rep
copies the challenge directory to a fresh workspace and writes a random secret to
the flag path the binary names, so a captured flag cannot have come from anywhere
but this rep. Targets that ship a flag.txt get theirs REPLACED in the copy, so
none can be credited for echoing a value that was already on disk.

Success levels, in the order they are preferred:

  SHELL_ACCESS   a shell was confirmed. The only achievable level for the 5 of 7
                 targets that have no flag path compiled in at all.
  FLAG_CAPTURED  the per-rep secret was reproduced.

`--libc` is deliberately NOT passed: T-1 says "without legacy fallback", the
recorded 1/7 baseline did not pass it, and a solve that needs it measures the
operator rather than the tool.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ORGANIZED = REPO / "tests" / "htb-targets" / "organized"

#: The flag path a target opens, relative to its own directory, where one is
#: compiled in. Established by `strings` (measured 2026-09-27): only
#: rocket_blaster_xxx names one. Targets absent from this map are scored on
#: SHELL_ACCESS; a secret is still planted at the conventional path so that a
#: flag-reading path nobody predicted is still attributable rather than invisible.
FLAG_PATHS = {
    "rocket_blaster_xxx": "flag.txt",
}
DEFAULT_FLAG_PATH = "flag.txt"

DEFAULT_REPS = 3
DEFAULT_TIMEOUT = 300


def targets() -> dict[str, Path]:
    """slug -> resolved binary path, from the `organized/` symlink farm."""
    out = {}
    for link in sorted(ORGANIZED.iterdir()):
        real = link.resolve()
        if real.is_file():
            out[link.name] = real
    return out


def _plant_secret(workspace: Path, slug: str) -> str:
    """Write a fresh secret at the flag path and return it.

    Overwrites any shipped flag.txt. That is the point: a value already on disk
    before the run began proves nothing about this run.
    """
    secret = f"HTB{{{secrets.token_hex(16)}}}"
    rel = FLAG_PATHS.get(slug, DEFAULT_FLAG_PATH)
    path = workspace / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secret + "\n")
    return secret


def _find_receipt(obj, out: list[dict]) -> None:
    """Collect every verification receipt anywhere in the JSON."""
    if isinstance(obj, dict):
        if "level" in obj and "success" in obj and "technique" in obj:
            out.append(obj)
        for v in obj.values():
            _find_receipt(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _find_receipt(v, out)


def run_rep(slug: str, binary: Path, timeout: int) -> dict:
    """One rep in a throwaway copy of the challenge directory."""
    src_dir = binary.parent
    with tempfile.TemporaryDirectory(prefix=f"htb_{slug}_") as tmp:
        workspace = Path(tmp) / src_dir.name
        shutil.copytree(src_dir, workspace, symlinks=True)
        secret = _plant_secret(workspace, slug)
        target = workspace / binary.name
        target.chmod(0o755)

        started = time.time()
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "supwngo.cli", "solve",
                 str(target), "--json"],
                cwd=str(workspace),           # './flag.txt' is relative
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "PYTHONPATH": str(REPO)},
            )
            timed_out = False
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            rc = None
        elapsed = round(time.time() - started, 1)

        rep = {
            "slug": slug, "elapsed_sec": elapsed, "timed_out": timed_out,
            "returncode": rc, "level": None, "technique": None,
            "secret_reproduced": False, "shell_confirmed": False,
            "parse_error": None,
        }
        if timed_out:
            return rep

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            rep["parse_error"] = f"{e} | stdout[:200]={stdout[:200]!r}"
            return rep

        receipts: list[dict] = []
        _find_receipt(data, receipts)
        winning = [r for r in receipts if r.get("success")]

        # A captured flag counts ONLY if it is this rep's secret. Anything else
        # -- a stale file, a hardcoded string, a decoy -- is not this rep's
        # evidence and must not be credited.
        for r in winning:
            if r.get("flag") and secret in str(r.get("flag")):
                rep["secret_reproduced"] = True
            if r.get("shell_confirmed"):
                rep["shell_confirmed"] = True

        if winning:
            rep["technique"] = winning[0].get("technique")
        if rep["shell_confirmed"]:
            rep["level"] = "SHELL_ACCESS"
        elif rep["secret_reproduced"]:
            rep["level"] = "FLAG_CAPTURED"
        elif winning:
            # The pipeline claimed success but produced neither a shell nor this
            # rep's secret. Recorded as its own state rather than counted: an
            # unattributable success is exactly what must not inflate a score.
            rep["level"] = "CLAIMED_UNATTRIBUTED"
        return rep


def verdict(reps: list[dict]) -> str:
    """Three states. INCONCLUSIVE is not rounded in either direction."""
    counted = sum(1 for r in reps if r["level"] in ("SHELL_ACCESS", "FLAG_CAPTURED"))
    if counted >= 2:
        return "SOLVED"
    if counted == 1 or any(r["timed_out"] for r in reps):
        return "INCONCLUSIVE"
    return "NOT_SOLVED"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=DEFAULT_REPS)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--target", action="append", default=None,
                    help="slug to run; repeatable. Default: all.")
    ap.add_argument("--extra-binary", action="append", default=[],
                    help="path=slug, for validation controls outside the corpus")
    ap.add_argument("--only-extras", action="store_true",
                    help="skip the HTB targets entirely; run only --extra-binary. "
                         "Used to validate this harness against its own controls "
                         "before any HTB number is trusted.")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    tgts = {} if args.only_extras else targets()
    if args.target and not args.only_extras:
        missing = [t for t in args.target if t not in tgts]
        if missing:
            print(f"unknown target(s): {missing}; have {sorted(tgts)}", file=sys.stderr)
            return 2
        tgts = {k: v for k, v in tgts.items() if k in args.target}
    for spec in args.extra_binary:
        path, _, slug = spec.partition("=")
        tgts[slug or Path(path).name] = Path(path).resolve()

    stamp = time.strftime("%Y%m%d-%H%M%SZ", time.gmtime())
    results = {"run": stamp, "reps": args.reps, "timeout": args.timeout,
               "targets": {}}

    for slug, binary in tgts.items():
        reps = []
        for i in range(args.reps):
            rep = run_rep(slug, binary, args.timeout)
            reps.append(rep)
            print(f"  {slug} rep{i+1}: level={rep['level']} "
                  f"technique={rep['technique']} {rep['elapsed_sec']}s"
                  + (" TIMEOUT" if rep["timed_out"] else ""), flush=True)
        v = verdict(reps)
        results["targets"][slug] = {"verdict": v, "reps": reps}
        print(f"[{slug}] {v}", flush=True)

    solved = [s for s, r in results["targets"].items() if r["verdict"] == "SOLVED"]
    results["solved"] = sorted(solved)
    results["score"] = f"{len(solved)}/{len(results['targets'])}"
    print(f"\nSCORE {results['score']}  solved={results['solved']}")

    out = args.out or (REPO / "benchmark" / "results_htb" / f"{stamp}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"report: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
