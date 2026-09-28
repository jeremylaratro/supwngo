#!/usr/bin/env python3
"""Measure the canonical pipeline against one variation family.

WHY THIS EXISTS ALONGSIDE run_bench.py

`run_bench.py` is the scoring harness: it re-provisions every target with a fresh
per-run secret flag, runs negative controls, and refuses to publish a rate when
anything about the run is untrustworthy. It reads its target list from a MANIFEST,
and `--corpus-root` alone does not move the manifest -- point it at a variation
family without also passing that family's manifest and it will look for R1's
fifteen slugs, find none of them, and (correctly) withhold the score. That is the
harness working, not failing.

The variation families added since R1 are measured for a narrower question: does
the canonical pipeline, with the family's executor registered, reach a shell on
each variant and decline the negative control? That needs no flag provisioning and
no manifest -- just the real `autopwn` CLI against each binary in the directory.
This script asks exactly that question and nothing else.

It deliberately does NOT compute a success rate. It prints one row per target and
the raw counts, because the interesting output is per-target: which variant broke,
and whether the control stayed declined. A family where 5 of 6 positives solve and
the control also "solves" is worse than 3 of 6 with a clean control, and a single
percentage hides that.

Usage:
    python benchmark/measure_family.py benchmark/corpus_scanf [--timeout 400] [--jobs 3]

Convention for reading the output: a slug containing `_9` (90, 91, ...) is a
NEGATIVE CONTROL and is expected NOT to solve. The script applies that convention
to label rows and to decide the exit code, so a control that starts solving fails
the run loudly instead of quietly inflating a count.
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

#: Slug marker for a negative control. The corpora put controls at 90+.
CONTROL_MARKER = "_9"


def is_control(slug: str) -> bool:
    return CONTROL_MARKER in slug


def find_targets(root: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    """Every built ELF in the family, as (slug, path).

    A target directory holds `<slug>.c`, `cflags`, `flag.txt` and the built
    binary; the binary is the file named exactly like its directory.
    """
    out = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        binary = d / d.name
        if binary.is_file() and os.access(binary, os.X_OK):
            out.append((d.name, binary))
    return out


def run_one(slug: str, path: pathlib.Path, timeout: float) -> dict:
    """Run the real autopwn CLI, canonical-only, and summarise the outcome.

    `--no-legacy` matters: without it a solve could come from the legacy engine
    and be credited to a canonical executor that did nothing.
    """
    started = time.time()
    cmd = [
        sys.executable,
        "-m",
        "supwngo.cli",
        "autopwn",
        str(path),
        "--json",
        "--no-legacy",
        "--timeout",
        str(int(timeout)),
    ]
    # cwd is the TARGET's directory, not the repo root: a target with a relative
    # PT_INTERP (the HTB `sabotage` shape, `./glibc/ld-...`) only runs from beside
    # its own loader. But `supwngo` is not installed into site-packages -- it
    # imports because the repo root is on sys.path when that is the cwd -- so the
    # repo root has to be handed over explicitly via PYTHONPATH. Getting this
    # wrong produces a run where every target "fails" in 0.0s with no stdout,
    # which looks exactly like a pipeline that solves nothing.
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        str(repo_root) + os.pathsep + env["PYTHONPATH"]
        if env.get("PYTHONPATH")
        else str(repo_root)
    )
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 120,
            cwd=str(path.parent),
            env=env,
        )
        raw = proc.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return {
            "slug": slug,
            "control": is_control(slug),
            "outcome": "HARNESS_TIMEOUT",
            "technique": None,
            "level": None,
            "elapsed": round(time.time() - started, 1),
            "note": f"no result within {timeout + 120:.0f}s wall",
        }

    # The CLI prints human lines before the JSON in some paths; take the last
    # balanced object rather than assuming stdout is pure JSON.
    payload = None
    for start in range(len(raw)):
        if raw[start] != "{":
            continue
        try:
            payload = json.loads(raw[start:])
            break
        except json.JSONDecodeError:
            continue

    if payload is None:
        # Report STDERR here, not just stdout's last line. A missing-module or
        # bad-flag failure says nothing on stdout at all, so a stdout-only note
        # reads as "the pipeline found nothing" when the CLI never ran.
        err = proc.stderr.decode(errors="replace").strip()
        tail = (err.splitlines() or raw.strip().splitlines() or ["<no output>"])[-1]
        return {
            "slug": slug,
            "control": is_control(slug),
            "outcome": "NO_JSON",
            "technique": None,
            "level": None,
            "elapsed": round(time.time() - started, 1),
            "note": f"rc={proc.returncode} {tail[:240]}",
        }

    # Field names read off an actual `autopwn --json` payload rather than guessed.
    # The keys are: attempts, binary, binary_load, flag, handoff, interrupted,
    # legacy_fallback, payload_length, profile, prologue, success, technique,
    # verified. Two of them are easy to get wrong in ways that quietly mislead:
    #
    #   * there is no `verification_level`/`level` key -- it is `verified`;
    #   * `legacy_fallback` is a STRING, one of not_reached/disabled/
    #     skipped_vector/ran. Every one of those is truthy, so a plain
    #     `if payload["legacy_fallback"]` warns on the *healthy* case. Only "ran"
    #     means the legacy engine actually executed.
    return {
        "slug": slug,
        "control": is_control(slug),
        "outcome": "SUCCESS" if payload.get("success") else "NOT_SOLVED",
        "technique": payload.get("technique"),
        "verified": payload.get("verified"),
        "flag": bool(payload.get("flag")),
        "legacy_fallback": payload.get("legacy_fallback"),
        "legacy_ran": payload.get("legacy_fallback") == "ran",
        "elapsed": round(time.time() - started, 1),
    }


def solved(row: dict) -> bool:
    return row.get("outcome") == "SUCCESS"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", help="family directory, e.g. benchmark/corpus_scanf")
    ap.add_argument("--timeout", type=float, default=400.0)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--out", default=None, help="write the rows as JSON here too")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    targets = find_targets(root)
    if not targets:
        print(f"no built binaries under {root} -- build the family first", file=sys.stderr)
        return 2

    print(f"family: {root}")
    print(f"targets: {len(targets)}  jobs: {args.jobs}  per-target timeout: {args.timeout:.0f}s")
    print()

    rows: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(run_one, slug, path, args.timeout): slug
            for slug, path in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            row = fut.result()
            rows.append(row)
            tag = "CONTROL " if row["control"] else "positive"
            ok = solved(row)
            verdict = "SOLVED" if ok else "not solved"
            expected = (not ok) if row["control"] else ok
            print(
                f"  [{tag}] {row['slug']:<28} {verdict:<10} "
                f"{'PASS' if expected else 'FAIL'}  "
                f"technique={row.get('technique')} verified={row.get('verified')} "
                f"flag={row.get('flag')} [{row['elapsed']}s]"
            )
            if row.get("note"):
                print(f"      note: {row['note']}")
            if row.get("legacy_ran"):
                print("      !! the LEGACY engine ran despite --no-legacy -- this solve "
                      "is not attributable to a canonical executor")
            if solved(row) and row.get("verified") is False:
                print("      .. solved but verified=False -- candidate, not a proven solve")

    rows.sort(key=lambda r: r["slug"])
    positives = [r for r in rows if not r["control"]]
    controls = [r for r in rows if r["control"]]
    pos_ok = sum(1 for r in positives if solved(r))
    ctl_bad = [r["slug"] for r in controls if solved(r)]

    print()
    print(f"positives solved: {pos_ok}/{len(positives)}")
    print(f"controls: {len(controls)}, wrongly solved: {len(ctl_bad)}{' ' + str(ctl_bad) if ctl_bad else ''}")

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(rows, indent=2))
        print(f"rows written to {args.out}")

    # A solving control is a harness failure, not a partial result: it means the
    # family cannot distinguish the capability from doing nothing.
    if ctl_bad:
        print("\nFAIL -- a negative control solved; this family cannot attribute a solve")
        return 1
    if pos_ok != len(positives):
        print("\nINCOMPLETE -- not every positive solved (see rows above)")
        return 3
    print("\nALL OK -- every positive solved, every control declined")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
