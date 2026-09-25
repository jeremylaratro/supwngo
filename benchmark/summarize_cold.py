#!/usr/bin/env python3
"""Per-target table + discovery-stall triage for a benchmark report.json.

Reports `solved` and `reliability` k/N side by side (neither is the answer alone --
best-of-N without the split is cherry-picking, a single rep understates), the
attribution witness class, and the pre-registered stub-rep count from
docs/reports/BENCHMARK-R2-COLD-24SEP2026.md section 1.5.

A rep is a STUB rep iff its generated script contains BOTH the
"no technique verified" template marker AND "offset = 0  # TODO". Both live in
report.json already, so this is decidable without re-executing anything.

Usage:  python3 benchmark/summarize_cold.py <report.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STUB_MARKERS = (
    "no technique verified",
    "offset = 0  # TODO",
)


def stub_reps(results_dir: Path, slug: str, n_reps: int) -> tuple[int, int]:
    """(stub_reps, scripts_found) for one target, read off the scripts on disk.

    report.json does NOT carry the per-rep generated script -- only a
    representative `autopwn_script_generation` record per target -- so per-rep stub
    detection reads `<results>/rep<N>/<slug>_generated.py` instead. Returning the
    number of scripts actually found keeps a missing script from masquerading as
    "not a stub": a rep with no script at all is not evidence of a real technique.
    """
    stubs = found = 0
    for rep in range(1, n_reps + 1):
        path = results_dir / f"rep{rep}" / f"{slug}_generated.py"
        if not path.is_file():
            continue
        found += 1
        text = path.read_text(errors="replace")
        if all(m in text for m in STUB_MARKERS):
            stubs += 1
    return stubs, found


def witness_class(reason: str) -> str:
    if "BEHAVIOURALLY ATTRIBUTED" in reason:
        return "ATTRIBUTED"
    if "UNWITNESSED" in reason:
        return "UNWITNESSED"
    return "-"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    report = Path(sys.argv[1])
    d = json.loads(report.read_text())
    results_dir = report.parent

    print(f"reps={d.get('reps')}  jobs={d.get('jobs')}  "
          f"timeout={d.get('timeout')}  strict={d.get('strict_attribution')}")
    print()
    hdr = (f"{'target':<34}{'diff':<8}{'status':<9}{'solved':<8}"
           f"{'k/N':<7}{'witness':<12}{'stubs':<8}{'outer_to':<9}")
    print(hdr)
    print("-" * len(hdr))

    n_success = n_full = n_interm = 0
    stubbed: list[tuple[str, int, int, int]] = []
    any_outer_timeout = False

    for t in d["results"]:
        attempts = t.get("attempts") or []
        k = sum(1 for a in attempts if a.get("status") == "SUCCESS")
        n = len(attempts)
        stubs, found = stub_reps(results_dir, t["slug"], n)
        solved = t["status"] == "SUCCESS"
        if solved:
            n_success += 1
            if k == n:
                n_full += 1
            else:
                n_interm += 1
        if stubs:
            stubbed.append((t["slug"], stubs, k, n))
        gen = t.get("autopwn_script_generation") or {}
        probe = t.get("autopwn_json_probe") or {}
        outer = bool(gen.get("wall_timed_out")) or bool(probe.get("wall_timed_out"))
        any_outer_timeout = any_outer_timeout or outer
        note = f"{stubs}/{found}" + ("" if found == n else f"!{n}")
        print(f"{t['slug']:<34}{t.get('difficulty','?'):<8}{t['status']:<9}"
              f"{str(solved):<8}{f'{k}/{n}':<7}"
              f"{witness_class(t.get('reason') or ''):<12}{note:<8}"
              f"{str(outer):<9}")

    total = len(d["results"])
    void = sum(1 for t in d["results"] if t["status"] == "VOID")
    print()
    print(f"PRIMARY  (5/5 reliability)     : {n_full}/{total - void}")
    print(f"SECONDARY(solved, >=1/5, expl.): {n_success}/{total - void}")
    print(f"intermittent successes         : {n_interm}")
    print(f"VOID (excluded)                : {void}")

    print()
    print("OUTER TRUNCATION: "
          + ("at least one autopwn invocation was killed by its wall clock -- "
             "the budget WAS binding somewhere"
             if any_outer_timeout else
             "none. Every autopwn invocation exited on its own within its budget, "
             "so no FAILED verdict is an outer-kill artifact."))
    print("  (Inner per-technique truncation remains NOT ruled out -- see the")
    print("   report's residual limits. This only rules out the outer kill.)")

    print()
    if not stubbed:
        print("DISCOVERY-STALL TRIAGE: not triggered -- 0 stub reps on any target.")
        print("  Per the pre-registered null-result commitment, this machinery is")
        print("  NOT repurposed for any other failure mode.")
    else:
        print("DISCOVERY-STALL TRIAGE: stub reps present")
        for slug, stubs, k, n in stubbed:
            if stubs == n and k == 0:
                cls = "discovery failure, cause undetermined"
            elif k >= 1:
                cls = "discovery-stall suspect (technique demonstrably works)"
            else:
                cls = "stall suspect, UNRESOLVED"
            print(f"  {slug:<34} stubs={stubs}/{n} credited={k}/{n}  -> {cls}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
