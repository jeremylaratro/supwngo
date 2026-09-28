#!/usr/bin/env python3
"""Verify the coverage map's per-technique claims by running the real ladder.

    python3 scripts/coverage_sweep.py benchmark/corpus benchmark/corpus_r2
    python3 scripts/coverage_sweep.py benchmark/corpus --timeout 300 --jobs 4

WHY THIS EXISTS ALONGSIDE `benchmark/measure_family.py`
-------------------------------------------------------
`measure_family.py` asks a family question -- do all five positives solve and
does the `_9` control decline -- and it discovers targets by one rule: the
binary is *the file named exactly like its directory*
(`corpus_typeconf/tc_10_direct_tag_write/tc_10_direct_tag_write`). Every corpus
built since R1 follows that rule.

The two OLDEST corpora do not. `benchmark/corpus/13_off_by_one/` holds a binary
called `off_by_one`, and `benchmark/corpus_r2/08_int_mul_overflow/` holds
`int_mul_overflow` -- the directory carries an ordinal the binary does not. So
pointing `measure_family.py` at either one prints `no built binaries under ...`
and exits 2. That is the script being honest rather than broken, but the
practical effect is that **round 1's fifteen targets were the only ones in the
tree with no one-command way to re-measure them**, and those are exactly the
targets whose coverage rows sat at provenance `recorded` for months.

Measured while writing this script, and worse than the naming mismatch:
**14 of round 2's 15 targets are not built at all.** `benchmark/corpus_r2/`
carries every `.c` and `cflags` from 2026-09-25, but only `08_int_mul_overflow`
has an ELF beside it. The coverage map cites ten of those unbuilt directories as
evidence for eight separate rows, so those rows cannot have been measured and
cannot be measured now without running `benchmark/build_all_r2.sh` first. This
script reports what it finds rather than what a root is supposed to contain,
which is why the gap surfaced: run it on `benchmark/corpus_r2` and it discovers
one target, not fifteen.

`I-40` is what that cost. The coverage map listed `corpus_r2/08_int_mul_overflow`
under `int_truncation_bypass`; the binary contains no `scanf` at all, so that
gate cannot open, and forced past it the executor still fails at ANALYSIS. The
row asserted coverage of a target solved by *nothing*. One of one rows checked
was wrong. A corpus path printed beside a technique is not evidence the
technique solves it, and the only thing that converts it into evidence is a run.

So this script answers a different question from `measure_family.py`: for an
arbitrary set of corpus roots, **which technique actually solves each target,
and how long does it take** -- with no family shape assumed, no control
convention required, and no success rate computed. Comparing that to the map is
a human's job; printing it is this script's.

It deliberately reuses `measure_family.run_one` rather than reimplementing the
CLI invocation. That function already encodes three things that are easy to get
wrong and that produce believable-looking garbage when wrong: `--no-legacy` (so
a legacy-engine solve is not credited to a canonical executor), cwd set to the
TARGET's directory with PYTHONPATH pointed at the repo root (get this wrong and
every target "fails" in 0.0s with no stdout, which reads as a pipeline that
solves nothing), and reading `verified` rather than a guessed
`verification_level` key.

EXIT CODES -- three states, not two
    0  every discovered target ran and produced a verdict
    1  bad usage, or a root that does not exist
    2  nothing was discovered, or a directory was AMBIGUOUS -- refusing to
       print quotable rows rather than reporting a vacuous all-clear

Ambiguity is a refusal and not a guess on purpose. A directory holding two
executables has no single answer, and picking one by sort order would produce a
row indistinguishable from a measured one.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import os
import pathlib
import sys

_REPO = pathlib.Path(__file__).resolve().parent.parent

#: Names that live beside a target binary and are never the target itself.
_NON_TARGET = {"cflags", "flag.txt", "Makefile", "build.sh", "README.md"}


def _load_measure_family():
    """Import `benchmark/measure_family.py` by path.

    It is a script rather than a package module, so there is no import path to
    it. Loading by spec keeps this script from duplicating `run_one`, which is
    the part that must not drift: a second copy of the `--no-legacy` / cwd /
    PYTHONPATH handling is a second chance to get it wrong silently.
    """
    path = _REPO / "benchmark" / "measure_family.py"
    if not path.is_file():
        print(f"cannot find {path}", file=sys.stderr)
        raise SystemExit(1)
    spec = importlib.util.spec_from_file_location("_measure_family", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _is_elf(path: pathlib.Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def discover(root: pathlib.Path) -> tuple[list[tuple[str, pathlib.Path]], list[str]]:
    """``(targets, ambiguous)`` for one corpus root.

    Prefers `<dir>/<dir.name>` so a corpus that follows `measure_family.py`'s
    convention is discovered identically here. Falls back to "the one executable
    ELF in the directory" for the older corpora, and reports -- rather than
    resolves -- a directory holding more than one.
    """
    targets: list[tuple[str, pathlib.Path]] = []
    ambiguous: list[str] = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        preferred = d / d.name
        if preferred.is_file() and os.access(preferred, os.X_OK):
            targets.append((f"{root.name}/{d.name}", preferred))
            continue
        candidates = [
            f
            for f in sorted(d.iterdir())
            if f.is_file()
            and f.name not in _NON_TARGET
            and not f.name.endswith((".c", ".h", ".py", ".txt", ".md", ".json"))
            and os.access(f, os.X_OK)
            and _is_elf(f)
        ]
        if len(candidates) == 1:
            targets.append((f"{root.name}/{d.name}", candidates[0]))
        elif len(candidates) > 1:
            ambiguous.append(
                f"{root.name}/{d.name}: {len(candidates)} executable ELFs "
                f"({', '.join(c.name for c in candidates)})"
            )
    return targets, ambiguous


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="+", help="corpus roots, e.g. benchmark/corpus")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()

    mf = _load_measure_family()

    targets: list[tuple[str, pathlib.Path]] = []
    ambiguous: list[str] = []
    for raw in args.roots:
        root = pathlib.Path(raw).resolve()
        if not root.is_dir():
            print(f"not a directory: {root}", file=sys.stderr)
            return 1
        found, amb = discover(root)
        targets.extend(found)
        ambiguous.extend(amb)

    if ambiguous:
        print("AMBIGUOUS directories -- refusing to guess which ELF is the target:",
              file=sys.stderr)
        for line in ambiguous:
            print(f"  {line}", file=sys.stderr)
        return 2

    if not targets:
        print(f"discovered no targets under {args.roots} -- nothing was measured, "
              f"so there is nothing to report", file=sys.stderr)
        return 2

    print(f"coverage sweep: {len(targets)} targets, timeout={args.timeout:.0f}s, "
          f"jobs={args.jobs}")
    print(f"{'target':<42} {'outcome':<14} {'technique':<26} {'verified':<14} {'s':>7}")
    print("-" * 108)

    rows: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(mf.run_one, slug, path, args.timeout): slug
            for slug, path in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            rows.append(fut.result())

    rows.sort(key=lambda r: r["slug"])
    for r in rows:
        print(f"{r['slug']:<42} {str(r.get('outcome')):<14} "
              f"{str(r.get('technique')):<26} {str(r.get('verified')):<14} "
              f"{r.get('elapsed', 0):>7.1f}")
        if r.get("note"):
            print(f"{'':<42} note: {r['note']}")
        if r.get("legacy_ran"):
            print(f"{'':<42} *** LEGACY ENGINE RAN -- this row is not canonical ***")

    solved = [r for r in rows if r.get("outcome") == "SUCCESS"]
    unsolved = [r for r in rows if r.get("outcome") != "SUCCESS"]
    print("-" * 108)
    print(f"solved {len(solved)}/{len(rows)}")
    if unsolved:
        print("NOT SOLVED (each one is a coverage row that cannot be substantiated):")
        for r in unsolved:
            print(f"  {r['slug']}  [{r.get('outcome')}]")

    by_technique: dict[str, list[str]] = {}
    for r in solved:
        by_technique.setdefault(str(r.get("technique")), []).append(r["slug"])
    print("credited technique -> targets:")
    for tech in sorted(by_technique):
        print(f"  {tech:<26} {', '.join(by_technique[tech])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
