#!/usr/bin/env python3
"""Do a target's reps produce the SAME artifact? Discriminates two failure modes.

WHY THIS EXISTS
---------------
The pipeline's discovery probes are bounded by timeouts hardcoded at 8
``deliver_parts`` call sites (1.5 / 2.0 / 3.0 s), and ``deliver_parts`` collapses a
timeout into empty output. So "this technique does not apply" and "the probe ran out
of time" are reported identically. If a FAILED target is actually a stalled probe, its
failure is not a capability limit and any diagnosis of it is unsafe.

Repetition discriminates the two WITHOUT a new measurement, because they have
different signatures across reps:

  * A **load-sensitive stall is a race.** It does not lose the same race five times
    and land on byte-identical output. Divergent artifacts across reps are the
    truncation signature -- which is exactly how round 1's ``04_canary_leak_bypass``
    presented: 9 byte-identical working exploits and one stub with ``offset = 0``.
  * A **genuine non-match is deterministic.** Identical artifacts across reps taken
    under varying load is strong evidence the probe returned the same answer because
    the answer was the same.

WHAT IT CANNOT ESTABLISH -- stated because the limit is the point
----------------------------------------------------------------
Identical artifacts rule out *race-type*, load-sensitive truncation. They do **not**
rule out **deterministic** truncation: a probe against a target that never answers
inside 2.0 s times out identically on every rep and yields identical stubs. That case
is indistinguishable here and needs ``DeliveryResult.timed_out`` to actually have
consumers (it currently has none outside ``__repr__``). So a PASS from this tool means
"not a flaky stall", never "not a stall".

ASLR NORMALISATION
------------------
Generated scripts embed leaked runtime addresses in their analysis comments, which
differ every run because of stack/heap ASLR. That is expected environmental
nondeterminism, not a truncation signal, so long integers and long hex literals are
normalised before comparison. Both the raw and normalised counts are reported: a
target that is identical only AFTER normalisation differed solely in addresses, and
the raw number is shown so nobody has to trust the normaliser.

Usage:  python3 benchmark/rep_divergence.py <results_dir> [--reps N]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# Long decimals and long hex literals are the shapes a leaked address takes in the
# generated scripts' comment blocks. Deliberately narrow: a 6+ digit hex or a 10+
# digit decimal is an address, while a small constant (an offset, a magic value, a
# gadget count) is exactly what we must NOT normalise away, since a differing offset
# between reps IS a divergence worth seeing.
_ADDR_DEC = re.compile(rb"[0-9]{10,}")
_ADDR_HEX = re.compile(rb"0x[0-9a-fA-F]{6,}")


def normalise(raw: bytes) -> bytes:
    raw = _ADDR_HEX.sub(b"<HEX>", raw)
    return _ADDR_DEC.sub(b"<ADDR>", raw)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir", type=Path)
    ap.add_argument("--reps", type=int, default=None)
    args = ap.parse_args()

    report = args.results_dir / "report.json"
    if not report.is_file():
        print(f"error: no report.json in {args.results_dir}", file=sys.stderr)
        return 2
    data = json.loads(report.read_text())
    n_reps = args.reps or int(data.get("reps") or 5)

    statuses = {t["slug"]: t["status"] for t in data["results"]}

    hdr = (f"{'target':<34}{'status':<9}{'found':<7}{'raw':<6}{'norm':<6}"
           f"{'verdict':<38}")
    print(f"reps={n_reps}  results={args.results_dir}")
    print()
    print(hdr)
    print("-" * len(hdr))

    undetermined: list[str] = []
    divergent: list[str] = []
    deterministic: list[str] = []

    for slug in sorted(statuses):
        raws, norms = [], []
        for rep in range(1, n_reps + 1):
            path = args.results_dir / f"rep{rep}" / f"{slug}_generated.py"
            if not path.is_file():
                continue
            blob = path.read_bytes()
            raws.append(digest(blob))
            norms.append(digest(normalise(blob)))

        found = len(raws)
        n_raw, n_norm = len(set(raws)), len(set(norms))

        if found < 2:
            verdict = "CANNOT DETERMINE (need >=2 archived reps)"
            undetermined.append(slug)
        elif n_norm > 1:
            verdict = "DIVERGENT -- truncation signature"
            divergent.append(slug)
        elif n_raw > 1:
            verdict = "identical modulo ASLR -- deterministic"
            deterministic.append(slug)
        else:
            verdict = "byte-identical -- deterministic"
            deterministic.append(slug)

        print(f"{slug:<34}{statuses[slug]:<9}{found:<7}{n_raw:<6}{n_norm:<6}"
              f"{verdict:<38}")

    print()
    print(f"deterministic  : {len(deterministic)}")
    print(f"DIVERGENT      : {len(divergent)}"
          + (f"  -> {', '.join(divergent)}" if divergent else ""))
    print(f"undetermined   : {len(undetermined)}"
          + (f"  -> {', '.join(undetermined)}" if undetermined else ""))
    print()
    if divergent:
        print("A DIVERGENT target's FAILED verdict is NOT established as a capability")
        print("limit, and any diagnosis of it is unsafe until the divergence is")
        print("explained. Investigate before planning a fix for it.")
    else:
        print("No target diverged: no FAILED verdict here is a flaky-stall artefact.")
    print("Reminder: this rules out RACE-type truncation only. A probe that times out")
    print("DETERMINISTICALLY produces identical artifacts too -- see the module docstring.")
    return 1 if divergent else 0


if __name__ == "__main__":
    sys.exit(main())
