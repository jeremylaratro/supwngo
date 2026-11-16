#!/usr/bin/env python3
"""VULN-axis identification scorer (Sprint B2) -- the Phase-8 benefit instrument
and the per-family precision+recall GATE.

Instrument: the EXACT production report path. For each frozen-truth target it runs
`supwngo.reporting.adapter.detect_all(Binary.load(path))` -- the same call the
`supwngo` report emits -- maps each emitted `VulnType` to an in-scope VULN family,
and scores against `vuln_ident_truth.yaml`.

Metric (per the round-1 review, R3): for each IN-SCOPE family the gate requires
BOTH per-family precision >= THRESHOLD and per-family recall >= THRESHOLD, scored
on MULTI-LABEL truth.
  * recall(F)    = |positives(F) that detected F| / |positives(F)|
  * precision(F) = |targets that detected F and have F in truth| / |targets that detected F|
    (control targets, truth == [], contribute only to precision denominators: any
    in-scope firing on them is a false positive -- this is what any-match hid.)
A family with no positives is reported `no-positives -> not gated`.

Tri-state: a target whose binary fails to load / detect is `inconclusive`, never a
silent pass; inconclusive targets are excluded from both numerator and denominator
and listed.

Exit status: 0 if every gated family clears the threshold on BOTH metrics (GREEN);
2 if any gated family is below on either metric (RED); 1 on a harness error. This
makes it a real gate that can be shown to go RED (Phase 7c).

Usage:
  SUPWNGO_REPO=/path/to/supwngo python3 benchmark/score_vuln_ident.py [--json OUT] [--threshold 0.9]
"""
import argparse
import collections
import json
import os
import sys
from pathlib import Path

import yaml

REPO = Path(os.environ.get("SUPWNGO_REPO", Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(REPO))

from supwngo.core.binary import Binary            # noqa: E402
from supwngo.reporting.adapter import detect_all  # noqa: E402

BENCH = REPO / "benchmark"

# VulnType member name -> in-scope VULN family. Members absent at a given SHA
# simply never appear in detected sets (e.g. OFF_BY_ONE before B2 adds it).
VT2FAM = {
    "STACK_BUFFER_OVERFLOW": "stack_bof",
    "HEAP_BUFFER_OVERFLOW": "heap_overflow",
    "USE_AFTER_FREE": "uaf",
    "DOUBLE_FREE": "double_free",
    "FORMAT_STRING": "format_string",
    "INTEGER_OVERFLOW": "integer",
    "INTEGER_UNDERFLOW": "integer",
    "OFF_BY_ONE": "off_by_one",
}


def detected_families(binpath: Path):
    """Return the set of in-scope VULN families detect_all emits for a binary."""
    b = Binary.load(str(binpath))
    vulns, _failures = detect_all(b)
    fams = set()
    for v in vulns:
        fam = VT2FAM.get(getattr(v.vuln_type, "name", None))
        if fam:
            fams.add(fam)
    return fams


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--threshold", type=float, default=0.90)
    ap.add_argument("--truth", type=Path, default=BENCH / "vuln_ident_truth.yaml")
    args = ap.parse_args()

    doc = yaml.safe_load(args.truth.read_text())
    in_scope = list(doc["policy"]["in_scope_families"])
    targets = doc["targets"]

    rows = []
    for t in targets:
        bp = (BENCH / t["binpath"])
        row = dict(corpus=t["corpus"], slug=t["slug"], role=t["role"], truth=t["truth"])
        try:
            fams = detected_families(bp)
            row["detected"] = sorted(fams)
            row["status"] = "ok"
        except Exception as e:  # noqa: BLE001 -- tri-state: harness/load failure
            row["detected"] = []
            row["status"] = "inconclusive"
            row["error"] = repr(e)
        rows.append(row)

    scored = [r for r in rows if r["status"] == "ok"]
    inconclusive = [r for r in rows if r["status"] != "ok"]

    # Per-family precision + recall over the in-scope families.
    fam_stat = {}
    for fam in in_scope:
        positives = [r for r in scored if fam in r["truth"]]
        recall_hits = sum(1 for r in positives if fam in r["detected"])
        fired = [r for r in scored if fam in r["detected"]]
        fired_correct = sum(1 for r in fired if fam in r["truth"])
        recall = (recall_hits / len(positives)) if positives else None
        precision = (fired_correct / len(fired)) if fired else None
        fam_stat[fam] = dict(
            positives=len(positives), recall_hits=recall_hits, recall=recall,
            fired_total=len(fired), fired_correct=fired_correct, precision=precision,
        )

    # Gate: families WITH positives must clear threshold on BOTH metrics.
    thr = args.threshold
    gate = {}
    red = False
    for fam, s in fam_stat.items():
        if s["positives"] == 0:
            gate[fam] = "no-positives -> not gated"
            continue
        # precision is None only if the family never fired; with positives present
        # that means 0 recall and vacuous precision -> treat as RED via recall.
        p_ok = (s["precision"] is not None and s["precision"] >= thr)
        r_ok = (s["recall"] is not None and s["recall"] >= thr)
        ok = p_ok and r_ok
        gate[fam] = "PASS" if ok else "FAIL"
        if not ok:
            red = True

    out = dict(threshold=thr, n_targets=len(rows), n_scored=len(scored),
               n_inconclusive=len(inconclusive), families=fam_stat, gate=gate,
               verdict=("RED" if red else "GREEN"), rows=rows)
    if args.json:
        args.json.write_text(json.dumps(out, indent=2))

    # Human summary.
    print(f"VULN-ID scorer  threshold={thr:.0%}  scored={len(scored)}/{len(rows)}"
          f"  inconclusive={len(inconclusive)}")
    print(f"{'family':14} {'pos':>4} {'recall':>12} {'precision':>14}  gate")
    for fam in in_scope:
        s = fam_stat[fam]
        rc = "n/a" if s["recall"] is None else f"{s['recall_hits']}/{s['positives']}={s['recall']:.0%}"
        pr = "n/a" if s["precision"] is None else f"{s['fired_correct']}/{s['fired_total']}={s['precision']:.0%}"
        print(f"{fam:14} {s['positives']:>4} {rc:>12} {pr:>14}  {gate[fam]}")
    if inconclusive:
        print("inconclusive:", ", ".join(f"{r['corpus']}/{r['slug']}" for r in inconclusive))
    print(f"\nVERDICT: {out['verdict']}")
    return 2 if red else 0


if __name__ == "__main__":
    raise SystemExit(main())
