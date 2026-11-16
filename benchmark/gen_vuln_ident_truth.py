#!/usr/bin/env python3
"""Generate the frozen VULN-axis identification truth (Sprint B2).

The output `benchmark/vuln_ident_truth.yaml` is the FROZEN, peer-reviewable truth
the vuln-ID scorer (`score_vuln_ident.py`) consumes. This generator encodes the
labelling RULES so the frozen artifact is auditable; re-running it must reproduce
the committed yaml byte-for-byte (sorted, deterministic).

Labelling rules (see docs/plans/2026-11-16-identification-sprintB-plan.md,
"B2 frozen target manifest + scope/VOID policy"):

* VULN truth = the DEFECT CLASS the target is built around, derived from corpus
  design intent (core: the per-target `technique`; specialised: the corpus's
  held-constant category). It is INDEPENDENT of what detect_all() emits -> no
  label leakage (R5 concerned the METHOD axis; VULN truth is the source-level
  defect, not the recommended method).
* Multi-label is SUPPORTED (truth is a list). These corpora are purpose-built to
  isolate ONE defect each, so a single primary label is correct for nearly all;
  a second label is added only where source review shows a genuine second defect.
* role == "control" (or a `_NN_neg_` / `_neg_` slug) is a NEGATIVE precision
  control: truth = [] (no in-scope family present). A detector emitting ANY
  in-scope family on it is a false positive.
* Only IN-SCOPE families are gated: stack_bof, format_string, integer,
  heap_overflow, uaf, off_by_one. double_free is gated only if a positive exists.

Usage: python3 benchmark/gen_vuln_ident_truth.py   # writes vuln_ident_truth.yaml
"""
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent

IN_SCOPE = ("stack_bof", "format_string", "integer", "heap_overflow", "uaf", "off_by_one")

# --- core corpus technique -> primary VULN family (from the reviewed spike TECH map) ---
CORE_TECH2VULN = {
    "stack_shellcode": "stack_bof", "stack_shellcode_relay": "stack_bof",
    "ret2plt_system": "stack_bof", "ret2plt_strcat_system": "stack_bof",
    "ret2libc_leak": "stack_bof", "pie_leak_ret2libc": "stack_bof",
    "pie_write_leak_ret2libc": "stack_bof", "ret2win_baseline": "stack_bof",
    "ret2win_arg_gate": "stack_bof", "canary_leak_bypass": "stack_bof",
    "canary_relay_bypass": "stack_bof", "srop": "stack_bof",
    "ret2csu_execve": "stack_bof", "static_ret2syscall": "stack_bof",
    "ret2dlresolve": "stack_bof",
    "fmtstr_arbread": "format_string", "fmtstr_arbwrite": "format_string",
    "fmtstr_short_write": "format_string", "fmtstr_pie_leak": "format_string",
    "fmtstr_got_overwrite": "format_string",
    "integer_overflow": "integer", "int_mul_overflow": "integer",
    "negative_index_oob_write": "integer",
    "heap_tcache_poison": "heap_overflow", "heap_overflow_tcache_poison": "heap_overflow",
    "heap_uaf_read": "uaf", "heap_dangling_global": "uaf",
    "off_by_one": "off_by_one", "off_by_one_retaddr_lsb": "off_by_one",
    "oob_read_flag_array": "off_by_one",
}

# --- in-scope specialised corpora: corpus -> (manifest path, binary dir, family) ---
# Manifest lives either beside the binaries (corpus_x/corpus_x.yaml) or at the
# benchmark root (corpus_x.yaml); binaries live under corpus_x/<slug>/<slug>.
SPECIALISED = {
    "corpus_scanf":    "stack_bof",
    "corpus_variants": "stack_bof",
    "corpus_vectors":  "stack_bof",
    "corpus_bon":      "heap_overflow",
    "corpus_uafread":  "uaf",
    "corpus_offbynul": "off_by_one",
    "corpus_offbyone": "off_by_one",
}
# corpus_fsop is OUT (FSOP/_IO_FILE arbitrary-read primitive, not a detector family).


def manifest_path(corpus: str) -> Path:
    for cand in (HERE / corpus / f"{corpus}.yaml", HERE / f"{corpus}.yaml"):
        if cand.exists():
            return cand
    raise FileNotFoundError(f"no manifest for {corpus}")


def is_negative(t: dict) -> bool:
    if (t.get("role") or "positive") == "control":
        return True
    slug = t["slug"]
    return bool(re.search(r"(^|_)neg(_|$)", slug) or re.search(r"_\d0_neg_", slug))


def core_binpath(corpus: str, slug: str) -> Path:
    name = re.sub(r"^\d\d_", "", slug)
    return HERE / corpus / slug / name


def spec_binpath(corpus: str, slug: str) -> Path:
    name = re.sub(r"^\d\d_", "", slug)  # specialised slugs have no NN_ prefix -> unchanged
    return HERE / corpus / slug / name


def main() -> int:
    rows = []
    unmapped = []

    # core corpus + corpus_r2 (per-target technique)
    for corpus in ("corpus", "corpus_r2"):
        data = yaml.safe_load(manifest_path(corpus).read_text())
        for t in data["targets"]:
            slug, tech = t["slug"], t.get("technique")
            fam = CORE_TECH2VULN.get(tech)
            if fam is None:
                unmapped.append((corpus, slug, tech))
                continue
            neg = is_negative(t)
            rows.append(dict(corpus=corpus, slug=slug, technique=tech,
                             role="control" if neg else "positive",
                             truth=[] if neg else [fam],
                             binpath=str(core_binpath(corpus, slug).relative_to(HERE))))

    # in-scope specialised corpora (corpus-level family)
    for corpus, fam in SPECIALISED.items():
        data = yaml.safe_load(manifest_path(corpus).read_text())
        for t in data["targets"]:
            slug = t["slug"]
            neg = is_negative(t)
            rows.append(dict(corpus=corpus, slug=slug, technique=None,
                             role="control" if neg else "positive",
                             truth=[] if neg else [fam],
                             binpath=str(spec_binpath(corpus, slug).relative_to(HERE))))

    if unmapped:
        print("ERROR: unmapped core techniques:", unmapped, file=sys.stderr)
        return 1

    rows.sort(key=lambda r: (r["corpus"], r["slug"]))
    doc = {
        "policy": {
            "in_scope_families": list(IN_SCOPE),
            "note": "double_free gated only if a positive exists; VOID corpora excluded.",
        },
        "targets": rows,
    }
    out = HERE / "vuln_ident_truth.yaml"
    out.write_text(
        "# FROZEN VULN-axis identification truth (Sprint B2) -- generated by\n"
        "# gen_vuln_ident_truth.py; do not hand-edit. Re-run the generator to refresh.\n"
        + yaml.safe_dump(doc, sort_keys=False, width=100)
    )
    pos = sum(1 for r in rows if r["role"] == "positive")
    neg = sum(1 for r in rows if r["role"] == "control")
    print(f"wrote {out.relative_to(HERE)}: {len(rows)} targets ({pos} positive, {neg} control)")
    from collections import Counter
    fams = Counter(f for r in rows for f in r["truth"])
    for fam, n in sorted(fams.items()):
        print(f"  {fam:14} {n} positives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
