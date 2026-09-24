"""R1 per-target technique-map gate.

Asserts, from the STRUCTURED field `autopwn_json_probe.parsed.technique` in a
benchmark `report.json`, that R1's 13 credited targets each won with the
expected technique -- the per-target map at
docs/plans/2026-09-24-pipeline-instrumentation-pass.md §2.1.

This is deliberately NOT a count check and NOT a multiset check: it is a
per-target mapping, so a regression that SWAPS two targets' expected
techniques is caught, which neither a count nor a multiset can see.

The two VOID slugs (`11_heap_uaf_leak`, `13_off_by_one`) are excluded BY
NAME, not by any derived filter (e.g. a `status == "SUCCESS"` check). This
matters because `13_off_by_one` is VOID yet still reports
`technique == "ret2win"` -- an "every slug with a technique present" filter
yields 14 rows, not 13.

Reads the structured field only. Never parses generated-script headers --
that is the defect this gate exists to not repeat (plan §2.2, §6 step 1: a
text-header parser silently dropped rows twice because generated scripts use
two different header formats).
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Plan §2.1 -- the per-target map. 13 rows: the 15-target R1 corpus minus the
# two VOID slugs (excluded below, by name).
EXPECTED_TECHNIQUE: dict[str, str] = {
    "01_shellcode_stack": "stack_shellcode",
    "02_ret2plt_system": "ret2plt",
    "03_pie_leak_ret2libc": "ret2libc_leak",
    "04_canary_leak_bypass": "canary_leak_ret2win",
    "05_fmtstr_arbread": "canary_leak_ret2win",
    "06_fmtstr_arbwrite": "fmtstr_write_gate",
    "07_ret2libc_leak": "ret2libc_leak",
    "08_ret2dlresolve": "ret2dlresolve",
    "09_srop": "srop",
    "10_int_overflow": "int_truncation_bypass",
    "12_heap_tcache_poison": "tcache_poison_got",
    "14_negative_index": "negative_index_write",
    "15_win_function": "ret2win",
}

# Excluded BY NAME per plan §2.1 requirement 3 -- not derived from `status`,
# `void_cause`, or any other field. `13_off_by_one` is VOID
# (corpus_trivially_solvable) but its autopwn_json_probe.parsed.technique is
# still "ret2win", so deriving the exclusion from "has a technique" would
# wrongly keep it.
VOID_SLUGS = frozenset({"11_heap_uaf_leak", "13_off_by_one"})

EXPECTED_CREDITED_COUNT = 13


@dataclass
class GateResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    observed: dict[str, str] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.ok


def _observed_techniques(results: Iterable[dict]) -> dict[str, str]:
    """Pull {slug: technique} from the structured field, excluding VOID by name.

    Only reads `row["autopwn_json_probe"]["parsed"]["technique"]`. Never
    touches generated-script text.
    """
    observed: dict[str, str] = {}
    for row in results:
        slug = row.get("slug")
        if not slug or slug in VOID_SLUGS:
            continue
        probe = row.get("autopwn_json_probe") or {}
        parsed = probe.get("parsed") or {}
        technique = parsed.get("technique")
        # Truthy, not merely non-None: 11_heap_uaf_leak's structured
        # technique is "" (empty string, not null) on a real FAILED probe.
        # Matching plan §2.1's "every slug with a technique" naive-filter
        # language exactly requires excluding empty values here too.
        if technique:
            observed[slug] = technique
    return observed


def gate(results: list[dict]) -> GateResult:
    """The R1 per-target technique-map gate.

    Returns a GateResult; never raises. `results` is the `report.json`
    `"results"` list (a list of per-target dicts each carrying
    `autopwn_json_probe.parsed.technique`).
    """
    errors: list[str] = []
    observed = _observed_techniques(results)

    if len(observed) != EXPECTED_CREDITED_COUNT:
        errors.append(
            f"expected exactly {EXPECTED_CREDITED_COUNT} credited targets "
            f"(VOID slugs {sorted(VOID_SLUGS)} excluded by name), got "
            f"{len(observed)}: {sorted(observed)}"
        )

    for slug, expected in EXPECTED_TECHNIQUE.items():
        if slug not in observed:
            errors.append(
                f"missing target: {slug!r} not present in observed "
                f"autopwn_json_probe.parsed.technique data"
            )
            continue
        actual = observed[slug]
        if actual != expected:
            errors.append(
                f"{slug}: expected technique {expected!r}, got {actual!r}"
            )

    extra = sorted(set(observed) - set(EXPECTED_TECHNIQUE))
    for slug in extra:
        errors.append(
            f"unexpected credited target not in the §2.1 map: {slug!r} "
            f"(technique {observed[slug]!r})"
        )

    return GateResult(ok=not errors, errors=errors, observed=observed)


def gate_report_file(report_path: Path) -> GateResult:
    data = json.loads(Path(report_path).read_text())
    results = data.get("results")
    if not isinstance(results, list):
        return GateResult(ok=False, errors=["report.json has no 'results' list"])
    return gate(results)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: r1_technique_gate.py <report.json>", file=sys.stderr)
        return 2
    result = gate_report_file(Path(argv[0]))
    if result.ok:
        print(
            f"R1 PER-TARGET TECHNIQUE GATE: PASS "
            f"({len(result.observed)}/{EXPECTED_CREDITED_COUNT})"
        )
        return 0
    print("R1 PER-TARGET TECHNIQUE GATE: FAIL")
    for err in result.errors:
        print(f"  - {err}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
