"""
I-45: no captured flag literal may live in a tracked benchmark YAML.

A flag readable from the repo lets a component "solve" a target by reading the
answer instead of exploiting it, so evidence comments carry the placeholder
``FLAG{REDACTED}`` rather than the value a run captured.

The scan is deliberately broad: any ``word{...}`` value of six or more
characters inside the braces counts as flag-shaped.
"""

from __future__ import annotations

import re
from pathlib import Path

BENCHMARK = Path(__file__).resolve().parent.parent / "benchmark"

FLAG_SHAPED = re.compile(r"[A-Za-z0-9_]+\{[^}]{6,}\}")

PLACEHOLDER = "FLAG{REDACTED}"

# Exact strings that are flag-shaped but are not flags. Keep this list to
# literal strings, never patterns, so it cannot grow into a blanket allowlist.
NOT_FLAGS = {
    # Format template in corpus_traversal.yaml's attribution note: the harness
    # fills `<slug>` itself; the text names the shape, not a value.
    "FLAG{supwngo_bench_<slug>}",
}


def test_no_flag_literals_in_benchmark_yaml():
    yaml_files = sorted(BENCHMARK.rglob("*.yaml"))
    assert yaml_files, "no benchmark YAML found; the scan would pass vacuously"
    hits = []
    for path in yaml_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in FLAG_SHAPED.finditer(line):
                if match.group(0) in {PLACEHOLDER, *NOT_FLAGS}:
                    continue
                hits.append(f"{path.relative_to(BENCHMARK.parent)}:{lineno}")
    assert not hits, "flag-shaped literals in benchmark YAML: " + ", ".join(hits)


def test_scan_pattern_detects_a_flag_literal():
    """The scan must be able to fail: a real-looking flag is a hit."""
    assert FLAG_SHAPED.search("flag=FLAG{0123456789abcdef}")
    assert FLAG_SHAPED.search(PLACEHOLDER)
