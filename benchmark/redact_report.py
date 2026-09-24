#!/usr/bin/env python3
"""Redact a benchmark ``report.json`` so it can be committed as evidence.

Why this exists
---------------
``report.json`` is gitignored by design: it embeds every rep's per-run secret
flag, and the corpus contract forbids committing a flag literal to git (rule R1
in ``benchmark/README.md``). But a *digest* of a file nobody else can obtain is
not evidence -- it cannot expose selective transcription of the numbers into a
prose report, which is the thing a reader should be able to check.

So: replace every occurrence of every per-rep secret with a placeholder, leaving
structure, per-rep statuses, reasons, attribution verdicts and timings intact and
independently checkable against the report's prose. The unredacted original stays
on disk, with its sha256 recorded, for anyone who can reach the machine.

The redaction is *verified*, not assumed: the output is rejected if any
``FLAG{<32 hex>}``-shaped string survives anywhere in it. That check is deliberately
independent of the substitution above, so a secret this script failed to enumerate
(a nested field added later, an unexpected embedding) still fails loudly rather
than being committed.

Usage:
    python3 benchmark/redact_report.py <report.json> <out.json>
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

# The corpus contract's flag shape: "FLAG{" + 32 hex + "}" (SECRET_FLAG_LEN = 38).
FLAG_RE = re.compile(r"FLAG\{[0-9a-fA-F]{32}\}")


def collect_secrets(node) -> set[str]:
    """Every secret the report records, from wherever it records it.

    Walks the whole structure rather than reading a fixed set of keys: each rep
    stores its own secret in ``attempts[]`` (which is what makes a multi-rep
    verdict falsifiable), and a schema change should not silently narrow what
    gets redacted.
    """
    found: set[str] = set()
    if isinstance(node, dict):
        for value in node.values():
            found |= collect_secrets(value)
    elif isinstance(node, list):
        for item in node:
            found |= collect_secrets(item)
    elif isinstance(node, str):
        found |= set(FLAG_RE.findall(node))
    return found


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2

    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    if not src.is_file():
        print(f"error: {src} not found", file=sys.stderr)
        return 2

    raw = src.read_text()
    digest = hashlib.sha256(src.read_bytes()).hexdigest()
    report = json.loads(raw)

    secrets = sorted(collect_secrets(report))
    # Longest first so no secret is a prefix of another's replacement.
    for i, secret in enumerate(sorted(secrets, key=len, reverse=True), 1):
        raw = raw.replace(secret, f"<REDACTED-SECRET-{i:02d}>")

    leftover = FLAG_RE.findall(raw)
    if leftover:
        print(f"error: redaction INCOMPLETE -- {len(leftover)} flag-shaped "
              f"string(s) survive; refusing to write {dst}", file=sys.stderr)
        return 1

    # Re-parse so a malformed result cannot be committed as evidence.
    json.loads(raw)
    dst.write_text(raw)

    print(f"source:            {src}")
    print(f"source sha256:     {digest}")
    print(f"secrets redacted:  {len(secrets)}")
    print(f"redacted written:  {dst}")
    print("verified:          no FLAG{<32 hex>} string survives")
    return 0


if __name__ == "__main__":
    sys.exit(main())
