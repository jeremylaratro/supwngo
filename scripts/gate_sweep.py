#!/usr/bin/env python3
"""Measure how narrow ONE executor's applicability gate is, over every ELF we have.

    python3 scripts/gate_sweep.py <module.path> <ExecutorClassName> <own-corpus-fragment>
    python3 scripts/gate_sweep.py allocsize_techniques AllocSizeOverflowExecutor corpus_allocsize

`<module.path>` is resolved first as a bare module name inside
``supwngo.exploit.pipeline.executors`` and then as an absolute import, so both
``allocsize_techniques`` and the fully-qualified path work.

WHY THIS IS A SCRIPT IN THE REPO

Every new vulnerability category owes a gate sweep -- condition 3 of "how a new
category is judged done" in
``docs/reference/2026-09-28-vulnerability-category-coverage.md``. For three
consecutive categories that sweep was run from a copy of this file in ``/tmp``,
which is wiped between sessions, so the one piece of tooling that decides whether
a gate is honest was the least durable thing in the loop. It lives here now.

WHY IT BUILDS A FULL CONTEXT INSTEAD OF CALLING A MODULE FUNCTION

An executor's gate reads ``context.binary``, ``context.win_function`` and
``context.profile_has_menu``. Those exist only after the profile stage has run,
so a sweep that imports the module and calls a bare ``analyse(path)`` raises on
every image. That failure mode is the reason for the positive control below: a
sweep that raises on all 159 images prints ``gate OPEN on: 0``, which reads
exactly like a flawlessly narrow gate. It happened, and the result was believed
for a while. A gate sweep that cannot distinguish "narrow" from "broken" is
decoration.

EXIT CODES
    0  the sweep ran and its own positives opened -- the numbers mean something
    2  the gate opened on NONE of its own family's targets: the sweep measured a
       broken harness, not a narrow gate, and its counts must not be quoted

Out-of-family opens are printed BY NAME rather than just counted. On this project
a loose gate is an accepted trade (solve rate is the goal), so an out-of-family
open is not automatically a defect -- but it has to be named to be judged.
"""

from __future__ import annotations

import importlib
import os
import pathlib
import sys
import time

#: Repo root, derived from this file so the script is not pinned to one checkout.
ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Extensions that are never a target binary. Cheap pre-filter before reading
#: magic bytes; the magic check below is what actually decides.
_NOT_BINARY = {".c", ".S", ".py", ".md", ".yaml", ".yml", ".json", ".txt", ".ld", ".sh"}

#: Where target ELFs live. `tests/htb-targets` holds real challenge binaries
#: alongside secret flags -- this script reads only ELF magic and prints only
#: relative paths, so no flag content can reach the output.
#:
#: Overridable via ``GATE_SWEEP_ROOTS`` (colon-separated, repo-relative) so the
#: script's own red-proofs can run against a handful of images instead of the
#: whole tree. Every run PRINTS the roots it actually swept, which is what keeps
#: that override honest: a narrowed sweep labels its own scope in its own output,
#: so its counts cannot later be quoted as a whole-tree result.
_DEFAULT_ROOTS = ("benchmark", "tests/htb-targets")
_SEARCH_ROOTS = tuple(
    os.environ.get("GATE_SWEEP_ROOTS", ":".join(_DEFAULT_ROOTS)).split(":")
)

#: Dynamic profile budget per image. The gate only needs to know whether a menu
#: exists, and 159 images at a generous timeout is an overnight job.
_PROFILE_TIMEOUT = 2.0


def _load_executor(module_arg: str, class_name: str):
    """Import the executor class, accepting a bare module name or a full path."""
    candidates = [
        f"supwngo.exploit.pipeline.executors.{module_arg}",
        module_arg,
    ]
    last: Exception | None = None
    for name in candidates:
        try:
            return getattr(importlib.import_module(name), class_name)()
        except ImportError as exc:
            last = exc
    raise SystemExit(f"could not import {class_name} from any of {candidates}: {last}")


def _find_elfs() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for rel in _SEARCH_ROOTS:
        root = ROOT / rel
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file() or p.is_symlink() or p.suffix in _NOT_BINARY:
                continue
            try:
                with open(p, "rb") as fh:
                    if fh.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            out.append(p)
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 64
    sys.path.insert(0, str(ROOT))
    executor = _load_executor(argv[1], argv[2])
    own = argv[3]

    from supwngo.core.binary import Binary
    from supwngo.core.context import ExploitContext
    from supwngo.exploit.pipeline.profile_stage import (
        run_dynamic_profile,
        run_static_analysis,
    )

    elfs = _find_elfs()
    scope = "WHOLE TREE" if _SEARCH_ROOTS == _DEFAULT_ROOTS else "NARROWED via GATE_SWEEP_ROOTS"
    print(f"sweep scope: {scope} -- roots {list(_SEARCH_ROOTS)}")
    print(f"ELF files swept: {len(elfs)}", flush=True)

    open_on: list[str] = []
    raised: list[tuple[str, str]] = []
    times: list[float] = []

    for p in elfs:
        rel = str(p.relative_to(ROOT))
        t0 = time.time()
        try:
            # `Binary.load`, never `Binary(path)`. The bare constructor returns a
            # fully-formed object whose ELF was never parsed, so every protection
            # reads as its default and nothing says so -- it has produced a
            # confident wrong measurement on this project more than once.
            binary = Binary.load(str(p))
            ctx = ExploitContext(binary=binary)
            run_static_analysis(ctx)
            run_dynamic_profile(ctx, timeout=_PROFILE_TIMEOUT)
            opened = bool(executor.is_applicable(ctx))
        except Exception as exc:  # noqa: BLE001 -- a gate that raises IS the finding
            raised.append((rel, repr(exc)[:160]))
            continue
        times.append(time.time() - t0)
        if opened:
            open_on.append(rel)

    print(f"gate OPEN on: {len(open_on)}")
    for rel in open_on:
        print(f"  {'OWN     ' if own in rel else 'OUTSIDE '} {rel}")
    outside = [r for r in open_on if own not in r]
    mine = [r for r in open_on if own in r]
    print(f"captured OUTSIDE the family: {len(outside)}")
    print(f"raised: {len(raised)}")
    for rel, exc in raised:
        print("  RAISED", rel, exc)
    if times:
        print(
            f"per-image cost: mean {sum(times) / len(times) * 1000:.0f} ms, "
            f"max {max(times) * 1000:.0f} ms"
        )

    # The positive control on the sweep ITSELF, not on the gate. Without it a
    # harness that fails on every image is indistinguishable from a perfect gate.
    own_elfs = [str(p.relative_to(ROOT)) for p in elfs if own in str(p)]
    print(f"\nown-family ELFs present: {len(own_elfs)}; gate opened on {len(mine)} of them")
    if own_elfs and not mine:
        print(
            "SWEEP INVALID: the gate opened on NONE of its own targets, so this "
            "sweep measures a broken harness, not a narrow gate. Do not quote "
            "these counts."
        )
        return 2
    if not own_elfs:
        print(
            f"SWEEP INVALID: no ELF under a path containing {own!r} was found, so "
            "the positive control could not run. Check the corpus fragment "
            "argument and whether the family's binaries are built."
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
