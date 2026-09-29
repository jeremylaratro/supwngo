"""Regression tests for value-controlled format-string writes."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.delivery import deliver_parts
from supwngo.exploit.pipeline.executors import build_default_registry
from supwngo.exploit.pipeline.executors.fmtstr_techniques import FmtStrWriteGateExecutor
from supwngo.exploit.pipeline.orchestrator import (
    APPROACH_TO_TECHNIQUE,
    FIRST_TECHNIQUES,
    LAST_TECHNIQUES,
    UNMODELED_TECHNIQUES,
)
from supwngo.exploit.pipeline.verifier import PipelineVerifier
from supwngo.exploit.strategy import ExploitApproach


ROOT = Path(__file__).resolve().parent.parent
SHORT = ROOT / "benchmark/corpus_r2/06_fmtstr_short_write/fmtstr_short_write"
GOT = ROOT / "benchmark/corpus_r2/12_fmtstr_got_overwrite/fmtstr_got_overwrite"
FLAG_FLIP = ROOT / "benchmark/corpus/06_fmtstr_arbwrite/fmtstr_arbwrite"
FLAG_RE = re.compile(rb"(?:flag|ctf|htb)\{[^}]+\}", re.IGNORECASE)


def _context(path: Path) -> ExploitContext:
    if not path.exists():
        pytest.skip(f"{path.name} not built")
    binary = Binary.load(str(path))
    context = ExploitContext.from_binary(binary)
    win = binary.symbols.get("win")
    assert win is not None
    context.win_function = ("win", win.address)
    return context


def _run_candidate(context: ExploitContext, candidate) -> bytes:
    executor = FmtStrWriteGateExecutor()
    path = str(context.binary.path.resolve())
    directory = str(context.binary.path.resolve().parent)
    arg_index = executor._find_buffer_arg_index(path, directory)
    assert arg_index is not None
    payload = executor._payload(
        context.binary, arg_index, dict(candidate.writes), candidate.write_size,
    )
    assert payload is not None
    return deliver_parts(path, [payload + b"\n"], cwd=directory, timeout=3.0).output


def test_recovers_exact_global_and_value_guarding_win() -> None:
    context = _context(SHORT)
    auth = context.binary.symbols["auth_level"].address

    assert FmtStrWriteGateExecutor()._guarded_global(context) == (auth, 0x1337, 2)


def test_exact_value_write_has_a_wrong_value_control() -> None:
    """The right address with the wrong value must fail before the real write passes."""
    context = _context(SHORT)
    executor = FmtStrWriteGateExecutor()
    path = str(context.binary.path.resolve())
    directory = str(context.binary.path.resolve().parent)
    candidates = executor._write_targets(context, path, directory)
    exact = next(
        target for target in candidates
        if target.kind == "chosen_global"
        and int.from_bytes(target.writes[0][1], context.binary.endian) == 0x1337
    )
    wrong = type(exact)(
        ((exact.address, (0x1336).to_bytes(2, context.binary.endian)),),
        "short", "chosen_global", "wrong-value control",
    )

    assert FLAG_RE.search(_run_candidate(context, wrong)) is None
    assert FLAG_RE.search(_run_candidate(context, exact)) is not None


def test_got_minimal_write_changes_only_the_two_differing_bytes() -> None:
    context = _context(GOT)
    executor = FmtStrWriteGateExecutor()
    path = str(context.binary.path.resolve())
    directory = str(context.binary.path.resolve().parent)
    candidates = executor._write_targets(context, path, directory)
    putchar = next(
        target for target in candidates
        if target.kind == "got_minimal" and target.address == context.binary.got["putchar"]
    )

    assert putchar.write_size == "short"
    assert putchar.writes == ((context.binary.got["putchar"], b"\x56\x12"),)
    assert FLAG_RE.search(_run_candidate(context, putchar)) is not None

    verifier = PipelineVerifier(str(GOT.resolve()), context=context)
    receipt = verifier.verify_script(
        executor.name, executor._script(context, 6, putchar),
    )
    assert receipt.success is True
    assert receipt.level.name == "FLAG_CAPTURED"


def test_nonzero_flag_flip_remains_a_working_last_fallback() -> None:
    context = _context(FLAG_FLIP)
    executor = FmtStrWriteGateExecutor()
    path = str(context.binary.path.resolve())
    directory = str(context.binary.path.resolve().parent)
    candidates = executor._write_targets(context, path, directory)
    unlocked = context.binary.symbols["unlocked"].address
    fallback = next(
        target for target in candidates
        if target.kind == "flag_flip" and target.address == unlocked
    )

    assert candidates.index(fallback) > max(
        index for index, target in enumerate(candidates) if target.kind.startswith("got_")
    )
    assert FLAG_RE.search(_run_candidate(context, fallback)) is not None


def test_only_the_working_format_string_executor_is_registered() -> None:
    names = build_default_registry().names()

    # The positive half keeps the absence assertion from passing vacuously after
    # a rename or accidental removal of all format-string automation.
    assert "fmtstr_write_gate" in names
    assert "format_string" not in names
    assert APPROACH_TO_TECHNIQUE[ExploitApproach.FORMAT_STRING] == "fmtstr_write_gate"
    assert "format_string" not in FIRST_TECHNIQUES
    assert "format_string" not in LAST_TECHNIQUES
    assert "format_string" not in UNMODELED_TECHNIQUES

    assert len(FIRST_TECHNIQUES) == len(set(FIRST_TECHNIQUES))
    assert set(FIRST_TECHNIQUES) <= set(names), "FIRST_TECHNIQUES contains an orphan"
