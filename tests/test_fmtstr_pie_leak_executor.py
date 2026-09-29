"""Focused tests for format-string PIE leak acquisition and ranking."""

from pathlib import Path
from types import SimpleNamespace

from supwngo.core.binary import Symbol
from supwngo.exploit.pipeline.executors.rop_techniques import (
    FMTSTR_PIE_RET_OFFSET,
    FMTSTR_PIE_SCAN,
    Ret2LibcLeakExecutor,
)
from supwngo.exploit.pipeline.volunteered_leaks import (
    HarvestCandidate,
    HarvestResult,
    HarvestState,
    LeakKind,
)


def _binary():
    symbols = {
        "vuln": Symbol("vuln", 0x1321, 276, "FUNC", "GLOBAL", ".text"),
        "main": Symbol("main", 0x1435, 80, "FUNC", "GLOBAL", ".text"),
        "helper": Symbol("helper", 0x1555, 32, "FUNC", "GLOBAL", ".text"),
    }
    return SimpleNamespace(
        path=Path("/tmp/fmtstr_pie_leak"), bits=64, symbols=symbols,
    )


def test_format_scan_reaches_position_41_and_fits_the_127_byte_read():
    assert FMTSTR_PIE_SCAN == b"%p." * 41 + b"\n"
    assert FMTSTR_PIE_SCAN.count(b"%p.") == 41
    assert len(FMTSTR_PIE_SCAN) == 124
    assert len(FMTSTR_PIE_SCAN) <= 127


def test_pie_candidates_prefer_two_independent_anchors_over_first_match():
    strong_base = 0x555555554000
    weak_base = 0x566666665000
    harvested = HarvestResult(HarvestState.HARVESTED, [
        HarvestCandidate(LeakKind.CODE_POINTER, weak_base + 0x1555, 1, "text",
                         symbol="helper", base=weak_base),
        HarvestCandidate(LeakKind.CODE_POINTER, strong_base + 0x1321, 2, "text",
                         symbol="vuln", base=strong_base),
        HarvestCandidate(LeakKind.CODE_POINTER, strong_base + 0x1435, 3, "text",
                         symbol="main", base=strong_base),
    ])

    ranked = Ret2LibcLeakExecutor._rank_pie_leaks(harvested, _binary())

    assert [base for base, _anchors in ranked] == [strong_base, weak_base]
    assert {name for _value, name, _offset in ranked[0][1]} == {"vuln", "main"}
    assert len(ranked[0][1]) == 2
    assert len(ranked[1][1]) == 1


def test_direct_win_script_requires_anchor_agreement_before_buf_232_overflow():
    executor = Ret2LibcLeakExecutor()
    context = SimpleNamespace(binary=_binary())
    anchors = [
        (0x555555555321, "vuln", 0x1321),
        (0x555555555435, "main", 0x1435),
    ]
    script = executor._fmtstr_win_script(
        context, anchors, "win", 0x1311, {"ret": 0x101A}, True,
    )

    corroboration = script.index("if not ranked or len(ranked[0][1]) < 2:")
    overflow = script.index(f"ret_offset = {FMTSTR_PIE_RET_OFFSET}")
    send = script.index("send_part(io, payload)")

    assert corroboration < send
    assert overflow < send
    assert "payload += p64(image_base + 0x101a)" in script
    assert "payload += p64(image_base + win_offset)" in script
