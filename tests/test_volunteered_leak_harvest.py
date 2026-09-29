"""Regression tests for pre-payload volunteered leak harvesting."""

from types import SimpleNamespace

from supwngo.core.binary import Protections, Symbol
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.volunteered_leaks import (
    HarvestState,
    LeakKind,
    classify_volunteered_output,
    harvest_volunteered_output,
)


def _binary_with_symbol(offset: int):
    return SimpleNamespace(
        symbols={
            "vuln": Symbol(
                name="vuln", address=offset, size=32,
                type="FUNC", binding="GLOBAL", section=".text",
            )
        }
    )


def test_code_pointer_requires_symbol_page_offset_positive_control():
    """A plausible mapping-range word is not enough to call it code."""
    binary = _binary_with_symbol(0x1249)
    wrong = 0x555555555ABC
    valid = 0x555555555249

    rejected = classify_volunteered_output(
        wrong.to_bytes(8, "little"), binary, pie_enabled=True,
    )
    accepted = classify_volunteered_output(
        valid.to_bytes(8, "little"), binary, pie_enabled=True,
    )

    assert rejected.state is HarvestState.AMBIGUOUS
    assert all(item.kind is not LeakKind.CODE_POINTER for item in rejected.candidates)
    assert accepted.state is HarvestState.HARVESTED
    code = [item for item in accepted.candidates if item.kind is LeakKind.CODE_POINTER]
    assert [(item.value, item.symbol, item.base) for item in code] == [
        (valid, "vuln", 0x555555554000),
    ]


def test_classifier_distinguishes_not_present_from_ambiguous():
    binary = _binary_with_symbol(0x1249)

    absent = classify_volunteered_output(
        b"ordinary prompt only", binary, pie_enabled=True,
    )
    ambiguous = classify_volunteered_output(
        (0x555555555ABC).to_bytes(8, "little"),
        binary,
        pie_enabled=True,
    )

    assert absent.state is HarvestState.NOT_PRESENT
    assert ambiguous.state is HarvestState.AMBIGUOUS


def test_harvest_registers_validated_pie_base_and_raw_canary():
    binary = _binary_with_symbol(0x1249)
    pie = ExploitContext(binary=binary, protections=Protections(pie=True))
    canary = ExploitContext(binary=binary, protections=Protections(canary=True))
    pointer = 0x655555555249
    canary_value = 0x9A71E2436D5C2B00

    harvest_volunteered_output(pie, pointer.to_bytes(8, "little"))
    harvest_volunteered_output(
        canary, b"Relay: " + canary_value.to_bytes(8, "little"),
    )

    assert pie.leaks["binary_base"] == 0x655555554000
    assert pie.leaks["pie_symbol_offset"] == 0x1249
    assert canary.stack.canary_value == canary_value
