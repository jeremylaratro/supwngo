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


def _binary_with_symbols(spec):
    """spec: {name: (offset, elf_type)} -> a stub exposing .symbols."""
    return SimpleNamespace(
        symbols={
            name: Symbol(
                name=name, address=off, size=32,
                type=sym_type, binding="GLOBAL", section=None,
            )
            for name, (off, sym_type) in spec.items()
        }
    )


def test_data_symbol_is_not_a_valid_code_pointer_anchor():
    """A DATA symbol must never anchor a PIE base.

    Measured on corpus_r2/05: `_end` (+0x4020, STT_NOTYPE) collides on low 12
    bits with unrelated stack values, and the base it implies is page-aligned,
    so page-alignment does not catch it either. Accepting it yields a confident
    wrong base.
    """
    binary = _binary_with_symbols({
        "_end": (0x4020, "STT_NOTYPE"),
        "vuln": (0x1321, "STT_FUNC"),
    })

    # low 12 bits 0x020 -> matches _end only, never the function.
    data_only = classify_volunteered_output(
        (0x555555556020).to_bytes(8, "little"), binary, pie_enabled=True,
    )
    assert all(
        item.kind is not LeakKind.CODE_POINTER for item in data_only.candidates
    ), "a data symbol was accepted as a code-pointer anchor"

    # Positive half: the function anchor must still work, or this test could
    # pass simply because classification was disabled altogether.
    func = classify_volunteered_output(
        (0x555555555321).to_bytes(8, "little"), binary, pie_enabled=True,
    )
    code = [i for i in func.candidates if i.kind is LeakKind.CODE_POINTER]
    assert [(i.symbol, i.base) for i in code] == [("vuln", 0x555555554000)]


def test_page_aligned_leak_is_not_a_code_pointer():
    """The degenerate low-12-bits-zero class must be excluded outright.

    Any page-aligned value matches every page-aligned symbol. `_init` is a real
    STT_FUNC at offset 0x1000, so a function-only filter alone does NOT close
    this; it needs its own exclusion.
    """
    binary = _binary_with_symbols({
        "_init": (0x1000, "STT_FUNC"),
        "vuln": (0x1321, "STT_FUNC"),
    })

    aligned = classify_volunteered_output(
        (0x555555554000).to_bytes(8, "little"), binary, pie_enabled=True,
    )
    assert all(
        item.kind is not LeakKind.CODE_POINTER for item in aligned.candidates
    ), "a page-aligned value was accepted via the degenerate match class"

    func = classify_volunteered_output(
        (0x555555555321).to_bytes(8, "little"), binary, pie_enabled=True,
    )
    assert any(i.kind is LeakKind.CODE_POINTER for i in func.candidates)
