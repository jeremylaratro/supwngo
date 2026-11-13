"""Payoff ("win function") ranker — directive W, phase W-1.

Identifies the payoff/win function of a binary from *static evidence* rather than
from hardcoded names, and returns a ranked candidate list whose top entry is the
payoff. See ``docs/plans/2026-11-13-w1-payoff-ranker-design.md`` (Rev 3).

This module is built up across the W-1 commits (see the plan's §7). Commit 1
establishes the address-normalization primitive: a backend-reported address is
mapped to the **corpus-truth RVA convention** ``rva = address - image_base``.

Why this is a dedicated, separately-tested primitive: ``Decompiler._to_file_address``
returns ``file_base + (address - backend_base)`` — the *link-time VADDR*, which for
a non-PIE ELF or a PE differs from the truth RVA by ``image_base``. The corpus truth
stores ``payoff_rva = address - image_base`` (``benchmark/gen/payoff/generate.py``),
so candidates must be normalized with the RVA convention below, **not** with
``_to_file_address`` directly.
"""

from __future__ import annotations

__all__ = ["to_corpus_rva"]


def to_corpus_rva(backend_addr: int, backend_base: int) -> int:
    """Map a backend-reported address to the corpus-truth RVA convention.

    ``rva = backend_addr - backend_base`` — equivalently
    ``Decompiler._to_file_address(addr, backend_base, file_base) - file_base``.

    ``backend_base`` is the backend's own image base (Ghidra's reported image base
    or angr's ``mapped_base``); for a non-relocated static load it equals the
    file's ``image_base`` (ELF lowest ``PT_LOAD`` vaddr / PE ``ImageBase``), so the
    result equals the truth ``payoff_rva``. No architecture constant (``0x400000``
    etc.) is assumed.

    Raises :class:`TypeError` for non-int inputs (``bool`` rejected) and
    :class:`ValueError` for implausible bases (negative, or an address below the
    image base). Callers turn these into an ``ERROR``/``DEGRADED`` report rather
    than silently dropping a found payoff — a normalization failure must never
    masquerade as a legitimate empty (negative) result.
    """
    for name, value in (("backend_addr", backend_addr), ("backend_base", backend_base)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if backend_addr < 0 or backend_base < 0:
        raise ValueError(
            f"addresses must be non-negative "
            f"(addr=0x{backend_addr:x}, base=0x{backend_base:x})"
        )
    rva = backend_addr - backend_base
    if rva < 0:
        raise ValueError(
            f"address 0x{backend_addr:x} is below image base 0x{backend_base:x}"
        )
    return rva
