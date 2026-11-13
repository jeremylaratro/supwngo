"""RELRO levels and the one function that maps any spelling onto them.

Three spellings of a RELRO level were in use across the code base: the display
strings of ``Protections.relro`` (``"Full RELRO"``), pwntools' ``ELF.relro``
(``"Full"``, ``"Partial"``, ``None``) and hand-written lowercase literals
(``"full"``, ``"none"``). Comparing one spelling against another silently never
matched, so every consumer goes through :func:`normalize_relro` instead.
"""

from enum import Enum
from typing import Any


class Relro(Enum):
    """How much of the GOT the dynamic linker locks after relocation."""

    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"

    @property
    def display(self) -> str:
        """The string ``Protections.relro`` has always carried for this level."""
        return _DISPLAY[self]


_DISPLAY = {
    Relro.NONE: "No RELRO",
    Relro.PARTIAL: "Partial RELRO",
    Relro.FULL: "Full RELRO",
}

_BY_NAME = {
    "none": Relro.NONE,
    "no relro": Relro.NONE,
    "partial": Relro.PARTIAL,
    "partial relro": Relro.PARTIAL,
    "full": Relro.FULL,
    "full relro": Relro.FULL,
}


def normalize_relro(value: Any) -> Relro:
    """Return the :class:`Relro` level for any spelling in use.

    Accepts a :class:`Relro`, the display strings (``"No RELRO"``,
    ``"Partial RELRO"``, ``"Full RELRO"``), pwntools' ``ELF.relro`` values
    (``None``, ``"Partial"``, ``"Full"``) and lowercase forms of either. ``False``
    is accepted as "no RELRO" for pwntools releases that reported a boolean.

    Raises:
        ValueError: for anything else, including ``True``, which says RELRO is
            present without saying which level.
    """
    if isinstance(value, Relro):
        return value
    if value is None or value is False:
        return Relro.NONE
    if isinstance(value, str):
        kind = _BY_NAME.get(value.strip().lower())
        if kind is not None:
            return kind
    raise ValueError(f"unrecognised RELRO value: {value!r}")
