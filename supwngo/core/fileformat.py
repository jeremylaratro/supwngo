"""
Executable file-format detection and the few header fields later code needs.

``detect_format`` says whether a file is an ELF, a PE or neither, from its
headers alone (``struct``, no third-party parser). The same rules apply to
every caller: a format is claimed only when its headers are complete, so a
truncated or corrupt file is ``unknown`` rather than a guess.

``elf_info`` and ``pe_info`` return the fields the decompile address
normalisation needs: for an ELF, ``e_type``, ``e_entry`` and the lowest
``PT_LOAD`` virtual address; for a PE, ``ImageBase``, ``AddressOfEntryPoint``
(an RVA), the machine type and the optional-header magic.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional, Union

ELF = "elf"
PE = "pe"
UNKNOWN = "unknown"

PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B

_PT_LOAD = 1
# Bytes of the optional header through the Windows-specific fixed fields, which
# hold ImageBase and the section/file alignments.
_OPT_MIN = {PE32_MAGIC: 96, PE32_PLUS_MAGIC: 112}


@dataclass(frozen=True)
class ElfInfo:
    """Header fields of an ELF file.

    ``min_load_vaddr`` is ``None`` when the file has no ``PT_LOAD`` segment.
    """

    bits: int
    e_type: int
    machine: int
    e_entry: int
    min_load_vaddr: Optional[int]


@dataclass(frozen=True)
class PeInfo:
    """Header fields of a PE file. ``entry_rva`` is ``AddressOfEntryPoint``."""

    machine: int
    magic: int
    image_base: int
    entry_rva: int

    @property
    def is_pe32_plus(self) -> bool:
        return self.magic == PE32_PLUS_MAGIC


class _File:
    """Bounds-checked reads at absolute offsets; closes the file on exit."""

    def __init__(self, fh: BinaryIO):
        self._fh = fh
        self.size = os.fstat(fh.fileno()).st_size

    def __enter__(self) -> "_File":
        return self

    def __exit__(self, *exc: object) -> None:
        self._fh.close()

    def read(self, offset: int, length: int) -> Optional[bytes]:
        """``length`` bytes at ``offset``, or ``None`` if they are not all there."""
        if offset < 0 or length < 0 or offset + length > self.size:
            return None
        self._fh.seek(offset)
        data = self._fh.read(length)
        return data if len(data) == length else None


class _Truncated(Exception):
    """A header table the file claims is not fully present."""


@dataclass
class _ElfHeader:
    bits: int
    order: str  # struct byte-order prefix
    e_type: int
    machine: int
    e_entry: int
    e_phoff: int
    e_phentsize: int
    e_phnum: int


def _elf_header(f: _File) -> Optional[_ElfHeader]:
    ident = f.read(0, 16)
    if ident is None or ident[:4] != b"\x7fELF":
        return None
    if ident[4] not in (1, 2) or ident[5] not in (1, 2):
        return None
    bits = 32 if ident[4] == 1 else 64
    order = "<" if ident[5] == 1 else ">"
    fmt = order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    data = f.read(16, struct.calcsize(fmt))
    if data is None:
        return None
    # e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
    # e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    v = struct.unpack(fmt, data)
    return _ElfHeader(bits, order, v[0], v[1], v[3], v[4], v[8], v[9])


def _min_load_vaddr(f: _File, hdr: _ElfHeader) -> Optional[int]:
    """Lowest ``PT_LOAD`` p_vaddr, ``None`` if there is none.

    Raises ``_Truncated`` when the program header table is not all in the file.
    """
    if hdr.e_phnum == 0:
        return None
    if hdr.e_phentsize < (32 if hdr.bits == 32 else 56):
        raise _Truncated("program header entries are too small")
    table = f.read(hdr.e_phoff, hdr.e_phentsize * hdr.e_phnum)
    if table is None:
        raise _Truncated("program header table runs past the end of the file")
    # p_type is first in both layouts. p_vaddr is the third word of an ELF32
    # entry (p_type, p_offset, p_vaddr) and the fourth field of an ELF64 one
    # (p_type, p_flags, p_offset, p_vaddr), at +8 and +16.
    vaddr_fmt, vaddr_at = ("I", 8) if hdr.bits == 32 else ("Q", 16)
    vaddrs = []
    for i in range(hdr.e_phnum):
        base = i * hdr.e_phentsize
        (p_type,) = struct.unpack_from(hdr.order + "I", table, base)
        if p_type == _PT_LOAD:
            (vaddr,) = struct.unpack_from(hdr.order + vaddr_fmt, table, base + vaddr_at)
            vaddrs.append(vaddr)
    return min(vaddrs) if vaddrs else None


def _pe_info(f: _File) -> Optional[PeInfo]:
    if f.read(0, 2) != b"MZ":
        return None
    raw = f.read(0x3C, 4)
    if raw is None:
        return None
    (lfanew,) = struct.unpack("<I", raw)
    if f.read(lfanew, 4) != b"PE\0\0":
        return None
    coff = f.read(lfanew + 4, 20)
    if coff is None:
        return None
    machine, _nsec, _ts, _sym, _nsyms, opt_size, _chars = struct.unpack(
        "<HHIIIHH", coff
    )
    opt = f.read(lfanew + 24, opt_size)
    if opt is None or len(opt) < 2:
        return None
    (magic,) = struct.unpack_from("<H", opt)
    if magic not in _OPT_MIN or len(opt) < _OPT_MIN[magic]:
        return None
    (entry_rva,) = struct.unpack_from("<I", opt, 16)
    if magic == PE32_MAGIC:
        (image_base,) = struct.unpack_from("<I", opt, 28)
    else:
        (image_base,) = struct.unpack_from("<Q", opt, 24)
    return PeInfo(machine, magic, image_base, entry_rva)


def _open(path: Union[str, "os.PathLike[str]"]) -> Optional[_File]:
    """The file at ``path`` ready for reads, or ``None`` if it cannot be read."""
    try:
        fh = open(os.fspath(path), "rb")
    except OSError:
        return None
    try:
        return _File(fh)
    except OSError:
        fh.close()
        return None


def detect_format(path: Union[str, "os.PathLike[str]"]) -> str:
    """Return ``"elf"``, ``"pe"`` or ``"unknown"`` for the file at ``path``.

    ``elf`` needs the ``\\x7fELF`` magic, a valid class and byte order, and a
    complete ELF header. ``pe`` needs all of: the ``MZ`` magic; a readable,
    in-bounds ``e_lfanew``; ``PE\\0\\0`` at that offset; complete COFF and
    optional headers; and an optional-header magic of ``0x10b`` or ``0x20b``.
    Anything else, including an empty, truncated or unreadable file, is
    ``unknown``.
    """
    f = _open(path)
    if f is None:
        return UNKNOWN
    with f:
        if _elf_header(f) is not None:
            return ELF
        if _pe_info(f) is not None:
            return PE
    return UNKNOWN


def elf_info(path: Union[str, "os.PathLike[str]"]) -> Optional[ElfInfo]:
    """Header fields of the ELF at ``path``; ``None`` if it is not a whole ELF.

    ``None`` also covers a program header table that runs past the end of the
    file, so ``min_load_vaddr`` is never a guess.
    """
    f = _open(path)
    if f is None:
        return None
    with f:
        hdr = _elf_header(f)
        if hdr is None:
            return None
        try:
            low = _min_load_vaddr(f, hdr)
        except _Truncated:
            return None
    return ElfInfo(hdr.bits, hdr.e_type, hdr.machine, hdr.e_entry, low)


def pe_info(path: Union[str, "os.PathLike[str]"]) -> Optional[PeInfo]:
    """Header fields of the PE at ``path``; ``None`` unless ``detect_format`` says pe."""
    f = _open(path)
    if f is None:
        return None
    with f:
        return _pe_info(f)


__all__ = [
    "ELF",
    "PE",
    "UNKNOWN",
    "PE32_MAGIC",
    "PE32_PLUS_MAGIC",
    "ElfInfo",
    "PeInfo",
    "detect_format",
    "elf_info",
    "pe_info",
]
