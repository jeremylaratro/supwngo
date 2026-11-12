"""RT-06 / RT-07 regression: ``stripped`` and ``uses_tcache`` reported facts.

Two reported-fact defects from the 2026-09 retest:

* **RT-06 (stripped):** ``_check_stripped`` returned ``len(symbols) < 10``.
  ``strip(1)`` removes ``.symtab`` but keeps ``.dynsym``, so a stripped dynamic
  binary still carries symbols (reported *not* stripped), while a tiny unstripped
  SROP target has few symbols (reported stripped). The fact keys on ``.symtab``
  presence, not a symbol count.

* **RT-07 (tcache):** ``_check_tcache`` reported tcache purely from a libc
  version string, so a statically linked pure-syscall target with no allocator
  reported ``uses_tcache: true`` (false positive), while a dynamic malloc target
  reported ``uses_tcache: false`` because ``_detect_libc_version`` read a
  ``GLIBC_2.x`` *symbol-version requirement tag* (e.g. ``malloc@@GLIBC_2.2.5``)
  as if it were the runtime libc release (false negative). tcache is a property
  of allocator *use*; the gate is actual malloc/free linkage, and the version is
  read only from a real glibc *release banner*.

The fake-binary tests drive the real ``ProtectionAnalyzer`` helpers through the
exact attribute surface they touch (``sections``/``plt``/``symbols``/
``strings()``), so they are deterministic and fail on the pre-fix code. The
parametrized tests pin the end-to-end facts on the real HTB targets.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from supwngo.analysis.protections import ProtectionAnalyzer


class _FakeBinary:
    """Minimal stand-in exposing only the surface the gated helpers read."""

    def __init__(self, *, sections=(), plt=(), symbols=(), strings=()):
        self.sections = list(sections)
        self.plt = dict.fromkeys(plt)
        self.symbols = dict.fromkeys(symbols)
        self._strings = list(strings)
        self.path = "/nonexistent/fake-binary"

    def strings(self):
        return list(self._strings)


def _analyzer(**kwargs) -> ProtectionAnalyzer:
    return ProtectionAnalyzer(_FakeBinary(**kwargs))


# --------------------------------------------------------------------------- #
# RT-06: stripped keys on .symtab, not a symbol count
# --------------------------------------------------------------------------- #

def test_stripped_true_when_symtab_absent_despite_many_dynsyms():
    """A stripped binary drops ``.symtab`` but keeps a populated ``.dynsym``.
    RED on base: ``len(symbols) < 10`` is False for these 12 dynsyms, so base
    reports *not* stripped."""
    many = tuple(f"sym{i}" for i in range(12))
    a = _analyzer(sections=[".dynsym", ".text", ".plt"], symbols=many)
    assert a._check_stripped() is True


def test_stripped_false_when_symtab_present_despite_few_symbols():
    """A tiny unstripped target (e.g. a minimal SROP binary) has few symbols but
    keeps ``.symtab``. RED on base: ``len(symbols) < 10`` is True for these 2
    symbols, so base reports stripped."""
    a = _analyzer(sections=[".symtab", ".dynsym", ".text"], symbols=("main", "_start"))
    assert a._check_stripped() is False


# --------------------------------------------------------------------------- #
# RT-07: tcache gates on allocator use, version from a release banner only
# --------------------------------------------------------------------------- #

def test_tcache_false_without_allocator():
    """No malloc/free anywhere -> no tcache, regardless of any libc string.
    RED on base: with no allocator gate and no version string, base falls to its
    ``return True`` default (the sick_rop false positive)."""
    a = _analyzer(plt=(), symbols=("main", "_start", "read", "write"), strings=[])
    assert a._check_tcache() is False


def test_tcache_false_without_allocator_even_with_modern_glibc_tag():
    """The allocator gate dominates any version string: a binary that imports no
    allocator but happens to carry a modern ``GLIBC_2.34`` tag still has no
    tcache. RED on base: base reads 2.34 and returns True."""
    a = _analyzer(
        plt=("puts", "printf"),
        symbols=("main",),
        strings=[(0x1000, "puts@@GLIBC_2.34"), (0x1008, "GLIBC_2.34")],
    )
    assert a._check_tcache() is False


def test_tcache_true_with_allocator_and_only_symbol_version_tags():
    """The bon-nie-appetit case: a dynamic malloc target whose only version
    strings are ``GLIBC_2.x`` *requirement tags*. Those are a minimum ABI, not
    the runtime libc, so with the allocator present we assume a modern (tcache)
    glibc. RED on base: ``_detect_libc_version`` reads ``2.2`` and returns
    False (the false negative)."""
    a = _analyzer(
        plt=("malloc", "free"),
        symbols=("main",),
        strings=[(0x1000, "malloc@@GLIBC_2.2.5"), (0x1008, "free@@GLIBC_2.2.5")],
    )
    assert a._check_tcache() is True


def test_tcache_true_with_allocator_and_no_version_strings():
    """Allocator present, no version string at all -> assume modern tcache
    glibc rather than guess old."""
    a = _analyzer(plt=("malloc", "free"), symbols=("main",), strings=[])
    assert a._check_tcache() is True


def test_tcache_true_with_allocator_and_modern_release_banner():
    """A real glibc release banner >= 2.26 confirms tcache."""
    a = _analyzer(
        symbols=("malloc", "free", "main"),
        strings=[(0x1000, "GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9) stable release version 2.31.")],
    )
    assert a._check_tcache() is True


def test_tcache_false_with_allocator_and_old_release_banner():
    """A genuinely old glibc (release banner < 2.26) has no tcache even with an
    allocator. RED on base: base finds no ``GLIBC_`` tag in this banner and
    falls to ``return True``."""
    a = _analyzer(
        symbols=("malloc", "free", "main"),
        strings=[(0x1000, "GNU C Library (GNU libc) stable release version 2.23, by Roland McGrath et al.")],
    )
    assert a._check_tcache() is False


# --------------------------------------------------------------------------- #
# _detect_glibc_release_version: banner only, never a symbol-version tag
# --------------------------------------------------------------------------- #

def test_release_version_ignores_symbol_version_tags():
    a = _analyzer(strings=[(0x1000, "malloc@@GLIBC_2.2.5"), (0x1008, "GLIBC_2.4")])
    assert a._detect_glibc_release_version() == ""


def test_release_version_reads_stable_release_banner():
    a = _analyzer(strings=[(0x1000, "GNU C Library ... stable release version 2.31.")])
    assert a._detect_glibc_release_version() == "2.31"


def test_release_version_reads_distro_glibc_banner():
    a = _analyzer(strings=[(0x1000, "Ubuntu GLIBC 2.35-0ubuntu3.6")])
    assert a._detect_glibc_release_version() == "2.35"


# --------------------------------------------------------------------------- #
# End-to-end on the real HTB targets (skip when the gitignored binary is absent)
# --------------------------------------------------------------------------- #

_HTB = Path(__file__).parent / "htb-targets" / "organized"

# (name, expected_stripped, expected_uses_tcache), ground-truthed via file/nm/readelf:
#   sick_rop/rocket_blaster_xxx/auth-or-out: no allocator -> no tcache
#   snow_scan: static glibc embedding malloc -> tcache
#   sabotage/bon-nie-appetit: dynamic malloc -> tcache
#   ancient_interface: stripped (.symtab removed), calloc -> tcache
_EXPECTED = [
    ("sick_rop", False, False),
    ("rocket_blaster_xxx", False, False),
    ("snow_scan", False, True),
    ("auth-or-out", False, False),
    ("sabotage", False, True),
    ("bon-nie-appetit", False, True),
    ("ancient_interface", True, True),
]


@pytest.mark.parametrize("name,exp_stripped,exp_tcache", _EXPECTED)
def test_real_target_stripped_and_tcache(name, exp_stripped, exp_tcache):
    target = _HTB / name
    if not target.exists():
        pytest.skip(f"HTB target {name} not present (gitignored)")

    from supwngo.core.binary import Binary

    analyzer = ProtectionAnalyzer(Binary.load(str(target)))
    assert analyzer._check_stripped() is exp_stripped, f"{name} stripped"
    assert analyzer._check_tcache() is exp_tcache, f"{name} uses_tcache"
