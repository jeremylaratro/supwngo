"""Binary protection detection reports the real RELRO level (SP-01 plan 4.3).

``Binary._detect_protections`` used to treat pwntools' RELRO level as a boolean
and then infer Full versus Partial from whether a ``.got.plt`` section carried
the write flag. A linker that keeps ``.got.plt`` under ``-z now`` (gold does)
therefore read as Partial. The level now comes from pwntools directly, and the
truth here is ``readelf -lW -d``.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from relro_support import (  # noqa: E402
    DISPLAY,
    FIXTURES,
    build_fixture,
    needs_toolchain,
    readelf_is_dynamic,
    readelf_level,
)

pytest.importorskip("pwn")

from supwngo.core.binary import Binary, Section  # noqa: E402


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("relro_fixtures")


@needs_toolchain
@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_fixture_matches_the_link_flags(fixture_dir, name):
    """Positive control: readelf agrees with what each fixture was linked for.

    Without this a mislinked fixture would make every assertion below vacuous.
    """
    path = build_fixture(fixture_dir, name)
    assert readelf_is_dynamic(path), "a RELRO fixture must be a dynamic executable"
    assert readelf_level(path) == FIXTURES[name][1]


@needs_toolchain
@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_detected_relro_matches_readelf(fixture_dir, name):
    path = build_fixture(fixture_dir, name)
    truth = readelf_level(path)
    # The Full image must be dynamic and read as Full before any strategy
    # assertion elsewhere is allowed to lean on it.
    assert readelf_is_dynamic(path)

    binary = Binary.load(str(path))

    assert binary.protections_measured is True
    assert binary.protections.relro == DISPLAY[truth]


class _FakeElf:
    """Only what ``_detect_protections`` reads from a pwntools ``ELF``."""

    def __init__(self, relro):
        self.canary = False
        self.nx = True
        self.pie = False
        self.relro = relro


def _section(name, *, writable):
    return Section(
        name=name,
        address=0x404000,
        size=0x28,
        offset=0x3000,
        flags=0x3 if writable else 0x2,
        type="SHT_PROGBITS",
        is_writable=writable,
    )


@pytest.mark.parametrize(
    "pwntools_level, sections, expected",
    [
        # The gold shape: Full RELRO with a writable .got.plt still present.
        ("Full", {".got.plt": _section(".got.plt", writable=True)}, "Full RELRO"),
        # Partial RELRO with no .got.plt section at all.
        ("Partial", {}, "Partial RELRO"),
        # Partial RELRO with a read-only .got.plt flag.
        (
            "Partial",
            {".got.plt": _section(".got.plt", writable=False)},
            "Partial RELRO",
        ),
        (None, {".got.plt": _section(".got.plt", writable=True)}, "No RELRO"),
    ],
)
def test_section_flags_do_not_decide_the_level(pwntools_level, sections, expected):
    binary = Binary(path=Path("/nonexistent/relro-fixture"))
    binary._elf = _FakeElf(pwntools_level)
    binary.sections = dict(sections)

    binary._detect_protections()

    assert binary.protections_measured is True
    assert binary.protections.relro == expected
