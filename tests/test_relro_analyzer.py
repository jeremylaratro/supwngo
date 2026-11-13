"""ProtectionAnalyzer reads RELRO from pwntools, like the core Binary does.

SP-01 plan section 4.3 (B-4), lead follow-up. ``ProtectionAnalyzer._get_relro_type``
had the same bug class the core fix closed: no ``.got.plt`` section meant Full,
and otherwise only ``DT_FLAGS & DF_BIND_NOW`` and ``DT_BIND_NOW`` were looked at,
so eager binding requested through ``DT_FLAGS_1 & DF_1_NOW`` read as Partial.
The truth is ``readelf -lW -d`` (see ``relro_support``).
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

from supwngo.analysis.protections import ProtectionAnalyzer  # noqa: E402
from supwngo.core.binary import Binary, Section, Segment  # noqa: E402
from supwngo.exploit.walkthrough.facts import _collect_protections  # noqa: E402


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("relro_analyzer_fixtures")


@needs_toolchain
@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_analyzer_reports_the_readelf_level(fixture_dir, name):
    path = build_fixture(fixture_dir, name)
    truth = readelf_level(path)
    assert readelf_is_dynamic(path)

    prots = ProtectionAnalyzer(Binary.load(str(path))).analyze()

    assert prots.relro == DISPLAY[truth]
    assert prots.full_relro is (truth == "full")
    assert prots.partial_relro is (truth == "partial")


@needs_toolchain
@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_walkthrough_cross_check_emits_no_relro_note(fixture_dir, name):
    """The ELF-derived level and the analyzer agree, so no "ELF wins" note."""
    path = build_fixture(fixture_dir, name)
    provenance: list = []

    facts = _collect_protections(Binary.load(str(path)), provenance)

    assert facts.relro == DISPLAY[readelf_level(path)]
    notes = [line for line in provenance if "RELRO derived as" in line]
    assert notes == []


class _FakeElf:
    """Only what ``_get_relro_type`` reads from a pwntools ``ELF``."""

    def __init__(self, relro):
        self.relro = relro


def _binary(pwntools_level, *, segments, sections):
    binary = Binary(path=Path("/nonexistent/relro-fixture"))
    binary._elf = _FakeElf(pwntools_level)
    binary.segments = list(segments)
    binary.sections = dict(sections)
    return binary


RELRO_SEGMENT = Segment(
    type="PT_GNU_RELRO",
    address=0x403E10,
    size=0x1F0,
    offset=0x2E10,
    flags="R--",
    memsz=0x1F0,
)
GOT_PLT = Section(
    name=".got.plt",
    address=0x404000,
    size=0x28,
    offset=0x3000,
    flags=0x3,
    type="SHT_PROGBITS",
    is_writable=True,
)


@pytest.mark.parametrize(
    "pwntools_level, segments, sections, expected",
    [
        # Partial RELRO whose image has no .got.plt section.
        ("Partial", [RELRO_SEGMENT], {}, "Partial RELRO"),
        # Full RELRO with a writable .got.plt and nothing the old probe looks for.
        ("Full", [RELRO_SEGMENT], {".got.plt": GOT_PLT}, "Full RELRO"),
        # Controls the old code already got right.
        (None, [], {".got.plt": GOT_PLT}, "No RELRO"),
        ("Partial", [RELRO_SEGMENT], {".got.plt": GOT_PLT}, "Partial RELRO"),
    ],
)
def test_segment_and_section_shape_do_not_decide_the_level(
    pwntools_level, segments, sections, expected
):
    analyzer = ProtectionAnalyzer(
        _binary(pwntools_level, segments=segments, sections=sections)
    )

    assert analyzer._get_relro_type() == expected


def test_no_elf_still_reports_no_relro():
    binary = Binary(path=Path("/nonexistent/relro-fixture"))
    binary._elf = None

    assert ProtectionAnalyzer(binary)._get_relro_type() == "No RELRO"
