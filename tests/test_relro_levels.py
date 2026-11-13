"""The RELRO level type and its normaliser (SP-01 plan section 4.3).

``Protections.relro`` stays the display string every legacy reader and JSON
consumer sees. ``Protections.relro_kind`` is the typed level, and
``normalize_relro`` is the one place that maps any spelling onto it.
"""

import json
import sys
from dataclasses import fields
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from relro_support import (  # noqa: E402
    DISPLAY,
    build_fixture,
    needs_toolchain,
    readelf_is_dynamic,
    readelf_level,
)

from supwngo.core.relro import Relro, normalize_relro  # noqa: E402

pytest.importorskip("pwn")

from supwngo.analysis.protections import DetailedProtections  # noqa: E402
from supwngo.core.binary import Binary, Protections  # noqa: E402

#: Every spelling the codebase and its tools have produced for each level.
SPELLINGS = {
    Relro.NONE: [None, False, "No RELRO", "no relro", "none", "None", "NONE"],
    Relro.PARTIAL: ["Partial RELRO", "partial relro", "Partial", "partial"],
    Relro.FULL: ["Full RELRO", "FULL RELRO", "full relro", "Full", "full"],
}

DISPLAY_BY_KIND = {
    Relro.NONE: "No RELRO",
    Relro.PARTIAL: "Partial RELRO",
    Relro.FULL: "Full RELRO",
}


@pytest.mark.parametrize("kind", list(Relro))
def test_every_spelling_of_a_level_normalises_to_it(kind):
    for spelling in SPELLINGS[kind]:
        assert normalize_relro(spelling) is kind, repr(spelling)


@pytest.mark.parametrize("kind", list(Relro))
def test_a_level_normalises_to_itself_and_has_a_display_string(kind):
    assert normalize_relro(kind) is kind
    assert kind.display == DISPLAY_BY_KIND[kind]
    assert normalize_relro(kind.display) is kind


def test_the_enum_has_exactly_three_levels():
    assert {k.name for k in Relro} == {"NONE", "PARTIAL", "FULL"}


@pytest.mark.parametrize(
    "bad", ["", "   ", "Half RELRO", "fulll", "full relro!", "yes", True, 1, [], {}]
)
def test_unknown_values_raise(bad):
    with pytest.raises(ValueError):
        normalize_relro(bad)


def test_the_error_names_the_offending_value():
    with pytest.raises(ValueError, match="Half RELRO"):
        normalize_relro("Half RELRO")


@pytest.mark.parametrize("kind", list(Relro))
def test_protections_relro_kind_follows_the_display_string(kind):
    prots = Protections(relro=DISPLAY_BY_KIND[kind])
    assert prots.relro_kind is kind


@pytest.mark.parametrize("kind", list(Relro))
def test_relro_kind_tracks_later_assignment_to_relro(kind):
    """``ProtectionAnalyzer.analyze`` assigns ``relro`` after construction."""
    prots = DetailedProtections()
    prots.relro = DISPLAY_BY_KIND[kind]
    assert prots.relro_kind is kind


def test_relro_kind_is_not_a_dataclass_field():
    """It is derived, so it cannot go stale and cannot reach the wire format."""
    assert "relro_kind" not in {f.name for f in fields(Protections)}
    assert "relro_kind" not in {f.name for f in fields(DetailedProtections)}


# The wire format captured from the base commit (992986e), key order included.
LEGACY_JSON = (
    '{"canary": true, "nx": true, "pie": false, "relro": "Partial RELRO", '
    '"fortify": false, "aslr": true}'
)


def test_legacy_json_round_trips_byte_identically():
    prots = Protections(**json.loads(LEGACY_JSON))

    assert json.dumps(prots.to_dict()) == LEGACY_JSON
    assert prots.relro_kind is Relro.PARTIAL
    assert "relro_kind" not in prots.to_dict()
    assert "relro_kind" not in prots.__dict__


@pytest.mark.parametrize("kind", list(Relro))
def test_every_level_serialises_to_its_display_string(kind):
    wire = Protections(relro=DISPLAY_BY_KIND[kind]).to_dict()
    assert wire["relro"] == DISPLAY_BY_KIND[kind]
    assert list(wire) == ["canary", "nx", "pie", "relro", "fortify", "aslr"]


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("relro_level_fixtures")


@needs_toolchain
@pytest.mark.parametrize(
    "name, kind",
    [
        ("norelro", Relro.NONE),
        ("relro_lazy", Relro.PARTIAL),
        ("relro_now", Relro.FULL),
        ("relro_now_gold", Relro.FULL),
    ],
)
def test_loaded_binary_reports_the_readelf_level(fixture_dir, name, kind):
    path = build_fixture(fixture_dir, name)
    assert readelf_is_dynamic(path)
    assert DISPLAY[readelf_level(path)] == DISPLAY_BY_KIND[kind]

    binary = Binary.load(str(path))

    assert binary.protections.relro_kind is kind
    assert binary.protections.relro == DISPLAY_BY_KIND[kind]
