"""Consumers of the core ``Protections`` decide on the typed RELRO level.

SP-01 plan section 4.3 (B-4). Before the migration these sites compared the
display string (``"Full RELRO"``) against a different spelling (``"full"``,
``"Full"``, ``"none"``), so the comparison never matched and the Full RELRO
branch was dead: ``StrategySuggester`` offered RET2DLRESOLVE on a Full RELRO
binary, where the GOT is resolved and read-only at startup.

The fixtures are real gcc/gold links; their truth is ``readelf`` (see
``relro_support``). The Full fixtures are asserted dynamic and detected FULL
before any strategy assertion leans on them.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

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

from supwngo.analysis.imports import ImportAnalyzer  # noqa: E402
from supwngo.core.binary import Binary, Protections  # noqa: E402
from supwngo.core.context import ExploitContext  # noqa: E402
from supwngo.core.relro import Relro  # noqa: E402
from supwngo.exploit.chainer import ExploitChainer  # noqa: E402
from supwngo.exploit.pie_bypass import PIEBypassAutomation  # noqa: E402
from supwngo.exploit.pipeline.executors.rop_techniques import (  # noqa: E402
    Ret2DlresolveExecutor,
)
from supwngo.exploit.strategy import ExploitApproach, StrategySuggester  # noqa: E402
from supwngo.vulns.leak_finder import LeakFinder, LeakPrimitive  # noqa: E402

LEVELS = [Relro.NONE, Relro.PARTIAL, Relro.FULL]


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("relro_consumer_fixtures")


def _load(fixture_dir, name) -> Binary:
    path = build_fixture(fixture_dir, name)
    assert readelf_is_dynamic(path)
    binary = Binary.load(str(path))
    assert binary.protections.relro == DISPLAY[readelf_level(path)]
    return binary


@needs_toolchain
@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_strategy_suggester_offers_ret2dlresolve_unless_full_relro(fixture_dir, name):
    binary = _load(fixture_dir, name)
    full = FIXTURES[name][1] == "full"

    report = StrategySuggester(binary).analyze()
    approaches = {s.approach for s in report.strategies}

    assert (ExploitApproach.RET2DLRESOLVE in approaches) is (not full)
    assert any("Full RELRO" in w for w in report.warnings) is full


@pytest.mark.parametrize("kind", LEVELS)
def test_lazy_bindings_exist_only_without_full_relro(kind):
    binary = SimpleNamespace(
        protections=Protections(relro=kind.display), plt={"puts": 0x401030}
    )
    analyzer = ImportAnalyzer(binary)
    analyzer.imports = {
        "puts": SimpleNamespace(is_lazy=False, name="puts"),
    }

    analyzer._analyze_lazy_binding()

    assert bool(analyzer.lazy_bindings) is (kind is not Relro.FULL)


@pytest.mark.parametrize("kind", LEVELS)
def test_pie_partial_overwrite_leak_needs_a_writable_got(kind):
    binary = SimpleNamespace(protections=Protections(pie=True, relro=kind.display))
    finder = LeakFinder(binary)

    finder._find_partial_overwrite_leaks()

    offered = any(
        leak.primitive == LeakPrimitive.PARTIAL_OVERWRITE for leak in finder.leaks
    )
    assert offered is (kind is not Relro.FULL)


@pytest.mark.parametrize("kind", LEVELS)
def test_pie_got_read_strategy_needs_a_writable_got(kind):
    binary = SimpleNamespace(
        protections=Protections(pie=True, relro=kind.display), bits=64
    )
    automation = PIEBypassAutomation(binary)
    automation._has_format_string = lambda: False

    strategies = automation._analyze_leak_opportunities()

    got_read = [s for s in strategies if s.description == "Leak PIE base via GOT read"]
    assert bool(got_read) is (kind is not Relro.FULL)


@pytest.mark.parametrize("kind", LEVELS)
def test_chainer_partial_relro_capability_matches_the_level(kind):
    binary = SimpleNamespace(
        protections=Protections(relro=kind.display), plt={}, bits=64
    )
    chainer = ExploitChainer(binary)

    chainer._analyze_binary_features()

    assert ("partial_relro_or_none" in chainer._available) is (kind is not Relro.FULL)


@pytest.mark.parametrize("kind", LEVELS)
def test_ret2dlresolve_executor_needs_lazy_binding(kind):
    binary = SimpleNamespace(plt={"read": 0x401030})
    context = ExploitContext(binary=binary, protections=Protections(relro=kind.display))

    applicable = Ret2DlresolveExecutor().is_applicable(context)

    assert applicable is (kind is not Relro.FULL)
