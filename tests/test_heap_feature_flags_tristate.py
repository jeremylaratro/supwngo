"""CG-01a: feature/feasibility verdicts read "unknown" on an unknown libc.

Unlike the offset-byte-critical paths (which refuse), capability/feasibility
APIs keep returning, but an unknown libc version yields an *unknown* tri-state
rather than a fabricated 2.31-derived true/false. On base ``dc22067`` these all
defaulted to glibc 2.31 (or 2.27 for House of Storm) and returned a definite
answer.
"""

from supwngo.exploit.heap.house_of_spirit import HouseOfSpirit
from supwngo.exploit.heap.large_bin import HouseOfStorm
from supwngo.exploit.heap.techniques import (
    HeapExploitConfig,
    HeapExploiter,
    HeapTechnique,
)
from supwngo.vulns.off_by_one import NullByteExploiter

TARGET = 0x404000


class _MockBinary:
    bits = 64
    path = type("obj", (object,), {"name": "test"})()


def test_heap_config_flags_default_unknown():
    cfg = HeapExploitConfig()
    assert cfg.libc_version is None
    # RED on base: base defaulted has_tcache=True, has_safe_linking=False.
    assert cfg.has_tcache is None
    assert cfg.has_safe_linking is None


def test_select_technique_unknown_surfaces_diagnostic():
    ex = HeapExploiter(_MockBinary())
    techs = ex.select_technique("uaf", "")  # empty -> unknown (config None)
    # RED on base: no such attribute existed (base always had a known version).
    assert ex.last_libc_version_known is False
    assert isinstance(techs, list)
    # Conservative set still offers tcache; the 2.32+ safe-linking requirement
    # is left undetermined rather than asserted.
    assert HeapTechnique.TCACHE_POISONING in techs
    assert HeapTechnique.SAFE_LINKING_BYPASS not in techs


def test_select_technique_known_sets_flag_true():
    ex = HeapExploiter(_MockBinary())
    ex.select_technique("uaf", "2.35")
    assert ex.last_libc_version_known is True


def test_house_of_spirit_unknown_bin_type():
    hos = HouseOfSpirit()
    assert hos.has_tcache is None
    v = hos.validate_chunk_size(0x40, use_tcache=True)
    # RED on base: base defaulted 2.31 -> bin_type "tcache".
    assert v["bin_type"] == "unknown"
    # 0x40 is within BOTH the fastbin (0x80) and tcache (0x410) maxima, so the
    # verdict is decidable (valid) even without knowing the version.
    assert v["valid"] is True


def test_house_of_spirit_unknown_size_limit_is_indeterminate():
    # Review finding 3: 0x400 fits the tcache max (0x410) but exceeds the
    # fastbin max (0x80), so validity depends on the unknown active bin -> the
    # verdict must be *indeterminate* (None), never a fabricated pass.
    v = HouseOfSpirit().validate_chunk_size(0x400, use_tcache=True)
    assert v["valid"] is None
    # A size over even the tcache max is invalid under any bin -> decidable False.
    assert HouseOfSpirit().validate_chunk_size(0x500, use_tcache=True)["valid"] is False
    # A version-independent failure (misaligned) still decides False, not None.
    assert HouseOfSpirit().validate_chunk_size(0x401, use_tcache=True)["valid"] is False


def test_house_of_spirit_known_bin_type_unchanged():
    assert (
        HouseOfSpirit(libc_version="2.31")
        .validate_chunk_size(0x40, use_tcache=True)["bin_type"]
        == "tcache"
    )
    assert (
        HouseOfSpirit(libc_version="2.23")
        .validate_chunk_size(0x40, use_tcache=True)["bin_type"]
        == "fastbin"
    )


def test_house_of_storm_unknown_feasibility():
    res = HouseOfStorm().check_feasibility()
    # RED on base: base defaulted "2.27" -> feasible True.
    assert res["feasible"] is None


def test_house_of_storm_known_feasibility_unchanged():
    assert HouseOfStorm(libc_version="2.27").check_feasibility()["feasible"] is True
    assert HouseOfStorm(libc_version="2.31").check_feasibility()["feasible"] is False


def test_nullbyte_einherjar_unknown_feasibility():
    nb = NullByteExploiter()
    assert nb.minor is None
    res = nb.house_of_einherjar(0x40, TARGET)
    # RED on base: base defaulted "2.31" -> minor 31 < 29 == False.
    assert res["feasible"] is None


def test_nullbyte_einherjar_known_feasibility_unchanged():
    assert (
        NullByteExploiter(libc_version="2.27").house_of_einherjar(0x40, TARGET)[
            "feasible"
        ]
        is True
    )
    assert (
        NullByteExploiter(libc_version="2.31").house_of_einherjar(0x40, TARGET)[
            "feasible"
        ]
        is False
    )
