"""Mapping-coverage tests for benchmark/passcard_families.py (SP-01 plan 2.2).

The three vocabularies are enumerated at runtime from the product, so a name
added to ``ExploitApproach``, to ``template -t`` or to the executor registry
without a mapping fails here rather than scoring as ``unmapped`` in a run.
"""

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE = REPO_ROOT / "benchmark" / "passcard_families.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "passcard_families_under_test", MODULE
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


pf = _load()

PLAN_METHOD_FAMILIES = (
    "ret2win",
    "ret2libc",
    "rop_syscall",
    "srop",
    "ret2dlresolve",
    "shellcode",
    "stack_pivot",
    "one_gadget",
    "fmt_write",
    "got_overwrite",
    "objptr_hijack",
    "heap_metadata",
    "fsop",
    "data_only",
    "env_hijack",
)
PLAN_VULN_FAMILIES = (
    "stack_bof",
    "heap_overflow",
    "uaf",
    "double_free",
    "integer",
    "format_string",
    "off_by_one",
    "logic",
)


def _approach_names():
    from supwngo.exploit.strategy import ExploitApproach

    return [member.name for member in ExploitApproach]


def _template_choices():
    from supwngo.cli import cli

    for param in cli.commands["template"].params:
        if param.name == "technique":
            return list(param.type.choices)
    raise AssertionError("template has no -t/--technique option")


def _registry_ids():
    from supwngo.exploit.pipeline.executors import build_default_registry

    return [executor.name for executor in build_default_registry().all()]


def test_families_equal_the_plan_lists_in_order():
    assert pf.METHOD_FAMILIES == PLAN_METHOD_FAMILIES
    assert pf.VULN_FAMILIES == PLAN_VULN_FAMILIES
    assert len(pf.METHOD_FAMILIES) == 15
    assert len(pf.VULN_FAMILIES) == 8


@pytest.mark.parametrize(
    "vocabulary, table",
    [
        (_approach_names, "APPROACH_MAP"),
        (_template_choices, "TEMPLATE_MAP"),
        (_registry_ids, "TECHNIQUE_MAP"),
    ],
    ids=["approach", "template", "registry"],
)
def test_every_runtime_name_maps_and_no_entry_is_stale(vocabulary, table):
    names = vocabulary()
    assert names, "vocabulary enumerated empty"
    table_keys = set(getattr(pf, table))
    assert table_keys == set(names)
    for name in names:
        assert pf.map_name(name) is not None, name


def test_mappings_are_well_formed():
    for name, (axis, value) in pf.NAME_MAP.items():
        if axis == pf.METHOD:
            assert value in pf.METHOD_FAMILIES, name
        elif axis == pf.VULN:
            assert value in pf.VULN_FAMILIES, name
        else:
            assert axis == pf.UNSCORED, name
            assert value.strip(), f"{name} is unscored without a reason"


def test_a_name_shared_across_vocabularies_maps_identically():
    for shared in ("ret2win", "srop", "ret2dlresolve"):
        assert pf.APPROACH_MAP[shared.upper()] == pf.TECHNIQUE_MAP[shared]
    assert pf.APPROACH_MAP["RET2WIN"] == pf.TEMPLATE_MAP["ret2win"]
    assert pf.APPROACH_MAP["SROP"] == pf.TEMPLATE_MAP["srop"]


def test_conflicting_duplicate_mapping_is_refused():
    with pytest.raises(ValueError):
        pf._merge({"A": ("method", "srop")}, {"a": ("method", "ret2win")})


@pytest.mark.parametrize(
    "name, expected",
    [
        ("ROP_SYSTEM", ("method", "ret2libc")),
        ("ret2system", ("method", "ret2libc")),
        ("ROP_EXECVE", ("method", "rop_syscall")),
        ("SROP", ("method", "srop")),
        ("RET2PLT", ("method", "ret2libc")),
        ("FORMAT_STRING", ("method", "fmt_write")),
        ("NEGATIVE_SIZE_BYPASS", ("vuln", "integer")),
        ("uaf", ("vuln", "uaf")),
        ("off_by_one_guard", ("vuln", "off_by_one")),
        ("container_file_rop", ("method", "rop_syscall")),
        ("eintr_accumulator_rop", ("method", "ret2libc")),
        ("env_path_hijack", ("method", "env_hijack")),
        ("heap_strlen_ofb1", ("method", "heap_metadata")),
        ("objptr_hijack", ("method", "objptr_hijack")),
        ("srop_symtab_pivot", ("method", "srop")),
        ("fsop_stdout_read", ("method", "fsop")),
        ("  Ret2Libc  ", ("method", "ret2libc")),
    ],
)
def test_spot_checks(name, expected):
    assert pf.map_name(name) == expected


@pytest.mark.parametrize("name", ["SECCOMP_BYPASS", "leak", "auto"])
def test_unscored_names_carry_a_reason(name):
    axis, reason = pf.map_name(name)
    assert axis == pf.UNSCORED
    assert reason


@pytest.mark.parametrize("family", PLAN_METHOD_FAMILIES)
def test_a_bare_method_family_name_maps_to_itself(family):
    assert pf.map_name(family) == ("method", family)
    assert pf.map_name(family.upper()) == ("method", family)


@pytest.mark.parametrize("name", ["FOO_BAR", "", "integer", None, 7])
def test_unknown_names_are_none(name):
    assert pf.map_name(name) is None


def test_s0_solve_proven_techniques_land_in_their_accept_sets():
    proven = {
        "srop_symtab_pivot": {"srop"},
        "ret2libc_leak": {"ret2win", "ret2libc"},
        "container_file_rop": {"srop", "rop_syscall"},
        "eintr_accumulator_rop": {"rop_syscall", "ret2libc"},
        "objptr_hijack": {"objptr_hijack"},
        "env_path_hijack": {"env_hijack"},
        "heap_strlen_ofb1": {"heap_metadata"},
    }
    for technique, accept in proven.items():
        axis, family = pf.map_name(technique)
        assert axis == pf.METHOD and family in accept, technique
