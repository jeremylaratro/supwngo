"""Schema and consistency tests for benchmark/truth/s0/*.yaml (SP-01 plan 2, 2.3).

The schema and plan-table tests are hermetic. The ELF cross-checks read the
shipped binaries from ``tests/htb-targets/organized`` (untracked, as in the other
HTB tests) and skip when that directory is absent.
"""

import struct
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUTH_DIR = REPO_ROOT / "benchmark" / "truth" / "s0"
HTB = REPO_ROOT / "tests" / "htb-targets" / "organized"
sys.path.insert(0, str(REPO_ROOT / "benchmark"))

import passcard_families as pf  # noqa: E402
import passcard_score as ps  # noqa: E402

SLUGS = [
    "sick_rop",
    "rocket_blaster_xxx",
    "snow_scan",
    "ancient_interface",
    "auth-or-out",
    "sabotage",
    "bon-nie-appetit",
]

# Plan 2.3: (vuln_family, method_accept, solve_proven, {kind: value or None}).
PLAN_TABLE = {
    "sick_rop": ("stack_bof", ["srop"], "srop_symtab_pivot", {"buf_to_ret": 40}),
    "rocket_blaster_xxx": (
        "stack_bof",
        ["ret2win", "ret2libc"],
        "ret2libc_leak",
        {"buf_to_ret": 40},
    ),
    "snow_scan": (
        "stack_bof",
        ["srop", "rop_syscall"],
        "container_file_rop",
        {"indexed_base_ptr": None},
    ),
    "ancient_interface": (
        "integer",
        ["rop_syscall", "ret2libc"],
        "eintr_accumulator_rop",
        {"buf_to_ret": 4120, "buf_to_canary": 4104},
    ),
    "auth-or-out": (
        "heap_overflow",
        ["objptr_hijack"],
        "objptr_hijack",
        {"record_to_fnptr": None},
    ),
    "sabotage": ("integer", ["env_hijack"], "env_path_hijack", {"buf_to_var": None}),
    "bon-nie-appetit": (
        "off_by_one",
        ["heap_metadata"],
        "heap_strlen_ofb1",
        {"chunk_to_next_size": None},
    ),
}

# Plan 4.4: which step of the default-function order selects each target.
SELECTOR = {
    "sick_rop": "entry",
    "ancient_interface": "libc_start_main_arg",
}

TOP_KEYS = {
    "slug",
    "format",
    "arch",
    "vuln_family",
    "method_accept",
    "method_basis",
    "solve_proven",
    "distance",
    "decompile",
    "stage",
    "forbidden_symbols",
    "provenance",
}


def load(slug):
    with open(TRUTH_DIR / f"{slug}.yaml") as handle:
        return yaml.safe_load(handle)


def nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def test_exactly_the_seven_s0_files_exist():
    assert sorted(p.stem for p in TRUTH_DIR.glob("*.yaml")) == sorted(SLUGS)


@pytest.mark.parametrize("slug", SLUGS)
def test_schema(slug):
    truth = load(slug)
    assert set(truth) == TOP_KEYS
    assert truth["slug"] == slug
    assert truth["format"] == "elf" and truth["arch"] == "amd64"
    assert truth["vuln_family"] in pf.VULN_FAMILIES
    assert truth["method_accept"] and all(
        family in pf.METHOD_FAMILIES for family in truth["method_accept"]
    )
    assert truth["method_basis"] == "reviewed"  # S0 is smoke, never a gate
    assert nonblank(truth["solve_proven"])
    assert all(isinstance(s, str) for s in truth["forbidden_symbols"])
    for entry in truth["distance"]:
        assert nonblank(entry["kind"]) and nonblank(entry["provenance"])
        assert entry["state"] in ps.TRUTH_STATES
        if entry["state"] == "known_value":
            assert isinstance(entry["value"], int) and entry["value"] > 0
        else:
            assert "value" not in entry
    decompile = truth["decompile"]
    assert isinstance(decompile["vuln_function"]["addr"], int)
    assert nonblank(decompile["vuln_function"]["provenance"])
    defaults = decompile["default_function_any_of"]
    assert defaults and all(isinstance(a, int) for a in defaults)
    anchors = decompile["anchors"]
    assert anchors["calls"] and all(nonblank(c) for c in anchors["calls"])
    assert 1 <= anchors["min_calls"] <= len(anchors["calls"])
    stage = truth["stage"]
    assert stage["files"] and isinstance(stage["placeholders"], list)
    for name in stage["files"] + stage["placeholders"]:
        assert nonblank(name) and "/" not in name and name not in (".", "..")
    expected = {"default_function", "anchors", "stage_files", "placeholders"}
    expected |= {"vuln_family", "method_accept"}
    assert expected <= set(truth["provenance"])
    assert all(nonblank(text) for text in truth["provenance"].values())


@pytest.mark.parametrize("slug", SLUGS)
def test_matches_the_plan_2_3_table(slug):
    vuln, accept, proven, off = PLAN_TABLE[slug]
    truth = load(slug)
    assert truth["vuln_family"] == vuln
    assert truth["method_accept"] == accept
    assert truth["solve_proven"] == proven
    cells = {d["kind"]: d.get("value") for d in truth["distance"]}
    assert cells == off
    for entry in truth["distance"]:
        known = PLAN_TABLE[slug][3][entry["kind"]] is not None
        assert entry["state"] == ("known_value" if known else "unknown")


def test_forbidden_symbols_follow_the_plan_table():
    forbidden = {slug: load(slug)["forbidden_symbols"] for slug in SLUGS}
    assert forbidden.pop("rocket_blaster_xxx") == ["fill_ammo"]
    assert all(symbols == [] for symbols in forbidden.values())


def test_off_cells_are_four_known_and_four_void():
    entries = [d for slug in SLUGS for d in load(slug)["distance"]]
    states = sorted(d["state"] for d in entries)
    assert states == ["known_value"] * 4 + ["unknown"] * 4


@pytest.mark.parametrize("slug", SLUGS)
def test_solve_proven_is_registered_and_lands_in_the_accept_set(slug):
    from supwngo.exploit.pipeline.executors import build_default_registry

    truth = load(slug)
    registered = {executor.name for executor in build_default_registry().all()}
    assert truth["solve_proven"] in registered
    axis, family = pf.map_name(truth["solve_proven"])
    assert axis == pf.METHOD and family in truth["method_accept"]


def test_only_rocket_needs_a_placeholder():
    placeholders = {slug: load(slug)["stage"]["placeholders"] for slug in SLUGS}
    assert placeholders.pop("rocket_blaster_xxx") == ["flag.txt"]
    assert all(files == [] for files in placeholders.values())


def echo_runs(truth):
    """The runs of a tool that answers every command with the truth itself."""
    accept, anchors = truth["method_accept"][0], truth["decompile"]["anchors"]
    values = {d["kind"]: d.get("value") for d in truth["distance"]}
    calls = "; ".join(f"{name}(0)" for name in anchors["calls"])
    docs = {
        "pwn": {
            "recommended": {"approach": accept, "confidence": 1.0, "priority": 1},
            "strategies": [{"approach": accept, "confidence": 1.0, "priority": 1}],
        },
        "template": {"technique": accept},
        "decompile": {
            "address": hex(truth["decompile"]["default_function_any_of"][0]),
            "code": "void f(void) { " + calls + "; }",
        },
        "offset": {
            "success": True,
            "offset": values.get("buf_to_ret"),
            "canary_offset": values.get("buf_to_canary"),
        },
    }
    import json

    return {c: ps.Run(rc=0, stdout=json.dumps(doc)) for c, doc in docs.items()}


@pytest.mark.parametrize("slug", SLUGS)
def test_the_truth_drives_the_scorer(slug):
    truth = load(slug)
    score = ps.score_target(truth, echo_runs(truth))
    verdicts = {(c.metric, c.kind): c.verdict for c in score.cells}
    for metric in ("METHOD-R0", "METHOD-L", "TEMPLATE", "DECOMP"):
        assert verdicts[(metric, None)] == ps.PASS, metric
    for entry in truth["distance"]:
        want = ps.PASS if entry["state"] == "known_value" else ps.VOID
        assert verdicts[("OFF", entry["kind"])] == want
    assert sum(1 for c in score.cells if c.metric == "ROBUST") == 4
    assert all(c.verdict == ps.PASS for c in score.cells if c.metric == "ROBUST")


# --- cross-checks against the shipped binaries -------------------------------


def _open_elf(slug):
    elftools = pytest.importorskip("elftools.elf.elffile")
    link = HTB / slug
    if not link.exists():
        pytest.skip("tests/htb-targets is not present")
    handle = open(link.resolve(), "rb")
    return handle, elftools.ELFFile(handle), link.resolve()


def _symbols(elf):
    names = {}
    for section in (".symtab", ".dynsym"):
        table = elf.get_section_by_name(section)
        if table is not None:
            for symbol in table.iter_symbols():
                names.setdefault(symbol.name, symbol["st_value"])
    return names


def _read_at(elf, handle, address, size):
    for segment in elf.iter_segments():
        start = segment["p_vaddr"]
        if (
            segment["p_type"] == "PT_LOAD"
            and start <= address < start + segment["p_filesz"]
        ):
            handle.seek(segment["p_offset"] + address - start)
            return handle.read(size)
    raise AssertionError(f"{address:#x} is not file-backed")


def _executable(elf, address):
    return any(
        s["p_type"] == "PT_LOAD"
        and s["p_flags"] & 1
        and s["p_vaddr"] <= address < s["p_vaddr"] + s["p_memsz"]
        for s in elf.iter_segments()
    )


@pytest.mark.parametrize("slug", SLUGS)
def test_default_and_vuln_addresses_match_the_binary(slug):
    handle, elf, _ = _open_elf(slug)
    with handle:
        truth = load(slug)["decompile"]
        (default,) = truth["default_function_any_of"]
        symbols = _symbols(elf)
        assert _executable(elf, default)
        assert _executable(elf, truth["vuln_function"]["addr"])
        selector = SELECTOR.get(slug, "symbol")
        if selector == "symbol":
            assert symbols["main"] == default
        elif selector == "entry":
            assert "main" not in symbols and elf["e_entry"] == default
        else:
            assert "main" not in symbols
            stub = _read_at(elf, handle, elf["e_entry"], 0x30)
            assert b"\x48\xc7\xc7" + struct.pack("<I", default) in stub
        if ".symtab" in {s.name for s in elf.iter_sections()}:
            assert truth["vuln_function"]["addr"] in symbols.values()


@pytest.mark.parametrize("slug", SLUGS)
def test_anchor_names_exist_in_the_binary(slug):
    handle, elf, _ = _open_elf(slug)
    with handle:
        symbols = _symbols(elf)
        for name in load(slug)["decompile"]["anchors"]["calls"]:
            assert name in symbols, name


@pytest.mark.parametrize("slug", SLUGS)
def test_stage_files_match_the_shipped_binary(slug):
    handle, _, real = _open_elf(slug)
    with handle:
        stage = load(slug)["stage"]
        assert stage["files"] == [real.name]
        for placeholder in stage["placeholders"]:
            assert placeholder.encode() in real.read_bytes()
