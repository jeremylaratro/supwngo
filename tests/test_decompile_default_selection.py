"""SP-01b 4.4 / V-9: ``decompile`` with no ``-f`` picks a default function.

The CLI used to force ``main`` when no function was named, so a binary with no
``main`` symbol (stripped, or built without one) decompiled nothing. It now
sends the empty selector and the backend searches, reporting how in
``selected_by``:

* ELF: ``symbol`` (a ``main`` symbol), ``libc_start_main_arg`` (the first
  argument of the entry function's call to ``__libc_start_main``), ``entry``
  (no such call), ``first_reachable`` (a breadth-first walk from the entry);
* PE: ``symbol``, ``mingw_crt_main_arg`` (the function whose result the CRT start
  passes to ``exit``), ``entry``. ``first_reachable`` is never used for a PE;
* an explicit ``-f`` is ``name`` or ``addr``.

Hermetic tests cover the CLI, the argument plumbing (entry offset for a PIE and
a non-PIE, checked against ``readelf``/``objdump``, not against the code under
test), the RetDec bypass and each angr step with a fake project. Tool-tier tests
(``SUPWNGO_REQUIRE_GHIDRA=1``) run the real backends on built fixtures and
compare the address with ``nm`` and the PE headers, and assert a code anchor, not
merely non-empty code.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))
from ghidra_support import need_ghidra  # noqa: E402

import supwngo.analysis._angr_subprocess as sub  # noqa: E402
import supwngo.analysis.decompile as decompile_mod  # noqa: E402
from supwngo.analysis.decompile import DecompiledFunction, Decompiler  # noqa: E402
from supwngo.core.proc import ProcState  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures" / "decompile_default"
NOMAIN_S = FIXTURES / "nomain.S"
NOMAIN_DYN_C = FIXTURES / "nomain_dyn.c"
PE_SYM = REPO / "benchmark" / "fixtures" / "s0pe" / "pe_sym.exe"
PE_STRIP = REPO / "benchmark" / "fixtures" / "s0pe" / "pe_strip.exe"

GCC = shutil.which("gcc")
NM = shutil.which("nm")
STRIP = shutil.which("strip")

# The user ``main`` of the S0-PE fixtures (truth/s0pe, objdump convention).
PE_USER_MAIN = 0x14000156F


@pytest.fixture(autouse=True)
def _generous_ghidra_budget(monkeypatch):
    """The host is shared and often loaded; the default 180 s can be too tight."""
    monkeypatch.setattr(decompile_mod, "DEFAULT_GHIDRA_TIMEOUT", 600.0)


def _build(cmd):
    built = subprocess.run(cmd, capture_output=True, text=True)
    assert built.returncode == 0, built.stderr


def _nm_address(binary: Path, symbol: str) -> int:
    out = subprocess.run([NM, str(binary)], capture_output=True, text=True, timeout=30)
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "Tt" and parts[2] == symbol:
            return int(parts[0], 16)
    raise AssertionError(f"{symbol} not in nm output of {binary}")


def _readelf_entry_rva(binary: Path) -> int:
    """``e_entry - min(PT_LOAD.p_vaddr)`` from ``readelf``, independent of the code."""
    header = subprocess.run(
        ["readelf", "-hW", str(binary)], capture_output=True, text=True
    ).stdout
    entry = int(re.search(r"Entry point address:\s+(0x[0-9a-f]+)", header).group(1), 16)
    segments = subprocess.run(
        ["readelf", "-lW", str(binary)], capture_output=True, text=True
    ).stdout
    low = min(
        int(m.group(1), 16)
        for m in re.finditer(r"^\s*LOAD\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)", segments, re.M)
    )
    return entry - low


def _objdump_pe_entry_rva(binary: Path) -> int:
    out = subprocess.run(
        ["objdump", "-p", str(binary)], capture_output=True, text=True
    ).stdout
    return int(re.search(r"^AddressOfEntryPoint\s+([0-9a-f]+)", out, re.M).group(1), 16)


@pytest.fixture(scope="module")
def nomain(tmp_path_factory):
    """Freestanding static program with no ``main`` and no libc start call."""
    if not GCC:
        pytest.skip("gcc not available")
    out = tmp_path_factory.mktemp("nomain") / "nomain"
    _build([GCC, "-nostdlib", "-static", "-o", str(out), str(NOMAIN_S)])
    return out


def _dyn(tmp_path_factory, pie: bool):
    if not (GCC and STRIP):
        pytest.skip("gcc/strip not available")
    work = tmp_path_factory.mktemp("nomain-dyn-" + ("pie" if pie else "exec"))
    full = work / "nomain_dyn"
    flags = ["-pie", "-fPIE"] if pie else ["-no-pie"]
    _build(
        [GCC, *flags, "-fno-stack-protector", "-O0", "-o", str(full), str(NOMAIN_DYN_C)]
    )
    stripped = work / "nomain_dyn.stripped"
    _build([STRIP, "-o", str(stripped), str(full)])
    return full, stripped


@pytest.fixture(scope="module")
def dyn_pie(tmp_path_factory):
    return _dyn(tmp_path_factory, pie=True)


@pytest.fixture(scope="module")
def dyn_exec(tmp_path_factory):
    return _dyn(tmp_path_factory, pie=False)


def _decompiler(binary: Path) -> Decompiler:
    d = Decompiler(types.SimpleNamespace(path=str(binary)))
    d._ghidra_path = Path("/opt/ghidra/support/analyzeHeadless")
    d._retdec_path = None
    return d


# --------------------------------------------------------------------------- #
# CLI: no -f sends the empty selector (RED: it forced "main")
# --------------------------------------------------------------------------- #


def _cli_env(monkeypatch, tmp_path, result=None):
    from supwngo.cli import cli  # noqa: F401  (import inside the patch scope)

    target = tmp_path / "target"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.setattr(Decompiler, "_find_ghidra", lambda self: None)
    monkeypatch.setattr(Decompiler, "_find_retdec", lambda self: None)
    monkeypatch.setattr(
        "supwngo.core.binary.Binary.load",
        staticmethod(
            lambda path: types.SimpleNamespace(path=path, symbols={}, bits=64)
        ),
    )
    seen = {}

    def fake(self, func_name=None, func_addr=None, use_ghidra=True):
        seen["func_name"], seen["func_addr"] = func_name, func_addr
        return result

    monkeypatch.setattr(Decompiler, "decompile", fake)
    return target, seen


def _invoke(target, *extra):
    from supwngo.cli import cli

    return CliRunner(mix_stderr=False).invoke(cli, ["decompile", str(target), *extra])


def test_cli_without_f_sends_the_empty_selector(tmp_path, monkeypatch):
    """RED on the base: ``func_name`` was forced to ``"main"``."""
    target, seen = _cli_env(monkeypatch, tmp_path)
    _invoke(target, "--json")
    assert seen == {"func_name": None, "func_addr": None}


def test_cli_without_f_displays_default_and_does_not_crash(tmp_path, monkeypatch):
    """The target display used ``hex(func_addr)``, which cannot take ``None``."""
    result = DecompiledFunction(
        name="FUN_1",
        address=0x1162,
        return_type="int",
        code="int f(void){return 0;}",
        selected_by="libc_start_main_arg",
    )
    target, _seen = _cli_env(monkeypatch, tmp_path, result)
    run = _invoke(target)
    assert run.exit_code == 0, run.stdout + run.stderr
    assert "Decompiling: default" in run.stdout
    assert "Selected by: libc_start_main_arg" in run.stdout


def test_cli_json_carries_selected_by(tmp_path, monkeypatch):
    """RED on the base: the JSON had no ``selected_by``."""
    result = DecompiledFunction(
        name="FUN_1",
        address=0x1162,
        return_type="int",
        code="int f(void){return 0;}",
        selected_by="entry",
    )
    target, _seen = _cli_env(monkeypatch, tmp_path, result)
    run = _invoke(target, "--json")
    assert run.exit_code == 0, run.stdout + run.stderr
    assert json.loads(run.stdout)["selected_by"] == "entry"


def test_cli_explicit_function_keeps_its_selector(tmp_path, monkeypatch):
    target, seen = _cli_env(monkeypatch, tmp_path)
    _invoke(target, "-f", "0x401136", "--json")
    assert seen == {"func_name": None, "func_addr": 0x401136}
    _invoke(target, "-f", "leaf_helper", "--json")
    assert seen["func_name"] == "leaf_helper"


# --------------------------------------------------------------------------- #
# Ghidra argument plumbing: empty selector, entry offset, format
# --------------------------------------------------------------------------- #


def _ghidra_cmd(d, func_name=None, func_addr=None, monkeypatch=None):
    cmds = []
    ran = decompile_mod.GhidraRun(state=ProcState.EXITED, rc=0)

    def run(cmd, timeout):
        cmds.append(cmd)
        return ran

    monkeypatch.setattr(d, "_run_ghidra_headless", run)
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: [])
    d._decompile_ghidra(func_name, func_addr)
    cmd = cmds[0]
    at = cmd.index(decompile_mod.GHIDRA_SCRIPT_NAME)
    return cmd[at + 1 : at + 6]  # selector, out, file_base, entry_rva, format


def test_ghidra_selector_is_empty_without_a_function(dyn_pie, monkeypatch):
    """Regression guard: the seam passes the empty selector through untouched (it
    was the CLI that turned "no -f" into ``name:main``)."""
    selector, _out, *_rest = _ghidra_cmd(
        _decompiler(dyn_pie[1]), monkeypatch=monkeypatch
    )
    assert selector == ""


@pytest.mark.skipif(not (GCC and STRIP), reason="gcc/strip not available")
@pytest.mark.parametrize("variant,file_base", [("pie", 0x0), ("exec", 0x400000)])
def test_entry_offset_for_a_pie_and_a_non_pie(request, monkeypatch, variant, file_base):
    """RED on the base: no entry offset or format was sent. The oracle is
    ``readelf``: ``e_entry - min(PT_LOAD.p_vaddr)``, an offset, not an address."""
    _full, stripped = request.getfixturevalue("dyn_" + variant)
    _sel, _out, base_arg, entry_arg, fmt = _ghidra_cmd(
        _decompiler(stripped), monkeypatch=monkeypatch
    )
    assert fmt == "elf"
    assert int(base_arg, 16) == file_base
    assert int(entry_arg, 16) == _readelf_entry_rva(stripped)
    assert int(entry_arg, 16) < 0x10000


def test_entry_offset_for_a_pe_is_address_of_entry_point(monkeypatch):
    for binary in (PE_SYM, PE_STRIP):
        _sel, _out, file_base, entry_rva, fmt = _ghidra_cmd(
            _decompiler(binary), monkeypatch=monkeypatch
        )
        assert int(entry_rva, 16) == _objdump_pe_entry_rva(binary) == 0x14F0
        assert fmt == "pe"
        assert int(file_base, 16) == 0x140000000


def test_unknown_format_sends_no_entry(tmp_path, monkeypatch):
    junk = tmp_path / "junk"
    junk.write_bytes(b"not an executable")
    _sel, _out, file_base, entry_rva, fmt = _ghidra_cmd(
        _decompiler(junk), monkeypatch=monkeypatch
    )
    assert (file_base, entry_rva, fmt) == ("none", "none", "unknown")


def test_ghidra_selected_by_and_entry_check_are_parsed(monkeypatch):
    d = _decompiler(PE_STRIP)
    entry = {
        "name": "FUN_14000156f",
        "address": 0x14000156F,
        "backend_base": 0x140000000,
        "selected_by": "mingw_crt_main_arg",
        "entry_check": "ok",
        "return_type": "void",
        "code": 'void FUN_14000156f(void)\n{\n  puts("x");\n}',
    }
    ran = decompile_mod.GhidraRun(state=ProcState.EXITED, rc=0)
    monkeypatch.setattr(d, "_run_ghidra_headless", lambda cmd, timeout: ran)
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: [entry])
    result = d._decompile_ghidra(None, None)
    assert result.selected_by == "mingw_crt_main_arg"
    assert result.address == PE_USER_MAIN
    assert d.ghidra_entry_check == "ok"


# --------------------------------------------------------------------------- #
# RetDec is bypassed for the empty selector (it fabricates ``main``)
# --------------------------------------------------------------------------- #


def _retdec_spy(monkeypatch, d):
    calls = []

    def fake_retdec(func_name, func_addr):
        calls.append((func_name, func_addr))
        return DecompiledFunction(
            name=func_name or "main",
            address=func_addr or 0,
            return_type="int",
            code="int main(void){return 0;}",
        )

    d._ghidra_path = None
    d._retdec_path = Path("/usr/bin/retdec-decompiler")
    monkeypatch.setattr(d, "_decompile_retdec", fake_retdec)
    monkeypatch.setattr(d, "_decompile_angr", lambda n, a: None)
    return calls


def test_retdec_is_not_used_for_the_empty_selector(tmp_path, monkeypatch):
    """RED on the base: RetDec ran for an empty selector and returned ``main``."""
    d = _decompiler(tmp_path / "x")
    calls = _retdec_spy(monkeypatch, d)
    assert d.decompile(func_name=None, func_addr=None) is None
    assert calls == []


def test_retdec_is_still_used_with_a_function(tmp_path, monkeypatch):
    d = _decompiler(tmp_path / "x")
    calls = _retdec_spy(monkeypatch, d)
    assert d.decompile(func_name="leaf_helper") is not None
    assert d.decompile(func_addr=0x401136) is not None
    assert calls == [("leaf_helper", None), (None, 0x401136)]


def test_retdec_result_reports_the_explicit_selector(tmp_path):
    d = _decompiler(tmp_path / "x")
    code = "int leaf_helper(int a)\n{\n  return a;\n}"
    assert d._parse_retdec_output(code, "leaf_helper", None).selected_by == "name"
    assert d._parse_retdec_output(code, None, 0x401136).selected_by == "addr"


# --------------------------------------------------------------------------- #
# angr: each step of the order, deterministically (fake functions)
# --------------------------------------------------------------------------- #


class _F:
    def __init__(self, name, addr, plt=False, simproc=False, align=False):
        self.name, self.addr = name, addr
        self.is_plt, self.is_simprocedure, self.is_alignment = plt, simproc, align


def _proj(entry, has_main_symbol=False):
    main_object = types.SimpleNamespace(
        get_symbol=lambda name: (
            object() if (has_main_symbol and name == "main") else None
        )
    )
    return types.SimpleNamespace(
        entry=entry, loader=types.SimpleNamespace(main_object=main_object)
    )


def _funcs(*fs):
    return {f.addr: f for f in fs}


def test_angr_step1_main_symbol():
    funcs = _funcs(_F("_start", 0x401060), _F("main", 0x401162))
    func, by = sub._select_default_function(_proj(0x401060, True), funcs, "elf")
    assert (func.name, by) == ("main", "symbol")


def test_angr_step1_recovered_main_is_the_start_call_argument():
    funcs = _funcs(_F("_start", 0x401060), _F("main", 0x401162))
    func, by = sub._select_default_function(_proj(0x401060, False), funcs, "elf")
    assert (func.name, by) == ("main", "libc_start_main_arg")


def test_angr_step2_the_function_at_exactly_the_entry():
    funcs = _funcs(
        _F("sub_401000", 0x401000), _F("sub_401040", 0x401040), _F("_start", 0x401060)
    )
    func, by = sub._select_default_function(_proj(0x401060), funcs, "elf")
    assert (func.name, by) == ("_start", "entry")


def test_angr_step3_first_real_function_by_address():
    funcs = _funcs(
        _F("puts", 0x401020, plt=True),
        _F("pad", 0x401030, align=True),
        _F("memcpy", 0x500000, simproc=True),
        _F("sub_401090", 0x401090),
        _F("sub_401040", 0x401040),
    )
    # The entry (0x401060) is not a function, so the search falls through.
    func, by = sub._select_default_function(_proj(0x401060), funcs, "elf")
    assert (func.name, by) == ("sub_401040", "first_reachable")


def test_angr_pe_never_uses_first_reachable():
    funcs = _funcs(_F("sub_140001000", 0x140001000), _F("sub_140001190", 0x140001190))
    func, by = sub._select_default_function(_proj(0x1400014F0), funcs, "pe")
    assert (func, by) == (None, "")


def test_angr_pe_entry_is_labelled_entry():
    funcs = _funcs(_F("sub_140001000", 0x140001000), _F("mainCRTStartup", 0x1400014F0))
    func, by = sub._select_default_function(_proj(0x1400014F0), funcs, "pe")
    assert (func.name, by) == ("mainCRTStartup", "entry")


def test_angr_main_beats_entry():
    funcs = _funcs(_F("_start", 0x401060), _F("main", 0x401162))
    assert sub._select_default_function(_proj(0x401060), funcs, "elf")[0].name == "main"


def test_angr_nothing_selectable_is_none():
    funcs = _funcs(_F("puts", 0x401020, plt=True))
    assert sub._select_default_function(_proj(0x401060), funcs, "elf") == (None, "")


def _fake_angr(monkeypatch, funcs, entry, has_main_symbol=False):
    cfg = types.SimpleNamespace(kb=types.SimpleNamespace(functions=funcs))
    decomp = lambda func, cfg=None: types.SimpleNamespace(  # noqa: E731
        codegen=types.SimpleNamespace(text="int f(void)\n{ return 0; }")
    )
    proj = _proj(entry, has_main_symbol)
    proj.loader.main_object.mapped_base = 0x400000
    proj.analyses = types.SimpleNamespace(CFGFast=lambda **kw: cfg, Decompiler=decomp)
    monkeypatch.setattr(sub, "_load_project", lambda path: proj)
    monkeypatch.setattr(
        "supwngo.analysis._angr_callgraph.iter_callees", lambda func, funcs: []
    )


def test_worker_default_reply_carries_selected_by(monkeypatch):
    _fake_angr(monkeypatch, _funcs(_F("_start", 0x401060)), 0x401060)
    reply = sub._op_decompile("x")
    assert reply["status"] == "ok" and reply["selected_by"] == "entry"
    assert reply["name"] == "_start"


def test_worker_default_with_nothing_to_select_is_missing_function(monkeypatch):
    _fake_angr(monkeypatch, _funcs(_F("puts", 0x401020, plt=True)), 0x401060)
    assert sub._op_decompile("x")["status"] == "missing_function"


def test_worker_explicit_selection_is_name_or_addr(monkeypatch):
    funcs = _funcs(_F("main", 0x401162))
    _fake_angr(monkeypatch, funcs, 0x401060)
    assert sub._op_decompile("x", func_name="main")["selected_by"] == "name"
    assert sub._op_decompile("x", func_addr=0x401162)["selected_by"] == "addr"
    # The CLI sends both for ``-f name``: the name is what the user asked for.
    both = sub._op_decompile("x", func_name="main", func_addr=0x401162)
    assert both["selected_by"] == "name"


def test_parent_requires_selected_by_on_an_ok_reply(monkeypatch):
    reply = {
        "status": "ok",
        "name": "main",
        "address": 0x401162,
        "backend_base": 0x400000,
        "return_type": "void",
        "code": 'int main(void)\n{\n    puts("x");\n    return 0;\n}',
        "calls": ["puts"],
    }
    d = _decompiler(PE_SYM)
    monkeypatch.setattr(sub, "run_angr_op", lambda *a, **k: reply)
    assert d._decompile_angr(None, None) is None
    assert d.angr_status == "exception"
    reply["selected_by"] = "symbol"
    assert d._decompile_angr(None, None).selected_by == "symbol"


def test_parent_tells_the_worker_the_file_format(dyn_pie, monkeypatch):
    seen = {}

    def fake(binary_path, op, seconds, **kwargs):
        seen.update(kwargs)
        return {"status": "missing_function", "backend_base": 0x400000}

    monkeypatch.setattr(sub, "run_angr_op", fake)
    _decompiler(dyn_pie[1])._decompile_angr(None, None)
    assert seen["file_format"] == "elf"
    _decompiler(PE_STRIP)._decompile_angr(None, None)
    assert seen["file_format"] == "pe"


# --------------------------------------------------------------------------- #
# Tool tier: real backends on built fixtures
# --------------------------------------------------------------------------- #


def _cli(binary: Path, backend: str, *extra: str):
    from supwngo.cli import cli

    run = CliRunner(mix_stderr=False).invoke(
        cli, ["decompile", str(binary), f"--{backend}", "--json", *extra]
    )
    assert run.exit_code == 0, run.stdout + run.stderr
    return json.loads(run.stdout)


@pytest.mark.timeout(900)
@pytest.mark.parametrize("backend", ["ghidra", "angr"])
def test_no_main_no_start_call_selects_the_entry(nomain, backend):
    """RED on the base: the CLI forced ``main`` and a freestanding program has
    none, so Ghidra selected nothing."""
    if backend == "ghidra":
        need_ghidra()
    doc = _cli(nomain, backend)
    assert doc["selected_by"] == "entry"
    assert int(doc["address"], 16) == _nm_address(nomain, "_start")
    assert doc["function"] in ("_start", "entry", "processEntry")
    assert doc["code"].strip()


@pytest.mark.timeout(900)
@pytest.mark.parametrize("backend", ["ghidra", "angr"])
@pytest.mark.parametrize("variant", ["pie", "exec"])
def test_stripped_dynamic_follows_the_start_call_to_the_user_function(
    request, backend, variant
):
    """RED on the base: the forced ``main`` is not in a stripped binary."""
    if backend == "ghidra":
        need_ghidra()
    full, stripped = request.getfixturevalue("dyn_" + variant)
    oracle = _nm_address(full, "main")

    doc = _cli(stripped, backend)

    assert doc["selected_by"] == "libc_start_main_arg"
    assert int(doc["address"], 16) == oracle
    assert "puts" in doc["code"]


@pytest.mark.timeout(900)
@pytest.mark.parametrize("backend", ["ghidra", "angr"])
def test_unstripped_dynamic_selects_by_the_main_symbol(dyn_pie, backend):
    if backend == "ghidra":
        need_ghidra()
    full, _stripped = dyn_pie
    doc = _cli(full, backend)
    assert doc["selected_by"] == "symbol"
    assert int(doc["address"], 16) == _nm_address(full, "main")


@pytest.mark.timeout(900)
def test_explicit_function_reports_name_or_addr(dyn_pie):
    need_ghidra()
    full, _stripped = dyn_pie
    oracle = _nm_address(full, "helper_value")
    assert _cli(full, "ghidra", "-f", "helper_value")["selected_by"] == "name"
    assert _cli(full, "ghidra", "-f", hex(oracle))["selected_by"] == "addr"


@pytest.mark.timeout(900)
def test_pe_with_symbols_selects_the_user_main_by_symbol():
    need_ghidra()
    doc = _cli(PE_SYM, "ghidra")
    assert doc["selected_by"] == "symbol"
    assert int(doc["address"], 16) == PE_USER_MAIN
    assert "puts" in doc["code"]


@pytest.mark.timeout(900)
def test_stripped_pe_recovers_the_user_main_through_the_crt_start():
    """V-9: the stripped fixture's entry point is the CRT start, not ``main``.
    The user ``main`` is the function whose result the CRT start passes to
    ``exit``; the planted address and a code anchor must both match."""
    need_ghidra()
    doc = _cli(PE_STRIP, "ghidra")
    assert doc["selected_by"] == "mingw_crt_main_arg"
    assert int(doc["address"], 16) == PE_USER_MAIN
    assert "puts" in doc["code"]


@pytest.mark.timeout(600)
def test_angr_on_an_unstripped_pe_selects_the_user_main_by_symbol():
    """angr reads the COFF symbol table of an unstripped PE, so ``main`` is a
    named function and the selection is a ``symbol`` one."""
    doc = _cli(PE_SYM, "angr")
    assert doc["selected_by"] == "symbol"
    assert int(doc["address"], 16) == PE_USER_MAIN


@pytest.mark.timeout(600)
def test_angr_on_a_stripped_pe_is_honest_about_taking_the_entry():
    """angr has no PE ``main`` recovery, so on the stripped fixture it reports
    the CRT start as ``entry`` (never as a user main, never ``first_reachable``)."""
    doc = _cli(PE_STRIP, "angr")
    assert doc["selected_by"] == "entry"
    assert int(doc["address"], 16) == 0x140000000 + _objdump_pe_entry_rva(PE_STRIP)
