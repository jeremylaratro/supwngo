"""SP-01b V-10: one address convention for every decompile backend.

For a PIE, Ghidra reports an address based at its own image base (``0x100000``
for an ordinary 64-bit ET_DYN) and angr one based at ``0x400000``, so the same
function got two different addresses and neither was the one ``objdump`` shows.

Both backends' ``address`` is now normalised to the file's link-time virtual
address: ``address = file_base + (backend_addr - backend_base)``, where each
backend *reports* its own ``backend_base`` (Ghidra ``getImageBase()``, angr
``main_object.mapped_base``) and the file base is ``min(PT_LOAD.p_vaddr)`` for an
ELF or ``ImageBase`` for a PE. The inverse mapping is applied to an explicit
``-f 0x...`` selector, inside the backend, with the backend's own base.

Hermetic tests feed canned backend output with *invented* bases, so a mapping
that hard-codes ``0x100000``/``0x400000`` corrupts the ET_EXEC case and fails.
Tool-tier tests (``SUPWNGO_REQUIRE_GHIDRA=1``) run both real backends and compare
with an independent oracle: ``nm`` for the ELF fixtures and the mingw ``nm`` for
the PE fixtures. Cross-backend equality alone would not count.
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
from supwngo.analysis.decompile import Decompiler  # noqa: E402
from supwngo.core.proc import ProcState  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
TWO_FUNCS = REPO / "tests" / "fixtures" / "angr_callgraph" / "two_funcs.c"
PE_VULN = REPO / "benchmark" / "fixtures" / "s0pe" / "pe_vuln.c"
PE_SYM = REPO / "benchmark" / "fixtures" / "s0pe" / "pe_sym.exe"

GCC = shutil.which("gcc")
MINGW32 = shutil.which("i686-w64-mingw32-gcc")
NM = shutil.which("nm")
MINGW32_NM = shutil.which("i686-w64-mingw32-nm")


# --------------------------------------------------------------------------- #
# Fixtures and independent oracles
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _generous_ghidra_budget(monkeypatch):
    """The host is shared and often loaded; the default 180 s can be too tight."""
    monkeypatch.setattr(decompile_mod, "DEFAULT_GHIDRA_TIMEOUT", 600.0)


def _build(cmd):
    built = subprocess.run(cmd, capture_output=True, text=True)
    assert built.returncode == 0, built.stderr


@pytest.fixture(scope="module")
def elf_exec(tmp_path_factory):
    if not GCC:
        pytest.skip("gcc not available")
    out = tmp_path_factory.mktemp("addr-exec") / "two_funcs_exec"
    _build(
        [GCC, "-no-pie", "-fno-stack-protector", "-O0", "-o", str(out), str(TWO_FUNCS)]
    )
    return out


@pytest.fixture(scope="module")
def elf_pie(tmp_path_factory):
    if not GCC:
        pytest.skip("gcc not available")
    out = tmp_path_factory.mktemp("addr-pie") / "two_funcs_pie"
    _build(
        [
            GCC,
            "-pie",
            "-fPIE",
            "-fno-stack-protector",
            "-O0",
            "-o",
            str(out),
            str(TWO_FUNCS),
        ]
    )
    return out


@pytest.fixture(scope="module")
def pe32(tmp_path_factory):
    if not MINGW32:
        pytest.skip("i686-w64-mingw32-gcc not available")
    out = tmp_path_factory.mktemp("addr-pe32") / "pe32.exe"
    _build([MINGW32, "-O0", "-o", str(out), str(PE_VULN)])
    return out


def _nm_address(nm: str, binary: Path, symbol: str) -> int:
    """Address of the text symbol ``symbol`` per ``nm`` (the objdump convention)."""
    out = subprocess.run([nm, str(binary)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "Tt" and parts[2] == symbol:
            return int(parts[0], 16)
    raise AssertionError(f"{symbol} not in nm output of {binary}")


def _first_load_vaddr(binary: Path) -> int:
    """Lowest ``PT_LOAD`` virtual address per ``readelf -lW``."""
    out = subprocess.run(
        ["readelf", "-lW", str(binary)], capture_output=True, text=True, timeout=30
    ).stdout
    vaddrs = [
        int(m.group(1), 16)
        for m in re.finditer(r"^\s*LOAD\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)", out, re.M)
    ]
    return min(vaddrs)


def _pe_image_base(binary: Path) -> int:
    out = subprocess.run(
        ["objdump", "-p", str(binary)], capture_output=True, text=True, timeout=30
    ).stdout
    return int(re.search(r"^ImageBase\s+([0-9a-f]+)", out, re.M).group(1), 16)


def _decompiler(binary: Path) -> Decompiler:
    d = Decompiler(types.SimpleNamespace(path=str(binary)))
    d._ghidra_path = Path("/opt/ghidra/support/analyzeHeadless")
    d._retdec_path = None
    return d


# --------------------------------------------------------------------------- #
# File base: min(PT_LOAD.p_vaddr) for an ELF, ImageBase for a PE
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not GCC, reason="gcc not available")
def test_file_base_of_a_pie_and_an_et_exec_is_the_lowest_load_vaddr(elf_pie, elf_exec):
    assert _decompiler(elf_pie)._file_base() == _first_load_vaddr(elf_pie) == 0
    assert _decompiler(elf_exec)._file_base() == _first_load_vaddr(elf_exec)
    assert _decompiler(elf_exec)._file_base() != 0


def test_file_base_of_a_pe_is_its_image_base(pe32):
    assert _decompiler(PE_SYM)._file_base() == _pe_image_base(PE_SYM)
    assert _decompiler(pe32)._file_base() == _pe_image_base(pe32)
    assert _decompiler(PE_SYM)._file_base() != _decompiler(pe32)._file_base()


def test_file_base_of_a_file_that_is_neither_is_none(tmp_path):
    junk = tmp_path / "junk"
    junk.write_bytes(b"not an executable")
    assert _decompiler(junk)._file_base() is None


# --------------------------------------------------------------------------- #
# Ghidra: canned output with invented bases (a hard-coded base fails these)
# --------------------------------------------------------------------------- #


def _ghidra_returning(d, entry, monkeypatch, cmds=None):
    ran = decompile_mod.GhidraRun(state=ProcState.EXITED, rc=0)

    def run(cmd, timeout):
        if cmds is not None:
            cmds.append(cmd)
        return ran

    monkeypatch.setattr(d, "_run_ghidra_headless", run)
    monkeypatch.setattr(d, "_read_ghidra_output", lambda path: [entry])


def _entry(address, backend_base, name="leaf_helper"):
    return {
        "name": name,
        "address": address,
        "backend_base": backend_base,
        "return_type": "int",
        "code": 'int leaf_helper(int a)\n{\n  printf("x");\n  return a;\n}',
    }


@pytest.mark.skipif(not (GCC and NM), reason="gcc/nm not available")
def test_ghidra_pie_address_is_the_nm_address_whatever_the_reported_base(
    elf_pie, monkeypatch
):
    """RED on the base: the address was returned as Ghidra gave it."""
    oracle = _nm_address(NM, elf_pie, "leaf_helper")
    for ghidra_base in (0x100000, 0x7F0000):
        d = _decompiler(elf_pie)
        _ghidra_returning(d, _entry(ghidra_base + oracle, ghidra_base), monkeypatch)
        result = d._decompile_ghidra("leaf_helper", None)
        assert result.address == oracle, hex(ghidra_base)


@pytest.mark.skipif(not (GCC and NM), reason="gcc/nm not available")
def test_ghidra_et_exec_address_survives_an_unusual_backend_base(elf_exec, monkeypatch):
    """A mapping that assumed 0x100000 for every ELF would shift an ET_EXEC."""
    oracle = _nm_address(NM, elf_exec, "leaf_helper")
    base = _first_load_vaddr(elf_exec)
    d = _decompiler(elf_exec)
    _ghidra_returning(d, _entry(0x500000 + (oracle - base), 0x500000), monkeypatch)
    assert d._decompile_ghidra("leaf_helper", None).address == oracle


def test_ghidra_pe_address_is_the_nm_address(monkeypatch):
    oracle = _nm_address("nm", PE_SYM, "pe_vuln")
    image_base = _pe_image_base(PE_SYM)
    d = _decompiler(PE_SYM)
    _ghidra_returning(d, _entry(0x10000 + (oracle - image_base), 0x10000), monkeypatch)
    assert d._decompile_ghidra("pe_vuln", None).address == oracle


def test_ghidra_output_without_a_backend_base_is_not_trusted(monkeypatch):
    d = _decompiler(PE_SYM)
    entry = _entry(0x1000, 0x0)
    del entry["backend_base"]
    _ghidra_returning(d, entry, monkeypatch)
    assert d._decompile_ghidra("pe_vuln", None) is None
    assert "backend_base" in d.ghidra_error


@pytest.mark.skipif(not GCC, reason="gcc not available")
def test_ghidra_explicit_address_is_sent_in_file_convention_with_the_file_base(
    elf_pie, elf_exec, monkeypatch
):
    """The inverse mapping happens in the script, with Ghidra's own base: Python
    sends the file-convention selector plus the file base, never a guessed
    backend address."""
    for binary in (elf_pie, elf_exec):
        cmds = []
        d = _decompiler(binary)
        _ghidra_returning(d, _entry(0x1000, 0x0), monkeypatch, cmds)
        d._decompile_ghidra(None, 0x1149)
        cmd = cmds[0]
        at = cmd.index(decompile_mod.GHIDRA_SCRIPT_NAME)
        assert cmd[at + 1] == "addr:0x1149"
        assert int(cmd[at + 3], 16) == _first_load_vaddr(binary)


# --------------------------------------------------------------------------- #
# angr: worker maps the selector, parent maps the reply
# --------------------------------------------------------------------------- #


class _FakeFunc:
    def __init__(self, name, addr):
        self.name, self.addr = name, addr


def _fake_angr_project(monkeypatch, funcs, mapped_base):
    cfg = types.SimpleNamespace(kb=types.SimpleNamespace(functions=funcs))
    decomp = lambda func, cfg=None: types.SimpleNamespace(  # noqa: E731
        codegen=types.SimpleNamespace(text="int f(void)\n{ return 0; }")
    )
    proj = types.SimpleNamespace(
        analyses=types.SimpleNamespace(CFGFast=lambda **kw: cfg, Decompiler=decomp),
        loader=types.SimpleNamespace(
            main_object=types.SimpleNamespace(mapped_base=mapped_base)
        ),
    )
    monkeypatch.setattr(sub, "_load_project", lambda path: proj)
    monkeypatch.setattr(
        "supwngo.analysis._angr_callgraph.iter_callees", lambda func, funcs: []
    )


def test_angr_worker_reports_its_own_backend_base(monkeypatch):
    _fake_angr_project(monkeypatch, {0x601149: _FakeFunc("f", 0x601149)}, 0x600000)
    reply = sub._op_decompile("x", func_name="f")
    assert reply["backend_base"] == 0x600000


def test_angr_worker_maps_a_file_convention_selector_with_its_own_base(monkeypatch):
    """File base 0 (PIE), angr mapped at an invented 0x600000: file address
    0x1149 is the function at 0x601149."""
    _fake_angr_project(monkeypatch, {0x601149: _FakeFunc("f", 0x601149)}, 0x600000)
    reply = sub._op_decompile("x", func_addr=0x1149, file_base=0x0)
    assert reply["status"] == "ok", reply
    assert reply["address"] == 0x601149 and reply["backend_base"] == 0x600000


def test_angr_worker_without_a_file_base_takes_the_address_as_given(monkeypatch):
    _fake_angr_project(monkeypatch, {0x1149: _FakeFunc("f", 0x1149)}, 0x600000)
    reply = sub._op_decompile("x", func_addr=0x1149)
    assert reply["status"] == "ok", reply


def _angr_ok(address, backend_base):
    return {
        "status": "ok",
        "name": "leaf_helper",
        "address": address,
        "backend_base": backend_base,
        "selected_by": "name",
        "return_type": "void",
        "code": 'int leaf_helper(int a0)\n{\n    printf("x");\n    return a0;\n}',
        "calls": ["printf"],
    }


@pytest.mark.skipif(not (GCC and NM), reason="gcc/nm not available")
def test_angr_parent_normalises_the_reply_address(elf_pie, elf_exec, monkeypatch):
    """RED on the base: the worker's address was returned as angr gave it."""
    for binary, angr_base in ((elf_pie, 0x400000), (elf_exec, 0x400000)):
        oracle = _nm_address(NM, binary, "leaf_helper")
        file_base = _first_load_vaddr(binary)
        reply = _angr_ok(angr_base + (oracle - file_base), angr_base)
        monkeypatch.setattr(sub, "run_angr_op", lambda *a, _r=reply, **k: _r)
        d = _decompiler(binary)
        assert d._decompile_angr("leaf_helper", None).address == oracle


def test_angr_parent_sends_the_file_base_and_the_file_convention_address(
    elf_pie, monkeypatch
):
    seen = {}

    def fake(binary_path, op, seconds, **kwargs):
        seen.update(kwargs)
        return {"status": "missing_function", "backend_base": 0x400000}

    monkeypatch.setattr(sub, "run_angr_op", fake)
    _decompiler(elf_pie)._decompile_angr(None, 0x1149)
    assert seen["func_addr"] == 0x1149 and seen["file_base"] == 0


def test_angr_ok_reply_without_a_backend_base_is_not_trusted(monkeypatch):
    reply = _angr_ok(0x401149, 0x400000)
    del reply["backend_base"]
    monkeypatch.setattr(sub, "run_angr_op", lambda *a, **k: reply)
    d = _decompiler(PE_SYM)
    assert d._decompile_angr("leaf_helper", None) is None
    assert d.angr_status == "exception"


# --------------------------------------------------------------------------- #
# Tool tier: both real backends against nm / the PE headers
# --------------------------------------------------------------------------- #


def _cli(binary: Path, selector: str, backend: str):
    from supwngo.cli import cli

    result = CliRunner(mix_stderr=False).invoke(
        cli, ["decompile", str(binary), "-f", selector, f"--{backend}", "--json"]
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


# (fixture, nm tool, symbol nm reports, anchor call, selectors to try)
_ELF_CASES = [
    ("elf_pie", "nm", "leaf_helper", "printf"),
    ("elf_exec", "nm", "leaf_helper", "printf"),
]


@pytest.mark.timeout(900)
@pytest.mark.parametrize("backend", ["ghidra", "angr"])
@pytest.mark.parametrize("how", ["name", "address"])
@pytest.mark.parametrize("fixture,nm,symbol,anchor", _ELF_CASES)
def test_elf_backends_report_the_nm_address(
    request, backend, how, fixture, nm, symbol, anchor
):
    if backend == "ghidra":
        need_ghidra()
    binary = request.getfixturevalue(fixture)
    oracle = _nm_address(nm, binary, symbol)
    selector = symbol if how == "name" else hex(oracle)

    doc = _cli(binary, selector, backend)

    assert doc["analysis_backend"] == backend
    assert int(doc["address"], 16) == oracle
    assert anchor in doc["code"]


@pytest.mark.timeout(900)
@pytest.mark.parametrize("backend", ["ghidra", "angr"])
@pytest.mark.parametrize("how", ["name", "address"])
def test_pe64_backends_report_the_nm_address(backend, how):
    if backend == "ghidra":
        need_ghidra()
    elif how == "name":
        pytest.skip("angr names PE functions sub_<addr>, so there is no name to select")
    oracle = _nm_address("nm", PE_SYM, "pe_vuln")
    assert oracle >> 32 == _pe_image_base(PE_SYM) >> 32  # nm is in PE convention
    selector = "pe_vuln" if how == "name" else hex(oracle)

    doc = _cli(PE_SYM, selector, backend)

    assert doc["analysis_backend"] == backend
    assert int(doc["address"], 16) == oracle
    assert "puts" in doc["code"]


@pytest.mark.timeout(900)
@pytest.mark.skipif(not (MINGW32 and MINGW32_NM), reason="i686 mingw not available")
@pytest.mark.parametrize("backend", ["ghidra", "angr"])
def test_pe32_backends_report_the_nm_address(pe32, backend):
    if backend == "ghidra":
        need_ghidra()
    oracle = _nm_address(MINGW32_NM, pe32, "_pe_vuln")
    assert _pe_image_base(pe32) <= oracle < _pe_image_base(pe32) + 0x100000

    doc = _cli(pe32, hex(oracle), backend)

    assert doc["analysis_backend"] == backend
    assert int(doc["address"], 16) == oracle
    assert "puts" in doc["code"]
