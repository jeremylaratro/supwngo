"""Integrity of the S0-PE decompile fixtures and truth (plan §8.1 V-15, V-9).

Pins the committed PE bytes and checks each truth file against them: SHA-256,
PE32+ x86-64, symbol table present only in ``pe_sym.exe``, the user ``main`` and
``pe_vuln`` addresses, and that the stripped file shares ``pe_sym.exe``'s VMA
layout and ``.text`` bytes (which is why one set of addresses serves both). The
PE is parsed with ``struct``; ``nm`` is used only as an independent cross-check
when a mingw ``nm`` is installed. Ghidra is never invoked.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "benchmark" / "fixtures" / "s0pe"
TRUTH_DIR = ROOT / "benchmark" / "truth" / "s0pe"
SLUGS = ["pe_sym", "pe_strip"]


def _truth(slug: str) -> dict:
    return yaml.safe_load((TRUTH_DIR / f"{slug}.yaml").read_text())


def _binary(slug: str) -> Path:
    return ROOT / _truth(slug)["binary"]["path"]


class _PE:
    """Just enough of a PE32+ parser for these assertions."""

    def __init__(self, data: bytes):
        self.data = data
        assert data[:2] == b"MZ"
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        assert data[lfanew : lfanew + 4] == b"PE\0\0"
        coff = lfanew + 4
        (self.machine, nsec, _ts, self.symtab, self.nsyms, optsize, _ch) = (
            struct.unpack_from("<HHIIIHH", data, coff)
        )
        opt = coff + 20
        (self.magic,) = struct.unpack_from("<H", data, opt)
        (self.entry_rva,) = struct.unpack_from("<I", data, opt + 16)
        (self.image_base,) = struct.unpack_from("<Q", data, opt + 24)
        self.sections: dict[str, tuple[int, int, int, int]] = {}
        sec = opt + optsize
        for i in range(nsec):
            name, vsize, vaddr, rawsize, rawptr = struct.unpack_from(
                "<8sIIII", data, sec + 40 * i
            )
            key = name.rstrip(b"\0").decode("ascii", "replace")
            self.sections[key] = (vaddr, vsize, rawptr, rawsize)

    def read_va(self, va: int, size: int) -> bytes:
        rva = va - self.image_base
        for vaddr, vsize, rawptr, rawsize in self.sections.values():
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                start = rawptr + (rva - vaddr)
                return self.data[start : start + size]
        raise AssertionError(f"VA {va:#x} is not in any section")

    def text(self) -> bytes:
        _vaddr, _vsize, rawptr, rawsize = self.sections[".text"]
        return self.data[rawptr : rawptr + rawsize]

    def call_targets(self, va: int, size: int) -> list[int]:
        """Targets of ``call rel32`` (E8) opcodes in ``size`` bytes at ``va``.

        Good enough for these tiny, pinned, -O0 functions; not a disassembler.
        """
        code = self.read_va(va, size)
        return [
            va + i + 5 + struct.unpack_from("<i", code, i + 1)[0]
            for i in range(len(code) - 4)
            if code[i] == 0xE8
        ]


def _pe(slug: str) -> _PE:
    return _PE(_binary(slug).read_bytes())


def _nm_tool() -> str | None:
    return shutil.which("x86_64-w64-mingw32-nm") or shutil.which("nm")


def _nm_symbols(path: Path) -> dict[str, int]:
    result = subprocess.run(
        [_nm_tool(), str(path)], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    symbols = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t"):
            symbols[parts[2]] = int(parts[0], 16)
    return symbols


@pytest.mark.parametrize("slug", SLUGS)
def test_truth_schema_and_scoring_scope(slug):
    truth = _truth(slug)
    assert truth["slug"] == slug
    assert truth["format"] == "pe"
    assert truth["arch"] == "amd64"
    assert truth["metrics"] == ["decomp", "robust"]
    assert truth["decompile"]["anchors"] == {"calls": ["puts"], "min_calls": 1}
    assert truth["stage"]["files"] == [_binary(slug).name]
    assert _binary(slug).parent == FIXTURE_DIR
    assert (FIXTURE_DIR / "pe_vuln.c").is_file()


@pytest.mark.parametrize("slug", SLUGS)
def test_committed_binary_matches_the_pinned_sha256(slug):
    digest = hashlib.sha256(_binary(slug).read_bytes()).hexdigest()
    assert digest == _truth(slug)["binary"]["sha256"], (
        f"{_binary(slug).name} changed: restore the committed binary, or rebuild "
        "per the commands in its truth file and re-pin"
    )


@pytest.mark.parametrize("slug", SLUGS)
def test_binary_is_pe32plus_amd64(slug):
    pe = _pe(slug)
    assert pe.machine == 0x8664
    assert pe.magic == 0x20B


def test_only_pe_sym_has_a_symbol_table():
    assert _pe("pe_sym").nsyms > 0
    stripped = _pe("pe_strip")
    assert (stripped.symtab, stripped.nsyms) == (0, 0)


@pytest.mark.parametrize("slug", SLUGS)
def test_default_function_truth_is_user_main_and_never_the_crt_entry(slug):
    truth = _truth(slug)["decompile"]
    pe = _pe(slug)
    entry = pe.image_base + pe.entry_rva
    assert len(truth["default_function_any_of"]) == 1
    (main,) = truth["default_function_any_of"]
    assert main != entry, "an `entry` result must stay an honest DECOMP FAIL"
    assert truth["vuln_function"]["addr"] not in (main, entry)


@pytest.mark.parametrize("slug", SLUGS)
def test_pinned_addresses_agree_with_the_committed_bytes(slug):
    # main calls pe_vuln, and pe_vuln calls one target (the `puts` thunk), both
    # read straight from the bytes at the pinned addresses.
    truth = _truth(slug)["decompile"]
    pe = _pe(slug)
    (main,) = truth["default_function_any_of"]
    vuln = truth["vuln_function"]["addr"]
    assert vuln in pe.call_targets(main, 0x20)
    puts_thunks = pe.call_targets(vuln, 0x20)
    assert len(puts_thunks) == 1
    # The thunk is `jmp qword ptr [rip+disp32]` through the import table.
    assert pe.read_va(puts_thunks[0], 2) == b"\xff\x25"


def test_both_truth_files_share_one_set_of_addresses():
    sym, strip = _truth("pe_sym")["decompile"], _truth("pe_strip")["decompile"]
    assert sym["default_function_any_of"] == strip["default_function_any_of"]
    assert sym["vuln_function"]["addr"] == strip["vuln_function"]["addr"]


def test_stripped_build_shares_pe_sym_vma_layout_and_text_bytes():
    sym, strip = _pe("pe_sym"), _pe("pe_strip")
    assert (sym.image_base, sym.entry_rva) == (strip.image_base, strip.entry_rva)
    shared = [name for name in strip.sections if not name.startswith(".debug")]
    assert ".text" in shared
    for name in shared:
        assert sym.sections[name][:2] == strip.sections[name][:2], name
    assert sym.text() == strip.text()


@pytest.mark.skipif(_nm_tool() is None, reason="no nm installed")
def test_nm_agrees_with_the_pinned_addresses_in_pe_sym():
    symbols = _nm_symbols(_binary("pe_sym"))
    truth = _truth("pe_sym")["decompile"]
    assert symbols["main"] == truth["default_function_any_of"][0]
    assert symbols["pe_vuln"] == truth["vuln_function"]["addr"]
    # The call pe_vuln makes goes to the symbol `puts`.
    pe = _pe("pe_sym")
    (puts_thunk,) = pe.call_targets(truth["vuln_function"]["addr"], 0x20)
    assert symbols["puts"] == puts_thunk
