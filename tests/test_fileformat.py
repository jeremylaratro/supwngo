"""Tests for supwngo.core.fileformat: detection and the header helpers.

The helpers are checked against ``objdump -p`` / ``objdump -f`` (PE) and
``readelf`` (ELF), not against another parse of the same bytes.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from supwngo.core.fileformat import (
    PE32_MAGIC,
    PE32_PLUS_MAGIC,
    detect_format,
    elf_info,
    pe_info,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from passcard_support import tiny_elf  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PE_DIR = ROOT / "benchmark" / "fixtures" / "s0pe"
PE_FIXTURES = [PE_DIR / "pe_sym.exe", PE_DIR / "pe_strip.exe"]
C_MAIN = b"int main(void) { return 0; }\n"

needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not installed")
needs_mingw32 = pytest.mark.skipif(
    shutil.which("i686-w64-mingw32-gcc") is None,
    reason="i686-w64-mingw32-gcc not installed",
)
needs_objdump = pytest.mark.skipif(
    shutil.which("objdump") is None, reason="objdump not installed"
)
needs_readelf = pytest.mark.skipif(
    shutil.which("readelf") is None, reason="readelf not installed"
)


def make_pe(
    magic: int = PE32_PLUS_MAGIC,
    machine: int = 0x8664,
    image_base: int = -1,
    entry_rva: int = 0x1000,
    lfanew: int = 0x80,
    opt_size: int = -1,
    sig: bytes = b"PE\0\0",
    cut: int = 0,
) -> bytes:
    """A header-only PE; ``cut`` drops that many trailing bytes."""
    if opt_size < 0:
        opt_size = 112 if magic == PE32_PLUS_MAGIC else 96
    if image_base < 0:
        image_base = 0x140000000 if magic == PE32_PLUS_MAGIC else 0x400000
    dos = bytearray(lfanew)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", lfanew)
    coff = struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, opt_size, 0x22)
    opt = bytearray(max(opt_size, 2))
    opt[0:2] = struct.pack("<H", magic)
    if opt_size >= 20:
        opt[16:20] = struct.pack("<I", entry_rva)
    if magic == PE32_PLUS_MAGIC and opt_size >= 32:
        opt[24:32] = struct.pack("<Q", image_base)
    elif magic == PE32_MAGIC and opt_size >= 32:
        opt[28:32] = struct.pack("<I", image_base)
    data = bytes(dos) + sig + coff + bytes(opt)
    return data[: len(data) - cut] if cut else data


def write(tmp_path: Path, data: bytes, name: str = "f.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def build(tmp_path: Path, compiler: str, out: str, *flags: str) -> Path:
    """Compile ``C_MAIN``; skip the test when this toolchain cannot."""
    src = write(tmp_path, C_MAIN, "m.c")
    exe = tmp_path / out
    done = subprocess.run(
        [compiler, str(src), "-o", str(exe), *flags],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if done.returncode != 0:
        pytest.skip("%s could not build %s: %s" % (compiler, out, done.stderr[-200:]))
    return exe


def objdump_pe(path: Path) -> dict:
    """ImageBase, AddressOfEntryPoint, Magic and the machine, from objdump."""
    headers = subprocess.run(
        ["objdump", "-p", str(path)], capture_output=True, text=True, check=True
    ).stdout
    fmt = subprocess.run(
        ["objdump", "-f", str(path)], capture_output=True, text=True, check=True
    ).stdout

    def field(name: str) -> int:
        match = re.search(r"^%s\s+([0-9a-fA-F]+)" % name, headers, re.M)
        assert match, "no %s in objdump -p output" % name
        return int(match.group(1), 16)

    machine = {"pei-x86-64": 0x8664, "pei-i386": 0x14C}[
        re.search(r"file format (\S+)", fmt).group(1)
    ]
    return {
        "image_base": field("ImageBase"),
        "entry_rva": field("AddressOfEntryPoint"),
        "magic": field("Magic"),
        "machine": machine,
    }


def pe_fields(path: Path) -> dict:
    info = pe_info(path)
    assert info is not None
    return {
        "image_base": info.image_base,
        "entry_rva": info.entry_rva,
        "magic": info.magic,
        "machine": info.machine,
    }


def readelf_elf(path: Path) -> dict:
    """e_type, e_entry and the lowest LOAD VirtAddr, from readelf."""
    header = subprocess.run(
        ["readelf", "-hW", str(path)], capture_output=True, text=True, check=True
    ).stdout
    phdrs = subprocess.run(
        ["readelf", "-lW", str(path)], capture_output=True, text=True, check=True
    ).stdout
    kind = re.search(r"Type:\s+(\w+)", header).group(1)
    entry = int(re.search(r"Entry point address:\s+(0x[0-9a-f]+)", header).group(1), 16)
    loads = [
        int(m.group(1), 16)
        for m in re.finditer(r"^\s*LOAD\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)", phdrs, re.M)
    ]
    return {"e_type": {"EXEC": 2, "DYN": 3}[kind], "e_entry": entry, "low": min(loads)}


# --- detection: the V-8 cases -------------------------------------------------


def test_detects_pe32_plus_fixtures():
    for fixture in PE_FIXTURES:
        assert detect_format(fixture) == "pe", fixture.name


@needs_mingw32
@needs_objdump
def test_detects_and_parses_pe32_built_with_mingw(tmp_path):
    exe = build(tmp_path, "i686-w64-mingw32-gcc", "m32.exe")
    assert detect_format(exe) == "pe"
    info = pe_info(exe)
    assert info.magic == PE32_MAGIC and not info.is_pe32_plus
    assert pe_fields(exe) == objdump_pe(exe)


def test_synthesised_pe32_and_pe32_plus_are_pe(tmp_path):
    assert detect_format(write(tmp_path, make_pe(PE32_MAGIC, 0x14C))) == "pe"
    assert detect_format(write(tmp_path, make_pe(PE32_PLUS_MAGIC))) == "pe"


@pytest.mark.parametrize("size", [0, 1, 2, 0x20, 0x3C, 0x3F])
def test_truncated_mz_is_unknown(tmp_path, size):
    assert detect_format(write(tmp_path, make_pe()[:size])) == "unknown"


def test_mz_with_no_room_for_a_signature_is_unknown(tmp_path):
    data = bytearray(0x40)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x3E)  # the signature would straddle EOF
    assert detect_format(write(tmp_path, bytes(data))) == "unknown"


@pytest.mark.parametrize("lfanew", [0x1000, 0xFFFFFFFC, 0xFFFFFFFF])
def test_out_of_range_e_lfanew_is_unknown(tmp_path, lfanew):
    data = bytearray(make_pe())
    data[0x3C:0x40] = struct.pack("<I", lfanew)
    assert detect_format(write(tmp_path, bytes(data))) == "unknown"


def test_missing_pe_signature_is_unknown(tmp_path):
    assert detect_format(write(tmp_path, make_pe(sig=b"PX\0\0"))) == "unknown"
    assert detect_format(write(tmp_path, make_pe(sig=b"PE\0\1"))) == "unknown"


def test_incomplete_coff_header_is_unknown(tmp_path):
    cut_into_coff = make_pe()[: 0x80 + 4 + 10]
    assert detect_format(write(tmp_path, cut_into_coff)) == "unknown"


@pytest.mark.parametrize("cut", [1, 20, 112])
def test_incomplete_optional_header_is_unknown(tmp_path, cut):
    assert detect_format(write(tmp_path, make_pe(cut=cut))) == "unknown"


def test_optional_header_too_small_for_its_magic_is_unknown(tmp_path):
    assert detect_format(write(tmp_path, make_pe(opt_size=2))) == "unknown"
    assert detect_format(write(tmp_path, make_pe(opt_size=64))) == "unknown"


@pytest.mark.parametrize("magic", [0x0, 0x107, 0x20A, 0x10C])
def test_unknown_optional_header_magic_is_unknown(tmp_path, magic):
    data = make_pe(magic=magic, opt_size=112)
    assert detect_format(write(tmp_path, data)) == "unknown"


@needs_gcc
def test_detects_elf_pie_and_non_pie(tmp_path):
    assert detect_format(build(tmp_path, "gcc", "pie")) == "elf"
    assert detect_format(build(tmp_path, "gcc", "nopie", "-no-pie")) == "elf"


def test_detects_the_host_elf():
    assert detect_format(shutil.which("true")) == "elf"


def test_truncated_elf_is_unknown(tmp_path):
    host = Path(shutil.which("true")).read_bytes()
    assert host[:4] == b"\x7fELF"
    for size in (0, 3, 4, 5, 15, 16, 40, 63):
        assert detect_format(write(tmp_path, host[:size])) == "unknown", size
    assert detect_format(write(tmp_path, host[:64])) == "elf"


def test_elf_with_bad_class_or_byte_order_is_unknown(tmp_path):
    header = Path(shutil.which("true")).read_bytes()[:64]
    for index, value in ((4, 0), (4, 3), (5, 0), (5, 3)):
        data = bytearray(header)
        data[index] = value
        assert detect_format(write(tmp_path, bytes(data))) == "unknown"


def test_text_missing_and_directory_are_unknown(tmp_path):
    assert detect_format(write(tmp_path, b"#!/bin/sh\nexit 0\n")) == "unknown"
    assert detect_format(tmp_path / "does-not-exist") == "unknown"
    assert detect_format(tmp_path) == "unknown"


def test_detect_accepts_str_and_path(tmp_path):
    path = write(tmp_path, make_pe())
    assert detect_format(str(path)) == detect_format(path) == "pe"


# --- helpers against an independent oracle -----------------------------------


@needs_objdump
@pytest.mark.parametrize("fixture", PE_FIXTURES, ids=lambda p: p.name)
def test_pe_info_matches_objdump(fixture):
    expected = objdump_pe(fixture)
    assert pe_fields(fixture) == expected
    assert pe_info(fixture).is_pe32_plus
    assert expected["image_base"] == 0x140000000  # the oracle itself, sanity only


def test_pe_info_reads_pe32_fields_from_a_synthesised_header(tmp_path):
    path = write(
        tmp_path, make_pe(PE32_MAGIC, 0x14C, image_base=0x400000, entry_rva=0x1234)
    )
    assert pe_fields(path) == {
        "image_base": 0x400000,
        "entry_rva": 0x1234,
        "magic": PE32_MAGIC,
        "machine": 0x14C,
    }


def test_pe_info_is_none_for_non_pe(tmp_path):
    assert pe_info(write(tmp_path, make_pe(cut=5))) is None
    assert pe_info(shutil.which("true")) is None
    assert pe_info(tmp_path / "missing") is None


@needs_gcc
@needs_readelf
@pytest.mark.parametrize(
    "flags", [[], ["-no-pie"], ["-static", "-no-pie"]], ids=["pie", "exec", "static"]
)
def test_elf_info_matches_readelf(tmp_path, flags):
    out = build(tmp_path, "gcc", "bin", *flags)
    info = elf_info(out)
    expected = readelf_elf(out)
    assert info is not None
    assert (info.bits, info.machine) == (64, 62)
    assert info.e_type == expected["e_type"]
    assert info.e_entry == expected["e_entry"]
    assert info.min_load_vaddr == expected["low"]


@needs_readelf
def test_elf_info_matches_readelf_on_the_host_binary():
    path = Path(shutil.which("true"))
    info = elf_info(path)
    expected = readelf_elf(path)
    assert info.e_type == expected["e_type"]
    assert info.e_entry == expected["e_entry"]
    assert info.min_load_vaddr == expected["low"]


@needs_gcc
@needs_readelf
def test_elf_info_reads_a_32_bit_elf_when_the_toolchain_builds_one(tmp_path):
    out = build(tmp_path, "gcc", "bin32", "-m32", "-no-pie")
    info = elf_info(out)
    expected = readelf_elf(out)
    assert (info.bits, info.machine) == (32, 3)
    assert info.e_entry == expected["e_entry"]
    assert info.min_load_vaddr == expected["low"]


def test_elf_info_is_none_for_non_elf_and_cut_program_headers(tmp_path):
    host = Path(shutil.which("true")).read_bytes()
    assert elf_info(write(tmp_path, host[:40])) is None
    # The ELF header is whole but the program header table is not.
    cut = write(tmp_path, host[:100], "cut.elf")
    assert detect_format(cut) == "elf"
    assert elf_info(cut) is None
    assert elf_info(PE_FIXTURES[0]) is None


def test_header_only_elf_has_no_pt_load(tmp_path):
    path = write(tmp_path, tiny_elf(64))
    assert detect_format(path) == "elf"
    assert elf_info(path).min_load_vaddr is None
