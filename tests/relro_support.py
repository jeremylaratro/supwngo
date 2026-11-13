"""Shared fixtures for the RELRO tests (SP-01 plan section 4.3).

Three gcc-built dynamic ELF executables, one per RELRO level, plus a Full RELRO
image linked with gold. gold keeps a writable ``.got.plt`` section under
``-z now``; GNU ld does not, so the gold image is the case that separates "read
the level from the headers" from "infer it from the ``.got.plt`` section flags".

The truth for every fixture comes from ``readelf -lW -d`` (``GNU_RELRO`` plus
``BIND_NOW`` / ``FLAGS_1 NOW``), never from supwngo or pwntools.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

C_SOURCE = r"""
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buf[32];
    puts("relro fixture");
    if (argc > 1)
        strcpy(buf, argv[1]);
    return buf[0];
}
"""

#: fixture name -> (extra link flags, expected level as readelf reports it)
FIXTURES = {
    "norelro": (["-Wl,-z,norelro"], "none"),
    "relro_lazy": (["-Wl,-z,relro", "-Wl,-z,lazy"], "partial"),
    "relro_now": (["-Wl,-z,relro", "-Wl,-z,now"], "full"),
    "relro_now_gold": (["-fuse-ld=gold", "-Wl,-z,relro", "-Wl,-z,now"], "full"),
}

#: The display strings the core ``Protections.relro`` field has always held.
DISPLAY = {"none": "No RELRO", "partial": "Partial RELRO", "full": "Full RELRO"}

needs_toolchain = pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("readelf") is None,
    reason="gcc and readelf are required",
)


def build_fixture(directory: Path, name: str) -> Path:
    """Build one fixture, skipping the test when the linker is unavailable."""
    flags, _ = FIXTURES[name]
    src = directory / "relro_fixture.c"
    src.write_text(C_SOURCE)
    out = directory / name
    cmd = ["gcc", "-no-pie", "-fno-stack-protector", *flags, "-o", str(out), str(src)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        pytest.skip(f"cannot build {name}: {proc.stderr.strip()[:200]}")
    return out


def readelf_dump(path: Path) -> str:
    return subprocess.run(
        ["readelf", "-lW", "-d", str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout


def readelf_level(path: Path) -> str:
    """RELRO level from the program headers and dynamic table: none/partial/full."""
    dump = readelf_dump(path)
    if "GNU_RELRO" not in dump:
        return "none"
    if "BIND_NOW" in dump or "Flags: NOW" in dump:
        return "full"
    return "partial"


def readelf_is_dynamic(path: Path) -> bool:
    dump = readelf_dump(path)
    return "INTERP" in dump and "DYNAMIC" in dump
