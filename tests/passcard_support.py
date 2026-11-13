"""Shared helpers for the passcard tests (not a test module).

Import with ``sys.path.insert(0, str(Path(__file__).parent))`` first, as the
benchmark modules are imported. Everything here is plain functions and constants.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = REPO_ROOT / "benchmark"

# The S0 binaries are gitignored. PASSCARD_TARGETS_ROOT points a checkout that
# lacks them (a fresh worktree) at the ones in another checkout.
TARGETS_ROOT = Path(
    os.environ.get("PASSCARD_TARGETS_ROOT")
    or REPO_ROOT / "tests" / "htb-targets" / "organized"
)

S0_SLUGS = [
    "sick_rop",
    "rocket_blaster_xxx",
    "snow_scan",
    "ancient_interface",
    "auth-or-out",
    "sabotage",
    "bon-nie-appetit",
]

HOST_LOADER = Path("/lib64/ld-linux-x86-64.so.2")


def have_targets() -> bool:
    return all((TARGETS_ROOT / slug).exists() for slug in S0_SLUGS)


needs_targets = pytest.mark.skipif(
    not have_targets(),
    reason="S0 binaries absent (gitignored); set PASSCARD_TARGETS_ROOT to a checkout "
    "that has tests/htb-targets/organized",
)
needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not installed")
needs_host_loader = pytest.mark.skipif(
    not HOST_LOADER.exists(), reason="no x86-64 host loader to copy"
)


def gcc(*args: str, cwd: Path) -> None:
    result = subprocess.run(
        ["gcc", *args], cwd=str(cwd), capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        pytest.skip("gcc could not build the fixture: %s" % result.stderr[-300:])


def tiny_elf(bits: int = 64, machine: int = 62, etype: int = 2) -> bytes:
    """A header-only ELF (no program headers): parses, never runs."""
    if bits == 64:
        return struct.pack(
            "<4sBBBBB7xHHIQQQIHHHHHH",
            b"\x7fELF", 2, 1, 1, 0, 0, etype, machine, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0,
        )  # fmt: skip
    return struct.pack(
        "<4sBBBBB7xHHIIIIIHHHHHH",
        b"\x7fELF", 1, 1, 1, 0, 0, etype, machine, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0,
    )  # fmt: skip


def build_lib_tree(root: Path) -> Path:
    """A challenge directory with a relative loader and a two-level library chain.

    ``app``      PT_INTERP ./ld/ld.so, RUNPATH $ORIGIN/lib, NEEDED libfoo.so
    ``app2``     PT_INTERP ./ld/ld.so, no RUNPATH, NEEDED libbar.so (next to the loader)
    ``lib/libfoo.so``  RUNPATH $ORIGIN, NEEDED libbar.so
    plus decoys that no search path reaches (source, .debug, notes, a stray libc).
    Returns the source directory.
    """
    build, src = root / "build", root / "src"
    for directory in (build, src / "lib", src / "ld", src / "extra"):
        directory.mkdir(parents=True, exist_ok=True)
    (build / "app.c").write_text("int foo(void);\nint main(void){return foo();}\n")
    (build / "foo.c").write_text("int bar(void);\nint foo(void){return bar();}\n")
    (build / "bar.c").write_text("int bar(void){return 0;}\n")
    (build / "app2.c").write_text("int bar(void);\nint main(void){return bar();}\n")
    gcc("-shared", "-fPIC", "-Wl,-soname,libbar.so", "-o", str(src / "lib/libbar.so"),
        "bar.c", cwd=build)  # fmt: skip
    gcc("-shared", "-fPIC", "-Wl,-soname,libfoo.so", "-Wl,--enable-new-dtags",
        "-Wl,-rpath,$ORIGIN", "-Wl,-rpath-link," + str(src / "lib"),
        "-o", str(src / "lib/libfoo.so"), "foo.c", "-L" + str(src / "lib"), "-lbar",
        cwd=build)  # fmt: skip
    gcc("-o", str(src / "app"), "app.c", "-Wl,--dynamic-linker=./ld/ld.so",
        "-Wl,--enable-new-dtags", "-Wl,-rpath,$ORIGIN/lib",
        "-Wl,-rpath-link," + str(src / "lib"), "-L" + str(src / "lib"), "-lfoo",
        cwd=build)  # fmt: skip
    shutil.copy(src / "lib/libbar.so", src / "ld/libbar.so")
    gcc("-o", str(src / "app2"), "app2.c", "-Wl,--dynamic-linker=./ld/ld.so",
        "-L" + str(src / "ld"), "-lbar", cwd=build)  # fmt: skip
    shutil.copy(os.path.realpath(HOST_LOADER), src / "ld/ld.so")
    # Decoys.
    (src / "app.c").write_text("/* the answer key */\n")
    (src / "app.debug").write_bytes(b"debug sibling")
    (src / "notes.txt").write_text("write-up\n")
    shutil.copy(src / "lib/libbar.so", src / "lib/libunused.so")
    shutil.copy(src / "lib/libbar.so", src / "extra/libc.so.6")
    return src
