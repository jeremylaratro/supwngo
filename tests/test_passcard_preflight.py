"""Tests for benchmark/passcard_preflight.py (SP-01 plan section 3.5).

Every pinned VOID reason has a case that triggers it. Header-only ELFs
(``tiny_elf``) stand in for loaders of the wrong class or machine; they parse but
never run, so no test executes anything.
"""

import os
import shutil
import stat
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from passcard_support import (  # noqa: E402
    BENCHMARK,
    HOST_LOADER,
    REPO_ROOT,
    S0_SLUGS,
    TARGETS_ROOT,
    build_lib_tree,
    gcc,
    needs_gcc,
    needs_host_loader,
    needs_targets,
    tiny_elf,
)

sys.path.insert(0, str(BENCHMARK))

import passcard_preflight as pf  # noqa: E402
import passcard_stage as st  # noqa: E402

EM_AARCH64 = 183
EM_386 = 3


def _write(path: Path, data: bytes, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def _dyn_target(cell: Path, interp: str) -> Path:
    """A target that is a real dynamic ELF with the given PT_INTERP."""
    gcc("-o", str(cell / "t"), "t.c", "-Wl,--dynamic-linker=" + interp, cwd=cell)
    return cell / "t"


@pytest.fixture
def cell(tmp_path):
    root = tmp_path / "cell"
    root.mkdir()
    return root


@pytest.fixture
def dyn_cell(cell):
    (cell / "t.c").write_text("int main(void){return 0;}\n")
    return cell


# --- the target itself -------------------------------------------------------


def test_a_missing_target_is_target_missing(cell):
    result = pf.run_preflight(cell, "nope")
    assert (result.ok, result.code) == (False, "target_missing")
    assert result.void_reason == "target_missing"


def test_a_directory_target_is_not_regular(cell):
    (cell / "d").mkdir()
    assert pf.run_preflight(cell, "d").code == "target_not_regular"


def test_an_empty_target_is_target_empty(cell):
    _write(cell / "t", b"")
    assert pf.run_preflight(cell, "t").code == "target_empty"


def test_a_pe_is_unsupported_format_not_a_permission_problem(cell):
    # No exec bit: the format check must come first so a PE never reads as chmod.
    _write(cell / "t.exe", b"MZ" + b"\x00" * 200, mode=0o644)
    result = pf.run_preflight(cell, "t.exe")
    assert result.code == "unsupported_format"


def test_a_truncated_elf_is_unsupported_format(cell):
    _write(cell / "t", b"\x7fELF\x02\x01\x01")
    assert pf.run_preflight(cell, "t").code == "unsupported_format"


def test_a_non_executable_elf_is_target_not_executable(cell):
    _write(cell / "t", tiny_elf(), mode=0o644)
    assert pf.run_preflight(cell, "t").code == "target_not_executable"


def test_a_foreign_machine_is_machine_unsupported(cell):
    _write(cell / "t", tiny_elf(machine=EM_AARCH64))
    result = pf.run_preflight(cell, "t", host_machine="x86_64")
    assert (result.ok, result.code) == (False, "machine_unsupported")
    assert "EM_AARCH64" in result.detail
    # The same file is fine on a host that runs it.
    assert pf.run_preflight(cell, "t", host_machine="aarch64").ok


def test_an_unknown_host_machine_runs_nothing(cell):
    _write(cell / "t", tiny_elf())
    assert pf.run_preflight(cell, "t", host_machine="riscv64").code == "machine_unsupported"


def test_a_32_bit_x86_target_is_acceptable_on_an_x86_64_host(cell):
    _write(cell / "t", tiny_elf(bits=32, machine=EM_386))
    assert pf.run_preflight(cell, "t", host_machine="x86_64").ok


# --- no loader ---------------------------------------------------------------


@needs_gcc
def test_a_static_target_without_pt_interp_is_ok(cell):
    (cell / "t.c").write_text("void _start(void){for(;;);}\n")
    gcc("-nostdlib", "-static", "-o", str(cell / "t"), "t.c", cwd=cell)
    assert st.read_elf(cell / "t").interp is None
    result = pf.run_preflight(cell, "t")
    assert result.ok and result.code == "" and result.void_reason is None


# --- loader checks -----------------------------------------------------------


@needs_gcc
def test_a_relative_loader_that_does_not_exist_is_interp_missing(dyn_cell):
    _dyn_target(dyn_cell, "./nope/ld.so")
    result = pf.run_preflight(dyn_cell, "t")
    assert (result.ok, result.code) == (False, "interp_missing")
    assert result.interp == "./nope/ld.so"


@needs_gcc
def test_an_absolute_loader_that_does_not_exist_is_interp_missing(dyn_cell):
    _dyn_target(dyn_cell, "/nonexistent/ld.so")
    result = pf.run_preflight(dyn_cell, "t")
    assert (result.ok, result.code) == (False, "interp_missing")
    assert result.interp == "/nonexistent/ld.so"


@needs_gcc
def test_a_zero_byte_loader_is_interp_empty(dyn_cell):
    _dyn_target(dyn_cell, "./ld.so")
    _write(dyn_cell / "ld.so", b"")
    assert pf.run_preflight(dyn_cell, "t").code == "interp_empty"


@needs_gcc
def test_a_directory_loader_is_interp_not_regular(dyn_cell):
    _dyn_target(dyn_cell, "./ld.so")
    (dyn_cell / "ld.so").mkdir()
    assert pf.run_preflight(dyn_cell, "t").code == "interp_not_regular"


@needs_gcc
def test_a_non_executable_loader_is_interp_not_executable(dyn_cell):
    _dyn_target(dyn_cell, "./ld.so")
    _write(dyn_cell / "ld.so", tiny_elf(), mode=0o644)
    assert pf.run_preflight(dyn_cell, "t").code == "interp_not_executable"


@needs_gcc
def test_a_loader_that_is_not_an_elf_is_interp_not_elf(dyn_cell):
    _dyn_target(dyn_cell, "./ld.so")
    _write(dyn_cell / "ld.so", b"#!/bin/sh\nexit 0\n")
    assert pf.run_preflight(dyn_cell, "t").code == "interp_not_elf"


@needs_gcc
def test_a_loader_of_the_wrong_class_is_interp_class_mismatch(dyn_cell):
    _dyn_target(dyn_cell, "./ld.so")
    _write(dyn_cell / "ld.so", tiny_elf(bits=32, machine=EM_386))
    assert pf.run_preflight(dyn_cell, "t").code == "interp_class_mismatch"


@needs_gcc
def test_a_loader_of_the_wrong_machine_is_interp_machine_mismatch(dyn_cell):
    _dyn_target(dyn_cell, "./ld.so")
    _write(dyn_cell / "ld.so", tiny_elf(machine=EM_AARCH64))
    assert pf.run_preflight(dyn_cell, "t").code == "interp_machine_mismatch"


@needs_gcc
@needs_host_loader
def test_a_real_relative_loader_is_ok(dyn_cell):
    _dyn_target(dyn_cell, "./ld.so")
    shutil.copy(os.path.realpath(HOST_LOADER), dyn_cell / "ld.so")
    result = pf.run_preflight(dyn_cell, "t")
    assert result.ok and result.interp == "./ld.so"


@needs_gcc
@needs_host_loader
def test_the_host_loader_at_its_absolute_path_is_ok(dyn_cell):
    _dyn_target(dyn_cell, str(HOST_LOADER))
    assert pf.run_preflight(dyn_cell, "t").ok


@needs_gcc
@needs_host_loader
def test_a_relative_loader_resolves_against_the_cell_not_the_cwd(dyn_cell, tmp_path, monkeypatch):
    _dyn_target(dyn_cell, "./ld.so")
    shutil.copy(os.path.realpath(HOST_LOADER), dyn_cell / "ld.so")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert pf.run_preflight(dyn_cell, "t").ok


@needs_gcc
@needs_host_loader
def test_a_staged_cell_with_a_relative_loader_passes_and_one_without_fails(tmp_path):
    src = build_lib_tree(tmp_path / "w")
    good = st.stage_cell(tmp_path / "run", "good", src, ["app"])
    assert pf.run_preflight(good.path, good.target).ok
    # Dropping the loader from the closure is what a broken staging would do.
    (good.path / "ld" / "ld.so").unlink()
    assert pf.run_preflight(good.path, good.target).code == "interp_missing"
    # A zero-byte loader (the S0 sabotage / bon-nie-appetit situation).
    (good.path / "ld" / "ld.so").write_bytes(b"")
    (good.path / "ld" / "ld.so").chmod(stat.S_IRWXU)
    assert pf.run_preflight(good.path, good.target).code == "interp_empty"


# --- the pinned reasons are exactly the ones the scorer knows -----------------


PINNED = {
    "target_missing",
    "target_not_regular",
    "target_empty",
    "unsupported_format",
    "target_not_executable",
    "machine_unsupported",
    "interp_missing",
    "interp_not_regular",
    "interp_empty",
    "interp_not_executable",
    "interp_not_elf",
    "interp_class_mismatch",
    "interp_machine_mismatch",
}


def test_codes_in_the_source_are_the_pinned_set():
    source = (BENCHMARK / "passcard_preflight.py").read_text()
    import re

    emitted = set(re.findall(r'_fail\(\s*"([a-z_]+)"', source))
    emitted |= {"interp_" + s for s in ("missing", "not_regular", "empty", "not_executable")}
    assert emitted == PINNED


# --- the real S0 binaries ----------------------------------------------------


def _truth(slug):
    return yaml.safe_load((REPO_ROOT / "benchmark/truth/s0" / f"{slug}.yaml").read_text())


# sabotage and bon-nie-appetit ship a zero-byte loader: OFF is VOID for them.
S0_PREFLIGHT = {
    "sick_rop": "",
    "rocket_blaster_xxx": "",
    "snow_scan": "",
    "ancient_interface": "",
    "auth-or-out": "",
    "sabotage": "interp_empty",
    "bon-nie-appetit": "interp_empty",
}


@needs_targets
@pytest.mark.parametrize("slug", S0_SLUGS)
def test_s0_preflight_matches_the_truth_file(slug, tmp_path):
    truth = _truth(slug)
    source = (TARGETS_ROOT / slug).resolve().parent
    cell = st.stage_cell(
        tmp_path, "c", source, truth["stage"]["files"], truth["stage"]["placeholders"],
        target=(TARGETS_ROOT / slug).resolve().name,
    )  # fmt: skip
    result = pf.run_preflight(cell.path, cell.target)
    assert result.code == S0_PREFLIGHT[slug], (slug, result)
    assert result.ok is (S0_PREFLIGHT[slug] == "")
