"""Tests for supwngo.core.exec_preflight (SP-01b, 4.1).

One case per rule, in the order the rules are applied. Header-only ELFs
(``tiny_elf``) stand in for loaders of the wrong class or machine and for
targets of a machine this host cannot run; they parse but are never executed.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from offset_support import build_asm_crash, copy_host_loader  # noqa: E402
from passcard_support import (  # noqa: E402
    REPO_ROOT,
    needs_gcc,
    needs_host_loader,
    tiny_elf,
)

from supwngo.core.exec_preflight import Preflight, check_executable  # noqa: E402

EM_AARCH64 = 183
EM_386 = 3
PE_DIR = REPO_ROOT / "benchmark" / "fixtures" / "s0pe"


def make_exec(path: Path, data: bytes, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


# --- rule 1: a regular, non-empty file ------------------------------------


def test_missing_target(tmp_path):
    result = check_executable(tmp_path / "nope")
    assert (result.ok, result.code) == (False, "target_missing")
    assert str(tmp_path / "nope") in result.detail


def test_directory_target(tmp_path):
    result = check_executable(tmp_path)
    assert (result.ok, result.code) == (False, "target_not_regular")


def test_empty_target(tmp_path):
    result = check_executable(make_exec(tmp_path / "t", b""))
    assert (result.ok, result.code) == (False, "target_empty")


# --- rule 2: a native ELF, before the executable bit ----------------------


@pytest.mark.parametrize("name", ["pe_sym.exe", "pe_strip.exe"])
def test_pe_is_unsupported_format_whatever_its_mode(tmp_path, name):
    data = (PE_DIR / name).read_bytes()
    for mode in (0o755, 0o644):  # never reads as a permissions problem
        result = check_executable(make_exec(tmp_path / name, data, mode))
        assert (result.ok, result.code) == (False, "unsupported_format"), mode
        assert "pe" in result.detail


@pytest.mark.parametrize(
    "data", [b"#!/bin/sh\nexit 0\n", b"\x7fELF", b"MZ", tiny_elf()[:40]]
)
def test_other_formats_and_truncated_elf_are_unsupported(tmp_path, data):
    result = check_executable(make_exec(tmp_path / "t", data))
    assert (result.ok, result.code) == (False, "unsupported_format")


# --- rule 3: executable ---------------------------------------------------


def test_non_executable_elf(tmp_path):
    result = check_executable(make_exec(tmp_path / "t", tiny_elf(), 0o644))
    assert (result.ok, result.code) == (False, "target_not_executable")


# --- rule 4: a machine this host runs -------------------------------------


def test_foreign_machine(tmp_path):
    target = make_exec(tmp_path / "t", tiny_elf(machine=EM_AARCH64))
    result = check_executable(target, host_machine="x86_64")
    assert (result.ok, result.code) == (False, "machine_unsupported")
    assert "EM_AARCH64" in result.detail and "x86_64" in result.detail


def test_host_machine_override_decides(tmp_path):
    target = make_exec(tmp_path / "t", tiny_elf(machine=EM_AARCH64))
    assert check_executable(target, host_machine="aarch64").ok
    assert not check_executable(target, host_machine="riscv64").ok
    i386 = make_exec(tmp_path / "t32", tiny_elf(bits=32, machine=EM_386))
    assert check_executable(i386, host_machine="x86_64").ok  # an x86-64 host runs i386


# --- rule 5: the interpreter ----------------------------------------------


def test_no_interpreter_is_fine(tmp_path):
    result = check_executable(
        make_exec(tmp_path / "t", tiny_elf()), host_machine="x86_64"
    )
    assert result == Preflight(True)


@needs_gcc
def test_static_binary_is_fine(tmp_path):
    result = check_executable(build_asm_crash(tmp_path))
    assert result.ok and result.interp is None


@needs_gcc
def test_host_dynamic_binary_is_fine(tmp_path):
    result = check_executable(
        build_asm_crash(tmp_path, interp="/lib64/ld-linux-x86-64.so.2")
    )
    assert result.ok
    assert result.interp == "/lib64/ld-linux-x86-64.so.2"


@needs_gcc
@needs_host_loader
def test_relative_interpreter_resolves_from_the_target_directory(tmp_path, monkeypatch):
    target = build_asm_crash(tmp_path / "chal", interp="./ld/ld.so")
    copy_host_loader(tmp_path / "chal" / "ld" / "ld.so")
    monkeypatch.chdir(tmp_path)  # not the target's directory
    result = check_executable(target)
    assert result.ok and result.interp == "./ld/ld.so"


@needs_gcc
def test_missing_loader_names_both_the_resolved_and_recorded_path(tmp_path):
    target = build_asm_crash(tmp_path, interp="./nope/ld.so")
    result = check_executable(target)
    assert (result.ok, result.code) == (False, "interp_missing")
    assert str(tmp_path / "nope" / "ld.so") in result.detail
    assert "./nope/ld.so" in result.detail
    assert result.interp == "./nope/ld.so"


@needs_gcc
def test_missing_absolute_loader(tmp_path):
    target = build_asm_crash(tmp_path, interp="/nonexistent/ld.so")
    result = check_executable(target)
    assert (result.ok, result.code) == (False, "interp_missing")
    assert "/nonexistent/ld.so" in result.detail


@needs_gcc
@pytest.mark.parametrize(
    "code, prepare",
    [
        ("interp_not_regular", lambda loader: loader.mkdir(parents=True)),
        ("interp_empty", lambda loader: make_exec(loader, b"")),
        (
            "interp_not_executable",
            lambda loader: make_exec(loader, tiny_elf(), 0o644),
        ),
        ("interp_not_elf", lambda loader: make_exec(loader, b"#!/bin/sh\n")),
        ("interp_not_elf", lambda loader: make_exec(loader, tiny_elf()[:40])),
        (
            "interp_not_elf",
            lambda loader: make_exec(loader, (PE_DIR / "pe_sym.exe").read_bytes()),
        ),
        (
            "interp_class_mismatch",
            lambda loader: make_exec(loader, tiny_elf(bits=32, machine=EM_386)),
        ),
        (
            "interp_machine_mismatch",
            lambda loader: make_exec(loader, tiny_elf(bits=64, machine=EM_AARCH64)),
        ),
    ],
)
def test_loader_problems(tmp_path, code, prepare):
    target = build_asm_crash(tmp_path, interp="./ld/ld.so")
    prepare(tmp_path / "ld" / "ld.so")
    result = check_executable(target)
    assert (result.ok, result.code) == (False, code)
    assert "./ld/ld.so" in result.detail
    assert result.interp == "./ld/ld.so"


@needs_gcc
def test_loader_symlink_is_followed(tmp_path):
    target = build_asm_crash(tmp_path, interp="./ld.so")
    (tmp_path / "ld.so").symlink_to("/lib64/ld-linux-x86-64.so.2")
    assert check_executable(target).ok
    (tmp_path / "ld.so").unlink()
    (tmp_path / "ld.so").symlink_to(tmp_path / "gone")
    assert check_executable(target).code == "interp_missing"


def test_first_failure_wins(tmp_path):
    """An empty file is reported as empty, not as an unsupported format."""
    assert (
        check_executable(make_exec(tmp_path / "t", b"", 0o644)).code == "target_empty"
    )
    # A non-ELF without the exec bit is a format problem, not a permission one.
    not_elf = make_exec(tmp_path / "u", b"text", 0o644)
    assert check_executable(not_elf).code == "unsupported_format"
    assert not os.access(not_elf, os.X_OK)
    assert stat.S_IMODE(not_elf.stat().st_mode) == 0o644
