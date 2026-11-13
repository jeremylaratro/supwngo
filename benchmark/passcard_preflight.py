"""Passcard preflight: can the staged target be executed at all? (plan section 3.5)

Applied with pyelftools against the cell directory, which is also the working
directory of every command. The rules, in order:

1. The target must exist and be a regular, non-empty file; otherwise
   ``target_missing`` / ``target_not_regular`` / ``target_empty``.
6. A file that is not a native ELF (a PE, anything else) is ``unsupported_format``.
   This is checked before the executable bit, so a PE never reads as a permissions
   problem. An ELF that cannot be parsed is also ``unsupported_format``.
4. The target must be executable: ``target_not_executable``.
5. The host must be able to run the target's machine: ``machine_unsupported``.
1. No ``PT_INTERP`` is fine (static, static-PIE).
2. An absolute interpreter is checked at its host path.
3. A relative interpreter is resolved against the cell directory.
4. The loader must be a regular, non-empty, executable file: ``interp_missing`` /
   ``interp_not_regular`` / ``interp_empty`` / ``interp_not_executable``.
5. The loader must be an ELF of the target's class and machine:
   ``interp_not_elf`` / ``interp_class_mismatch`` / ``interp_machine_mismatch``.

A failure makes only the execution-dependent cells VOID (OFF); ``pwn``,
``template`` (static) and ``decompile`` are still scored and ROBUST is scored on
every cell. The scorer takes ``Preflight.code`` as its ``preflight_void`` reason.

This module is the instrument's own copy. The product gets a separate one in
SP-01b, so the harness does not share judgement code with what it measures.
"""

from __future__ import annotations

import os
import platform
import posixpath
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Optional

from passcard_stage import ElfError, ElfInfo, has_elf_magic, read_elf

# ``platform.machine()`` -> the ELF machines that host can execute.
_HOST_MACHINES: Dict[str, FrozenSet[str]] = {
    "x86_64": frozenset({"EM_X86_64", "EM_386"}),
    "amd64": frozenset({"EM_X86_64", "EM_386"}),
    "i386": frozenset({"EM_386"}),
    "i686": frozenset({"EM_386"}),
    "aarch64": frozenset({"EM_AARCH64", "EM_ARM"}),
    "arm64": frozenset({"EM_AARCH64", "EM_ARM"}),
    "armv7l": frozenset({"EM_ARM"}),
}


@dataclass(frozen=True)
class Preflight:
    """``ok`` or the pinned reason code. ``interp`` is the loader path as recorded."""

    ok: bool
    code: str = ""
    detail: str = ""
    interp: Optional[str] = None

    @property
    def void_reason(self) -> Optional[str]:
        """The reason to hand the scorer as ``preflight_void`` (None when ok)."""
        return None if self.ok else self.code


def _fail(code: str, detail: str, interp: Optional[str] = None) -> Preflight:
    return Preflight(False, code, detail, interp)


def _file_problem(path: Path, prefix: str, label: str) -> Optional[Preflight]:
    """Rule 4 for one file, as a failure (None when it is fine)."""
    try:
        info = os.stat(path)  # follows symlinks
    except OSError as exc:
        return _fail(prefix + "_missing", "%s %s: %s" % (label, path, exc.strerror))
    if not stat.S_ISREG(info.st_mode):
        return _fail(
            prefix + "_not_regular", "%s %s is not a regular file" % (label, path)
        )
    if info.st_size == 0:
        return _fail(prefix + "_empty", "%s %s is zero bytes" % (label, path))
    if not os.access(path, os.X_OK):
        return _fail(
            prefix + "_not_executable", "%s %s is not executable" % (label, path)
        )
    return None


def _host_machines(machine: Optional[str]) -> FrozenSet[str]:
    machine = (machine or platform.machine()).lower()
    return _HOST_MACHINES.get(machine, frozenset())


def run_preflight(
    cell_dir: os.PathLike, target: str, *, host_machine: Optional[str] = None
) -> Preflight:
    """Apply the section 3.5 rules to ``target`` (relative to ``cell_dir``)."""
    cell = Path(cell_dir)
    path = cell / target

    # Rule 4 for the target, up to the format check (which precedes the x bit).
    try:
        info = os.stat(path)
    except OSError as exc:
        return _fail("target_missing", "%s: %s" % (path, exc.strerror))
    if not stat.S_ISREG(info.st_mode):
        return _fail("target_not_regular", "%s is not a regular file" % path)
    if info.st_size == 0:
        return _fail("target_empty", "%s is zero bytes" % path)

    # Rule 6: PE or any other non-native format.
    if not has_elf_magic(path):
        return _fail("unsupported_format", "%s is not an ELF file" % path)
    try:
        elf = read_elf(path)
    except ElfError as exc:
        return _fail("unsupported_format", str(exc))

    if not os.access(path, os.X_OK):
        return _fail("target_not_executable", "%s is not executable" % path)

    # Rule 5, host half.
    if elf.machine not in _host_machines(host_machine):
        return _fail(
            "machine_unsupported",
            "target machine %s cannot run on host %s"
            % (elf.machine, host_machine or platform.machine()),
        )

    interp = elf.interp
    if not interp:  # rule 1
        return Preflight(True)

    if interp.startswith("/"):  # rule 2: the host path
        loader = Path(interp)
    else:  # rule 3: resolved against the cell directory
        loader = Path(posixpath.normpath(str(cell / interp)))
    problem = _file_problem(loader, "interp", "interpreter")
    if problem is not None:
        return Preflight(False, problem.code, problem.detail, interp)

    # Rule 5, loader half.
    if not has_elf_magic(loader):
        return _fail(
            "interp_not_elf", "interpreter %s is not an ELF file" % loader, interp
        )
    try:
        loader_elf: ElfInfo = read_elf(loader)
    except ElfError as exc:
        return _fail("interp_not_elf", str(exc), interp)
    if loader_elf.elf_class != elf.elf_class:
        return _fail(
            "interp_class_mismatch",
            "interpreter is ELF%d, target is ELF%d"
            % (loader_elf.elf_class, elf.elf_class),
            interp,
        )
    if loader_elf.machine != elf.machine:
        return _fail(
            "interp_machine_mismatch",
            "interpreter is %s, target is %s" % (loader_elf.machine, elf.machine),
            interp,
        )
    return Preflight(True, interp=interp)
