"""
Preflight: can this target be executed here at all?

Run before a tool spends time launching a target, so that a binary which can
never start (a PE, a missing or empty loader, the wrong CPU) is reported as
that, instead of as "no crash found". Rules, in order; the first failure wins:

1. The target must be a regular, non-empty file: ``target_missing``,
   ``target_not_regular``, ``target_empty``.
2. It must be a native ELF: ``unsupported_format`` for a PE or anything else.
   This precedes the executable bit, so a PE never reads as a permissions problem.
3. It must be executable: ``target_not_executable``.
4. The host must run its machine: ``machine_unsupported``.
5. No ``PT_INTERP`` is fine (static, static-PIE). An absolute interpreter is
   checked at its host path; a relative one is resolved against the target's
   directory, which is the working directory the target is launched from. The
   loader must be a regular, non-empty, executable file (``interp_missing``,
   ``interp_not_regular``, ``interp_empty``, ``interp_not_executable``) and an
   ELF of the target's class and machine (``interp_not_elf``,
   ``interp_class_mismatch``, ``interp_machine_mismatch``).

The benchmark harness keeps its own copy of these rules (``benchmark/
passcard_preflight.py``) so that the instrument does not share judgement code
with the product it measures.
"""

from __future__ import annotations

import os
import platform
import posixpath
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Tuple, Union

from supwngo.core.fileformat import ELF, detect_format

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
    """``ok``, or the failing rule's ``code`` and a ``detail`` that names the file.

    ``interp`` is the interpreter path exactly as recorded in the ELF, when the
    target has one.
    """

    ok: bool
    code: str = ""
    detail: str = ""
    interp: Optional[str] = None


def _fail(code: str, detail: str, interp: Optional[str] = None) -> Preflight:
    return Preflight(False, code, detail, interp)


def _elf_facts(path: Path) -> Optional[Tuple[int, str, Optional[str]]]:
    """``(class, machine, interpreter)`` of an ELF, or ``None`` if unparseable."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            interp = None
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_INTERP":
                    interp = segment.get_interp_name()
                    break
            return elf.elfclass, str(elf["e_machine"]), interp
    except (ELFError, OSError, ValueError, KeyError, EOFError):
        return None


def _file_problem(path: Path, prefix: str, label: str) -> Optional[Preflight]:
    """Rule 1 for one file; ``None`` when it is regular and non-empty."""
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
    return None


def check_executable(
    path: Union[str, "os.PathLike[str]"], *, host_machine: Optional[str] = None
) -> Preflight:
    """Apply the rules to ``path``; its directory is the launch directory."""
    target = Path(os.fspath(path))

    problem = _file_problem(target, "target", "target")
    if problem is not None:
        return problem

    detected = detect_format(target)
    if detected != ELF:
        return _fail(
            "unsupported_format",
            "%s is not a native ELF file (detected: %s)" % (target, detected),
        )
    facts = _elf_facts(target)
    if facts is None:
        return _fail("unsupported_format", "%s is not a parseable ELF file" % target)
    elf_class, machine, interp = facts

    if not os.access(target, os.X_OK):
        return _fail("target_not_executable", "target %s is not executable" % target)

    host = (host_machine or platform.machine()).lower()
    if machine not in _HOST_MACHINES.get(host, frozenset()):
        return _fail(
            "machine_unsupported",
            "target machine %s cannot run on host %s" % (machine, host),
        )

    if not interp:
        return Preflight(True)

    if interp.startswith("/"):
        loader = Path(interp)
    else:
        loader = Path(posixpath.normpath(str(target.parent / interp)))
    problem = _file_problem(loader, "interp", "interpreter")
    if problem is not None:
        detail = "%s (recorded as %s)" % (problem.detail, interp)
        return _fail(problem.code, detail, interp)
    if not os.access(loader, os.X_OK):
        return _fail(
            "interp_not_executable",
            "interpreter %s (recorded as %s) is not executable" % (loader, interp),
            interp,
        )

    loader_facts = _elf_facts(loader) if detect_format(loader) == ELF else None
    if loader_facts is None:
        return _fail(
            "interp_not_elf",
            "interpreter %s (recorded as %s) is not an ELF file" % (loader, interp),
            interp,
        )
    if loader_facts[0] != elf_class:
        return _fail(
            "interp_class_mismatch",
            "interpreter %s (recorded as %s) is ELF%d, target is ELF%d"
            % (loader, interp, loader_facts[0], elf_class),
            interp,
        )
    if loader_facts[1] != machine:
        return _fail(
            "interp_machine_mismatch",
            "interpreter %s (recorded as %s) is %s, target is %s"
            % (loader, interp, loader_facts[1], machine),
            interp,
        )
    return Preflight(True, interp=interp)
