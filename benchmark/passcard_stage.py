"""File-granular staging of one passcard cell (SP-01 plan sections 3.3 and 8.1 V-1).

A cell is a fresh host directory, ``<scratch>/<run>/<cell>``, laid out as::

    <cell>/<target and its dependency closure, placeholders>
    <cell>/tmp   <cell>/home   <cell>/cache      (TMPDIR, HOME, XDG_CACHE_HOME)

What goes in is an allowlist, never a directory copy:

* the truth file's ``stage.files`` (the shipped binary);
* the dependency closure, file by file. Start from the ``PT_INTERP`` file when it
  is relative, then add every ``DT_NEEDED`` soname that resolves to a file under
  the source directory, through a ``DT_RUNPATH``/``DT_RPATH`` entry or relative
  to the loader's directory, and repeat transitively. Only those resolved files
  are copied, keeping their relative paths;
* ``stage.placeholders``, written with neutral content.

Sources, write-ups, ``.debug`` siblings and every unlisted file stay out, which is
what keeps an answer key out of the cell. No scratch or cell path may contain a
dot-component: Ghidra rejects such a project path (V-1).

This module reads ELF headers with pyelftools and copies files. It runs nothing.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

CELL_SUBDIRS: Tuple[str, ...] = ("tmp", "home", "cache")

# Neutral content for ``stage.placeholders``. Deliberately not flag-shaped.
PLACEHOLDER_CONTENT = b"placeholder\n"

_ELF_MAGIC = b"\x7fELF"


class StageError(ValueError):
    """A staging request that cannot be honoured."""


class ElfError(ValueError):
    """A file that carries the ELF magic but cannot be parsed as an ELF."""


# --- paths -------------------------------------------------------------------


def has_dot_component(path: str) -> bool:
    """True when any component of ``path`` starts with ``.`` (``..`` included)."""
    return any(part.startswith(".") for part in str(path).split("/") if part)


def assert_no_dot_component(path: str, what: str = "path") -> None:
    """Raise StageError for a path Ghidra would reject (plan 8.1 V-1)."""
    if has_dot_component(str(path)):
        raise StageError("%s %r has a '.'-prefixed component" % (what, str(path)))


# --- ELF reading -------------------------------------------------------------


@dataclass(frozen=True)
class ElfInfo:
    """The header facts staging and preflight need."""

    elf_class: int  # 32 or 64
    machine: str  # pyelftools name, e.g. EM_X86_64
    etype: str  # e.g. ET_EXEC
    interp: Optional[str] = None
    needed: Tuple[str, ...] = ()
    runpath: Tuple[str, ...] = ()
    rpath: Tuple[str, ...] = ()


def has_elf_magic(path: os.PathLike) -> bool:
    """True when the file starts with ``\\x7fELF`` (unreadable files are False)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == _ELF_MAGIC
    except OSError:
        return False


def read_elf(path: os.PathLike) -> ElfInfo:
    """Parse ``path`` with pyelftools; raise ElfError when that is not possible."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    interp: Optional[str] = None
    needed: List[str] = []
    runpath: List[str] = []
    rpath: List[str] = []
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            for segment in elf.iter_segments():
                kind = segment["p_type"]
                if kind == "PT_INTERP":
                    interp = segment.get_interp_name()
                elif kind == "PT_DYNAMIC":
                    for tag in segment.iter_tags():
                        name = tag.entry.d_tag
                        if name == "DT_NEEDED":
                            needed.append(tag.needed)
                        elif name == "DT_RUNPATH":
                            runpath += [p for p in tag.runpath.split(":") if p]
                        elif name == "DT_RPATH":
                            rpath += [p for p in tag.rpath.split(":") if p]
            return ElfInfo(
                elf_class=elf.elfclass,
                machine=str(elf["e_machine"]),
                etype=str(elf["e_type"]),
                interp=interp,
                needed=tuple(needed),
                runpath=tuple(runpath),
                rpath=tuple(rpath),
            )
    except (ELFError, OSError, ValueError, KeyError, struct.error) as exc:
        raise ElfError("cannot parse %s as ELF: %s" % (path, exc)) from exc


# --- dependency closure ------------------------------------------------------


def _clean(rel: str) -> Optional[str]:
    """Normalise a relative posix path; None when it is absolute or escapes."""
    if rel.startswith("/"):
        return None
    norm = posixpath.normpath(rel)
    if norm == ".." or norm.startswith("../") or norm == ".":
        return None
    return norm


def _is_file(source_dir: Path, rel: str) -> bool:
    return (source_dir / rel).is_file()  # follows symlinks


def _search_dirs(obj_rel: str, info: ElfInfo, interp_dir: Optional[str]) -> List[str]:
    """Directories (relative to the source dir) searched for ``obj_rel``'s libraries."""
    origin = posixpath.dirname(obj_rel) or "."
    found: List[str] = []
    for entry in list(info.runpath) + list(info.rpath):
        entry = entry.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
        if "$" in entry or entry.startswith("/"):
            continue  # $LIB, $PLATFORM, or a host directory
        norm = posixpath.normpath(entry)
        if norm != ".." and not norm.startswith("../"):
            found.append(norm)
    if interp_dir is not None:
        found.append(interp_dir)
    return found


def compute_closure(source_dir: os.PathLike, seeds: Sequence[str]) -> List[str]:
    """Dependency files (relative paths) of ``seeds``, excluding the seeds.

    ``seeds`` are paths relative to ``source_dir``. Non-ELF seeds contribute no
    dependencies. The result is sorted and never contains a directory.
    """
    root = Path(source_dir)
    seeds_clean = [_clean(s) for s in seeds]
    if any(s is None for s in seeds_clean):
        raise StageError("stage file escapes the source directory: %r" % (seeds,))
    closure: Dict[str, None] = {}
    seen = set(seeds_clean)
    queue = list(seeds_clean)
    while queue:
        obj = queue.pop(0)
        path = root / obj
        if not path.is_file() or not has_elf_magic(path):
            continue
        info = read_elf(path)
        interp_dir: Optional[str] = None
        deps: List[str] = []
        if info.interp and not info.interp.startswith("/"):
            interp = _clean(info.interp)
            if interp is not None and _is_file(root, interp):
                deps.append(interp)
                interp_dir = posixpath.dirname(interp) or "."
        dirs = _search_dirs(obj, info, interp_dir)
        for soname in info.needed:
            if "/" in soname:
                hit = _clean(soname)
                if hit is not None and _is_file(root, hit):
                    deps.append(hit)
                continue
            for directory in dirs:
                candidate = _clean(posixpath.join(directory, soname))
                if candidate is not None and _is_file(root, candidate):
                    deps.append(candidate)
                    break
        for dep in deps:
            if dep not in seen:
                seen.add(dep)
                closure[dep] = None
                queue.append(dep)
    return sorted(closure)


# --- staging -----------------------------------------------------------------


@dataclass
class StagedCell:
    """A staged cell directory and what was put in it."""

    path: Path
    source_dir: Path
    target: str  # the shipped binary, relative to ``path``
    files: List[str]  # every staged file, relative, sorted (placeholders included)
    closure: List[str] = field(default_factory=list)
    placeholders: List[str] = field(default_factory=list)
    sha256: str = ""  # of the target as staged

    @property
    def target_path(self) -> Path:
        return self.path / self.target


def sha256_file(path: os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def staged_files(cell: os.PathLike) -> List[str]:
    """Sorted relative paths of every file in a cell, outside tmp/home/cache."""
    root = Path(cell)
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d not in CELL_SUBDIRS]
        for name in filenames:
            rel = os.path.join(rel_dir, name) if rel_dir != "." else name
            found.append(rel.replace(os.sep, "/"))
    return sorted(found)


def _copy_file(source_dir: Path, rel: str, cell: Path) -> None:
    src, dst = source_dir / rel, cell / rel
    if not src.is_file():
        raise StageError("%s is not a file under %s" % (rel, source_dir))
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)  # follows symlinks: the content is staged, not the link


def stage_cell(
    run_dir: os.PathLike,
    cell_name: str,
    source_dir: os.PathLike,
    files: Iterable[str],
    placeholders: Iterable[str] = (),
    *,
    target: Optional[str] = None,
) -> StagedCell:
    """Build one cell under ``run_dir`` and return what it holds.

    ``files`` are relative to ``source_dir``; ``target`` (default: the first
    file) is the shipped binary. Raises StageError for a dot-component path, a
    file that escapes ``source_dir``, a placeholder that collides with a staged
    file, or a name that collides with the cell's own tmp/home/cache directories.
    """
    source = Path(source_dir)
    cell = Path(run_dir) / cell_name
    assert_no_dot_component(str(cell), "cell path")
    file_list = [_clean(f) for f in files]
    if not file_list or any(f is None for f in file_list):
        raise StageError("stage.files must be non-empty relative paths: %r" % (files,))
    holders = [_clean(p) for p in placeholders]
    if any(p is None for p in holders):
        raise StageError("placeholder escapes the cell: %r" % (placeholders,))
    target = file_list[0] if target is None else _clean(target)
    if target not in file_list:
        raise StageError("target %r is not among stage.files %r" % (target, file_list))
    for rel in file_list + holders:
        if rel.split("/")[0] in CELL_SUBDIRS:
            raise StageError("%r collides with the cell's own %s" % (rel, CELL_SUBDIRS))
    if set(holders) & set(file_list):
        raise StageError("a placeholder collides with a staged file")

    closure = compute_closure(source, file_list)
    if cell.exists():
        raise StageError("cell %s already exists" % cell)
    cell.mkdir(parents=True)
    for sub in CELL_SUBDIRS:
        (cell / sub).mkdir()
        assert_no_dot_component(str(cell / sub), "cell directory")
    for rel in file_list + closure:
        _copy_file(source, rel, cell)
    for rel in holders:
        dst = cell / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(PLACEHOLDER_CONTENT)

    expected = sorted(set(file_list) | set(closure) | set(holders))
    actual = staged_files(cell)
    if actual != expected:  # a self-check, not an input error
        raise StageError("staged %r but the closure is %r" % (actual, expected))
    return StagedCell(
        path=cell,
        source_dir=source,
        target=target,
        files=actual,
        closure=closure,
        placeholders=sorted(set(holders)),
        sha256=sha256_file(cell / target),
    )
