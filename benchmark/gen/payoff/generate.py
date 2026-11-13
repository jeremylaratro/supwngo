#!/usr/bin/env python3
"""Seeded generator for the payoff corpus v0 (W-0 of the retire-hardcoded-values plan).

The corpus tests identifying a payoff function by analysis rather than by name. It
writes C sources, builds them, and writes a truth file (the answer key) per binary
plus one index, all under ``--out``::

    out/index.json          what was built (written last)
    out/src/<id>.c          one source per positive/negative (twins and PE reuse one)
    out/bin/<id>            the binaries (``.exe`` for PE)
    out/truth/<id>.json     the answer key, never embedded in the binary

Usage::

    python3 -B benchmark/gen/payoff/generate.py --set dev [--seed N] [--out DIR]
    python3 -B benchmark/gen/payoff/generate.py --set held --seed N --out DIR
    SUPWNGO_PAYOFF_HELD_SEED=N python3 -B ... --set held --out DIR

The default dev output is ``benchmark/gen/payoff/build/`` (git-ignored), default
dev seed 1. The held set is only ever built to a caller-supplied ``--out`` outside
the repository from a caller-supplied seed (``--seed`` or the environment variable
``SUPWNGO_PAYOFF_HELD_SEED``); the generator refuses an in-repository ``--out`` and
never records a held seed anywhere but in the held truth beside the held binaries.

Dev set (exact counts)::

    32 positives   ELF amd64, gcc: 4 shapes x PIE on/off x stripped/unstripped x 2
                   seeds. Shapes: exec (a fixed command via execve or system), file
                   (a fixed path opened and written to stdout), arg1 and arg3 (a
                   parameter, resp. three parameters, compared with constants, and
                   only then exec or file).
    32 twins       of the 16 unstripped positives: 16 rename twins (every generated
                   function renamed with ``objcopy --redefine-sym``; ``main`` keeps
                   its name) and 16 strip twins (``strip``). Addresses are unchanged
                   by construction and asserted.
     8 negatives   the same skeleton and decoys, no payoff function:
                   PIE on/off x stripped/unstripped x 2 seeds.
     8 PE          mingw ``x86_64-w64-mingw32-gcc`` builds of the source of the
                   k=0, non-PIE positive of each shape, unstripped and stripped
                   (4 shapes x 2); truth uses the PE ImageBase.

Held set: 16 ELF positives, 4 shapes x PIE on/off x stripped/unstripped, one seed
each, under opaque ids (``held-NN``).

"Two seeds" is read as two replicates (k = 0, 1) per cell; each replicate has its own
seed derived from the master seed and its id, so the 32 dev positives are 32
different programs.

Address convention (V-10): ``rva = address - image_base``, the image base being the
lowest PT_LOAD vaddr for ELF and ImageBase for PE. Truth carries both.

Truth keys: schema_version, id, set, kind (positive, negative, rename_twin,
strip_twin, pe), format, arch, shape (exec, file, arg1, arg3, or null),
shape_letter (a-d), pie, stripped, twin_of, twin_kind, built_from, image_base,
payoff_vaddr, payoff_rva, payoff_symbol, required_args ([{position, value}]),
decoys (rva by kind: nop, filecopy, compare), decoy_called, functions (name, role,
rva, called, ascending by rva), names (every generated identifier), renames,
symbols_present, program (generator facts), binary, source, build, seed,
binary_seed, tools, generator_version. ``called`` means ``main`` contains a call to
the function; the payoff is never called. For a stripped binary the names in
``functions`` are the names assigned at generation and ``symbols_present`` is false.

Same seed and toolchain give the same sources, truth and binaries. The source file
name is not embedded (gcc reads the source from stdin) and mingw gets
``--no-insert-timestamp``.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import payoff_names  # noqa: E402
import payoff_source  # noqa: E402

REPO_ROOT = HERE.parents[2]
DEFAULT_DEV_OUT = HERE / "build"
DEFAULT_DEV_SEED = "1"
HELD_SEED_ENV = "SUPWNGO_PAYOFF_HELD_SEED"
CORPUS_NAME = "payoff-corpus-v0"
GENERATOR_VERSION = 1
SCHEMA_VERSION = 1
SHAPES = payoff_source.SHAPES

ELF_BASE_FLAGS = ["-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0"]
ELF_PIE_FLAGS = ["-fPIE", "-pie"]
ELF_NOPIE_FLAGS = ["-fno-pie", "-no-pie"]
PE_FLAGS = [
    "-O0",
    "-fno-stack-protector",
    "-DBUILD_FOR_PE=1",
    "-Wl,--no-insert-timestamp",
]

PT_LOAD = 1
ET_DYN = 3
SHF_ALLOC = 2
SHT_NOBITS = 8
DLL_DYNAMIC_BASE = 0x40


class BuildError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Toolchain


@dataclasses.dataclass
class Tools:
    gcc: str
    objcopy: str
    strip: str
    nm: str
    mingw_gcc: Optional[str]
    mingw_strip: Optional[str]
    versions: Dict[str, str]


def _first_line(cmd: str) -> str:
    proc = subprocess.run([cmd, "--version"], capture_output=True, text=True)
    lines = (proc.stdout or proc.stderr).splitlines()
    return lines[0].strip() if lines else "unknown"


def find_tools(with_pe: bool) -> Tools:
    def need(name: str) -> str:
        found = shutil.which(name)
        if not found:
            raise BuildError("required tool not found on PATH: %s" % name)
        return found

    gcc, objcopy, strip, nm = (need(n) for n in ("gcc", "objcopy", "strip", "nm"))
    mingw_gcc = mingw_strip = None
    versions = {
        "gcc": _first_line(gcc),
        "objcopy": _first_line(objcopy),
        "strip": _first_line(strip),
        "nm": _first_line(nm),
        "python": "%d.%d.%d" % sys.version_info[:3],
    }
    if with_pe:
        mingw_gcc = need("x86_64-w64-mingw32-gcc")
        mingw_strip = need("x86_64-w64-mingw32-strip")
        versions["mingw_gcc"] = _first_line(mingw_gcc)
        versions["mingw_strip"] = _first_line(mingw_strip)
    return Tools(gcc, objcopy, strip, nm, mingw_gcc, mingw_strip, versions)


def run(cmd: Sequence[str], stdin: Optional[str] = None) -> str:
    proc = subprocess.run(list(cmd), input=stdin, capture_output=True, text=True)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout)[-1500:]
        raise BuildError(
            "%s failed (%d): %s" % (" ".join(cmd[:2]), proc.returncode, tail)
        )
    return proc.stdout


# ---------------------------------------------------------------------------
# Reading just enough of ELF and PE to know the image base and the loaded bytes


@dataclasses.dataclass
class Image:
    fmt: str
    image_base: int
    pie: bool
    pieces: Dict[int, bytes]  # link-time address (ELF) or RVA (PE) -> loaded bytes
    has_symbols: bool = False
    layout: Tuple[Tuple[int, ...], ...] = ()  # ELF program headers


def read_image(path: Path) -> Image:
    data = Path(path).read_bytes()
    if data[:4] == b"\x7fELF":
        return _read_elf(data)
    if data[:2] == b"MZ":
        return _read_pe(data)
    raise BuildError("%s is neither ELF nor PE" % path)


def _read_elf(data: bytes) -> Image:
    if data[4] != 2 or data[5] != 1:
        raise BuildError("not a little-endian ELF64")
    (e_type,) = struct.unpack_from("<H", data, 16)
    (e_machine,) = struct.unpack_from("<H", data, 18)
    if e_machine != 62:
        raise BuildError("not x86-64 (e_machine %d)" % e_machine)
    (phoff,) = struct.unpack_from("<Q", data, 32)
    (shoff,) = struct.unpack_from("<Q", data, 40)
    phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", data, 54)
    loads: List[int] = []
    layout: List[Tuple[int, ...]] = []
    for i in range(phnum):
        fields = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _al = fields
        layout.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
        if p_type == PT_LOAD:
            loads.append(p_vaddr)
    if not loads:
        raise BuildError("ELF has no PT_LOAD segment")
    # The ELF header sits in the first PT_LOAD and strip/objcopy rewrite its section
    # table fields, so compare the bytes of every loaded section instead.
    pieces: Dict[int, bytes] = {}
    for i in range(shnum):
        fields = struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize)
        _name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = fields
        if sh_flags & SHF_ALLOC and sh_type != SHT_NOBITS:
            pieces[sh_addr] = data[sh_offset : sh_offset + sh_size]
    return Image("elf", min(loads), e_type == ET_DYN, pieces, layout=tuple(layout))


def _read_pe(data: bytes) -> Image:
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise BuildError("bad PE signature")
    coff = e_lfanew + 4
    _machine, nsections, _stamp, _symptr, nsymbols, optsize, _chars = (
        struct.unpack_from("<HHIIIHH", data, coff)
    )
    opt = coff + 20
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic != 0x20B:
        raise BuildError("not PE32+ (magic %#x)" % magic)
    (image_base,) = struct.unpack_from("<Q", data, opt + 24)
    (dll_chars,) = struct.unpack_from("<H", data, opt + 70)
    pieces: Dict[int, bytes] = {}
    table = opt + optsize
    for i in range(nsections):
        _name, _vsize, vaddr, rawsize, rawptr = struct.unpack_from(
            "<8sIIII", data, table + i * 40
        )
        if rawsize:
            pieces[vaddr] = data[rawptr : rawptr + rawsize]
    return Image(
        "pe", image_base, bool(dll_chars & DLL_DYNAMIC_BASE), pieces, nsymbols > 0
    )


def function_symbols(tools: Tools, path: Path) -> Dict[str, int]:
    """Defined text symbols (name -> link-time address) from ``nm``."""
    out = run([tools.nm, "--defined-only", str(path)])
    symbols: Dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t"):
            symbols[parts[2]] = int(parts[0], 16)
    return symbols


def assert_same_image(before: Image, after: Image, label: str, exact: bool) -> None:
    """The loaded bytes are unchanged (strip and objcopy touch only symbol data)."""
    if before.image_base != after.image_base or before.pie != after.pie:
        raise BuildError("%s: image base or type changed" % label)
    if exact:
        same = before.pieces == after.pieces and before.layout == after.layout
    else:  # PE strip also drops the discardable debug sections
        same = after.pieces.items() <= before.pieces.items()
    if not same:
        raise BuildError("%s: loaded bytes changed" % label)


# ---------------------------------------------------------------------------
# Plan


@dataclasses.dataclass(frozen=True)
class Unit:
    id: str
    kind: str  # positive | negative
    shape: Optional[str]
    pie: bool
    stripped: bool
    twins: bool = False


@dataclasses.dataclass(frozen=True)
class PeUnit:
    id: str
    base: Unit
    stripped: bool


def _pie_tag(pie: bool) -> str:
    return "pie" if pie else "nopie"


def _strip_tag(stripped: bool) -> str:
    return "stripped" if stripped else "unstripped"


def positive_id(shape: str, pie: bool, stripped: bool, k: int) -> str:
    return "pos-%s-%s-%s-%d" % (shape, _pie_tag(pie), _strip_tag(stripped), k)


def plan_dev() -> Tuple[List[Unit], List[PeUnit]]:
    units: List[Unit] = []
    for shape in SHAPES:
        for pie in (False, True):
            for stripped in (False, True):
                for k in (0, 1):
                    units.append(
                        Unit(
                            positive_id(shape, pie, stripped, k),
                            "positive",
                            shape,
                            pie,
                            stripped,
                            twins=not stripped,
                        )
                    )
    for pie in (False, True):
        for stripped in (False, True):
            for k in (0, 1):
                nid = "neg-%s-%s-%d" % (_pie_tag(pie), _strip_tag(stripped), k)
                units.append(Unit(nid, "negative", None, pie, stripped))
    by_id = {u.id: u for u in units}
    pes = [
        PeUnit("pe-%s-%s" % (shape, _strip_tag(stripped)), base, stripped)
        for shape in SHAPES
        for stripped in (False, True)
        for base in (by_id[positive_id(shape, False, stripped, 0)],)
    ]
    return units, pes


def plan_held(master: str) -> Tuple[List[Unit], List[PeUnit]]:
    cells = [
        (shape, pie, stripped)
        for shape in SHAPES
        for pie in (False, True)
        for stripped in (False, True)
    ]
    random.Random(unit_seed(master, "held-order")).shuffle(cells)
    units = [
        Unit("held-%02d" % i, "positive", shape, pie, stripped)
        for i, (shape, pie, stripped) in enumerate(cells)
    ]
    return units, []


def master_hex(set_name: str, seed_text: str) -> str:
    text = "%s|%s|%s" % (CORPUS_NAME, set_name, seed_text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def unit_seed(master: str, unit_id: str) -> int:
    return int(hashlib.sha256(("%s|%s" % (master, unit_id)).encode()).hexdigest(), 16)


# ---------------------------------------------------------------------------
# Building


@dataclasses.dataclass
class Context:
    out: Path
    work: Path
    tools: Tools
    deps: payoff_names.Deps
    set_name: str
    seed_text: str
    master: str


def compile_elf(tools: Tools, source: str, out: Path, pie: bool) -> List[str]:
    flags = ELF_BASE_FLAGS + (ELF_PIE_FLAGS if pie else ELF_NOPIE_FLAGS)
    run([tools.gcc, "-w", *flags, "-x", "c", "-", "-o", str(out)], stdin=source)
    return flags


def compile_pe(tools: Tools, source: str, out: Path) -> List[str]:
    assert tools.mingw_gcc
    run(
        [tools.mingw_gcc, "-w", *PE_FLAGS, "-x", "c", "-", "-o", str(out)], stdin=source
    )
    return list(PE_FLAGS)


def resolve_rvas(
    program: payoff_source.Program,
    symbols: Dict[str, int],
    image_base: int,
    label: str,
) -> Dict[str, int]:
    rvas: Dict[str, int] = {}
    for func in program.functions:
        if func.name not in symbols:
            raise BuildError("%s: no symbol for %s" % (label, func.name))
        rva = symbols[func.name] - image_base
        if rva <= 0:
            raise BuildError("%s: %s is below the image base" % (label, func.name))
        rvas[func.name] = rva
    order = [rvas[f.name] for f in program.functions]
    if order != sorted(order) or len(set(order)) != len(order):
        raise BuildError("%s: address order differs from source order" % label)
    return rvas


def _truth(
    ctx: Context,
    *,
    id: str,
    kind: str,
    fmt: str,
    program: payoff_source.Program,
    image: Image,
    rvas: Dict[str, int],
    stripped: bool,
    binary_rel: str,
    source_rel: str,
    flags: List[str],
    post: Optional[str],
    binary_seed: int,
    twin_of: Optional[str] = None,
    built_from: Optional[str] = None,
    renames: Optional[Dict[str, str]] = None,
) -> dict:
    renames = renames or {}
    shown = {f.name: renames.get(f.name, f.name) for f in program.functions}
    payoff = next((f for f in program.functions if f.role == "payoff"), None)
    decoy_by_role = {
        f.role.split("_", 1)[1]: f
        for f in program.functions
        if f.role.startswith("decoy_")
    }
    base = image.image_base
    functions = [
        {
            "name": shown[f.name],
            "role": f.role,
            "rva": rvas[f.name],
            "called": f.called,
        }
        for f in sorted(program.functions, key=lambda f: rvas[f.name])
    ]
    names = sorted(
        [shown[f.name] for f in program.functions if f.role != "main"]
        + program.globals_
    )
    letter = payoff_source.SHAPE_LETTERS.get(program.shape or "")
    return {
        "schema_version": SCHEMA_VERSION,
        "id": id,
        "set": ctx.set_name,
        "kind": kind,
        "format": fmt,
        "arch": "x86_64",
        "shape": program.shape,
        "shape_letter": letter,
        "pie": image.pie,
        "stripped": stripped,
        "twin_of": twin_of,
        "twin_kind": {"rename_twin": "rename", "strip_twin": "strip"}.get(kind),
        "built_from": built_from,
        "image_base": base,
        "payoff_vaddr": rvas[payoff.name] + base if payoff else None,
        "payoff_rva": rvas[payoff.name] if payoff else None,
        "payoff_symbol": None if stripped or not payoff else shown[payoff.name],
        "required_args": program.required_args,
        "decoys": {k: rvas[f.name] for k, f in sorted(decoy_by_role.items())},
        "decoy_called": {k: f.called for k, f in sorted(decoy_by_role.items())},
        "functions": functions,
        "names": names,
        "renames": dict(sorted(renames.items())),
        "symbols_present": not stripped,
        "program": program.detail,
        "binary": binary_rel,
        "source": source_rel,
        "build": {"flags": flags, "post": post},
        "seed": ctx.seed_text,
        "binary_seed": "%x" % binary_seed,
        "tools": ctx.tools.versions,
        "generator_version": GENERATOR_VERSION,
    }


def build_elf_unit(
    ctx: Context, unit: Unit, program: payoff_source.Program
) -> List[dict]:
    source_rel = "src/%s.c" % unit.id
    (ctx.out / source_rel).write_text(program.source, encoding="utf-8", newline="\n")
    seed = unit_seed(ctx.master, unit.id)
    final = ctx.out / "bin" / unit.id
    sym_path = ctx.work / (unit.id + ".sym") if unit.stripped else final
    flags = compile_elf(ctx.tools, program.source, sym_path, unit.pie)
    image = read_image(sym_path)
    rvas = resolve_rvas(
        program, function_symbols(ctx.tools, sym_path), image.image_base, unit.id
    )
    common = dict(
        program=program,
        rvas=rvas,
        source_rel=source_rel,
        flags=flags,
        fmt="elf",
    )
    kind = unit.kind
    if unit.stripped:
        run([ctx.tools.strip, "-o", str(final), str(sym_path)])
        stripped_image = read_image(final)
        assert_same_image(image, stripped_image, unit.id, exact=True)
        if function_symbols(ctx.tools, final):
            raise BuildError("%s: strip left symbols behind" % unit.id)
        os.remove(sym_path)
    truth = [
        _truth(
            ctx,
            id=unit.id,
            kind=kind,
            image=image,
            stripped=unit.stripped,
            binary_rel="bin/" + unit.id,
            post="strip" if unit.stripped else None,
            binary_seed=seed,
            **common,
        )
    ]
    if unit.twins:
        truth.append(_strip_twin(ctx, unit, final, image, seed, common))
        truth.append(_rename_twin(ctx, unit, final, image, program, common))
    return truth


def _strip_twin(
    ctx: Context, unit: Unit, original: Path, image: Image, seed: int, common: dict
) -> dict:
    twin_id = unit.id + "-twin-stripped"
    path = ctx.out / "bin" / twin_id
    run([ctx.tools.strip, "-o", str(path), str(original)])
    assert_same_image(image, read_image(path), twin_id, exact=True)
    if function_symbols(ctx.tools, path):
        raise BuildError("%s: strip left symbols behind" % twin_id)
    return _truth(
        ctx,
        id=twin_id,
        kind="strip_twin",
        image=image,
        stripped=True,
        binary_rel="bin/" + twin_id,
        post="strip",
        binary_seed=seed,
        twin_of=unit.id,
        **common,
    )


def _rename_twin(
    ctx: Context,
    unit: Unit,
    original: Path,
    image: Image,
    program: payoff_source.Program,
    common: dict,
) -> dict:
    twin_id = unit.id + "-twin-renamed"
    seed = unit_seed(ctx.master, twin_id)
    rng = random.Random(seed)
    ns = payoff_names.Namespace(rng, ctx.deps, used=program.names)
    mapping = {f.name: ns.fresh() for f in program.functions if f.role != "main"}
    path = ctx.out / "bin" / twin_id
    cmd = [ctx.tools.objcopy]
    for old, new in mapping.items():
        cmd.extend(["--redefine-sym", "%s=%s" % (old, new)])
    run([*cmd, str(original), str(path)])
    assert_same_image(image, read_image(path), twin_id, exact=True)
    after = function_symbols(ctx.tools, path)
    before = function_symbols(ctx.tools, original)
    for old, new in mapping.items():
        if old in after or after.get(new) != before[old]:
            raise BuildError(
                "%s: rename of %s did not keep its address" % (twin_id, old)
            )
    bad = payoff_names.check_names(ctx.deps, list(mapping.values()))
    if bad:
        raise BuildError("%s: names violate the namespace: %s" % (twin_id, bad))
    return _truth(
        ctx,
        id=twin_id,
        kind="rename_twin",
        image=image,
        stripped=False,
        binary_rel="bin/" + twin_id,
        post="objcopy --redefine-sym",
        binary_seed=seed,
        twin_of=unit.id,
        renames=mapping,
        **common,
    )


def build_pe_unit(
    ctx: Context, pe: PeUnit, program: payoff_source.Program
) -> List[dict]:
    final = ctx.out / "bin" / (pe.id + ".exe")
    sym_path = ctx.work / (pe.id + ".sym.exe") if pe.stripped else final
    flags = compile_pe(ctx.tools, program.source, sym_path)
    image = read_image(sym_path)
    rvas = resolve_rvas(
        program, function_symbols(ctx.tools, sym_path), image.image_base, pe.id
    )
    if pe.stripped:
        assert ctx.tools.mingw_strip
        run([ctx.tools.mingw_strip, "-o", str(final), str(sym_path)])
        stripped_image = read_image(final)
        assert_same_image(image, stripped_image, pe.id, exact=False)
        if stripped_image.has_symbols:
            raise BuildError("%s: strip left symbols behind" % pe.id)
        os.remove(sym_path)
    return [
        _truth(
            ctx,
            id=pe.id,
            kind="pe",
            fmt="pe",
            program=program,
            image=image,
            rvas=rvas,
            stripped=pe.stripped,
            binary_rel="bin/" + pe.id + ".exe",
            source_rel="src/%s.c" % pe.base.id,
            flags=flags,
            post="strip" if pe.stripped else None,
            binary_seed=unit_seed(ctx.master, pe.base.id),
            built_from=pe.base.id,
        )
    ]


def synthesize_unit(ctx: Context, unit: Unit) -> payoff_source.Program:
    rng = random.Random(unit_seed(ctx.master, unit.id))
    ns = payoff_names.Namespace(rng, ctx.deps)
    program = payoff_source.synthesize(rng, ns, unit.shape)
    bad = payoff_names.check_names(ctx.deps, program.names)
    if bad:
        raise BuildError("%s: names violate the namespace: %s" % (unit.id, bad))
    hits = ctx.deps.lint_source(program.source)
    if hits:
        raise BuildError("%s: source contains forbidden tokens: %s" % (unit.id, hits))
    return program


def _dump(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def remove_flat_dir(path: Path) -> None:
    """Delete a directory holding only files (no recursion)."""
    for entry in os.scandir(path):
        os.remove(entry.path)
    os.rmdir(path)


def build_corpus(
    set_name: str,
    seed_text: str,
    out: Path,
    *,
    jobs: int = 4,
    with_pe: bool = True,
    repo_root: Path = REPO_ROOT,
) -> dict:
    """Build one set into ``out`` and return the index."""
    if set_name not in ("dev", "held"):
        raise ValueError("set must be dev or held")
    master = master_hex(set_name, seed_text)
    units, pes = plan_dev() if set_name == "dev" else plan_held(master)
    if not with_pe:
        pes = []
    tools = find_tools(with_pe=bool(pes))
    deps = payoff_names.Deps(repo_root)
    for sub in ("bin", "truth", "src"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    stale_index = out / "index.json"
    if stale_index.exists():  # a failed rebuild must not look complete
        stale_index.unlink()
    work = Path(tempfile.mkdtemp(prefix="payoff-corpus-"))
    try:
        ctx = Context(out, work, tools, deps, set_name, seed_text, master)
        programs = {u.id: synthesize_unit(ctx, u) for u in units}
        tasks = [(build_elf_unit, u, programs[u.id]) for u in units]
        tasks += [(build_pe_unit, p, programs[p.base.id]) for p in pes]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            results = list(pool.map(lambda t: t[0](ctx, t[1], t[2]), tasks))
    finally:
        remove_flat_dir(work)
    truths = [t for group in results for t in group]
    for truth in truths:
        (out / "truth" / (truth["id"] + ".json")).write_text(
            _dump(truth), encoding="utf-8"
        )
    index = _index(ctx, truths, with_pe=bool(pes))
    (out / "index.json").write_text(_dump(index), encoding="utf-8")
    return index


def _index(ctx: Context, truths: List[dict], with_pe: bool) -> dict:
    entries = [
        {
            "id": t["id"],
            "kind": t["kind"],
            "format": t["format"],
            "shape": t["shape"],
            "pie": t["pie"],
            "stripped": t["stripped"],
            "twin_of": t["twin_of"],
            "binary": t["binary"],
            "truth": "truth/%s.json" % t["id"],
            "source": t["source"],
        }
        for t in sorted(truths, key=lambda t: t["id"])
    ]
    by_kind: Dict[str, int] = {}
    for t in truths:
        by_kind[t["kind"]] = by_kind.get(t["kind"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "corpus": CORPUS_NAME,
        "set": ctx.set_name,
        "seed": ctx.seed_text,
        "pe_included": with_pe,
        "generator_version": GENERATOR_VERSION,
        "tools": ctx.tools.versions,
        "counts": {"total": len(truths), "by_kind": dict(sorted(by_kind.items()))},
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# CLI


def inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build the payoff corpus v0.")
    parser.add_argument(
        "--set", dest="set_name", choices=("dev", "held"), required=True
    )
    parser.add_argument("--seed", help="master seed (held: or %s)" % HELD_SEED_ENV)
    parser.add_argument("--out", type=Path, help="output directory (required for held)")
    parser.add_argument(
        "--jobs", type=int, default=4, help="parallel builds (default 4)"
    )
    parser.add_argument("--no-pe", action="store_true", help="skip the PE builds")
    args = parser.parse_args(argv)

    seed = args.seed
    if args.set_name == "held":
        seed = seed if seed is not None else os.environ.get(HELD_SEED_ENV)
        if not seed:
            parser.error("held needs a seed: --seed or %s" % HELD_SEED_ENV)
        if args.out is None:
            parser.error("held needs --out, outside the repository")
        if inside(args.out, REPO_ROOT):
            parser.error("held output must not be inside the repository")
        out = args.out
    else:
        seed = seed if seed is not None else DEFAULT_DEV_SEED
        out = args.out or DEFAULT_DEV_OUT
    if not seed or "\n" in seed or "\r" in seed:
        parser.error("the seed must be a non-empty single line")

    try:
        index = build_corpus(
            args.set_name, seed, out, jobs=args.jobs, with_pe=not args.no_pe
        )
    except BuildError as exc:
        print("payoff corpus build failed: %s" % exc, file=sys.stderr)
        return 1
    counts = index["counts"]
    print(
        "built %d %s binaries into %s (%s)"
        % (
            counts["total"],
            args.set_name,
            out,
            ", ".join("%s=%d" % kv for kv in counts["by_kind"].items()),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
