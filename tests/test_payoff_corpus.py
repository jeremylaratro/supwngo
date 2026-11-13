"""The payoff corpus v0 generator (``benchmark/gen/payoff/``) and its truth files.

The corpus is test input for payoff identification by analysis, so these tests pin
what the corpus *is*: exact counts, an answer key that agrees with the binaries
through tools that are not the generator, twins that really share addresses, names
that cannot be an answer key, and determinism. Nothing here tests product code.

The dev set is built once per session, through the CLI, into a pytest tmp dir. The
oracles are independent of the generator on purpose: pyelftools for ELF symbols and
segments, pefile plus a COFF symbol-table reader for PE, ``objdump`` for call
targets. The generator itself reads symbols with ``nm``.

Skipped, with a reason: the whole file without gcc and binutils; the PE tests without
mingw (the dev set is then built with ``--no-pe``) or pefile; the ELF oracle tests
without pyelftools.
"""

from __future__ import annotations

import ast
import json
import os
import random
import re
import secrets
import shutil
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GEN_DIR = REPO_ROOT / "benchmark" / "gen" / "payoff"
GENERATE = GEN_DIR / "generate.py"
HELD_SEED_ENV = "SUPWNGO_PAYOFF_HELD_SEED"

for _tool in ("gcc", "objcopy", "strip", "nm", "objdump"):
    if shutil.which(_tool) is None:
        pytest.skip(
            "%s not found; the payoff corpus cannot be built" % _tool,
            allow_module_level=True,
        )

HAVE_MINGW = bool(
    shutil.which("x86_64-w64-mingw32-gcc") and shutil.which("x86_64-w64-mingw32-strip")
)

sys.dont_write_bytecode = True
sys.path.insert(0, str(GEN_DIR))
import generate  # noqa: E402
import payoff_names  # noqa: E402
import payoff_source  # noqa: E402

SHAPES = ("exec", "file", "arg1", "arg3")
GENERIC_WORDS = (
    "win",
    "flag",
    "shell",
    "secret",
    "backdoor",
    "admin",
    "debug",
    "print_flag",
    "get_flag",
    "give_shell",
    "vuln",
)
REQUIRED_TRUTH_KEYS = {
    "schema_version",
    "id",
    "set",
    "kind",
    "format",
    "shape",
    "pie",
    "stripped",
    "twin_of",
    "image_base",
    "payoff_vaddr",
    "payoff_rva",
    "required_args",
    "decoys",
    "seed",
    "binary_seed",
    "tools",
    "binary",
    "source",
}

# gcc -O0 opens every function with push rbp; mov rbp, rsp (after endbr64 when
# -fcf-protection is on, as on Ubuntu).
PROLOGUES = (b"\x55\x48\x89\xe5", b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5")


# ---------------------------------------------------------------------------
# Building and loading


def build(out: Path, *args: str, env: Optional[dict] = None, check: bool = True):
    cmd = [sys.executable, "-B", str(GENERATE), *args, "--out", str(out)]
    return subprocess.run(
        cmd, capture_output=True, text=True, cwd=str(out.parent), env=env, check=check
    )


class Corpus:
    def __init__(self, root: Path):
        self.root = root
        self.index = json.loads((root / "index.json").read_text())
        self.truth: Dict[str, dict] = {
            e["id"]: json.loads((root / e["truth"]).read_text())
            for e in self.index["entries"]
        }

    def path(self, ident: str) -> Path:
        return self.root / self.truth[ident]["binary"]

    def source(self, ident: str) -> str:
        return (self.root / self.truth[ident]["source"]).read_text()

    def of_kind(self, *kinds: str) -> List[dict]:
        return [t for t in self.truth.values() if t["kind"] in kinds]


@pytest.fixture(scope="session")
def dev_dir(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("payoff-dev") / "dev"
    build(out, "--set", "dev", *([] if HAVE_MINGW else ["--no-pe"]))
    return out


@pytest.fixture(scope="session")
def dev(dev_dir) -> Corpus:
    return Corpus(dev_dir)


def snapshot_tree(root: Path) -> Dict[str, Tuple[int, int]]:
    snap: Dict[str, Tuple[int, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in (".git", "__pycache__"))
        for name in filenames:
            if name == ".git":
                continue
            path = Path(dirpath) / name
            st = path.lstat()
            snap[str(path.relative_to(root))] = (st.st_size, st.st_mtime_ns)
        for d in dirnames:
            snap[str((Path(dirpath) / d).relative_to(root)) + "/"] = (0, 0)
    return snap


# ---------------------------------------------------------------------------
# Independent oracles


class ElfView:
    """pyelftools view of one ELF: image base, function symbols, loaded bytes."""

    def __init__(self, path: Path):
        elf_file = pytest.importorskip("elftools.elf.elffile").ELFFile
        with open(path, "rb") as fh:
            elf = elf_file(fh)
            self.e_type = elf["e_type"]
            self.loads = [
                (s["p_vaddr"], s.data())
                for s in elf.iter_segments()
                if s["p_type"] == "PT_LOAD"
            ]
            self.image_base = min(v for v, _ in self.loads)
            symtab = elf.get_section_by_name(".symtab")
            self.has_symtab = symtab is not None
            self.funcs: Dict[str, int] = {}
            if symtab is not None:
                for sym in symtab.iter_symbols():
                    defined = sym["st_shndx"] != "SHN_UNDEF"
                    if sym["st_info"]["type"] == "STT_FUNC" and defined:
                        self.funcs[sym.name] = sym["st_value"]
            self.alloc = {
                sec.name: sec.data()
                for sec in elf.iter_sections()
                if sec["sh_flags"] & 2 and sec["sh_type"] != "SHT_NOBITS"
            }
            dynsym = elf.get_section_by_name(".dynsym")
            self.imports = (
                {s.name for s in dynsym.iter_symbols() if s["st_shndx"] == "SHN_UNDEF"}
                if dynsym is not None
                else set()
            )

    def bytes_at_rva(self, rva: int, count: int) -> bytes:
        addr = self.image_base + rva
        for vaddr, data in self.loads:
            if vaddr <= addr < vaddr + len(data):
                return data[addr - vaddr : addr - vaddr + count]
        raise AssertionError("rva %#x is not in a loaded segment" % rva)


def elf_view(corpus: Corpus, ident: str) -> ElfView:
    return ElfView(corpus.path(ident))


def pe_symbols(path: Path):
    """(ImageBase, {function name: RVA}, pefile object) from the PE and its COFF table."""
    pefile = pytest.importorskip("pefile")
    pe = pefile.PE(str(path))
    image_base = pe.OPTIONAL_HEADER.ImageBase
    raw = path.read_bytes()
    count = pe.FILE_HEADER.NumberOfSymbols
    table = pe.FILE_HEADER.PointerToSymbolTable
    funcs: Dict[str, int] = {}
    if count:
        strings = table + 18 * count

        def name_of(entry: bytes) -> str:
            if entry[:4] == b"\0\0\0\0":
                (off,) = struct.unpack_from("<I", entry, 4)
                end = raw.index(b"\0", strings + off)
                return raw[strings + off : end].decode()
            return entry[:8].split(b"\0")[0].decode()

        i = 0
        while i < count:
            entry = raw[table + 18 * i : table + 18 * (i + 1)]
            value, section, typ, _cls, aux = struct.unpack_from("<IhHBB", entry, 8)
            if section > 0 and typ == 0x20:  # a function in a real section
                sec = pe.sections[section - 1]
                funcs[name_of(entry)] = sec.VirtualAddress + value
            i += 1 + aux
    return image_base, funcs, pe


def call_targets(path: Path) -> set:
    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", "-M", "intel", str(path)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {int(m.group(1), 16) for m in re.finditer(r"\bcall\s+([0-9a-f]+)\s", out)}


def starts_a_function(head: bytes) -> bool:
    return any(head.startswith(p) for p in PROLOGUES)


# ---------------------------------------------------------------------------
# Composition


def test_plan_counts_without_building():
    units, pes = generate.plan_dev()
    kinds = Counter(u.kind for u in units)
    assert kinds == {"positive": 32, "negative": 8}
    assert sum(u.twins for u in units) == 16
    assert all(not u.stripped and u.kind == "positive" for u in units if u.twins)
    assert len(pes) == 8 and len({p.id for p in pes}) == 8
    assert len({u.id for u in units}) == 40
    held, held_pes = generate.plan_held(generate.master_hex("held", "x"))
    assert len(held) == 16 and not held_pes and all(u.kind == "positive" for u in held)


def test_dev_set_composition(dev):
    counts = Counter(t["kind"] for t in dev.truth.values())
    assert counts["positive"] == 32
    assert counts["rename_twin"] == 16
    assert counts["strip_twin"] == 16
    assert counts["negative"] == 8
    assert counts["pe"] == (8 if HAVE_MINGW else 0)
    assert dev.index["counts"]["total"] == len(dev.index["entries"]) == len(dev.truth)

    cells = Counter(
        (t["shape"], t["pie"], t["stripped"])
        for t in dev.truth.values()
        if t["kind"] == "positive"
    )
    assert set(cells) == {
        (shape, pie, stripped)
        for shape in SHAPES
        for pie in (False, True)
        for stripped in (False, True)
    }
    assert set(cells.values()) == {2}, "each cell has exactly 2 seeds"
    negatives = Counter(
        (t["pie"], t["stripped"]) for t in dev.truth.values() if t["kind"] == "negative"
    )
    assert len(negatives) == 4 and set(negatives.values()) == {2}
    # Every positive is its own program, not a rebuild of a sibling.
    sources = {dev.source(t["id"]) for t in dev.of_kind("positive")}
    assert len(sources) == 32


def test_binaries_truth_and_index_agree(dev):
    listed = sorted(e["binary"] for e in dev.index["entries"])
    on_disk = sorted("bin/" + p.name for p in (dev.root / "bin").iterdir())
    assert listed == on_disk
    assert sorted(p.stem for p in (dev.root / "truth").iterdir()) == sorted(dev.truth)
    for ident, truth in dev.truth.items():
        assert REQUIRED_TRUTH_KEYS <= set(truth), ident
        assert truth["id"] == ident and truth["set"] == "dev"
        assert (dev.root / truth["binary"]).is_file()
        assert (dev.root / truth["source"]).is_file()
        assert truth["tools"]["gcc"], "tool versions are recorded"
        assert truth["seed"] == "1"


def test_truth_is_not_embedded_in_binaries(dev):
    for truth in dev.truth.values():
        data = (dev.root / truth["binary"]).read_bytes()
        assert truth["id"].encode() not in data
        assert truth["source"].encode() not in data
        if truth["stripped"]:
            for name in truth["names"]:
                assert name.encode() not in data, (truth["id"], name)


@pytest.mark.skipif(not HAVE_MINGW, reason="mingw not installed; no PE binaries")
def test_pe_subset_covers_all_shapes(dev):
    pes = dev.of_kind("pe")
    assert len(pes) == 8
    assert {t["shape"] for t in pes} == set(SHAPES)
    # The documented subset: the k=0 non-PIE positive of each shape, in both strip
    # states, built from that positive's own source.
    expected = {
        "pos-%s-nopie-%s-0" % (shape, tag)
        for shape in SHAPES
        for tag in ("stripped", "unstripped")
    }
    assert {t["built_from"] for t in pes} == expected
    for t in pes:
        base = dev.truth[t["built_from"]]
        assert t["source"] == base["source"]
        assert t["format"] == "pe" and t["stripped"] == base["stripped"]
        assert t["shape"] == base["shape"]
        assert t["required_args"] == base["required_args"]


# ---------------------------------------------------------------------------
# The answer key against independent oracles


def test_unstripped_elf_truth_matches_the_symbol_table(dev):
    checked = 0
    for truth in dev.truth.values():
        if truth["format"] != "elf" or truth["stripped"]:
            continue
        view = elf_view(dev, truth["id"])
        assert view.has_symtab, truth["id"]
        assert view.image_base == truth["image_base"], truth["id"]
        assert (view.e_type == "ET_DYN") == truth["pie"], truth["id"]
        for func in truth["functions"]:
            assert func["name"] in view.funcs, (truth["id"], func["name"])
            assert view.funcs[func["name"]] - view.image_base == func["rva"], truth[
                "id"
            ]
        if truth["kind"] == "negative":
            assert truth["payoff_rva"] is None and truth["payoff_vaddr"] is None
            continue
        symbol = truth["payoff_symbol"]
        assert view.funcs[symbol] - view.image_base == truth["payoff_rva"], truth["id"]
        assert truth["payoff_vaddr"] == view.funcs[symbol]
        checked += 1
    assert checked == 32  # 16 unstripped positives + 16 rename twins


def test_every_elf_function_rva_starts_a_function(dev):
    """Binary-level sanity that also covers stripped binaries: -O0 prologues."""
    for truth in dev.truth.values():
        if truth["format"] != "elf":
            continue
        rvas = [f["rva"] for f in truth["functions"]]
        assert truth["payoff_rva"] is None or truth["payoff_rva"] in rvas
        assert set(truth["decoys"].values()) <= set(rvas)
        view = elf_view(dev, truth["id"])
        for rva in rvas:
            assert starts_a_function(view.bytes_at_rva(rva, 8)), (truth["id"], hex(rva))


@pytest.mark.skipif(not HAVE_MINGW, reason="mingw not installed; no PE binaries")
def test_pe_truth_matches_header_and_coff_symbols(dev):
    for truth in dev.of_kind("pe"):
        base, funcs, pe = pe_symbols(dev.path(truth["id"]))
        assert truth["image_base"] == base == pe.OPTIONAL_HEADER.ImageBase
        assert truth["payoff_vaddr"] == truth["payoff_rva"] + base
        for func in truth["functions"]:
            assert starts_a_function(pe.get_data(func["rva"], 8)), (truth["id"], func)
        if truth["stripped"]:
            assert pe.FILE_HEADER.NumberOfSymbols == 0 and not funcs
            continue
        for func in truth["functions"]:
            assert funcs[func["name"]] == func["rva"], (truth["id"], func["name"])
        assert funcs[truth["payoff_symbol"]] == truth["payoff_rva"]


def test_negative_has_no_payoff_truth(dev):
    negatives = dev.of_kind("negative")
    assert len(negatives) == 8
    for truth in negatives:
        assert truth["shape"] is None
        assert truth["payoff_rva"] is None and truth["payoff_vaddr"] is None
        assert truth["payoff_symbol"] is None
        assert truth["required_args"] == []
        assert all(f["role"] != "payoff" for f in truth["functions"])
        assert set(truth["decoys"]) == {"nop", "filecopy", "compare"}
        # No exec payoff means nothing in the binary imports an exec entry point.
        assert not ({"execve", "system"} & elf_view(dev, truth["id"]).imports)


def test_positive_truth_fields(dev):
    for truth in dev.of_kind("positive"):
        assert truth["payoff_rva"] == truth["payoff_vaddr"] - truth["image_base"]
        assert set(truth["decoys"]) == {"nop", "filecopy", "compare"}
        assert truth["payoff_rva"] not in truth["decoys"].values()
        args = truth["required_args"]
        if truth["shape"] in ("exec", "file"):
            assert args == []
        else:
            want = 1 if truth["shape"] == "arg1" else 3
            assert [a["position"] for a in args] == list(range(1, want + 1))
            assert all(0x1000 <= a["value"] <= 0x7FFFFFFF for a in args)
            assert len({a["value"] for a in args}) == want
        # Only an exec payoff brings an exec import; the decoys never do.
        imports = elf_view(dev, truth["id"]).imports
        has_exec = bool({"execve", "system"} & imports)
        assert has_exec == (truth["program"]["action"] == "exec"), truth["id"]


# ---------------------------------------------------------------------------
# Twins


def test_twins_keep_addresses_and_bytes(dev):
    twins = dev.of_kind("rename_twin", "strip_twin")
    assert len(twins) == 32
    renamed = Counter()
    for twin in twins:
        orig = dev.truth[twin["twin_of"]]
        assert orig["kind"] == "positive" and not orig["stripped"], twin["id"]
        for key in (
            "shape",
            "pie",
            "image_base",
            "payoff_rva",
            "payoff_vaddr",
            "decoys",
        ):
            assert twin[key] == orig[key], (twin["id"], key)
        assert twin["required_args"] == orig["required_args"]
        assert [f["rva"] for f in twin["functions"]] == [
            f["rva"] for f in orig["functions"]
        ]
        assert twin["source"] == orig["source"]

        a, b = elf_view(dev, orig["id"]), elf_view(dev, twin["id"])
        assert a.image_base == b.image_base
        rva = orig["payoff_rva"]
        assert b.bytes_at_rva(rva, 96) == a.bytes_at_rva(rva, 96)
        assert a.alloc == b.alloc, "every loaded section is byte-identical"
        if twin["kind"] == "strip_twin":
            assert not b.has_symtab and twin["stripped"] and not twin["symbols_present"]
            assert twin["payoff_symbol"] is None
        else:
            renamed[twin["twin_of"]] += 1
            assert b.has_symtab and not twin["stripped"]
            mapping = twin["renames"]
            fresh = {f["name"] for f in twin["functions"] if f["role"] != "main"}
            assert set(mapping.values()) == fresh and len(fresh) == len(mapping)
            assert set(mapping) <= set(a.funcs)
            assert not set(mapping) & set(b.funcs), "no original user name survives"
            assert fresh <= set(b.funcs) and not fresh & set(a.funcs)
            assert b.funcs[twin["payoff_symbol"]] == a.funcs[orig["payoff_symbol"]]
            assert "main" in b.funcs
    assert len(renamed) == 16 and set(renamed.values()) == {1}


# ---------------------------------------------------------------------------
# Decoys, references, layout


def test_decoys_and_references_match_the_binary(dev):
    """The truth's ``called`` flags equal the call targets objdump sees."""
    checked = 0
    for truth in dev.truth.values():
        symbols_present = truth["symbols_present"] and truth["format"] == "elf"
        if not symbols_present or truth["kind"] == "rename_twin":
            continue
        base = truth["image_base"]
        targets = call_targets(dev.path(truth["id"]))
        for func in truth["functions"]:
            if func["role"] != "main":
                assert (func["rva"] + base in targets) == func["called"], (
                    truth["id"],
                    func,
                )
        if truth["payoff_vaddr"] is not None:
            assert truth["payoff_vaddr"] not in targets, "the payoff is never called"
        called = truth["decoy_called"]
        assert any(called.values()) and not all(called.values()), truth["id"]
        unreferenced = [
            f for f in truth["functions"] if f["role"] != "main" and not f["called"]
        ]
        if truth["kind"] == "positive":
            assert len(unreferenced) >= 2, "unreferenced alone must not identify it"
        checked += 1
    assert checked == 20  # 16 unstripped positives and 4 unstripped negatives


def test_layout_does_not_identify_the_payoff(dev):
    ranks = set()
    sizes = set()
    first = last = 0
    for truth in dev.of_kind("positive"):
        order = [f["role"] for f in truth["functions"]]
        index = order.index("payoff")
        ranks.add(index)
        first += index == 0
        last += index == len(order) - 1
        sizes.add(len(order))
    assert len(ranks) >= 5, ranks
    assert first < 16 and last < 16
    assert len(sizes) >= 4, "the filler count varies"
    main_positions = {
        [f["role"] for f in t["functions"]].index("main")
        for t in dev.of_kind("positive")
    }
    assert len(main_positions) >= 5


def test_skeleton_reads_stdin_past_a_stack_buffer(dev):
    for truth in dev.truth.values():
        if truth["kind"] not in ("positive", "negative"):
            continue
        src = dev.source(truth["id"])
        (buf,) = re.findall(r"char buf\[(\d+)\];", src)
        (read,) = re.findall(r"read\(0, buf, (\d+)\)", src)
        assert int(read) > int(buf), truth["id"]
        assert int(buf) == truth["program"]["buffer_size"]
        assert int(read) == truth["program"]["read_size"]
        main_text = src[src.index("int main(") :].split("\n}\n")[0]
        attr = r"__attribute__\(\(noinline, used\)\) "
        defs = re.findall(attr + r"\w[\w ]*? (\w+)\(", src)
        assert len(defs) == 2 * (len(truth["functions"]) - 1), "a proto and a def each"
        if truth["payoff_symbol"]:
            name = truth["payoff_symbol"]
            assert name not in main_text, "main never refers to the payoff"
            assert len(re.findall(r"\b%s\b" % re.escape(name), src)) == 2


# ---------------------------------------------------------------------------
# Names


def lint_tokens() -> List[str]:
    """The identifier lint's tokens, derived the way that lint derives them, plus the
    generic payoff words. Re-derived here so a bug in the generator cannot hide."""
    truth_dir = REPO_ROOT / "benchmark" / "truth"
    tokens = {w.replace("-", "_") for w in GENERIC_WORDS}
    for path in sorted((truth_dir / "s0").glob("*.yaml")):
        slug = yaml.safe_load(path.read_text())["slug"]
        tokens.add(slug.strip().lower().replace("-", "_"))
    for path in sorted(truth_dir.rglob("*.yaml")):
        for symbol in yaml.safe_load(path.read_text()).get("forbidden_symbols") or []:
            tokens.add(symbol.strip().lower().replace("-", "_"))
    return sorted(tokens)


def token_patterns(tokens: List[str]):
    return {
        t: re.compile("[-_]".join(re.escape(p) for p in t.split("_")), re.I)
        for t in tokens
    }


@pytest.fixture(scope="session")
def product_constants() -> set:
    constants = set()
    for path in sorted((REPO_ROOT / "supwngo").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                constants.add(node.value.lower())
    assert len(constants) > 1000, "the product scan would be vacuous"
    return constants


def test_generated_names_avoid_forbidden_tokens_and_product_strings(
    dev, product_constants
):
    tokens = lint_tokens()
    assert set(GENERIC_WORDS) <= set(tokens) and len(tokens) > len(GENERIC_WORDS)
    patterns = token_patterns(tokens)
    names = set()
    for truth in dev.truth.values():
        names.update(truth["names"])
        names.update(truth["renames"])
        names.update(truth["renames"].values())
    assert len(names) > 400
    for name in sorted(names):
        for token, pattern in patterns.items():
            assert not pattern.search(name), (name, "contains", token)
        assert name.lower() not in product_constants, (name, "is a string in supwngo/")
    # The C text itself (identifiers and string literals) is clean as well.
    words = set()
    for truth in dev.of_kind("positive", "negative"):
        words.update(re.findall(r"[A-Za-z0-9_]+", dev.source(truth["id"])))
    for word in sorted(words):
        for token, pattern in patterns.items():
            assert not pattern.search(word), (word, "contains", token)


def test_generator_check_is_at_least_as_strict_as_the_lint():
    deps = payoff_names.Deps(REPO_ROOT)
    assert set(lint_tokens()) <= set(deps.tokens)


def test_name_check_can_fail(product_constants):
    """Controls: the namespace check rejects what it must and accepts ordinary names."""
    deps = payoff_names.Deps(REPO_ROOT)
    bad_names = (
        "winter_loop",
        "kopflagu",
        "fill_ammo",
        "xfill_ammo_y",
        "Shellac",
        "bigvuln",
    )
    for bad in bad_names:
        assert deps.violation(bad), bad
    # A name equal to a product string constant is refused, whatever its case.
    clash = next(
        c
        for c in sorted(product_constants)
        if re.fullmatch(r"[a-z]{7,10}", c)
        and not deps.token_hits(c)
        and c not in payoff_names.C_RESERVED
    )
    for spelling in (clash, clash.upper(), clash.capitalize()):
        assert "string constant" in (deps.violation(spelling) or ""), spelling
    for good in ("kolavutren", "brimtane_sol"):
        assert deps.violation(good) is None, good
    assert deps.lint_source("int main(void) { return 0; }") == []
    assert deps.lint_source('puts("a flag here");') == ["flag"]


# ---------------------------------------------------------------------------
# Determinism


def test_same_seed_gives_identical_sources_truth_and_binaries(dev, tmp_path):
    again = tmp_path / "again"
    build(
        again,
        "--set",
        "dev",
        "--seed",
        "1",
        "--jobs",
        "2",
        *([] if HAVE_MINGW else ["--no-pe"]),
    )
    first = sorted(p.relative_to(dev.root) for p in dev.root.rglob("*") if p.is_file())
    second = sorted(p.relative_to(again) for p in again.rglob("*") if p.is_file())
    assert first == second
    assert len(first) == 2 * len(dev.truth) + 40 + 1  # bin, truth, 40 sources, index
    for rel in first:
        assert (dev.root / rel).read_bytes() == (again / rel).read_bytes(), rel


def test_a_different_seed_gives_different_programs():
    deps = payoff_names.Deps(REPO_ROOT)
    master = {s: generate.master_hex("dev", s) for s in ("1", "2")}
    sources = []
    for seed in ("1", "2"):
        rng = random.Random(
            generate.unit_seed(master[seed], "pos-exec-pie-unstripped-0")
        )
        ns = payoff_names.Namespace(rng, deps)
        sources.append(payoff_source.synthesize(rng, ns, "exec").source)
    assert sources[0] != sources[1]
    rng = random.Random(generate.unit_seed(master["1"], "pos-exec-pie-unstripped-0"))
    again = payoff_source.synthesize(rng, payoff_names.Namespace(rng, deps), "exec")
    assert again.source == sources[0], "one stream gives one program"


# ---------------------------------------------------------------------------
# The held set


def test_held_set_builds_from_the_environment_seed_outside_the_repo(dev, tmp_path):
    seed = secrets.token_hex(8)  # throwaway for this test; not the real held seed
    before = snapshot_tree(REPO_ROOT)
    out = tmp_path / "held"
    env = dict(os.environ, **{HELD_SEED_ENV: seed})
    result = build(out, "--set", "held", env=env)
    assert seed not in result.stdout and seed not in result.stderr
    assert (
        snapshot_tree(REPO_ROOT) == before
    ), "the held build wrote into the repository"

    held = Corpus(out)
    assert held.index["set"] == "held" and held.index["counts"]["total"] == 16
    assert len(held.truth) == 16
    assert all(
        t["format"] == "elf" and t["kind"] == "positive" for t in held.truth.values()
    )
    assert all(t["set"] == "held" and t["seed"] == seed for t in held.truth.values())
    assert sorted(held.truth) == ["held-%02d" % i for i in range(16)], "opaque ids"
    cells = Counter((t["shape"], t["pie"], t["stripped"]) for t in held.truth.values())
    assert len(cells) == 16 and set(cells.values()) == {1}
    for truth in held.truth.values():
        assert (out / truth["binary"]).is_file() and truth["payoff_rva"] is not None
    dev_sources = {dev.source(i) for i in dev.truth}
    assert not {held.source(i) for i in held.truth} & dev_sources


def test_held_refuses_to_build_inside_the_repo_or_without_a_seed(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != HELD_SEED_ENV}
    inside = REPO_ROOT / "benchmark" / "gen" / "payoff" / "never-built"
    before = snapshot_tree(REPO_ROOT)
    refused = build(inside, "--set", "held", "--seed", "x", env=env, check=False)
    assert refused.returncode != 0 and "inside the repository" in refused.stderr
    missing = build(tmp_path / "held", "--set", "held", env=env, check=False)
    assert missing.returncode != 0 and HELD_SEED_ENV in missing.stderr
    assert not (tmp_path / "held").exists()
    no_out = subprocess.run(
        [sys.executable, "-B", str(GENERATE), "--set", "held", "--seed", "x"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
    )
    assert no_out.returncode != 0 and "--out" in no_out.stderr
    assert snapshot_tree(REPO_ROOT) == before


def test_dev_default_output_is_ignored_and_the_generator_is_not():
    if shutil.which("git") is None:
        pytest.skip("git not found")

    def ignored(path: str) -> Optional[bool]:
        rc = subprocess.run(
            ["git", "check-ignore", "-q", path], cwd=str(REPO_ROOT), capture_output=True
        ).returncode
        return None if rc == 128 else rc == 0

    if ignored("benchmark/gen/payoff/build/index.json") is None:
        pytest.skip("not a git checkout")
    assert ignored("benchmark/gen/payoff/build/index.json")
    assert ignored("benchmark/gen/payoff/build/bin/pos-exec-pie-unstripped-0")
    for tracked in ("generate.py", "payoff_names.py", "payoff_source.py"):
        assert ignored("benchmark/gen/payoff/" + tracked) is False, tracked


def test_tokens_agree_with_the_lint_module_when_it_is_present():
    try:
        lint = __import__("tests.test_no_target_identifiers", fromlist=["x"])
    except ImportError:
        pytest.skip("the target-identifier lint is not on this branch")
    assert set(lint.load_forbidden_tokens()) <= set(payoff_names.Deps(REPO_ROOT).tokens)
