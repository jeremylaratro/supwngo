"""Lint: no code outside ``supwngo/core`` may read ``.relro`` as a RELRO level.

SP-01 plan section 4.3 (B-4, B3-4). Four spellings of a RELRO level were
compared against each other across the code base (``"Full RELRO"``, ``"Full"``,
``"full"``, ``"none"``), and the comparisons silently never matched. The core
``Protections`` now carries ``relro_kind`` and ``supwngo.core.relro`` owns the
normaliser, so a read of ``.relro`` outside ``supwngo/core/`` must be one of:

* a **display** read -- the value only reaches a place that shows it (an f-string
  field, an argument to ``.format()``, a logging method, ``print`` or
  ``console.print``, or a dict-literal value), after stripping ``str()`` and
  ``repr()`` calls, conditional expressions and ``or <constant>``;
* an **allowlisted** read -- a receiver that is not the core ``Protections``
  (pwntools ``ELF``, ``GOTAnalysis``, ``DetailedProtections``,
  ``ProtectionFacts`` and so on), keyed by ``(path, enclosing qualname)`` with a
  stated receiver type and justification. An entry that matches no read is
  stale and fails the lint.

Every other read -- a comparison, ``in``, ``.lower()``, ``.startswith()``, a
keyword argument, a tuple member, an assignment to a local alias -- is flagged.

``python tests/test_relro_lint.py --report`` prints every read and its class,
for recording an inventory at a merge base.
"""

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_DIR = REPO_ROOT / "supwngo"
CORE_DIR = SCAN_DIR / "core"

#: Calls that show a value to a human; a read reaching one of these is display.
LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)

#: Receiver types an allowlist entry may name. The core ``Protections`` is
#: deliberately absent: its reads are migrated to ``relro_kind``, never allowed.
NON_CORE_RECEIVERS = frozenset(
    {
        "pwntools ELF",
        "GOTAnalysis",
        "DetailedProtections",
        "ProtectionFacts",
        "_Image",
    }
)


@dataclass(frozen=True)
class AllowEntry:
    """One allowlisted site, keyed by qualname so it survives line drift.

    ``expr`` is the source of the read (``elf.relro``). Two receivers of
    different types can share one function (``GOTAnalyzer.analyze`` reads a
    pwntools ``ELF`` and a ``GOTAnalysis``), and an entry must not quietly cover
    a new read of the core ``Protections`` that later lands in the same function.
    Several reads with the same expression in one function share one entry.
    """

    path: str
    qualname: str
    expr: str
    receiver: str
    justification: str

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.path, self.qualname, self.expr)


@dataclass(frozen=True)
class Read:
    """One load of an attribute named ``relro`` (or ``getattr(_, "relro")``)."""

    path: str
    qualname: str
    line: int
    source: str
    display: bool


ALLOWLIST: Tuple[AllowEntry, ...] = (
    AllowEntry(
        "supwngo/exploit/rop/ret2dlresolve.py",
        "Ret2dlresolve.can_use_technique",
        "elf.relro",
        "pwntools ELF",
        "pwntools reports 'Full', 'Partial' or None; the check compares against "
        "that exact spelling.",
    ),
    AllowEntry(
        "supwngo/exploit/got_plt.py",
        "GOTAnalyzer.analyze",
        "elf.relro",
        "pwntools ELF",
        "Copies pwntools' level (or 'none') into GOTAnalysis.relro.",
    ),
    AllowEntry(
        "supwngo/exploit/got_plt.py",
        "GOTAnalyzer.analyze",
        "result.relro",
        "GOTAnalysis",
        "GOTAnalysis.relro holds the pwntools spelling written two lines above, "
        "not a Protections display string.",
    ),
    AllowEntry(
        "supwngo/exploit/got_plt.py",
        "GOTOverwriter.overwrite_with_system",
        "analysis.relro",
        "GOTAnalysis",
        "analysis is the GOTAnalysis from GOTAnalyzer.analyze (pwntools spelling).",
    ),
    AllowEntry(
        "supwngo/exploit/got_plt.py",
        "GOTOverwriter.format_string_got_overwrite",
        "analysis.relro",
        "GOTAnalysis",
        "analysis is the GOTAnalysis from GOTAnalyzer.analyze (pwntools spelling).",
    ),
    AllowEntry(
        "supwngo/analysis/protections.py",
        "ProtectionAnalyzer.analyze",
        "prots.relro",
        "DetailedProtections",
        "The analyzer assigns prots.relro from its own _get_relro_type() two lines "
        "earlier and derives full_relro/partial_relro from that same display "
        "string; it is the producer, not a consumer.",
    ),
    AllowEntry(
        "supwngo/exploit/walkthrough/facts.py",
        "ProtectionFacts.full_relro",
        "self.relro",
        "ProtectionFacts",
        "ProtectionFacts.relro is the walkthrough's own display string, derived "
        "from PT_GNU_RELRO plus BIND_NOW by _derive_relro().",
    ),
    AllowEntry(
        "supwngo/exploit/walkthrough/common.py",
        "protection_verdicts",
        "prot.relro",
        "ProtectionFacts",
        "prot is ProtectionFacts; the read is a state label (keyword argument), "
        "and the level decision uses prot.full_relro.",
    ),
    AllowEntry(
        "supwngo/exploit/walkthrough/families/heap.py",
        "_weaponisation_step",
        "facts.protections.relro",
        "ProtectionFacts",
        "facts.protections is ProtectionFacts. Both reads (the Partial test and "
        "the string passed to _q(), which the display rule does not strip) are "
        "on that display string.",
    ),
    AllowEntry(
        "supwngo/exploit/pipeline/executors/finiarray_techniques.py",
        "_Image.is_writable",
        "self.relro",
        "_Image",
        "_Image.relro is a list of PT_GNU_RELRO address ranges, not a level.",
    ),
)


# --------------------------------------------------------------------------
# The scanner
# --------------------------------------------------------------------------


def _is_name(node: ast.AST, names: Sequence[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in names


def _is_relro_getattr(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and _is_name(node.func, ("getattr",))
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "relro"
    )


def _is_display_call(call: ast.Call) -> bool:
    func = call.func
    if _is_name(func, ("print",)):
        return True
    if isinstance(func, ast.Attribute):
        return func.attr == "format" or func.attr == "print" or func.attr in LOG_METHODS
    return False


def _reaches_display(node: ast.AST, parents: Dict[ast.AST, ast.AST]) -> bool:
    """True when the read's value only reaches a display position."""
    child = node
    while True:
        parent = parents.get(child)
        if parent is None:
            return False
        # Wrappers that do not change what the value is used for.
        if (
            isinstance(parent, ast.Call)
            and _is_name(parent.func, ("str", "repr"))
            and parent.args == [child]
            and not parent.keywords
        ):
            child = parent
            continue
        if isinstance(parent, ast.IfExp) and child is not parent.test:
            child = parent
            continue
        if (
            isinstance(parent, ast.BoolOp)
            and isinstance(parent.op, ast.Or)
            and parent.values[0] is child
            and all(isinstance(v, ast.Constant) for v in parent.values[1:])
        ):
            child = parent
            continue
        # Display positions.
        if isinstance(parent, ast.FormattedValue):
            return parent.value is child
        if isinstance(parent, ast.Dict):
            return any(v is child for v in parent.values)
        if isinstance(parent, ast.Call):
            return child in parent.args and _is_display_call(parent)
        if isinstance(parent, ast.keyword):
            call = parents.get(parent)
            return (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "format"
            )
        return False


class _Collector(ast.NodeVisitor):
    def __init__(self, path: str, parents: Dict[ast.AST, ast.AST]):
        self.path = path
        self.parents = parents
        self.stack: List[str] = []
        self.reads: List[Read] = []

    def _scope(self, node) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_ClassDef = _scope
    visit_FunctionDef = _scope
    visit_AsyncFunctionDef = _scope

    def _record(self, node: ast.AST) -> None:
        self.reads.append(
            Read(
                path=self.path,
                qualname=".".join(self.stack) or "<module>",
                line=node.lineno,
                source=ast.unparse(node),
                display=_reaches_display(node, self.parents),
            )
        )

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "relro" and isinstance(node.ctx, ast.Load):
            self._record(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _is_relro_getattr(node):
            self._record(node)
        self.generic_visit(node)


def find_reads(source: str, path: str = "<synthetic>") -> List[Read]:
    """Every read of ``.relro`` in ``source``, each marked display or not."""
    tree = ast.parse(source)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    collector = _Collector(path, parents)
    collector.visit(tree)
    return collector.reads


def scan_tree(root: Path = SCAN_DIR, exclude: Path = CORE_DIR) -> List[Read]:
    reads: List[Read] = []
    for file in sorted(root.rglob("*.py")):
        if exclude in file.parents:
            continue
        rel = file.relative_to(REPO_ROOT).as_posix()
        reads.extend(find_reads(file.read_text(encoding="utf-8"), rel))
    return reads


@dataclass
class Classified:
    display: List[Read]
    allowlisted: List[Tuple[Read, AllowEntry]]
    unclassified: List[Read]
    stale: List[AllowEntry]


def classify(reads: Sequence[Read], allowlist: Sequence[AllowEntry]) -> Classified:
    by_key = {e.key: e for e in allowlist}
    used = set()
    result = Classified(display=[], allowlisted=[], unclassified=[], stale=[])
    for read in reads:
        if read.display:
            result.display.append(read)
            continue
        entry = by_key.get((read.path, read.qualname, read.source))
        if entry is None:
            result.unclassified.append(read)
        else:
            used.add(entry.key)
            result.allowlisted.append((read, entry))
    result.stale = [e for e in allowlist if e.key not in used]
    return result


def report(classified: Classified) -> str:
    lines: List[str] = []

    def row(tag: str, read: Read, extra: str = "") -> None:
        lines.append(
            f"{tag:<10} {read.path}:{read.line}  {read.qualname}  "
            f"`{read.source}`{extra}"
        )

    for read in classified.unclassified:
        row("MIGRATE", read)
    for read, entry in classified.allowlisted:
        row("ALLOWLIST", read, f"  [{entry.receiver}]")
    for read in classified.display:
        row("DISPLAY", read)
    for entry in classified.stale:
        lines.append(
            f"{'STALE':<10} {entry.path}  {entry.qualname}  `{entry.expr}`  "
            f"[{entry.receiver}]"
        )
    migrate_lines = {(r.path, r.line) for r in classified.unclassified}
    total = (
        len(classified.unclassified)
        + len(classified.allowlisted)
        + len(classified.display)
    )
    lines.append(
        f"total reads: {total}  migrate: {len(classified.unclassified)} reads on "
        f"{len(migrate_lines)} lines  allowlist: {len(classified.allowlisted)}  "
        f"display: {len(classified.display)}  stale entries: {len(classified.stale)}"
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Controls on the scanner itself
# --------------------------------------------------------------------------

POSITIVE = """
def f(prots, p, ctx, x):
    a = prots.relro == "full"
    b = str(getattr(p, "relro", "") or "").lower().startswith("full")
    r = ctx.protections.relro
    f(state=x.relro)
"""

NEGATIVE = """
def g(p, log, console):
    a = f"{p.relro}"
    log.info("%s", p.relro)
    b = {"relro": str(p.relro) if p else None}
    print(p.relro)
    console.print(f"RELRO: {p.relro!r}")
    c = "{}".format(p.relro)
    d = "{r}".format(r=p.relro)
    e = f"{getattr(p, 'relro', '') or 'unknown'}"
    log.warning("relro %s", repr(p.relro))
"""

STILL_FLAGGED = """
def h(p, log, items):
    a = p.relro.lower()
    b = p.relro in ("Full RELRO", "Partial RELRO")
    c = (p.relro, 1)
    d = p.relro or "d"
    e = "x" if p.relro else "y"
    f"{p.relro.lower()}"
    g = str(p.relro) == "x"
    i = "RELRO %s" % p.relro
    log.info("x", extra=p.relro)
    j = {p.relro: 1}
    k = items.append(p.relro)
"""


def test_positive_control_flags_all_four_shapes():
    reads = find_reads(POSITIVE)
    assert len(reads) == 4
    assert [r.display for r in reads] == [False, False, False, False]


def test_negative_control_passes_every_display_position():
    reads = find_reads(NEGATIVE)
    assert len(reads) == 9
    assert all(r.display for r in reads), [r.source for r in reads if not r.display]


def test_every_non_display_shape_is_still_flagged():
    reads = find_reads(STILL_FLAGGED)
    assert len(reads) == 11
    assert not any(r.display for r in reads), [r.source for r in reads if r.display]


def test_stores_and_unrelated_names_are_not_reads():
    source = (
        "def f(p, relro):\n"
        "    p.relro = 'Full RELRO'\n"
        "    x = relro\n"
        "    y = p.relro_kind\n"
        "    z = getattr(p, 'relro_kind', None)\n"
        "    w = hasattr(p, 'relro')\n"
    )
    assert find_reads(source) == []


def test_qualnames_follow_classes_and_functions():
    source = (
        "class A:\n"
        "    def m(self, p):\n"
        "        def inner():\n"
        "            return p.relro == 'x'\n"
        "        return p.relro == 'y'\n"
        "def top(p):\n"
        "    return p.relro == 'z'\n"
        "q = p.relro == 'w'\n"
    )
    assert [r.qualname for r in find_reads(source)] == [
        "A.m.inner",
        "A.m",
        "top",
        "<module>",
    ]


def test_stale_allowlist_entry_is_reported():
    reads = find_reads(POSITIVE, "synthetic.py")
    stale = AllowEntry(
        "synthetic.py", "nowhere", "p.relro", "pwntools ELF", "matches nothing"
    )
    wrong_expr = AllowEntry(
        "synthetic.py", "f", "other.relro", "pwntools ELF", "right function, no read"
    )
    live = [
        AllowEntry("synthetic.py", "f", r.source, "pwntools ELF", "matches a read")
        for r in reads
    ]

    result = classify(reads, [stale, wrong_expr, *live])

    assert result.stale == [stale, wrong_expr]
    assert result.unclassified == []
    assert len(result.allowlisted) == 4


def test_an_entry_does_not_cover_a_new_read_in_the_same_function():
    reads = find_reads(
        "def f(elf, prots):\n    a = elf.relro == 'Full'\n    b = prots.relro == 'x'\n",
        "synthetic.py",
    )
    entry = AllowEntry("synthetic.py", "f", "elf.relro", "pwntools ELF", "pwntools")

    result = classify(reads, [entry])

    assert [r.source for r in result.unclassified] == ["prots.relro"]
    assert result.stale == []


def test_an_unallowlisted_read_is_unclassified():
    result = classify(find_reads(POSITIVE, "synthetic.py"), [])
    assert len(result.unclassified) == 4


def test_allowlist_never_admits_the_core_protections():
    assert "Protections" not in NON_CORE_RECEIVERS
    for entry in ALLOWLIST:
        assert entry.receiver in NON_CORE_RECEIVERS, entry
        assert entry.justification.strip(), entry
    keys = [e.key for e in ALLOWLIST]
    assert len(keys) == len(set(keys)), "duplicate allowlist keys"


def test_allowlist_paths_exist_outside_core():
    for entry in ALLOWLIST:
        path = REPO_ROOT / entry.path
        assert path.is_file(), entry
        assert CORE_DIR not in path.parents, entry


# --------------------------------------------------------------------------
# The lint over the real tree
# --------------------------------------------------------------------------


def test_the_scan_sees_the_tree():
    """Guard against a scan that silently finds nothing."""
    reads = scan_tree()
    assert len(reads) >= 15
    assert any(r.path == "supwngo/analysis/protections.py" for r in reads)


def test_no_unclassified_relro_read_outside_core():
    result = classify(scan_tree(), ALLOWLIST)
    assert not result.unclassified, (
        "these reads of .relro are not display, not allowlisted by receiver type "
        "and should use Protections.relro_kind or normalize_relro():\n"
        + "\n".join(
            f"  {r.path}:{r.line} {r.qualname}  {r.source}" for r in result.unclassified
        )
    )


def test_no_stale_allowlist_entry():
    result = classify(scan_tree(), ALLOWLIST)
    assert not result.stale, "allowlist entries that match no read: " + ", ".join(
        f"{e.path}::{e.qualname}::{e.expr}" for e in result.stale
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv != ["--report"]:
        print("usage: test_relro_lint.py --report", file=sys.stderr)
        return 2
    print(report(classify(scan_tree(), ALLOWLIST)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
