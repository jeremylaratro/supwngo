"""SP-01 plan 4.5: no benchmark target's name may live in ``supwngo/`` code.

The product must not name the targets it is scored on. The forbidden tokens are
read from ``benchmark/truth/`` rather than listed here:

* every ``slug`` under ``benchmark/truth/s0/`` (the S0 smoke set), and
* every ``forbidden_symbols`` entry of every truth file (target-specific
  identifiers such as ``fill_ammo`` that a name list could otherwise carry).

Matching is case-insensitive, and a slug's ``-`` and ``_`` spellings are the same
token (``bon-nie-appetit`` and ``bon_nie_appetit``). A token is a hit anywhere
inside a longer word; the scan is for leaks, not for exact names.

Two policies, because the two kinds of text carry different risk:

* **Code: zero.** No identifier (name, attribute, def/class name, argument,
  keyword argument, import name) and no non-docstring string constant may contain
  a forbidden token. A string constant is data the product can act on or show a
  user, so a target name there is an answer key.
* **Documentation: an exact inventory.** Comments and docstrings may cite the
  evidence a rule came from. They are listed in
  ``tests/data/target_identifier_inventory.json`` as
  ``(path, token, kind, count)`` and any difference fails. The file is generated
  by this module's own helper and is never edited by hand::

      python3 tests/test_no_target_identifiers.py --regen

This is hygiene only. Held-out scoring is the anti-overfitting control.
"""

from __future__ import annotations

import argparse
import ast
import functools
import io
import json
import re
import sys
import tokenize
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = REPO_ROOT / "supwngo"
TRUTH_DIR = REPO_ROOT / "benchmark" / "truth"
S0_TRUTH_DIR = TRUTH_DIR / "s0"
INVENTORY = REPO_ROOT / "tests" / "data" / "target_identifier_inventory.json"

REGEN_COMMAND = "python3 tests/test_no_target_identifiers.py --regen"

CODE_KINDS = ("identifier", "string")
DOC_KINDS = ("comment", "docstring")

# AST fields that hold an identifier as a plain string, on whichever node
# carries them: Name.id, Attribute.attr, FunctionDef/ClassDef/ExceptHandler/
# MatchAs/MatchStar/TypeVar.name, arg.arg, keyword.arg, alias.name/asname,
# ImportFrom.module, MatchMapping.rest. Global/Nonlocal carry a list, `names`.
IDENTIFIER_FIELDS = ("id", "attr", "arg", "name", "asname", "module", "rest")


class Hit(NamedTuple):
    kind: str  # identifier | string | comment | docstring
    token: str  # canonical (underscore) spelling
    line: int
    count: int


# ---------------------------------------------------------------------------
# The forbidden tokens


def canonical(token: str) -> str:
    return token.strip().lower().replace("-", "_")


def load_forbidden_tokens(truth_dir: Path = TRUTH_DIR) -> List[str]:
    """Canonical forbidden tokens, read from the truth files."""
    tokens = set()
    s0_files = sorted((truth_dir / "s0").glob("*.yaml"))
    assert s0_files, f"no S0 truth under {truth_dir / 's0'}; the lint would be vacuous"
    for path in s0_files:
        truth = yaml.safe_load(path.read_text(encoding="utf-8"))
        tokens.add(canonical(truth["slug"]))
    for path in sorted(truth_dir.rglob("*.yaml")):
        truth = yaml.safe_load(path.read_text(encoding="utf-8"))
        for symbol in truth.get("forbidden_symbols") or []:
            tokens.add(canonical(symbol))
    return sorted(tokens)


def compile_patterns(tokens: List[str]) -> Dict[str, "re.Pattern[str]"]:
    """One pattern per token; ``-`` and ``_`` are interchangeable inside it."""
    return {
        token: re.compile("[-_]".join(re.escape(p) for p in token.split("_")), re.I)
        for token in tokens
    }


# ---------------------------------------------------------------------------
# The scanner


def _docstring_node(node: ast.AST) -> Optional[ast.Constant]:
    if not isinstance(
        node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        return None
    body = getattr(node, "body", None)
    if not body:
        return None
    first = body[0]
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        return first.value
    return None


def _identifiers(tree: ast.AST) -> Iterator[Tuple[str, int]]:
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        for field in IDENTIFIER_FIELDS:
            value = getattr(node, field, None)
            if isinstance(value, str):
                yield value, line
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                yield name, line


def scan_source(source: str, patterns: Dict[str, "re.Pattern[str]"]) -> List[Hit]:
    """Every forbidden-token hit in one module's source, by kind."""
    if not patterns:
        return []
    tree = ast.parse(source)
    hits: List[Hit] = []
    # One alternation first: almost no text matches, so most calls stop here.
    any_token = re.compile("|".join(p.pattern for p in patterns.values()), re.I)

    def record(kind: str, text: str, line: int) -> None:
        if not any_token.search(text):
            return
        for token, pattern in patterns.items():
            count = len(pattern.findall(text))
            if count:
                hits.append(Hit(kind, token, line, count))

    docstrings = set()
    for node in ast.walk(tree):
        doc = _docstring_node(node)
        if doc is not None:
            docstrings.add(id(doc))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            text = node.value
            if isinstance(text, bytes):
                text = text.decode("latin-1")
            kind = "docstring" if id(node) in docstrings else "string"
            record(kind, text, node.lineno)
    for name, line in _identifiers(tree):
        record("identifier", name, line)
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            record("comment", tok.string, tok.start[0])
    return hits


def scan_package(
    patterns: Dict[str, "re.Pattern[str]"], package: Path = PACKAGE
) -> List[Tuple[str, Hit]]:
    files = sorted(package.rglob("*.py"))
    assert files, f"no Python files under {package}; the lint would be vacuous"
    found: List[Tuple[str, Hit]] = []
    for path in files:
        rel = path.relative_to(package.parent).as_posix()
        try:
            hits = scan_source(path.read_text(encoding="utf-8"), patterns)
        except (SyntaxError, tokenize.TokenError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"cannot scan {rel}: {exc}") from exc
        found.extend((rel, hit) for hit in hits)
    return found


# ---------------------------------------------------------------------------
# The documentation inventory


def build_inventory(found: List[Tuple[str, Hit]]) -> List[dict]:
    """(path, token, kind, count) for comments and docstrings, sorted."""
    counts: Counter = Counter()
    for rel, hit in found:
        if hit.kind in DOC_KINDS:
            counts[(rel, hit.token, hit.kind)] += hit.count
    return [
        {"path": path, "token": token, "kind": kind, "count": count}
        for (path, token, kind), count in sorted(counts.items())
    ]


def render_inventory(entries: List[dict]) -> str:
    lines = [
        "{",
        '  "generated_by": "' + REGEN_COMMAND + ' -- never edit by hand",',
        '  "entries": [',
    ]
    body = ["    " + json.dumps(entry) for entry in entries]
    lines.append(",\n".join(body))
    lines.extend(["  ]", "}", ""])
    return "\n".join(lines)


@functools.lru_cache(maxsize=None)
def current_inventory() -> Tuple[List[Tuple[str, Hit]], List[dict]]:
    found = scan_package(compile_patterns(load_forbidden_tokens()))
    return found, build_inventory(found)


def regen(path: Path = INVENTORY) -> int:
    found, entries = current_inventory()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_inventory(entries), encoding="utf-8")
    print(f"wrote {path}: {len(entries)} entries")
    for rel, hit in found:
        if hit.kind in CODE_KINDS:
            print(
                f"WARNING: code hit {rel}:{hit.line} {hit.kind} {hit.token}; "
                "not inventoried, test_no_forbidden_token_in_code fails on it",
                file=sys.stderr,
            )
    return 0


def _describe(entry: dict) -> str:
    return f"{entry['path']} {entry['token']} {entry['kind']} x{entry['count']}"


# ---------------------------------------------------------------------------
# Tests over the real tree


def test_forbidden_tokens_come_from_the_truth_files():
    tokens = load_forbidden_tokens()
    s0_files = sorted(S0_TRUTH_DIR.glob("*.yaml"))
    assert len(s0_files) >= 7, "the S0 truth set shrank; the lint would weaken"
    assert "fill_ammo" in tokens, "a truth file's forbidden_symbols was not read"
    assert all(t == canonical(t) and t for t in tokens)


def test_no_forbidden_token_in_code():
    found, _ = current_inventory()
    bad = [
        f"{rel}:{hit.line} {hit.kind} {hit.token}"
        for rel, hit in found
        if hit.kind in CODE_KINDS
    ]
    assert not bad, (
        "a benchmark target's name is in product code (identifier or string "
        "constant); reword it generically: " + "; ".join(bad)
    )


def test_documentation_hits_match_the_committed_inventory():
    assert INVENTORY.is_file(), f"missing {INVENTORY}; run {REGEN_COMMAND}"
    committed = json.loads(INVENTORY.read_text(encoding="utf-8"))["entries"]
    _, current = current_inventory()
    key = lambda e: (e["path"], e["token"], e["kind"])  # noqa: E731
    have = {key(e): e for e in committed}
    want = {key(e): e for e in current}
    added = [_describe(want[k]) for k in sorted(want) if k not in have]
    removed = [_describe(have[k]) for k in sorted(have) if k not in want]
    changed = [
        f"{_describe(have[k])} -> x{want[k]['count']}"
        for k in sorted(have)
        if k in want and have[k] != want[k]
    ]
    assert not (added or removed or changed), (
        "target names in comments or docstrings differ from the inventory. "
        f"If the change is intended, run `{REGEN_COMMAND}` and commit it. "
        f"new: {added}; gone: {removed}; count changed: {changed}"
    )


def test_inventory_file_is_the_generated_form():
    """Not hand-edited: the bytes are exactly what the helper would write."""
    entries = json.loads(INVENTORY.read_text(encoding="utf-8"))["entries"]
    assert INVENTORY.read_text(encoding="utf-8") == render_inventory(entries)
    assert entries == sorted(
        entries, key=lambda e: (e["path"], e["token"], e["kind"])
    ), "entries are not in generated order"
    assert all(e["kind"] in DOC_KINDS and e["count"] > 0 for e in entries)


def test_regen_writes_the_committed_file(tmp_path):
    out = tmp_path / "inventory.json"
    assert regen(out) == 0
    assert out.read_text(encoding="utf-8") == INVENTORY.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Controls: the scanner can fail, and does not flag ordinary words


@pytest.fixture(scope="module")
def patterns():
    return compile_patterns(load_forbidden_tokens())


def kinds(source: str, patterns) -> List[Tuple[str, str]]:
    return sorted((h.kind, h.token) for h in scan_source(source, patterns))


def test_positive_a_slug_in_a_string_constant_is_flagged(patterns):
    assert kinds('x = "solved rocket_blaster_xxx"\n', patterns) == [
        ("string", "rocket_blaster_xxx")
    ]


def test_positive_a_forbidden_symbol_as_an_identifier_is_flagged(patterns):
    assert kinds("fill_ammo = 1\n", patterns) == [("identifier", "fill_ammo")]


@pytest.mark.parametrize(
    "source",
    [
        "obj.fill_ammo\n",
        "def fill_ammo():\n    pass\n",
        "class Fill_Ammo:\n    pass\n",
        "f(fill_ammo=1)\n",
        "def f(fill_ammo):\n    pass\n",
        "import fill_ammo\n",
        "from x import y as fill_ammo\n",
        "def f():\n    global fill_ammo\n",
        "try:\n    pass\nexcept E as fill_ammo:\n    pass\n",
    ],
)
def test_positive_every_identifier_position_is_flagged(source, patterns):
    assert ("identifier", "fill_ammo") in kinds(source, patterns)


@pytest.mark.parametrize(
    "spelling", ["sick_rop", "sick-rop", "SICK_ROP", "Sick-Rop", "xsick_rop2"]
)
def test_positive_spellings_and_case_are_one_token(spelling, patterns):
    assert kinds(f's = "{spelling}"\n', patterns) == [("string", "sick_rop")]


def test_positive_a_slug_split_over_adjacent_literals_is_flagged(patterns):
    source = 'why = (\n    "declined HTB `bon-nie-"\n    "appetit`, a target"\n)\n'
    assert kinds(source, patterns) == [("string", "bon_nie_appetit")]


def test_positive_fstring_constant_parts_are_flagged(patterns):
    assert kinds('x = f"{y} sabotage"\n', patterns) == [("string", "sabotage")]


def test_positive_a_non_docstring_bare_string_is_code(patterns):
    source = 'x = 1\n"sabotage"\n'
    assert kinds(source, patterns) == [("string", "sabotage")]


def test_documentation_is_classified_not_flagged_as_code(patterns):
    source = (
        '"""Module cites sabotage."""\n'
        "# a comment about snow-scan\n"
        "def f():\n"
        '    """Docstring: auth-or-out."""\n'
    )
    assert kinds(source, patterns) == [
        ("comment", "snow_scan"),
        ("docstring", "auth_or_out"),
        ("docstring", "sabotage"),
    ]


def test_counts_are_occurrences_not_lines(patterns):
    (hit,) = scan_source('"""sabotage and Sabotage"""\n', patterns)
    assert (hit.kind, hit.count) == ("docstring", 2)


NEGATIVES = ["main", "win", "flag", "success", "read", "system", "reward", "vuln"]


@pytest.mark.parametrize("word", NEGATIVES)
def test_negative_ordinary_words_are_not_flagged(word, patterns):
    source = (
        f'"""A module that mentions {word}."""\n'
        f"# {word}\n"
        f"{word} = {word}.{word}({word}={word!r})\n"
        f"def {word}({word}):\n"
        f'    """The {word} function."""\n'
        f"    return '{word}'\n"
        f"class {word.capitalize()}:\n"
        "    pass\n"
    )
    assert scan_source(source, patterns) == []


def test_negative_words_are_not_forbidden_tokens():
    assert not set(NEGATIVES) & set(load_forbidden_tokens())


# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--regen",
        action="store_true",
        help="rewrite tests/data/target_identifier_inventory.json",
    )
    args = parser.parse_args(argv)
    if args.regen:
        return regen()
    parser.error("nothing to do; pass --regen, or run this file with pytest")
    return 2


if __name__ == "__main__":
    sys.exit(main())
