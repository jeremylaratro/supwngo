#!/usr/bin/env python3
"""Platform-token lint (W-3 design section 4).

AST-walks Python source and flags platform tokens inside ``str``/``bytes``
constants (including the constant segments of f-strings).  Only syntactic
module/class/function docstrings are excluded; comments are never AST
constants, so they are inherently out of scope.

Usage: check_platform_tokens.py [PATH ...]   (default: supwngo/)
Exit status 1 when any violation is found.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Iterable, List, NamedTuple

TOKENS = ("htb", "hackthebox", "picoctf", "csaw", "asis")
BRACE_PREFIXES = ("flag", "ctf") + TOKENS

# Word-bounded identifier tokens: "asis" must not match "basis" / "OASIS".
WORD_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" % "|".join(TOKENS), re.IGNORECASE
)
# Brace shapes, plain (flag{) and raw-regex (flag\{) forms.
BRACE_RE = re.compile(r"(?:%s)\\?\{" % "|".join(BRACE_PREFIXES), re.IGNORECASE)


class Violation(NamedTuple):
    path: str
    line: int
    token: str
    value: str


def _scan_value(value: str) -> List[str]:
    hits = [m.group(0) for m in WORD_RE.finditer(value)]
    hits += [m.group(0) for m in BRACE_RE.finditer(value)]
    return hits


def _docstring_nodes(tree: ast.AST) -> set:
    skip = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, (str, bytes))
            ):
                skip.add(id(body[0].value))
    return skip


def scan_source(source: str, path: str = "<string>") -> List[Violation]:
    tree = ast.parse(source, filename=path)
    skip = _docstring_nodes(tree)
    out: List[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or id(node) in skip:
            continue
        v = node.value
        if isinstance(v, bytes):
            v = v.decode("latin-1")
        elif not isinstance(v, str):
            continue
        for tok in _scan_value(v):
            out.append(Violation(path, node.lineno, tok, v[:80]))
    return out


def scan_paths(paths: Iterable[Path]) -> List[Violation]:
    out: List[Violation] = []
    for p in paths:
        files = sorted(p.rglob("*.py")) if p.is_dir() else [p]
        for f in files:
            out += scan_source(f.read_text(encoding="utf-8", errors="replace"), str(f))
    return out


def main(argv: List[str] | None = None) -> int:
    args = (argv if argv is not None else sys.argv[1:]) or ["supwngo"]
    violations = scan_paths(Path(a) for a in args)
    for v in violations:
        print(f"{v.path}:{v.line}: platform token {v.token!r} in {v.value!r}")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
