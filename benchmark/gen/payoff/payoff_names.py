"""Seeded identifier namespace for the payoff corpus, with its disjointness check.

Every user function and global in a generated program gets a random pronounceable
name. A name is rejected (and another drawn) if it could be an answer key or a
product-side string:

* it contains a forbidden token: every ``slug`` and every ``forbidden_symbols``
  entry under ``benchmark/truth/`` (the same source the target-identifier lint
  reads) plus the generic payoff words in ``GENERIC_WORDS``; a token is matched
  anywhere inside a longer word, case-insensitively, with ``-`` and ``_`` the same,
  and also with the separators stripped from both sides;
* it equals a string constant in ``supwngo/**/*.py`` (collected with ``ast``,
  case-insensitive), or any identifier-shaped word inside one;
* it is a C keyword or a name the program skeleton itself uses.

The same checks run over the finished C source text (``lint_source``), so a
forbidden word cannot arrive through a string literal or a skeleton identifier.
"""

from __future__ import annotations

import ast
import functools
import random
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

# Words that would name a payoff function in a hand-written list. The corpus must
# never carry them as a function or global name.
GENERIC_WORDS: Tuple[str, ...] = (
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

# C keywords, plus every identifier the generated skeleton uses itself.
C_RESERVED = frozenset(word.lower() for word in """
    auto break case char const continue default do double else enum extern float
    for goto if inline int long register restrict return short signed sizeof
    static struct switch typedef union unsigned void volatile while
    main argc argv buf got tmp acc size_t FILE NULL stdin stdout stderr
    read write open close fopen fread fwrite fclose fgets fputs puts printf
    execve execv execl system exit abort malloc free memcpy memset strlen strcpy
    sprintf snprintf getenv setenv signal alarm fork wait kill
    """.split())

MIN_NAME_LENGTH = 6

_ONSETS = (
    "b d f g h j k l m n p r s t v z br dr fr gr kr pr tr bl fl gl kl pl sl st sp "
    "th ch"
).split()
_VOWELS = "a e i o u a e i o u ai ea ou io".split()
_INNER_CODAS = "", "", "", "n", "r", "l", "m", "s"
_FINAL_CODAS = "", "", "", "n", "r", "l", "m", "s", "k", "t", "x"
_STYLES = ("plain", "snake", "camel")


def canonical(token: str) -> str:
    return token.strip().lower().replace("-", "_")


def _token_pattern(token: str) -> "re.Pattern[str]":
    parts = canonical(token).split("_")
    return re.compile("[-_]".join(re.escape(p) for p in parts), re.I)


def load_forbidden_tokens(repo_root: Path) -> List[str]:
    """Canonical forbidden tokens: truth-file slugs and symbols, plus the generics."""
    truth_dir = repo_root / "benchmark" / "truth"
    files = sorted(truth_dir.rglob("*.yaml"))
    if not files:
        raise RuntimeError(
            f"no truth files under {truth_dir}; the check would be vacuous"
        )
    tokens: Set[str] = {canonical(w) for w in GENERIC_WORDS}
    for path in files:
        truth = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        slug = truth.get("slug")
        if isinstance(slug, str) and slug:
            tokens.add(canonical(slug))
        symbols = truth.get("forbidden_symbols")
        if isinstance(symbols, list):
            tokens.update(canonical(s) for s in symbols if isinstance(s, str) and s)
    return sorted(tokens)


@functools.lru_cache(maxsize=4)
def product_strings(repo_root: Path) -> Tuple[frozenset, frozenset]:
    """(string constants, identifier-shaped words inside them), lowercased.

    Collected from every ``supwngo/**/*.py`` with ``ast``. A file that does not parse
    is an error: an unscanned file would make the disjointness claim unsound.
    """
    package = repo_root / "supwngo"
    files = sorted(package.rglob("*.py"))
    if not files:
        raise RuntimeError(
            f"no Python files under {package}; the check would be vacuous"
        )
    constants: Set[str] = set()
    words: Set[str] = set()
    word_re = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value.lower()
                constants.add(text)
                constants.add(text.strip())
                words.update(word_re.findall(text))
    return frozenset(constants), frozenset(words)


class Deps:
    """The disjointness inputs, built once per run (read-only afterwards)."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.tokens = load_forbidden_tokens(repo_root)
        self.patterns = [(t, _token_pattern(t)) for t in self.tokens]
        self.flat_tokens = [(t, t.replace("_", "")) for t in self.tokens]
        self.constants, self.words = product_strings(repo_root)

    def token_hits(self, text: str) -> List[str]:
        """Forbidden tokens found inside ``text`` (separator-insensitive)."""
        low = text.lower()
        flat = low.replace("_", "").replace("-", "")
        hits = []
        for (token, pattern), (_, flat_token) in zip(self.patterns, self.flat_tokens):
            if pattern.search(text) or flat_token in flat:
                hits.append(token)
        return hits

    def violation(self, name: str) -> Optional[str]:
        """Why ``name`` may not be a generated identifier, or None if it may."""
        low = name.lower()
        if len(name) < MIN_NAME_LENGTH:
            return "too short"
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            return "not a plain C identifier"
        if low in C_RESERVED:
            return "reserved C or skeleton word"
        hits = self.token_hits(name)
        if hits:
            return "contains forbidden token " + ", ".join(hits)
        if low in self.constants:
            return "equals a string constant in supwngo/"
        if low in self.words:
            return "equals a word inside a string constant in supwngo/"
        return None

    def lint_source(self, text: str) -> List[str]:
        """Forbidden tokens anywhere in generated C text (identifiers and strings)."""
        found: Set[str] = set()
        for word in re.findall(r"[A-Za-z0-9_]+", text):
            found.update(self.token_hits(word))
        return sorted(found)


class Namespace:
    """Draws fresh, pronounceable, lint-clean identifiers from one seeded stream."""

    def __init__(
        self,
        rng: random.Random,
        deps: Deps,
        used: Iterable[str] = (),
    ):
        self.rng = rng
        self.deps = deps
        self.used: Set[str] = {u.lower() for u in used}
        self.style = rng.choice(_STYLES)

    def _syllables(self, count: int) -> str:
        rng = self.rng
        out = []
        for i in range(count):
            coda = rng.choice(_FINAL_CODAS if i == count - 1 else _INNER_CODAS)
            out.append(rng.choice(_ONSETS) + rng.choice(_VOWELS) + coda)
        return "".join(out)

    def _candidate(self) -> str:
        rng = self.rng
        if self.style == "plain":
            return self._syllables(rng.randint(3, 4))
        first = self._syllables(2)
        second = self._syllables(rng.randint(1, 2))
        if self.style == "snake":
            return first + "_" + second
        return first + second[:1].upper() + second[1:]

    def fresh(self) -> str:
        for _ in range(10000):
            name = self._candidate()
            if name.lower() in self.used or self.deps.violation(name):
                continue
            self.used.add(name.lower())
            return name
        raise RuntimeError("could not draw a lint-clean identifier in 10000 attempts")

    def fresh_many(self, count: int) -> List[str]:
        return [self.fresh() for _ in range(count)]

    def phrase(self, words: int = 2) -> str:
        """A short lowercase phrase for a string literal, clean under the same lint."""
        picked = []
        while len(picked) < words:
            word = self._syllables(self.rng.randint(2, 3))
            if len(word) >= 4 and not self.deps.token_hits(word):
                picked.append(word)
        return " ".join(picked)


def check_names(deps: Deps, names: Sequence[str]) -> Dict[str, str]:
    """Name -> reason, for every name that violates the namespace rules."""
    return {n: v for n in names if (v := deps.violation(n)) is not None}
