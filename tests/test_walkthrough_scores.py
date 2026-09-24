"""The cross-family score ordering, enforced instead of reviewed.

``registry.generate_walkthrough`` picks the winning family with ``max()`` over
the applicable routes.  ``max()`` keeps the FIRST maximum it sees, so two routes
that share a score make the winner depend on the incidental position of the
family in the list returned by ``registry._families()`` -- and a family added
later can then silently capture a target that an earlier family used to win,
with no code in either family changing.  That failure mode is invisible in a
diff and invisible in a single family's own tests, because a family's tests only
look at the targets it expects to win.

Two of the shipped families hit it during development: the integer family had to
raise 0.88/0.90 to 0.96/0.97 (they tied SROP and ret2shellcode), and the
format-string family raised its read route off 0.90 (tied ``stack_bof``'s
ret2shellcode) and its GOT route off 0.80 (tied ``syscall``'s ret2syscall).
Both were found by hand.  This module makes the invariant a test.

Scores are read out of the family modules with ``ast``, not by calling
``propose()``, for three reasons: it needs no binaries and no fixtures, so it
runs in a fresh clone; it sees *every* branch of a family's scoring, including
the routes that a corpus target happens not to exercise; and it cannot be
satisfied by a family that merely declines to propose during the test run.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

FAMILIES_DIR = (
    Path(__file__).resolve().parent.parent
    / "supwngo"
    / "exploit"
    / "walkthrough"
    / "families"
)

#: ``score=0.0`` is the package's convention for "this route is not on the
#: table at all", used by the non-applicable routes that exist purely to explain
#: in the decision tree why the technique does not fit.  Several families use it,
#: so it is the one value allowed to repeat -- and
#: ``test_zero_scored_routes_are_never_applicable`` holds that convention up.
NOT_ON_THE_TABLE = 0.0


def _module_level_numbers(tree: ast.Module) -> dict[str, float]:
    """Module-level ``NAME = <number>`` bindings, so named scores resolve."""
    consts: dict[str, float] = {}
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not isinstance(stmt.value, ast.Constant):
            continue
        if not isinstance(stmt.value.value, (int, float)):
            continue
        if isinstance(stmt.value.value, bool):
            continue
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                consts[target.id] = float(stmt.value.value)
    return consts


def _scores_of(expr: ast.expr, consts: dict[str, float]) -> list[float]:
    """Every value ``expr`` can evaluate to.

    A conditional (``0.95 if has_rdi else 0.35`` in ``rop_chain``) contributes
    BOTH of its arms: each is a score the registry can genuinely see, so each
    has to be distinct from every other family's.  An expression this function
    cannot resolve is an error rather than a skip -- a family that computed its
    score arithmetically would otherwise slip past the whole invariant.
    """
    if isinstance(expr, ast.Constant) and isinstance(expr.value, (int, float)):
        return [float(expr.value)]
    if isinstance(expr, ast.Name) and expr.id in consts:
        return [consts[expr.id]]
    if isinstance(expr, ast.IfExp):
        return _scores_of(expr.body, consts) + _scores_of(expr.orelse, consts)
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.USub):
        return [-value for value in _scores_of(expr.operand, consts)]
    raise AssertionError(
        "A Route's score is not a literal, a module-level constant or a "
        "conditional over those, so this test cannot enumerate it and the "
        "no-ties invariant would silently stop covering it: "
        f"{ast.unparse(expr)!r}. Bind it to a module-level constant."
    )


class RouteScore:
    """One ``Route(...)`` site's score, with enough context to name it."""

    def __init__(self, family: str, score: float, applicable, lineno: int):
        self.family = family
        self.score = score
        self.applicable = applicable
        self.lineno = lineno

    def __repr__(self) -> str:  # pragma: no cover - failure messages only
        return f"{self.family}.py:{self.lineno} score={self.score:.2f}"


def _collect() -> list[RouteScore]:
    found: list[RouteScore] = []
    modules = sorted(
        p for p in FAMILIES_DIR.glob("*.py") if p.name != "__init__.py"
    )
    assert modules, f"no family modules under {FAMILIES_DIR}"
    for path in modules:
        tree = ast.parse(path.read_text())
        consts = _module_level_numbers(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Name) and node.func.id == "Route"):
                continue
            keywords = {kw.arg: kw.value for kw in node.keywords}
            if "score" not in keywords:
                raise AssertionError(
                    f"{path.name}:{node.lineno} builds a Route with no explicit "
                    "score, so its rank is whatever the dataclass default is."
                )
            applicable_node = keywords.get("applicable")
            if isinstance(applicable_node, ast.Constant):
                applicable = applicable_node.value
            else:
                applicable = "dynamic"
            for score in _scores_of(keywords["score"], consts):
                found.append(RouteScore(path.stem, score, applicable, node.lineno))
    return found


ALL_SCORES = _collect()


def test_every_family_module_was_parsed():
    """Guards the collector itself against silently finding nothing."""
    families = {rs.family for rs in ALL_SCORES}
    assert families >= {
        "rop_chain",
        "syscall",
        "stack_bof",
        "fmtstr",
        "integer",
        "triage",
    }, f"collector missed a shipped family; saw {sorted(families)}"
    assert len(ALL_SCORES) >= 17, f"only found {len(ALL_SCORES)} Route scores"


def test_no_two_routes_share_a_score():
    """The invariant: distinct scores, so list order can never decide a winner."""
    by_score: dict[float, list[RouteScore]] = {}
    for rs in ALL_SCORES:
        if rs.score == NOT_ON_THE_TABLE:
            continue
        by_score.setdefault(rs.score, []).append(rs)

    ties = {
        score: sites for score, sites in by_score.items() if len(sites) > 1
    }
    assert not ties, (
        "Two routes share a score. registry.generate_walkthrough resolves that "
        "by list position in registry._families(), so one of these families "
        "would silently outrank the other on any binary where both apply: "
        + "; ".join(
            f"{score:.2f} <- {[repr(s) for s in sites]}"
            for score, sites in sorted(ties.items())
        )
    )


def test_zero_scored_routes_are_never_applicable():
    """0.0 is allowed to repeat only because it means "not on the table"."""
    offenders = [
        rs
        for rs in ALL_SCORES
        if rs.score == NOT_ON_THE_TABLE and rs.applicable is not False
    ]
    assert not offenders, (
        "A route scores 0.0 but is applicable (or decides applicability at "
        f"runtime): {offenders}. 0.0 is exempted from the no-ties check on the "
        "grounds that it never competes; an applicable 0.0 route breaks that."
    )


def test_triage_is_the_floor():
    """Nothing may rank at or below the route of last resort."""
    from supwngo.exploit.walkthrough.families.triage import TRIAGE_SCORE

    below = [
        rs
        for rs in ALL_SCORES
        if rs.family != "triage"
        and rs.score != NOT_ON_THE_TABLE
        and rs.score <= TRIAGE_SCORE
    ]
    assert not below, (
        f"guided triage scores {TRIAGE_SCORE} and exists to lose to everything "
        f"that has something specific to say, but these rank at or below it: "
        f"{below}"
    )


def test_scores_stay_below_one():
    """A score above 1.0 would read as a certainty the model cannot express."""
    over = [rs for rs in ALL_SCORES if rs.score > 1.0]
    assert not over, f"scores are a 0..1 rank: {over}"


@pytest.mark.parametrize(
    "family, expected",
    [
        # The full cross-family ordering, highest first, as of the fmtstr +
        # integer consolidation and the heap family. Listed per family so that a
        # family changing one of its own scores fails here with the whole picture
        # in the message rather than only in the tie check.
        ("integer", [0.97, 0.96, 0.45]),
        ("rop_chain", [0.95, 0.85, 0.60, 0.35]),
        ("fmtstr", [0.92, 0.91, 0.82, 0.55]),
        ("stack_bof", [0.90, 0.75, 0.30]),
        ("syscall", [0.88, 0.80]),
        # heap ships detection only: it characterises a primitive without
        # claiming control of execution, so it must lose to every technique
        # family (lowest of those is integer's partial route at 0.45) and beat
        # the generic discovery workflow (triage at 0.15). 0.25 rather than
        # 0.30/0.35, which are taken by non-applicable routes that the
        # uniqueness invariant covers anyway.
        ("heap", [0.25]),
        ("triage", [0.15]),
    ],
)
def test_recorded_ordering_is_the_live_ordering(family, expected):
    live = sorted(
        {rs.score for rs in ALL_SCORES if rs.family == family and rs.score > 0},
        reverse=True,
    )
    assert live == sorted(expected, reverse=True), (
        f"{family}'s scores changed. Re-derive the whole cross-family ordering "
        "before editing this list -- the point of recording it is that a local "
        "edit cannot move a family past another one unnoticed."
    )
