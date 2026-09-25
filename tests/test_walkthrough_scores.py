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


#: Every ``(family, score)`` where a family declares two or more routes at the
#: same score, with the count. Recorded as data rather than prose because the
#: cross-family check above deliberately exempts ``0.0`` -- which means every
#: entry here is a pair of routes the *within*-family selection has to separate
#: without help from the score.
#:
#: Derived, not hand-written: see ``test_recorded_within_family_ties_are_live``.
WITHIN_FAMILY_TIES = {
    ("fmtstr", 0.0): 3,
    ("heap", 0.0): 2,
    ("integer", 0.0): 4,
    ("syscall", 0.0): 2,
}


def _within_family_ties() -> dict[tuple[str, float], int]:
    counts: dict[tuple[str, float], int] = {}
    for rs in ALL_SCORES:
        key = (rs.family, rs.score)
        counts[key] = counts.get(key, 0) + 1
    return {key: n for key, n in counts.items() if n > 1}


def test_recorded_within_family_ties_are_live():
    """The enumeration above must match the code, or it is documentation.

    This is the sweep the cross-family check cannot do. That check holds the
    within-family dimension constant -- it compares scores *between* families and
    exempts ``0.0`` entirely -- so a family with four routes at ``0.0`` reads as
    fully compliant while its own selection is decided by list position. A test
    that holds constant the dimension where the defect lives looks exactly like
    correctness.
    """
    assert _within_family_ties() == WITHIN_FAMILY_TIES, (
        "the set of within-family score ties changed. These are the route pairs "
        "that `common.select_route` has to separate without help from the score, "
        "so re-check the selection in the affected family before editing this "
        "table."
    )


def test_no_family_resolves_a_score_tie_by_list_position():
    """Static rule: a family may not rank its own routes by score.

    ``max(routes, key=lambda r: r.score)`` keeps the FIRST maximum, so with two
    routes at ``0.0`` -- which four families have -- the winner is the one that
    happens to appear first in a list, and the other's explanation is silently
    discarded. ``heap`` shipped that defect; ``fmtstr`` and ``integer`` both had
    it latent (``fmtstr`` keyed on ``(applicable, score)``, ``integer`` fell
    through to ``candidates[0]``).

    Families must select through ``common.select_route``, whose order is total,
    or partition on a predicate so that nothing is discarded at all (``heap``).
    This is a structural check rather than a behavioural one so it also covers
    the fact-states no corpus target reaches.
    """
    offenders = []
    for path in sorted(FAMILIES_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            if name not in {"max", "min", "sorted"}:
                continue
            for keyword in node.keywords:
                if keyword.arg != "key":
                    continue
                if ".score" in ast.unparse(keyword.value):
                    offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, (
        "a family ranks routes by score itself, which resolves a tie by list "
        f"position: {offenders}. Use common.select_route (total order) or "
        "partition the routes on a predicate."
    )


def test_select_route_order_does_not_decide_among_tied_routes():
    """The behavioural half, on the shared selector and with no binaries needed.

    Builds the exact shape that broke ``heap`` -- two non-applicable routes at
    ``0.0`` -- and asserts the answer is the same whichever order they arrive in.
    """
    from supwngo.exploit.walkthrough import common
    from supwngo.exploit.walkthrough.model import Rejection, Requirement, Route

    def rejection(name, satisfied):
        return Route(
            name=name,
            score=NOT_ON_THE_TABLE,
            applicable=False,
            rationale=f"{name} does not fit",
            requires=tuple(
                Requirement(f"precondition {i}", ok) for i, ok in enumerate(satisfied)
            ),
            rejection=Rejection.UNMET_PRECONDITION,
        )

    closer = rejection("closer to viable", [True, True, False])
    further = rejection("further from viable", [False, False, False])

    assert common.select_route([closer, further]) is closer
    assert common.select_route([further, closer]) is closer, (
        "reversing the candidate list changed the answer, so position is still "
        "deciding"
    )


def test_select_route_refuses_rather_than_inventing_a_winner():
    """Two indistinguishable routes must raise, not resolve.

    The obvious fix for a tie is a final arbitrary-but-deterministic key such as
    ``name``. That makes the tie unobservable without making it correct: an
    earlier version of ``select_route`` did exactly that and silently handed
    ``fmtstr`` to the ``%n`` write route in a case whose whole point is to report
    the read rejection, because "write" sorts after "read". Raising is what forces
    the family to partition its routes or score them apart.
    """
    from supwngo.exploit.walkthrough import common
    from supwngo.exploit.walkthrough.model import (
        Rejection,
        Requirement,
        Route,
        WalkthroughError,
    )

    def rejection(name):
        return Route(
            name=name,
            score=NOT_ON_THE_TABLE,
            applicable=False,
            rationale=f"{name} does not fit",
            requires=(Requirement("the same unmet precondition", False),),
            rejection=Rejection.UNMET_PRECONDITION,
        )

    first, second = rejection("alpha route"), rejection("beta route")

    for candidates in ([first, second], [second, first]):
        with pytest.raises(WalkthroughError) as caught:
            common.select_route(candidates)
        message = str(caught.value)
        assert "alpha route" in message and "beta route" in message, message
        assert "partition" in message, (
            "the error must tell the family how to resolve the tie, not just "
            f"report it: {message}"
        )


def test_select_route_prefers_applicable_over_a_higher_scoring_rejection():
    """A route that works beats one that does not, whatever the scores say."""
    from supwngo.exploit.walkthrough import common
    from supwngo.exploit.walkthrough.model import Rejection, Route

    works = Route(
        name="works",
        score=0.25,
        applicable=True,
        rationale="measured",
    )
    louder = Route(
        name="does not work",
        score=0.97,
        applicable=False,
        rationale="unmet",
        rejection=Rejection.UNMET_PRECONDITION,
    )
    assert common.select_route([louder, works]) is works
    assert common.select_route([works, louder]) is works


def test_select_route_drops_none_and_returns_none_when_empty():
    """Families pass builders that return ``None`` to mean "nothing to say"."""
    from supwngo.exploit.walkthrough import common
    from supwngo.exploit.walkthrough.model import Route

    only = Route(name="only", score=0.5, applicable=True, rationale="x")
    assert common.select_route([None, only, None]) is only
    assert common.select_route([]) is None
    assert common.select_route([None, None]) is None


def _tied_rejections():
    """Two non-applicable routes at 0.0, one closer to viable than the other."""
    from supwngo.exploit.walkthrough.model import Rejection, Requirement, Route

    def rejection(name, satisfied):
        return Route(
            name=name,
            score=NOT_ON_THE_TABLE,
            applicable=False,
            rationale=f"{name} does not fit",
            requires=tuple(
                Requirement(f"precondition {i}", ok) for i, ok in enumerate(satisfied)
            ),
            rejection=Rejection.UNMET_PRECONDITION,
        )

    return (
        rejection("closer to viable", [True, True, False]),
        rejection("further from viable", [False, False, False]),
    )


def test_integer_selects_rather_than_indexes_when_both_sites_exist(monkeypatch):
    """Forced two-candidate state: no corpus target reaches it.

    ``integer`` used to ``return candidates[0]`` when neither route applied, which
    is positional selection written plainly. It is invisible on this corpus
    because no target has *both* a negative-index site and a truncation site, so
    only one candidate is ever built -- the same "inert, not safe" shape that two
    heap mutants had. Forcing the state is the only way to cover it.
    """
    from supwngo.exploit.walkthrough.families import integer

    closer, further = _tied_rejections()

    class BothSites:
        empty = False
        negative_indexes = [object()]
        truncations = [object()]

    class Facts:
        bits = 64

    monkeypatch.setattr(integer, "_analyse", lambda facts: BothSites())
    monkeypatch.setattr(integer, "_negative_index_route", lambda f, a: further)
    monkeypatch.setattr(integer, "_truncation_route", lambda f, a: closer)
    assert integer.propose(Facts()) is closer

    # Swap which builder yields which route: the answer must follow the facts,
    # not the order the conditions are written in.
    monkeypatch.setattr(integer, "_negative_index_route", lambda f, a: closer)
    monkeypatch.setattr(integer, "_truncation_route", lambda f, a: further)
    assert integer.propose(Facts()) is closer, (
        "integer returned the first candidate rather than selecting, so the route "
        "it proposes depends on which condition is written first"
    )


def test_fmtstr_selects_rather_than_ranking_when_both_routes_are_rejections(
    monkeypatch,
):
    """``fmtstr`` must *partition* its two rejections, not rank them.

    Reachable in principle -- a reachable format string whose read target is
    unreachable and whose argument index was not measured -- but not by target 05
    or 06, which each yield one applicable route.

    The two rejections are genuinely indistinguishable to a ranking: both score
    ``0.0``, and the real read rejection and the real "nothing to write to"
    rejection also have the same number of satisfied requirements. So the answer
    must come from the family's own decision -- the read rejection, because a
    format-string bug *is* a read primitive -- and must not change when the
    candidates swap places or when one of them looks "closer to viable".
    """
    from supwngo.exploit.walkthrough.families import fmtstr

    closer, further = _tied_rejections()

    class Fs:
        reachable = True

    class Facts:
        fmtstr = Fs()

    # Whichever route is the *read* one wins, in both directions -- including the
    # direction where that makes the "further from viable" route the answer.
    monkeypatch.setattr(fmtstr, "_read_route", lambda f, fs: further)
    monkeypatch.setattr(fmtstr, "_write_route", lambda f, fs: closer)
    assert fmtstr.propose(Facts()) is further, (
        "fmtstr ranked its rejections instead of partitioning them: the read "
        "rejection is the answer even when the write rejection satisfies more "
        "requirements"
    )

    monkeypatch.setattr(fmtstr, "_read_route", lambda f, fs: closer)
    monkeypatch.setattr(fmtstr, "_write_route", lambda f, fs: further)
    assert fmtstr.propose(Facts()) is closer, (
        "fmtstr resolved the 0.0 tie by list position"
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
