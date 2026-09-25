"""C6: the refusal-coverage instrument (unit-1 plan §6).

Fully mechanical, no hand-annotation: patch each of
:mod:`supwngo.schema.resolve`'s OWN error classes' ``__init__`` to record the
caller's line number, run a representative subset of the suite, and diff the
fired line numbers against every ``raise`` found by parsing the module's
current source with :mod:`ast`.

**REFUSAL-SITE CONTROL COVERAGE -- NOT a proof of accepted-domain closure.**
Full coverage here can coexist with a false C2: a type-only evidence gate
fires on a ``float`` (earning its raise site a "covered" mark) while
silently accepting an ``enum``, ``tuple`` or ``dataclass`` along a path that
raises nothing at all. This instrument answers "did every constructable
refusal fire at least once", never "is the accepted domain correct" -- C1,
C2 and P21 answer that question, and this file does not substitute for them.

**Scope is discovered, not declared.** A raise site's exception class is
attempted to be patched; if CPython refuses (an immutable builtin type), the
site is reported OUT OF SCOPE, never scored as uncovered. This project has
twice reported a category of coverage as absent when it was present, or
present when it was absent (the ``ABSENT.__bool__`` pragma; the stale
"exactly one out-of-scope site" sentence) -- so every out-of-scope site here
must be a DECLARED allowlist entry with a reason, and an undeclared or
now-stale entry fails this file's own gate rather than being silently
trusted.
"""

from __future__ import annotations

import ast
import builtins
import pathlib
import sys
from typing import Dict, List, Set, Tuple

import pytest

from supwngo.schema import resolve as R

_RESOLVE_PATH = pathlib.Path(R.__file__)

#: The representative subset this instrument runs while instrumented.
#: Confirmed by
#: ``grep -rl "schema.resolve\\|schema import resolve\\|schema\\.mutants\\|from supwngo.schema" tests/``
#: to be exactly these two files -- the only test modules in this repository
#: that import :mod:`supwngo.schema.resolve` or :mod:`supwngo.schema.mutants`
#: at all. Running the rest of the repository's suite alongside these two
#: would add zero additional coverage of this module's raise sites while
#: adding host load and touching ``tests/test_challenges.py``, which this
#: project's working constraints forbid running here.
_REPRESENTATIVE_SUBSET: Tuple[str, ...] = (
    "tests/test_context_resolve_properties.py",
    "tests/test_context_resolve_golden.py",
)

#: C6's declared allowlist: raise sites whose exception class this
#: instrument mechanically cannot patch, keyed by the exception class NAME
#: as it appears at the raise site. Each entry carries a REASON (why it
#: cannot be instrumented) and a CONTROL -- a hand-verified test that is
#: independently known to exercise that site, or (for the CLI boundary) a
#: declared exclusion rather than a control. An allowlist entry claiming
#: unreachability without a named control is an absence assertion this
#: project has been burned by before (``transition``'s old
#: ``# pragma: no cover - P11 forbids``, deleted below because the branch it
#: named IS reachable) -- so both entries here name a concrete, checkable
#: control rather than asserting the site is fine unexamined.
_DECLARED_OUT_OF_SCOPE: Dict[str, Dict[str, str]] = {
    "TypeError": {
        "reason": "builtin, __init__ not assignable",
        "control": "tests/test_context_resolve_properties.py "
                   "prop_P12_absent_is_not_false calls bool(R.ABSENT), which "
                   "raises Absent.__bool__'s TypeError",
    },
    "SystemExit": {
        "reason": "builtin, __init__ not assignable -- also the CLI exit "
                  "path in _main(), which carries a process exit status "
                  "rather than a refusal",
        "control": "DECLARED CLI EXCLUSION -- excluded from the census by "
                  "declaration, not by a hand-verified test",
    },
}


def _raise_site_inventory() -> Tuple[int, List[Tuple[int, str]]]:
    """Every ``raise`` in resolve.py, found by parsing its CURRENT source --
    never hand-maintained, so a raise added after this file was written is
    still found and classified rather than silently missing."""
    src = _RESOLVE_PATH.read_text()
    tree = ast.parse(src, filename=str(_RESOLVE_PATH))
    bare = 0
    constructed: List[Tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Raise):
            continue
        if node.exc is None:
            bare += 1
            continue
        exc = node.exc
        name = None
        if isinstance(exc, ast.Call):
            f = exc.func
            if isinstance(f, ast.Name):
                name = f.id
            elif isinstance(f, ast.Attribute):
                name = f.attr
        elif isinstance(exc, ast.Name):
            name = exc.id
        if name is None:
            raise AssertionError(
                f"{_RESOLVE_PATH}:{node.lineno}: this instrument's AST walk "
                "could not name the raised exception -- fully mechanical "
                "means every site is classified, not silently skipped"
            )
        constructed.append((node.lineno, name))
    return bare, constructed


def _run_instrumented() -> Tuple[
    Set[int], List[Tuple[int, str]], int, Set[str], Dict[str, str]
]:
    """Patch every class this run can patch, run the representative subset
    with those patches live, restore, and return what fired.

    Scope is discovered here, in the same pass that patches: a class that
    refuses assignment (``TypeError: cannot set '__init__' ...``) is
    recorded out of scope with CPython's own message as the reason, rather
    than a second, separately-maintained guess at which classes are
    builtins.
    """
    bare, constructed = _raise_site_inventory()
    names = sorted({n for _, n in constructed})

    fired: Set[int] = set()
    originals: Dict[type, object] = {}
    out_of_scope_reason: Dict[str, str] = {}
    in_scope_names: Set[str] = set()

    for name in names:
        cls = getattr(R, name, None)
        if cls is None:
            cls = getattr(builtins, name, None)
        if cls is None:
            out_of_scope_reason[name] = (
                f"{name!r} is not resolvable as an attribute of the resolve "
                "module or of builtins"
            )
            continue

        orig_init = cls.__init__

        def _make_wrapper(orig_init=orig_init):
            def wrapper(self, *args, **kwargs):
                fired.add(sys._getframe(1).f_lineno)
                return orig_init(self, *args, **kwargs)
            return wrapper

        try:
            cls.__init__ = _make_wrapper()
        except TypeError as exc:
            out_of_scope_reason[name] = str(exc)
            continue
        originals[cls] = orig_init
        in_scope_names.add(name)

    try:
        rc = pytest.main([
            *_REPRESENTATIVE_SUBSET, "-q", "--no-header", "-p", "no:cacheprovider",
        ])
    finally:
        for cls, orig_init in originals.items():
            cls.__init__ = orig_init

    if rc != 0:
        raise AssertionError(
            f"the representative subset did not pass while instrumented "
            f"(pytest exit code {rc}); coverage measured against a red "
            "suite is not trustworthy"
        )

    return fired, constructed, bare, in_scope_names, out_of_scope_reason


def test_refusal_coverage_census(capsys) -> None:
    """Run the instrument, print the census, and gate on allowlist drift.

    Not a claim that every refusal is exercised -- that number is measured
    and printed, never asserted to be zero or any other fixed value, because
    a hardcoded target would itself be the kind of unmeasured claim this
    file exists to avoid making.
    """
    fired, constructed, bare, in_scope_names, out_of_scope_reason = _run_instrumented()

    in_scope_sites = sorted(ln_n for ln_n in constructed if ln_n[1] in in_scope_names)
    out_of_scope_sites = sorted(
        ln_n for ln_n in constructed if ln_n[1] in out_of_scope_reason
    )
    never_fired = sorted(ln_n for ln_n in in_scope_sites if ln_n[0] not in fired)

    # C6's gate: every out-of-scope site must be a DECLARED allowlist entry.
    undeclared = sorted({n for _, n in out_of_scope_sites} - set(_DECLARED_OUT_OF_SCOPE))
    assert not undeclared, (
        f"raise site(s) for {undeclared} are out of instrument scope with no "
        "declared allowlist entry -- C6 requires every out-of-scope site to "
        "be named with a reason, not merely discovered and left unlabelled"
    )
    stale = sorted(set(_DECLARED_OUT_OF_SCOPE) - {n for _, n in out_of_scope_sites})
    assert not stale, (
        f"allowlist entries {stale} no longer correspond to any out-of-scope "
        "raise site in resolve.py -- the class became patchable or the site "
        "was removed, and this allowlist is stale (the same stale-claim "
        "defect §6 records against this project's own review twice already)"
    )
    assert in_scope_sites, (
        "no in-scope raise sites were found -- the AST walk or the scope "
        "classifier is broken, not that resolve.py stopped raising anything"
    )

    n_in_scope = len(in_scope_sites)
    n_never_fired = len(never_fired)
    n_fired_once = n_in_scope - n_never_fired
    controls = sum(
        1 for entry in _DECLARED_OUT_OF_SCOPE.values()
        if not entry["control"].startswith("DECLARED CLI")
    )

    with capsys.disabled():
        lines = [
            "",
            "REFUSAL-SITE CONTROL COVERAGE -- NOT a proof of accepted-domain "
            "closure",
            "(control coverage only: a covered site proves it CAN raise, "
            "never that every value it should refuse actually reaches it)",
            f"representative subset: {', '.join(_REPRESENTATIVE_SUBSET)}",
            f"constructed-exception raise sites:            {len(constructed)}",
            f"bare re-raise sites (exempt):                  {bare}",
            f"in instrument scope (module error classes):   {n_in_scope}",
            f"out of instrument scope (UN-INSTRUMENTABLE):    {len(out_of_scope_sites)}",
        ]
        for ln, name in out_of_scope_sites:
            entry = _DECLARED_OUT_OF_SCOPE[name]
            lines.append(f"    L{ln}   {name:<12} -- {entry['reason']}")
            lines.append(f"        control: {entry['control']}")
        lines.append(
            f"NEVER FIRED by the representative subset:      "
            f"{n_never_fired} / {n_in_scope}   (measured THIS run, not "
            "re-quoted)"
        )
        lines.append(
            f"fired at least once (positive-control coverage): "
            f"{n_fired_once} / {n_in_scope}   (measured THIS run, not "
            "re-quoted)"
        )
        lines.append(
            f"allowlist reasons declared: {len(_DECLARED_OUT_OF_SCOPE)}"
            f"   allowlist entries with a hand-verified control: {controls}"
        )
        if never_fired:
            lines.append("never-fired sites (line, exception class):")
            for ln, name in never_fired:
                lines.append(f"    L{ln}  {name}")
        print("\n".join(lines))
