"""Guard: tests must run the checkout's CLI, never the installed ``supwngo`` script.

``shutil.which("supwngo")`` resolves to whatever editable install happens to be
first on ``PATH`` (on this host, one under ``/usr/bin/python3``), which can be a
different tree from the one under test. Tests build their command as
``[sys.executable, "-m", "supwngo.cli"]`` instead, so the interpreter running
pytest imports the checkout (plan §8.1 V-3).

The check parses each test file with ``ast`` rather than grepping, so quoting
style and surrounding whitespace do not matter, and a mention in a comment or
docstring does not trip it.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS_DIR = Path(__file__).parent


def _which_supwngo_lines(source: str) -> list[int]:
    """Line numbers of ``which("supwngo")`` / ``shutil.which("supwngo")`` calls."""
    hits: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name != "which":
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        if any(isinstance(a, ast.Constant) and a.value == "supwngo" for a in args):
            hits.append(node.lineno)
    return hits


def test_detector_flags_which_supwngo_in_every_spelling():
    # The guard is only worth having if it can fail.
    assert _which_supwngo_lines('import shutil\nx = shutil.which("supwngo")\n') == [2]
    assert _which_supwngo_lines("from shutil import which\nwhich('supwngo')\n") == [2]
    assert _which_supwngo_lines('import shutil\nshutil.which(cmd="supwngo")\n') == [2]


def test_detector_ignores_other_executables_and_mentions():
    assert _which_supwngo_lines('import shutil\nshutil.which("gcc")\n') == []
    assert _which_supwngo_lines('# shutil.which("supwngo")\nx = "supwngo"\n') == []


def test_no_test_resolves_the_cli_with_which():
    offenders: list[str] = []
    for path in sorted(TESTS_DIR.rglob("*.py")):
        for line in _which_supwngo_lines(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(TESTS_DIR.parent)}:{line}")
    assert not offenders, (
        'tests must use [sys.executable, "-m", "supwngo.cli"], not '
        'which("supwngo"): ' + ", ".join(offenders)
    )
