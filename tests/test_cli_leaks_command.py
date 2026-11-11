"""RT-01 regression: the ``supwngo leaks`` command was fully broken.

The handler called ``finder.analyze()``, ``finder.get_fingerprint_strategy()``
and ``finder.build_leak_chain()`` -- none of which exist on the static
``vulns.leak_finder.LeakFinder``. The real entry point is ``find_all_leaks()``
(which also populates ``finder.chains``), with ``get_best_leak_for`` and
``fingerprint_libc`` as the supporting API. Every ``leaks`` invocation raised
``AttributeError`` and printed nothing (the retest saw EMPTY on 7/7 targets).

These tests drive the real ``CliRunner`` so they fail if the command is broken
(a direct ``LeakFinder`` call would pass even with the CLI wiring broken, which
is exactly the defect). They assert content, not mere parseability: the JSON
counts must equal a direct analyzer call, and all three modes (default,
``--fingerprint``, ``--chain``) must run.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from supwngo.cli import cli

GCC_AVAILABLE = shutil.which("gcc") is not None

# printf(buf) gives a format-string leak; puts in the PLT/GOT gives a GOT leak;
# dynamic (not -static) so there is a GOT to leak from.
SOURCE = """
#include <stdio.h>
#include <unistd.h>
int main(void) {
    char buf[64];
    puts("ready");
    read(0, buf, 256);
    printf(buf);
    return 0;
}
"""


@pytest.fixture(scope="module")
def target(tmp_path_factory) -> Path:
    if not GCC_AVAILABLE:
        pytest.skip("gcc not on PATH")
    d = tmp_path_factory.mktemp("leaks_target")
    src = d / "target.c"
    src.write_text(SOURCE)
    out = d / "target"
    subprocess.run(
        ["gcc", "-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0",
         "-no-pie", str(src), "-o", str(out)],
        check=True,
        capture_output=True,
    )
    return out


def _direct_leak_count(path: Path) -> int:
    from supwngo.core.binary import Binary
    from supwngo.vulns.leak_finder import LeakFinder

    finder = LeakFinder(Binary.load(str(path)))
    return len(finder.find_all_leaks())


def test_leaks_json_runs_and_counts_match_analyzer(target):
    """Default mode, measured at the file-descriptor level (as the retest matrix
    does): real stdout is exactly one JSON document and ``total`` equals a direct
    ``LeakFinder.find_all_leaks()`` call on the same binary.

    A subprocess is used rather than ``CliRunner`` because the command's human
    output is routed to stderr in --json mode, and ``CliRunner`` merges stderr
    into its captured stdout -- which would mask the very contamination this
    guards against."""
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "supwngo.cli", "leaks", str(target), "--json"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(Path(__file__).parent.parent),
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr[-300:])
    out = proc.stdout.strip()
    assert "[ERROR]" not in proc.stdout

    data = json.loads(out)  # exactly one JSON document
    assert "error" not in data
    assert data["total"] == _direct_leak_count(target)
    assert isinstance(data["by_type"], dict)


def test_leaks_finds_something_on_fmtstr_target(target):
    """A printf(buf) + puts target must yield at least one leak opportunity, so
    the count assertion above is not vacuously comparing 0 == 0."""
    assert _direct_leak_count(target) > 0


def test_leaks_fingerprint_mode_runs(target):
    """``--fingerprint`` used to call the nonexistent
    ``get_fingerprint_strategy``; it must now run cleanly."""
    result = CliRunner().invoke(cli, ["leaks", str(target), "--fingerprint"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "has no attribute" not in result.output
    assert "Libc Fingerprinting Info" in result.output


def test_leaks_chain_mode_runs(target):
    """``--chain`` used to call the nonexistent ``build_leak_chain``; it must now
    serialize ``finder.chains`` instead."""
    result = CliRunner().invoke(cli, ["leaks", str(target), "--chain"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert "has no attribute" not in result.output
