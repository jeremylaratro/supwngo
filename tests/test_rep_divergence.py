"""Mutation tests for benchmark/rep_divergence.py -- prove the gate can go RED.

This project has repeatedly shipped validations that could only ever pass, every one
of them asserting the ABSENCE of something. `rep_divergence.py` asserts the absence of
cross-rep divergence, which puts it squarely in that family, so a green result from it
is worthless until the red path is demonstrated.

These tests therefore do not check that identical reps pass. They check that:

  * a functional difference between reps is reported DIVERGENT and exits 1,
  * an address-only difference is NOT reported divergent (the ASLR normaliser does its
    job and does not manufacture a finding),
  * a small constant differing between reps IS still caught -- i.e. the normaliser is
    narrow enough not to sand away a changed offset, which is the exact signal the
    tool exists to see,
  * too few archived reps yields CANNOT DETERMINE rather than a silent pass.

The third case is the one that matters most: an over-broad normaliser would turn this
tool into another validation that cannot fail.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "benchmark" / "rep_divergence.py"


def _fixture(tmp_path: Path, per_rep: dict[str, list[str]], reps: int) -> Path:
    """Build a results dir. `per_rep[slug]` is the script text for each rep."""
    slugs = sorted(per_rep)
    results = ",\n".join(
        f'  {{"slug": "{s}", "status": "FAILED"}}' for s in slugs
    )
    (tmp_path / "report.json").write_text(
        '{"reps": %d, "results": [\n%s\n]}' % (reps, results)
    )
    for rep in range(1, reps + 1):
        d = tmp_path / f"rep{rep}"
        d.mkdir(exist_ok=True)
        for slug, texts in per_rep.items():
            if rep - 1 < len(texts):
                (d / f"{slug}_generated.py").write_text(texts[rep - 1])
    return tmp_path


def _run(results_dir: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOL), str(results_dir)],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout


def test_functional_divergence_is_caught_and_exits_nonzero(tmp_path):
    """The RED path. A differing NOP-sled size across reps is the truncation shape."""
    d = _fixture(tmp_path, {
        "t_diverge": [
            "offset = 0  # TODO\nsled = 8\n",
            "offset = 0  # TODO\nsled = 16\n",
            "offset = 0  # TODO\nsled = 24\n",
        ],
    }, reps=3)
    rc, out = _run(d)
    assert "DIVERGENT" in out, out
    assert rc == 1, f"divergence must exit 1, got {rc}\n{out}"


def test_address_only_difference_is_not_divergent(tmp_path):
    """ASLR in a comment is environmental, not a truncation signal."""
    d = _fixture(tmp_path, {
        "t_aslr": [
            '# Leaked addresses: {"stack": 140732459705408}\noffset = 0  # TODO\n',
            '# Leaked addresses: {"stack": 140726508893760}\noffset = 0  # TODO\n',
            '# Leaked addresses: {"stack": 140737488347136}\noffset = 0  # TODO\n',
        ],
    }, reps=3)
    rc, out = _run(d)
    assert "identical modulo ASLR" in out, out
    assert "DIVERGENT      : 0" in out, out
    assert rc == 0, out


def test_normaliser_does_not_sand_away_a_changed_offset(tmp_path):
    """The narrowness check. A SMALL differing constant must still be caught.

    If the address normaliser were written broadly (e.g. stripping all digits), a
    changed exploit offset would vanish and the tool would become another validation
    that cannot fail. 4 / 12 / 20 are offset-sized, not address-sized.
    """
    d = _fixture(tmp_path, {
        "t_small_const": [
            "offset = 4\n", "offset = 12\n", "offset = 20\n",
        ],
    }, reps=3)
    rc, out = _run(d)
    assert "DIVERGENT" in out, f"small-constant divergence was sanded away:\n{out}"
    assert rc == 1, out


def test_insufficient_reps_reports_cannot_determine(tmp_path):
    """Absence of evidence must not read as evidence of determinism."""
    d = _fixture(tmp_path, {"t_one": ["only one rep\n"]}, reps=3)
    rc, out = _run(d)
    assert "CANNOT DETERMINE" in out, out
    assert "undetermined   : 1" in out, out
    assert rc == 0, out


def test_missing_report_json_fails_loudly(tmp_path):
    """Fail closed on a malformed results dir rather than reporting 0 divergent."""
    rc, _ = _run(tmp_path)
    assert rc == 2, "a missing report.json must exit 2, not pass"
