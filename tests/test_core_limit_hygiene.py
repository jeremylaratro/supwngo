"""The suite runs with a soft ``RLIMIT_CORE`` of 0; children can opt back in.

``conftest.py`` zeroes the soft core limit at import so crash fixtures stop
leaving ``core.<pid>`` files behind (plan §8.1 V-4). Only the *soft* limit is
lowered, so a child that explicitly raises its own limit -- which is what
pwntools' ``process`` does for ``p.corefile`` -- can still dump. These tests
pin both halves.
"""

from __future__ import annotations

import resource
import subprocess
import sys
from pathlib import Path

import pytest

_PRINT_SOFT = "import resource; print(resource.getrlimit(resource.RLIMIT_CORE)[0])"
_ABORT = "import os; os.abort()"


def _raise_soft_core_limit_to_hard() -> None:
    """``preexec_fn`` for a child that opts in to core dumps."""
    _soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (hard, hard))


def _hard_limit() -> int:
    return resource.getrlimit(resource.RLIMIT_CORE)[1]


def _core_pattern_is_a_plain_file() -> bool:
    try:
        pattern = Path("/proc/sys/kernel/core_pattern").read_text().strip()
    except OSError:
        return False
    return bool(pattern) and not pattern.startswith("|")


needs_raisable_limit = pytest.mark.skipif(
    _hard_limit() == 0, reason="hard RLIMIT_CORE is 0; a child cannot opt in"
)


def _run(code: str, cwd: Path, *, opt_in: bool) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=cwd,
        preexec_fn=_raise_soft_core_limit_to_hard if opt_in else None,
    )


def test_pytest_process_has_zero_soft_core_limit():
    soft, _hard = resource.getrlimit(resource.RLIMIT_CORE)
    assert soft == 0


def test_child_inherits_the_zero_soft_limit(tmp_path):
    result = _run(_PRINT_SOFT, tmp_path, opt_in=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0"


@needs_raisable_limit
def test_child_can_opt_in_by_raising_its_own_soft_limit(tmp_path):
    result = _run(_PRINT_SOFT, tmp_path, opt_in=True)
    assert result.returncode == 0, result.stderr
    soft = int(result.stdout.strip())
    assert soft != 0
    assert soft == _hard_limit()


@needs_raisable_limit
@pytest.mark.skipif(
    not _core_pattern_is_a_plain_file(),
    reason="kernel.core_pattern pipes to a handler; no core file to look for",
)
def test_opted_in_child_dumps_a_core_and_a_default_child_does_not(tmp_path):
    quiet = tmp_path / "default"
    loud = tmp_path / "opted_in"
    quiet.mkdir()
    loud.mkdir()

    _run(_ABORT, quiet, opt_in=False)
    _run(_ABORT, loud, opt_in=True)

    try:
        assert not list(quiet.glob("core*")), "default child dumped a core"
        assert list(loud.glob("core*")), "opted-in child produced no core"
    finally:
        for core in tmp_path.rglob("core*"):
            core.unlink(missing_ok=True)
