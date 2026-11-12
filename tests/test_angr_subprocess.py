"""S4b-i: the budgeted angr subprocess primitive must be killable (RT-05).

``analysis/_angr_subprocess.run_angr_op`` runs an angr op in a *spawned* child
and, on timeout, kills the child's whole process group so a C-level CFGFast hang
(and any descendant angr spawned) is truly cancelled -- the thing an in-process
watchdog cannot do.

These tests exercise the primitive's *machinery* through its ``_selftest`` hook,
so they need no angr and no gitignored target: they are fully deterministic and
run in a couple of seconds. The budget path is proven by making a child that
records its own PID and a deliberately-spawned grandchild's PID, then blocks
forever; after the budget fires we assert *both* are gone -- i.e. the group was
reaped, not just the direct child.

Each test carries a hard ``@pytest.mark.timeout`` safety net (pytest-timeout is
a dev dependency) so a regression that reintroduces a hang fails the test
instead of wedging the suite.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

import pytest

from supwngo.analysis._angr_subprocess import (
    AnalysisBudgetExceeded,
    AngrSubprocessError,
    DEFAULT_ANGR_TIMEOUT,
    run_angr_op,
)

# _selftest ignores the binary path; any existing file is fine.
DUMMY = "/bin/true" if os.path.exists("/bin/true") else os.path.abspath(__file__)


def _alive(pid: int) -> bool:
    """True if ``pid`` is a live (non-zombie-reaped) process."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:  # exists but not ours
        return True


def _wait_dead(pids, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and any(_alive(p) for p in pids):
        time.sleep(0.05)


def test_default_timeout_is_a_sane_reserve_under_the_harness():
    # The retest harness cuts each command at ~60s; the default must leave room
    # for spawn + angr import + reap + the capstone/symbol fallback + output.
    assert 0 < DEFAULT_ANGR_TIMEOUT <= 45


def test_echo_roundtrips_through_the_pickle_handoff():
    out = run_angr_op(DUMMY, "_selftest", 10, mode="echo", alpha="1", beta="two")
    assert out == {"mode": "echo", "alpha": "1", "beta": "two"} or out == {
        "alpha": "1",
        "beta": "two",
    }


def test_child_error_surfaces_as_subprocess_error_not_a_hang():
    with pytest.raises(AngrSubprocessError) as ei:
        run_angr_op(DUMMY, "_selftest", 10, mode="raise")
    assert "RuntimeError" in str(ei.value)


def test_unknown_op_surfaces_as_subprocess_error():
    with pytest.raises(AngrSubprocessError):
        run_angr_op(DUMMY, "no_such_op", 10)


@pytest.mark.parametrize("bad", [0, -1, -0.5, float("nan"), float("inf"), "abc", None])
def test_invalid_budget_rejected_at_the_boundary(bad):
    with pytest.raises(ValueError):
        run_angr_op(DUMMY, "_selftest", bad, mode="echo")


@pytest.mark.timeout(30)
def test_budget_exceeded_kills_child_and_its_descendants(tmp_path):
    """The core RT-05 guarantee: a hung op is killed, group and all."""
    sentinel = tmp_path / f"sentinel-{uuid.uuid4().hex}.txt"

    start = time.monotonic()
    with pytest.raises(AnalysisBudgetExceeded) as ei:
        run_angr_op(DUMMY, "_selftest", 3, mode="sleep", sentinel_path=str(sentinel))
    elapsed = time.monotonic() - start

    # The budget actually bounded the call (not the 600s the child would sleep).
    assert elapsed < 15, f"timeout path took {elapsed:.1f}s for a 3s budget"
    assert "exceeded" in str(ei.value)

    # The child wrote both PIDs before blocking; both must now be gone, proving
    # the whole session group was reaped -- not merely the direct child.
    assert sentinel.exists(), "child never reached the handshake (test setup problem)"
    child_pid, grandchild_pid = (int(x) for x in sentinel.read_text().split())
    _wait_dead([child_pid, grandchild_pid], timeout=8)
    assert not _alive(child_pid), f"child {child_pid} survived the budget kill"
    assert not _alive(grandchild_pid), (
        f"grandchild {grandchild_pid} survived -- the process group was not reaped "
        "(a leaked angr descendant would keep mutating the kb: the RT-05 failure)"
    )


@pytest.mark.timeout(20)
def test_timeout_leaves_no_temp_files_behind(tmp_path, monkeypatch):
    """The parent-created handoff temp file is unlinked on every exit path."""
    import tempfile

    staging = tmp_path / "tmp"
    staging.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(staging))

    before = set(staging.iterdir())
    with pytest.raises(AnalysisBudgetExceeded):
        run_angr_op(DUMMY, "_selftest", 2, mode="sleep",
                    sentinel_path=str(tmp_path / "s.txt"))
    # Give the finally-clause unlink a beat, then assert nothing leaked.
    time.sleep(0.2)
    leaked = [p for p in staging.iterdir() if p.name.startswith("supwngo-angr-")]
    assert leaked == [], f"leaked handoff temp files: {leaked}"
