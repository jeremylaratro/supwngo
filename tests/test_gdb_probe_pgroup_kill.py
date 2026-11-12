"""S4b-ii: the gdb offset probe must reap gdb's whole process group on timeout.

``probe_offset_with_gdb`` runs the target under ``gdb -batch``. gdb launches the
target as its own inferior, and that inferior can fork further descendants. On
the pre-fix tree the probe used ``subprocess.run(timeout=...)``, whose POSIX
timeout path kills only the *direct* child (gdb); any surviving descendant in
gdb's process group is left holding gdb's stdout pipe, and the probe's budget
never effectively takes hold -- the ``ancient_interface`` / ``auth-or-out``
``explain`` hang (RT-04 residual, verified: both went rc=124 -> rc=0 after this
fix on the gitignored HTB targets).

The fix spawns gdb with ``start_new_session=True`` and, on timeout, SIGKILLs the
whole process group (``_kill_process_group``) instead of only gdb.

Mechanism RED proof (deterministic, no real gdb): a fake ``gdb`` on ``PATH``
backgrounds a uniquely-named sleeper that stays in gdb's process group, then
blocks so the probe's ``communicate`` times out. The real ``gdb`` is unsuitable
as a fixture here because it reparents its inferior into gdb's *own* job-control
group, which varies by build; a plain shell keeps the descendant in the spawned
group, isolating exactly the behaviour the fix changes.

* Pre-fix (``subprocess.run``): the timeout kills only gdb, so the sleeper
  survives -> this test's "no descendant survived" assertion fails (RED).
* Post-fix (``killpg``): the sleeper is reaped -> GREEN, and the probe returns
  at its budget.
"""

import os
import signal
import subprocess
import time
import uuid
from pathlib import Path

import pytest


def _marker_duration() -> str:
    """A unique, bounded sleep duration (~30 s) usable as a pgrep needle."""
    return f"30.{uuid.uuid4().int % 10**8:08d}"


def _alive(marker: str) -> list[int]:
    r = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    me = os.getpid()
    return [int(p) for p in r.stdout.split() if p.strip() and int(p) != me]


def _write_fake_gdb(path: Path, marker: str) -> None:
    # Backgrounds a sleeper that stays in gdb's process group (no setsid), then
    # blocks so the caller's communicate() times out. Ignores all gdb args.
    path.write_text(
        "#!/bin/sh\n"
        f"sleep {marker} &\n"
        "sleep 30\n"
    )
    path.chmod(0o755)


@pytest.mark.timeout(30)
def test_gdb_probe_reaps_process_group_on_timeout(tmp_path, monkeypatch):
    if not os.path.exists("/bin/sh"):
        pytest.skip("POSIX /bin/sh required for the fake-gdb fixture")
    from supwngo.exploit.walkthrough import facts

    marker = _marker_duration()
    gdb = tmp_path / "gdb"
    _write_fake_gdb(gdb, marker)

    # Non-vacuity guard: confirm the fake gdb really spawns a detectable sleeper
    # in its own group. If the environment cannot background it, skip rather than
    # pass trivially. Clean the sanity group up via a group kill.
    sanity = subprocess.Popen([str(gdb)], start_new_session=True)
    try:
        time.sleep(0.6)
        spawned = _alive(marker)
        if not spawned:
            pytest.skip("fake-gdb fixture did not spawn a detectable sleeper")
    finally:
        try:
            os.killpg(os.getpgid(sanity.pid), signal.SIGKILL)
        except OSError:
            sanity.kill()
        try:
            sanity.wait(timeout=5)
        except Exception:
            pass
    time.sleep(0.3)

    # Route the probe's bare "gdb" to our fake via PATH.
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))

    dummy = tmp_path / "target"
    dummy.write_bytes(b"\x7fELF" + b"\x00" * 60)

    before = _alive(marker)
    start = time.monotonic()
    result = facts.probe_offset_with_gdb(str(dummy), timeout=2)
    elapsed = time.monotonic() - start
    time.sleep(0.4)
    after = _alive(marker)

    leaked = [p for p in after if p not in before]
    # Always clean up anything we leaked so a failing run strands nothing.
    for p in leaked:
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass

    assert leaked == [], (
        "gdb-probe timeout left a descendant alive in gdb's process group "
        f"({leaked}); the whole group was not reaped (the explain hang)"
    )
    # The 2 s budget holds: a correct implementation returns shortly after it,
    # not after the inferior's own ~30 s sleep.
    assert elapsed < 8.0, (
        f"gdb probe took {elapsed:.1f}s for a 2s budget -- the timeout did not "
        "take effect"
    )
    # No crash signal from the fake gdb -> inconclusive, not a fabricated offset.
    assert result is None
