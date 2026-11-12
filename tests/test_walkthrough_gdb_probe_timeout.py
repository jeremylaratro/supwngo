"""S4b-iii: the generated walkthrough's offset step must survive a gdb hang.

``explain`` renders a standalone walkthrough script whose ``offset`` step drives
the target under ``gdb -batch`` to measure the saved-return offset. On the
pre-fix tree that step used ``subprocess.run(argv, timeout=60)`` with a
*hard-coded* budget and no handling for ``TimeoutExpired``:

* when gdb (or its inferior) hangs, the step crashed the whole walkthrough with
  an uncaught ``subprocess.TimeoutExpired`` traceback -- the user ran a teaching
  script and got a Python stack trace, not a diagnosis; and
* the POSIX timeout path reaped only the *direct* child, leaving gdb's inferior
  (and any descendant it forked) alive in gdb's process group -- the second
  surface of the ``explain`` hang (RT-04).

The fix (``exploit/walkthrough/common.py`` ``offset_step``) spawns gdb with
``start_new_session=True``, honours a ``SUPWNGO_WALKTHROUGH_GDB_TIMEOUT`` budget,
and on timeout SIGKILLs the whole process group then returns a graceful failure.

This test renders a real ret2win walkthrough and runs *only* its offset step
with a fake ``gdb`` on ``PATH`` that backgrounds a uniquely-named sleeper (kept
in gdb's process group, stdio detached so it holds no pipe) and then blocks, so
the probe's budget is forced to fire.

RED proof (pre-fix ``common.py``, verified manually 2026-11-12): the base render
ignores the env budget, waits its hard-coded 60 s, then exits with an uncaught
``TimeoutExpired`` traceback and leaves the sleeper alive -- both the
"no traceback" and "no leaked descendant" assertions below fail. Post-fix: the
step honours the 2 s budget, reaps the group, prints a graceful failure, and
leaks nothing (GREEN, ~3 s).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import textwrap
import time
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from supwngo.cli import cli

GCC_AVAILABLE = shutil.which("gcc") is not None

#: A ret2win target: one overflowing read() and a function worth reaching. The
#: rendered walkthrough always includes an ``offset`` step for a target like
#: this, which is the step under test.
VULN_SOURCE = textwrap.dedent(
    """
    #include <stdio.h>
    #include <unistd.h>

    void win(void) {
        puts("WIN REACHED");
        fflush(stdout);
    }

    void vuln(void) {
        char buf[32];
        printf("Input: ");
        fflush(stdout);
        read(0, buf, 256);
    }

    int main(void) {
        setvbuf(stdout, NULL, _IONBF, 0);
        vuln();
        return 0;
    }
    """
)


def _marker_duration() -> str:
    """A unique, bounded sleep duration usable as a pgrep needle.

    Long enough (~600 s) that a *leaked* sleeper clearly outlives the probe;
    the test SIGKILLs it in cleanup regardless.
    """
    return f"600.{uuid.uuid4().int % 10**8:08d}"


def _alive(marker: str) -> list[int]:
    """PIDs of bare ``sleep <marker>`` processes (never shell lines)."""
    out = []
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            cmdline = (pid_dir / "cmdline").read_bytes().split(b"\x00")
        except OSError:
            continue
        argv = [c.decode("utf-8", "replace") for c in cmdline if c]
        if argv[:1] == ["sleep"] and marker in argv:
            out.append(int(pid_dir.name))
    return out


def _write_fake_gdb(path: Path, marker: str) -> None:
    # Backgrounds a sleeper that stays in gdb's process group (no setsid) but
    # detaches its stdio so it holds no pipe, then blocks so the caller's probe
    # times out. Ignores all gdb args.
    path.write_text(
        "#!/bin/sh\n"
        f"sleep {marker} >/dev/null 2>&1 </dev/null &\n"
        "sleep 120\n"
    )
    path.chmod(0o755)


@pytest.fixture(scope="module")
def compiled_target(tmp_path_factory):
    if not GCC_AVAILABLE:
        pytest.skip("gcc not available")
    workdir = tmp_path_factory.mktemp("wt-gdb-timeout")
    source = workdir / "vuln.c"
    source.write_text(VULN_SOURCE)
    binary = workdir / "vuln"
    result = subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-z", "noexecstack",
         "-o", str(binary), str(source)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:  # pragma: no cover - toolchain problem
        pytest.skip(f"gcc could not build the fixture: {result.stderr}")
    return binary


def _render_walkthrough(target: Path, out: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["explain", str(target), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()


def _offset_step_index(script: Path) -> int:
    """Discover the offset step's number from the script's own ``steps`` list.

    The index is not hard-coded: it shifts with which facts a target yields, so
    we parse it at runtime to keep the test robust to walkthrough changes.
    """
    listing = subprocess.run(
        ["python3", str(script), "steps"],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    for line in listing.stdout.splitlines():
        m = re.match(r"\s*(\d+)\s+offset\b", line)
        if m:
            return int(m.group(1))
    raise AssertionError(
        f"no 'offset' step in walkthrough steps:\n{listing.stdout}\n{listing.stderr}"
    )


@pytest.mark.skipif(not GCC_AVAILABLE, reason="gcc not available")
@pytest.mark.timeout(90)
def test_offset_step_degrades_gracefully_when_gdb_hangs(compiled_target, tmp_path):
    if not os.path.exists("/bin/sh"):
        pytest.skip("POSIX /bin/sh required for the fake-gdb fixture")

    script = tmp_path / "wt.py"
    _render_walkthrough(compiled_target, script)
    offset_idx = _offset_step_index(script)

    marker = _marker_duration()
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    _write_fake_gdb(fakebin / "gdb", marker)

    # Non-vacuity guard: confirm the fake gdb really spawns a detectable sleeper
    # in its own group. If the environment cannot background it, skip rather than
    # pass trivially; clean the sanity group up via a group kill.
    sanity = subprocess.Popen([str(fakebin / "gdb")], start_new_session=True)
    try:
        time.sleep(0.6)
        if not _alive(marker):
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

    env = {
        **os.environ,
        "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
        "SUPWNGO_WALKTHROUGH_GDB_TIMEOUT": "2",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    before = _alive(marker)
    start = time.monotonic()
    # Safety net only: a correct offset step returns at its 2 s budget, well
    # under this. (Pre-fix it would run its own hard-coded 60 s wait.)
    proc = subprocess.run(
        ["python3", str(script), str(offset_idx)],
        capture_output=True, text=True, timeout=45, env=env,
    )
    elapsed = time.monotonic() - start
    time.sleep(0.4)
    leaked = [p for p in _alive(marker) if p not in before]
    for p in leaked:  # never strand a sleeper, even on a failing run
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass

    output = proc.stdout + proc.stderr
    assert "Traceback" not in output, (
        "the offset step crashed with a Python traceback instead of degrading "
        f"gracefully on a gdb hang:\n{output[-2000:]}"
    )
    assert leaked == [], (
        f"the offset step left a descendant alive in gdb's process group ({leaked}); "
        "the whole group was not reaped (the explain hang)"
    )
    assert "did not finish within" in output, (
        f"expected a graceful gdb-timeout diagnosis; got:\n{output[-2000:]}"
    )
    assert elapsed < 20.0, (
        f"offset step took {elapsed:.1f}s for a 2s budget -- the env timeout did "
        "not take effect"
    )
