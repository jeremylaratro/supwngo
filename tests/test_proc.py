"""Tests for supwngo.core.proc: typed process results and survivor helpers."""

import errno
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from supwngo.core import proc
from supwngo.core.proc import ProcResult, ProcState

# Generous: the host is often heavily loaded.
LONG = 30.0


def _alive(pid):
    """True while ``pid`` exists and is not a zombie awaiting reaping."""
    try:
        data = Path("/proc/%d/stat" % pid).read_text()
    except OSError:
        return False
    return data[data.rindex(")") + 2 :].split()[0] != "Z"


def _wait_gone(pid, seconds=15.0):
    deadline = time.monotonic() + seconds
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not _alive(pid)


def test_exit_zero_captures_output(tmp_path):
    res = proc.run(
        ["sh", "-c", "printf out; printf err >&2"], cwd=str(tmp_path), timeout=LONG
    )
    assert isinstance(res, ProcResult)
    assert res.state is ProcState.EXITED
    assert res.rc == 0
    assert res.signal is None and res.errno is None
    assert res.stdout == b"out" and res.stderr == b"err"
    assert res.pid and res.wall_s >= 0
    assert res.isolation == "none" and res.hide_absent == []


def test_nonzero_exit(tmp_path):
    res = proc.run(["sh", "-c", "exit 3"], cwd=str(tmp_path), timeout=LONG)
    assert res.state is ProcState.EXITED
    assert res.rc == 3


def test_signal_death(tmp_path):
    res = proc.run(["sh", "-c", "kill -SEGV $$"], cwd=str(tmp_path), timeout=LONG)
    assert res.state is ProcState.SIGNALED
    assert res.signal == signal.SIGSEGV
    assert res.rc is None


def test_stdin_input(tmp_path):
    res = proc.run(["cat"], input=b"hello\n", cwd=str(tmp_path), timeout=LONG)
    assert res.state is ProcState.EXITED
    assert res.stdout == b"hello\n"


def test_env_and_cwd_are_applied(tmp_path):
    res = proc.run(
        ["sh", "-c", 'printf "%s %s" "$PROBE" "$(pwd)"'],
        cwd=str(tmp_path),
        env={"PROBE": "x1", "PATH": os.environ["PATH"]},
        timeout=LONG,
    )
    assert res.stdout.decode() == "x1 " + os.path.realpath(str(tmp_path))


def test_timeout_kills_the_process_group(tmp_path):
    # The sleeper stays in sh's process group, so killpg must take it too.
    res = proc.run(
        ["sh", "-c", "sleep 60 & echo $!; wait"], cwd=str(tmp_path), timeout=5.0
    )
    assert res.state is ProcState.TIMEOUT
    assert res.rc is None and res.signal is None
    sleeper = int(res.stdout.split()[0])
    assert _wait_gone(res.pid), "process-group leader survived the timeout"
    assert _wait_gone(sleeper), "background sleeper survived the timeout"


def test_missing_binary_is_spawn_error(tmp_path):
    res = proc.run(["/nonexistent/supwngo-binary"], cwd=str(tmp_path), timeout=LONG)
    assert res.state is ProcState.SPAWN_ERROR
    assert res.errno == errno.ENOENT
    assert res.pid is None


def test_missing_cwd_is_spawn_error(tmp_path):
    res = proc.run(["true"], cwd=str(tmp_path / "absent"), timeout=LONG)
    assert res.state is ProcState.SPAWN_ERROR
    assert res.errno == errno.ENOENT


# The subreaper tests must not make the pytest process a subreaper, so they run
# in a child interpreter. proc.py is loaded by path to skip the heavy package
# import (pwntools) in a process that adopts children.
_CHILD = textwrap.dedent(r"""
    import importlib.util, os, sys, time

    spec = importlib.util.spec_from_file_location("proc", sys.argv[1])
    proc = importlib.util.module_from_spec(spec)
    sys.modules["proc"] = proc
    spec.loader.exec_module(proc)

    assert proc.become_subreaper(), "prctl(PR_SET_CHILD_SUBREAPER) refused"
    assert proc.adopted_children() == []

    rd, wr = os.pipe()
    middle = os.fork()
    if middle == 0:
        os.setsid()
        if os.fork() == 0:
            # comm with a space and parentheses must not break the stat parse.
            with open("/proc/self/comm", "w") as fh:
                fh.write("a) 1 (b")
            os.write(wr, b"%d\n" % os.getpid())
            time.sleep(60)
            os._exit(0)
        os._exit(0)
    os.close(wr)
    grandchild = int(os.read(rd, 32))
    os.waitpid(middle, 0)

    deadline = time.monotonic() + 20
    while grandchild not in proc.adopted_children() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert grandchild in proc.adopted_children(), "grandchild was not adopted"
    assert grandchild not in proc.adopted_children(exclude=[grandchild])

    found = proc.reap_survivors()
    assert grandchild in found, found
    assert not os.path.exists("/proc/%d" % grandchild), "survivor still present"
    assert proc.adopted_children() == []
    print("ok")
    """)


def test_subreaper_adopts_and_reaps_a_setsid_double_fork(tmp_path):
    res = subprocess.run(
        [sys.executable, "-B", "-c", _CHILD, proc.__file__],
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    assert res.returncode == 0, res.stderr.decode()
    assert res.stdout.strip() == b"ok"
