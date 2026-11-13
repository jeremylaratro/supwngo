"""
Process runner with typed results, plus survivor helpers.

``run`` executes one command in its own session and reports what happened as a
:class:`ProcState` instead of raising or collapsing every failure into a return
code. The survivor helpers let a long-lived harness find and kill descendants
that outlived a command (double-forks, ``setsid()`` daemons) by making itself a
child subreaper. This module uses the standard library only.
"""

from __future__ import annotations

import ctypes
import enum
import os
import signal as _signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Mapping, Optional, Sequence

# prctl(2) option from <linux/prctl.h>.
_PR_SET_CHILD_SUBREAPER = 36

# Longest a post-kill drain waits for the pipes before giving up on them.
_DRAIN_TIMEOUT_S = 5.0


class ProcState(enum.Enum):
    """How a command ended."""

    EXITED = "exited"
    SIGNALED = "signaled"
    TIMEOUT = "timeout"
    SPAWN_ERROR = "spawn_error"


@dataclass
class ProcResult:
    """Outcome of one command.

    ``rc`` is set only for ``EXITED`` and ``signal`` only for ``SIGNALED``;
    ``errno`` only for ``SPAWN_ERROR``. ``isolation`` and ``hide_absent`` are
    filled in by ``sandbox.run``.
    """

    state: ProcState
    rc: Optional[int] = None
    signal: Optional[int] = None
    errno: Optional[int] = None
    stdout: bytes = b""
    stderr: bytes = b""
    pid: Optional[int] = None
    wall_s: float = 0.0
    isolation: str = "none"
    hide_absent: List[str] = field(default_factory=list)


def _killpg(pgid: int) -> None:
    try:
        os.killpg(pgid, _signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _drain(proc: "subprocess.Popen[bytes]"):
    """Reap ``proc`` and collect its output after the group was killed."""
    try:
        return proc.communicate(timeout=_DRAIN_TIMEOUT_S)
    except subprocess.TimeoutExpired as exc:
        # A descendant that left the group still holds the pipes open. Take
        # what was read so far; the harness's survivor scan deals with it.
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()
        proc.wait()
        return exc.stdout or b"", exc.stderr or b""


def run(
    argv: Sequence[str],
    *,
    input: Optional[bytes] = None,
    cwd: str,
    env: Optional[Mapping[str, str]] = None,
    timeout: float,
) -> ProcResult:
    """Run ``argv`` in a new session and return a typed result.

    On timeout the whole process group is sent SIGKILL and reaped, and the
    state is ``TIMEOUT``. A failure to spawn (missing binary, bad ``cwd``,
    permissions) is ``SPAWN_ERROR`` with ``errno`` set; this function never
    raises for either.
    """
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=None if env is None else dict(env),
            start_new_session=True,
        )
    except OSError as exc:
        return ProcResult(
            ProcState.SPAWN_ERROR,
            errno=exc.errno,
            wall_s=time.monotonic() - started,
        )

    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _killpg(proc.pid)
        stdout, stderr = _drain(proc)
        return ProcResult(
            ProcState.TIMEOUT,
            stdout=stdout,
            stderr=stderr,
            pid=proc.pid,
            wall_s=time.monotonic() - started,
        )

    wall_s = time.monotonic() - started
    if proc.returncode < 0:
        return ProcResult(
            ProcState.SIGNALED,
            signal=-proc.returncode,
            stdout=stdout,
            stderr=stderr,
            pid=proc.pid,
            wall_s=wall_s,
        )
    return ProcResult(
        ProcState.EXITED,
        rc=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        pid=proc.pid,
        wall_s=wall_s,
    )


def become_subreaper() -> bool:
    """Make this process a child subreaper; True if the kernel accepted it.

    Orphaned descendants, including ones that called ``setsid()`` or
    double-forked, are then re-parented to this process instead of init.
    """
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        args = [ctypes.c_int(_PR_SET_CHILD_SUBREAPER)]
        args += [ctypes.c_ulong(v) for v in (1, 0, 0, 0)]
        return libc.prctl(*args) == 0
    except (OSError, AttributeError):
        return False


def adopted_children(exclude: Iterable[int] = ()) -> List[int]:
    """PIDs whose parent is this process, other than those in ``exclude``.

    Zombies are included. ``/proc/<pid>/stat`` is ``pid (comm) state ppid ...``
    and ``comm`` may hold spaces and parentheses, so the fields are parsed after
    the last ``)``.
    """
    skip = set(exclude)
    me = os.getpid()
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) in skip:
            continue
        try:
            with open("/proc/%s/stat" % name, "rb") as fh:
                data = fh.read().decode("ascii", "replace")
        except OSError:
            continue  # exited between listdir and open
        fields = data[data.rindex(")") + 2 :].split()
        if len(fields) > 1 and int(fields[1]) == me:
            found.append(int(name))
    return sorted(found)


def reap_survivors(exclude: Iterable[int] = (), *, grace_s: float = 10.0) -> List[int]:
    """Kill and reap every adopted child; return all PIDs that were found.

    Repeats until a scan finds nothing, because killing an intermediate process
    can orphan more descendants to this process. ``ESRCH`` and ``ECHILD`` races
    are tolerated. Gives up after ``grace_s`` seconds so an unkillable process
    cannot hang the caller.
    """
    seen: List[int] = []
    deadline = time.monotonic() + grace_s
    while time.monotonic() < deadline:
        pids = adopted_children(exclude)
        if not pids:
            break
        for pid in pids:
            if pid not in seen:
                seen.append(pid)
            try:
                os.kill(pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        time.sleep(0.01)
    return seen
