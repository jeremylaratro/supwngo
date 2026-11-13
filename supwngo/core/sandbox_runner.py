"""
Reusable sandboxed analysis runner.

``SandboxRunner`` runs one command (a target, or gdb on a target) from a fixed
working directory through :mod:`supwngo.core.sandbox` and :mod:`supwngo.core.proc`
and reports a typed :class:`~supwngo.core.proc.ProcResult`. It is the mechanism ``offset`` uses, kept
here so that any analysis step that executes a target or gdb gets the same
containment instead of a copy of it.

What a run is held to, when :attr:`SandboxRunner.isolation` is ``"bwrap"``:

- a bounded wall time: on timeout the result is ``ProcState.TIMEOUT``, never an
  exception, and the PID namespace takes every descendant with it;
- a private, writable workspace (:meth:`SandboxRunner.workspace`), a fresh
  ``/tmp/<prefix>*`` directory bound into the sandbox for scripts, patterns and
  file input, and removed when its owner leaves it. Everything else is
  read-only, apart from one exception that follows from how the sandbox
  works: its ``/tmp`` is a fresh tmpfs, so a working directory that lives under
  ``/tmp/`` is bound back, writable, to stay visible;
- no IP network (a private loopback with no host listeners);
- a private PID namespace, so no descendant outlives the command, including
  ones that called ``setsid()``.

It is not a host-confidentiality boundary: the host's files stay readable.
``sandbox.run`` can hide paths, but this runner passes none; a harness that
needs that wraps ``sandbox.run`` itself.

The isolation label is the truth about the run, decided once per runner by
:func:`plan_isolation`: ``"bwrap"`` when this process sandboxed the command,
``"outer"`` when it did not but an enclosing harness demonstrably did, and
``"none"`` otherwise (including when asked not to sandbox).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, NamedTuple, Optional, Sequence, Union

from supwngo.core import proc, sandbox
from supwngo.core.proc import ProcResult
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# ``gdb --version``. A loaded host can take far longer than a version string
# should; a probe that gave up early silently turned gdb off.
GDB_PROBE_TIMEOUT_S = 30.0

# Names the sandbox may not see: it replaces these with fresh mounts.
_UNBINDABLE_ROOTS = ("/dev", "/proc")


def outer_sandbox() -> bool:
    """True when an enclosing harness says it sandboxes this process, and it does.

    Both must hold: ``SUPWNGO_OUTER_SANDBOX=1`` and a PID namespace different
    from the host's, whose ``/proc/self/ns/pid`` value the harness passes in
    ``SUPWNGO_HOST_PIDNS``. Either alone is just a claim.
    """
    if os.environ.get("SUPWNGO_OUTER_SANDBOX") != "1":
        return False
    host_ns = os.environ.get("SUPWNGO_HOST_PIDNS", "")
    try:
        return bool(host_ns) and os.readlink("/proc/self/ns/pid") != host_ns
    except OSError:
        return False


def sandbox_fits(directory: str) -> bool:
    """True when the sandbox can use ``directory`` as the target's working directory.

    It rejects a path with a ``.``-prefixed component, replaces ``/dev`` and
    ``/proc`` with fresh mounts, and cannot bind ``/tmp`` at its own path.
    """
    if any(part.startswith(".") for part in directory.split("/") if part):
        return False
    if directory == "/tmp":
        return False
    return not any(
        directory == root or directory.startswith(root + "/")
        for root in _UNBINDABLE_ROOTS
    )


class IsolationPlan(NamedTuple):
    """How runs from one directory are contained; unpacks as a 3-tuple.

    ``backend`` is what ``sandbox.run`` is asked for (``"bwrap"`` or ``"none"``),
    ``isolation`` is the label (``"bwrap"``, ``"outer"`` or ``"none"``) and
    ``fits`` says whether the sandbox can take the directory at all.
    """

    backend: str
    isolation: str
    fits: bool


def plan_isolation(directory: str, use_sandbox: bool = True) -> IsolationPlan:
    """Decide ``(backend, isolation label, sandbox can take the cwd)``.

    ``use_sandbox=False`` always gives the label ``"none"``. Otherwise the
    sandbox is used when ``directory`` fits and ``sandbox.available()`` (its
    self-check passed); failing that the label is ``"outer"`` when
    :func:`outer_sandbox` holds, else ``"none"``.
    """
    fits = sandbox_fits(directory)
    if not use_sandbox:
        return IsolationPlan("none", "none", fits)
    if fits and sandbox.available():
        return IsolationPlan("bwrap", "bwrap", fits)
    if not fits:
        logger.warning(
            "Cannot sandbox a target in %s (the sandbox rejects "
            "'.'-prefixed components and /dev, /proc, /tmp itself); "
            "running it unsandboxed",
            directory,
        )
    return IsolationPlan("none", "outer" if outer_sandbox() else "none", fits)


class SandboxRunner:
    """Runs commands from ``cwd`` under one isolation plan and one workspace.

    The plan is decided on first use and kept, so a runner reports one label
    for all of its runs.
    """

    def __init__(
        self,
        cwd: Union[str, "os.PathLike[str]"],
        *,
        use_sandbox: bool = True,
        workspace_prefix: str = "supwngo-run-",
    ):
        """
        Args:
            cwd: working directory of every run (normally the target's directory)
            use_sandbox: False forces the label ``"none"`` (debugging)
            workspace_prefix: name prefix of the ``/tmp`` workspace directory
        """
        self.cwd = os.fspath(cwd)
        self.use_sandbox = use_sandbox
        self.workspace_prefix = workspace_prefix
        self._plan: Optional[IsolationPlan] = None
        self._workspace: Optional[Path] = None

    @property
    def plan(self) -> IsolationPlan:
        """The isolation plan for ``cwd``, decided once."""
        if self._plan is None:
            self._plan = plan_isolation(self.cwd, self.use_sandbox)
        return self._plan

    @property
    def isolation(self) -> str:
        """``"bwrap"``, ``"outer"`` or ``"none"``: how runs are contained."""
        return self.plan.isolation

    @contextlib.contextmanager
    def workspace(self) -> Iterator[Path]:
        """The private workspace, created on first use and removed with its owner.

        Re-entrant: a nested use gets the same directory, and only the outermost
        one removes it. ``run`` uses it too, so it is bound for every run.
        """
        if self._workspace is not None:
            yield self._workspace
            return
        # dir is pinned so a caller's TMPDIR cannot move it out from under the
        # sandbox's /tmp bind.
        self._workspace = Path(
            tempfile.mkdtemp(dir="/tmp", prefix=self.workspace_prefix)
        )
        try:
            yield self._workspace
        finally:
            workspace, self._workspace = self._workspace, None
            shutil.rmtree(workspace, ignore_errors=True)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        input: Optional[bytes] = None,
    ) -> ProcResult:
        """Run ``argv`` from ``cwd`` under the planned isolation.

        Never raises for a timeout or a failure to spawn: the result's ``state``
        says so (see :class:`~supwngo.core.proc.ProcResult`). Under ``"bwrap"``
        a command killed by a signal is reported as ``EXITED`` with ``128 +
        signal`` (see :mod:`supwngo.core.sandbox`). The result's ``isolation`` is
        the plan's label, so it can be ``"outer"``, which ``sandbox.run`` never
        says.
        """
        plan = self.plan
        with self.workspace() as workspace:
            if not plan.fits:
                res = proc.run(argv, input=input, cwd=self.cwd, timeout=timeout)
            else:
                binds = [(str(workspace), str(workspace))]
                if self.cwd.startswith("/tmp/"):
                    # The sandbox's /tmp is a fresh tmpfs, so a binary that lives
                    # under the host /tmp is invisible unless bound back. That
                    # bind is writable, unlike the read-only rest of the
                    # filesystem.
                    binds.append((self.cwd, self.cwd))
                res = sandbox.run(
                    argv,
                    cwd=self.cwd,
                    binds=binds,
                    net=False,
                    timeout=timeout,
                    input=input,
                    backend=plan.backend,
                )
        res.isolation = plan.isolation
        return res


@dataclass(frozen=True)
class GdbProbe:
    """Whether gdb can be used: ``usable``, where it was found, and why not.

    ``path`` is ``None`` when gdb is not installed, a normal host. A found gdb
    that is not ``usable`` carries the ``reason``.
    """

    usable: bool
    path: Optional[str] = None
    reason: str = ""


def probe_gdb(timeout: Optional[float] = None) -> GdbProbe:
    """Check that gdb is installed and answers ``--version`` within ``timeout``.

    ``timeout`` defaults to :data:`GDB_PROBE_TIMEOUT_S`, read at call time. This
    runs gdb outside the sandbox: it only prints a version.
    """
    budget = GDB_PROBE_TIMEOUT_S if timeout is None else timeout
    found = shutil.which("gdb")
    if found is None:
        return GdbProbe(False)
    try:
        result = subprocess.run(
            ["gdb", "--version"],
            capture_output=True,
            timeout=budget,
        )
    except subprocess.TimeoutExpired:
        reason = "`gdb --version` timed out after %g s (host under load?)" % budget
    except Exception as exc:
        reason = "`gdb --version` could not run (%s: %s)" % (
            type(exc).__name__,
            exc,
        )
    else:
        if result.returncode == 0:
            return GdbProbe(True, found)
        tail = (result.stderr or b"").decode("utf-8", "replace").strip()
        reason = "`gdb --version` exited with status %s%s" % (
            result.returncode,
            ": " + tail[-200:] if tail else "",
        )
    return GdbProbe(False, found, reason)
