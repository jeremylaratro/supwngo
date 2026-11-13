"""
Bubblewrap sandbox with a self-check.

``run`` executes a command under ``bwrap`` (or unsandboxed when asked to) and
returns the same typed :class:`~supwngo.core.proc.ProcResult` as ``proc.run``.

What the sandbox contains: writes (the root is read-only), IP networking (a
private loopback with no host listeners) and processes (a private PID
namespace, so a timeout takes every descendant with it, including ones that
called ``setsid()``). What it does not contain: reads. ``--ro-bind / /`` leaves
most host files readable, and pathname Unix sockets visible on the root stay
reachable, so only the paths passed in ``hide`` are protected. This is not a
general host-confidentiality boundary.

A command killed by a signal inside the sandbox makes ``bwrap`` exit with
``128 + signal``, so under ``bwrap`` it is reported as ``EXITED``, not
``SIGNALED``.
"""

from __future__ import annotations

import os
import posixpath
import shutil
import socket
import sys
import tempfile
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from supwngo.core import proc
from supwngo.core.proc import ProcResult, ProcState

_PROBE_TIMEOUT_S = 30.0

# Exit code the net probe's client uses for "connect failed".
_NET_REFUSED = 7
_NET_CLIENT = (
    "import socket, sys\n"
    "s = socket.socket()\n"
    "s.settimeout(5)\n"
    "try:\n"
    "    s.connect(('127.0.0.1', int(sys.argv[1])))\n"
    "except OSError:\n"
    "    sys.exit(%d)\n" % _NET_REFUSED
)

_report: Optional[Dict[str, object]] = None


def _bad_component(path: str) -> bool:
    return any(part.startswith(".") for part in path.split("/") if part)


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _validate(
    cwd: str,
    binds: Sequence[Tuple[str, str]],
    hide: Sequence[str],
    backend: str,
) -> None:
    """Raise ValueError for a configuration the sandbox cannot honour."""
    for host, inside in binds:
        if not posixpath.normpath(inside).startswith("/tmp/"):
            raise ValueError("bind target %r is not under /tmp/" % inside)
        for what, path in (("bind target", inside), ("bind source", host)):
            if _bad_component(path):
                raise ValueError("%s %r has a '.'-prefixed component" % (what, path))
    if _bad_component(cwd):
        raise ValueError("cwd %r has a '.'-prefixed component" % cwd)

    cwd = os.path.abspath(cwd)
    if any(_within(cwd, posixpath.normpath(inside)) for _, inside in binds):
        return
    if not os.path.exists(cwd):
        raise ValueError("cwd %r is not a bind target and does not exist" % cwd)
    # Under bwrap, /tmp is a fresh tmpfs, so a host path there is not visible.
    hidden = [os.path.abspath(h) for h in hide]
    if backend == "bwrap":
        hidden.append("/tmp")
    if any(_within(cwd, h) for h in hidden):
        raise ValueError("cwd %r is hidden" % cwd)


def run(
    argv: Sequence[str],
    *,
    cwd: str,
    binds: Sequence[Tuple[str, str]] = (),
    hide: Sequence[str] = (),
    net: bool = False,
    timeout: float,
    input: Optional[bytes] = None,
    env: Optional[Mapping[str, str]] = None,
    backend: str = "auto",
) -> ProcResult:
    """Run ``argv`` in the sandbox and return a typed result.

    ``binds`` are ``(host_dir, inside_path)`` pairs, writable, with every
    ``inside_path`` under ``/tmp/``. ``hide`` paths are replaced by an empty
    tmpfs; ones that do not exist are skipped and listed in ``hide_absent``.
    ``cwd`` must be a bind target (or below one) or an existing, unhidden path.
    No path may have a component starting with ``.``. ``backend`` is ``"auto"``
    (bwrap when ``available()``), ``"bwrap"`` or ``"none"``; with ``"none"``
    the command is a plain ``proc.run`` and ``binds``, ``hide`` and ``net`` are
    ignored. The result's ``isolation`` says which backend ran.

    Raises ValueError, before spawning, for an invalid configuration.
    """
    if backend not in ("auto", "bwrap", "none"):
        raise ValueError("unknown backend %r" % backend)
    cwd = os.fspath(cwd)
    binds = [(os.fspath(h), os.fspath(i)) for h, i in binds]
    hide = [os.fspath(h) for h in hide]
    if backend == "auto":
        backend = "bwrap" if available() else "none"
    _validate(cwd, binds, hide, backend)

    if backend == "none":
        return proc.run(argv, input=input, cwd=cwd, env=env, timeout=timeout)

    absent = [h for h in hide if not os.path.exists(h)]
    cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    for path in hide:
        if path not in absent:
            cmd += ["--tmpfs", os.path.abspath(path)]
    cmd += ["--tmpfs", "/tmp"]
    for host, inside in binds:
        cmd += ["--bind", os.path.abspath(host), posixpath.normpath(inside)]
    if not net:
        cmd.append("--unshare-net")
    cmd += ["--unshare-pid", "--die-with-parent", "--new-session"]
    cmd += ["--chdir", os.path.abspath(cwd), "--"] + list(argv)

    res = proc.run(cmd, input=input, cwd="/", env=env, timeout=timeout)
    res.isolation = "bwrap"
    res.hide_absent = absent
    return res


def _exited_ok(res: ProcResult) -> bool:
    return res.state is ProcState.EXITED and res.rc == 0


def _scratch_outside_tmp() -> str:
    """A fresh host directory that the sandbox's /tmp tmpfs does not cover."""
    for base in ("/var/tmp", os.path.expanduser("~")):
        try:
            return tempfile.mkdtemp(prefix="supwngo-sbx-", dir=base)
        except OSError:
            continue
    raise OSError("no writable directory outside /tmp for the hide probe")


def _probe_bootstrap(notes: List[str]) -> bool:
    if not _exited_ok(proc.run(["true"], cwd="/", timeout=_PROBE_TIMEOUT_S)):
        notes.append("bootstrap: unsandboxed `true` failed")
        return False
    res = run(["true"], cwd="/", timeout=_PROBE_TIMEOUT_S, backend="bwrap")
    if not _exited_ok(res):
        notes.append("bootstrap: bwrap failed: %r" % res.stderr[:200])
        return False
    return True


def _probe_hide(notes: List[str]) -> bool:
    # Under /tmp the sentinel would vanish behind the /tmp tmpfs even with no
    # working hide, so it lives elsewhere.
    try:
        scratch = _scratch_outside_tmp()
    except OSError as exc:
        notes.append("hide: %s" % exc)
        return False
    try:
        sentinel = os.path.join(scratch, "sentinel")
        with open(sentinel, "w") as fh:
            fh.write("visible")
        direct = proc.run(["cat", sentinel], cwd="/", timeout=_PROBE_TIMEOUT_S)
        if not _exited_ok(direct) or direct.stdout != b"visible":
            notes.append("hide: sentinel not readable outside the sandbox")
            return False
        res = run(
            ["cat", sentinel],
            cwd="/",
            hide=[scratch],
            timeout=_PROBE_TIMEOUT_S,
            backend="bwrap",
        )
        # cat's own error, not a bwrap failure, must be what stopped the read.
        if (
            res.state is not ProcState.EXITED
            or res.rc == 0
            or res.stdout
            or not res.stderr.startswith(b"cat:")
        ):
            notes.append("hide: sentinel readable or bwrap failed: %r" % res.stderr)
            return False
        return True
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _probe_net(notes: List[str]) -> bool:
    py = [sys.executable or "python3", "-I", "-S", "-c", _NET_CLIENT]
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = str(server.getsockname()[1])
        direct = proc.run(py + [port], cwd="/", timeout=_PROBE_TIMEOUT_S)
        if not _exited_ok(direct):
            notes.append("net: unsandboxed connect failed: %r" % direct.stderr[:200])
            return False
        res = run(py + [port], cwd="/", timeout=_PROBE_TIMEOUT_S, backend="bwrap")
    if res.state is not ProcState.EXITED or res.rc != _NET_REFUSED:
        notes.append("net: host listener reachable or bwrap failed: %r" % res.stderr)
        return False
    return True


def _probe_bind(notes: List[str]) -> bool:
    host = tempfile.mkdtemp(prefix="supwngo-sbx-", dir="/tmp")
    inside = "/tmp/supwngo-selfcheck"
    try:
        direct = os.path.join(host, "direct")
        with open(direct, "w") as fh:
            fh.write("payload")
        with open(direct) as fh:
            if fh.read() != "payload":
                notes.append("bind: host round trip failed")
                return False
        res = run(
            ["sh", "-c", "printf payload > out"],
            cwd=inside,
            binds=[(host, inside)],
            timeout=_PROBE_TIMEOUT_S,
            backend="bwrap",
        )
        written = os.path.join(host, "out")
        if not _exited_ok(res) or not os.path.exists(written):
            notes.append("bind: sandbox write did not reach host: %r" % res.stderr)
            return False
        with open(written) as fh:
            return fh.read() == "payload"
    finally:
        shutil.rmtree(host, ignore_errors=True)


def self_check_report() -> Dict[str, object]:
    """Run the self-check once per process; return each probe's result.

    Keys: ``bwrap`` (path or None), ``bootstrap``, ``hide``, ``net``, ``bind``
    (bool each), ``available`` (all four held) and ``notes`` (why not).
    """
    global _report
    if _report is None:
        notes: List[str] = []
        probes = {"bootstrap": False, "hide": False, "net": False, "bind": False}
        path = shutil.which("bwrap")
        if path is None:
            notes.append("bwrap not found on PATH")
        elif _probe_bootstrap(notes):
            probes["bootstrap"] = True
            probes["hide"] = _probe_hide(notes)
            probes["net"] = _probe_net(notes)
            probes["bind"] = _probe_bind(notes)
        _report = dict(probes, bwrap=path, available=all(probes.values()), notes=notes)
    return dict(_report)


def available() -> bool:
    """True when bwrap passed all four self-check probes (cached per process)."""
    return bool(self_check_report()["available"])
