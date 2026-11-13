"""Tests for supwngo.core.sandbox: the bwrap backend and its self-check.

Tests that need a working bwrap skip when the self-check fails, and fail
instead when ``SUPWNGO_REQUIRE_BWRAP=1``. Validation and ``backend="none"``
tests run either way.
"""

import os
import shutil
import socket
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from supwngo.core import sandbox
from supwngo.core.proc import ProcState

REQUIRE_BWRAP = os.environ.get("SUPWNGO_REQUIRE_BWRAP") == "1"

# Generous: the host is often heavily loaded.
LONG = 30.0

NET_CLIENT = (
    "import socket, sys\n"
    "s = socket.socket()\n"
    "s.settimeout(5)\n"
    "try:\n"
    "    s.connect(('127.0.0.1', int(sys.argv[1])))\n"
    "except OSError:\n"
    "    sys.exit(7)\n"
)


@pytest.fixture(scope="module")
def bwrap():
    if not sandbox.available():
        message = "bwrap unavailable: %r" % (sandbox.self_check_report(),)
        if REQUIRE_BWRAP:
            pytest.fail(message)
        pytest.skip(message)


@pytest.fixture
def outside_tmp():
    """A host directory outside /tmp, which the sandbox replaces with a tmpfs."""
    for base in ("/var/tmp", os.path.expanduser("~")):
        try:
            path = tempfile.mkdtemp(prefix="supwngo-test-", dir=base)
            break
        except OSError:
            continue
    else:
        pytest.skip("no writable directory outside /tmp")
    yield path
    shutil.rmtree(path, ignore_errors=True)


def _pids_with(token):
    """Host PIDs whose command line contains ``token``."""
    needle = token.encode()
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            cmdline = Path("/proc/%s/cmdline" % name).read_bytes()
        except OSError:
            continue
        if needle in cmdline:
            found.append(int(name))
    return found


def _wait_until(predicate, seconds=15.0):
    deadline = time.monotonic() + seconds
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.05)
    return predicate()


def test_self_check_probes_all_hold(bwrap):
    report = sandbox.self_check_report()
    for probe in ("bootstrap", "hide", "net", "bind"):
        assert report[probe] is True, report
    assert report["available"] is True and report["notes"] == []
    assert sandbox.available() is True


def test_hidden_sentinel_is_unreadable_inside_and_readable_outside(bwrap, outside_tmp):
    sentinel = os.path.join(outside_tmp, "sentinel")
    Path(sentinel).write_text("secret")
    assert Path(sentinel).read_text() == "secret"  # outside

    visible = sandbox.run(
        ["cat", sentinel], cwd="/", timeout=LONG, backend="bwrap"
    )  # control: the sentinel is not hidden by default
    assert visible.stdout == b"secret"

    hidden = sandbox.run(
        ["cat", sentinel],
        cwd="/",
        hide=[outside_tmp],
        timeout=LONG,
        backend="bwrap",
    )
    assert hidden.state is ProcState.EXITED and hidden.rc != 0
    assert hidden.stdout == b"" and hidden.stderr.startswith(b"cat:")
    assert hidden.hide_absent == []
    assert Path(sentinel).read_text() == "secret"  # still there afterwards


def test_host_listener_is_unreachable_but_reachable_with_net(bwrap):
    py = [sys.executable, "-I", "-S", "-c", NET_CLIENT]
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = str(server.getsockname()[1])
        direct = sandbox.run(py + [port], cwd="/", timeout=LONG, backend="none")
        isolated = sandbox.run(py + [port], cwd="/", timeout=LONG, backend="bwrap")
        shared = sandbox.run(
            py + [port], cwd="/", net=True, timeout=LONG, backend="bwrap"
        )
    assert direct.rc == 0, direct.stderr
    assert isolated.state is ProcState.EXITED and isolated.rc == 7, isolated.stderr
    assert shared.rc == 0, shared.stderr


def test_bind_round_trip_and_unbound_paths_are_read_only(bwrap, outside_tmp, tmp_path):
    (tmp_path / "in.txt").write_text("from-host")
    res = sandbox.run(
        [
            "sh",
            "-c",
            "cat in.txt > out.txt && echo x > %s/leak || echo blocked" % outside_tmp,
        ],
        cwd="/tmp/cell",
        binds=[(str(tmp_path), "/tmp/cell")],
        timeout=LONG,
        backend="bwrap",
    )
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert res.stdout.strip() == b"blocked"
    assert (tmp_path / "out.txt").read_text() == "from-host"
    assert not os.path.exists(os.path.join(outside_tmp, "leak"))
    assert res.isolation == "bwrap"


def test_bind_source_inside_a_hidden_directory_still_binds(bwrap, outside_tmp):
    # Mount order: hides first, then the /tmp tmpfs, then binds. Bind sources
    # come from the old root, so hiding their parent cannot cut them off.
    host = os.path.join(outside_tmp, "cell")
    os.mkdir(host)
    res = sandbox.run(
        ["sh", "-c", "ls %s | wc -l; echo done > out.txt" % outside_tmp],
        cwd="/tmp/cell",
        binds=[(host, "/tmp/cell")],
        hide=[outside_tmp],
        timeout=LONG,
        backend="bwrap",
    )
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert res.stdout.strip() == b"0"  # the hidden parent is empty inside
    assert Path(host, "out.txt").read_text() == "done\n"


def test_timeout_kills_a_setsid_sleeper_in_the_pid_namespace(bwrap, tmp_path):
    def script(ready, token):
        return (
            'setsid sh -c ": %s; echo up > %s; sleep 300" '
            "</dev/null >/dev/null 2>&1 & sleep 300" % (token, ready)
        )

    # Control: unsandboxed, setsid escapes the process-group kill, so the check
    # below can see a survivor when there is one.
    control_dir = tmp_path / "control"
    control_dir.mkdir()
    control_token = "sbxctl" + uuid.uuid4().hex
    try:
        res = sandbox.run(
            ["sh", "-c", script(control_dir / "ready", control_token)],
            cwd=str(control_dir),
            timeout=10.0,
            backend="none",
        )
        assert res.state is ProcState.TIMEOUT
        assert _wait_until(lambda: _pids_with(control_token)), "control: no survivor"
    finally:
        for pid in _pids_with(control_token):
            os.kill(pid, 9)

    cell = tmp_path / "cell"
    cell.mkdir()
    token = "sbx" + uuid.uuid4().hex
    res = sandbox.run(
        ["sh", "-c", script("/tmp/cell/ready", token)],
        cwd="/tmp/cell",
        binds=[(str(cell), "/tmp/cell")],
        timeout=10.0,
        backend="bwrap",
    )
    assert res.state is ProcState.TIMEOUT and res.isolation == "bwrap"
    assert (cell / "ready").exists(), "sleeper never started"
    assert _wait_until(lambda: not _pids_with(token)), _pids_with(token)


def test_absent_hide_path_is_recorded(bwrap, outside_tmp):
    absent = os.path.join(outside_tmp, "no-such-dir")
    res = sandbox.run(
        ["true"],
        cwd="/",
        hide=[absent, outside_tmp],
        timeout=LONG,
        backend="bwrap",
    )
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert res.hide_absent == [absent]


def test_signal_death_under_bwrap_is_reported_as_128_plus_signal(bwrap):
    res = sandbox.run(
        ["sh", "-c", "kill -SEGV $$"], cwd="/", timeout=LONG, backend="bwrap"
    )
    assert res.state is ProcState.EXITED and res.rc == 128 + 11


def test_auto_uses_bwrap_when_available(bwrap):
    res = sandbox.run(["true"], cwd="/", timeout=LONG)
    assert res.isolation == "bwrap" and res.rc == 0


def test_backend_none_is_a_plain_run(tmp_path):
    res = sandbox.run(
        ["sh", "-c", "echo hi"],
        cwd=str(tmp_path),
        hide=["/nonexistent/hidden"],
        timeout=LONG,
        backend="none",
    )
    assert res.state is ProcState.EXITED and res.stdout == b"hi\n"
    assert res.isolation == "none" and res.hide_absent == []


@pytest.mark.parametrize(
    "inside",
    ["/etc/cell", "/tmp", "tmp/cell", "/tmp/../etc/cell", "/tmpx/cell"],
)
def test_inside_path_must_be_under_tmp(tmp_path, inside):
    with pytest.raises(ValueError):
        sandbox.run(
            ["true"],
            cwd=str(tmp_path),
            binds=[(str(tmp_path), inside)],
            timeout=LONG,
            backend="bwrap",
        )


def test_dot_component_is_rejected_in_inside_cwd_and_host(tmp_path):
    host = tmp_path / "host"
    host.mkdir()
    with pytest.raises(ValueError):  # inside path
        sandbox.run(
            ["true"],
            cwd="/tmp/.cell",
            binds=[(str(host), "/tmp/.cell")],
            timeout=LONG,
            backend="bwrap",
        )
    with pytest.raises(ValueError):  # cwd
        sandbox.run(["true"], cwd=str(tmp_path / ".cwd"), timeout=LONG, backend="none")
    with pytest.raises(ValueError):  # bind source
        sandbox.run(
            ["true"],
            cwd="/tmp/cell",
            binds=[(str(tmp_path / ".host"), "/tmp/cell")],
            timeout=LONG,
            backend="bwrap",
        )


def test_cwd_must_be_a_bind_or_an_existing_unhidden_path(tmp_path):
    with pytest.raises(ValueError):  # missing and not a bind target
        sandbox.run(["true"], cwd=str(tmp_path / "gone"), timeout=LONG, backend="none")
    with pytest.raises(ValueError):  # hidden
        sandbox.run(
            ["true"],
            cwd=str(tmp_path),
            hide=[str(tmp_path.parent)],
            timeout=LONG,
            backend="none",
        )
    with pytest.raises(ValueError):  # under /tmp, which bwrap replaces
        sandbox.run(["true"], cwd=str(tmp_path), timeout=LONG, backend="bwrap")


def test_unknown_backend_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        sandbox.run(["true"], cwd=str(tmp_path), timeout=LONG, backend="docker")
