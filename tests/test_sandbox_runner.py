"""Tests for supwngo.core.sandbox_runner, the reusable sandboxed analysis runner.

These prove the isolation contract from the runner's own module, with no
``OffsetFinder`` in the loop: a run is time-bounded and typed, writes only into
its private workspace, reaches no IP network, leaves no surviving process, and
reports an isolation label that is true. The ``offset`` tests still cover the
runner through its first consumer.

Tests that need a working bwrap skip when the self-check fails, and fail instead
when ``SUPWNGO_REQUIRE_BWRAP=1``. The label, workspace and gdb-probe tests run
either way. Nothing here needs Ghidra.
"""

from __future__ import annotations

import errno
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from passcard_support import gcc, needs_gcc  # noqa: E402

from supwngo.core import sandbox, sandbox_runner  # noqa: E402
from supwngo.core.proc import ProcResult, ProcState  # noqa: E402
from supwngo.core.sandbox_runner import (  # noqa: E402
    IsolationPlan,
    SandboxRunner,
    plan_isolation,
    probe_gdb,
    sandbox_fits,
)

REQUIRE_BWRAP = os.environ.get("SUPWNGO_REQUIRE_BWRAP") == "1"

# Generous: the host is often heavily loaded.
LONG = 30.0

NET_REFUSED = 7
NET_CLIENT = (
    "import socket, sys\n"
    "s = socket.socket()\n"
    "s.settimeout(5)\n"
    "try:\n"
    "    s.connect(('127.0.0.1', int(sys.argv[1])))\n"
    "except OSError:\n"
    "    sys.exit(%d)\n" % NET_REFUSED
)

# Forks a session leader that outlives its parent and closes its stdio, as a
# daemon does. argv[1] (a token) stays in the grandchild's command line, so a
# test can find it. The 60 s sleep is a safety net, not part of any assertion.
FORK_SLEEPER_C = """\
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (fork() == 0) {
        setsid();
        int null = open("/dev/null", O_RDWR);
        dup2(null, 0);
        dup2(null, 1);
        dup2(null, 2);
        sleep(60);
        _exit(0);
    }
    return 0;
}
"""

# argv[1..]: paths. Prints "wrote <path>" or "denied <path>" for each attempt.
WRITE_ATTEMPTS = (
    'for p in "$@"; do '
    'if echo x > "$p" 2>/dev/null; then echo "wrote $p"; '
    'else echo "denied $p"; fi; done'
)


@pytest.fixture(scope="module")
def bwrap():
    if not sandbox.available():
        message = "bwrap unavailable: %r" % (sandbox.self_check_report(),)
        if REQUIRE_BWRAP:
            pytest.fail(message)
        pytest.skip(message)


@pytest.fixture
def no_outer(monkeypatch):
    monkeypatch.delenv("SUPWNGO_OUTER_SANDBOX", raising=False)
    monkeypatch.delenv("SUPWNGO_HOST_PIDNS", raising=False)


@pytest.fixture
def outside_tmp():
    """A host directory outside /tmp, which the sandbox replaces with a tmpfs."""
    path = tempfile.mkdtemp(prefix="supwngo-test-", dir="/var/tmp")
    yield Path(path)
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
    return bool(predicate())


def _kill_all(token):
    for pid in _pids_with(token):
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def _build_fork_sleeper(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "fork_sleeper.c"
    source.write_text(FORK_SLEEPER_C)
    out = directory / "fork_sleeper"
    gcc("-O0", "-o", str(out), str(source), cwd=directory)
    source.unlink()
    return out


def _pidns() -> str:
    return os.readlink("/proc/self/ns/pid")


def _fake_outer(monkeypatch):
    """The harness markers, claiming a PID namespace that is not ours."""
    monkeypatch.setenv("SUPWNGO_OUTER_SANDBOX", "1")
    monkeypatch.setenv("SUPWNGO_HOST_PIDNS", "pid:[1]")


# --- the isolation decision ------------------------------------------------


@pytest.mark.parametrize(
    "directory, fits",
    [
        ("/tmp/a/b", True),
        ("/var/tmp/x", True),
        ("/srv/share/dev/x", True),
        ("/tmp", False),
        ("/dev", False),
        ("/dev/shm/x", False),
        ("/proc/1", False),
        ("/a/.hidden/b", False),
        ("/home/u/.cache/x", False),
        ("/developer/x", True),
    ],
)
def test_sandbox_fits_the_directories_the_sandbox_accepts(directory, fits):
    assert sandbox_fits(directory) is fits


def test_a_plan_unpacks_as_backend_label_and_fits(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox, "available", lambda: True)
    plan = plan_isolation(str(tmp_path))
    backend, label, fits = plan
    assert (backend, label, fits) == ("bwrap", "bwrap", True)
    assert isinstance(plan, IsolationPlan)
    assert (plan.backend, plan.isolation, plan.fits) == (backend, label, fits)


def test_a_working_sandbox_is_bwrap_whatever_the_outer_markers_say(
    monkeypatch, tmp_path
):
    """Outer markers do not demote a sandbox this process built itself."""
    monkeypatch.setattr(sandbox, "available", lambda: True)
    _fake_outer(monkeypatch)
    assert plan_isolation(str(tmp_path)) == ("bwrap", "bwrap", True)


def test_no_sandbox_is_none_even_with_a_working_sandbox_and_outer_markers(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(sandbox, "available", lambda: True)
    _fake_outer(monkeypatch)
    assert plan_isolation(str(tmp_path), use_sandbox=False) == ("none", "none", True)
    assert SandboxRunner(tmp_path, use_sandbox=False).isolation == "none"


@pytest.mark.parametrize(
    "marker, host_ns, expected",
    [
        ("1", "pid:[1]", "outer"),  # a different PID namespace, claimed by the harness
        ("1", "SAME", "none"),  # the harness says outer but we share the host's
        ("1", "", "none"),  # no recorded host namespace to compare against
        ("1", None, "none"),  # variable absent
        (None, "pid:[1]", "none"),  # a namespace that differs is not a claim
        ("0", "pid:[1]", "none"),
        ("true", "pid:[1]", "none"),
    ],
)
def test_outer_requires_the_marker_and_a_different_pid_namespace(
    tmp_path, monkeypatch, no_outer, marker, host_ns, expected
):
    monkeypatch.setattr(sandbox, "available", lambda: False)  # nested bwrap failed
    if marker is not None:
        monkeypatch.setenv("SUPWNGO_OUTER_SANDBOX", marker)
    if host_ns is not None:
        monkeypatch.setenv(
            "SUPWNGO_HOST_PIDNS", _pidns() if host_ns == "SAME" else host_ns
        )
    assert plan_isolation(str(tmp_path)) == ("none", expected, True)
    assert SandboxRunner(tmp_path).isolation == expected


def test_the_plan_is_decided_once(monkeypatch, tmp_path, no_outer):
    answers = iter([True, False])
    monkeypatch.setattr(sandbox, "available", lambda: next(answers))
    runner = SandboxRunner(tmp_path)
    assert runner.isolation == "bwrap"
    assert runner.plan is runner.plan
    assert runner.isolation == "bwrap"  # a second self-check answer is not asked


def test_a_dotted_directory_runs_unsandboxed_and_says_so(
    tmp_path, monkeypatch, no_outer
):
    """The sandbox rejects '.'-prefixed components, so the run is unsandboxed and
    the label is "none" rather than a boundary that is not there."""
    cwd = tmp_path / ".hidden" / "bin"
    cwd.mkdir(parents=True)
    runner = SandboxRunner(cwd)
    assert runner.plan.fits is False
    assert runner.isolation == "none"
    res = runner.run(["pwd", "-P"], timeout=LONG)
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert res.stdout.decode().strip() == str(cwd.resolve())
    assert res.isolation == "none"


def test_a_dotted_directory_under_an_outer_sandbox_is_outer(tmp_path, monkeypatch):
    cwd = tmp_path / ".hidden" / "bin"
    cwd.mkdir(parents=True)
    _fake_outer(monkeypatch)
    runner = SandboxRunner(cwd)
    assert runner.isolation == "outer"
    assert runner.run(["true"], timeout=LONG).isolation == "outer"


# --- the private workspace -------------------------------------------------


def test_the_workspace_is_private_named_and_removed_with_its_owner(
    tmp_path, monkeypatch
):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("TMPDIR", str(elsewhere))  # must not move the workspace
    runner = SandboxRunner(tmp_path, workspace_prefix="supwngo-wstest-")
    with runner.workspace() as workspace:
        assert workspace.parent == Path("/tmp")
        assert workspace.name.startswith("supwngo-wstest-")
        assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
        with runner.workspace() as nested:
            assert nested == workspace
        assert workspace.is_dir(), "the nested user removed the owner's workspace"
        (workspace / "file").write_text("x")
    assert not workspace.exists(), "workspace left behind"
    with runner.workspace() as second:
        assert second != workspace
    assert not second.exists()


def test_a_run_creates_one_workspace_when_there_is_no_owner(tmp_path, monkeypatch):
    made = []
    real = tempfile.mkdtemp

    def mkdtemp(*args, **kwargs):
        path = real(*args, **kwargs)
        if kwargs.get("prefix") == "supwngo-wstest-":
            made.append(path)
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    runner = SandboxRunner(
        tmp_path, use_sandbox=False, workspace_prefix="supwngo-wstest-"
    )
    for call in (1, 2):
        assert runner.run(["true"], timeout=LONG).rc == 0
        assert len(made) == call, made
        assert not os.path.exists(made[-1]), "workspace left behind"


# --- a run: result, isolation, containment ---------------------------------


def test_the_unsandboxed_run_is_typed_and_labelled_none(tmp_path):
    runner = SandboxRunner(tmp_path, use_sandbox=False)
    res = runner.run(["cat"], timeout=LONG, input=b"in\x00put")
    assert isinstance(res, ProcResult)
    assert res.state is ProcState.EXITED and res.rc == 0
    assert res.stdout == b"in\x00put"
    assert res.isolation == "none"

    missing = runner.run(["/nonexistent/supwngo-test"], timeout=LONG)
    assert missing.state is ProcState.SPAWN_ERROR
    assert missing.errno == errno.ENOENT
    assert missing.isolation == "none"

    # A shell is not a sandbox: the PID namespace is the host's.
    ns = runner.run(["readlink", "/proc/self/ns/pid"], timeout=LONG)
    assert ns.stdout.decode().strip() == _pidns()


def test_isolation_is_bwrap_when_the_sandbox_works_and_the_run_really_is(
    bwrap, tmp_path, monkeypatch
):
    """The label is a claim, so the run is checked: its PID namespace is not ours."""
    _fake_outer(monkeypatch)  # an outer harness does not demote a working sandbox
    runner = SandboxRunner(tmp_path)
    res = runner.run(["readlink", "/proc/self/ns/pid"], timeout=LONG)
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert runner.isolation == "bwrap"
    assert res.isolation == "bwrap"
    inside = res.stdout.decode().strip()
    assert inside.startswith("pid:[") and inside != _pidns()


def test_a_timeout_is_a_typed_outcome_and_bounded(bwrap, tmp_path):
    res = SandboxRunner(tmp_path).run(["sleep", "30"], timeout=1.0)
    assert res.state is ProcState.TIMEOUT
    assert res.rc is None and res.signal is None
    assert res.isolation == "bwrap"
    assert res.wall_s < 20


def test_a_signalled_target_is_exited_128_plus_signal_under_bwrap(bwrap, tmp_path):
    res = SandboxRunner(tmp_path).run(["sh", "-c", "kill -SEGV $$"], timeout=LONG)
    assert res.state is ProcState.EXITED
    assert res.rc == 128 + 11


def test_file_input_and_scripts_reach_the_run_through_the_workspace(bwrap, tmp_path):
    runner = SandboxRunner(tmp_path, workspace_prefix="supwngo-wstest-")
    with runner.workspace() as workspace:
        (workspace / "input.bin").write_bytes(b"\xff\x00AB\n")
        res = runner.run(["cat", str(workspace / "input.bin")], timeout=LONG)
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert res.stdout == b"\xff\x00AB\n"
    assert res.isolation == "bwrap"


def test_a_run_writes_only_into_the_workspace(bwrap, outside_tmp, no_outer):
    cwd = outside_tmp / "bin"
    cwd.mkdir()
    leak_tmp = "/tmp/supwngo-leak-" + uuid.uuid4().hex
    try:
        # Control: with no sandbox every one of these writes lands.
        bare = SandboxRunner(cwd, use_sandbox=False, workspace_prefix="supwngo-wstest-")
        with bare.workspace() as workspace:
            targets = [
                str(cwd / "c"),
                str(outside_tmp / "o"),
                leak_tmp,
                str(workspace / "w"),
            ]
            res = bare.run(["sh", "-c", WRITE_ATTEMPTS, "sh"] + targets, timeout=LONG)
            assert res.stdout.decode().split("\n")[:-1] == [
                "wrote " + t for t in targets
            ]
        for path in (cwd / "c", outside_tmp / "o", leak_tmp):
            Path(path).unlink()

        runner = SandboxRunner(cwd, workspace_prefix="supwngo-wstest-")
        with runner.workspace() as workspace:
            targets = [
                str(cwd / "c"),
                str(outside_tmp / "o"),
                leak_tmp,
                str(workspace / "w"),
            ]
            res = runner.run(["sh", "-c", WRITE_ATTEMPTS, "sh"] + targets, timeout=LONG)
            assert res.isolation == "bwrap"
            said = res.stdout.decode().split("\n")[:-1]
            assert said[0] == "denied " + targets[0]  # the working directory
            assert said[1] == "denied " + targets[1]  # the rest of the filesystem
            assert said[3] == "wrote " + targets[3]  # the workspace
            # Positive control: a workspace write reaches the host, so the
            # sandbox did run the script and the absences below mean something.
            assert (workspace / "w").read_text() == "x\n"
        assert not (cwd / "c").exists()
        assert not (outside_tmp / "o").exists()
        # Its /tmp is a private tmpfs: a write there never reaches the host.
        assert not os.path.exists(leak_tmp)
    finally:
        if os.path.exists(leak_tmp):
            os.unlink(leak_tmp)


def test_a_cwd_under_tmp_is_visible_inside_the_sandbox(bwrap, tmp_path, no_outer):
    """The sandbox's /tmp is a fresh tmpfs, so the runner binds the cwd back."""
    (tmp_path / "marker").write_text("here")
    res = SandboxRunner(tmp_path).run(["cat", "marker"], timeout=LONG)
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert res.stdout == b"here"
    assert res.isolation == "bwrap"


def test_a_run_has_no_ip_network(bwrap, tmp_path, no_outer):
    py = [sys.executable or "python3", "-I", "-S", "-c", NET_CLIENT]
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = str(server.getsockname()[1])
        # Control: the listener is reachable without the sandbox.
        bare = SandboxRunner(tmp_path, use_sandbox=False).run(py + [port], timeout=LONG)
        assert bare.state is ProcState.EXITED and bare.rc == 0, bare.stderr
        res = SandboxRunner(tmp_path).run(py + [port], timeout=LONG)
    assert res.state is ProcState.EXITED
    assert res.rc == NET_REFUSED, res.stderr
    assert res.isolation == "bwrap"


@needs_gcc
def test_no_process_outlives_a_run_under_bwrap(bwrap, tmp_path, no_outer):
    binary = _build_fork_sleeper(tmp_path / "bin")

    # Control: the carrier works, i.e. with no sandbox the grandchild does survive.
    control = "ctl" + uuid.uuid4().hex
    try:
        bare = SandboxRunner(binary.parent, use_sandbox=False)
        res = bare.run([str(binary), control], timeout=LONG)
        assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
        assert _wait_until(lambda: _pids_with(control)), "control: no survivor"
    finally:
        _kill_all(control)

    token = "tok" + uuid.uuid4().hex
    try:
        res = SandboxRunner(binary.parent).run([str(binary), token], timeout=LONG)
        assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
        assert res.isolation == "bwrap"
        assert _wait_until(
            lambda: not _pids_with(token), seconds=10.0
        ), "setsid grandchildren survived: %r" % _pids_with(token)
    finally:
        _kill_all(token)


def test_a_path_passed_in_hide_is_not_readable_by_the_run(
    bwrap, outside_tmp, tmp_path, monkeypatch, no_outer
):
    """The runner passes no ``hide`` itself; a wrapper around ``sandbox.run``
    injects one, which is how the passcard hides its answer keys."""
    secret = outside_tmp / "secret"
    secret.write_text("answer")
    runner = SandboxRunner(tmp_path)

    # Control: without a hide the secret is readable inside the sandbox.
    res = runner.run(["cat", str(secret)], timeout=LONG)
    assert res.rc == 0 and res.stdout == b"answer", res.stderr

    real_run = sandbox.run

    def hiding(argv, **kwargs):
        kwargs["hide"] = [str(outside_tmp)]
        return real_run(argv, **kwargs)

    monkeypatch.setattr(sandbox, "run", hiding)
    res = runner.run(["cat", str(secret)], timeout=LONG)
    assert res.state is ProcState.EXITED
    assert res.rc != 0 and res.stdout == b""
    assert res.stderr.startswith(b"cat:"), res.stderr
    assert secret.read_text() == "answer"


# --- gdb through the runner ------------------------------------------------


@pytest.mark.skipif(shutil.which("gdb") is None, reason="gdb not installed")
def test_gdb_runs_under_bwrap_with_its_script_in_the_workspace(
    bwrap, tmp_path, no_outer
):
    runner = SandboxRunner(tmp_path, workspace_prefix="supwngo-wstest-")
    with runner.workspace() as workspace:
        script = workspace / "s.gdb"
        script.write_text("set pagination off\nrun\nquit\n")
        argv = ["gdb", "-q", "-batch", "-x", str(script), "/bin/true"]
        res = runner.run(argv, timeout=LONG)
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert res.isolation == "bwrap"
    assert b"exited normally" in res.stdout, res.stdout  # gdb ran the target


# --- the gdb probe ---------------------------------------------------------


def _scripted_gdb(monkeypatch, *, installed=True, run=None):
    """Script ``shutil.which("gdb")`` and the ``gdb --version`` call.

    Returns the list of keyword arguments of each probe call.
    """
    real_which = shutil.which
    real_run = subprocess.run
    probes = []

    def which(name, *args, **kwargs):
        if name == "gdb":
            return "/usr/bin/gdb" if installed else None
        return real_which(name, *args, **kwargs)

    def scripted(argv, *args, **kwargs):
        if argv[0] == "gdb" and argv[1:2] == ["--version"]:
            probes.append(kwargs)
            return run(argv, **kwargs)
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(shutil, "which", which)
    monkeypatch.setattr(subprocess, "run", scripted)
    return probes


def _answered(returncode=0, stderr=b""):
    return lambda argv, **kwargs: subprocess.CompletedProcess(
        argv, returncode, b"GNU gdb\n", stderr
    )


def _raising(exc):
    def run(argv, **kwargs):
        raise exc

    return run


def test_the_gdb_probe_budget_is_a_named_constant_of_at_least_30_seconds():
    assert sandbox_runner.GDB_PROBE_TIMEOUT_S >= 30


def test_the_probe_defaults_to_the_named_budget_read_at_call_time(monkeypatch):
    probes = _scripted_gdb(monkeypatch, run=_answered())
    assert probe_gdb().usable is True
    monkeypatch.setattr(sandbox_runner, "GDB_PROBE_TIMEOUT_S", 7.0)
    assert probe_gdb().usable is True
    assert probe_gdb(timeout=3.0).usable is True
    assert [p.get("timeout") for p in probes] == [30.0, 7.0, 3.0]


def test_a_gdb_that_answers_is_usable(monkeypatch):
    _scripted_gdb(monkeypatch, run=_answered())
    probe = probe_gdb()
    assert (probe.usable, probe.path, probe.reason) == (True, "/usr/bin/gdb", "")


def test_a_gdb_that_is_not_installed_is_not_probed(monkeypatch):
    probes = _scripted_gdb(monkeypatch, installed=False, run=_answered())
    probe = probe_gdb()
    assert (probe.usable, probe.path, probe.reason) == (False, None, "")
    assert probes == []


@pytest.mark.parametrize(
    "run, reason",
    [
        (
            _raising(subprocess.TimeoutExpired(["gdb", "--version"], 30)),
            "timed out after 30 s",
        ),
        (_raising(OSError(8, "Exec format error")), "Exec format error"),
        (_answered(returncode=3, stderr=b"gdb: broken install\n"), "broken install"),
    ],
    ids=["timeout", "oserror", "nonzero"],
)
def test_a_gdb_that_is_found_but_will_not_answer_carries_its_reason(
    monkeypatch, run, reason
):
    _scripted_gdb(monkeypatch, run=run)
    probe = probe_gdb()
    assert probe.usable is False
    assert probe.path == "/usr/bin/gdb"
    assert "gdb --version" in probe.reason
    assert reason in probe.reason, probe.reason
