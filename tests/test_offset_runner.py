"""Tests for the OffsetFinder runner, sandbox and tri-state search (SP-01b, 4.1).

Seam tests script the target runner (``_run_target``, ``subprocess.run`` on the
base) so they need no process. The rest run real fixtures: a crash target in
assembly whose distance to the return address is ``CRASH_OFFSET`` by
construction, plus small C programs that fork a ``setsid`` sleeper, spin on EOF
or try to open a path.

Every ``monkeypatch`` that stands in for the target runner matches ``argv[0]``:
a blanket ``subprocess.run`` patch would also catch unrelated calls such as
``file -b`` or ``gdb --version``.
"""

from __future__ import annotations

import errno
import inspect
import logging
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from offset_support import (  # noqa: E402
    CRASH_OFFSET,
    EOF_SPIN_C,
    FORK_SLEEPER_C,
    PROBE_C,
    build_asm_crash,
    build_c,
    copy_host_loader,
    fast_budgets,
    kill_all,
    make_core,
    needs_gdb,
    pids_with,
    wait_until,
)
from passcard_support import (  # noqa: E402
    REPO_ROOT,
    needs_bwrap,
    needs_gcc,
    needs_host_loader,
)

from supwngo.core import sandbox  # noqa: E402
from supwngo.core.proc import ProcResult, ProcState  # noqa: E402
from supwngo.exploit import offset_finder  # noqa: E402
from supwngo.exploit.offset_finder import OffsetFinder, OffsetResult  # noqa: E402

PE_SYM = REPO_ROOT / "benchmark" / "fixtures" / "s0pe" / "pe_sym.exe"


# --- helpers ---------------------------------------------------------------


def unsandboxed_finder(path):
    """The ``--no-sandbox`` finder.

    On the fix that is ``use_sandbox=False``. The base has no sandbox to switch
    off, so a plain finder is the same thing there.
    """
    if "use_sandbox" in inspect.signature(OffsetFinder).parameters:
        return OffsetFinder(path, use_sandbox=False)
    return OffsetFinder(path)


def script_target(monkeypatch, finder, outcome):
    """Replace the target runner of ``finder`` with a scripted one.

    ``outcome(payload) -> "crash" | "ok" | "timeout" | "spawn_error"``. On the fix
    ``_run_target`` is replaced; on the base the same outcomes are produced from
    ``subprocess.run`` calls whose ``argv[0]`` is the target. Returns the list of
    payloads the runner was asked to run.
    """
    binary = str(finder.binary_path)
    calls = []

    def run_target(self, payload, input_method, args, timeout):
        calls.append(payload)
        verdict = outcome(payload)
        if verdict == "crash":
            return ProcResult(ProcState.SIGNALED, signal=signal.SIGSEGV)
        if verdict == "ok":
            return ProcResult(ProcState.EXITED, rc=0)
        if verdict == "timeout":
            return ProcResult(ProcState.TIMEOUT)
        return ProcResult(ProcState.SPAWN_ERROR, errno=errno.ENOEXEC)

    real_run = subprocess.run

    def base_run(argv, *args, **kwargs):
        if argv[0] != binary:
            return real_run(argv, *args, **kwargs)
        payload = kwargs.get("input") or b""
        calls.append(payload)
        verdict = outcome(payload)
        if verdict == "crash":
            return subprocess.CompletedProcess(argv, -signal.SIGSEGV, b"", b"")
        if verdict == "ok":
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if verdict == "timeout":
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 5))
        raise OSError(errno.ENOEXEC, "Exec format error")

    monkeypatch.setattr(OffsetFinder, "_run_target", run_target, raising=False)
    monkeypatch.setattr(subprocess, "run", base_run)
    return calls


def record_workspaces(monkeypatch):
    """Record every directory made with the ``supwngo-offset-`` prefix."""
    made = []
    real = tempfile.mkdtemp

    def mkdtemp(*args, **kwargs):
        path = real(*args, **kwargs)
        if kwargs.get("prefix") == "supwngo-offset-":
            made.append(path)
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    return made


def only_pure_a(payload):
    return set(payload) <= {ord("A")}


@pytest.fixture
def no_outer(monkeypatch):
    monkeypatch.delenv("SUPWNGO_OUTER_SANDBOX", raising=False)
    monkeypatch.delenv("SUPWNGO_HOST_PIDNS", raising=False)


@pytest.fixture
def var_tmp_dir():
    """A directory outside /tmp, which the sandbox cannot see without a bind."""
    path = tempfile.mkdtemp(prefix="supwngo-test-", dir="/var/tmp")
    yield Path(path)
    shutil.rmtree(path, ignore_errors=True)


# --- tri-state search ------------------------------------------------------


@pytest.mark.parametrize("kind", ["timeout", "spawn_error"])
def test_refine_probe_that_cannot_answer_aborts_instead_of_raising(
    tmp_path, monkeypatch, kind
):
    """RED on the base: the refine loop has no handler, so the error escapes."""
    finder = OffsetFinder(build_asm_crash(tmp_path))

    def outcome(payload):
        if not only_pure_a(payload):  # the first refine probe
            return kind
        return "crash" if len(payload) >= 100 else "ok"

    script_target(monkeypatch, finder, outcome)
    result = finder._find_with_binary_search(256, "stdin", [])
    assert result.success is False
    assert result.offset is None
    assert result.error_code == kind


@pytest.mark.parametrize("kind", ["timeout", "spawn_error"])
def test_probe_that_cannot_answer_mid_search_is_not_read_as_no_crash(
    tmp_path, monkeypatch, kind
):
    """RED on the base: the first probe reads as "no crash" and a threshold is made up."""
    finder = OffsetFinder(build_asm_crash(tmp_path))

    def outcome(payload):
        if only_pure_a(payload) and len(payload) == 1024:  # the first probe
            return kind
        return "crash" if len(payload) >= 100 else "ok"

    calls = script_target(monkeypatch, finder, outcome)
    result = finder._find_with_binary_search(2048, "stdin", [])
    assert result.success is False, "fabricated a threshold: %r" % (result.offset,)
    assert result.offset is None
    assert result.error_code == kind
    assert len(calls) == 1, "kept probing after an unknown answer"


def test_a_clean_search_still_finds_a_threshold(tmp_path, monkeypatch):
    """Control for the two tests above: with no unknown probe the search works."""
    finder = OffsetFinder(build_asm_crash(tmp_path))
    script_target(monkeypatch, finder, lambda p: "crash" if len(p) >= 100 else "ok")
    result = finder._find_with_binary_search(256, "stdin", [])
    assert result.success is True
    assert result.method.startswith("Binary search")
    assert result.offset is not None


@pytest.mark.parametrize(
    "state, rc, sig, expected",
    [
        (ProcState.EXITED, 0, None, "NO_CRASH"),
        (ProcState.EXITED, 1, None, "NO_CRASH"),
        (ProcState.EXITED, 128 + signal.SIGSEGV, None, "CRASH"),
        (ProcState.EXITED, 128 + signal.SIGABRT, None, "CRASH"),
        (ProcState.EXITED, 128 + signal.SIGILL, None, "CRASH"),
        (ProcState.EXITED, 128 + signal.SIGKILL, None, "NO_CRASH"),
        (ProcState.SIGNALED, None, signal.SIGSEGV, "CRASH"),
        (ProcState.SIGNALED, None, signal.SIGABRT, "CRASH"),
        (ProcState.SIGNALED, None, signal.SIGILL, "CRASH"),
        (ProcState.SIGNALED, None, signal.SIGTERM, "NO_CRASH"),
        (ProcState.TIMEOUT, None, None, "UNKNOWN"),
        (ProcState.SPAWN_ERROR, None, None, "UNKNOWN"),
    ],
)
def test_classify_is_tri_state(state, rc, sig, expected):
    result = ProcResult(state, rc=rc, signal=sig)
    assert offset_finder.classify(result).name == expected


# --- the adapters ----------------------------------------------------------


@needs_bwrap
@pytest.mark.parametrize(
    "binary, method, payload, args, expected",
    [
        ("/bin/cat", "stdin", b"hello\x00world", [], b"hello\x00world"),
        ("/bin/echo", "stdin", b"ignored", ["a", "b"], b"a b\n"),
        ("/bin/echo", "argv", b"AAAA", [], b"AAAA\n"),
        ("/bin/cat", "file", b"\xff\x00AB\n", [], b"\xff\x00AB\n"),
    ],
)
def test_run_target_adapts_stdin_argv_and_file_input(
    binary, method, payload, args, expected
):
    finder = OffsetFinder(binary)
    res = finder._run_target(payload, method, args, 30.0)
    assert res.state is ProcState.EXITED and res.rc == 0, res.stderr
    assert res.isolation == "bwrap"
    assert res.stdout == expected


@needs_bwrap
def test_file_input_is_an_absolute_path_in_the_private_workspace():
    res = OffsetFinder("/bin/echo")._run_target(b"x", "file", [], 30.0)
    path = res.stdout.decode().strip()
    assert re.fullmatch(r"/tmp/supwngo-offset-[^/]+/input\.bin", path), path


@needs_bwrap
def test_run_target_times_out_and_says_so():
    res = OffsetFinder("/bin/sleep")._run_target(b"", "stdin", ["30"], 1.0)
    assert res.state is ProcState.TIMEOUT
    assert res.isolation == "bwrap"
    assert res.wall_s < 20


# --- isolation, and the private workspace ----------------------------------


@needs_gcc
@needs_gdb
@needs_bwrap
@pytest.mark.parametrize("location", ["tmp", "var_tmp"])
def test_gdb_runs_under_bwrap_with_its_files_in_the_workspace(
    tmp_path, var_tmp_dir, monkeypatch, no_outer, location
):
    """RED on the base: no sandbox, and the pattern and script sit in host /tmp.

    ``var_tmp`` puts the binary where the sandbox's ``/tmp`` tmpfs cannot hide
    it; ``tmp`` puts it where only a bind makes it visible.
    """
    binary = build_asm_crash((tmp_path if location == "tmp" else var_tmp_dir) / "bin")
    made = record_workspaces(monkeypatch)
    recorded = []
    real_run = sandbox.run

    def recording(argv, **kwargs):
        script = None
        if "-x" in argv:
            script = Path(argv[argv.index("-x") + 1]).read_text()
        recorded.append((list(argv), script))
        return real_run(argv, **kwargs)

    monkeypatch.setattr(sandbox, "run", recording)

    result = OffsetFinder(binary).find_offset(max_length=256)

    assert getattr(result, "isolation", None) == "bwrap"
    assert result.success, result.error
    assert result.method.startswith("GDB - "), result.method  # not a fall-through
    assert result.offset == CRASH_OFFSET
    assert len(made) == 1
    workspace = made[0]
    gdb_calls = [item for item in recorded if item[0][0] == "gdb"]
    assert gdb_calls, "gdb did not go through sandbox.run"
    argv, script = gdb_calls[0]
    assert argv[argv.index("-x") + 1].startswith(workspace + "/")
    pattern = re.search(r"< (\S+)", script).group(1)
    assert pattern.startswith(workspace + "/")


@needs_gcc
@needs_bwrap
def test_bisect_runs_under_bwrap_when_gdb_is_unavailable(tmp_path, no_outer):
    """RED on the base: no sandbox. The value is recorded, not asserted: bisect
    is approximate by design; this proves the route."""
    finder = OffsetFinder(build_asm_crash(tmp_path))
    finder._gdb_available = False
    result = finder.find_offset(max_length=256)
    assert getattr(result, "isolation", None) == "bwrap"
    assert result.success, result.error
    assert result.method.startswith("Binary search"), result.method
    print("bisect offset (source distance %d): %r" % (CRASH_OFFSET, result.offset))


@needs_gcc
def test_one_private_workspace_per_call_and_it_is_removed(
    tmp_path, monkeypatch, no_outer
):
    """RED on the base: it has no workspace; the pattern goes to the host /tmp."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("TMPDIR", str(elsewhere))  # must not move the workspace
    made = record_workspaces(monkeypatch)
    finder = OffsetFinder(build_asm_crash(tmp_path / "bin"))
    for call in (1, 2):
        finder.find_offset(max_length=128)
        assert len(made) == call, made
        assert os.path.dirname(made[-1]) == "/tmp"
        assert not os.path.exists(made[-1]), "workspace left behind"
    assert made[0] != made[1]


def test_binary_path_is_absolute(tmp_path, monkeypatch):
    """RED on the base: the path is kept as given."""
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "target").write_bytes(b"x")
    monkeypatch.chdir(tmp_path / "bin")
    finder = OffsetFinder("./../bin/target")
    assert finder.binary_path == (tmp_path / "bin" / "target").resolve()
    assert finder.binary_path.is_absolute()


# --- isolation labels ------------------------------------------------------


@needs_bwrap
def test_isolation_is_bwrap_when_the_sandbox_works(tmp_path, monkeypatch, no_outer):
    binary = build_asm_crash(tmp_path)
    assert OffsetFinder(binary).isolation == "bwrap"
    # Outer markers do not demote a sandbox this process built itself.
    monkeypatch.setenv("SUPWNGO_OUTER_SANDBOX", "1")
    monkeypatch.setenv("SUPWNGO_HOST_PIDNS", "pid:[1]")
    assert OffsetFinder(binary).isolation == "bwrap"


def test_no_sandbox_forces_none_even_with_outer_markers(tmp_path, monkeypatch):
    binary = build_asm_crash(tmp_path)
    monkeypatch.setenv("SUPWNGO_OUTER_SANDBOX", "1")
    monkeypatch.setenv("SUPWNGO_HOST_PIDNS", "pid:[1]")
    assert OffsetFinder(binary, use_sandbox=False).isolation == "none"


def _same_namespace():
    return os.readlink("/proc/self/ns/pid")


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
    tmp_path, monkeypatch, marker, host_ns, expected
):
    binary = build_asm_crash(tmp_path)
    monkeypatch.setattr(sandbox, "available", lambda: False)  # nested bwrap failed
    monkeypatch.delenv("SUPWNGO_OUTER_SANDBOX", raising=False)
    monkeypatch.delenv("SUPWNGO_HOST_PIDNS", raising=False)
    if marker is not None:
        monkeypatch.setenv("SUPWNGO_OUTER_SANDBOX", marker)
    if host_ns is not None:
        monkeypatch.setenv(
            "SUPWNGO_HOST_PIDNS", _same_namespace() if host_ns == "SAME" else host_ns
        )
    assert OffsetFinder(binary).isolation == expected


@needs_gdb
def test_a_failed_nested_sandbox_runs_with_the_label_the_harness_earns(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(sandbox, "available", lambda: False)
    monkeypatch.setenv("SUPWNGO_OUTER_SANDBOX", "1")
    monkeypatch.setenv("SUPWNGO_HOST_PIDNS", "pid:[1]")
    result = OffsetFinder(build_asm_crash(tmp_path)).find_offset(max_length=256)
    assert result.success, result.error
    assert result.isolation == "outer"
    assert result.offset == CRASH_OFFSET


@needs_gdb
def test_a_dotted_directory_cannot_be_sandboxed_and_says_so(tmp_path, no_outer):
    """The sandbox rejects '.'-prefixed components, so the run is unsandboxed and
    the result says "none" rather than claiming a boundary that is not there."""
    binary = build_asm_crash(tmp_path / ".hidden" / "bin")
    finder = OffsetFinder(binary)
    assert finder.isolation == "none"
    result = finder.find_offset(max_length=256)
    assert result.success, result.error
    assert result.isolation == "none"
    assert result.offset == CRASH_OFFSET


def test_a_dotted_directory_under_an_outer_sandbox_is_outer(tmp_path, monkeypatch):
    monkeypatch.setenv("SUPWNGO_OUTER_SANDBOX", "1")
    monkeypatch.setenv("SUPWNGO_HOST_PIDNS", "pid:[1]")
    binary = build_asm_crash(tmp_path / ".hidden" / "bin")
    assert OffsetFinder(binary).isolation == "outer"


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
    assert offset_finder._sandbox_fits(directory) is fits


# --- the sandbox earns its keep --------------------------------------------


@needs_gcc
@needs_bwrap
def test_no_process_outlives_a_run_under_bwrap(tmp_path, no_outer):
    """RED on the base: a setsid grandchild survives the run."""
    binary = build_c(tmp_path / "bin", "fork_sleeper", FORK_SLEEPER_C)

    # Control: the carrier works, i.e. unsandboxed the grandchild does survive.
    control = "ctl" + uuid.uuid4().hex
    try:
        subprocess.run([str(binary), control], timeout=30, check=True)
        assert wait_until(lambda: pids_with(control)), "control: no survivor"
    finally:
        kill_all(control)

    token = "tok" + uuid.uuid4().hex
    try:
        result = OffsetFinder(binary).find_offset(max_length=64, args=[token])
        assert wait_until(
            lambda: not pids_with(token), seconds=10.0
        ), "setsid grandchildren survived: %r" % pids_with(token)
        assert getattr(result, "isolation", None) == "bwrap"
    finally:
        kill_all(token)


@needs_gcc
@needs_bwrap
def test_a_path_passed_in_hide_is_not_readable_by_the_target(
    tmp_path, var_tmp_dir, monkeypatch, no_outer
):
    """RED on the base: nothing is hidden, so the target opens the secret.

    The finder passes no ``hide`` itself; a wrapper injects one, which is how the
    passcard hides its answer keys. On the base the wrapper is never called.
    """
    secret = var_tmp_dir / "secret"
    secret.write_text("answer")
    binary = build_c(tmp_path / "bin", "probe", PROBE_C)
    out = tmp_path / "bin" / "verdict"

    def verdict():
        out.unlink(missing_ok=True)
        finder = OffsetFinder(binary)
        finder._gdb_available = False  # a few cheap runs are enough
        finder.find_offset(max_length=16, args=[str(secret), str(out)])
        return out.read_text() if out.exists() else None

    # Control: without a hide the secret is readable inside the sandbox.
    assert verdict() == "opened"

    real_run = sandbox.run

    def hiding(argv, **kwargs):
        kwargs["hide"] = [str(var_tmp_dir)]
        return real_run(argv, **kwargs)

    monkeypatch.setattr(sandbox, "run", hiding)
    assert verdict() == "denied"
    assert secret.read_text() == "answer"


# --- preflight first -------------------------------------------------------


def _refuse_to_run(monkeypatch):
    def boom(self, *args, **kwargs):
        raise AssertionError(
            "a target or gdb run was attempted after a failed preflight"
        )

    monkeypatch.setattr(OffsetFinder, "_exec", boom, raising=False)


@needs_gcc
def test_missing_relative_interpreter_is_reported_with_its_path(tmp_path, monkeypatch):
    """RED on the base: "Could not determine offset with any method"."""
    binary = build_asm_crash(tmp_path, interp="./nope/ld.so")
    _refuse_to_run(monkeypatch)
    result = OffsetFinder(binary).find_offset(max_length=64)
    assert result.success is False
    assert result.error_code == "target_not_executable"
    assert "interp_missing" in result.error
    assert "./nope/ld.so" in result.error


@needs_gcc
def test_zero_byte_relative_loader_is_reported(tmp_path, monkeypatch):
    """RED on the base: "Could not determine offset with any method"."""
    binary = build_asm_crash(tmp_path, interp="./ld/ld.so")
    (tmp_path / "ld").mkdir()
    (tmp_path / "ld" / "ld.so").write_bytes(b"")
    _refuse_to_run(monkeypatch)
    result = OffsetFinder(binary).find_offset(max_length=64)
    assert result.success is False
    assert result.error_code == "target_not_executable"
    assert "interp_empty" in result.error
    assert "./ld/ld.so" in result.error


@needs_gcc
@needs_gdb
@needs_host_loader
def test_relative_interpreter_resolves_from_the_binary_directory(
    tmp_path, monkeypatch, no_outer
):
    """RED on the base: a relative interpreter is looked up from the caller's
    working directory, so the target cannot even be exec'd."""
    chal = tmp_path / "chal"
    binary = build_asm_crash(chal, interp="./ld/ld.so")
    copy_host_loader(chal / "ld" / "ld.so")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    # Control: the fixture really does crash when run from its own directory.
    direct = subprocess.run(
        ["./crash"], cwd=str(chal), input=b"A" * 200, capture_output=True, timeout=30
    )
    assert direct.returncode == -signal.SIGSEGV

    finder = OffsetFinder(os.path.relpath(binary, elsewhere))
    result = finder.find_offset(max_length=256)
    assert result.success, result.error
    assert result.offset == CRASH_OFFSET


def test_a_pe_is_refused_before_any_run(monkeypatch):
    _refuse_to_run(monkeypatch)
    result = OffsetFinder(PE_SYM).find_offset(max_length=64)
    assert result.success is False
    assert result.error_code == "unsupported_format"
    assert result.isolation in ("bwrap", "outer", "none")


# --- core dumps ------------------------------------------------------------


@pytest.fixture
def cores_enabled():
    """Raise the soft core limit (the conftest zeroes it) for one test."""
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (hard, hard))
    yield
    resource.setrlimit(resource.RLIMIT_CORE, (soft, hard))


@needs_gcc
@needs_gdb
def test_stale_core_in_the_working_directory_is_not_analysed(
    tmp_path, monkeypatch, no_outer
):
    """RED on the base: it scans ``Path(".")`` after the run and analyses
    whatever ``core*`` it finds there, however old."""
    binary = build_asm_crash(tmp_path / "bin")
    pattern = offset_finder.PatternGenerator().generate(128, n=8)
    stale_dir = tmp_path / "elsewhere"
    stale = make_core(binary, stale_dir, pattern)
    if stale is None:
        pytest.skip("this host writes no core file")
    monkeypatch.chdir(stale_dir)

    finder = unsandboxed_finder(binary)
    # Control: the stale core is analysable, so ignoring it is a choice.
    assert finder._analyze_core(stale, pattern).success

    monkeypatch.setattr(
        finder,
        "_find_with_gdb",
        lambda *a, **k: OffsetResult(success=False, error="gdb off"),
    )
    result = finder.find_offset(max_length=128)
    assert not result.method.startswith("Core dump"), result.method


@needs_gcc
def test_core_scan_is_limited_to_the_binary_directory(tmp_path, monkeypatch):
    """RED on the base: it globs a temp directory, ``.`` and the global /tmp."""
    binary = build_asm_crash(tmp_path)
    seen = []
    real_glob = Path.glob

    def recording(self, pattern, *args, **kwargs):
        seen.append((str(self), pattern))
        return real_glob(self, pattern, *args, **kwargs)

    monkeypatch.setattr(Path, "glob", recording)
    finder = unsandboxed_finder(binary)
    finder._find_with_coredump(128, "stdin", [])
    core_roots = {root for root, pattern in seen if pattern.startswith("core")}
    assert core_roots <= {str(binary.parent)}, core_roots


@needs_gcc
@needs_gdb
def test_only_this_runs_core_is_analysed_and_removed(tmp_path, no_outer, cores_enabled):
    binary = build_asm_crash(tmp_path)
    older = tmp_path / "core"
    older.write_bytes(b"not mine")
    finder = unsandboxed_finder(binary)
    result = finder._find_with_coredump(128, "stdin", [])
    if not result.success and result.error == "No core dump found":
        pytest.skip("this host writes no core file")
    assert result.success, result.error
    assert result.method.startswith("Core dump")
    assert result.offset == CRASH_OFFSET
    assert older.read_bytes() == b"not mine"  # a core that was there before: left alone
    assert [p.name for p in tmp_path.glob("core*")] == ["core"]  # this run's is gone


@needs_gcc
@needs_bwrap
def test_core_method_is_skipped_under_bwrap(tmp_path, monkeypatch, no_outer):
    """RED on the base: it runs the target and looks for a core."""
    binary = build_asm_crash(tmp_path)
    finder = OffsetFinder(binary)

    def boom(self, *args, **kwargs):
        raise AssertionError("the target was run although the method is skipped")

    monkeypatch.setattr(OffsetFinder, "_run_target", boom, raising=False)
    result = finder._find_with_coredump(128, "stdin", [])
    assert result.success is False
    assert result.error == "method_skipped: core (sandboxed)"


# --- a target that never ends ----------------------------------------------


@needs_gcc
@needs_bwrap
def test_a_target_that_spins_on_eof_ends_in_a_timeout_error(
    tmp_path, monkeypatch, no_outer
):
    """RED on the base: every probe that timed out reads as "no crash", so it ends
    in "No crash detected at any length" with no error code."""
    unique = "eofspin-" + uuid.uuid4().hex
    binary = build_c(tmp_path / unique, "eof_spin", EOF_SPIN_C)
    fast_budgets(monkeypatch, binary, 1.5)
    try:
        result = OffsetFinder(binary).find_offset(max_length=64)
        assert wait_until(
            lambda: not pids_with(unique), seconds=10.0
        ), "the spinning target outlived the run: %r" % pids_with(unique)
        assert result.success is False
        assert result.error_code == "timeout"
        assert result.offset is None
        assert getattr(result, "isolation", None) == "bwrap"
    finally:
        kill_all(unique)


# --- the result schema -----------------------------------------------------


def test_result_carries_kind_error_code_and_isolation():
    failed = OffsetResult(success=False, error="x", error_code="timeout")
    as_dict = failed.to_dict()
    assert as_dict["kind"] == "buf_to_ret"
    assert as_dict["error_code"] == "timeout"
    assert as_dict["isolation"] == ""
    ok = OffsetResult(offset=8, success=True, isolation="bwrap").to_dict()
    assert ok["error_code"] == "" and ok["isolation"] == "bwrap"


# --- the gdb probe ---------------------------------------------------------

LOGGER = "supwngo.exploit.offset_finder"


def probe_gdb(monkeypatch, tmp_path, *, installed=True, run=None):
    """Build a finder with ``shutil.which("gdb")`` and the ``gdb --version`` probe
    scripted. Returns ``(finder, probes)``; ``probes`` holds the keyword arguments
    of each probe call. ``run(argv, **kwargs)`` stands in for ``subprocess.run``.
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
    return unsandboxed_finder(tmp_path / "target"), probes


def answered(returncode=0, stderr=b""):
    return lambda argv, **kwargs: subprocess.CompletedProcess(
        argv, returncode, b"GNU gdb\n", stderr
    )


def raising(exc):
    def run(argv, **kwargs):
        raise exc

    return run


def warnings_of(caplog):
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER and r.levelno == logging.WARNING
    ]


def test_gdb_probe_budget_is_a_named_constant_of_at_least_30_seconds():
    """RED on the base: a hard-coded 5 s, with no constant to read."""
    assert getattr(offset_finder, "GDB_PROBE_TIMEOUT_S", 0) >= 30


def test_the_probe_is_given_the_named_budget(monkeypatch, tmp_path):
    """RED on the base: it passes a literal 5, whatever the constant says."""
    monkeypatch.setattr(offset_finder, "GDB_PROBE_TIMEOUT_S", 7.0, raising=False)
    finder, probes = probe_gdb(monkeypatch, tmp_path, run=answered())
    assert finder._gdb_available is True
    assert [p.get("timeout") for p in probes] == [7.0]


@pytest.mark.parametrize(
    "run, reason",
    [
        (
            raising(subprocess.TimeoutExpired(["gdb", "--version"], 30)),
            "timed out",
        ),
        (raising(OSError(8, "Exec format error")), "Exec format error"),
        (answered(returncode=3, stderr=b"gdb: broken install\n"), "broken install"),
    ],
    ids=["timeout", "oserror", "nonzero"],
)
def test_a_gdb_that_is_found_but_will_not_answer_is_warned_about(
    monkeypatch, tmp_path, caplog, run, reason
):
    """RED on the base: the failure is swallowed, so gdb is silently off and the
    search falls back to the less exact bisect with nothing said."""
    caplog.set_level(logging.WARNING, logger=LOGGER)
    finder, _ = probe_gdb(monkeypatch, tmp_path, run=run)
    assert finder._gdb_available is False
    messages = warnings_of(caplog)
    assert len(messages) == 1, messages
    assert "gdb" in messages[0]
    assert reason in messages[0], messages[0]


def test_a_gdb_that_is_not_installed_is_off_without_a_warning(
    monkeypatch, tmp_path, caplog
):
    """RED on the base: it runs the version probe anyway instead of checking
    ``shutil.which`` first."""
    caplog.set_level(logging.WARNING, logger=LOGGER)
    finder, probes = probe_gdb(monkeypatch, tmp_path, installed=False, run=answered())
    assert finder._gdb_available is False
    assert probes == []
    assert warnings_of(caplog) == []


def test_a_gdb_that_answers_is_on_without_a_warning(monkeypatch, tmp_path, caplog):
    """A control: the healthy path is unchanged and quiet."""
    caplog.set_level(logging.WARNING, logger=LOGGER)
    finder, probes = probe_gdb(monkeypatch, tmp_path, run=answered())
    assert finder._gdb_available is True
    assert len(probes) == 1
    assert warnings_of(caplog) == []
