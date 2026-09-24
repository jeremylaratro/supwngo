"""Tests for the ``pwn`` import hazard that the root ``conftest.py`` defuses.

The defect is not a crash, it is a **silently wrong answer that persists for the
rest of the process**. ``pwnlib/term/text.py`` calls ``curses.setupterm()`` at
module scope, guarded only by ``except curses.error`` -- which does not catch the
``io.UnsupportedOperation: fileno`` raised when ``sys.stdout`` has no file
descriptor, as under ``click.testing.CliRunner``. The aborted import evicts the
half-built ``pwnlib`` from ``sys.modules`` while leaving its finished submodules
cached, so every later ``import pwn`` gets a fresh empty ``pwnlib`` whose
submodules are never rebound, and ``from pwnlib import *`` in ``pwn/toplevel.py``
raises ``AttributeError: module 'pwnlib' has no attribute 'context'`` forever.

``supwngo/core/binary.py`` catches that broadly and reports the binary as having
no symbols, so ``rop_chain`` abstains and every target needing a ROP technique
collapses to ``triage``. That is how ten walkthrough tests failed while the code
under test was correct.

These run in subprocesses because the hazard is a property of a *process's*
import state: once poisoned, it cannot be undone in-process, so it cannot be
demonstrated in the session that is asserting it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

#: Reproduce the hazard exactly: make stdout an in-memory stream with no
#: ``fileno()`` -- what ``CliRunner`` installs -- then import ``pwn`` for the
#: first time in the process, exactly as ``supwngo/core/binary.py`` does.
#:
#: The second import, with stdout restored, is the part that matters: it is the
#: *later, innocent* caller that inherits the damage.
_PROBE = textwrap.dedent(
    """
    import io, sys

    real_stdout = sys.stdout
    sys.stdout = io.StringIO()          # no fileno(), like CliRunner's
    first = "ok"
    try:
        from pwn import ELF, context
    except Exception as exc:
        first = f"{type(exc).__name__}: {exc}"
    finally:
        sys.stdout = real_stdout

    second = "ok"
    try:
        from pwn import ELF, context
    except Exception as exc:
        second = f"{type(exc).__name__}: {exc}"

    print("FIRST:", first)
    print("SECOND:", second)
    """
)


def _probe(*, noterm: bool) -> str:
    """Run the import probe in a clean process, with or without the fix."""
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.path.expanduser("~"),
        "TERM": "xterm",
        # Keep the gadget cache out of any shared location for this probe.
        "XDG_CACHE_HOME": "/tmp/supwngo-import-probe-cache",
    }
    if noterm:
        env["PWNLIB_NOTERM"] = "1"
    done = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
    )
    return done.stdout + done.stderr


@pytest.fixture(scope="module", autouse=True)
def _require_pwnlib():
    pytest.importorskip("pwnlib")


def test_in_memory_stdout_poisons_pwnlib_without_the_env_default():
    """The positive control.

    Without this, the test below could pass because the hazard simply does not
    arise on this machine, in which case it would be evidence of nothing. This
    asserts the damage is real *and* that it outlives the import that caused it.
    """
    output = _probe(noterm=False)
    assert "FIRST: UnsupportedOperation: fileno" in output, (
        "the first import did not fail the way the hazard requires, so "
        "test_the_env_default_keeps_pwn_importable_under_in_memory_stdout is "
        f"not demonstrating anything. Output:\n{output}"
    )
    assert "SECOND: AttributeError: module 'pwnlib' has no attribute" in output, (
        "the first import failed but left the process usable, so the "
        "persistent-poisoning half of the defect did not reproduce. "
        f"Output:\n{output}"
    )


def test_the_env_default_keeps_pwn_importable_under_in_memory_stdout():
    """With ``PWNLIB_NOTERM`` set, neither import is harmed."""
    output = _probe(noterm=True)
    assert "FIRST: ok" in output, output
    assert "SECOND: ok" in output, output


def test_conftest_sets_the_defaults_before_any_test_module_is_imported():
    """The fix has to land at conftest *import* time, not in a fixture.

    A fixture runs after collection, and collection imports the test modules --
    any one of which may import ``pwn``. So what matters is that merely importing
    the conftest is enough, with ``pwnlib`` never loaded.

    Checking ``os.environ`` from inside this session would be inert: when
    ``curses.setupterm()`` raises ``curses.error``, ``unix_termcap.init()`` sets
    ``PWNLIB_NOTERM=1`` in ``os.environ`` itself, so the variable is present in
    any session that has imported pwnlib regardless of whether the conftest set
    it. This runs in a child with the variable explicitly absent and asserts
    ``pwnlib`` was never imported, which leaves the conftest as the only possible
    source.
    """
    root = Path(__file__).resolve().parent.parent
    probe = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(root)!r})
        import conftest  # noqa: F401
        import os
        print("NOTERM=", os.environ.get("PWNLIB_NOTERM"))
        print("XDG=", os.environ.get("XDG_CACHE_HOME"))
        print("PWNLIB_LOADED=", "pwnlib" in sys.modules)
        """
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~"), "TERM": "xterm"}
    done = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    output = done.stdout + done.stderr
    assert "PWNLIB_LOADED= False" in output, (
        "pwnlib was imported by the probe, so pwnlib's own curses fallback could "
        f"be the source of PWNLIB_NOTERM and this test proves nothing:\n{output}"
    )
    assert "NOTERM= 1" in output, output
    assert "XDG= None" not in output, output


def test_the_gadget_cache_root_is_not_shared_between_sessions():
    """Two sessions must not resolve to the same pwntools cache directory.

    pwntools writes that file non-atomically and reads it with an uncaught
    ``eval``, so sharing it across concurrent sessions is what makes a suite
    result untrustworthy in both directions.
    """
    context = pytest.importorskip("pwn").context
    cache_dir = str(context.cache_dir)
    assert os.environ["XDG_CACHE_HOME"] in cache_dir, (
        f"pwntools resolved {cache_dir!r}, which is not under this session's "
        f"XDG_CACHE_HOME {os.environ['XDG_CACHE_HOME']!r}"
    )
    assert str(os.getpid()) in cache_dir, (
        f"cache dir {cache_dir!r} is not specific to this session, so a "
        "concurrent session would share it"
    )


def test_conftest_is_at_the_repository_root_so_it_applies_to_every_test():
    """A conftest one directory down would not cover ``tests/`` siblings."""
    root = Path(__file__).resolve().parent.parent
    assert (root / "conftest.py").is_file(), (
        "the env defaults must live in a repository-root conftest.py; pytest "
        "imports it before collecting anything under tests/"
    )
