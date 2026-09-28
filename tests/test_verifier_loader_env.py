"""`verify_script` must not run the interpreter under the TARGET's loader env.

THE DEFECT, MEASURED
--------------------
`PipelineVerifier.verify_script` launches `[sys.executable, script]` with the
environment `Binary.libc_env()` built for the target — which sets
`LD_LIBRARY_PATH=<challenge>/glibc` so the target loads the libc it was compiled
against. That is right for the target and poisonous for the interpreter::

    LD_LIBRARY_PATH=<challenge>/glibc python3 -c pass
    -> /usr/bin/env: .../libc.so.6: version `GLIBC_2.34' not found

The only symptom that reaches a caller is `script exited rc=127`, which reads as
"the exploit failed". Measured on this tree: of the five HTB challenges shipping a
`glibc/` directory, the ones at **2.27 and 2.39 poison the interpreter** while the
three at **2.35 do not** — so the bug is silent, target-dependent, and looks
exactly like a broken exploit rather than a broken harness.

WHY THIS FILE IS SHAPED THIS WAY
--------------------------------
The interesting assertion is an *absence* ("the env no longer contains
LD_LIBRARY_PATH"), and an absence assertion cannot stand alone — a rename or a
no-op would satisfy it vacuously. So every test here pairs with its opposite:

* a poisoned env must be stripped **and** a harmless env must be left untouched,
  or "strips everything" would pass as "fixes the bug";
* the stripped values must be **republished**, or the fix would silently take the
  shipped libc away from a script that needs it;
* the probe itself is shown to discriminate — the poisoned env really does stop
  `sys.executable`, asserted directly, so the test cannot pass on a host where the
  premise is false.

The poison is synthesised from a real on-disk glibc directory when one exists, and
the test skips rather than faking it if none does: a fabricated `LD_LIBRARY_PATH`
that happens not to break anything would make every assertion here vacuous.
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys

import pytest

from supwngo.exploit.pipeline.verifier import (
    _LOADER_VARS,
    _TARGET_LOADER_PREFIX,
    _interpreter_safe_env,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _poisoning_glibc_dir() -> str | None:
    """A real shipped glibc directory that genuinely stops this interpreter.

    Found by measurement, not by assumption: each candidate is tried and the first
    one that actually breaks `python -c pass` is returned. Returns None when every
    shipped glibc is compatible with the host, in which case the tests that need a
    poison skip — an unbreakable premise must not silently produce green tests.
    """
    for directory in sorted(glob.glob(os.path.join(REPO, "tests", "htb-targets", "*", "*", "glibc"))):
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = directory
        try:
            probe = subprocess.run(
                [sys.executable, "-c", "pass"], env=env, capture_output=True, timeout=30
            )
        except Exception:
            continue
        if probe.returncode != 0:
            return directory
    return None


POISON = _poisoning_glibc_dir()


def test_a_harmless_env_is_left_completely_untouched() -> None:
    """The control half. Without this, "strip everything" would look like a fix.

    Behaviour for a target whose shipped libc works must not change at all,
    because those targets currently rely on INHERITING the loader path: pwntools'
    `process` hands `os.environ` to the child.
    """
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = "/nonexistent-but-harmless"
    cleaned, notes = _interpreter_safe_env(env)

    assert cleaned is env or cleaned == env, (
        "a loader path the interpreter starts fine under must be preserved -- "
        "stripping it would take the shipped libc away from a working target"
    )
    assert notes == [], f"nothing to report, got {notes!r}"


def test_an_env_with_no_loader_vars_is_a_no_op() -> None:
    env = {k: v for k, v in os.environ.items() if k not in _LOADER_VARS}
    cleaned, notes = _interpreter_safe_env(env)
    assert cleaned == env
    assert notes == []


@pytest.mark.skipif(
    POISON is None,
    reason="no shipped glibc on this host actually breaks this interpreter, so the "
           "premise cannot be established and a green result would be vacuous",
)
def test_the_premise_holds_this_env_really_does_break_the_interpreter() -> None:
    """Positive control, asserted FIRST so nothing below can pass vacuously."""
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = POISON
    probe = subprocess.run(
        [sys.executable, "-c", "pass"], env=env, capture_output=True, timeout=30
    )
    assert probe.returncode != 0, (
        f"{POISON} was selected because it broke the interpreter; it no longer "
        "does, so this file's premise is stale and its other assertions mean nothing"
    )


@pytest.mark.skipif(POISON is None, reason="no poisoning glibc available on this host")
def test_a_poisoning_env_is_stripped_and_the_interpreter_then_starts() -> None:
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = POISON
    cleaned, notes = _interpreter_safe_env(env)

    assert "LD_LIBRARY_PATH" not in cleaned, (
        "the variable that stops the interpreter must be removed from the env the "
        "interpreter is launched with"
    )
    # The point is not the absence -- it is that the interpreter now runs.
    probe = subprocess.run(
        [sys.executable, "-c", "pass"], env=cleaned, capture_output=True, timeout=30
    )
    assert probe.returncode == 0, (
        f"stripped the variable and the interpreter still will not start: "
        f"{probe.stderr!r}"
    )
    assert notes, "a silent behaviour change is the thing this note exists to prevent"
    assert "rc=127" not in "".join(notes), "the note should explain, not restate the symptom"


@pytest.mark.skipif(POISON is None, reason="no poisoning glibc available on this host")
def test_the_stripped_value_is_republished_for_the_target() -> None:
    """Stripping without republishing would trade one silent failure for another.

    The target still needs the shipped libc. If the fix merely deleted the path,
    a libc-version-dependent chain would start running against the host libc with
    nothing saying so.
    """
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = POISON
    cleaned, _notes = _interpreter_safe_env(env)

    key = f"{_TARGET_LOADER_PREFIX}LD_LIBRARY_PATH"
    assert cleaned.get(key) == POISON, (
        f"expected the stripped path republished as {key} so a generated script "
        f"can hand it to the child it spawns; got {cleaned.get(key)!r}"
    )


@pytest.mark.skipif(POISON is None, reason="no poisoning glibc available on this host")
def test_the_note_warns_that_inheritance_no_longer_works() -> None:
    """The consequence has to be stated, not just the action.

    A reader who sees "dropped LD_LIBRARY_PATH" and nothing else has no way to know
    that their target is now loading a different libc.
    """
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = POISON
    _cleaned, notes = _interpreter_safe_env(env)
    joined = " ".join(notes).lower()
    assert "inherit" in joined, f"note must say inheritance stopped working: {notes!r}"
    assert "host libc" in joined, f"note must name the consequence: {notes!r}"
