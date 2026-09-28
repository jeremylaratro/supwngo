"""Red-proofs for the shell-only markers in verify_script.

These tests exist because the oracle they guard was WRONG once already (I-16: a
target that merely echoes its input was credited with a shell). The rule that
follows from that, and that this file enforces, is that every marker must be shown
to go RED on a non-shell before it is trusted to go green on a shell.

Each marker gets three cases:

  * positive control -- a real `/bin/sh` answers it,
  * negative control -- a pure echo of the same bytes does NOT answer it,
  * the environment the marker specifically claims to survive.

The third case is the one that matters for `_ARITH_MARK`: an SROP or syscall-chain
exploit reaches `execve("/bin/sh", NULL, NULL)`, giving a shell with no PATH. `id`
does not exist in that shell. A test suite that only ever ran markers under a
normal login environment could not tell the difference.
"""

import subprocess

from supwngo.exploit.pipeline.verifier import _ARITH_MARK, _ARITH_PROBE


def _sh(stdin: str, env: dict) -> str:
    """Run /bin/sh with an EXACT environment (no inheritance) and return its output."""
    return subprocess.run(
        ["/bin/sh"],
        input=stdin.encode(),
        capture_output=True,
        timeout=20,
        env=env,
    ).stdout.decode(errors="replace")


PROBES = f'echo TOKZ\nid\necho TOKZ""_STRICT\necho {_ARITH_PROBE}\n'


def test_arith_marker_is_answered_by_a_real_shell():
    """Positive control: without this, a red result below proves nothing."""
    out = _sh(PROBES, {"PATH": "/usr/bin:/bin"})
    assert _ARITH_MARK in out


def test_arith_marker_survives_a_shell_with_no_usable_path():
    """The claim the marker was adopted for -- and the case `id` fails.

    This is the null-envp shell an SROP chain produces. Asserting only that the
    arithmetic marker appears would be a half test, so this also asserts that `id`
    genuinely FAILS here: that is what makes the arithmetic marker load-bearing
    rather than redundant, and if some future libc made `id` resolvable anyway the
    assertion below would fail loudly instead of the rationale rotting silently.
    """
    out = _sh(PROBES, {"PATH": ""})
    assert _ARITH_MARK in out, "arithmetic expansion needs no PATH and must still work"
    assert "uid=" not in out, (
        "`id` unexpectedly resolved with an empty PATH -- the stated reason for "
        "adopting the arithmetic marker no longer holds; re-measure before trusting it"
    )


def test_arith_marker_is_not_produced_by_echoing_the_probe_back():
    """Negative control: the I-16 failure mode, applied to the new marker.

    `cat` stands in for a target that reflects its input. It reproduces the probe
    bytes exactly -- and those bytes do not contain the answer, which is the whole
    reason this marker is sound.
    """
    reflected = subprocess.run(
        ["cat"], input=PROBES.encode(), capture_output=True, timeout=20
    ).stdout.decode()
    assert _ARITH_PROBE in reflected, (
        "guard for the guard: if the probe text itself were absent from the "
        "reflection, the assertion below would pass vacuously"
    )
    assert _ARITH_MARK not in reflected
    assert "uid=" not in reflected
    assert "TOKZ_STRICT" not in reflected


def test_the_answer_is_never_in_the_bytes_we_send():
    """A marker whose answer we transmit is not a marker. Cheap, but it is exactly
    the mistake probes 1-2 make, so it is worth asserting rather than assuming."""
    assert _ARITH_MARK not in PROBES
