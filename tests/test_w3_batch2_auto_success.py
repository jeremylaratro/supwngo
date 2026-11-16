"""W-3 batch 2 seam test: the auto-family in-process success checks now decide
success through ``success_oracle.check`` (design 2.1 / 2.4 / 3).

These are L-context, tool-controlled local runs. The test drives a real
migrated function (``AutoExploiter._test_exploit``, a subprocess path — no
pwntools, no network, no real binary) with a fake ``subprocess.run`` and
proves:

(a) a target whose output carries a neutral ``word{...}`` flag shape is a
    success through the migrated path;
(b) a reflecting target that only echoes the bytes we sent — including a
    planted ``word{...}``-shaped value and an ``echo PWNED`` — is NOT a success
    (anti-echo, design 2.4);
(c) a bare banner word ("you win", "congratulations") is NOT a success
    (B3, design 2.1).

A focused check also covers the echo-foolable ret2libc shell test fixed at
``auto.py`` W-0018 (design 3): the shell-proof probe set is credited only for a
real shell, never for a target that reflects the probe commands back.
"""

from __future__ import annotations

import subprocess

import pytest

from supwngo.core import success_oracle
from supwngo.exploit.auto import AutoExploiter


class _FakeBinary:
    def __init__(self, path):
        self.path = path


def _make_exploiter(tmp_path):
    """An ``AutoExploiter`` wired just enough for ``_test_exploit`` (no init)."""
    binary = tmp_path / "vuln"
    binary.write_bytes(b"\x7fELF")
    exp = AutoExploiter.__new__(AutoExploiter)
    exp.binary = _FakeBinary(binary)
    exp._binary_path = str(binary)
    exp.timeout = 1.0
    return exp


class _Completed:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _patch_run(monkeypatch, *, baseline=b"menu> ", on_exploit):
    """Fake ``subprocess.run``: ``on_exploit(payload) -> _Completed`` for the
    exploit run; the baseline run (``input == b"test\\n"``) returns ``baseline``.
    """

    def fake_run(cmd, input=None, capture_output=False, timeout=None, cwd=None, **kw):
        if input == b"test\n":
            return _Completed(stdout=baseline)
        return on_exploit(input)

    monkeypatch.setattr(subprocess, "run", fake_run)


def test_a_neutral_shape_flag_is_success(tmp_path, monkeypatch):
    exp = _make_exploiter(tmp_path)
    _patch_run(
        monkeypatch,
        on_exploit=lambda payload: _Completed(
            stdout=b"nice work, here is win{cafef00d} for you\n"
        ),
    )
    assert exp._test_exploit(b"A" * 64) is True


def test_b_reflecting_target_is_not_success(tmp_path, monkeypatch):
    exp = _make_exploiter(tmp_path)
    # The payload itself carries a qualifying shape and an ``echo PWNED``; a
    # reflecting target echoes exactly these bytes back. Anti-echo must drop
    # every match, so this is NOT a success.
    payload = b"A" * 16 + b"win{deadbeef}" + b" echo PWNED\n"
    _patch_run(
        monkeypatch,
        on_exploit=lambda sent: _Completed(stdout=sent + b"PWNED\n"),
    )
    assert exp._test_exploit(payload) is False


def test_c_bare_banner_word_is_not_success(tmp_path, monkeypatch):
    exp = _make_exploiter(tmp_path)
    for banner in (b"Congratulations!\n", b"you win\n", b"access granted\n"):
        _patch_run(monkeypatch, on_exploit=lambda sent, b=banner: _Completed(stdout=b))
        assert exp._test_exploit(b"A" * 64) is False, banner


def test_a_flag_already_in_baseline_is_not_credited(tmp_path, monkeypatch):
    # A flag the unexploited program always prints is not exploit-induced.
    exp = _make_exploiter(tmp_path)
    _patch_run(
        monkeypatch,
        baseline=b"welcome win{cafef00d}\n",
        on_exploit=lambda sent: _Completed(stdout=b"welcome win{cafef00d}\n"),
    )
    assert exp._test_exploit(b"A" * 64) is False


def test_w0018_shell_probe_rejects_reflection_credits_real_shell():
    """The echo-foolable ``echo PWNED`` test is replaced by shell-proof probes
    (design 3): credited only when the oracle returns the SHELL tier.
    """
    token = "deadbeefcafebabe"
    strict = success_oracle.strict_probe(token).encode()
    arith = b"echo " + success_oracle.ARITH_PROBE.encode()
    sent = b"A" * 32 + strict + b"\n" + arith + b"\n" + b"id\n"

    # Reflecting target: echoes the probe commands (and a planted PWNED). The
    # marker forms never appear un-echoed, so this is NOT the SHELL tier.
    reflected = success_oracle.check(sent + b"PWNED\n", sent, token=token)
    assert reflected.primary_tier != success_oracle.TIER_SHELL
    assert reflected.success is False

    # Real shell: emits the strict marker, the arithmetic answer and uid=.
    real_out = (
        success_oracle.strict_marker(token).encode()
        + b"\n" + success_oracle.ARITH_MARK.encode()
        + b"\nuid=0(root) gid=0(root)\n"
    )
    real = success_oracle.check(real_out, sent, token=token)
    assert real.primary_tier == success_oracle.TIER_SHELL
    assert real.success is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
