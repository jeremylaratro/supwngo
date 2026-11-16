"""W-3 step 3, batch 4: the generated-script ("G") oracle snippet.

Design: ``docs/plans/2026-11-15-w3-success-detection-design.md`` section 2.4
("Generated scripts (G)"). The five G-executors (W-0106/0108/0116/0118/0124)
can no longer carry a hand-rolled platform ``FLAG_RE``: a standalone script the
operator runs later cannot import the product, so the canonical oracle *emits* a
self-contained snippet of source that each generator embeds. This module proves
the emitted snippet, run inside such a script, does exactly what ``check()`` does
on the two tiers a generated script needs:

  (a) matches the neutral flag shape (``SUPWNGO_FLAG_RE`` overrides it);
  (b) applies the per-match anti-echo filter -- a flag that also occurs in the
      bytes the script sent to the target is dropped;
  (c) for weak_prng's shell path, confirms a shell ONLY on an un-echoable answer
      (arithmetic / strict marker / ``uid=``); a reflected token never counts.

Pure Python: the snippet is executed via ``exec`` in a fresh namespace holding
only ``os`` and ``re`` (exactly what a generated script imports). No network, no
target binary, no real shell.
"""

from __future__ import annotations

import os
import re
from typing import Callable, Dict, Tuple

import pytest

from supwngo.core.success_oracle import (
    ARITH_MARK,
    ARITH_PROBE,
    FLAG_RE_ENV,
    NEUTRAL_FLAG_SHAPE,
    emit_flag_match_snippet,
    strict_marker,
    strict_probe,
)


def _load(env_value: str | None = None) -> Tuple[Callable, Callable]:
    """Exec the emitted snippet in a generated-script-like namespace.

    The namespace holds only ``os`` and ``re`` -- the two modules every
    ``build_script`` output imports -- so a snippet that reached for anything
    else would ``NameError`` here, which is the property a standalone script
    needs. The ``SUPWNGO_FLAG_RE`` env is read by the snippet at call time, so it
    is set on ``os.environ`` for the duration of the test.
    """
    ns: Dict[str, object] = {"os": os, "re": re}
    exec(emit_flag_match_snippet(), ns)
    return ns["_oracle_flag_hits"], ns["_oracle_shell_proven"]  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# (a) neutral-shape matching


def test_snippet_is_pure_and_names_no_platform_token():
    text = emit_flag_match_snippet()
    # The neutral shape is interpolated from the one exempt constant, never a
    # fresh flag/platform literal, so the emitted text carries no platform word.
    for token in ("htb", "picoctf", "csaw", "hackthebox", "flag{", "ctf{"):
        assert token not in text.lower()
    # It defines exactly the two helpers the G-executors call.
    assert "def _oracle_flag_hits(" in text
    assert "def _oracle_shell_proven(" in text


def test_snippet_matches_neutral_shape_bytes_and_text():
    flag_hits, _ = _load()
    # bytes output (oob_read / weak_prng / symlink / toctou work in bytes)
    assert flag_hits(b"noise X{abcd1234} more") == ["X{abcd1234}"]
    # str output (path_traversal decodes latin-1 before matching)
    assert flag_hits("pre flag{secret_body} post") == ["flag{secret_body}"]
    # the neutral shape requires a 4+ non-space body: a short brace is not a flag
    assert flag_hits(b"X{abc}") == []
    assert flag_hits(b"no braces here") == []


def test_snippet_shape_override_via_env(monkeypatch):
    monkeypatch.setenv(FLAG_RE_ENV, r"ZZZ-[0-9]{4}")
    flag_hits, _ = _load()
    assert flag_hits(b"ticket ZZZ-4242 end") == ["ZZZ-4242"]
    # and the neutral shape no longer applies while the override is set
    assert flag_hits(b"flag{overridden_away}") == []


# ---------------------------------------------------------------------------
# (b) per-match anti-echo


def test_snippet_drops_a_flag_present_in_sent_bytes():
    flag_hits, _ = _load()
    # A flag shape the script itself fed the target is an echo, not a disclosure.
    assert flag_hits(b"out E{abcdef}", b"we sent E{abcdef}") == []
    # A different, non-echoed flag at the same tier still qualifies.
    out = b"echoed E{abcdef} and real R{realbody}"
    assert flag_hits(out, b"we sent E{abcdef}") == ["R{realbody}"]


# ---------------------------------------------------------------------------
# (c) shell proof: reflected token must not count


def test_shell_proof_rejects_echoed_token():
    _, shell_proven = _load()
    token = b"recpt123"
    # The target merely reflected `echo recpt123` -- the bare token is in the
    # output AND in what we sent. That is exactly the echo-foolable case the old
    # `TOKEN in out` check got wrong; it must NOT confirm a shell.
    sent = b"echo recpt123\n"
    assert shell_proven(b"checking echo recpt123", sent, token) is False


def test_shell_proof_accepts_unechoable_answers():
    _, shell_proven = _load()
    token = b"recpt123"
    sent = (
        b"echo recpt123\n"
        + strict_probe("recpt123").encode()
        + b"\n"
        + ARITH_PROBE.encode()
        + b"\nid\n"
    )
    # strict marker: the shell stripped the empty quotes; the sent bytes never
    # contain this form.
    assert strict_marker("recpt123").encode() not in sent
    assert shell_proven(strict_marker("recpt123").encode() + b" ok", sent, token)
    # arithmetic marker: the shell evaluated $((6*7)); SH42OK is never sent.
    assert ARITH_MARK.encode() not in sent
    assert shell_proven(b"xx " + ARITH_MARK.encode() + b" yy", sent, token)
    # uid= needs no token at all.
    assert shell_proven(b"uid=0(root) gid=0", sent, None)


def test_shell_proof_drops_an_unechoable_marker_we_sent():
    _, shell_proven = _load()
    # Defensive: even a shell-only marker is dropped if it was in the sent bytes
    # (so a target echoing a crafted SH42OK cannot fake a shell).
    assert shell_proven(ARITH_MARK.encode(), ARITH_MARK.encode(), None) is False


# ---------------------------------------------------------------------------
# The weak_prng (W-0124) generated script actually embeds the snippet and the
# shell-proof probe, and no longer the echo-foolable `TOKEN in out`.


def test_weak_prng_script_embeds_snippet_and_shell_proof():
    from supwngo.exploit.pipeline.executors.weak_prng_techniques import (
        _PrngPlan,
        build_replay_script,
    )

    plan = _PrngPlan(generators=["rand"], bases=[10])
    script = build_replay_script("/bin/true", plan)

    compile(script, "weak_prng_generated.py", "exec")  # it is runnable Python
    assert "def _oracle_flag_hits(" in script
    assert "def _oracle_shell_proven(" in script
    # the win path routes through the oracle, not a hand-rolled regex
    assert "_oracle_flag_hits(out, bytes(SENT))" in script
    assert "_oracle_shell_proven(out, bytes(SENT), TOKEN)" in script
    # the echo-foolable confirmation is gone, and the arithmetic probe is in
    assert "TOKEN in out" not in script
    assert ARITH_MARK in script  # SH42OK, keyed on in the snippet
    # no platform flag literal survives in the emitted text
    for token in ("picoCTF", "HTB", r"flag\{", r"FLAG\{"):
        assert token not in script


def test_weak_prng_default_probe_is_shell_proof_not_a_bare_token():
    """Run standalone (no verifier stdin), the script sends its OWN shell-proof
    probe. A bare `echo <token>` default would be echo-foolable; the arithmetic
    probe is not."""
    from supwngo.exploit.pipeline.executors.weak_prng_techniques import (
        _PrngPlan,
        build_replay_script,
    )

    script = build_replay_script("/bin/true", _PrngPlan(generators=["rand"]))
    assert ARITH_PROBE in script  # SH$((6*7))OK as the default stdin probe
    assert "echo supwngo_shell_probe" not in script
