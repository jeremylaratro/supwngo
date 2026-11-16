"""W-3 batch 3 seam tests.

Covers the two behaviours this batch is responsible for (design
``docs/plans/2026-11-15-w3-success-detection-design.md`` §2.1/§2.4, §6 step 3):

(a) the executor pre-screens accept the oracle's neutral flag SHAPE and reject
    plain text / bare banner words / an echoed shape; and
(b) the migrated ``remote/interaction.py`` shell test proves a shell only from
    an un-echoed oracle probe answer, never from a reflected token or ``PWNED``.

No network / no real process: fake tubes and the pure-stdlib oracle only.
"""

from supwngo.core.success_oracle import ARITH_MARK, strict_marker
from supwngo.exploit.pipeline.executors.input_shape_techniques import (
    NegativeIndexWriteExecutor,
)
from supwngo.exploit.pipeline.executors.loop_counter_techniques import (
    _looks_like_flag,
)
from supwngo.remote.interaction import ConnectionConfig, RemoteInteraction


# ---------------------------------------------------------------------------
# (a) pre-screens: neutral shape true, plain text false
# ---------------------------------------------------------------------------


def test_loop_counter_prescreen_shape_vs_plain():
    # Neutral flag SHAPE (word{>=4 non-space}) is accepted; it names no platform.
    assert _looks_like_flag("result: NEUTRAL{abcd1234}") is True
    # Plain text with no shape is not a hit.
    assert _looks_like_flag("segmentation fault (core dumped)") is False
    # A platform-literal is matched only as the generic shape, never by name.
    assert _looks_like_flag("flag{aaaa}") is True


def test_input_shape_prescreen_shape_banner_and_echo():
    win = NegativeIndexWriteExecutor._looks_like_win
    # Neutral shape on un-sent output -> hit.
    assert win("WIN{abcd1234}", b"") is True
    # Plain text -> miss.
    assert win("try again", b"") is False
    # Bare banner words are no longer a success signal (design §2.1/B3).
    assert win("congratulations, you win! access granted", b"") is False
    # Anti-echo: a shape reflected from the bytes we delivered is dropped.
    assert win("WIN{abcd1234}", b"0\nWIN{abcd1234}\n") is False


# ---------------------------------------------------------------------------
# (b) remote shell test: un-echoed proof vs reflecting decoy
# ---------------------------------------------------------------------------


class _ShellTube:
    """A fake tube backed by a real shell: it *computes* probe answers, so the
    strict marker and the arithmetic answer appear un-echoed in the output."""

    def __init__(self):
        self._outbox = []

    def sendline(self, data: bytes):
        if data == b"id":
            self._outbox.append(b"uid=1000(op) gid=1000(op) groups=1000(op)\n")
        elif data.startswith(b"echo "):
            arg = data[len(b"echo "):]
            # Emulate the shell: strip the empty quotes, evaluate $((6*7)).
            out = arg.replace(b'""', b"").replace(b"$((6*7))", b"42")
            self._outbox.append(out + b"\n")
        else:
            self._outbox.append(b"\n")

    def recv(self, numb: int = 4096, timeout=None) -> bytes:
        return self._outbox.pop(0) if self._outbox else b""


class _EchoTube:
    """An echo-foolable decoy: it reflects every byte sent (so the token is
    echoed back verbatim) and even prints a bare ``PWNED`` banner. Neither can
    produce the un-echoed strict marker or the arithmetic answer."""

    def __init__(self):
        self._outbox = []

    def sendline(self, data: bytes):
        self._outbox.append(data + b"\n")   # reflect input verbatim
        self._outbox.append(b"PWNED\n")     # adversarial banner

    def recv(self, numb: int = 4096, timeout=None) -> bytes:
        return self._outbox.pop(0) if self._outbox else b""


def _make_interaction(tube) -> RemoteInteraction:
    ri = RemoteInteraction.__new__(RemoteInteraction)
    ri._tube = tube
    ri.config = ConnectionConfig()
    ri._is_remote = True
    return ri


def test_get_shell_true_on_unechoed_probe_answer():
    ri = _make_interaction(_ShellTube())
    assert ri.get_shell() is True


def test_get_shell_false_on_reflecting_decoy():
    ri = _make_interaction(_EchoTube())
    assert ri.get_shell() is False


def test_oracle_probe_markers_are_not_in_the_sent_bytes():
    """Guard the anti-echo property the fakes rely on: the shell forms of the
    probes never appear in what we send, so a reflector cannot forge them."""
    token = "deadbeefdeadbeef"
    sent = b'id\necho ' + token.encode() + b'""_STRICT\necho SH$((6*7))OK\n'
    assert strict_marker(token).encode() not in sent
    assert ARITH_MARK.encode() not in sent
