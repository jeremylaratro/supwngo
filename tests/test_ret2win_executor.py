"""Focused regression tests for ret2win stack-parity retries."""

from types import SimpleNamespace

from supwngo.exploit.pipeline.contracts import AttemptOutcome
from supwngo.exploit.pipeline.executors.stack_techniques import Ret2WinExecutor


class _Verifier:
    def __init__(self, winning_payload):
        self.winning_payload = winning_payload
        self.payloads = []

    def verify_payload(self, _technique, payload):
        self.payloads.append(payload)
        return SimpleNamespace(success=payload == self.winning_payload)


def _context():
    return SimpleNamespace(
        win_function=("win", 0x401234),
        binary=SimpleNamespace(bits=64),
        offset=40,
        gadgets={"ret": 0x40101A},
    )


def test_ret2win_sweeps_both_stack_parities_and_accepts_unaligned(monkeypatch):
    executor = Ret2WinExecutor()
    monkeypatch.setattr(executor, "_discover_args", lambda *_args: [])
    aligned = b"A" * 40 + (0x40101A).to_bytes(8, "little")
    bare = b"A" * 40
    win = (0x401234).to_bytes(8, "little")
    verifier = _Verifier(bare + win + b"\n")

    record = executor.attempt(_context(), verifier)

    assert verifier.payloads == [aligned + win + b"\n", bare + win + b"\n"]
    assert record.outcome is AttemptOutcome.SUCCESS
    assert record.payload == bare + win
    assert "alignment_ret=no" in record.notes[-1]


def test_ret2win_keeps_first_verified_parity(monkeypatch):
    executor = Ret2WinExecutor()
    monkeypatch.setattr(executor, "_discover_args", lambda *_args: [])
    aligned = (
        b"A" * 40
        + (0x40101A).to_bytes(8, "little")
        + (0x401234).to_bytes(8, "little")
        + b"\n"
    )
    verifier = _Verifier(aligned)

    record = executor.attempt(_context(), verifier)

    assert verifier.payloads == [aligned]
    assert record.outcome is AttemptOutcome.SUCCESS
    assert "alignment_ret=yes" in record.notes[-1]
