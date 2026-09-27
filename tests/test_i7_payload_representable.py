"""
I-7: an undeliverable candidate must be PRUNED from a sweep, not abort it.

`VariableOverwriteExecutor` sweeps candidate gate constants recovered from the
target, ordered smallest-first. Small values pack with NUL bytes, and an argv
token cannot contain a NUL. Before this fix the executor called
`verify_payload` with no exception handling, so the verifier's correct refusal
propagated out and killed the entire sweep on its first candidate -- the
NUL-free constant that would have won was never reached. Measured on
`benchmark/corpus_vectors/24_ingress_argv_direct`: the whole technique reported
ERROR with an empty `failure_reason`, and the benchmark row read as 0/5, which
is indistinguishable from "the argv transport does not work".

Two claims are protected here:

1. `payload_representable` answers per sink, and is the ONLY place the rule
   lives. Both the verifier (which raises) and the executor (which prunes) ask
   it, so the two can never disagree about what is deliverable.
2. The executor CONTINUES past an unrepresentable candidate and can still win
   on a later one -- and says how many it pruned, because a silently shortened
   search is indistinguishable from an exhausted one.
"""
from __future__ import annotations

import pytest

from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import (
    SINK_ARGV,
    SINK_FILE_ARGV,
    SINK_FILE_FIXED,
    SINK_STDIN,
    AttemptOutcome,
    DeliverySpec,
    payload_representable,
)
from supwngo.exploit.pipeline.executors.stack_techniques import (
    VariableOverwriteExecutor,
)
from supwngo.exploit.pipeline.executors.input_shape_techniques import (
    FALLBACK_MAGIC_VALUES,
)

#: A NUL-bearing fallback constant and a NUL-free one, taken from the real
#: candidate list rather than invented, so this test tracks the shipped values.
#: 0x1337 packs little-endian as 37 13 00 00; 0xfeedface as ce fa ed fe.
#:
#: NUL_FREE must sit AFTER NUL_BEARING in the candidate order, or the pruning
#: test is vacuous: the sweep would win before ever reaching the candidate it
#: is supposed to prune, and would pass with the prune deleted. An earlier
#: draft used 0xdeadbeef (index 1, ahead of 0x1337 at index 4) and did exactly
#: that. `test_the_ordering_this_module_depends_on_still_holds` pins it.
NUL_BEARING = 0x1337
NUL_FREE = 0xFEEDFACE


class TestThePredicate:

    def test_the_two_constants_this_module_relies_on_are_still_candidates(self):
        """Non-vacuity: if either value left FALLBACK_MAGIC_VALUES the sweep
        tests below would stop exercising what they claim to."""
        assert NUL_BEARING in FALLBACK_MAGIC_VALUES
        assert NUL_FREE in FALLBACK_MAGIC_VALUES

    def test_the_ordering_this_module_depends_on_still_holds(self):
        """The pruning test is only meaningful if the winnable candidate comes
        AFTER the one that must be pruned. If a future edit reorders
        FALLBACK_MAGIC_VALUES this fails loudly instead of quietly turning the
        pruning test into a tautology."""
        order = list(FALLBACK_MAGIC_VALUES)
        assert order.index(NUL_FREE) > order.index(NUL_BEARING), order

    def test_argv_refuses_a_nul_and_explains_why(self):
        ok, why = payload_representable(SINK_ARGV, b"AAAA\x00")
        assert ok is False
        assert "NUL" in why

    def test_argv_accepts_nul_free_bytes(self):
        ok, why = payload_representable(SINK_ARGV, b"\xef\xbe\xad\xde")
        assert (ok, why) == (True, "")

    @pytest.mark.parametrize(
        "sink", [SINK_STDIN, SINK_FILE_ARGV, SINK_FILE_FIXED]
    )
    def test_every_other_sink_carries_a_nul_fine(self, sink):
        """A NUL is only a problem at the argv syscall boundary. fd 0 and a
        payload file are byte channels, so refusing a NUL there would prune
        winnable candidates for no reason."""
        ok, why = payload_representable(sink, b"AAAA\x00BBBB")
        assert (ok, why) == (True, "")


class _Receipt:
    """Minimal stand-in: the executor reads `.success` and stores the object."""

    def __init__(self, success: bool) -> None:
        self.success = success
        self.flag = "FLAG{stub}" if success else None
        self.level = "FLAG_CAPTURED" if success else "NONE"


class _StubVerifier:
    """Records every payload it is asked to deliver, and fails loudly if it is
    ever handed one the sink cannot carry -- that is the defect's signature."""

    def __init__(self, sink: str, winning_magic: int | None) -> None:
        self._spec = DeliverySpec(
            sink=sink,
            payload_filename="",
            argv_template=("{payload_arg}",) if sink == SINK_ARGV else (),
        )
        self._winning = winning_magic
        self.seen: list[bytes] = []

    def resolve_delivery_spec(self) -> DeliverySpec:
        return self._spec

    def verify_payload(self, technique: str, payload: bytes) -> _Receipt:
        ok, why = payload_representable(self._spec.sink, payload)
        assert ok, (
            "executor handed the verifier a payload the sink cannot carry "
            f"({why}); it should have been pruned before this call"
        )
        self.seen.append(payload)
        if self._winning is None:
            return _Receipt(False)
        import struct
        return _Receipt(struct.pack("<I", self._winning) in payload)


def _context() -> ExploitContext:
    """`binary=None` makes the executor fall back to FALLBACK_MAGIC_VALUES,
    which is what pins the candidate ordering this test depends on."""
    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = None
    return ctx


class TestTheSweepPrunesRatherThanAborts:

    def test_it_reaches_a_later_candidate_after_pruning_an_earlier_one(self):
        """The regression test for I-7 proper.

        0x1337 is unrepresentable over argv and is a candidate. If the sweep
        aborted on it -- the old behaviour -- it could never confirm
        0xdeadbeef. A SUCCESS here means the prune happened and the sweep
        carried on.
        """
        verifier = _StubVerifier(SINK_ARGV, winning_magic=NUL_FREE)
        record = VariableOverwriteExecutor().attempt(_context(), verifier)

        assert record.outcome == AttemptOutcome.SUCCESS
        assert not any(b"\x00" in p for p in verifier.seen)

    def test_an_exhausted_argv_sweep_reports_how_many_it_could_not_try(self):
        """Pass/fail is not enough: the operator has to be able to tell a
        transport limit from an absent gate constant."""
        verifier = _StubVerifier(SINK_ARGV, winning_magic=None)
        record = VariableOverwriteExecutor().attempt(_context(), verifier)

        assert record.outcome == AttemptOutcome.FAILED
        assert "pruned unattempted" in record.failure_reason
        assert repr(SINK_ARGV) in record.failure_reason

    def test_a_stdin_sweep_prunes_nothing_and_says_nothing(self):
        """Red-proof for the message above: the same exhausted sweep over a
        sink that CAN carry every candidate must not claim any prune. Without
        this, a hardcoded prune notice would pass the test above forever."""
        verifier = _StubVerifier(SINK_STDIN, winning_magic=None)
        record = VariableOverwriteExecutor().attempt(_context(), verifier)

        assert record.outcome == AttemptOutcome.FAILED
        assert "pruned unattempted" not in record.failure_reason

    def test_the_prune_wording_does_not_trip_the_script_audit_regex(self):
        """`templates.py` interpolates `failure_reason` into generated scripts,
        and `run_bench.py`'s `_SCRAPES_BINARY_RE` routes any mention of
        strings/objdump/readelf/xxd to a CHEAT verdict. The existing audit test
        in test_variable_overwrite_budget.py only exercises a stdin sweep, so it
        never sees the argv-only prune wording -- this closes that path rather
        than assuming it is clean.
        """
        import importlib.util
        import sys
        from pathlib import Path

        pytest.importorskip("yaml")
        repo_root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "run_bench_i7_audit", repo_root / "benchmark" / "run_bench.py")
        rb = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = rb
        spec.loader.exec_module(rb)

        # Positive control first: the regex must be able to fire, or asserting
        # that it does not match proves nothing at all.
        assert rb._SCRAPES_BINARY_RE.search("ran objdump on it")

        verifier = _StubVerifier(SINK_ARGV, winning_magic=None)
        record = VariableOverwriteExecutor().attempt(_context(), verifier)

        assert "pruned unattempted" in record.failure_reason, (
            "precondition: this sweep must actually have pruned something"
        )
        assert not rb._SCRAPES_BINARY_RE.search(record.failure_reason), (
            record.failure_reason
        )

    def test_stdin_still_delivers_nul_bearing_candidates(self):
        """The prune must be sink-specific. Over stdin the NUL-bearing
        candidate is winnable, so it must still be attempted -- a fix that
        pruned NULs unconditionally would regress every stdin target whose
        gate constant happens to contain a zero byte.
        """
        verifier = _StubVerifier(SINK_STDIN, winning_magic=NUL_BEARING)
        record = VariableOverwriteExecutor().attempt(_context(), verifier)

        assert record.outcome == AttemptOutcome.SUCCESS
        assert any(b"\x00" in p for p in verifier.seen)
