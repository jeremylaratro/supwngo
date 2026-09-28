"""Proofs for the loop-counter-overflow executor (`loop_counter_overflow`).

Corpus: benchmark/corpus_g23/ (5 positives + 1 negative control), built with

    benchmark/build_corpus_g23.sh

Two things here carry more weight than ordinary "the executor works"
coverage, because both were MEASURED (hand-verified against real `objdump -d
-M intel` output, recorded in
docs/plans/2026-09-28-g23-loop-counter-overflow-plan.md) rather than assumed:

1. **The static gate MUST open on the negative control, and that is the
   point.** ``g23_90_neg_widened_check`` has the byte-for-byte identical loop
   shape -- same destination arithmetic, same reloaded bound, same stack
   offsets -- as ``g23_10_adjacent_above``; only the size CHECK's own
   arithmetic width differs (32-bit there, 8-bit everywhere else), which is a
   fact about whether the check itself can ever wrap, not about the loop's
   shape. A static gate that closed on the control would be keying on
   something other than "this loop's own steering state sits inside the
   overflow's reach" -- in a family this uniform, on a corpus artifact. The
   refusal belongs to the live-measurement layer (exercised end to end by
   ``benchmark/measure_family.py`` and ``benchmark/reference_exploits/
   g23_variants_reference.py``, not here -- both spawn the target).

2. **The discriminator (`I < BUF and L < BUF`) and the byte-exact payload
   derivation are both proven load-bearing by MUTATION to WRONG-BUT-PRESENT,
   not by an absence check.** Per this project's validation-first
   convention: a test that only checks "the field is missing" cannot tell a
   real gate from one that always returns True. Every load-bearing test below
   mutates a plausible-looking, still-present value and asserts the specific
   downstream consequence -- a declined gate, a `None` payload, an excluded
   sweep candidate -- changes for the reason the docstring claims.

Every test below either needs no corpus at all or skips cleanly when the
family is not built. None of them spawn a target: the runtime measurement
(the live sweep, ``verify_script``) is exercised end to end by
``benchmark/measure_family.py`` and ``benchmark/reference_exploits/
g23_variants_reference.py``, which is where a multi-minute, multi-process
sweep belongs.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "benchmark" / "corpus_g23"

from supwngo.exploit.pipeline.executors import build_default_registry
from supwngo.exploit.pipeline.executors import loop_counter_techniques as lct
from supwngo.exploit.pipeline.executors.loop_counter_techniques import (
    FIXED_SWEEP,
    LoopCounterOverflowExecutor,
    LoopSite,
    _build_payload,
    _count_candidates,
    _find_check_cap,
    analyse,
    disassemble,
    find_loop_sites,
    find_ret_gadget,
)

POSITIVES = (
    "g23_10_adjacent_above",
    "g23_11_swapped_order",
    "g23_12_word_bound",
    "g23_13_stride16",
    "g23_14_second_narrow",
)
CONTROL = "g23_90_neg_widened_check"
ALL_TARGETS = POSITIVES + (CONTROL,)

#: Ground truth, measured by hand against each target's own compiled
#: `vuln()` (see the module docstring and the plan doc). Kept in the test
#: file as a SEPARATE record from the executor's own derivation, so a bug
#: that made `analyse()` compute a wrong-but-self-consistent answer would
#: still be caught here.
GROUND_TRUTH = {
    "g23_10_adjacent_above": dict(buf=0x50, i_off=0x4, l_off=0x5, l_width=8,
                                  stride=8, cap=0x40, r_ctrl=9, i_in_rec=4,
                                  r_ret=11, len_in_rec=3),
    "g23_11_swapped_order": dict(buf=0x70, i_off=0x4, l_off=0x5, l_width=8,
                                 stride=8, cap=0x60, r_ctrl=13, i_in_rec=4,
                                 r_ret=15, len_in_rec=3),
    "g23_12_word_bound": dict(buf=0x50, i_off=0x4, l_off=0x6, l_width=16,
                              stride=8, cap=0x40, r_ctrl=9, i_in_rec=4,
                              r_ret=11, len_in_rec=2),
    "g23_13_stride16": dict(buf=0x50, i_off=0x4, l_off=0x5, l_width=8,
                            stride=16, cap=0x40, r_ctrl=4, i_in_rec=12,
                            r_ret=5, len_in_rec=11),
    "g23_14_second_narrow": dict(buf=0x50, i_off=0x4, l_off=0x7, l_width=8,
                                 stride=8, cap=0x40, r_ctrl=9, i_in_rec=4,
                                 r_ret=11, len_in_rec=1),
    "g23_90_neg_widened_check": dict(buf=0x50, i_off=0x4, l_off=0x5,
                                     l_width=8, stride=8, cap=0x40, r_ctrl=9,
                                     i_in_rec=4, r_ret=11, len_in_rec=3),
}


def _path(slug: str) -> str:
    path = CORPUS / slug / slug
    if not path.is_file():
        pytest.skip(f"{path} not built (see this module's docstring)")
    return str(path)


def _binary(slug: str):
    from supwngo.core.binary import Binary

    return Binary.load(_path(slug))


def _context(slug: str):
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = _binary(slug)
    # Mirror profile_stage.run_static_analysis's own unwrap exactly: pwntools
    # symbol lookups return a `Symbol` object, not a bare int, and the real
    # pipeline never hands `_script` anything but the unwrapped address (see
    # profile_stage.py's `addr = sym.address if hasattr(sym, 'address') else
    # sym`) -- measured directly: passing the raw Symbol through crashed
    # `_script`'s own `hex(win_addr)` with "'Symbol' object cannot be
    # interpreted as an integer".
    sym = ctx.binary.symbols["win"]
    addr = sym.address if hasattr(sym, "address") else sym
    ctx.win_function = ("win", addr)
    return ctx


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_executor_is_registered_in_the_default_registry():
    registry = build_default_registry()
    assert "loop_counter_overflow" in registry
    assert registry.get("loop_counter_overflow") is not None


def test_the_registered_name_is_the_one_the_orchestrator_would_order_on():
    assert LoopCounterOverflowExecutor.name == "loop_counter_overflow"


# --------------------------------------------------------------------------
# The static derivation, measured against the corpus
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_static_gate_recovers_every_offset_on_every_target(slug):
    """The exact offsets the plan doc's hand derivation recorded, read back
    out of the image -- including the control, which has the identical loop
    shape (see the module docstring's point 1)."""
    truth = GROUND_TRUTH[slug]
    gate, reason = analyse(_path(slug))
    assert gate is not None, reason
    site = gate.site
    assert site.buf_off == truth["buf"]
    assert site.i_off == truth["i_off"]
    assert site.l_off == truth["l_off"]
    assert site.l_width_bits == truth["l_width"]
    assert site.stride == truth["stride"]
    assert gate.cap == truth["cap"]
    assert gate.r_ctrl == truth["r_ctrl"]
    assert gate.i_in_rec == truth["i_in_rec"]
    assert gate.r_ret == truth["r_ret"]
    assert gate.len_in_rec == truth["len_in_rec"]
    # The discriminator itself.
    assert site.i_off < site.buf_off
    assert site.l_off < site.buf_off


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_gate_accepts_every_target_including_the_control(slug):
    assert LoopCounterOverflowExecutor().is_applicable(_context(slug)) is True


def test_static_gate_opens_on_the_control_too():
    """Deliberate, and asserted so it cannot drift into looking like a bug.

    See the module docstring's point 1. ``skip_reason`` on the control
    returns "ok" -- there is nothing static to refuse on; the refusal is a
    live-measurement fact.
    """
    gate, reason = analyse(_path(CONTROL))
    assert gate is not None, reason
    assert LoopCounterOverflowExecutor().skip_reason(_context(CONTROL)) == "ok"


# --------------------------------------------------------------------------
# The discriminator is load-bearing -- proven by mutation, not by absence
# --------------------------------------------------------------------------


def test_the_discriminator_rejects_a_loop_whose_steering_state_is_past_buf():
    """RED proof, via a synthetic disassembly built by hand from the SAME
    instruction shapes the real corpus emits (Intel syntax, gcc -O0's own
    idiom) with exactly one number changed: BUF moved from 0x50 to 0x2, so
    ``I(0x4) < BUF`` -- the discriminator's own condition -- goes FALSE while
    every other instruction is untouched and still parses. A gate keyed on
    "a loop calls read() with a computed destination" alone (ignoring the
    discriminator) would still open here; this one must not.
    """
    insns = _synthetic_vuln_insns(buf_hex="0x2")
    funcs = {"vuln": insns}
    orig = lct.disassemble
    lct._DISASM_CACHE[("<synthetic-red>", 0.0)] = funcs
    try:
        sites = find_loop_sites("<synthetic-red>")
    finally:
        lct._DISASM_CACHE.pop(("<synthetic-red>", 0.0), None)
    assert sites == [], (
        "a loop site was still found with I(0x4) >= BUF(0x2) -- the "
        "discriminator did not reject it")


def test_the_discriminator_accepts_the_same_shape_with_buf_restored():
    """GREEN counterpart to the test above -- same synthetic construction,
    only BUF restored to a value that satisfies ``I < BUF``, proving the
    RED result above was caused by the discriminator and not by some other
    difference between the synthetic fixture and a real target."""
    insns = _synthetic_vuln_insns(buf_hex="0x50")
    funcs = {"vuln": insns}
    lct._DISASM_CACHE[("<synthetic-green>", 0.0)] = funcs
    try:
        sites = find_loop_sites("<synthetic-green>")
    finally:
        lct._DISASM_CACHE.pop(("<synthetic-green>", 0.0), None)
    assert len(sites) == 1
    assert sites[0].buf_off == 0x50
    assert sites[0].i_off == 0x4


def _synthetic_vuln_insns(buf_hex: str):
    """A minimal, hand-built instruction list in the exact Intel-syntax
    shape gcc -O0 emits for this category's loop (matches
    ``g23_10_adjacent_above``'s own compiled ``vuln()``, addresses renumbered
    for a short, self-contained fixture). ``buf_hex`` is substituted into the
    ``lea rdx,[rbp-BUF]`` instruction only -- every other instruction is
    fixed, so changing it isolates exactly the discriminator's own input.
    """
    text = [
        "mov    DWORD PTR [rbp-0x4],0x0",           # 0x0
        "jmp    0x30",                               # 0x4  (into the check)
        "mov    eax,DWORD PTR [rbp-0x4]",           # 0x8  (loop_start)
        "shl    eax,0x3",                            # 0xc
        "cdqe   ",                                   # 0x10
        f"lea    rdx,[rbp-{buf_hex}]",               # 0x14
        "add    rax,rdx",                            # 0x18
        "mov    edx,0x8",                            # 0x1c
        "mov    rsi,rax",                            # 0x20
        "mov    edi,0x0",                            # 0x24
        "call   1000 <read@plt>",                    # 0x28  (bare hex target,
                                                       #  matches real objdump)
        "add    DWORD PTR [rbp-0x4],0x1",            # 0x2c
        "movzx  eax,BYTE PTR [rbp-0x5]",             # 0x30  (loop_end's check)
        "cmp    DWORD PTR [rbp-0x4],eax",            # 0x34
        "jl     0x8",                                # 0x38  (loop_end)
    ]
    return [(0x0 + 4 * i, t) for i, t in enumerate(text)]


def test_build_payload_declines_when_the_control_record_would_extend_past_buf():
    """RED proof at the payload-construction layer: take a REAL, cached gate
    from a real target (so every other field is genuinely consistent) and
    mutate only ``buf_off`` down below where the control record's own end
    already sits. ``_build_payload`` must refuse rather than emit a payload
    whose geometry it can no longer vouch for -- this is the guard added
    specifically because ``analyse()``'s own boundary check cannot protect a
    ``_Gate`` object built or mutated after the fact.
    """
    gate, reason = analyse(_path(POSITIVES[0]))
    assert gate is not None, reason
    mutated = copy.deepcopy(gate)
    # The real gate has ctrl_end == buf_off exactly (see the module
    # docstring's derivation); moving buf_off one byte lower makes
    # ctrl_end > buf_off, which is the shape _build_payload refuses.
    mutated.site.buf_off -= 1
    result = _build_payload(mutated, 0, b"\x00" * 8)
    assert result is None, (
        "_build_payload built a payload even though the control record's "
        "own end now sits past the mutated BUF -- the boundary guard is "
        "not load-bearing")
    # ...and the cached original is untouched, proving the mutation was
    # made on the deep copy and not on the shared cache entry.
    assert analyse(_path(POSITIVES[0]))[0].site.buf_off == gate.site.buf_off


def test_count_candidates_cap_filter_is_load_bearing():
    """RED proof: a candidate that the fixed sweep WOULD offer is excluded
    the instant a cap makes its low byte exceed the buffer -- not merely
    absent from an unrelated list."""
    stride = 8
    # 48 * 8 = 384; 384 & 0xff == 128, which exceeds a cap of 64.
    with_cap = _count_candidates(stride, cap=0x40)
    assert 48 not in with_cap, (
        "candidate 48 (whose low byte 128 exceeds cap 0x40) was not "
        "excluded -- the cap filter is not load-bearing")
    without_cap = _count_candidates(stride, cap=None)
    assert 48 in without_cap, (
        "precondition failed: 48 should be offered when no cap is known"
    )


def test_find_check_cap_recovers_the_real_immediate():
    """The cap read straight out of each target's own `cmp ..., IMM`
    instruction, not a value this test invents."""
    for slug in ALL_TARGETS:
        funcs = disassemble(_path(slug))
        insns = funcs["vuln"]
        cap = _find_check_cap(insns, len(insns))
        assert cap == GROUND_TRUTH[slug]["cap"], slug


# --------------------------------------------------------------------------
# Applicability preconditions
# --------------------------------------------------------------------------


def test_gate_declines_without_a_win_function():
    ctx = _context(POSITIVES[0])
    ctx.win_function = None
    executor = LoopCounterOverflowExecutor()
    assert executor.is_applicable(ctx) is False
    assert "win" in executor.skip_reason(ctx).lower()


def test_gate_declines_without_a_binary():
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    executor = LoopCounterOverflowExecutor()
    assert executor.is_applicable(ctx) is False
    assert "no binary" in executor.skip_reason(ctx).lower()


def test_gate_declines_on_a_binary_with_no_matching_loop():
    """Negative control from OUTSIDE the family, so "the gate opens" is not
    vacuous. ``/bin/true`` calls no bulk-input function inside a
    backward-branching loop at all."""
    gate, reason = analyse("/bin/true")
    assert gate is None
    assert reason  # a real, non-empty reason, not a silent None


# --------------------------------------------------------------------------
# find_loop_sites / find_ret_gadget, against the real corpus
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_find_loop_sites_finds_exactly_one_site_per_positive(slug):
    sites = find_loop_sites(_path(slug))
    assert len(sites) == 1
    assert sites[0].callee == "read"


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_find_ret_gadget_finds_a_real_ret_in_every_target(slug):
    """Every target's own `vuln()` ends in a bare `ret` (see the plan doc's
    disassembly), so the fallback gadget finder (used when
    ``context.gadgets['ret']`` was never populated) must find SOMETHING --
    a presence assertion, not merely "did not raise"."""
    addr = find_ret_gadget(disassemble(_path(slug)))
    assert addr is not None
    assert addr > 0


# --------------------------------------------------------------------------
# The payload is byte-exact, not merely "the right length"
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_build_payload_places_the_induction_variable_and_bound_at_the_measured_offsets(slug):
    gate, reason = analyse(_path(slug))
    assert gate is not None, reason
    tail = b"\xCC" * 8
    built = _build_payload(gate, 0, tail)
    assert built is not None
    payload, n_records = built

    ctrl_start = gate.r_ctrl * gate.stride
    ctrl = payload[ctrl_start:ctrl_start + gate.stride]
    # The 4-byte induction-variable field must read back r_ctrl itself (the
    # loop's own `add [rbp-I],1` turns this into r_ctrl+1 for the NEXT
    # comparison -- see the module docstring).
    assert int.from_bytes(ctrl[gate.i_in_rec:gate.i_in_rec + 4], "little") == gate.r_ctrl
    # The bound field must read back n_records, sized to L's own load width.
    width_bytes = gate.l_width_bytes
    got_bound = int.from_bytes(
        ctrl[gate.len_in_rec:gate.len_in_rec + width_bytes], "little")
    assert got_bound == n_records
    # The tail lands at exactly BUF+8 bytes from the payload's start.
    assert payload[gate.site.buf_off + 8: gate.site.buf_off + 8 + len(tail)] == tail
    # And the loop's own termination is exact: n_records * stride is at
    # least BUF+8+len(tail), and less than one more stride than that.
    assert n_records * gate.stride >= gate.site.buf_off + 8 + len(tail)
    assert (n_records - 1) * gate.stride < gate.site.buf_off + 8 + len(tail)


def test_build_payload_mutation_moves_the_planted_index_red_proof():
    """RED proof that the induction-variable placement is load-bearing: feed
    a mutated ``i_in_rec`` and confirm the planted bytes move to the wrong
    offset (rather than the test merely checking a value is present
    somewhere in the payload).

    Uses ``g23_13_stride16`` (stride=16) specifically: its 16-byte record has
    room for a 4-byte index field at an offset that does NOT collide with its
    own 1-byte bound field (at len_in_rec=11) -- every stride=8 target's own
    len_in_rec sits close enough to i_in_rec=4 that any other in-bounds
    placement of the 4-byte field overlaps it, which would make this a test
    of the (unrelated) overlap guard instead of the placement itself.
    """
    gate, reason = analyse(_path("g23_13_stride16"))
    assert gate is not None, reason
    assert gate.i_in_rec == 12 and gate.len_in_rec == 11  # measured (see GROUND_TRUTH)
    mutated = copy.deepcopy(gate)
    mutated.i_in_rec = 0  # non-overlapping with len_in_rec=11 (occupies [11,12))
    tail = b"\xCC" * 8
    built = _build_payload(mutated, 0, tail)
    assert built is not None
    payload, _n = built
    ctrl_start = mutated.r_ctrl * mutated.stride
    ctrl = payload[ctrl_start:ctrl_start + mutated.stride]
    # With i_in_rec mutated to 0, the planted r_ctrl value must now be at
    # offset 0, NOT at the real (measured) offset -- proving the field
    # actually moved rather than the test tolerating either position.
    assert int.from_bytes(ctrl[0:4], "little") == mutated.r_ctrl
    assert int.from_bytes(ctrl[gate.i_in_rec:gate.i_in_rec + 4], "little") != mutated.r_ctrl


# --------------------------------------------------------------------------
# The generated script embeds the exact, already-verified payload
# --------------------------------------------------------------------------


def test_script_embeds_the_two_part_send_and_the_exact_payload_bytes():
    """PRESENCE assertions on the emitted script text -- this family's
    template does not reconstruct the payload symbolically (see
    ``LoopCounterOverflowExecutor._script``'s own docstring for why), so the
    exact bytes measured to work must appear in the script verbatim."""
    gate, reason = analyse(_path(POSITIVES[0]))
    assert gate is not None, reason
    tail = b"\xAA" * 8
    built = _build_payload(gate, 0, tail)
    assert built is not None
    payload, _n = built

    ctx = _context(POSITIVES[0])
    executor = LoopCounterOverflowExecutor()
    script = executor._script(ctx, gate, 32, payload, "bare_win",
                              "win", ctx.win_function[1])
    assert "send_part(io, b'%d\\n' % count)" in script
    assert "send_part(io, payload)" in script
    assert repr(payload) in script
    assert "io.interactive()" in script  # from script_builder's own template


def test_script_generation_two_tail_variants_are_both_reachable():
    """Both alignment variants the module docstring documents (bare `win`
    and the ret-gadget slide) must be representable by ``_script`` -- a
    presence check on the doc line each produces, not on the byte content,
    since the payload bytes themselves already differ per call and are
    checked by the test above."""
    gate, reason = analyse(_path(POSITIVES[0]))
    assert gate is not None, reason
    ctx = _context(POSITIVES[0])
    executor = LoopCounterOverflowExecutor()
    tail = b"\x11" * 8
    built = _build_payload(gate, 0, tail)
    assert built is not None
    payload, _n = built

    ret_script = executor._script(ctx, gate, 32, payload, "ret_slide",
                                  "win", ctx.win_function[1])
    bare_script = executor._script(ctx, gate, 32, payload, "bare_win",
                                   "win", ctx.win_function[1])
    assert "ret gadget" in ret_script
    assert "win directly" in bare_script
