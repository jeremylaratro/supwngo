"""Proofs for the union-tag type-confusion executor (`type_confusion_tag`).

Corpus: benchmark/corpus_typeconf/ (5 positives + 1 negative control), built with
    SUPWNGO_BENCH_CORPUS=benchmark/corpus_typeconf benchmark/build_all.sh

Three things here carry more weight than ordinary "the executor works" coverage,
because all three were **measured** during development rather than assumed.

1. **The static gate MUST open on the negative control, and that is the point.**
   ``tc_90_neg_tag_bound_to_write`` is the same program with the same record
   layout and the same tag-guarded indirect call; only its behaviour differs. A
   static gate that closed on it would be keying on something other than the
   category -- in a family this uniform, on a corpus artifact. So
   ``test_static_gate_opens_on_the_control_too`` asserts the open, and the
   control's refusal is proven separately, at the layer that actually measures
   it (the mis-tag sweep). Writing it the other way round would make the gate
   look sharper and the measurement weaker.

2. **The fact that separates this category from ``objptr_hijack``.** MEASURED:
   ``ObjPtrHijackExecutor.is_applicable`` returns True on all six targets here --
   it asks only for a reader, an indirect call through a memory load, and
   somewhere to point it, all of which are true. What it never asks is whether
   the called offset is also an integer's home and whether the call is guarded by
   a narrower field of the same object. ``test_objptr_gate_also_opens_*`` pins
   that overlap as a measured fact rather than leaving it as a claim in a
   docstring, and ``test_gate_requires_an_integer_store_at_the_called_offset``
   proves the extra fact is load-bearing by removing it.

3. **The generated script's own oracle can go RED.** ``prove_shell()`` uses
   ``echo SH$((6*7))OK`` -> ``SH42OK``: arithmetic expansion is a shell builtin,
   so the answer is absent from the bytes sent and a target that echoes its input
   cannot satisfy it. The script exits 1 WITHOUT bridging stdin when the marker
   is missing, which is what stops a failed attempt from being credited with the
   verifier's receipt. Guarded as a PRESENCE assertion on the emitted text, not
   as an absence assertion about tokens -- an absence check would pass vacuously
   the moment something is renamed.

Every test below either needs no corpus at all or skips cleanly when the family
is not built. None of them spawn a target: the runtime measurement is exercised
end to end by ``benchmark/measure_family.py``, which is where a multi-minute
sweep belongs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "benchmark" / "corpus_typeconf"

from supwngo.exploit.pipeline.executors import build_default_registry
from supwngo.exploit.pipeline.executors.typeconfusion_techniques import (
    MAX_TAG_IMM,
    TypeConfusionTagExecutor,
    _blob,
    analyse,
    find_tag_sites,
)

POSITIVES = (
    "tc_10_direct_tag_write",
    "tc_11_struct_blob_tag",
    "tc_12_offbyone_tag_bound",
    "tc_13_stale_tag_realloc",
    "tc_14_computed_tag_truncation",
)
CONTROL = "tc_90_neg_tag_bound_to_write"
ALL_TARGETS = POSITIVES + (CONTROL,)


def _path(slug: str) -> str:
    path = CORPUS / slug / slug
    if not path.is_file():
        pytest.skip(f"{path} not built (see this module's docstring)")
    return str(path)


def _binary(slug: str):
    from supwngo.core.binary import Binary

    # Binary.load, not Binary(...): the bare constructor leaves the ELF unparsed
    # and every derived fact silently reads as its default.
    return Binary.load(_path(slug))


def _context(slug: str, *, menu: bool = True):
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = _binary(slug)
    ctx.win_function = ("win", ctx.binary.symbols["win"])
    ctx.profile_has_menu = menu
    return ctx


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_executor_is_registered_in_the_default_registry():
    registry = build_default_registry()
    assert "type_confusion_tag" in registry
    assert registry.get("type_confusion_tag") is not None


def test_the_registered_name_is_the_one_the_orchestrator_would_order_on():
    assert TypeConfusionTagExecutor.name == "type_confusion_tag"


# --------------------------------------------------------------------------
# The static derivation, measured against the corpus
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_static_gate_recovers_the_tag_guarded_call_on_every_target(slug):
    """The three offsets the exploit is built from, read out of the image."""
    gate, reason = analyse(_path(slug))
    assert gate is not None, reason
    site = gate.best
    assert site is not None
    # The record is {int tag; int seq; union {...}; char label[16];} -- so the
    # discriminant is at +0 and the union at +8. Both are DERIVED, and asserting
    # the derived values is what would catch a walker that found some other call.
    assert site.tag_off == 0x0
    assert site.union_off == 0x8
    assert site.tag_value == 2          # TAG_FN, read from the `cmp`
    assert site.tag_off != site.union_off
    assert site.func == "invoke_cell"


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_the_called_offset_is_also_an_integers_home(slug):
    """THE fact that separates this from a stored callback.

    A qword store into the union's offset, inside a function that reaches a
    text-to-number conversion. ``objptr_hijack``'s gate never computes this.
    """
    gate, _ = analyse(_path(slug))
    site = gate.best
    assert site.int_writers, (
        "no numeric writer stores into the called offset, so nothing writes an "
        "integer where the program later reads a code pointer -- that is not "
        "this category"
    )
    assert "set_num" in site.int_writers


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_the_leak_channel_is_derived(slug):
    """PIE is on, so a code-address leak is mandatory. The program publishes its
    own handler into the union's pointer arm, at the same offset the call reads
    from -- which is why a raw record dump discloses the image base."""
    gate, _ = analyse(_path(slug))
    assert gate.handler_sym is not None
    assert gate.handler_field == gate.best.union_off


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_gate_accepts_every_target_including_the_control(slug):
    assert TypeConfusionTagExecutor().is_applicable(_context(slug)) is True


def test_static_gate_opens_on_the_control_too():
    """Deliberate, and asserted so it cannot drift into looking like a bug.

    ``tc_90`` has the identical record layout, the identical tag-guarded call and
    the identical numeric writer; what it lacks is any operation that changes the
    tag without rewriting the arm it names. That is a RUNTIME property. A static
    gate that declined here would have to be keying on something that is not the
    category -- and in a family this uniform, the only things left to key on are
    corpus artifacts.
    """
    gate, reason = analyse(_path(CONTROL))
    assert gate is not None, reason
    assert gate.best.tag_value == 2
    assert gate.best.int_writers


def test_the_controls_refusal_is_measured_not_static():
    """The counterpart to the test above: state where the refusal DOES come from.

    ``skip_reason`` on the control returns the static gate's "ok" -- there is
    nothing static to refuse on. The refusal is produced by the mis-tag sweep in
    ``plan_for``, and it is exercised end to end by
    ``benchmark/measure_family.py``, not here, because it spawns the target
    several dozen times.
    """
    assert TypeConfusionTagExecutor().skip_reason(_context(CONTROL)) == "ok"


# --------------------------------------------------------------------------
# The gate's extra fact is load-bearing -- proven by removing it
# --------------------------------------------------------------------------


def test_gate_requires_an_integer_store_at_the_called_offset():
    """Positive control on the gate itself.

    Strip the numeric-writer fact from the derived site and the gate must close.
    Without this the previous tests would all still pass on a gate that returned
    a ``_Gate`` unconditionally, and "the gate opens on every positive" would be
    decoration.

    ``analyse`` is cached per (realpath, mtime) and hands back the SAME ``_Gate``
    object every time, so the mutation is made on a deep copy. Mutating the cached
    one poisoned every later test in this module -- measured, not hypothetical.
    """
    import copy

    gate = copy.deepcopy(analyse(_path(POSITIVES[0]))[0])
    assert gate.confused, "precondition: the site had the fact to begin with"
    for site in gate.sites:
        site.int_writers = []
    assert gate.confused == []
    assert gate.best is None
    # ...and the cached original is untouched, which is what the tests after this
    # one depend on.
    assert analyse(_path(POSITIVES[0]))[0].best.int_writers


def test_tag_immediate_bound_excludes_lengths_and_indices():
    """A discriminant names one of a handful of arms. The bound is what stops a
    length check or an index bound from being read as a tag, and it is the reason
    the gate does not open on every bounds-checked loop that ends in a call."""
    assert MAX_TAG_IMM == 0x100
    gate, _ = analyse(_path(POSITIVES[0]))
    assert 0 <= gate.best.tag_value < MAX_TAG_IMM


def test_crt_indirect_calls_are_not_counted_as_application_sites():
    """``_init``'s ``call rax`` is the ``__gmon_start__`` probe. Counting it makes
    every dynamically linked binary look applicable, which is how a gate stops
    measuring anything."""
    sites = find_tag_sites(_path(POSITIVES[0]))
    assert sites
    assert all(s.func not in ("_init", "_start", "frame_dummy") for s in sites)


# --------------------------------------------------------------------------
# The line against objptr_hijack -- pinned as a measurement
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_objptr_gate_also_opens_on_this_family(slug):
    """MEASURED, and recorded here so the overlap is a fact and not a claim.

    ``objptr_hijack`` opens on all six of these because it asks only for a
    reader, an indirect call through a memory load, and a destination. It then
    FAILS at ANALYSIS in ~0.0s ("its pointer and its argument do not share a
    base") because ``c->u.fn()`` takes no argument. Same destination, different
    cause -- and the overlap being in the GATE rather than in the solve is
    precisely why no attribution seat is needed in the attempt order.
    """
    from supwngo.exploit.pipeline.executors.objptr_hijack_techniques import (
        ObjPtrHijackExecutor,
    )

    assert ObjPtrHijackExecutor().is_applicable(_context(slug)) is True


def test_this_gate_asks_for_something_objptrs_does_not():
    """The two gates are not the same predicate wearing different names.

    ``objptr_hijack`` requires a reader + a hijackable call site + a destination.
    This one additionally requires that the call's pointer offset coincide with
    the destination of a numeric store, and that the call be dominated by a
    comparison of a narrower field of the same object. Assert the extra facts
    exist and are distinct offsets, which is the part that cannot be satisfied by
    an ordinary stored callback.
    """
    from supwngo.exploit.pipeline.executors.objptr_hijack_techniques import (
        find_call_targets,
        find_hijack_sites,
    )

    binary = _binary(POSITIVES[0])
    assert find_hijack_sites(binary)          # objptr's fact
    assert find_call_targets(binary)          # objptr's fact
    site = analyse(_path(POSITIVES[0]))[0].best
    assert site.int_writers                   # ours, and objptr never asks
    assert site.tag_off != site.union_off     # ours, and objptr never asks


# --------------------------------------------------------------------------
# Applicability preconditions
# --------------------------------------------------------------------------


def test_gate_declines_without_a_win_function():
    """``o->u.fn()`` takes no controlled argument, so ``system@plt`` is not a
    usable destination on this shape and a target with no win function is out of
    reach rather than merely harder. The decline names that."""
    ctx = _context(POSITIVES[0])
    ctx.win_function = None
    executor = TypeConfusionTagExecutor()
    assert executor.is_applicable(ctx) is False
    assert "no controlled argument" in executor.skip_reason(ctx)


def test_gate_declines_without_a_menu():
    ctx = _context(POSITIVES[0], menu=False)
    executor = TypeConfusionTagExecutor()
    assert executor.is_applicable(ctx) is False
    assert "menu" in executor.skip_reason(ctx)


def test_gate_declines_on_a_binary_with_no_tag_guarded_call():
    """Negative control from outside the family, so "the gate opens" is not
    vacuous. ``/bin/true`` has no tag-guarded indirect call."""
    gate, reason = analyse("/bin/true")
    assert gate is None
    assert "tag" in reason.lower()


# --------------------------------------------------------------------------
# The struct-shaped payload is built by PATCHING, not by assembling
# --------------------------------------------------------------------------


def test_blob_preserves_every_field_it_is_not_changing():
    """The record image sent to a raw read is the target's OWN dumped record with
    two fields patched. Assembling one from assumptions would zero a sequence
    number or a length the program keeps there and leave the record incoherent
    after the write."""
    record = bytes(range(32))
    out = _blob(record, tag_off=0, union_off=8, tag_value=2, value=0xDEAD, length=16)
    assert len(out) == 16
    assert out[0:4] == (2).to_bytes(4, "little")
    assert out[4:8] == record[4:8], "the seq field must survive untouched"
    assert out[8:16] == (0xDEAD).to_bytes(8, "little")


def test_blob_truncates_rather_than_overruns_a_short_read():
    """A blob longer than the target's read leaves bytes in the pipe that the
    menu then eats, desynchronising the session. Length is respected exactly."""
    out = _blob(bytes(32), 0, 8, 2, 1, length=12)
    assert len(out) == 12


# --------------------------------------------------------------------------
# The generated script's own oracle
# --------------------------------------------------------------------------


def test_the_template_proves_a_shell_before_bridging_stdin():
    """PRESENCE assertions on the emitted text.

    Written this way on purpose: an absence assertion ("the script does not merely
    echo") passes vacuously the moment a marker is renamed, and this family's
    whole success signal is a real shell, because win() prints no flag.
    """
    from supwngo.exploit.pipeline.executors import typeconfusion_techniques as tc

    template = tc._TYPECONF_TEMPLATE
    assert "echo SH$((6*7))OK" in template
    assert "SH42OK" in template
    # The exit must come BEFORE the bridge, or a failed attempt can still be
    # credited with the verifier's receipt.
    assert template.index("SH42OK") < template.index("def bridge()")
    assert "sys.exit(1)" in template.split("def prove_shell()")[1].split(
        "def bridge()")[0]


def test_the_template_locates_the_record_rather_than_assuming_it_starts_at_zero():
    from supwngo.exploit.pipeline.executors import typeconfusion_techniques as tc

    body = tc._TYPECONF_TEMPLATE.split("def dump()")[1].split("def mistag")[0]
    assert "HANDLER_SYM" in body
    assert "0xFFF" in body, "the leak is validated by page alignment"
    assert "sys.exit(1)" in body, "an unfound leak must fail, not guess a base"
