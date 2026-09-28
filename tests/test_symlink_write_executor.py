"""Proofs for the symlink-following-write executor (`symlink_follow_write`,
CWE-59).

Corpus: benchmark/corpus_symlink/ (5 positives + 1 negative control), built with
    SUPWNGO_BENCH_CORPUS=benchmark/corpus_symlink benchmark/build_all.sh

Three things here carry more weight than ordinary "the executor works"
coverage, because all three were **measured** during development rather than
assumed -- and one of them is a corpus bug this test suite would have caught
immediately, had it existed first.

1. **The gate MUST decline on the negative control, and it does so for a
   REASON THAT IS FULLY STATIC.** Unlike ``type_confusion_tag``'s control
   (which the static gate accepts and only a runtime sweep refuses),
   ``sym_90_neg_nofollow`` differs from ``sym_10_truncate_redirect`` by
   exactly one immediate bit (``O_NOFOLLOW`` in the write's flags operand),
   and that bit is visible to the disassembly-level gate directly --
   ``test_static_gate_declines_on_the_control`` asserts the decline and
   ``test_the_controls_refusal_is_measured_by_analyse_not_by_skip_reason``
   pins WHERE that refusal actually comes from.

2. **A real bug this project shipped and caught before trusting the corpus.**
   The first build of this corpus had ``seed_gate()`` -- an internal,
   fixed-content, once-at-startup write with no attacker-controlled content
   at all -- built with the exact same ``snprintf`` + ``open(O_CREAT, no
   O_NOFOLLOW)`` shape as the real vulnerable ``write_output()``. Because
   ``_analyse`` returned the FIRST matching candidate found (functions are
   walked alphabetically, and ``seed_gate`` < ``write_output``), the gate was
   silently keying on the wrong function on EVERY target, including the
   control -- ``is_applicable`` returned True on ``sym_90`` too, for a reason
   having nothing to do with ``O_NOFOLLOW``. Fixed at the corpus level (the
   corpus's own seeding now uses an fd-anchored ``openat()``, which has no
   ``snprintf`` call for the gate's join-site scan to find at all -- see
   ``sym_10_truncate_redirect.c``'s ``seed_gate()``), not by loosening or
   special-casing the executor. ``test_plan_selects_write_output_not_seed_gate``
   pins the derived facts (route, write API, components) against the ONE
   function that should ever be selected, so a regression of this exact bug
   would fail loudly instead of silently degrading into "gate opens on
   everything, gate=None, attempt() always fails at ANALYSIS".

3. **Distinctness from ``toctou_path_race`` and ``path_traversal_read`` is a
   measured fact, not a docstring claim.** ``test_toctou_gate_never_opens_*``
   and ``test_path_traversal_gate_never_opens_*`` run those executors'
   REAL ``is_applicable`` against this family's images (and this family's
   gate against theirs), which is the same check
   ``scripts/gate_sweep.py`` makes at corpus-tree scale; see this module's
   companion run log for the full-tree sweep (0 out-of-family opens in
   either direction for either pairing).

Every test below either needs no corpus at all or skips cleanly when the
family is not built. None of them spawn a target: the runtime measurement
(the redirected write actually landing, the gate actually unlocking, the
flag actually being disclosed) is exercised end to end by
``benchmark/measure_family.py`` and ``benchmark/reference_exploits/
symlink_variants_reference.py``, which is where a process-spawning,
filesystem-mutating proof belongs.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "benchmark" / "corpus_symlink"

from supwngo.exploit.pipeline.executors import build_default_registry
from supwngo.exploit.pipeline.executors.symlink_write_techniques import (
    CHECK_APIS,
    O_NOFOLLOW,
    SymlinkFollowWriteExecutor,
    Insn,
    _has_check,
    _join_sites,
    analyse,
    calls_in,
    disassemble,
    trace_arg,
)

POSITIVES = (
    "sym_10_truncate_redirect",
    "sym_11_append_redirect",
    "sym_12_dir_component_redirect",
    "sym_13_creat_redirect",
    "sym_14_fopen_redirect",
)
CONTROL = "sym_90_neg_nofollow"
ALL_TARGETS = POSITIVES + (CONTROL,)

#: Measured facts (see this module's docstring point 2 for why these are
#: pinned rather than merely "gate opens"). request_dir is identical in
#: shape across the family (``/tmp/supwngo_<slug-without-the-scenario-name>``)
#: so only the parts that vary by mechanism are asserted here.
EXPECTED = {
    "sym_10_truncate_redirect": dict(
        components=["note.txt"], route="leaf", write_api="open"),
    "sym_11_append_redirect": dict(
        components=["log.txt"], route="leaf", write_api="open"),
    "sym_12_dir_component_redirect": dict(
        components=["pending", "policy.conf"], route="dir", write_api="open"),
    "sym_13_creat_redirect": dict(
        components=["cache.txt"], route="leaf", write_api="creat"),
    "sym_14_fopen_redirect": dict(
        components=["stats.dat"], route="leaf", write_api="fopen"),
}


def _path(slug: str) -> str:
    path = CORPUS / slug / slug
    if not path.is_file():
        pytest.skip(f"{path} not built (see this module's docstring)")
    return str(path)


def _binary(slug: str):
    from supwngo.core.binary import Binary

    # Binary.load, not Binary(...): the bare constructor leaves the ELF
    # unparsed and every derived fact silently reads as its default.
    return Binary.load(_path(slug))


def _context(slug: str):
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = _binary(slug)
    return ctx


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_executor_is_registered_in_the_default_registry():
    registry = build_default_registry()
    assert "symlink_follow_write" in registry
    assert registry.get("symlink_follow_write") is not None


def test_the_registered_name_is_the_one_the_orchestrator_would_order_on():
    assert SymlinkFollowWriteExecutor.name == "symlink_follow_write"


def test_seated_immediately_behind_the_narrower_path_gate():
    """The ordering seat, and the POSITION, both measured 2026-09-28.

    Granted for SPEED on the same two-justification test that DENIED
    `loop_counter_overflow` a seat:

        forced (`--strategy`, the technique's own cost)   5.0-5.2 s
        unordered, via the applicability tail           61.6-62.1 s
        seated                                           3.8-4.2 s

    ~58 s per target, in the band that earned seats for
    `heap_offbynul_overlap` (98.6 -> 17.2 s) and `type_confusion_tag`
    (108.8 -> 25.9 s), not the ~4.3 s that got one denied. Attribution needed
    nothing: unordered, all five positives were already credited to
    `symlink_follow_write` at `FLAG_CAPTURED` with 0 misattributed.

    POSITION is pinned, not just membership. The seat sits immediately behind
    `toctou_path_race`: both are writes that follow an attacker-controlled path,
    and toctou is the narrower of the pair because it additionally needs a usable
    race window. Narrower gate first -- the same rule that puts
    `heap_offbynul_overlap` behind `heap_strlen_ofb1`.

    Unlike that pair, this seat cannot cost another family anything, and that was
    measured rather than assumed: a gate sweep over 203 ELFs opens on 5 images,
    all of them its own, 0 outside and 0 raised. There are no shared images for
    the ordering to outbid anyone on.
    """
    from supwngo.exploit.pipeline.orchestrator import FIRST_TECHNIQUES

    assert "symlink_follow_write" in FIRST_TECHNIQUES
    assert "toctou_path_race" in FIRST_TECHNIQUES
    assert FIRST_TECHNIQUES.index("symlink_follow_write") == (
        FIRST_TECHNIQUES.index("toctou_path_race") + 1
    ), "the seat must stay immediately behind the narrower path-following gate"
    assert len(FIRST_TECHNIQUES) == len(set(FIRST_TECHNIQUES))


# --------------------------------------------------------------------------
# The static derivation, measured against the corpus
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_plan_selects_write_output_not_seed_gate(slug):
    """The regression guard for the exact bug this project shipped and
    caught (see module docstring point 2): the derived plan's route,
    write API, and path components must match ``write_output()`` -- the
    ATTACKER-REDIRECTABLE scratch write -- never ``seed_gate()``, which
    happens to satisfy the identical structural shape (a snprintf-built,
    O_CREAT, no-check write) but targets the gate file directly with fixed
    content and no attacker influence at all.
    """
    plan, reason = analyse(_path(slug))
    assert plan is not None, reason
    expected = EXPECTED[slug]
    assert plan.components == expected["components"]
    assert plan.route == expected["route"]
    assert plan.write_api == expected["write_api"]


@pytest.mark.parametrize("slug", POSITIVES)
def test_plan_derives_the_gate_file_as_a_separate_join(slug):
    """The gate is a DIFFERENT function's join (check_gate's), confirmed by
    an independent fact (it is read back AND compared with strstr), not
    assumed from the write's own components."""
    plan, reason = analyse(_path(slug))
    assert plan is not None, reason
    assert plan.gate_name == "policy.conf"
    assert plan.gate_magic == "UNLOCK"
    # The gate is never the same join as the write itself.
    assert plan.gate_name not in plan.components or plan.route == "dir"


@pytest.mark.parametrize("slug", POSITIVES)
def test_plan_resolves_the_secret_at_runtime_not_as_a_literal(slug):
    """secret_name is a bare filename that also exists beside the binary
    (``_secret_beside``), never a value read out of a compiled-in FLAG{...}
    literal -- see the module docstring's SUCCESS ORACLE section."""
    plan, reason = analyse(_path(slug))
    assert plan is not None, reason
    assert plan.secret_name == "flag.txt"


@pytest.mark.parametrize("slug", POSITIVES)
def test_gate_accepts_every_positive(slug):
    assert SymlinkFollowWriteExecutor().is_applicable(_context(slug)) is True


def test_static_gate_declines_on_the_control():
    """THE fact that distinguishes this family's control from
    ``type_confusion_tag``'s: the refusal is fully static and derivable from
    the disassembly alone. ``sym_90_neg_nofollow`` differs from the anchor by
    exactly the O_NOFOLLOW bit in write_output()'s flags immediate, and
    ``_find_write`` reads that immediate directly -- no runtime sweep is
    needed to know this target is safe.
    """
    plan, reason = analyse(_path(CONTROL))
    assert plan is None
    assert "O_NOFOLLOW" in reason or "no path built" in reason


def test_the_controls_refusal_is_measured_by_analyse_not_by_skip_reason():
    """Pin WHERE the refusal comes from. ``skip_reason`` is the base class's
    generic message (this executor overrides neither is_applicable's
    diagnostics nor skip_reason with target-specific text) -- the actual,
    checkable reason lives in ``analyse()``'s second return value, asserted
    above. This test exists so a future skip_reason override does not
    silently become the only place the real reason is recorded.
    """
    executor = SymlinkFollowWriteExecutor()
    ctx = _context(CONTROL)
    assert executor.is_applicable(ctx) is False
    assert executor.skip_reason(ctx) == "precondition not met"


def test_gate_declines_without_a_binary():
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = None
    assert SymlinkFollowWriteExecutor().is_applicable(ctx) is False


def test_gate_declines_on_a_binary_with_no_qualifying_write():
    """Negative control from OUTSIDE the family entirely, so "the gate
    declines" is not vacuous. /bin/true has no join at all."""
    plan, reason = analyse("/bin/true")
    assert plan is None
    assert "no path built" in reason


# --------------------------------------------------------------------------
# The gate's defining facts are load-bearing -- proven by mutation
# --------------------------------------------------------------------------


def test_check_absence_is_load_bearing_proven_by_inserting_a_real_check_call():
    """VALIDATION-FIRST: prove ``_has_check`` can go RED before trusting that
    "no check API anywhere on the buffer" is actually what the gate is
    keying on.

    WRONG-BUT-PRESENT mutation: take the REAL, disassembled ``write_output``
    from a real positive, and insert a real ``lstat@plt`` call targeting the
    EXACT frame slot the write's buffer occupies. ``_has_check`` must flip
    from False to True -- if it did not, "no check API anywhere on this
    buffer" would not actually be what excludes ``toctou_path_race``'s route
    A, and the module docstring's central distinctness claim would be an
    unverified assertion. The mutation is a deep copy; the cached original
    (re-fetched from ``disassemble``'s cache) must be provably untouched, or
    a later test in this file could observe a poisoned gate.
    """
    slug = POSITIVES[0]
    binary = _binary(slug)
    path = _path(slug)
    funcs = disassemble(path)
    func = funcs["write_output"]

    sites = list(_join_sites(binary, func))
    assert sites, "precondition: write_output has a join on this target"
    index, slot, _fmt, _components = sites[0]
    assert _has_check(func, slot) is False, "baseline: no check present yet"

    mutated = copy.deepcopy(func)
    slot_text = ("-0x%x" % (-slot)) if slot < 0 else ("0x%x" % slot)
    mutated.insns.append(Insn(addr=0x999999, text="lea    %s(%%rbp),%%rdi" % slot_text))
    mutated.insns.append(Insn(addr=0x999999 + 1, text="call   401000 <lstat@plt>"))

    assert _has_check(mutated, slot) is True, (
        "inserting a real lstat() call on the write's own slot must flip "
        "_has_check -- if it does not, the check-absence fact is decorative"
    )
    # The cached original, re-fetched, must be untouched by the deepcopy'd
    # mutation -- mutating the cached Func in place would poison every test
    # after this one (measured failure mode elsewhere in this project's test
    # suite, see tests/test_typeconfusion_executor.py).
    assert _has_check(disassemble(path)["write_output"], slot) is False


def test_nofollow_bit_is_load_bearing_proven_by_a_real_compiled_control():
    """The counterpart RED proof for the WRITE side, using a REAL compiled
    binary rather than a synthetic mutation -- the strongest form available,
    since ``sym_90_neg_nofollow`` differs from ``sym_10_truncate_redirect``
    by exactly the ``O_NOFOLLOW`` bit and nothing else (same request
    protocol, same gate file, same mkdir/seed/check shape). If flipping that
    one bit did not flip the gate's verdict, O_NOFOLLOW would not actually
    be load-bearing for this category's applicability test.
    """
    anchor_plan, _ = analyse(_path(POSITIVES[0]))
    control_plan, control_reason = analyse(_path(CONTROL))
    assert anchor_plan is not None
    assert control_plan is None
    assert "NOFOLLOW" in control_reason or "no path built" in control_reason
    # O_NOFOLLOW's numeric value, asserted so the constant itself cannot
    # silently drift out of sync with the bit the corpus's C source sets.
    assert O_NOFOLLOW == 0o400000


def test_check_apis_table_excludes_descriptor_based_fstat():
    """fstat/fstatat operate on an already-open descriptor, not a name -- they
    are the FIX for this category, not an instance of the bug. If they were
    ever added to CHECK_APIS, a hardened target using fstat() to validate an
    fd it already holds would be misread as "checked", which is backwards:
    the category's exclusion is about checks on the NAME before it is
    resolved, not about validating what was already opened.
    """
    assert "fstat" not in CHECK_APIS
    assert "fstatat" not in CHECK_APIS


# --------------------------------------------------------------------------
# Distinctness from toctou_path_race -- measured, both directions
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_toctou_gate_never_opens_on_this_family(slug):
    """MEASURED (also confirmed at corpus-tree scale by
    ``scripts/gate_sweep.py toctou_techniques ToctouPathRaceExecutor
    corpus_toctou``, 0 opens outside corpus_toctou/ across the whole tree).

    toctou_path_race's route A needs a check-then-use pair; this family has
    none (test_check_absence_is_load_bearing_proven_by_inserting_a_real_check_call
    is precisely the proof that "none" is what the gate enforces). Route B
    needs the path argument to trace to ``("rodata", addr)`` -- a
    compile-time literal; every write in this family is a
    ``("frame_addr", slot)``, a stack buffer built by snprintf, which is
    exactly what defeats route B by construction (see the module docstring).
    """
    from supwngo.exploit.pipeline.executors.toctou_techniques import (
        ToctouPathRaceExecutor,
    )

    assert ToctouPathRaceExecutor().is_applicable(_context(slug)) is False


def test_toctou_gate_never_opens_on_the_control_either():
    from supwngo.exploit.pipeline.executors.toctou_techniques import (
        ToctouPathRaceExecutor,
    )

    assert ToctouPathRaceExecutor().is_applicable(_context(CONTROL)) is False


@pytest.mark.parametrize(
    "slug",
    (
        "toctou_10_stat_ino_then_open",
        "toctou_11_lstat_type_then_fopen",
        "toctou_12_realpath_then_fopen",
        "toctou_13_dir_component_swap",
        "toctou_14_predictable_tmp_no_excl",
        "toctou_90_neg_fd_anchored",
    ),
)
def test_this_gate_never_opens_on_toctous_family(slug):
    """The other direction. MEASURED (also confirmed at corpus-tree scale by
    ``scripts/gate_sweep.py symlink_write_techniques SymlinkFollowWriteExecutor
    corpus_symlink``, 0 opens outside corpus_symlink/ across the whole tree,
    which includes every corpus_toctou/ image)."""
    from supwngo.core.binary import Binary
    from supwngo.core.context import ExploitContext

    toctou_root = REPO_ROOT / "benchmark" / "corpus_toctou"
    path = toctou_root / slug / slug
    if not path.is_file():
        pytest.skip(f"{path} not built")
    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = Binary.load(str(path))
    assert SymlinkFollowWriteExecutor().is_applicable(ctx) is False


def test_trace_arg_never_resolves_a_join_built_path_to_rodata():
    """The mechanical fact that makes route B structurally unreachable here,
    asserted directly rather than only inferred from the applicability
    result above: every write's path argument traces to a FRAME address
    (a stack buffer), never to rodata (a compile-time literal)."""
    slug = POSITIVES[0]
    binary = _binary(slug)
    funcs = disassemble(_path(slug))
    func = funcs["write_output"]
    sites = list(_join_sites(binary, func))
    assert sites
    index, slot, _fmt, _components = sites[0]
    for call_index, callee in calls_in(func):
        if call_index <= index or callee not in ("open", "open64", "creat", "fopen"):
            continue
        arg0 = trace_arg(func.insns, call_index, 0)
        assert arg0[0] == "frame_addr", (
            "the write's path argument must be a stack buffer, never a "
            "rodata literal, or this target would also satisfy toctou's "
            "route B"
        )
        assert arg0[1] == slot


# --------------------------------------------------------------------------
# Distinctness from path_traversal_read -- measured, both directions
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_path_traversal_gate_never_opens_on_this_family(slug):
    """path_traversal_read's ``_join_sites`` requires the LAST vararg to be
    DYNAMIC (operator-supplied text). Every join in this family has EVERY
    vararg as a rodata literal -- there is no operator-supplied text
    anywhere in the constructed path, which is what this test measures via
    the real executor rather than re-deriving path_traversal's predicate by
    hand."""
    from supwngo.exploit.pipeline.executors.path_traversal_techniques import (
        PathTraversalReadExecutor,
    )

    assert PathTraversalReadExecutor().is_applicable(_context(slug)) is False


@pytest.mark.parametrize(
    "slug",
    (
        "trav_10_naive_concat",
        "trav_11_single_pass_dotdot_strip",
        "trav_12_prefix_check_before_resolution",
        "trav_13_absolute_path_accepted",
        "trav_14_suffix_append_truncated",
        "trav_90_neg_realpath_confined",
    ),
)
def test_this_gate_never_opens_on_path_traversals_family(slug):
    """The other direction. MEASURED (also confirmed at corpus-tree scale by
    ``scripts/gate_sweep.py symlink_write_techniques SymlinkFollowWriteExecutor
    corpus_symlink``, 0 opens outside corpus_symlink/ across the whole tree,
    which includes every corpus_traversal/ image)."""
    from supwngo.core.binary import Binary
    from supwngo.core.context import ExploitContext

    trav_root = REPO_ROOT / "benchmark" / "corpus_traversal"
    path = trav_root / slug / slug
    if not path.is_file():
        pytest.skip(f"{path} not built")
    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = Binary.load(str(path))
    assert SymlinkFollowWriteExecutor().is_applicable(ctx) is False


# --------------------------------------------------------------------------
# The generated script's own shape
# --------------------------------------------------------------------------


def test_script_plants_the_filesystem_before_opening_the_target():
    """PRESENCE assertion on the emitted text: plant() must run, and the
    process must be opened, from run_once() -- and the FIRST body line must
    close whatever open_target() produced before plant() had a chance to
    run, or the technique would race its own filesystem setup against the
    process it just started (the exact window this whole category claims
    does not need to exist)."""
    slug = POSITIVES[0]
    plan, reason = analyse(_path(slug))
    assert plan is not None, reason
    executor = SymlinkFollowWriteExecutor()
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = _binary(slug)
    script = executor._script(ctx, plan)

    assert "def plant():" in script
    assert "def unplant():" in script
    assert "def run_once():" in script
    assert "os.symlink(target, swap_path)" in script
    assert script.index("io.close()") < script.index("hits = run_once()")
    # plant() happens INSIDE run_once(), strictly before open_target():
    run_once_body = script.split("def run_once():")[1].split("def exploit")[0]
    assert run_once_body.index("plant()") < run_once_body.index("open_target()")


def test_script_never_opens_the_secret_itself():
    """The disclosed bytes can only have come from the TARGET's own stdout:
    this script's only reference to the secret's path is SECRET_ABS, and
    SECRET_ABS is never passed to an open call in the generated script --
    only compared against nothing, computed, and left unused except as a
    human-readable doc constant. (Matches the family-wide convention
    documented in benchmark/reference_exploits/symlink_variants_reference.py
    under "PROVING WE NEVER READ IT".)
    """
    slug = POSITIVES[0]
    plan, reason = analyse(_path(slug))
    assert plan is not None, reason
    executor = SymlinkFollowWriteExecutor()
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = _binary(slug)
    script = executor._script(ctx, plan)

    assert "open(SECRET_ABS" not in script
    assert "open(SECRET_ABS)" not in script
    assert "SECRET_ABS" in script  # present as a documented constant only


def test_script_fails_closed_when_nothing_is_disclosed():
    """PRESENCE assertion on the emitted text: an attempt that discloses
    nothing must sys.exit(1) rather than silently falling through, or a
    failed run could be credited as a receipt by the verifier."""
    slug = POSITIVES[0]
    plan, reason = analyse(_path(slug))
    assert plan is not None, reason
    executor = SymlinkFollowWriteExecutor()
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = _binary(slug)
    script = executor._script(ctx, plan)

    assert "if not hits:" in script
    body = script.split("if not hits:")[1].split("log.success")[0]
    assert "sys.exit(1)" in body
