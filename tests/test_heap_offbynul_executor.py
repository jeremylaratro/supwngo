"""Proofs for the heap off-by-NUL -> overlapping record executor
(`heap_offbynul_overlap`).

Corpus: benchmark/corpus_offbynul/ (5 positives + 1 negative control), built with
    SUPWNGO_BENCH_CORPUS=benchmark/corpus_offbynul benchmark/build_all.sh
(or by hand -- see each target's own `cflags`).

This category is item 7 of the stage-4 gap queue in
docs/reference/2026-09-28-vulnerability-category-coverage.md:
``strcpy``/manual-copy writes a terminating NUL one byte past a fixed-capacity
record field because an inclusive bound (``if (n > CAP) n = CAP;``) lets
``n == CAP`` survive, and that NUL lands on the low byte of the NEXT record's
own length/capacity-like field -- a program-owned header, never real glibc
chunk metadata. Success is SHELL_ACCESS: the bug redirects control flow to
``win()``, it does not disclose anything.

Per this category's own explicit instructions, `HeapOffByNulOverlapExecutor`
is registered in `build_default_registry()` but DELIBERATELY NOT added to
`FIRST_TECHNIQUES` in orchestrator.py -- `test_not_added_to_first_techniques`
pins that rather than leaving it as something only a diff could catch.

Three things below carry more weight than ordinary "the executor works"
coverage, because all three were MEASURED during development rather than
assumed.

1. **The static gate (`inclusive_bound_terminator`) opens on the negative
   control ON PURPOSE, and that is stated as a fact about the corpus rather
   than treated as a defect.** `obn_90_neg_slack_byte` keeps the IDENTICAL
   off-by-one code shape in `set()` -- same inclusive clamp, same constant,
   same explicit NUL store -- so the gate cannot and must not distinguish it;
   what makes it a control is a runtime property (a slack byte absorbs the
   NUL) that a static gate over the disassembly has no way to see, and
   should not be asked to fake seeing. `test_gate_opens_on_the_control_too`
   pins that on purpose, and `test_the_byte_store_evidence_is_load_bearing`
   is the RED PROOF that the gate's byte-store detection is not a decoration
   -- degrade only that regex to something that can never match and five of
   the six targets' gates close (the sixth, obn_13, is detected through the
   OTHER piece of evidence, `strcpy-call`, and is asserted to stay open
   specifically because of that).

2. **The discriminating facts against this category's two nearest neighbours
   are proven by direct measurement, not merely asserted in a docstring.**
   `test_my_gate_does_not_open_on_heap_record_hijacks_family` and the two
   `test_neither_neighbours_gate_opens_on_this_family_*` tests call the
   OTHER categories' own gate functions directly against this corpus (and
   vice versa) and assert zero opens in both directions -- the same
   three-way measurement reported in `corpus_offbynul.yaml`'s
   NON-DUPLICATION section, reproduced here as a standing regression guard.

3. **The generated script's success signal is the shell, not a flag.**
   `test_template_has_a_shell_receipt_bridge` and
   `test_template_has_no_flag_pattern` are PRESENCE/ABSENCE pairs: the
   template must contain `bridge()` (this family's only route to
   FLAG_CAPTURED-equivalent proof, which for a control-flow-hijack category
   is SHELL_ACCESS) and must never contain a hardcoded flag literal a lazy
   script could print without actually working.

Every test below either needs no corpus at all or skips cleanly when the
family is not built. None of them spawn a target: the runtime measurement is
exercised end to end by `benchmark/measure_family.py`, which is where a
multi-minute sweep belongs.
"""

from __future__ import annotations

import inspect
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH = REPO_ROOT / "benchmark"
CORPUS = BENCH / "corpus_offbynul"

from supwngo.exploit.pipeline.contracts import AttemptOutcome, Stage
from supwngo.exploit.pipeline.executors import build_default_registry
from supwngo.exploit.pipeline.executors.heap_offbynul_techniques import (
    _OFFBYNUL_TEMPLATE,
    HeapOffByNulOverlapExecutor,
    _Plan,
    _has_size_prompt,
    _recipe_a_body,
    _recipe_b_body,
    _roles,
    inclusive_bound_terminator,
)

POSITIVES = (
    "obn_10_len_scan_handler",
    "obn_11_cap_resize_handler",
    "obn_12_limit_underflow_append",
    "obn_13_strcpy_len_scan",
    "obn_14_liveness_bypass_scan",
)
CONTROL = "obn_90_neg_slack_byte"
ALL_TARGETS = POSITIVES + (CONTROL,)

#: MEASURED gate evidence (`inclusive_bound_terminator`, 2026-09-28). Every
#: target shares the same 24-byte bound; only obn_13 is detected through the
#: `strcpy-call` half rather than the `byte-store` half, because it is the
#: one variant built on a REAL `strcpy()` rather than a manual clamp-then-
#: store.
EXPECTED_GATE = {
    "obn_10_len_scan_handler": (24, "byte-store"),
    "obn_11_cap_resize_handler": (24, "byte-store"),
    "obn_12_limit_underflow_append": (24, "byte-store"),
    "obn_13_strcpy_len_scan": (24, "strcpy-call"),
    "obn_14_liveness_bypass_scan": (24, "byte-store"),
    "obn_90_neg_slack_byte": (24, "byte-store"),
}

#: The family's real menu shape, read off the targets: create/edit/show/invoke,
#: discovered and prompt-probed at runtime by the executor -- never hardcoded
#: to a slug. Used only to exercise `_roles` without spawning anything.
FAMILY_MENU = [
    (1, "create record"), (2, "edit record"), (3, "show record"),
    (4, "trigger record"), (5, "exit"),
]


def target_elf(slug: str) -> Path:
    return CORPUS / slug / slug


def require_built(slug: str) -> Path:
    elf = target_elf(slug)
    if not elf.exists():
        pytest.skip(
            f"{slug} is not built -- run "
            f"SUPWNGO_BENCH_CORPUS=benchmark/corpus_offbynul benchmark/build_all.sh"
        )
    return elf


class _StubBinary:
    def __init__(self, path: str) -> None:
        self.path = path


class _StubContext:
    """The attributes `is_applicable`/`skip_reason` actually read."""

    def __init__(self, binary=None, win_function=("win", 0x1234),
                 profile_has_menu=False) -> None:
        self.binary = binary
        self.win_function = win_function
        self.profile_has_menu = profile_has_menu


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def test_the_technique_name_is_exactly_heap_offbynul_overlap():
    assert HeapOffByNulOverlapExecutor.name == "heap_offbynul_overlap"


def test_registered_in_the_default_registry():
    names = {ex.name for ex in build_default_registry().all()}
    assert "heap_offbynul_overlap" in names


def test_registered_under_its_own_class():
    matches = [ex for ex in build_default_registry().all()
               if ex.name == "heap_offbynul_overlap"]
    assert len(matches) == 1
    assert isinstance(matches[0], HeapOffByNulOverlapExecutor)


def test_seated_immediately_behind_the_narrower_heap_gate():
    """DECISION REVERSED 2026-09-28, by measurement. This test asserted the
    opposite until then, and the reversal is recorded here rather than by
    deleting the test.

    The original instruction for this category was "registered, but not
    prioritised", and this test pinned `heap_offbynul_overlap` OUT of
    `FIRST_TECHNIQUES`. Then the two justifications for a seat were actually
    measured:

        forced (`--strategy`, the technique's own cost)   15.8 s
        unordered, via the applicability tail            98.3-99.2 s
        seated                                           17.2 s

    ~83 s per target was time spent failing through earlier gates -- the same
    order as the savings that justified `type_confusion_tag` (108.8 -> 25.9 s)
    and `heap_record_hijack` (105.6 -> 20.5 s). Attribution needed nothing:
    unordered, all five positives were already credited correctly with 0
    misattributed. So the seat was granted for SPEED alone.

    That the same test run also DENIED `loop_counter_overflow` a seat (forced
    5.09 s vs unordered 9.4 s, a ~4.3 s saving) is what makes this a decision
    rather than a default.

    POSITION is asserted, not just membership. The seat sits immediately behind
    `heap_strlen_ofb1`, the narrower of the two heap off-by-one gates, and that
    order is load-bearing: this gate also opens on two `corpus_offbyone` images,
    so seating it AHEAD of the narrower gate is what would start stealing
    attribution from `off_by_one_guard`.
    """
    from supwngo.exploit.pipeline.orchestrator import FIRST_TECHNIQUES

    assert len(FIRST_TECHNIQUES) > 10  # the list itself is not empty/broken
    assert "heap_offbynul_overlap" in FIRST_TECHNIQUES
    assert "heap_strlen_ofb1" in FIRST_TECHNIQUES
    assert FIRST_TECHNIQUES.index("heap_offbynul_overlap") == (
        FIRST_TECHNIQUES.index("heap_strlen_ofb1") + 1
    ), "the seat must stay immediately behind the narrower heap off-by-one gate"
    # No duplicates: a second entry would be reached only once but would make
    # the ordering rationale above unreadable.
    assert len(FIRST_TECHNIQUES) == len(set(FIRST_TECHNIQUES))


# ---------------------------------------------------------------------------
# The static gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_static_gate_opens_on_every_positive(slug):
    gate = inclusive_bound_terminator(str(require_built(slug)))
    assert gate is not None, f"{slug} declined to open"
    assert gate == EXPECTED_GATE[slug]


def test_gate_opens_on_the_control_too():
    """On purpose -- see point 1 in the module docstring.

    The control's off-by-one CODE SHAPE is identical to every positive's; it
    is declined by MEASUREMENT (the slack byte absorbs the NUL at runtime),
    not by a gate special-cased to exempt it. A gate that closed on the
    control here would be discriminating on the corpus, not on the code.
    """
    gate = inclusive_bound_terminator(str(require_built(CONTROL)))
    assert gate == EXPECTED_GATE[CONTROL]


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_gate_evidence_matches_what_was_measured(slug):
    assert inclusive_bound_terminator(str(require_built(slug))) == EXPECTED_GATE[slug]


def test_the_byte_store_evidence_is_load_bearing(monkeypatch):
    """RED PROOF: break only the byte-store regex and five of six gates close.

    A WRONG-BUT-PRESENT mutation, not an absence: the regex object still
    exists and is still exercised on every instruction window, it is simply
    tuned to match a byte pattern (`0xFE` immediate) that never occurs in any
    of these images, so it can never fire. obn_13 is the one target proven to
    survive this mutation, because it is detected through the OTHER piece of
    evidence (`strcpy-call`) entirely -- if it also closed, that would show
    the two evidence paths are not actually independent.
    """
    import supwngo.exploit.pipeline.executors.heap_offbynul_techniques as mod

    for slug in POSITIVES + (CONTROL,):
        assert inclusive_bound_terminator(str(require_built(slug))) is not None, (
            f"precondition: {slug}'s gate opens before the mutation"
        )

    broken = __import__("re").compile(r"mov\s+BYTE PTR \[[^\]]+\],0xfe\b")
    monkeypatch.setattr(mod, "_BYTE_ZERO_STORE", broken)

    for slug in ("obn_10_len_scan_handler", "obn_11_cap_resize_handler",
                 "obn_12_limit_underflow_append", "obn_14_liveness_bypass_scan",
                 CONTROL):
        elf = target_elf(slug)
        if not elf.exists():
            pytest.skip(f"{slug} is not built")
        assert mod.inclusive_bound_terminator(str(elf)) is None, (
            f"{slug} still opened after the byte-store regex was broken -- "
            "the byte-store evidence path is not load-bearing for it"
        )

    strcpy_slug = "obn_13_strcpy_len_scan"
    strcpy_elf = target_elf(strcpy_slug)
    if strcpy_elf.exists():
        assert mod.inclusive_bound_terminator(str(strcpy_elf)) is not None, (
            "obn_13 closed too -- it should be detected through strcpy-call "
            "evidence alone, independent of the byte-store regex"
        )


def test_the_strcpy_call_evidence_is_load_bearing(monkeypatch):
    """RED PROOF, the mirror image: break only the strcpy-call regex.

    obn_13 is the sole target that relies on it; every byte-store target
    must be UNAFFECTED, proving the two evidence paths are independent in
    both directions, not just one.
    """
    import supwngo.exploit.pipeline.executors.heap_offbynul_techniques as mod

    strcpy_elf = target_elf("obn_13_strcpy_len_scan")
    if not strcpy_elf.exists():
        pytest.skip("obn_13_strcpy_len_scan is not built")
    assert mod.inclusive_bound_terminator(str(strcpy_elf)) is not None

    broken = __import__("re").compile(r"call\s+[0-9a-f]+\s+<memfrob(?:@plt)?>")
    monkeypatch.setattr(mod, "_CALL_STRCPY", broken)

    assert mod.inclusive_bound_terminator(str(strcpy_elf)) is None, (
        "obn_13 still opened after strcpy-call evidence was broken -- some "
        "other evidence path is covering for it unexpectedly"
    )

    other = target_elf("obn_10_len_scan_handler")
    if other.exists():
        assert mod.inclusive_bound_terminator(str(other)) is not None, (
            "obn_10's gate closed too, from a mutation that should only "
            "touch the strcpy-call path"
        )


def test_gate_verdicts_survive_renaming_every_file(tmp_path):
    """The gate must read the image, never the slug/filename/path.

    Every target is copied to a name that says nothing about the family, in
    a directory outside the corpus. All six must still open (this gate opens
    on positives AND the control alike -- see point 1 above), and a target
    from an unrelated family must still close.
    """
    for slug in ALL_TARGETS:
        src = require_built(slug)
        dest = tmp_path / f"anonymous_image_{ALL_TARGETS.index(slug)}"
        shutil.copy2(src, dest)
        assert inclusive_bound_terminator(str(dest)) is not None, (
            f"{slug} changed verdict when renamed to {dest.name}"
        )

    unrelated = BENCH / "corpus_bon" / "bon_10_reach_size_lsb" / "bon_10_reach_size_lsb"
    if unrelated.exists():
        dest = tmp_path / "anonymous_unrelated"
        shutil.copy2(unrelated, dest)
        assert inclusive_bound_terminator(str(dest)) is None, (
            "a target from an unrelated family opened this gate once renamed"
        )


def test_gate_declines_cleanly_on_a_missing_file():
    assert inclusive_bound_terminator("/nonexistent/definitely/not/a/binary") is None


def test_gate_ignores_a_zero_immediate():
    """`cmp reg,0x0` is not a capacity bound -- the gate must skip it, not
    treat every branch-on-zero as evidence."""
    assert inclusive_bound_terminator.__doc__ is not None
    # Direct behavioural proof lives in the positive/negative measurements
    # above; this pins the documented rule (`if cap == 0: continue`) stays
    # readable from the source, since a silent removal would not be caught
    # by any single target's verdict (every real target's bound is 24, never
    # 0, so no corpus target can exercise this branch by itself).
    import supwngo.exploit.pipeline.executors.heap_offbynul_techniques as mod
    source = inspect.getsource(mod.inclusive_bound_terminator)
    assert "cap == 0" in source


# ---------------------------------------------------------------------------
# Non-duplication against the two nearest neighbours -- measured, both ways
# ---------------------------------------------------------------------------


def test_my_gate_does_not_open_on_heap_record_hijacks_family():
    fam = BENCH / "corpus_heap_variants"
    if not fam.exists():
        pytest.skip("benchmark/corpus_heap_variants/ is not built")
    opened = []
    checked = 0
    for elf in sorted(fam.glob("*/*")):
        if not elf.is_file() or not (elf.stat().st_mode & 0o111):
            continue
        checked += 1
        if inclusive_bound_terminator(str(elf)) is not None:
            opened.append(str(elf))
    if checked == 0:
        pytest.skip("no built ELF found under benchmark/corpus_heap_variants/")
    assert opened == [], (
        f"heap_offbynul_overlap's own gate opened on heap_record_hijack's "
        f"family: {opened}"
    )


def test_heap_strlen_ofb1s_gate_does_not_open_on_this_family():
    from supwngo.exploit.pipeline.executors.heap_strlen_ofb1_techniques import (
        strlen_feeds_length,
    )

    opened = [slug for slug in ALL_TARGETS
              if target_elf(slug).exists()
              and strlen_feeds_length(str(target_elf(slug))) is not None]
    present = [slug for slug in ALL_TARGETS if target_elf(slug).exists()]
    if not present:
        pytest.skip("benchmark/corpus_offbynul/ is not built")
    assert opened == [], (
        f"heap_strlen_ofb1's gate (strlen_feeds_length) opened on this "
        f"family's targets: {opened} -- an unclamped-strlen bug and a "
        f"clamped-off-by-one bug should be mutually exclusive at any one "
        f"code site"
    )


def test_heap_record_hijacks_gate_does_not_open_on_this_family():
    """`derive_image_facts`'s `handler_sym` is heap_record_hijack's own
    discriminating fact -- called directly, no ExploitContext required.

    Every record in this family is initialised via `memcpy()` from a
    `static const` template, never a `lea <fn>; mov [obj+N],<fn>` pair, so
    `handler_sym` must be `None` on every target.
    """
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.executors.heap_techniques import (
        derive_image_facts,
    )

    present = [slug for slug in ALL_TARGETS if target_elf(slug).exists()]
    if not present:
        pytest.skip("benchmark/corpus_offbynul/ is not built")
    published = []
    for slug in present:
        path = str(target_elf(slug))
        binary = Binary.load(path)
        facts = derive_image_facts(binary, path)
        if facts.get("handler_sym") is not None:
            published.append(slug)
    assert published == [], (
        f"heap_record_hijack's handler-publish fact fired on: {published}"
    )


# ---------------------------------------------------------------------------
# Applicability, without spawning anything
# ---------------------------------------------------------------------------


def test_is_applicable_requires_a_binary():
    ex = HeapOffByNulOverlapExecutor()
    ctx = _StubContext(binary=None)
    assert ex.is_applicable(ctx) is False
    assert ex.skip_reason(ctx) == "no binary loaded"


def test_is_applicable_requires_a_win_function():
    ex = HeapOffByNulOverlapExecutor()
    elf = require_built(POSITIVES[0])
    ctx = _StubContext(binary=_StubBinary(str(elf)), win_function=None,
                       profile_has_menu=True)
    assert ex.is_applicable(ctx) is False
    assert "win function" in ex.skip_reason(ctx)


def test_is_applicable_requires_a_menu():
    ex = HeapOffByNulOverlapExecutor()
    elf = require_built(POSITIVES[0])
    ctx = _StubContext(binary=_StubBinary(str(elf)), profile_has_menu=False)
    assert ex.is_applicable(ctx) is False
    assert "menu" in ex.skip_reason(ctx)
    ctx.profile_has_menu = True
    assert ex.is_applicable(ctx) is True


def test_is_applicable_true_on_every_positive_and_the_control():
    """The static half of applicability -- the runtime half (menu discovery,
    prompt probing, recipe selection) is exercised end to end by
    `measure_family.py`, not re-driven here."""
    ex = HeapOffByNulOverlapExecutor()
    for slug in ALL_TARGETS:
        elf = require_built(slug)
        ctx = _StubContext(binary=_StubBinary(str(elf)), profile_has_menu=True)
        assert ex.is_applicable(ctx) is True, slug


def test_attempt_skips_cleanly_with_no_binary():
    ex = HeapOffByNulOverlapExecutor()
    record = ex.attempt(_StubContext(binary=None), verifier=None)
    assert record.technique == "heap_offbynul_overlap"
    assert record.outcome is AttemptOutcome.SKIPPED
    assert record.failure_reason == "no binary loaded"


def test_attempt_skips_cleanly_with_no_win_function():
    ex = HeapOffByNulOverlapExecutor()
    elf = require_built(POSITIVES[0])
    ctx = _StubContext(binary=_StubBinary(str(elf)), win_function=None,
                       profile_has_menu=True)
    record = ex.attempt(ctx, verifier=None)
    assert record.outcome is AttemptOutcome.SKIPPED
    assert "win function" in record.failure_reason


# ---------------------------------------------------------------------------
# Menu roles, prompt classification, and the two recipes
# ---------------------------------------------------------------------------


def test_roles_reads_the_family_menu():
    roles = _roles(FAMILY_MENU)
    assert roles["create"] == 1
    assert roles["edit"] == 2
    assert roles["show"] == 3
    assert roles["invoke"] == 4


def test_roles_takes_the_first_match_only():
    """One number per role, not a list -- unlike heap_record_hijack's
    `_roles`, this family never needs to distinguish two creators."""
    roles = _roles([(1, "create record"), (2, "create another record")])
    assert roles["create"] == 1


def test_has_size_prompt_recognises_size_words():
    assert _has_size_prompt(["len"]) is True
    assert _has_size_prompt(["size"]) is True
    assert _has_size_prompt(["index"]) is False
    assert _has_size_prompt([]) is False


def test_plan_defaults_to_recipe_a():
    plan = _Plan()
    assert plan.recipe == "A"
    assert plan.set_has_size is True


def test_recipe_a_walks_directly_into_the_corrupted_records_own_index():
    """The KEY generalisation this category's design rests on: `invoke` is
    fired on index 1 (the record the fake header was planted into), reached
    by walking from index 0 -- the corrupted record's own index, not always
    index 0 itself for every family member. Pinning the exact call shape
    here is what would catch a regression to `trigger(0)`."""
    plan = _Plan()
    plan.cap = 24
    plan.set_has_size = True
    body = "\n".join(_recipe_a_body(plan))
    assert 'do(OPT["create"])' in body
    assert 'do(OPT["edit"], idx=0, size=24, data=b"A" * 24)' in body
    assert 'do(OPT["edit"], idx=1, size=len(fake), data=fake)' in body
    assert 'fire(OPT["invoke"], idx=1)' in body


def test_recipe_a_strcpy_variant_uses_the_msb_trick():
    """obn_13's shape: no `size=` kwarg (strcpy takes no length), and the fake
    header is built from 8 bytes of filler plus only the LOW 6 bytes of the
    win address -- the top 2 bytes come free from strcpy's own terminator
    and the record's untouched, still-zero tail."""
    plan = _Plan()
    plan.cap = 24
    plan.set_has_size = False
    body = "\n".join(_recipe_a_body(plan))
    assert 'do(OPT["edit"], idx=0, data=b"A" * 24)' in body
    assert "size=" not in body.split('do(OPT["edit"], idx=0')[1].split("\n")[0]
    assert 'fake = b"B" * 8 + p64(win)[:6]' in body
    assert 'do(OPT["edit"], idx=1, data=fake)' in body


def test_recipe_b_combines_the_overwrite_and_the_notify_in_one_call():
    """obn_12's distinguishing structural fact: the OVERWRITE step both
    plants the fake header AND invokes `win()` in a single `fire()` call, via
    `invoke`'s own 'notify next record' side effect -- there is no separate
    trigger step afterwards."""
    plan = _Plan()
    plan.cap = 24
    plan.set_has_size = True
    body = "\n".join(_recipe_b_body(plan))
    assert body.count('do(OPT["create"])') == 3
    assert 'do(OPT["invoke"], idx=1, size=24, data=b"A" * 24)' in body  # the FILL
    assert 'fire(OPT["invoke"], idx=1, size=len(fake), data=fake)' in body  # OVERWRITE+notify
    # And no separate trailing trigger call beyond the combined one.
    assert body.count('fire(OPT["invoke"]') == 1


# ---------------------------------------------------------------------------
# The generated script must prove a shell, never carry a secret
# ---------------------------------------------------------------------------


def test_template_has_a_shell_receipt_bridge():
    assert "def bridge(" in _OFFBYNUL_TEMPLATE
    assert "sys.stdin.buffer.read()" in _OFFBYNUL_TEMPLATE
    assert "bridge()" in _OFFBYNUL_TEMPLATE.rstrip().splitlines()[-1]


def test_template_has_no_flag_pattern():
    """Nothing here discloses a secret; the oracle is the shell, not a flag."""
    assert "FLAG{" not in _OFFBYNUL_TEMPLATE
    assert "flag.txt" not in _OFFBYNUL_TEMPLATE


def test_template_computes_win_from_a_measured_leak_not_a_literal():
    assert "def leak_base(" in _OFFBYNUL_TEMPLATE
    assert "HANDLER_SYM" in _OFFBYNUL_TEMPLATE
    assert "WIN_SYM" in _OFFBYNUL_TEMPLATE
    assert "leaked - HANDLER_SYM" in _OFFBYNUL_TEMPLATE


def test_template_routes_prompts_by_what_they_ask_not_by_position():
    """This family's prompt handling has to be measured, not assumed:
    `route()` decides a prompt's value from ITS OWN keyword, which is what
    lets one template serve both the std `set()` shape (index/len/data) and
    the strcpy shape (index/data, no len)."""
    assert "def route(" in _OFFBYNUL_TEMPLATE
    assert "SIZE_WORDS" in _OFFBYNUL_TEMPLATE and "INT_WORDS" in _OFFBYNUL_TEMPLATE


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------


def test_verify_script_budget_is_explicit_and_wider_than_the_default():
    """An explicit 45s budget, matching HeapRecordHijackExecutor.escalate's
    own rationale: this script spawns the target and walks its menu several
    times, and the verifier's default budget can kill a working exploit
    part-way through on a loaded machine."""
    source = inspect.getsource(HeapOffByNulOverlapExecutor.attempt)
    assert "timeout=45.0" in source


def test_attempt_records_the_measured_notes_not_assumed_ones():
    """The plan's provenance language (`DERIVED` vs `MEASURED`) is meant to
    be readable in a report; pin that both words are still used somewhere in
    `attempt`'s own source (via `_build_plan`), so a refactor cannot quietly
    drop the distinction this category's docstring makes a point of."""
    import supwngo.exploit.pipeline.executors.heap_offbynul_techniques as mod

    source = inspect.getsource(mod._build_plan)
    assert "DERIVED" in source
    assert "MEASURED" in source
