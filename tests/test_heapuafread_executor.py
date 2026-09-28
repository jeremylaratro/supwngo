"""Proofs for the heap use-after-free READ executor (`heap_uaf_read`).

Corpus: benchmark/corpus_uafread/ (5 positives + 1 negative control), built with
    SUPWNGO_BENCH_CORPUS=benchmark/corpus_uafread benchmark/build_all.sh

This category is the last orphan in `orchestrator.py`'s `FIRST_TECHNIQUES`: the
name `heap_uaf_read` was listed there with no executor behind it. Its success
signal is FLAG_CAPTURED and not SHELL_ACCESS -- the defect discloses memory, it
does not redirect control flow -- so nothing here looks for a win function and
nothing here asserts a shell.

Four things below carry more weight than ordinary "the executor works" coverage,
because all four were MEASURED during development rather than assumed.

1. **The static gate CLOSES on the negative control, and that is a fact about the
   binary rather than an artifact.** `uafr_90_neg_cleared_on_free` is the same
   program, the same record layout, the same nine menu commands and the same
   sealed secret; what differs is that every one of its three `free()` call sites
   is immediately preceded by a wipe of the object being released. That is what
   `derive_free_sites` measures. Two tests keep it honest in opposite directions:
   `test_the_wipe_fact_is_load_bearing` proves the decline is CAUSED by that fact
   (substitute one unwiped site and the gate opens), and
   `test_gate_verdicts_survive_renaming_every_file` proves it is not keying on a
   slug, a filename or a path (copy all six images to unrelated names in a temp
   directory and the six verdicts do not move). A gate that closed on the control
   for any other reason would be discriminating on the corpus.

2. **The gate is LOOSE on purpose and the overlap is pinned as a measurement.**
   MEASURED: `analyse()` opens on four of the six `corpus_uninit` images and on
   `benchmark/corpus/11_heap_uaf_leak`. On this project a cheap decline is
   preferred to a narrow one and solve rate is the goal, so an out-of-family open
   is not automatically a defect -- but it has to be pinned, or the next reader
   assumes a narrowness nobody measured.
   `test_gate_also_opens_on_the_uninit_family` asserts the overlap rather than
   hiding it, and `test_gate_closes_on_the_two_stack_record_uninit_targets`
   records where the line actually falls: those two images never call `free()` at
   all.

3. **The plan and the emitted script never hold the secret.** The disclosed bytes
   are the RESULT. If they were baked into the plan and from there into the
   script, a script that did nothing at all would print them and the verifier
   would credit FLAG_CAPTURED. `test_plan_has_no_field_for_the_disclosed_bytes`
   and `test_template_writes_the_TARGETs_bytes_and_nothing_else` guard that as
   PRESENCE assertions on what the template does (it writes the bytes it read
   from the target's fd 1), not only as an absence assertion about a literal --
   an absence check passes vacuously the moment something is renamed.

4. **The sweep's own control side runs FIRST.** `_sweep` measures every read path
   with NOTHING released before it tries any release, records the answer, and
   only falls back to that baseline as a loudly-labelled last resort. That exists
   because the pre-existing anchor `benchmark/corpus/11_heap_uaf_leak` prints its
   flag from `show(0)` with no free anywhere in the run, so on that target "a flag
   appeared" is not evidence of a use-after-free. `test_baseline_recipe_frees_nothing`
   and `test_ladder_recipes_all_release_something` pin the distinction the
   AttemptRecord has to be able to make.

Every test below either needs no corpus at all or skips cleanly when the family
is not built. None of them spawn a target: the runtime measurement is exercised
end to end by `benchmark/measure_family.py`, which is where a multi-minute sweep
belongs.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH = REPO_ROOT / "benchmark"
CORPUS = BENCH / "corpus_uafread"

from supwngo.exploit.pipeline.contracts import AttemptRecord, AttemptOutcome, Stage
from supwngo.exploit.pipeline.executors import build_default_registry
from supwngo.exploit.pipeline.executors.heapuafread_techniques import (
    BULK_SINKS,
    FLAG_RE,
    READ_INDICES,
    SECRET_IDX,
    SHORT_WRITE,
    WIPE_CALLS,
    _GATE_CACHE,
    _SWEEP_BUDGET_SEC,
    _UAFREAD_TEMPLATE,
    HeapUafReadExecutor,
    Recipe,
    Step,
    UafReadPlan,
    analyse,
    build_ladder,
    classify,
    derive_free_sites,
    read_steps,
)

POSITIVES = (
    "uafr_10_show_after_free",
    "uafr_11_stale_count_iteration",
    "uafr_12_reuse_shorter_write",
    "uafr_13_alias_handle",
    "uafr_14_coalesced_hole",
)
CONTROL = "uafr_90_neg_cleared_on_free"
ALL_TARGETS = POSITIVES + (CONTROL,)

#: The anchor this category was opened against. Recorded FAILING (88.0 s) in
#: docs/reports/PHASE1-BASELINE-24SEP2026.md line 93.
ANCHOR = BENCH / "corpus" / "11_heap_uaf_leak" / "heap_uaf_leak"

#: MEASURED free-site table (`derive_free_sites`, 2026-09-28). The control is the
#: only target where every site is wipe-preceded, which is the whole
#: discriminator; uafr_14 has the fewest wiped because its own release path
#: clears the bookkeeping without scrubbing the body.
EXPECTED_FREE_SITES = {
    "uafr_10_show_after_free": (3, 2),
    "uafr_11_stale_count_iteration": (3, 2),
    "uafr_12_reuse_shorter_write": (3, 2),
    "uafr_13_alias_handle": (3, 2),
    "uafr_14_coalesced_hole": (3, 1),
    "uafr_90_neg_cleared_on_free": (3, 3),
}

#: The family's real menu, read off the targets. Held byte-identical across all
#: six so the menu cannot tell a detector which variant it is looking at.
FAMILY_MENU = [
    (1, "create"), (2, "delete"), (3, "show"), (4, "list"),
    (5, "bookmark"), (6, "recall"), (7, "retype"), (8, "report"), (9, "exit"),
]


def target_elf(slug: str) -> Path:
    return CORPUS / slug / slug


def require_built(slug: str) -> Path:
    elf = target_elf(slug)
    if not elf.exists():
        pytest.skip(
            f"{slug} is not built -- run "
            f"SUPWNGO_BENCH_CORPUS=benchmark/corpus_uafread benchmark/build_all.sh"
        )
    return elf


def wipe_preceded(elf: Path) -> tuple[int, int]:
    sites = derive_free_sites(str(elf))
    wiped = sum(1 for _fn, prev in sites
                if prev is not None and any(w in prev for w in WIPE_CALLS))
    return len(sites), wiped


class _StubBinary:
    def __init__(self, path: str) -> None:
        self.path = path


class _StubContext:
    """The three attributes `is_applicable`/`skip_reason` actually read."""

    def __init__(self, binary=None, profile_has_menu=False) -> None:
        self.binary = binary
        self.profile_has_menu = profile_has_menu


# ---------------------------------------------------------------------------
# Wiring: the name is the contract with the orchestrator
# ---------------------------------------------------------------------------


def test_the_technique_name_is_exactly_the_orphan_string():
    assert HeapUafReadExecutor.name == "heap_uaf_read"


def test_the_orphan_is_no_longer_an_orphan():
    """`FIRST_TECHNIQUES` names it; the registry now has something behind it."""
    from supwngo.exploit.pipeline.orchestrator import FIRST_TECHNIQUES

    # Assert the SUBJECT of the search exists before trusting the search: an
    # empty list would make the membership check below pass for the wrong reason
    # if it were ever written as an absence.
    assert len(FIRST_TECHNIQUES) > 10
    assert "heap_uaf_read" in FIRST_TECHNIQUES

    names = {ex.name for ex in build_default_registry().all()}
    assert "heap_uaf_read" in names


def test_registered_under_its_own_class():
    matches = [ex for ex in build_default_registry().all()
               if ex.name == "heap_uaf_read"]
    assert len(matches) == 1
    assert isinstance(matches[0], HeapUafReadExecutor)


# ---------------------------------------------------------------------------
# The static gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_static_gate_opens_on_every_positive(slug):
    gate, reason = analyse(str(require_built(slug)))
    assert gate is not None, f"{slug} declined: {reason}"
    assert gate.unwiped, "an open gate must name at least one un-wiped free site"


def test_static_gate_closes_on_the_control_and_says_why():
    gate, reason = analyse(str(require_built(CONTROL)))
    assert gate is None
    # The reason has to name the measured fact, not just refuse: this string is
    # what a reader of a non-solve gets.
    assert "wipe" in reason and "free()" in reason


@pytest.mark.parametrize("slug", ALL_TARGETS)
def test_free_site_table_matches_what_was_measured(slug):
    elf = require_built(slug)
    assert wipe_preceded(elf) == EXPECTED_FREE_SITES[slug]


def test_the_wipe_fact_is_load_bearing(monkeypatch):
    """RED PROOF: change only that fact and the control's gate opens.

    Substituting an un-wiped site (rather than asserting the absence of one)
    keeps this a WRONG-BUT-PRESENT mutation: the image still has three free
    sites, still has its allocators and still has its bulk sink, so if the gate
    still declined, its reason would be something other than the wipe.
    """
    import supwngo.exploit.pipeline.executors.heapuafread_techniques as mod

    elf = require_built(CONTROL)
    assert analyse(str(elf))[0] is None, "precondition: the control is declined"

    real = mod.derive_free_sites

    def one_site_unwiped(path):
        sites = list(real(path))
        assert sites, "precondition: the control has free sites to mutate"
        sites[0] = (sites[0][0], "puts")
        return sites

    monkeypatch.setattr(mod, "derive_free_sites", one_site_unwiped)
    _GATE_CACHE.clear()
    try:
        gate, reason = analyse(str(elf))
        assert gate is not None, (
            "the control was declined for some reason OTHER than its wipes: "
            + reason
        )
    finally:
        _GATE_CACHE.clear()


def test_gate_verdicts_survive_renaming_every_file(tmp_path):
    """The gate must read the image, never the slug/filename/path.

    Every target is copied to a name that says nothing about the family, in a
    directory outside the corpus. All six verdicts must be unchanged -- five open,
    the control closed.
    """
    for slug in ALL_TARGETS:
        src = require_built(slug)
        dest = tmp_path / f"anonymous_image_{ALL_TARGETS.index(slug)}"
        shutil.copy2(src, dest)
        opened = analyse(str(dest))[0] is not None
        assert opened == (slug in POSITIVES), (
            f"{slug} changed verdict when renamed to {dest.name}"
        )


def test_gate_opens_on_the_previously_failing_anchor():
    """The target this category exists to fix.

    `benchmark/corpus/11_heap_uaf_leak` is recorded FAILING in
    docs/reports/PHASE1-BASELINE-24SEP2026.md line 93. The gate opening is the
    necessary condition for the solve measured through the CLI; the solve itself
    is not re-run here.
    """
    if not ANCHOR.exists():
        pytest.skip("benchmark/corpus/ is not built")
    gate, reason = analyse(str(ANCHOR))
    assert gate is not None, reason


def test_gate_also_opens_on_the_uninit_family():
    """MEASURED overlap with `uninit_disclosure`, asserted rather than hidden.

    These are the closest neighbours in the tree: both categories end in a
    disclosure of stale heap bytes. This gate asks only for an unwiped free plus a
    length-bearing sink, which those three positives and that control all satisfy,
    so it opens on them. Loose by design; pinned so nobody infers a narrowness
    that was never measured.
    """
    fam = BENCH / "corpus_uninit"
    overlap = ("uninit_10_stale_heap_chunk", "uninit_12_short_memset",
               "uninit_14_struct_padding", "uninit_90_neg_full_memset")
    present = [s for s in overlap if (fam / s / s).exists()]
    if not present:
        pytest.skip("benchmark/corpus_uninit/ is not built")
    for slug in present:
        gate, reason = analyse(str(fam / slug / slug))
        assert gate is not None, f"{slug} unexpectedly declined: {reason}"


def test_gate_closes_on_the_two_stack_record_uninit_targets():
    """Where the line actually falls -- and it is not a guess about the category.

    `uninit_11` and `uninit_13` keep their record on the STACK, so neither image
    calls `free()` at all. That is the measured reason, and it is the reason the
    gate reports.
    """
    fam = BENCH / "corpus_uninit"
    stack_ones = ("uninit_11_stale_stack_frame", "uninit_13_stale_frame_canary")
    present = [s for s in stack_ones if (fam / s / s).exists()]
    if not present:
        pytest.skip("benchmark/corpus_uninit/ is not built")
    for slug in present:
        gate, reason = analyse(str(fam / slug / slug))
        assert gate is None, f"{slug} unexpectedly opened"
        assert "never calls free()" in reason


def test_gate_is_cached_per_mtime_not_per_path():
    slug = POSITIVES[0]
    elf = require_built(slug)
    first = analyse(str(elf))
    second = analyse(str(elf))
    assert first is second, "the cache must return the same tuple object"


# ---------------------------------------------------------------------------
# Applicability, without spawning anything
# ---------------------------------------------------------------------------


def test_is_applicable_requires_a_binary():
    ex = HeapUafReadExecutor()
    assert ex.is_applicable(_StubContext(binary=None)) is False
    assert ex.skip_reason(_StubContext(binary=None)) == "no binary loaded"


def test_is_applicable_requires_a_menu():
    ex = HeapUafReadExecutor()
    elf = require_built(POSITIVES[0])
    ctx = _StubContext(binary=_StubBinary(str(elf)), profile_has_menu=False)
    assert ex.is_applicable(ctx) is False
    assert "menu" in ex.skip_reason(ctx)
    ctx.profile_has_menu = True
    assert ex.is_applicable(ctx) is True


def test_no_win_function_is_required():
    """A disclosure has nothing to call, so the gate must not ask for one.

    Guarded positively: the stub context below has no `win_function` attribute at
    all, and the gate still opens. A gate that read it would raise here.
    """
    ex = HeapUafReadExecutor()
    ctx = _StubContext(binary=_StubBinary(str(require_built(POSITIVES[0]))),
                       profile_has_menu=True)
    assert not hasattr(ctx, "win_function")
    assert ex.is_applicable(ctx) is True


def test_attempt_skips_cleanly_with_no_binary():
    ex = HeapUafReadExecutor()
    record = ex.attempt(_StubContext(binary=None), verifier=None)
    assert record.technique == "heap_uaf_read"
    assert record.outcome is AttemptOutcome.SKIPPED
    assert record.stage_reached is Stage.ANALYSIS
    assert record.failure_reason == "no binary loaded"


# ---------------------------------------------------------------------------
# Menu roles and the recipe ladder
# ---------------------------------------------------------------------------


def test_classify_reads_the_family_menu_the_way_the_ladder_needs():
    roles = classify(FAMILY_MENU)
    assert 1 in roles["create"]
    assert 2 in roles["free"]
    assert 3 in roles["read"] and 4 in roles["read"]
    # `bookmark` and `retype` are the two commands that turn out to matter for
    # the alias and stale-length shapes, and no verb list predicted which -- so
    # they must land in `other` and be swept, not dropped.
    assert 5 in roles["other"] and 7 in roles["other"]
    # `exit` is recognised and is not swept as an unclassified command.
    assert 9 not in roles["other"]
    assert 9 not in roles["read"] and 9 not in roles["free"]


def test_recall_and_report_are_read_verbs():
    """Two of the five positives disclose through `recall` and `report`.

    If either fell out of READ_VERBS its variant becomes unsolvable, and the
    family would silently measure four mechanisms instead of five.
    """
    roles = classify(FAMILY_MENU)
    assert 6 in roles["read"], "recall must be swept as a read path"
    assert 8 in roles["read"], "report must be swept as a read path"


def test_read_steps_sweeps_every_index_for_every_read_option():
    steps = read_steps([3, 4])
    assert len(steps) == 2 * len(READ_INDICES)
    assert {s.idx for s in steps} == set(READ_INDICES)
    assert SECRET_IDX in READ_INDICES


def test_ladder_covers_all_five_mechanisms_in_the_family():
    ladder = build_ladder(classify(FAMILY_MENU))
    names = " ".join(r.name for r in ladder)
    for shape in ("release_then_read", "rebuild_short_then_read",
                  "alias_then_release", "occupy_then_release",
                  "release_twice", "own_object_release"):
        assert shape in names, f"the ladder lost the {shape} shape"


def test_ladder_recipes_all_release_something():
    ladder = build_ladder(classify(FAMILY_MENU))
    assert ladder, "precondition: the ladder is not empty"
    assert all(r.frees for r in ladder)


def test_baseline_recipe_frees_nothing():
    """The control side of the sweep, which is what makes a solve interpretable.

    A recipe with `frees=False` is the one the AttemptRecord has to label as "the
    secret is reachable here WITHOUT a use-after-free". Building it here pins the
    flag that distinction rides on.
    """
    baseline = Recipe("baseline_no_release", "control side", [],
                      read_steps([3]), False)
    assert baseline.frees is False
    assert baseline.setup == []
    assert baseline.steps == baseline.reads


def test_ladder_is_empty_when_nothing_can_be_released():
    """No free command and no unclassified command -> no shape to try."""
    roles = classify([(1, "show"), (2, "exit")])
    assert roles["free"] == [] and roles["other"] == []
    assert build_ladder(roles) == []


def test_short_write_is_shorter_than_any_plausible_record():
    """uafr_12's mechanism needs a SHORT write, or its tail is overwritten."""
    assert 0 < SHORT_WRITE <= 16


def test_step_repr_is_readable_in_a_report():
    assert repr(Step(2, idx=0)) == "(2, idx=0)"
    assert "size=8" in repr(Step(7, idx=0, size=8, data=b"A" * 8))


# ---------------------------------------------------------------------------
# The plan and the emitted script must not carry the secret
# ---------------------------------------------------------------------------


def test_plan_has_no_field_for_the_disclosed_bytes():
    plan = UafReadPlan()
    fields = set(vars(plan))
    assert "flag" not in fields and "secret" not in fields
    # And the fields that DO exist are the recipe, not the result.
    assert {"steps", "recipe_name", "marker", "prompts"} <= fields


def test_template_writes_the_TARGETs_bytes_and_nothing_else():
    """PRESENCE assertions: the script's output comes from the target's fd 1."""
    assert "sys.stdout.buffer.write(blob)" in _UAFREAD_TEMPLATE
    assert "def route(" in _UAFREAD_TEMPLATE
    assert "STEPS = %(steps)r" in _UAFREAD_TEMPLATE
    # Paired absence check, meaningful only because the presence checks above
    # pin what the script actually does.
    assert "FLAG{" not in _UAFREAD_TEMPLATE


def test_template_has_no_shell_receipt_bridge():
    """Nothing here obtains a shell, so there is no token to write.

    The pipeline's oracle for this script is the FLAG pattern in the TARGET's
    output, which the presence assertion above pins.
    """
    assert "def bridge(" not in _UAFREAD_TEMPLATE
    assert "/bin/sh" not in _UAFREAD_TEMPLATE


def test_flag_regex_matches_what_the_verifier_credits():
    for good in (b"FLAG{abc}", b"flag{abc}", b"HTB{abc}", b"htb{a_b-c}",
                 b"CTF{x}", b"ctf{x}"):
        assert FLAG_RE.search(good), good
    for bad in (b"FLAG", b"FLAG{", b"{abc}", b"flagabc"):
        assert not FLAG_RE.search(bad), bad


def test_flag_regex_finds_a_flag_inside_a_binary_blob():
    """The disclosed bytes are raw chunk contents, not a tidy line."""
    blob = b"\x00\x01\xff" + b"A" * 16 + b"FLAG{deadbeef}" + b"\x00" * 32
    match = FLAG_RE.search(blob)
    assert match and match.group(0) == b"FLAG{deadbeef}"


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------


def test_sweep_budget_fits_inside_the_verification_budget():
    """The sweep must decline inside its budget rather than be killed.

    A sweep killed mid-attempt produces NO AttemptRecord, so the measured reason
    for a non-solve is lost -- which is strictly worse than declining. 45 s is
    also the explicit `verify_script` timeout in `attempt`.
    """
    assert 0 < _SWEEP_BUDGET_SEC <= 45.0
    import inspect
    import supwngo.exploit.pipeline.executors.heapuafread_techniques as mod

    source = inspect.getsource(mod.HeapUafReadExecutor.attempt)
    assert "timeout=45.0" in source


def test_bulk_sink_list_includes_the_one_the_family_uses():
    """uafr_14 discloses through `write(1, ws, WS_SZ)`; the gate needs that name."""
    assert "write" in BULK_SINKS
