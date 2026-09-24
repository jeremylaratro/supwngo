"""Regression tests for the benchmark harness's scoring logic.

These cover the decision rules that make benchmark/run_bench.py a trustworthy
measurement instrument, per
docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md. They are pure-logic tests:
no compilation, no pwntools, no autopwn. The end-to-end adversarial checks
live in benchmark/soundness_probes/.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_BENCH = REPO_ROOT / "benchmark" / "run_bench.py"


def _load_run_bench():
    spec = importlib.util.spec_from_file_location("run_bench", RUN_BENCH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_bench"] = mod
    spec.loader.exec_module(mod)
    return mod


rb = pytest.importorskip("yaml") and _load_run_bench()


CLEAN_CONTROL = {"flag_leaked_without_exploit": [], "controls": {}}
CLEAN_AUDIT = {"present": True, "contains_flag_literal": False,
               "reads_flag_file_directly": False,
               "spawns_local_flag_reader": False,
               "scrapes_binary_with_tooling": False}
FLAG_FOUND = {"flag_found": True, "shell_proven": False, "ran": True}
NO_FLAG = {"flag_found": False, "shell_proven": False, "ran": True}


class TestNegativeControlGate:
    def test_leaking_control_voids_even_when_flag_found(self):
        """The core FP-1 fix: if the flag is free, nothing is scored SUCCESS."""
        control = {"flag_leaked_without_exploit": ["bare_run_filler"]}
        status, reason, cause = rb.classify(None, FLAG_FOUND, control, CLEAN_AUDIT)
        assert status == "VOID"
        assert cause == "corpus_trivially_solvable"
        assert "filler" in reason

    def test_harness_stdin_leak_is_distinguished_from_a_weak_target(self):
        """The two controls mean different things and must not share a cause:
        one is an instrument fault, the other a corpus fault."""
        stdin_status, stdin_reason, stdin_cause = rb.classify(
            None, FLAG_FOUND,
            {"flag_leaked_without_exploit": ["bare_run_verify_stdin"]}, CLEAN_AUDIT)
        assert stdin_status == "VOID"
        assert stdin_cause == "harness_stdin_solves_target"
        assert "NO exploit" in stdin_reason
        _s, _r, filler_cause = rb.classify(
            None, FLAG_FOUND,
            {"flag_leaked_without_exploit": ["bare_run_filler"]}, CLEAN_AUDIT)
        assert filler_cause != stdin_cause

    def test_harness_stdin_leak_takes_precedence_over_a_filler_leak(self):
        """If both controls leak, the instrument fault is the one to report --
        a target the harness itself solves cannot be judged at all."""
        _s, _r, cause = rb.classify(
            None, FLAG_FOUND,
            {"flag_leaked_without_exploit": ["bare_run_filler",
                                             "bare_run_verify_stdin"]},
            CLEAN_AUDIT)
        assert cause == "harness_stdin_solves_target"

    def test_leaking_control_beats_autopwn_self_report(self):
        control = {"flag_leaked_without_exploit": ["bare_run_verify_stdin"]}
        status, _r, _cause = rb.classify({"success": True}, NO_FLAG, control, CLEAN_AUDIT)
        assert status == "VOID"

    def test_clean_control_allows_success(self):
        status, _r, _cause = rb.classify(None, FLAG_FOUND, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "SUCCESS"


class TestAntiGamingScriptAudit:
    @pytest.mark.parametrize("key", [
        "contains_flag_literal",
        "reads_flag_file_directly",
        "spawns_local_flag_reader",
        "scrapes_binary_with_tooling",
    ])
    def test_each_cheat_signal_voids(self, key):
        audit = dict(CLEAN_AUDIT, **{key: True})
        status, _r, cause = rb.classify(None, FLAG_FOUND, CLEAN_CONTROL, audit)
        assert status == "VOID"
        assert cause == "script_gamed_the_check"

    @pytest.mark.parametrize("key", [
        "contains_flag_literal",
        "reads_flag_file_directly",
        "spawns_local_flag_reader",
        "scrapes_binary_with_tooling",
    ])
    def test_a_cheat_pattern_that_did_not_work_stays_a_failure(self, key):
        """A cheating script that still produced no flag is a FAILURE, not a
        VOID. Voiding it would drop a failed target out of the denominator and
        silently inflate the success rate."""
        audit = dict(CLEAN_AUDIT, **{key: True})
        status, _r, cause = rb.classify({"success": False}, NO_FLAG,
                                        CLEAN_CONTROL, audit)
        assert status == "FAILED"
        assert cause is None

    def test_clean_script_is_not_flagged(self):
        assert rb.script_cheat_reason(CLEAN_AUDIT) is None

    def test_hardcoded_flag_literal_detected(self, tmp_path):
        secret = "FLAG{" + "a" * 32 + "}"
        s = tmp_path / "x.py"
        s.write_text(f'print("{secret}")\n')
        assert rb.inspect_generated_script(s, secret)["contains_flag_literal"]

    def test_python_side_flag_read_detected(self, tmp_path):
        s = tmp_path / "x.py"
        s.write_text("print(open('flag.txt').read())\n")
        assert rb.inspect_generated_script(s, "FLAG{x}")["reads_flag_file_directly"]

    def test_strings_scrape_detected(self, tmp_path):
        s = tmp_path / "x.py"
        s.write_text("import subprocess\nsubprocess.run(['strings','./vuln'])\n")
        assert rb.inspect_generated_script(s, "FLAG{x}")["scrapes_binary_with_tooling"]

    def test_sending_cat_to_an_obtained_shell_is_legitimate(self, tmp_path):
        """False-negative guard: the intended solve path for shell targets
        must never be mistaken for cheating."""
        s = tmp_path / "x.py"
        s.write_text(
            "from pwn import *\n"
            "io = process('./vuln')\n"
            "io.send(payload)\n"
            "io.sendline(b'cat flag.txt')\n"
        )
        audit = rb.inspect_generated_script(s, "FLAG{x}")
        assert not audit["reads_flag_file_directly"]
        assert not audit["scrapes_binary_with_tooling"]
        assert rb.script_cheat_reason(audit) is None


class TestClassificationOrdinaryPaths:
    def test_partial_on_self_reported_success_without_flag(self):
        status, _r, _cause = rb.classify({"success": True}, NO_FLAG, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "PARTIAL"

    def test_partial_on_successful_attempt_without_flag(self):
        """The key is "outcome"/"SUCCESS" -- what AttemptRecord.to_dict()
        actually emits (supwngo/exploit/pipeline/contracts.py). An earlier
        version read a "result" key that does not exist, making this branch
        dead code, so a run with a self-reported winning attempt was scored a
        flat FAILED instead of PARTIAL."""
        j = {"success": False, "attempts": [{"outcome": "SUCCESS"}]}
        status, _r, _cause = rb.classify(j, NO_FLAG, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "PARTIAL"

    def test_attempt_outcome_key_matches_the_contract(self):
        """Guard against the dead-code regression coming back: this asserts
        against the real contract class, not a hand-written fixture."""
        contracts = REPO_ROOT / "supwngo" / "exploit" / "pipeline" / "contracts.py"
        if not contracts.exists():
            pytest.skip("contracts.py not present in this checkout")
        assert '"outcome": self.outcome.name' in contracts.read_text(), (
            "AttemptRecord.to_dict() no longer emits 'outcome' -- classify()'s "
            "PARTIAL branch reads that key and would go dead"
        )

    def test_failed_when_nothing_worked(self):
        status, _r, _cause = rb.classify({"success": False}, NO_FLAG, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "FAILED"

    def test_shell_proven_is_reported_not_required(self):
        """win()-style targets never get a shell and must still pass."""
        status, reason, _cause = rb.classify(None, FLAG_FOUND, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "SUCCESS"
        assert "target's own output" in reason
        status, reason, _cause = rb.classify(
            None, dict(FLAG_FOUND, shell_proven=True), CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "SUCCESS"
        assert "shell" in reason


class TestSecretFlagHygiene:
    def test_minted_flags_are_unique_and_long_enough(self):
        flags = {rb.mint_secret_flag() for _ in range(200)}
        assert len(flags) == 200
        assert all(len(f) >= rb.MIN_FLAG_LEN for f in flags)
        assert all(f.startswith("FLAG{") and f.endswith("}") for f in flags)

    def test_minted_flags_are_fixed_length(self):
        """Stable length keeps target memory layout stable across runs."""
        assert len({len(rb.mint_secret_flag()) for _ in range(50)}) == 1

    def test_injected_stdin_is_short_enough_for_a_32_byte_read(self):
        """FP-1: a 48-byte stdin solved 13_off_by_one (read(0,buf,32)) by
        itself. Keep it under that; negative controls are the real guard."""
        assert len(rb.VERIFY_STDIN) < 32

    def test_shell_proof_matches_shell_output_not_echoed_input(self):
        assert rb.SHELL_PROOF_RE.search("some output\n42\n")
        assert not rb.SHELL_PROOF_RE.search("You said: echo $((6*7))\n")


class TestCorpusParameterisation:
    def test_default_corpus_paths(self):
        c = rb.Corpus(root=rb.DEFAULT_CORPUS_DIR, manifest=rb.DEFAULT_CORPUS_YAML)
        assert c.binary("15_win_function").name == "win_function"
        assert c.flag_file("15_win_function").name == "flag.txt"
        assert c.source("15_win_function").name == "win_function.c"
        assert c.results_root().name == "results"

    def test_alternate_round_corpus(self):
        root = rb.DEFAULT_CORPUS_DIR.parent / "corpus_r2"
        c = rb.Corpus(root=root, manifest=root.parent / "corpus_r2.yaml")
        assert c.binary("03_some_target").parent == root / "03_some_target"
        assert c.binary("03_some_target").name == "some_target"
        # results are kept beside the corpus they describe
        assert c.results_root().name == "results_r2"

    def test_binary_name_strips_numeric_prefix(self):
        assert rb.Corpus.binary_name("07_ret2libc_leak") == "ret2libc_leak"


class TestVoidIsDetectedNotHardcoded:
    """VOID must come from measurement, so a benign-input-solvable target in
    ANY future corpus is caught automatically rather than needing a manual
    exclusion list."""

    def test_no_target_slug_is_hardcoded_in_the_harness(self):
        src = RUN_BENCH.read_text()
        # Slugs may appear in comments/docstrings explaining the audit, but
        # must never be used in a conditional.
        code = "\n".join(
            line.split("#")[0] for line in src.splitlines()
            if not line.strip().startswith("#")
        )
        for slug in ("13_off_by_one", "off_by_one", "15_win_function"):
            assert f'"{slug}"' not in code and f"'{slug}'" not in code, (
                f"{slug} appears as a string literal in harness code -- VOID "
                f"must be detected, not hardcoded"
            )

    def test_any_target_leaking_to_controls_is_voided(self):
        """Not specific to 13_off_by_one: any slug behaves the same."""
        for name in ("bare_run_verify_stdin", "bare_run_filler"):
            status, _r, _cause = rb.classify(
                {"success": True}, FLAG_FOUND,
                {"flag_leaked_without_exploit": [name]}, CLEAN_AUDIT)
            assert status == "VOID"

    def _summary(self, results, tmp_path):
        return rb.write_summary(results, tmp_path / "s.txt", 12.0,
                                rb.Corpus(root=rb.DEFAULT_CORPUS_DIR,
                                          manifest=rb.DEFAULT_CORPUS_YAML))

    @staticmethod
    def _fifteen(void_cause="harness_stdin_solves_target"):
        return [
            {"slug": "13_off_by_one", "difficulty": "easy", "status": "VOID",
             "void_cause": void_cause,
             "reason": "negative control produced the flag with NO exploit at all"},
            {"slug": "15_win_function", "difficulty": "easy", "status": "SUCCESS",
             "reason": "ok", "verification": {"shell_proven": False}},
        ] + [
            {"slug": f"{i:02d}_t", "difficulty": "medium", "status": "FAILED",
             "reason": "no", "verification": {"shell_proven": False}}
            for i in range(1, 14)
        ]

    def test_void_excluded_from_denominator_and_explained(self, tmp_path):
        text = self._summary(self._fifteen(), tmp_path)
        # 15 run, 1 VOID -> denominator 14, not 15 and not 13
        assert "1/14 SUCCESS" in text
        assert "EXCLUDES 1 VOID" in text
        assert "EXCLUDED FROM SCORING" in text
        assert "NEITHER success NOR failure" in text
        assert "13_off_by_one" in text

    def test_both_denominators_are_printed(self, tmp_path):
        """The /scored rate is the honest one but it moves when the VOID set
        moves, so /total must be printed beside it for comparability."""
        text = self._summary(self._fifteen(), tmp_path)
        assert "1/14 SUCCESS" in text
        assert "1/15 of ALL targets run" in text

    def test_void_cause_and_its_meaning_are_both_in_the_summary(self, tmp_path):
        """summary.txt has to stand alone: a reader must be able to tell an
        instrument fault from a corpus fault without opening a doc."""
        text = self._summary(self._fifteen(), tmp_path)
        assert "harness_stdin_solves_target" in text
        assert rb.VOID_CAUSES["harness_stdin_solves_target"] in text
        # every cause is explained, not just the one that fired
        for cause, meaning in rb.VOID_CAUSES.items():
            assert cause in text and meaning in text

    def test_provisioning_fault_withholds_the_score_entirely(self, tmp_path):
        """A build fault shrinks the denominator, so it would read as a SCORE
        IMPROVEMENT. Refuse to publish a rate instead."""
        text = self._summary(self._fifteen(void_cause="provisioning_failed"),
                             tmp_path)
        assert "NO SCORE PUBLISHED" in text
        assert "1/14 SUCCESS" not in text
        assert "build/infra fault" in text

    def test_every_fatal_cause_withholds_the_score(self, tmp_path):
        for cause in rb.FATAL_VOID_CAUSES:
            text = self._summary(self._fifteen(void_cause=cause), tmp_path)
            assert "NO SCORE PUBLISHED" in text, cause

    def test_all_void_means_no_rate_not_a_zero_division(self, tmp_path):
        results = [{"slug": "01_t", "difficulty": "easy", "status": "VOID",
                    "void_cause": "corpus_trivially_solvable", "reason": "n/a"}]
        text = self._summary(results, tmp_path)
        assert "no scorable targets" in text

    def test_summary_says_so_when_nothing_is_void(self, tmp_path):
        results = [{"slug": "15_win_function", "difficulty": "easy",
                    "status": "SUCCESS", "reason": "ok",
                    "verification": {"shell_proven": False}}]
        text = rb.write_summary(results, tmp_path / "s.txt", 12.0,
                                rb.Corpus(root=rb.DEFAULT_CORPUS_DIR,
                                          manifest=rb.DEFAULT_CORPUS_YAML))
        assert "No VOID targets" in text
        assert "1/1 SUCCESS" in text


class TestMenuWalkControl:
    """A menu-driven target can have no liveness gate on its read path -- the
    flag comes out of a LIVE object and the vulnerability it claims to require
    is never used. The filler blob cannot catch this (scanf("%d") rejects 'A'),
    so a benign menu walk is a separate, standard control."""

    def test_menu_walk_leak_voids_with_its_own_cause(self):
        status, reason, cause = rb.classify(
            None, FLAG_FOUND,
            {"flag_leaked_without_exploit": ["bare_run_menu_walk"]}, CLEAN_AUDIT)
        assert status == "VOID"
        assert cause == "corpus_missing_liveness_gate"
        assert "liveness" in reason

    def test_probes_are_separate_runs_not_one_stream(self):
        """Regression guard, and it is a real one: a single concatenated walk
        reported 11_heap_uaf_leak clean because the stream selected the menu's
        "exit" option before reaching the option that leaks."""
        assert isinstance(rb.CONTROL_MENU_PROBES, tuple)
        assert len(rb.CONTROL_MENU_PROBES) >= 4
        assert not hasattr(rb, "CONTROL_MENU_WALK"), (
            "a single concatenated menu stream is unsound -- an early 'exit' "
            "option masks every option after it"
        )

    def test_each_probe_is_a_plain_menu_selection(self):
        """These must stay benign: a probe long enough to overflow a buffer
        would conflate 'no liveness gate' with 'overflowed by the control'."""
        for probe in rb.CONTROL_MENU_PROBES:
            assert len(probe) < 16, probe
            assert all(c in b"0123456789\n" for c in probe), probe

    def test_menu_cause_is_distinct_from_the_filler_cause(self):
        """Different defects, different fixes: filler means 'does not
        discriminate', menu means 'missing gate on the read path'."""
        _s, _r, filler = rb.classify(
            None, FLAG_FOUND,
            {"flag_leaked_without_exploit": ["bare_run_filler"]}, CLEAN_AUDIT)
        _s, _r, menu = rb.classify(
            None, FLAG_FOUND,
            {"flag_leaked_without_exploit": ["bare_run_menu_walk"]}, CLEAN_AUDIT)
        assert filler != menu
        assert {filler, menu} <= set(rb.VOID_CAUSES)


class TestScrapeChannels:
    def test_behavioural_hits_are_used_when_present(self):
        assert rb.scrape_channels(
            {"flag_scrapeable_without_exploit": ["strings_output"]}
        ) == ["strings_output"]

    def test_falls_back_to_the_image_substring_test(self):
        """If `strings` is missing from the box, the check must not silently
        downgrade to 'no exposure found'."""
        assert rb.scrape_channels(
            {"flag_scrapeable_without_exploit": [],
             "flag_statically_extractable_from_binary": True}
        ) == ["elf_image_substring"]

    def test_no_exposure_reports_none(self):
        assert rb.scrape_channels(
            {"flag_scrapeable_without_exploit": [],
             "flag_statically_extractable_from_binary": False}) == []

    def test_strict_attribution_voids_a_scrapeable_target(self):
        control = {"flag_leaked_without_exploit": [],
                   "flag_scrapeable_without_exploit": ["strings_output"]}
        status, reason, cause = rb.classify(None, FLAG_FOUND, control,
                                            CLEAN_AUDIT, strict_attribution=True)
        assert status == "VOID"
        assert cause == "corpus_flag_is_scrapeable"
        assert "strings" in reason

    def test_strict_attribution_leaves_clean_targets_alone(self):
        control = {"flag_leaked_without_exploit": [],
                   "flag_scrapeable_without_exploit": []}
        status, _r, _c = rb.classify(None, FLAG_FOUND, control, CLEAN_AUDIT,
                                     strict_attribution=True)
        assert status == "SUCCESS"

    def test_strict_attribution_is_off_by_default(self):
        """Default-on would exclude every win()-style target, which must
        compile its flag in -- that is a corpus fix, not a scoring change."""
        control = {"flag_leaked_without_exploit": [],
                   "flag_scrapeable_without_exploit": ["strings_output"]}
        status, _r, _c = rb.classify(None, FLAG_FOUND, control, CLEAN_AUDIT)
        assert status == "SUCCESS"


class TestAttributionStrengthIsReported:
    """A SUCCESS on a target whose flag sits in the binary image is only as
    good as the (bypassable) script audit. A SUCCESS on a target whose image
    holds no flag is a structural argument. The two must not look alike."""

    WEAK = {"flag_leaked_without_exploit": [],
            "flag_statically_extractable_from_binary": True}
    STRONG = {"flag_leaked_without_exploit": [],
              "flag_statically_extractable_from_binary": False}

    def test_weak_attribution_is_flagged_in_the_reason(self):
        status, reason, _c = rb.classify(None, FLAG_FOUND, self.WEAK, CLEAN_AUDIT)
        assert status == "SUCCESS"
        assert "WEAK ATTRIBUTION" in reason

    def test_strong_attribution_carries_no_caveat(self):
        status, reason, _c = rb.classify(None, FLAG_FOUND, self.STRONG, CLEAN_AUDIT)
        assert status == "SUCCESS"
        assert "WEAK ATTRIBUTION" not in reason

    def test_weak_attribution_does_not_change_the_score(self):
        """It is a caveat, not a downgrade: a scrapeable flag is inherent to
        win()-style targets, so voiding them would gut the corpus and conflate
        'weakly attributed' with 'unmeasurable'."""
        for control in (self.WEAK, self.STRONG):
            status, _r, cause = rb.classify(None, FLAG_FOUND, control, CLEAN_AUDIT)
            assert status == "SUCCESS" and cause is None

    def test_summary_separates_weak_from_strong_successes(self, tmp_path):
        results = [
            {"slug": "15_win_function", "difficulty": "easy", "status": "SUCCESS",
             "reason": "ok", "verification": {"shell_proven": False},
             "negative_control": self.WEAK},
            {"slug": "02_ret2plt_system", "difficulty": "medium",
             "status": "SUCCESS", "reason": "ok",
             "verification": {"shell_proven": True},
             "negative_control": self.STRONG},
        ]
        text = rb.write_summary(results, tmp_path / "s.txt", 12.0,
                                rb.Corpus(root=rb.DEFAULT_CORPUS_DIR,
                                          manifest=rb.DEFAULT_CORPUS_YAML))
        assert "WEAKLY attributed" in text
        assert "1 of 2 SUCCESS" in text
        # the weak one is named, and the strong one is named as strong
        assert "- 15_win_function:" in text
        assert "Strongly attributed" in text and "02_ret2plt_system" in text

    def test_summary_omits_the_block_when_all_successes_are_strong(self, tmp_path):
        results = [{"slug": "02_ret2plt_system", "difficulty": "medium",
                    "status": "SUCCESS", "reason": "ok",
                    "verification": {"shell_proven": True},
                    "negative_control": self.STRONG}]
        text = rb.write_summary(results, tmp_path / "s.txt", 12.0,
                                rb.Corpus(root=rb.DEFAULT_CORPUS_DIR,
                                          manifest=rb.DEFAULT_CORPUS_YAML))
        assert "WEAKLY attributed" not in text


class TestExcerpt:
    def test_short_text_kept_whole(self):
        assert rb._excerpt("hello", 100) == "hello"

    def test_long_text_keeps_both_ends(self):
        """The old out[-4000:] hid the flag behind trailing stderr warnings."""
        text = "FLAGSTART" + ("x" * 5000) + "ENDWARNING"
        got = rb._excerpt(text, 100)
        assert got.startswith("FLAGSTART")
        assert got.endswith("ENDWARNING")
        assert "omitted" in got
