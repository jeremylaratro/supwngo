"""Regression tests for the benchmark harness's scoring logic.

These cover the decision rules that make benchmark/run_bench.py a trustworthy
measurement instrument, per
docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md. They are pure-logic tests:
no compilation, no pwntools, no autopwn. The end-to-end adversarial checks
live in benchmark/soundness_probes/.
"""
import importlib.util
import sys
import time
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

    def test_report_records_the_settings_that_change_a_verdicts_meaning(self):
        """A report that omits these cannot be compared against another report.

        `strict_attribution` decides whether an unwitnessed success scores at
        all, and `jobs` is the scheduling shape the run used -- two runs of the
        same corpus that differ in either are not the same experiment. Found
        during the R4 plumbing check, where a report gave no way to tell.
        """
        import ast

        tree = ast.parse(RUN_BENCH.read_text())
        main = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "main")
        keys: set[str] = set()
        for node in ast.walk(main):
            if isinstance(node, ast.Dict):
                got = {k.value for k in node.keys
                       if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                if "corpus_root" in got and "results" in got:
                    keys = got
                    break
        assert keys, "could not find main()'s report dict"
        for required in ("jobs", "strict_attribution", "corpus_root", "manifest",
                         "timeout", "targets_run"):
            assert required in keys, (
                f"report.json omits {required!r}; a run artifact must record the "
                f"settings that change what its verdicts mean"
            )


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

    def test_scrapeability_is_reported_on_the_unwitnessed_path(self):
        """Scrapeability no longer decides anything by itself -- behavioural
        attribution does. It survives as a severity note on the fallback path."""
        control = {"flag_leaked_without_exploit": [],
                   "flag_scrapeable_without_exploit": ["strings_output"]}
        status, reason, _c = rb.classify(None, FLAG_FOUND, control, CLEAN_AUDIT)
        assert status == "SUCCESS"
        assert "UNWITNESSED" in reason
        assert "strings_output" in reason


class TestAttributionStrengthIsReported:
    """A SUCCESS on a target whose flag sits in the binary image is only as
    good as the (bypassable) script audit. A SUCCESS on a target whose image
    holds no flag is a structural argument. The two must not look alike."""

    WEAK = {"flag_leaked_without_exploit": [],
            "flag_statically_extractable_from_binary": True}
    STRONG = {"flag_leaked_without_exploit": [],
              "flag_statically_extractable_from_binary": False}

    WITNESSED = {"available": True, "flag_disclosed_by_target": True,
                 "flag_in_output": True, "target_observed": True,
                 "shell_proven": False,
                 "credited_writers": [{"pid": 42, "chain": "42:win_function <- 7:python3"}],
                 "uncredited_writers": []}
    NOT_CREDITED = {"available": True, "flag_disclosed_by_target": False,
                    "flag_in_output": True, "target_observed": True,
                    "shell_proven": False, "credited_writers": [],
                    "uncredited_writers": [{"pid": 7, "chain": "7:python3"}]}
    NO_WITNESS = {"available": False, "unavailable_reason": "strace is not installed"}

    def test_witnessed_success_says_so_and_carries_no_caveat(self):
        status, reason, cause = rb.classify(
            None, FLAG_FOUND, self.WEAK, CLEAN_AUDIT, attribution=self.WITNESSED)
        assert status == "SUCCESS" and cause is None
        assert "BEHAVIOURALLY ATTRIBUTED" in reason
        assert "UNWITNESSED" not in reason

    def test_a_witness_overrides_scrapeability(self):
        """The whole point: once we have watched the target disclose the flag,
        the fact that the flag is ALSO scrapeable stops mattering."""
        status, reason, _c = rb.classify(
            None, FLAG_FOUND, self.WEAK, CLEAN_AUDIT, attribution=self.WITNESSED)
        assert status == "SUCCESS"
        assert "scrapeable" not in reason

    def test_not_credited_is_void_and_blames_the_script(self):
        status, reason, cause = rb.classify(
            None, FLAG_FOUND, self.WEAK, CLEAN_AUDIT, attribution=self.NOT_CREDITED)
        assert status == "VOID"
        assert cause == "script_gamed_the_check"
        assert "WITHOUT exploiting" in reason

    def test_a_witness_overrides_a_clean_pattern_audit(self):
        """pure_python_scrape.py passes every regex. The witness must still
        reject it -- that is the hole behavioural attribution exists to close."""
        status, _r, cause = rb.classify(
            None, FLAG_FOUND, self.WEAK, CLEAN_AUDIT, attribution=self.NOT_CREDITED)
        assert status == "VOID" and cause == "script_gamed_the_check"

    def test_missing_witness_falls_back_and_is_labelled(self):
        """A missing witness is NOT a negative witness."""
        status, reason, cause = rb.classify(
            None, FLAG_FOUND, self.STRONG, CLEAN_AUDIT, attribution=self.NO_WITNESS)
        assert status == "SUCCESS" and cause is None
        assert "UNWITNESSED" in reason
        assert "strace is not installed" in reason

    def test_strict_attribution_voids_an_unwitnessed_success(self):
        status, reason, cause = rb.classify(
            None, FLAG_FOUND, self.STRONG, CLEAN_AUDIT,
            attribution=self.NO_WITNESS, strict_attribution=True)
        assert status == "VOID"
        assert cause == "unwitnessed_success"
        assert "--strict-attribution" in reason

    def test_strict_attribution_keeps_witnessed_successes(self):
        status, _r, cause = rb.classify(
            None, FLAG_FOUND, self.WEAK, CLEAN_AUDIT,
            attribution=self.WITNESSED, strict_attribution=True)
        assert status == "SUCCESS" and cause is None

    def test_a_cheating_script_that_produced_nothing_still_just_fails(self):
        """Attribution must not turn a plain failure into a VOID and shrink
        the denominator."""
        status, _r, cause = rb.classify(
            {"success": False}, NO_FLAG, self.WEAK,
            dict(CLEAN_AUDIT, reads_flag_file_directly=True),
            attribution={"available": True, "flag_in_output": False,
                         "flag_disclosed_by_target": False,
                         "target_observed": True})
        assert status == "FAILED" and cause is None

    def test_summary_separates_witnessed_from_unwitnessed(self, tmp_path):
        results = [
            {"slug": "15_win_function", "difficulty": "easy", "status": "SUCCESS",
             "reason": "ok", "verification": {"shell_proven": False},
             "negative_control": self.WEAK, "attribution": self.WITNESSED},
            {"slug": "02_ret2plt_system", "difficulty": "medium",
             "status": "SUCCESS", "reason": "ok",
             "verification": {"shell_proven": True},
             "negative_control": self.STRONG, "attribution": self.NO_WITNESS},
        ]
        text = rb.write_summary(results, tmp_path / "s.txt", 12.0,
                                rb.Corpus(root=rb.DEFAULT_CORPUS_DIR,
                                          manifest=rb.DEFAULT_CORPUS_YAML))
        assert "1 behaviourally witnessed, 1 unwitnessed" in text
        assert "WITNESSED    15_win_function" in text
        assert "UNWITNESSED  02_ret2plt_system" in text
        assert "--strict-attribution" in text
        # the credited write chain is shown, so the claim is checkable
        assert "42:win_function <- 7:python3" in text


class TestParallelSchedulingIntegrity:
    """Speed must never cost result integrity: results stay in manifest order,
    one target's crash cannot alter another's verdict, and a harness fault is
    loud rather than a silent denominator shrink."""

    TARGETS = [{"slug": f"{i:02d}_t", "technique": "x", "difficulty": "easy"}
               for i in range(1, 8)]

    def _fake_run_one(self, monkeypatch, behaviour):
        seen = []

        def fake(corpus, target, timeout, results_dir, strict_attribution=False,
                 tmpdir=None, echo=True):
            seen.append((target["slug"], tmpdir))
            return behaviour(target, tmpdir)

        monkeypatch.setattr(rb, "run_one", fake)
        return seen

    def test_results_come_back_in_manifest_order(self, monkeypatch, tmp_path):
        """Completion order under parallelism is nondeterministic; the report
        must not be."""
        import random

        def behaviour(target, tmpdir):
            time.sleep(random.uniform(0, 0.05))
            return {"slug": target["slug"], "status": "FAILED", "reason": "x",
                    "difficulty": "easy"}

        self._fake_run_one(monkeypatch, behaviour)
        out = rb.run_targets(None, self.TARGETS, 1.0, tmp_path,
                             strict_attribution=False, jobs=4)
        assert [r["slug"] for r in out] == [t["slug"] for t in self.TARGETS]

    def test_each_target_gets_a_private_tmpdir(self, monkeypatch, tmp_path):
        seen = self._fake_run_one(
            monkeypatch,
            lambda t, d: {"slug": t["slug"], "status": "FAILED", "reason": "x",
                          "difficulty": "easy"})
        rb.run_targets(None, self.TARGETS, 1.0, tmp_path,
                       strict_attribution=False, jobs=4)
        dirs = [d for _s, d in seen]
        assert all(d is not None for d in dirs)
        assert len(set(map(str, dirs))) == len(self.TARGETS), "tmpdirs collided"
        assert all(Path(d).is_dir() for d in dirs)

    def test_one_target_crashing_does_not_affect_the_others(self, monkeypatch, tmp_path):
        def behaviour(target, tmpdir):
            if target["slug"] == "03_t":
                raise RuntimeError("boom")
            return {"slug": target["slug"], "status": "FAILED", "reason": "x",
                    "difficulty": "easy"}

        self._fake_run_one(monkeypatch, behaviour)
        out = rb.run_targets(None, self.TARGETS, 1.0, tmp_path,
                             strict_attribution=False, jobs=4)
        assert len(out) == len(self.TARGETS)
        crashed = [r for r in out if r["slug"] == "03_t"][0]
        assert crashed["status"] == "VOID"
        assert crashed["void_cause"] == "harness_error"
        assert all(r["status"] == "FAILED" for r in out if r["slug"] != "03_t")

    def test_a_harness_error_is_fatal_and_withholds_the_score(self):
        """An instrument fault must not read as a score change -- it removes a
        target from the denominator, which would push the rate UP."""
        assert "harness_error" in rb.FATAL_VOID_CAUSES
        assert "harness_error" in rb.VOID_CAUSES

    def test_serial_and_parallel_agree(self, monkeypatch, tmp_path):
        def behaviour(target, tmpdir):
            return {"slug": target["slug"],
                    "status": "SUCCESS" if target["slug"] == "02_t" else "FAILED",
                    "reason": "x", "difficulty": "easy"}

        self._fake_run_one(monkeypatch, behaviour)
        serial = rb.run_targets(None, self.TARGETS, 1.0, tmp_path / "a",
                                strict_attribution=False, jobs=1)
        parallel = rb.run_targets(None, self.TARGETS, 1.0, tmp_path / "b",
                                  strict_attribution=False, jobs=5)
        assert [(r["slug"], r["status"]) for r in serial] == \
               [(r["slug"], r["status"]) for r in parallel]

    def test_default_job_count_is_bounded(self):
        """angr will happily exhaust memory, so the default is capped rather
        than 'however many cores this box has'."""
        assert 1 <= rb._default_jobs() <= 8


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
