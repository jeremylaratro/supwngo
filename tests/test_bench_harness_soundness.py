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
               "scrapes_binary_with_tooling": False}
FLAG_FOUND = {"flag_found": True, "shell_proven": False, "ran": True}
NO_FLAG = {"flag_found": False, "shell_proven": False, "ran": True}


class TestNegativeControlGate:
    def test_leaking_control_voids_even_when_flag_found(self):
        """The core FP-1 fix: if the flag is free, nothing is scored SUCCESS."""
        control = {"flag_leaked_without_exploit": ["bare_run_filler"]}
        status, reason = rb.classify(None, FLAG_FOUND, control, CLEAN_AUDIT)
        assert status == "VOID"
        assert "NO exploit" in reason

    def test_leaking_control_beats_autopwn_self_report(self):
        control = {"flag_leaked_without_exploit": ["bare_run_verify_stdin"]}
        status, _ = rb.classify({"success": True}, NO_FLAG, control, CLEAN_AUDIT)
        assert status == "VOID"

    def test_clean_control_allows_success(self):
        status, _ = rb.classify(None, FLAG_FOUND, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "SUCCESS"


class TestAntiGamingScriptAudit:
    @pytest.mark.parametrize("key", [
        "contains_flag_literal",
        "reads_flag_file_directly",
        "scrapes_binary_with_tooling",
    ])
    def test_each_cheat_signal_voids(self, key):
        audit = dict(CLEAN_AUDIT, **{key: True})
        status, _ = rb.classify(None, FLAG_FOUND, CLEAN_CONTROL, audit)
        assert status == "VOID"

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
        status, _ = rb.classify({"success": True}, NO_FLAG, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "PARTIAL"

    def test_partial_on_successful_attempt_without_flag(self):
        j = {"success": False, "attempts": [{"result": "success"}]}
        status, _ = rb.classify(j, NO_FLAG, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "PARTIAL"

    def test_failed_when_nothing_worked(self):
        status, _ = rb.classify({"success": False}, NO_FLAG, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "FAILED"

    def test_shell_proven_is_reported_not_required(self):
        """win()-style targets never get a shell and must still pass."""
        status, reason = rb.classify(None, FLAG_FOUND, CLEAN_CONTROL, CLEAN_AUDIT)
        assert status == "SUCCESS"
        assert "target's own output" in reason
        status, reason = rb.classify(
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
