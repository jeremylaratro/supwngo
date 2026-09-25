"""
Tests for wiring the I2 prologue-stage timings and the pwntools load-state
fields into the `autopwn --json` payload (`supwngo/cli.py`'s `result` dict).

Both fields already existed with zero readers before this change:

- `CanonicalAutopwnEngine.static_analysis_duration_sec` /
  `dynamic_profile_duration_sec` / `leak_acquisition_duration_sec`
  (`supwngo/exploit/pipeline/orchestrator.py:170-172`, computed in
  `_run_prologue()`).
- `Binary.pwntools_load_state` / `pwntools_load_error` /
  `protections_measured` (`supwngo/core/binary.py`, commit `3453f09`).

These tests exercise the real `autopwn --json` CLI as a subprocess end to
end (mirroring `tests/test_solve_command.py`'s `_run_solve` pattern and
`benchmark/run_bench.py`'s `run_supwngo`/`parse_json_result`) rather than
importing `cli.py`'s `autopwn` function directly, because the point being
proven is specifically that the *payload* a real invocation prints carries
these values - not that some internal object has them (that was already
proven by `tests/test_i2_attempt_duration.py` and
`tests/test_binary_load_state.py`, which predate and do not touch `cli.py`).

Per the brief: never assert on `AttemptRecord.notes`/`failure_reason` here,
and never touch `benchmark/`, `orchestrator.py`, or `binary.py`.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_BINARY = REPO_ROOT / "benchmark" / "corpus" / "15_win_function" / "win_function"


@pytest.fixture(scope="module", autouse=True)
def _require_pwnlib():
    pytest.importorskip("pwn")


def _run_autopwn_json(binary: Path, timeout: float = 3.0, wall_timeout: float = 90.0) -> dict:
    """Invoke the real `autopwn --json` CLI as a subprocess and parse the
    trailing JSON object off stdout, matching
    `benchmark/run_bench.py::parse_json_result`'s defensive
    find-first-brace/find-last-brace approach (rich also prints log lines
    before the JSON)."""
    proc = subprocess.run(
        [sys.executable, "-m", "supwngo.cli", "autopwn", str(binary),
         "--timeout", str(timeout), "--json"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=wall_timeout,
    )
    assert proc.returncode == 0, (
        f"autopwn --json exited {proc.returncode}\nSTDOUT:\n{proc.stdout}\n"
        f"STDERR:\n{proc.stderr}"
    )
    start = proc.stdout.find("{")
    end = proc.stdout.rfind("}")
    assert start != -1 and end > start, f"no JSON object found in stdout:\n{proc.stdout}"
    return json.loads(proc.stdout[start:end + 1])


def _write_bad_elf(tmp_path: Path) -> Path:
    """A file that satisfies `click.Path(exists=True)` but is not a valid
    ELF, so `Binary._load_with_pwntools()`'s `except Exception` arm fires
    for real (same mechanism `tests/test_binary_load_state.py`'s
    `test_generic_pwntools_failure_reports_load_failed_not_success` proves
    at the `Binary` level - this drives the same failure through the real
    CLI instead)."""
    bad = tmp_path / "notanelf"
    bad.write_text("not an elf file at all, just padding text 1234567890")
    bad.chmod(0o755)
    return bad


# ---------------------------------------------------------------------------
# Part A - the "prologue" key (I2 stage timings)
# ---------------------------------------------------------------------------

class TestPrologueJsonPayload:
    def test_prologue_present_nonzero_and_mutually_distinct(self):
        """Positive instance: a real run against a real corpus binary must
        emit all three stage durations, each present, non-null, non-zero,
        and mutually distinct from the other two - three equal numbers
        would mean one clock read was reused (or a constant was hardcoded)
        rather than each stage being timed separately."""
        result = _run_autopwn_json(CORPUS_BINARY)

        assert "prologue" in result
        prologue = result["prologue"]
        assert set(prologue.keys()) == {
            "static_analysis_duration_sec",
            "dynamic_profile_duration_sec",
            "leak_acquisition_duration_sec",
        }

        static = prologue["static_analysis_duration_sec"]
        dynamic = prologue["dynamic_profile_duration_sec"]
        leak = prologue["leak_acquisition_duration_sec"]

        for name, value in (("static", static), ("dynamic", dynamic), ("leak", leak)):
            assert value is not None, f"{name} duration was None on a run where the prologue ran"
            assert isinstance(value, float), f"{name} duration was not a float: {value!r}"
            assert value > 0, f"{name} duration was not > 0: {value!r}"

        assert len({static, dynamic, leak}) == 3, (
            f"stage durations were not mutually distinct: "
            f"static={static}, dynamic={dynamic}, leak={leak} - this is exactly "
            f"what a single reused clock read or a hardcoded constant would produce")

    def test_prologue_present_even_when_the_binary_fails_to_load(self, tmp_path):
        """Gate-scope requirement: `_run_prologue()` runs unconditionally
        inside `run()`, regardless of whether `Binary.load()` succeeded, so
        the "prologue" key must be present with real (non-None) values even
        on a target whose ELF load failed - not only on the happy path.
        A gate keyed to "the key exists somewhere in some report" would
        pass even if `cli.py` only populated it inside a success branch;
        this proves it is unconditional."""
        bad_elf = _write_bad_elf(tmp_path)
        result = _run_autopwn_json(bad_elf, timeout=1.0, wall_timeout=90.0)

        prologue = result["prologue"]
        assert prologue["static_analysis_duration_sec"] is not None
        assert prologue["dynamic_profile_duration_sec"] is not None
        assert prologue["leak_acquisition_duration_sec"] is not None
        assert prologue["static_analysis_duration_sec"] > 0
        assert prologue["dynamic_profile_duration_sec"] > 0
        assert prologue["leak_acquisition_duration_sec"] > 0


# ---------------------------------------------------------------------------
# Part B - the "binary_load" key (pwntools load state, commit 3453f09)
# ---------------------------------------------------------------------------

class TestBinaryLoadJsonPayload:
    def test_successful_load_emits_success_state_null_error_measured_true(self):
        """Positive instance: a successful load emits the success state, a
        null error, and `protections_measured` true - asserted against the
        actual JSON payload the CLI prints, not `Binary`'s attribute
        directly (that is `tests/test_binary_load_state.py`'s job)."""
        result = _run_autopwn_json(CORPUS_BINARY)

        assert result["binary_load"] == {
            "pwntools_load_state": "success",
            "pwntools_load_error": None,
            "protections_measured": True,
        }

    def test_forced_load_failure_emits_failed_state_in_the_payload(self, tmp_path):
        """Failure instance: a forced pwntools load failure must emit the
        failed state IN THE JSON PAYLOAD, with the error string present.
        Asserting `Binary.pwntools_load_state` directly would only re-test
        commit 3453f09 and prove nothing about `cli.py`'s wiring - this
        drives the real CLI subprocess end to end and reads stdout."""
        bad_elf = _write_bad_elf(tmp_path)
        result = _run_autopwn_json(bad_elf, timeout=1.0, wall_timeout=90.0)

        binary_load = result["binary_load"]
        assert binary_load["pwntools_load_state"] == "load_failed"
        assert binary_load["pwntools_load_state"] != "success"
        assert binary_load["pwntools_load_error"], (
            "expected a non-empty error string on a forced load failure")
        assert binary_load["protections_measured"] is False


# ---------------------------------------------------------------------------
# Both parts - the new values must never reach a generated exploit script
# (Class 2 / constraint 1: `templates.py` renders `notes`/`failure_reason`
# into scripts that `benchmark/rep_divergence.py` hashes per rep).
# ---------------------------------------------------------------------------

_NEW_FIELD_NAMES = (
    "prologue",
    "static_analysis_duration_sec",
    "dynamic_profile_duration_sec",
    "leak_acquisition_duration_sec",
    "binary_load",
    "pwntools_load_state",
    "pwntools_load_error",
    "protections_measured",
)


class TestNewFieldsNeverReachGeneratedScripts:
    def test_templates_source_never_reads_the_new_field_names(self):
        """Structural guard mirroring `tests/test_i2_attempt_duration.py`'s
        `test_templates_source_never_reads_duration_sec`: `templates.py`
        must never reference any of the new field names, because doing so
        would put a per-run-varying value into a generated script that
        `rep_divergence.py` hashes per rep."""
        templates_src = (REPO_ROOT / "supwngo" / "exploit" / "pipeline"
                          / "templates.py").read_text()
        for name in _NEW_FIELD_NAMES:
            assert name not in templates_src, (
                f"templates.py unexpectedly references {name!r}")

    def test_generated_script_from_a_real_run_contains_none_of_the_new_fields(
            self, tmp_path):
        """Behavioural proof, not just trust: run `autopwn` (no `--json`,
        matching how `-o` actually writes a script) against the same real
        corpus binary the positive-instance tests above use, and confirm
        none of the new field names show up anywhere in the written
        script's text."""
        output = tmp_path / "exploit.py"
        proc = subprocess.run(
            [sys.executable, "-m", "supwngo.cli", "autopwn", str(CORPUS_BINARY),
             "--timeout", "3", "-o", str(output)],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert output.exists()
        script_text = output.read_text()

        for name in _NEW_FIELD_NAMES:
            assert name not in script_text, (
                f"generated script unexpectedly contains {name!r} - this is "
                f"the exact per-rep divergence hazard constraint 1 exists to "
                f"prevent")
