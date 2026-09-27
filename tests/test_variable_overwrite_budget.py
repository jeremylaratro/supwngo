"""
Executable gate for the `variable_overwrite` candidate budget (item B-1).

Gap analysis: docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md B-1
Plan / metric M-3: docs/plans/2026-09-26-legacy-to-canonical-sprint-plan.md

`VariableOverwriteExecutor` recovers gate constants from the target's own
`cmp`/`test` immediates instead of only sweeping a fixed folklore list. That
recovery is what makes a non-folklore gate constant reachable at all, but each
extra candidate costs a full 14-entry buffer-size sweep, so an unbounded
recovered list inflates the worst case: `comparison_immediates()`'s own default
(`limit=24`) plus the 9 fallback values is 33 candidates -> 462 attempts,
3.67x the pre-recovery 126, measured on `snowscan`.

The first attempt at a bound capped the *recovered slice* at 6, which does not
bound the total (6 recovered + 9 fallback = 15 -> 210, 1.67x) and therefore
still violated M-3. The cap must apply to the **merged** list. These tests
exist so that regression cannot recur silently.

M-3's stated threshold is 1.25x of 126 = 158 attempts.

Note on units: this counts *candidate payloads*, which is the quantity the cap
controls. It is deliberately NOT called a process-spawn count -- a failed
`verify_payload()` may launch the target more than once, so spawns are a
multiple of this number, not equal to it.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from supwngo.core.binary import Binary
from supwngo.core.context import ExploitContext
from supwngo.exploit.pipeline.contracts import (
    SINK_STDIN, AttemptOutcome, DeliverySpec,
)
from supwngo.exploit.pipeline.executors.input_shape_techniques import (
    FALLBACK_MAGIC_VALUES,
    comparison_immediates,
)
from supwngo.exploit.pipeline.executors.stack_techniques import (
    MERGED_CANDIDATE_CAP,
    VariableOverwriteExecutor,
)

BUFFER_SWEEP_LEN = 14
PRE_RECOVERY_ATTEMPTS = 126  # 9 folklore values x 14 buffer sizes
M3_MAX_ATTEMPTS = 158  # 1.25x of 126, per metric M-3

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "i3_candidate_provenance"

#: A target whose recovered-immediate list is long enough to exercise the cap.
#: Built from source rather than relying on an HTB binary, which is not
#: committed to this repo.
_MANY_CONSTANTS_SRC = """
#include <stdio.h>
#include <string.h>
/* Many distinct comparison immediates, so comparison_immediates() returns a
   list longer than the cap and truncation is genuinely exercised. The gate
   this target actually checks is deliberately LAST in numeric order so it is
   a realistic "ranks below the cap" case. */
int main(void) {
    char buf[64]; unsigned int gate = 0;
    if (gate == 0x111) return 1;   if (gate == 0x222) return 1;
    if (gate == 0x333) return 1;   if (gate == 0x444) return 1;
    if (gate == 0x555) return 1;   if (gate == 0x666) return 1;
    if (gate == 0x777) return 1;   if (gate == 0x888) return 1;
    if (gate == 0x999) return 1;   if (gate == 0xaaa) return 1;
    if (gate == 0xbbb) return 1;   if (gate == 0xccc) return 1;
    if (gate == 0xddd) return 1;   if (gate == 0xeee) return 1;
    if (gate == 0x1234) return 1;  if (gate == 0x5678) return 1;
    if (gate == 0x9abc) return 1;  if (gate == 0xdef0) return 1;
    read(0, buf, 512);
    if (gate == 0x7ACEBEEF) puts("win");
    return 0;
}
"""


@pytest.fixture(scope="module")
def many_constants_binary(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("vo_budget")
    src = d / "many_constants.c"
    src.write_text(_MANY_CONSTANTS_SRC)
    out = d / "many_constants"
    subprocess.run(
        ["gcc", "-m64", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0",
         "-w", "-o", str(out), str(src)],
        check=True, capture_output=True, text=True,
    )
    assert out.is_file()
    return out


class TestCapIsTightEnoughForM3:
    """The cap must be a number that actually satisfies M-3, independent of any
    particular binary."""

    def test_cap_times_buffer_sweep_is_within_the_m3_threshold(self):
        worst_case = MERGED_CANDIDATE_CAP * BUFFER_SWEEP_LEN
        assert worst_case <= M3_MAX_ATTEMPTS, (
            f"MERGED_CANDIDATE_CAP={MERGED_CANDIDATE_CAP} yields {worst_case} "
            f"attempts, over M-3's {M3_MAX_ATTEMPTS}"
        )

    def test_the_superseded_recovered_slice_only_bound_would_fail_this_gate(self):
        """Positive control / red-proof: the bound this replaced (cap the
        RECOVERED slice at 6, leaving the 9 fallbacks uncapped) must be shown to
        FAIL the threshold. Without this, a green result above proves nothing
        about whether the gate can discriminate a bad bound from a good one.
        """
        superseded_total = 6 + len(FALLBACK_MAGIC_VALUES)  # == 15
        superseded_attempts = superseded_total * BUFFER_SWEEP_LEN  # == 210
        assert superseded_attempts > M3_MAX_ATTEMPTS, (
            "the superseded recovered-slice-only bound must violate M-3, "
            "otherwise this gate cannot tell a bad bound from a good one"
        )


class TestCapIsEnforcedAgainstARealBinary:
    def test_recovered_list_is_long_enough_to_exercise_truncation(
            self, many_constants_binary):
        """Guard against a vacuous pass: if this binary yielded fewer
        candidates than the cap, the truncation tests below would be testing
        nothing."""
        available = comparison_immediates(Binary.load(str(many_constants_binary)))
        assert len(available) > MERGED_CANDIDATE_CAP, (
            f"fixture yields only {len(available)} candidates, which does not "
            f"exceed the cap ({MERGED_CANDIDATE_CAP}) -- truncation is not "
            f"exercised and the gate is vacuous"
        )

    def test_attempt_count_stays_within_m3_on_a_constant_rich_binary(
            self, many_constants_binary):
        """The executor must not issue more than the cap allows. Counted by a
        verifier double, so this is the real executor's real candidate loop
        without paying for process spawns."""
        calls: list[bytes] = []

        class _CountingVerifier:
            def resolve_delivery_spec(self):
                """I-7: the executor asks which sink it will deliver over so it can
                prune candidates the transport cannot carry. This double stands in for
                the real PipelineVerifier, whose own resolution defaults to stdin when
                no spec has been set, so that is what it returns."""
                return DeliverySpec(
                    sink=SINK_STDIN, payload_filename="", argv_template=()
                )

            def verify_payload(self, technique, payload):
                calls.append(payload)
                class _R:
                    success = False
                return _R()

        context = ExploitContext()
        context.binary = Binary.load(str(many_constants_binary))
        record = VariableOverwriteExecutor().attempt(context, _CountingVerifier())

        assert record.outcome == AttemptOutcome.FAILED
        assert len(calls) <= M3_MAX_ATTEMPTS, (
            f"executor issued {len(calls)} attempts, over M-3's "
            f"{M3_MAX_ATTEMPTS}"
        )
        assert len(calls) == MERGED_CANDIDATE_CAP * BUFFER_SWEEP_LEN, (
            f"expected exactly the capped sweep "
            f"({MERGED_CANDIDATE_CAP}x{BUFFER_SWEEP_LEN}), got {len(calls)}"
        )


class TestTruncationIsReportedNotSilent:
    """A gate constant ranking below the cap is an accepted limitation, but it
    must be *diagnosable*. If truncation were silent, such a target would look
    identical to one with no recoverable constant at all."""

    def test_failure_reason_states_how_many_candidates_were_not_tried(
            self, many_constants_binary):
        class _NeverWins:
            def resolve_delivery_spec(self):
                """I-7: the executor asks which sink it will deliver over so it can
                prune candidates the transport cannot carry. This double stands in for
                the real PipelineVerifier, whose own resolution defaults to stdin when
                no spec has been set, so that is what it returns."""
                return DeliverySpec(
                    sink=SINK_STDIN, payload_filename="", argv_template=()
                )

            def verify_payload(self, technique, payload):
                class _R:
                    success = False
                return _R()

        context = ExploitContext()
        context.binary = Binary.load(str(many_constants_binary))
        record = VariableOverwriteExecutor().attempt(context, _NeverWins())

        assert record.failure_reason != ""
        assert "were NOT tried" in record.failure_reason
        assert str(MERGED_CANDIDATE_CAP) in record.failure_reason

    def test_no_truncation_claim_when_nothing_was_truncated(self):
        """The paired half of the assertion above: with no binary the candidate
        list is the 9 fallbacks, under the cap, so the executor must NOT claim
        anything was dropped. Prevents the message becoming boilerplate that is
        emitted regardless of what happened."""
        class _NeverWins:
            def resolve_delivery_spec(self):
                """I-7: the executor asks which sink it will deliver over so it can
                prune candidates the transport cannot carry. This double stands in for
                the real PipelineVerifier, whose own resolution defaults to stdin when
                no spec has been set, so that is what it returns."""
                return DeliverySpec(
                    sink=SINK_STDIN, payload_filename="", argv_template=()
                )

            def verify_payload(self, technique, payload):
                class _R:
                    success = False
                return _R()

        record = VariableOverwriteExecutor().attempt(ExploitContext(), _NeverWins())
        assert record.failure_reason != ""
        assert "were NOT tried" not in record.failure_reason


class TestFailureReasonStaysClearOfTheScriptAuditVocabulary:
    """`templates.py` interpolates `failure_reason` into generated scripts, and
    `run_bench.py`'s `_SCRAPES_BINARY_RE` routes `strings`/`objdump`/`readelf`/
    `xxd` to a cheat verdict. The new truncation wording must not introduce one.
    """

    def test_new_wording_does_not_match_the_audit_regex(self, many_constants_binary):
        import importlib.util
        import sys

        pytest.importorskip("yaml")
        spec = importlib.util.spec_from_file_location(
            "run_bench_budget_audit", REPO_ROOT / "benchmark" / "run_bench.py")
        rb = importlib.util.module_from_spec(spec)
        sys.modules["run_bench_budget_audit"] = rb
        spec.loader.exec_module(rb)

        # Positive control: prove the regex can still go red.
        assert rb._SCRAPES_BINARY_RE.search("ran objdump on it")

        class _NeverWins:
            def resolve_delivery_spec(self):
                """I-7: the executor asks which sink it will deliver over so it can
                prune candidates the transport cannot carry. This double stands in for
                the real PipelineVerifier, whose own resolution defaults to stdin when
                no spec has been set, so that is what it returns."""
                return DeliverySpec(
                    sink=SINK_STDIN, payload_filename="", argv_template=()
                )

            def verify_payload(self, technique, payload):
                class _R:
                    success = False
                return _R()

        context = ExploitContext()
        context.binary = Binary.load(str(many_constants_binary))
        record = VariableOverwriteExecutor().attempt(context, _NeverWins())
        assert not rb._SCRAPES_BINARY_RE.search(record.failure_reason)
