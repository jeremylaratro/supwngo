# Peer review — 2026-09-26-m1b-plan-review-r1-sol

Model: Sol 5.6 (xhigh). Date: 2026-09-26. Non-interactive file handoff.

## Verbatim review

## Critical

1. **The 7/7 PASS condition is unreachable with the current engine.**

   **Failure scenario:** `06_win_argv_direct` uses ret2win, whose payload contains a packed 64-bit address and therefore NUL bytes; argv delivery explicitly rejects any NUL-containing payload ([verifier.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:237), [stack_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/stack_techniques.py:205)). Separately, `09_negidx_file_argv` requires `negative_index_write`, but every non-stdin technique outside `{"variable_overwrite", "ret2win"}` is deliberately refused ([orchestrator.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:133), [orchestrator.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:427)). Thus two required rows fail regardless of manifest plumbing.

   **Fix:** Replace row 06 with an argv-compatible no-NUL payload shape, such as variable overwrite. Remove row 09 from the required matrix, or separately scope and implement negative-index non-stdin delivery. Merely adding it to the allowlist is insufficient because its executor currently hardcodes stdin delivery.

2. **The inherited VOID controls do not exercise the declared ingress, so a trivially solvable file target can score SUCCESS.**

   **Failure scenario:** A defective `file-argv` target prints the secret whenever it opens any non-empty file, regardless of payload contents. `negative_control()` launches only `[binary]` and supplies stdin fillers—no payload file, argv path, flag template, or fixed file ([run_bench.py](/srv/share/dev/supwngo/benchmark/run_bench.py:507), [run_bench.py](/srv/share/dev/supwngo/benchmark/run_bench.py:521)). It sees no flag. The generated artifact then writes arbitrary bytes to a file, launches with the declared argv, and the target prints the flag; behavioral attribution credits the target and reports SUCCESS. This is exactly the payload-blind implementation the gate is meant to reject.

   **Fix:** Make negative controls delivery-spec-aware: materialize benign/wrong payloads through the exact declared sink, filename, and argv template, plus counterfactual routes. Assert a correct-content payload succeeds while wrong-content payloads over the same ingress do not.

## High

1. **The file-vector rows omit the mandatory `--input-name`, making their delivery specs invalid as written.**

   **Failure scenario:** Rows 02–05, 07–09, and 90 declare file vectors without filenames. The engine constructs `payload_filename=""` ([orchestrator.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:235)), while both file sinks reject an empty filename ([contracts.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/contracts.py:320), [contracts.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/contracts.py:334)). The allowlisted techniques are skipped as invalid, and the matrix fails for configuration rather than transport behavior.

   **Fix:** Specify complete `cli_args` in the matrix and manifest: every `file-argv` row needs a concrete payload filename, and row 05 must use exactly `--input-name input.dat`. Gate the resulting `DeliverySpec.to_dict()`, not merely raw argument forwarding.

2. **The fixed-file variant will self-contaminate later reps and turn a real success into VOID.**

   **Failure scenario:** Rep 1’s generated script writes `input.dat` and intentionally does not remove it ([templates.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:345); the behavior is acknowledged in [test_input_vector_delivery.py](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:263)). Rep 2 rebuilds the same non-PIE target with an equal-length new flag, then runs the bare negative control before generating a new script. The stale winning `input.dat` remains valid, reaches the new flag, and the target becomes VOID. A subsequent benchmark run can fail on its first rep for the same reason.

   **Fix:** Give every rep a fresh target working directory, or backup/remove/restore every manifest-declared payload path before controls and after verification. Add a red test seeded with a stale winning fixed-path file.

3. **The required two-state result for control 91 cannot be represented by the proposed single manifest entry.**

   **Failure scenario:** With `cli_args: []`, target 91 measures only stdin-SUCCESS; with `file-argv` arguments, it measures only file-argv-FAILED. `run_bench.py` executes each target under one fixed manifest configuration, so the report can never contain both facts required by the PASS condition.

   **Fix:** Define two byte-identical target entries with distinct slugs/configurations, or define two immutable manifests and a gate program that joins their reports. The reducer must emit PASS/FAIL/INCONCLUSIVE and fail when either leg is absent.

## Medium

1. **T-V3’s stated red-proof does not make control 90 pass.**

   **Failure scenario:** Target 90 has no vulnerability or flag-producing path. Changing it from “does not open the payload file” to “opens the payload file” only exposes generated payload bytes; those bytes do not contain the fresh secret. It therefore remains FAILED, so the mutation does not prove the control can go red.

   **Fix:** Specify a mutation that makes the received file bytes reach a deterministic flag gate, then show SUCCESS only after that mutation. Alternatively use a paired positive target with the same source except for the causal file-consumption branch.

2. **The single byte-identical baseline does not isolate ingress changes in the rewritten variants.**

   **Failure scenario:** Row 02 accidentally uses an `fread` length too short to reach the saved return address, or row 04 changes buffer geometry/build flags. Row 01 still matches corpus 15 and passes, while the variant fails for a changed vulnerability rather than transport. T-V4 checks only source identity for row 01; recorded manifest flags do not prove the builder used matching flags.

   **Fix:** Build variants from a shared vulnerable core with only the ingress adapter varied. Mechanically compare buffer geometry, vulnerable length, win path, and effective compiler flags, and hand-run a known-good payload through each declared route plus counterfactual routes.

3. **The “0 of 7 measured” baseline is inferred and presently undefined, not measured.**

   **Failure scenario:** The plan simultaneously says the corpus does not exist and labels its pre-change result `measured` ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-26-m1b-variation-benchmark-plan.md:162)). No historical revision ran these seven targets, so reporting a measured +7 improvement creates an observation that never occurred.

   **Fix:** Either label it `inferred`/counterfactual, or construct the corpus and benchmark-only plumbing on the historical revision and archive the actual report.

4. **[R1] incorrectly says `@@` is unsupported.**

   **Failure scenario:** `--input-argv "-f @@"` is split into `("-f", "@@")`, normalized to `{payload_file}`, and works identically ([contracts.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/contracts.py:128)). The plan therefore diagnoses a valid historical spelling as a transport-breaking typo.

   **Fix:** State that `{payload_file}` is the chosen canonical spelling, not the only supported spelling, and retain an equivalence test for both forms.

VERDICT: NOT-APPROVED