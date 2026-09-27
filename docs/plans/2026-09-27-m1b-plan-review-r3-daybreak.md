# Peer review — 2026-09-27-m1b-plan-review-r3-daybreak

Model: Daybreak Blue (xhigh). Date: 2026-09-27. Non-interactive file handoff. **Round 3 of 3 — FINAL.**

## Verbatim review

Revision 3 remains structurally unsound. The payload-blind defect has recurred, so the plan’s own escalation rule applies.

## Critical

1. **R3.2 still does not replay the complete credited execution, allowing a payload-blind target to be classified DISCRIMINATING.**

   **FAILURE SCENARIO:** A file-argv target ignores file contents, but prints the flag only when both a non-empty file and subsequent stdin are present. The correct artifact wins because `independent_verify()` injects `VERIFY_STDIN` ([run_bench.py](/srv/share/dev/supwngo/benchmark/run_bench.py:721)); existing bare controls have stdin but no file. R3.2’s wrong-payload run is required to preserve only the `DeliverySpec`—sink, filename, and argv template—so an implementation may omit `VERIFY_STDIN`, static argv, auxiliary files, or other replay state. The wrong run then fails and the payload-blind target is falsely credited DISCRIMINATING.

   **Fix:** Escalate the design, as R3.11 requires. Capture one complete launch recipe from the credited replay—exact exec argv, stdin transcript, cwd, environment, static argv, and materialized files—and replay it with only the payload bytes changed. Add a negative target requiring both the normal auxiliary stdin and a non-empty payload while ignoring payload contents. This is the round-1 Critical-2 payload-blind defect class recurring again; another wording patch is insufficient.

2. **The required `90p`, `91a`, and `91b` slugs cannot be built and located under the harness’s incompatible naming rules.**

   **FAILURE SCENARIO:** For `91a_config_flag_stdin`, `build_all.sh` strips only `[0-9][0-9]_`, so it expects `91a_config_flag_stdin.c` and emits that binary ([build_all.sh](/srv/share/dev/supwngo/benchmark/build_all.sh:55)). `Corpus.binary_name()` strips everything through the first underscore, so it expects `config_flag_stdin.c` and `config_flag_stdin` ([run_bench.py](/srv/share/dev/supwngo/benchmark/run_bench.py:252)). The same mismatch affects `90p` and `91b`; required controls therefore become provisioning VOIDs and M-1b can never PASS.

   **Fix:** Give every target a strict two-digit prefix, such as `90_…`, `91_…`, `92_…`, and `93_…`, then update the exact census and tests. Alternatively, change both parsers under one tested slug grammar.

## High

1. **A single-report reducer cannot validate the original corpus-15 fixed point or the mandatory M-1a regression run.**

   **FAILURE SCENARIO:** A vectors report contains rows `00–91`, but not the original `benchmark/corpus/15_win_function` or the other M-1a targets; one `run_bench.py` report has exactly one corpus root and manifest ([run_bench.py](/srv/share/dev/supwngo/benchmark/run_bench.py:1556)). Therefore `m1b_gate.py`, described as reading “a report,” must either remain INCONCLUSIVE forever or silently obtain unstated/stale evidence for clauses 3 and 5.

   **Fix:** Define explicit inputs for the vectors report and a fresh M-1a report, plus the checked-in baseline or expected per-target map. Validate matching harness revision, run configuration, and provenance before comparison.

2. **T-V11 permits a predicate-blind—or permanently INCONCLUSIVE—reducer to pass its entire test suite.**

   **FAILURE SCENARIO:** Implement `m1b_gate.py` as “PASS whenever every slug exists,” ignoring statuses, discrimination, launch evidence, rates, core evidence, and regression results. Every removal case in T-V11 correctly stops producing PASS, so all tests pass. An implementation that always returns INCONCLUSIVE also satisfies every stated T-V11 expectation.

   **Fix:** Add a complete golden report that must PASS, then mutate every predicate while keeping the leg present: wrong status, `discriminating=false`, missing launch evidence, rate below 4/5, VOID, mismatched core evidence, and changed M-1a result.

3. **Control 91b again accepts generic pre-delivery failure as its expected FAILED result.**

   **FAILURE SCENARIO:** Static-argv/file-argv composition drops `{payload_file}` or creates an invalid `DeliverySpec`. The CLI refuses before launching 91b, while 91a succeeds. R3.10 sees `91a SUCCESS / 91b FAILED` and passes because only control 90 requires launch evidence.

   **Fix:** Use one common control-result contract for every expected-negative leg: valid configuration, payload materialized, process exec observed, target liveness observed, and flag absent. This is a recurrence of round-2 High-3; escalate the control design rather than adding another 91-specific exception.

4. **The source-only staging rule excludes the real `profile.cfg` required by 91a.**

   **FAILURE SCENARIO:** R3.8 copies only `.c` and `cflags`. In the fresh workspace, a genuine 91a implementation that opens `profile.cfg` exits because the file is absent, making the required SUCCESS unreachable. If the target merely ignores the named file, the claimed “config file coexisting with stdin delivery” was never demonstrated.

   **Fix:** Add manifest-declared immutable fixtures, stage and hash `profile.cfg`, assert it exists before launch, and forbid fixture paths from overlapping payload paths. Also specify how `target_argv` is merged into `DeliverySpec.argv_template` for both verifier execution and generated replay.

5. **Per-family core evidence is not bound to the binaries that produced the report.**

   **FAILURE SCENARIO:** Run the benchmark using sources with differing geometry, then replace them with family-matching sources before invoking the reducer. The old runtime report supplies SUCCESS while T-V4′ inspects the new tree and supplies core equality. The reducer can PASS although the matching cores were never executed; current reports contain no source, cflags, compiler-command, or binary hashes.

   **Fix:** Record source and cflags hashes, effective compiler argv, and built-binary hash for every rep. Make the reducer validate the archived evidence from the execution rather than unrelated current workspace state.

## Medium

1. **Row 07 has contradictory gate membership.**

   **FAILURE SCENARIO:** R3.3 includes 07 in the ret2win family’s mandatory core comparison, R3.10 says “no row VOID,” but then says 07 is not part of any clause; T-V11 also does not test removal of 07. Different reasonable reducer implementations will respectively reject or accept an absent/VOID 07.

   **Fix:** State one rule mechanically: either 07 is required for census/core/hygiene with status informational, or it is excluded from all gate predicates. Add the corresponding absence and VOID tests.

**VERDICT: NOT-APPROVED**