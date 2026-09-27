# Peer review — 2026-09-26-m1b-plan-review-r2-sol

Model: Sol 5.6 (xhigh). Date: 2026-09-26. Non-interactive file handoff. Round 2 of 3.

## Verbatim review

Revision 2 remains unapprovable: two core gates are still structurally unsound, and several controls can pass or fail for reasons unrelated to payload transport.

## Critical

1. **Round-1 Critical 2 remains unfixed, and row 06’s `0x41414141` gate makes filler-only delivery score SUCCESS.**

   **FAILURE SCENARIO:** Row 06’s adjacent variable is compared with `0x41414141`, while `VariableOverwriteExecutor` uses `A` as its filler. A payload-blind implementation that sends 512 `A` bytes through argv overwrites the variable with the winning value without recovering or appending the comparison constant. T-V6 passes because the filler is NUL-free; the existing negative control invokes only `[binary]` with stdin, so it never tests that filler through argv. Row 06 is credited SUCCESS despite not validating payload construction.

   **Fix:** Choose a NUL-free value distinct from the filler, such as `0x42434445`, and implement the accepted delivery-aware control for every required row: deliver the successful payload and a same-length wrong payload through the exact `DeliverySpec`; only the correct bytes may disclose the flag. The 90/91 pairs are not substitutes for per-row discrimination.

2. **The “one shared vulnerable core across every row” gate is incompatible with a matrix containing both ret2win and variable-overwrite techniques.**

   **FAILURE SCENARIO:** T-V4 compares row 02’s saved-return-address overwrite and win-symbol path with row 08’s adjacent-variable comparison gate. If it enforces R2.6 literally—identical vulnerable core and win path—it rejects two correctly authored targets. If it ignores the technique-specific difference, it no longer establishes that the variable-overwrite rows share a controlled core.

   **Fix:** Define two explicit core families: a ret2win core for `01–05/07`, and a variable-overwrite core for `06/08/09`. Give the variable-overwrite family its own non-required stdin fixed point, then enforce source geometry, read length, gate/win path, and effective flags within each family.

## High

1. **R2.9 has no executable reducer, so missing controls can still produce an apparent 7-of-7 pass.**

   **FAILURE SCENARIO:** Run `run_bench.py` with only targets `02,03,04,05,06,08,09`. The generic summary reports 7/7 SUCCESS; neither `90p` nor `91b` exists in the report, and existing `write_summary()` has no knowledge of the M-1b PASS/FAIL/INCONCLUSIVE rules. Nothing mechanically converts the missing legs into INCONCLUSIVE.

   **Fix:** Add a committed M-1b reducer that validates the exact required slug census, expected control statuses, core evidence, fixed point, and VOID/build conditions, and emits one authoritative three-state verdict. Test removal of every individual leg.

2. **T-V9 cannot pass against the current, correct normalization contract.**

   **FAILURE SCENARIO:** `_normalize_argv_template()` normalizes `@@` only while building argv, but `DeliverySpec.to_dict()` serializes the original `argv_template`. Consequently `("-f", "@@")` and `("-f", "{payload_file}")` produce different dictionaries while producing identical launch argv. The proposed gate therefore rejects working behavior. See [contracts.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/contracts.py:128) and [contracts.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/contracts.py:381).

   **Fix:** Compare `build_argv()` outputs using the same payload path. Only change `to_dict()` if canonicalized serialization is separately intended and specified.

3. **The negative controls accept generic pre-delivery failure, and 90/90p still lack complete file-sink configurations.**

   **FAILURE SCENARIO:** Leave `--input-name` absent from control 90, as the governing text still does, but configure 90p correctly. Control 90 is refused for an invalid `DeliverySpec` and records the required FAILED; 90p succeeds. The pair passes even though 90 never launched with a payload file and therefore proved nothing about ignoring file contents. If both follow the text literally, 90p cannot succeed at all.

   **Fix:** Specify complete CLI arguments for every control. Require identical valid `DeliverySpec`s and effective flags for 90/90p, validate them with `build_argv()`, and require evidence that the negative leg actually launched with the materialized file before FAILED is accepted.

## Medium

1. **The 91 pair does not exercise the claimed “config file in argv, payload on stdin” behavior on its positive leg.**

   **FAILURE SCENARIO:** A target that simply runs the stdin vulnerability when `argc == 1` and exits whenever any argument is present satisfies the gate: 91a with `cli_args: []` succeeds, while 91b fails. The source files are byte-identical, yet no run demonstrated that an argv config file can coexist with stdin payload delivery.

   **Fix:** Run 91a with a real static config argument/file while retaining the stdin sink, then change only the payload sink for 91b. This needs an explicit static-target-argv manifest path because the current CLI rejects `--input-argv` with the stdin vector.

2. **R2.3’s fresh-workspace procedure and T-V8 staging are underspecified, while the claimed existing private cwd is only a banner assertion.**

   **FAILURE SCENARIO:** An implementation creates a rep directory with `copytree(target_dir, rep_dir)`. Because the seeded stale `input.dat` is inside `target_dir`, it is copied into the supposedly fresh workspace; the bare negative control still wins and row 05 becomes VOID. Current `_run_one_isolated()` creates a private TMPDIR but continues using the persistent corpus target directory as cwd. See [run_bench.py](/srv/share/dev/supwngo/benchmark/run_bench.py:1218).

   **Fix:** Define source-only workspace staging—copy an allowlist such as source and `cflags`, build inside a newly empty rep directory, and assert the declared payload path is absent before controls. T-V8 must seed the persistent/prior workspace, not the newly created rep workspace.

3. **Exact equality of two five-rep reliability values is a flaky fixed-point gate.**

   **FAILURE SCENARIO:** Byte-identical row 01 and corpus 15 produce 5/5 and 4/5 because one process hits the documented delivery race. R2.9 declares the milestone failed even though the fixed point and ingress behavior are unchanged.

   **Fix:** Pre-register a reliability threshold or statistically meaningful comparison, and report both observed rates. Do not require exact equality of two small stochastic samples.

4. **Revision 2 still labels code inspection and self-reported banners as `measured`, contrary to its own provenance definition.**

   **FAILURE SCENARIO:** R2.1 says “measured by reading the code,” R2.2 derives behavior from source lines, and R2.3 calls a banner proof of private cwd. A final report can therefore cite runtime measurement for facts that have no archived execution—and the cwd claim is materially weaker than the banner states.

   **Fix:** Label these `inferred` or `verified by inspection`; reserve `measured` for archived executions with inputs and outputs.

VERDICT: NOT-APPROVED