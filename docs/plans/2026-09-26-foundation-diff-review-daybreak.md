# Peer review — Sprint 2′ foundation-layer implementation diff

- **Date:** 2026-09-26
- **Reviewer:** Daybreak Blue (`gpt-daybreak-blue-latest`, `model_reasoning_effort=xhigh`, `--sandbox read-only`)
- **Subject:** `git diff d4083dc` over `supwngo/` + the two input-vector test suites (1188 lines), inlined in the prompt
- **Method:** non-interactive `codex exec`, file handoff, polled the output file until its size was stable (0 bytes for 300 s, then 5955 bytes — an empty file would have meant the review silently did not happen)
- **Verdict:** **NOT-APPROVED**
- **Scope note:** the prompt excluded tool-hardening, constant tables, and compliance findings as out of scope, and pinned the advisory-probe design plus the two documented safe false negatives as not-defects, so the reviewer did not spend effort there.

This is the Phase-6 implementation-diff review. It is **not** one of the plan's
three review rounds (those are exhausted; see REVISION 3).

## Verbatim review

# Verdict: NOT-APPROVED

## Findings

1. **HIGH — `DeliverySpec.build_argv()` silently accepts undeliverable or contradictory specifications.**

   The promised closed sink vocabulary is not validated, and a required placeholder does not imply that a usable value was supplied.

   | Input/state | Actual result | Failure |
   |---|---|---|
   | `DeliverySpec(sink="file-arg", payload_filename="p.bin").build_argv("/v")` | `["/v"]` | Typoed/unknown file sink is treated like stdin and silently drops the payload. |
   | `DeliverySpec(SINK_FILE_ARGV, ("{payload_file}",), "p.bin").build_argv("/v")` | `["/v", ""]` | Validation passes, but the default empty `payload_value` supplies no path. |
   | Declared `payload_filename="input.bmp"` with `payload_value="/tmp/input.bin"` | `["/v", "/tmp/input.bin"]` | The declared load-bearing extension is ignored; an extension-gated target rejects the payload. |
   | `SINK_FILE_FIXED` with `argv_template=("{payload_arg}",)` | Payload value is inserted into argv | Contradicts fixed-path semantics; only `{payload_file}` is forbidden. |
   | `SINK_ARGV` containing both placeholder kinds, or `SINK_FILE_ARGV` containing both | Both are replaced with the same value | A typo silently creates an extra or malformed argument instead of raising. |
   | `SINK_STDIN` with `{payload_file}` | Path/empty token is placed in argv although no payload file is implied | An argv-sensitive target can switch away from its working stdin mode. |

   The tests cover missing required placeholders and empty `payload_filename`, but none of these combinations. `build_argv()` should validate the sink itself, reject incompatible placeholder kinds, and reject or derive an empty file-path value.

2. **MEDIUM — the “advisory-only” regression tests do not enforce the property they claim.**

   `TestProbeIsAdvisoryOnly` checks only three parameter names and the absence of the exact global name `ExploitContext`.

   Concrete green regression: change the function to accept `state=None`, then assign `state.delivery_spec = ...`. Alternatively, import a context module under an alias and mutate a singleton. The function-existence check passes, none of `"context"`, `"ctx"`, or `"exploit_context"` appears in the signature, and `"ExploitContext"` need not appear in the module dictionary—yet the probe has become authoritative.

   There are two additional test-structure gaps:

   - `sorted(EXPECTED_VERDICTS.items())` currently happens to cover all ten fixtures, but there is no assertion that its keys equal `FIXTURE_NAMES`. Adding a fixture only to `FIXTURE_NAMES` silently skips its precise expected-verdict test; any wrong non-`file-candidate` verdict remains green.
   - In `test_materialize_does_not_insert_a_trailing_newline`, once `joined == b"ab"` passes, `not joined.endswith(b"\n")` cannot independently fail. It is a tautological second assertion.

3. **MEDIUM — stages 2 and 3 do not isolate file existence or content; pathname differences can manufacture “strong” evidence.**

   Stage 2 compares `missing_input.ext` with `existing_small.ext`; stage 3 compares `existing_small.ext` with `existing_large.ext`. Thus both stages change the pathname as well as the intended variable.

   Concrete scenario: a stdin-payload target merely prints or branches on the supplied basename and never opens it. It prints different text for `missing_input`, `existing_small`, and `existing_large`. The probe reports:

   - `stage2_opened=True`
   - `stage3_volume_sensitive=True`
   - `stage3_basis="output"`
   - verdict `file-candidate`

   despite no file read occurring at all. The same path should be probed absent, then created with 32 bytes, then rewritten with 4096 bytes.

   Even with that correction, the stronger claim that output/return-code evidence implies a genuine payload file sink is unsupported. A fast configuration parser can print “small config” versus “large config” and then take its exploit payload from stdin. That produces a strong `"output"` basis while remaining a non-file payload target. The fixture corpus establishes only its observed examples, not the implication that callers “may rely on.”

4. **MEDIUM — post-stage-0 failure handling contradicts its documented ordering and mislabels launch errors as timeouts.**

   Extension discovery occurs after stage 0 but uses `_run()`, not `_run_tolerant()`. A target that exits normally without argv but hangs only for `bogus_nonexistent_probe` therefore returns `inconclusive-launch`. This contradicts the `_run_tolerant()` claim that everything after stage 0 treats a per-argument timeout as behavioral evidence.

   Separately, `_run_tolerant()` uses the same `None` sentinel for `TimeoutExpired` and every `OSError`, while stage 3 labels either case `"timeout"`.

   Concrete state: the small-file run succeeds, then the executable loses execute permission before the large-file run. The large invocation raises `PermissionError`; the probe returns `file-candidate` with `stage3_basis="timeout"`, even though no process timed out and the difference says nothing about file contents.

5. **LOW — several probe descriptions are stronger than the observations.**

   - Stages 1 and 2 are documented as comparing output, but the implementation compares `(returncode, output)`. Same output with an argc-dependent exit status follows a different classification path than the documented algorithm.
   - Equal missing/existing behavior does not prove the file was “never opened/read.” A target can open and read the existing file, ignore success and data, and return the same observable result.
   - A stage-2 difference followed by equal 32/4096 behavior does not prove the file “is read but only used as configuration”; `stat()`, `access()`, or open-and-close behavior produces the same evidence.

`materialize()` itself correctly performs an exact byte join; I found no current implementation error in that method.