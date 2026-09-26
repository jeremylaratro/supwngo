# Verdict: NOT-APPROVED

The narrowed single-shot scope is coherent and useful, but the revised classifier still has the same unsafe false-positive failure mode. More importantly, T5(c) directly contradicts the specified algorithm.

## Prior findings

| # | Status | Assessment |
|---|---|---|
| 1 | **PARTIALLY CLOSED** | §4 fixes launch identity by probing the direct binary and distinguishes argc-only behavior. It does not establish that exploit bytes belong in the opened file. A config-file-plus-stdin target satisfies all three stages and is promoted to `SINK_FILE`, suppressing its real stdin input. |
| 2 | **CLOSED** | S5 requires call-time resolution from `context.delivery_spec`, and T9 sets the field after verifier construction. This addresses the ordering at [orchestrator.py:152](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:152) versus [orchestrator.py:237](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:237). Implementation must give `PipelineVerifier` a live context reference because it currently holds none at [verifier.py:84](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:84). |
| 3 | **CLOSED** | S6 correctly supports only the raw-payload template, where `PAYLOAD` exists pre-spawn, and refuses generic `build_script()` artifacts. That resolves the ordering at [script_builder.py:113](/srv/share/dev/supwngo/supwngo/exploit/pipeline/script_builder.py:113). Runtime enforcement remains a separate T10 weakness below. |
| 4 | **CLOSED** | §5.1 inventories approximately 15 target/artifact launches and gives each a consume/refuse/defer disposition. The deliberate deferral is coherent with the narrowed scope. |
| 5 | **CLOSED** | T1b replaces “unchanged by construction” with per-site seam assertions. S1/S3 define multi-part materialization as exact `b"".join(parts)`, and T2 addresses the `input=` versus `sendline()` newline difference. |
| 6 | **CLOSED** | T3 now uses `CanonicalAutopwnEngine.run()` with the real probe and wiring, then independently executes the emitted artifact. M-4 is correctly relabeled `inferred` pending the actual pre-change run. |
| 7 | **CLOSED** | Required gates now fail on inconclusive, red proofs are substantive, and the regression command actually deselects the two named failures. |
| 8 | **PARTIALLY CLOSED** | The units are clearer, but the counts are still wrong. The supplied table has **2 conclusive stdin negatives, 1 file positive, and 3 inconclusive-safe targets**. “3 negatives + 1 positive + 3 inconclusive on 6” sums to seven. M-7 should be **5/5 retaining stdin: 2 conclusive negatives + 3 inconclusive-safe**, not 6/6. |
| 9 | **CLOSED** | The receipt-serialization claim is explicitly withdrawn in §3 and §7 rather than left unsupported. |

## Scope coherence

The narrowed capability is not useless. A single-shot executor can compute a complete candidate, `verify_payload()` can materialize it before spawning, and the raw-payload template can replay the successful candidate. Refusing leak-driven, interactive, and multi-round techniques is a legitimate boundary.

It is not shippable as written because:

- The automatic promotion to `SINK_FILE` remains unsafe.
- The promised refusals are not centrally enforced. Several excluded techniques launch before reaching `build_script()`, such as offset discovery at [input_shape_techniques.py:158](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/input_shape_techniques.py:158), direct shellcode at [stack_techniques.py:308](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/stack_techniques.py:308), and UAF execution at [heap_and_bypass.py:249](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_and_bypass.py:249). A refusal inside the script builder is too late for these paths.

## Three-stage probe attack

A deterministic hybrid target defeats it:

1. It accepts a configuration/resource filename in `argv`.
2. Its output differs for missing versus readable files because it opens or inspects that file.
3. It reads the actual vulnerable input from stdin.

It passes determinism, argv sensitivity, and “causal file-open,” so the algorithm selects `SINK_FILE`. S3 then suppresses stdin. That is the **unsafe file-sink route**, not the safe stdin fallback.

T5(c) is exactly this target class. Under the stated algorithm it cannot return `SINK_STDIN`. Output comparison also cannot establish “opened and read”: `stat()`, `access()`, or any existence-dependent branch can produce the same differential.

The advertised `argv-only` representation is also incomplete. `DeliverySpec` has only a `{payload_file}` placeholder; it has no separate auxiliary/configuration-file contents or lifecycle for a target whose config comes from argv while payload bytes come from stdin.

## Gate attacks

- **T1b:** Can pass while file delivery is entirely broken because it pins only the default-stdin seams.
- **T2:** Can pass with wrong argv position, extension, cwd, or creation timing. It proves byte materialization, not that the target receives the file correctly.
- **T3:** Proves one happy path only. It can pass while hybrid targets are misclassified, `deliver_parts()` is broken, or other supported candidates fail. It should also explicitly require the default registry.
- **T5:** Cannot honestly pass fixture (c) under the specified classifier. If the fixture does not produce a missing/existing differential, it no longer tests the claimed adversary.
- **T9:** Merely observing the context spec does not prove it controls the spawned argv/stdin. The assertion should capture the effective launch.
- **T10:** One multi-round technique can refuse while the other excluded techniques still launch through stdin. This needs a central gate or parameterization over every excluded executor.

There is also an exact-replay gap: current executors verify `payload + b"\n"` but store `record.payload = payload`, for example [stack_techniques.py:125](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/stack_techniques.py:125). The current raw template recovers that newline through `sendline()` at [templates.py:178](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:178). A file template that writes only `PAYLOAD` will not reproduce the verified bytes. T6 should assert exact artifact-file bytes, not just a tolerant fixture’s flag.

## Smallest approvable change

Make the behavioral probe advisory rather than authoritative:

> A probe-positive result becomes `FILE_CANDIDATE`; only an explicit public engine option such as `input_vector="file"` may commit `context.delivery_spec` to `SINK_FILE`.

Use that public option in T3/M-5, not an injected verifier spec. Default behavior remains stdin, so a heuristic false positive cannot regress a working target. The same engine-level file-mode branch can centrally refuse unsupported techniques before their `attempt()` methods launch anything.

That is the smallest safe change because generic black-box output differentials cannot prove which input source carries the exploit bytes.