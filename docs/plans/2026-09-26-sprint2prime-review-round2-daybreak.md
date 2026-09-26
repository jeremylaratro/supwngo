# Verdict: NOT-APPROVED

The plan still rests on an invalid inference: “argv changes output” is treated as “the exploit payload belongs in a file.” That is not established, and false positives do not degrade safely. There are also ordering and call-graph holes that would leave the detected spec unapplied.

## Critical findings

### 1. The argv-differential probe does not identify a file payload sink

**Section:** §4, S2/S8, T4/T5.

[`probe_argv_vector()`](/srv/share/dev/supwngo/docs/plans/2026-09-26-sprint2prime-input-vector-plan.md:115) proves only that two executions produced different output. It does not prove that:

- the target opened the supplied path;
- the target read payload bytes from that file;
- stdin ceased to be the exploit channel.

It gives false positives for:

- stdin targets printing a PID, ASLR address, nonce, or timestamp;
- stdin targets with argc-dependent banners or option parsing;
- targets taking a config/resource filename in argv while reading the vulnerable input from stdin;
- hybrid targets needing both an argv file and stdin.

The latter two should be representable as `sink=SINK_STDIN` plus a non-empty `argv_template`—an advertised advantage of Method A—but the feeder instead unconditionally flips `sink` to file.

This does **not** degrade safely. A false positive removes the working stdin delivery and can regress a solvable target. Only errors, timeouts, inconclusive results, and false negatives degrade safely.

The measurement “0 false positives” covers three deterministic negatives, not these classes. It also uses a bundled-loader invocation while production generally launches the binary directly, so its match identity differs from the consumer being classified.

**Required change:** Separate “argv sensitivity” from “payload sink.” At minimum:

1. Reject nondeterminism by requiring repeated within-condition stability.
2. Demonstrate a causal file-open transition using same-extension nonexistent versus readable paths.
3. Do not select `SINK_FILE` merely because argc changes output.
4. Add negative fixtures for nondeterministic stdout, argc-sensitive stdin, and argv-plus-stdin targets.
5. Probe through the same argv/env/loader construction used by actual delivery.

### 2. The detected spec will be stale in `PipelineVerifier`

**Section:** S5/S8 and ordering.

The engine constructs `PipelineVerifier` in `__init__` before the prologue runs ([orchestrator.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:152)). The proposed spec is computed later in the prologue ([plan S8](/srv/share/dev/supwngo/docs/plans/2026-09-26-sprint2prime-input-vector-plan.md:160); current prologue begins here: [orchestrator.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:237)).

Therefore a constructor-carried spec will be `None`/stdin even after `context.delivery_spec` changes. Merely storing the result on the context does not update the verifier.

Dynamic profiling and leak acquisition also execute targets after detection should occur, but the plan does not say they consume the spec.

**Required change:** Define the runtime order explicitly:

`static analysis → vector probe → assign spec → configure/create verifier → vector-aware dynamic profile/leak acquisition → attempts`

Alternatively, make every consumer resolve `context.delivery_spec` at call time. Add an end-to-end assertion that the verifier sees the exact same spec object/value stored on the context.

### 3. S6 cannot work with the current generated-script shape

**Section:** S6.

In `script_builder`, the target is spawned before the body computes its payload ([script_builder.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/script_builder.py:113)). `open_target()` receives no payload ([script_builder.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/script_builder.py:88)). It therefore cannot “write the payload file and pass argv” as proposed.

There are 13 `build_script()` consumers across the executor modules, many constructing payloads dynamically or in multiple stages. Editing only `script_builder.py` does not provide the payload before spawn. The universal template has the same ordering problem: it spawns at line 74 and constructs `payload` later.

**Required change:** Define a realizable file-artifact contract before implementation. Either:

- file-mode scripts provide a pre-spawn payload expression/hook and all 13 builder callers are updated; or
- dynamic/multipart builders explicitly declare file delivery unsupported rather than emitting a misleading artifact.

The raw-payload success template is simpler because `PAYLOAD` already exists before spawn, but that does not solve the generic builder path.

## High findings

### 4. The “five spawn sites” inventory is materially incomplete

**Section:** §1 and §5.

Additional canonical target launches include:

- [profile_stage.py:198](/srv/share/dev/supwngo/supwngo/exploit/pipeline/profile_stage.py:198)
- [leak_stage.py:82](/srv/share/dev/supwngo/supwngo/exploit/pipeline/leak_stage.py:82)
- GDB target execution at [_shared.py:77](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/_shared.py:77)
- `spawn_and_send()` at [_shared.py:250](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/_shared.py:250)
- [heap_and_bypass.py:166](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_and_bypass.py:166), [280](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_and_bypass.py:280), and [376](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_and_bypass.py:376)
- [stack_techniques.py:352](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/stack_techniques.py:352)
- [canary_leak_techniques.py:247](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/canary_leak_techniques.py:247)

Missed forwarding contracts include `deliver_parts_expect_shell`, `_crashes_with_padding`, `find_return_offset`, `resolve_offset(s)`, and `spawn_and_send`.

The sub-component table also omits:

- `core/context.py`, where the claimed context field must be declared;
- `orchestrator.py`, which must synchronize the spec and verifier;
- all `build_script()` callers;
- `VerificationReceipt`, despite the receipt-serialization claim.

**Required change:** Replace the five-site claim with a semantic inventory of every canonical target execution. Mark static-tool subprocesses such as `objdump` separately. Every target launch must either consume the spec or explicitly document why it must not.

### 5. Default stdin is not “unchanged by construction”

**Section:** §3 and T1.

For the listed forms:

- `subprocess.run([binary])` can remain exactly `[binary]`;
- `process([binary])` can remain exactly `[binary]`;
- current pwntools normalizes `process(BINARY)` to a one-element argv list, so changing it to `[BINARY]` is launch-equivalent under the current dependency.

But T1 proves only a pure function returns `[binary]`. It does not prove any site actually uses it or preserves:

- exact stdin bytes;
- `send` versus `sendline`;
- cwd, environment, timeout, or inter-part timing;
- absence of file creation;
- generated artifact bytes.

File semantics are also undefined. `deliver_parts` has a sequence of parts, while S3 says “write payload” singular. Verification currently has exact `subprocess.run(input=payload)` versus pwntools `sendline(payload)`, which adds a newline. The plan does not define file contents for either case or whether stdin is suppressed in file mode.

**Required change:** Preserve the current stdin branch literally at each site. Define file materialization precisely—e.g. exact bytes or `b"".join(parts)`—and explicitly remove stdin delivery in file mode. Add per-site seam tests capturing argv, stdin writes, cwd, env, and newline behavior. If “byte-identical” includes artifacts, add golden-output tests for default generated scripts.

### 6. T3/M-4 can pass without proving automatic canonical integration

**Section:** T3 and M-4.

T3 says the fixture succeeds with a spec and fails with `spec=None`. That can go green while S8 is broken, the verifier has a stale spec, or the detector is never called. It proves manually injected plumbing, not “solved by the canonical pipeline.”

The baseline is also labeled `measured`, although the proposed fixture and test do not yet exist. At present it is an inferred structural claim.

**Required change:** T3 must invoke `CanonicalAutopwnEngine(...).run()` with:

- no injected spec;
- no supplied offset/known facts;
- the real probe;
- the real context/verifier wiring;
- the emitted artifact executed independently afterward.

Run that exact fixture on the pre-change revision and record the failure before calling the baseline measured.

## Medium findings

### 7. Several red-proofs are weak or vacuous

**Section:** §6.

- **T1:** Mutating `sink` need not change `build_argv()` if argv construction ignores the sink. It does not exercise any launch site.
- **T2:** Reasonable pure-contract test.
- **T3:** Sound only after the end-to-end correction above.
- **T4:** An argv-ignoring fixture is too easy; it cannot catch argc-sensitive stdin or nondeterministic-output false positives.
- **T5:** “Return True unconditionally” catches only the most trivial defect, not the actual classifier error.
- **T6:** Potentially sound, provided it runs in a clean directory with no pre-existing payload file.
- **T7:** Deleting a fixture and getting a setup error proves subject existence, not that the five stdin paths remain functional.
- **T8:** Sound if the induced failure occurs after file creation.
- **Three-state rule:** A required gate reported as skipped/xfail/inconclusive can leave pytest green. Required capability gates must fail on inconclusive; only tests specifically exercising the tri-state API should assert an inconclusive result.

The stated regression command also does not actually exclude either known failure. Supply exact `--deselect` node IDs or compare a recorded result vector.

### 8. M-4 through M-7 are not all correctly unitted

**Section:** §7.

- **M-4:** Use `fixture targets solved: 0/1 → 1/1`; change baseline provenance to inferred until the pre-change fixture run exists. `tests/...::T3` is not a concrete pytest node ID as written.
- **M-5:** “Gate 0” is outside the four-gate B-3 ladder. Define the unit as `validation gates passed, 0/4 → 2/4`. Run it through the new delivery abstraction; a manual direct run with argv can pass today and is not attributable to the implementation. Assert the exact signature-stage error, not merely “some later/different output.”
- **M-6:** The target unit is valid, but “5/5 reliable” is mis-unitted. Correct wording is `13/13 eligible targets SUCCESS; each target 5/5 reps`. Keep the per-target vector.
- **M-7:** The table contains **3 negatives, 1 positive, and 2 inconclusive**, not “4/6 probe-negative.” Four of six is the number of conclusive rows. The correct routing metric is `5/5 known stdin targets retain SINK_STDIN`, including the two safe-fallback inconclusives, plus their per-target outcome vector.

### 9. The receipt-provenance claim has no implementation component

**Section:** §3 benefit claim and §5.

`VerificationReceipt` currently has no delivery field, and neither S1 nor S5 says to modify its schema or `to_dict()`. A frozen dataclass is not automatically receipt-serializable.

**Required change:** Either add a serialized delivery snapshot to `VerificationReceipt` and populate it at every receipt construction site, or remove the claim that the harness can audit delivery from the receipt.

The plan is directionally reasonable, but its feeder, propagation order, artifact contract, and evidence gates are not yet sufficient to prevent another premise-driven failed sprint.