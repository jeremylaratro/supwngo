NOT-APPROVED

No Critical findings.

## High

1. H1 is not fully closed: repeated placeholders produce a silently wrong artifact.

`DeliverySpec.build_argv()` and the verifier replace every occurrence, but `_render_embedded_token()` splits only once at [templates.py:142](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:142).

Concrete failure:

- Input: `SINK_ARGV`, token `"{payload_arg}:{payload_arg}"`, payload `b"X"`.
- Verification launches with `b"X:X"`.
- Generated artifact launches with `PAYLOAD + b":<random-sentinel>"`.

I confirmed the generated output directly. The same defect affects repeated `{payload_file}` occurrences. Generation succeeds, so this is silent artifact divergence and should block.

2. Non-stdin verification and artifacts disagree about fd 0.

The subprocess verifier uses `input=b""`, producing immediate EOF at [verification.py:286](/srv/share/dev/supwngo/supwngo/exploit/verification.py:286). The pwntools fallback and generated artifacts spawn with an open PTY and neither send nor close it at [verification.py:340](/srv/share/dev/supwngo/supwngo/exploit/verification.py:340) and [templates.py:316](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:316).

Concrete failure:

- Target waits for EOF on stdin before opening its declared file/argv input.
- `subprocess.run` verification reaches EOF and wins.
- Generated artifact waits indefinitely or exits without reproducing the win because the target never receives EOF.
- The fallback may instead feed shell-verification commands into that initial stdin read.

This is a new spawn-path divergence and should block.

3. File materialization failures are converted into generic exploitation failures.

`target_path.write_bytes(...)` runs through `pre_spawn` at [verifier.py:317](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:317), but `ExploitVerifier` catches any resulting exception and returns an unsuccessful result at [verification.py:308](/srv/share/dev/supwngo/supwngo/exploit/verification.py:308). The executors then discard those notes and eventually report only “no combination was confirmed.”

Concrete failure:

- Input: file vector targeting a non-writable binary directory or missing parent directory.
- No payload file is ever delivered.
- The run reports that payload candidates failed, rather than that delivery itself failed.

That violates the loud-failure requirement and should block.

## Round-2 disposition

| Finding | Status | Assessment |
|---|---|---|
| C1 | CLOSED | All non-stdin sinks reach the allowlist gate at [orchestrator.py:427](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:427). |
| C2 | CLOSED | Actual argv/file remote branches raise before connecting at [templates.py:308](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:308) and [templates.py:327](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:327). Test coverage remains weak, below. |
| H1 | NOT CLOSED | Single embedded placeholders work; repeated legal placeholders diverge at [templates.py:142](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:142). |
| H2 | CLOSED | Non-empty stdin templates reach both verifier argv and generated artifacts at [verifier.py:208](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:208) and [templates.py:286](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:286). |
| M1 | CLOSED | Sink validation precedes stdin/non-stdin classification at [orchestrator.py:405](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:405). |
| M2 | CLOSED for stock non-stdin executors | Both stock executors populate the field, and non-stdin templates prefer it. The fallback and stdin caveats below remain. |
| Six old test defects | CLOSED | Artifacts are executed; child consumption is observed; fallback consumption is observed; and all three cleanup tests prove mid-attempt materialization before checking cleanup. |

The no-flag code path remains unchanged in the reviewed implementation: `delivery_spec` stays `None`, default verifier argv remains the binary alone, and the pinned stdin script remains exact.

## Remaining tests that can pass without the named capability

- The C1 test enumerates only four non-allowlisted names at [test_input_vector_delivery.py:995](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:995). A gate hard-coded to refuse those names—plus `srop` for the older wiring test—while allowing the other registered non-allowlisted techniques remains green. Derive the cases from `registry.names() - FILE_DELIVERY_ALLOWLIST`.

- The “allowlisted pair” positive control exercises only `variable_overwrite` at [test_input_vector_delivery.py:1048](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:1048). Removing `ret2win` support leaves this file green.

- M2 directly tests `delivered_bytes` assignment only for `variable_overwrite` at [test_input_vector_delivery.py:904](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:904). Removing either `ret2win` assignment leaves all delivery tests green.

- Remote refusal tests only inspect source text at [test_input_vector_delivery.py:799](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:799). Mutation `if REMOTE_HOST and False:` retains every asserted string while silently taking the local branch. Execute the generated script with remote placeholders populated.

- The stdin-template real-spawn test observes only the last writer and explicitly accepts either stdin encoding at [test_input_vector_delivery.py:858](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:858). A mutation making the subprocess path ignore argv/stdin while leaving the fallback correct remains green.

- Embedded generated-artifact tests inspect source rather than executing it at [test_input_vector_delivery.py:773](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:773). They consequently miss the repeated-placeholder defect above.

## `delivered_bytes` split

For stock non-stdin attempts, the delivered vector bytes are faithful: neither verification path appends data, and the artifact uses `delivered_bytes`.

It can differ for stdin:

- Executor calls `verify_payload(P + b"\n")`.
- If subprocess verification succeeds, the target and artifact both receive `P + b"\n"`.
- If the pwntools fallback succeeds, `sendline(P + b"\n")` makes the verified target receive `P + b"\n\n"` at [verification.py:341](/srv/share/dev/supwngo/supwngo/exploit/verification.py:341).
- The generated stdin artifact still sends `P + b"\n"` at [templates.py:302](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:302).

Therefore the claim that the stdin artifact always replays the verified bytes is false for fallback-only success. This is pre-existing default behavior and can be recorded as a known gap rather than blocking this diff by itself.

Also, the non-stdin fallback `payload + b"\n"` when `delivered_bytes is None` at [templates.py:278](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:278) is inherently speculative. A future/custom allowlisted executor can silently receive a wrong artifact; loud generation failure would be safer.

## Commit judgement

Block the atomic commit on:

- repeated-placeholder artifact corruption;
- non-stdin EOF/open-stdin spawn divergence;
- swallowed file-materialization failures.

Given your explicit test standard, I would also add runtime remote-refusal coverage and exhaustive allowlist/`ret2win` controls before calling the round final.

I could not run pytest in this read-only environment because Python had no writable temporary directory; the findings above come from source inspection plus a direct no-write generation probe.