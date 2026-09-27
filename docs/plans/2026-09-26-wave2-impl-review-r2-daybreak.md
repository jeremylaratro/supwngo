NOT-APPROVED

## Critical

1. `argv` can still be silently ignored by script-based executors.

The refusal gate only checks `is_file_sink(...)` at [orchestrator.py:383](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:383). Consequently, `SINK_ARGV` reaches every executor. Executors using `verify_script()` then launch their ordinary stdin-oriented scripts; `verify_script()` never resolves or validates the delivery spec at [verifier.py:310](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:310).

Some executors bypass the verifier even earlier. For example, `fmtstr_write_gate` probes via stdin at [fmtstr_techniques.py:102](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/fmtstr_techniques.py:102), then verifies its stdin script at [fmtstr_techniques.py:114](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/fmtstr_techniques.py:114).

Concrete failure:

```text
input_vector="argv"
target is exploitable by stack_shellcode/fmtstr/ret2libc through stdin
generated executor script succeeds through stdin
engine reports SUCCESS despite never using argv
```

The same route lets a late-bound `DeliverySpec(sink="typo")` succeed through stdin. The central gate must validate every sink before classification and refuse every non-stdin vector for executors not explicitly proven vector-aware.

2. Generated non-stdin artifacts silently do nothing under `solve --remote`.

The argv branch connects remotely but never sends `PAYLOAD` at [templates.py:216](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:216). The file branch writes a local file, then connects remotely without transferring the file or sending anything at [templates.py:225](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:225).

Concrete failure:

```text
solve vuln --input-vector argv --remote host:port
```

Local verification succeeds; the saved script connects to `host:port` and sends zero exploit bytes. File vectors behave similarly. Non-stdin vectors need a loud remote-mode refusal unless a remote delivery protocol is implemented.

## High

1. Embedded placeholders lose their literal prefix and suffix.

Both `_verify_argv_sink()` and `_render_argv_literal()` replace the entire token whenever it contains the sentinel:

- [verifier.py:239](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:239)
- [templates.py:138](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:138)

But `DeliverySpec.build_argv()` supports replacement inside a token at [contracts.py:363](/srv/share/dev/supwngo/supwngo/exploit/pipeline/contracts.py:363).

Measured from the implementation:

```text
file template:  --input={payload_file}
build_argv:     --input=/tmp/p.bin
saved script:   payload_path                 # "--input=" lost

argv template:  --data={payload_arg}
build_argv:     --data=SENT
actual verifier argv token: raw payload      # "--data=" lost
```

For file delivery, verification can succeed and the saved artifact then fail. For argv delivery, even verification launches the wrong argv. Replacement must happen within the encoded token, preserving surrounding bytes.

2. Valid stdin-plus-argv specs are silently discarded.

The contract explicitly permits a nonempty `argv_template` with `SINK_STDIN` at [contracts.py:244](/srv/share/dev/supwngo/supwngo/exploit/pipeline/contracts.py:244). However, the verifier’s stdin branch launches default argv without calling `build_argv()` at [verifier.py:194](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:194), and the generated script likewise uses `process(BINARY)` at [templates.py:202](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:202).

Concrete API input:

```python
DeliverySpec(
    sink=SINK_STDIN,
    argv_template=("--config", "profile.cfg"),
)
```

Expected: those arguments plus stdin payload. Actual: arguments silently vanish. Either honor the established contract or reject such specs loudly everywhere.

## Medium

1. Exact delivered bytes are not recorded or consumed.

The two stock allowlisted executors currently always verify `record.payload + b"\n"`, so the generated file/argv scripts’ explicit newline is correct today. But `AttemptRecord.delivered_bytes` exists specifically to avoid reconstructing delivery bytes and remains unset at [stack_techniques.py:125](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/stack_techniques.py:125) and [stack_techniques.py:214](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/stack_techniques.py:214). The generator hardcodes the reconstruction at [templates.py:215](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:215) and [templates.py:228](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:228).

A custom registered executor named `ret2win` that verifies `b"ABC"` exactly and records `delivered_bytes=b"ABC"` will receive a saved artifact delivering `b"ABC\n"`. Set `delivered_bytes` on success and use it for non-stdin artifacts.

2. Raw argv works on ordinary POSIX paths, but pwntools cannot handle every filesystem byte sequence used for `argv[0]`.

`os.fsencode` is correct for preserving payload-adjacent filesystem tokens, and both `subprocess` and the installed pwntools preserve raw high bytes in nonzero argv tokens. However, the installed pwntools converts `argv[0]` back with UTF-8 decoding. A binary whose filename contains non-UTF-8 bytes can therefore run through `subprocess` but fail only in the pwntools fallback. This is a niche real-target divergence, not corruption of the payload token itself.

## Round-1 closure status

| Finding | Status | Assessment |
|---|---|---|
| C1 argv neither delivered nor refused | **NOT CLOSED** | The raw `verify_payload` path now delivers argv correctly for whole-token templates, but script-based executors silently remain stdin-based because the gate at [orchestrator.py:383](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:383) excludes `SINK_ARGV`. |
| C2 stdin-only success artifact | **NOT CLOSED** | The simple local whole-token cases are fixed, but embedded placeholders produce the wrong artifact, and both remote branches deliver nothing. |
| H1 legacy fallback drops vector | **CLOSED** | Both guards are present at [cli.py:2770](/srv/share/dev/supwngo/supwngo/cli.py:2770) and [cli.py:3344](/srv/share/dev/supwngo/supwngo/cli.py:3344). Guided retry also threads the options. |
| H2 target mutates file between spawns | **CLOSED** | `_materialize` is passed as `pre_spawn` at [verifier.py:286](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:286), and both spawn paths invoke it. |
| H3 restore nonexistence | **CLOSED** | Existing bytes are restored and newly created paths unlinked in the `finally` at [verifier.py:301](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:301). |
| M1 typo sink falls through | **NOT CLOSED** | `verify_payload()` validates it, but script executors never enter that method; an invalid late-bound sink can still reach and succeed through stdin. |
| M2 EOF versus open stdin | **CLOSED as wording** | The difference is documented at [verification.py:131](/srv/share/dev/supwngo/supwngo/exploit/verification.py:131). The paths remain intentionally semantically different. |
| M3 ignored input options | **CLOSED** | Incompatible `input_name` and `input_argv` combinations are rejected at [orchestrator.py:195](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:195) and [orchestrator.py:202](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:202). |

## Test defects

These tests can pass while the stated capability is absent:

- `test_mechanism_solves_with_declared_vector_and_fails_with_default` never executes `engine_pos.exploit_script`. All six cases could pass with the old stdin-only artifact generator, so C2 is completely untested.

- `test_identical_bytes_across_both_spawn_paths` observes the same test callback writing the same bytes twice at [test_input_vector_delivery.py:204](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:204). It would still pass if either child ignored the supplied argv or never consumed the file.

- `test_verify_with_pwntools_directly_sees_the_full_payload` asserts only that `_pre_spawn` left a file behind at [test_input_vector_delivery.py:247](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:247). `_verify_with_pwntools()` catches launch errors internally, so this passes even if `process(argv)` fails or silently launches without the file argument.

- `test_file_that_did_not_exist_is_removed_afterwards` asserts only final absence at [test_input_vector_delivery.py:291](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:291). It passes if the file was never materialized.

- `test_preexisting_file_is_restored_byte_for_byte` also passes if materialization is absent: the untouched original already equals the expected final bytes.

- `test_restoration_holds_even_when_the_attempt_raises` does not assert that `pre_spawn` was supplied or that the file changed before the exception. Removing both materialization and cleanup leaves `ORIGINAL` untouched and passes.

The positive and negative halves use the same compiled executable. They do **not** hold the filename constant for the four randomized file-argv cases: the name is supplied only to the positive engine at [test_input_vector_delivery.py:143](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:143); the negative engine receives no filename or argv at [test_input_vector_delivery.py:172](/srv/share/dev/supwngo/tests/test_input_vector_delivery.py:172). That does not satisfy the plan’s stated “held constant across negative and positive runs” gate. `file-fixed` is intrinsically tied to `input.dat`; argv has no filename.

There is no runnable non-stdin artifact test at all.

## Direct answers

- `payload + b"\n"` is correct for the current stock `variable_overwrite` and `ret2win` file/argv paths. The verifier receives exactly that byte sequence, materializes/passes exactly it, and does not call `sendline` for non-stdin delivery. The generated local artifact therefore matches the verified non-stdin bytes.

- It should nevertheless use `record.delivered_bytes`, because reconstructing the bytes by convention is already contrary to that field’s contract and breaks custom/future executors.

- For the currently tested local templates—bare file path, `-f @@`, fixed `input.dat`, and whole-token `{payload_arg}`—the generated scripts are structurally runnable. Embedded placeholders and every non-stdin remote artifact are not.

- No no-flag regression was found: default subprocess argv/stdin and fallback argv/`sendline` remain equivalent to HEAD, and the two exact-script tests correctly pin the generated stdin artifact.