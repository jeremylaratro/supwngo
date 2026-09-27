NOT-APPROVED

## Critical

1. `argv` remains a silent stdin fallback.

The proposed non-file branch groups `SINK_ARGV` with `SINK_STDIN`:

```python
argv=None
stdin_payload=True
```

Concrete failure: run `mech_argv_payload` with `--input-vector argv`. Wave 2 still launches `[binary]` and writes the payload to stdin; the target sees no `argv[1]`. The Wave-1 gate does not refuse this because it only gates file sinks at [orchestrator.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:348).

Either implement `SINK_ARGV` now or centrally refuse it. Implementing it requires byte-valued argv: the existing fixture proves Latin-1-to-`str` corrupts high bytes at [test_input_vector_fixture_validation.py](/srv/share/dev/supwngo/tests/test_input_vector_fixture_validation.py:160). Embedded NUL must fail loudly because it cannot be represented in an OS argv token.

2. A verified file solve will still produce an unusable stdin exploit script.

The allowlisted executors store `record.payload`, after which the orchestrator calls `generate_success_script()` at [orchestrator.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:435). That template launches `process(BINARY)` without argv and calls `sendline(PAYLOAD)` at [templates.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/templates.py:172).

Concrete failure:

```text
solve file_vector_gate --input-vector file-argv --input-name p.bin
```

The in-pipeline verification succeeds, then `solve` reports that it saved a working exploit. Running that script produces `ERROR: no file argument`.

Documentation is not a refusal. If script generation is out of scope, the runtime must suppress it and the CLI must not claim that a working artifact was saved. Also, the cited `build_script()` ordering is not the immediate path used by these two allowlisted executors; `generate_success_script()` is.

## High

1. Both CLI commands silently discard the vector in the legacy fallback.

After a canonical failure, `autopwn` and `solve` construct `EnhancedAutoExploiter` without any delivery information at [cli.py](/srv/share/dev/supwngo/supwngo/cli.py:2758) and [cli.py](/srv/share/dev/supwngo/supwngo/cli.py:3304).

Example: a target has a declared file route, but also happens to be exploitable through stdin by a legacy technique. The canonical file attempt fails, the legacy engine succeeds through stdin, and the command reports overall success despite never honoring the declared vector.

Disable legacy fallback for non-default vectors, thread the vector into it, or record a clear refusal.

2. Writing the file only once does not guarantee identical bytes at the second spawn.

Initially, `materialize([payload])` gives exact parity for `b""`, `b"X"`, and `b"X\n"`: neither spawn path adds a newline. But the first target execution can truncate, rewrite, rename, or unlink its input file. If the subprocess attempt does not report success and pwntools fallback runs, it sees the first process’s mutated file.

Example:

```text
first run reads p.bin, truncates it, exits without a recognized success string
fallback launches with the same path
```

The first process sees the payload; the fallback sees an empty file. Re-materialize the same bytes immediately before each spawn, ideally through a generic pre-spawn callback so `ExploitVerifier` remains sink-agnostic.

3. “Restore afterwards” must include restoring nonexistence.

Backing up and restoring only pre-existing files leaves a newly created file behind. For `file-fixed`, that can contaminate later runs:

```text
file-fixed attempt creates input.dat containing a winning payload
later run with no input-vector launches the same target
target consumes the stale input.dat and wins
```

That makes a later default run differ from historical behavior. In `finally`:

- If the path existed, restore its original contents.
- If it did not exist, remove the materialized file.
- Do this after success, failure, timeout, and exceptions.

## Medium

1. Invalid late-bound specs can bypass all five `build_argv()` validations.

The gate calls `is_file_sink()` before `build_argv()`. Thus:

```python
context.delivery_spec = DeliverySpec(
    sink="file-arg",  # typo
    payload_filename="p.bin",
)
```

is classified as non-file and proceeds. Under the Wave-2 proposal it is then treated as stdin. A malformed `SINK_ARGV` spec similarly never reaches `build_argv()`.

This matters because late assignment to `context.delivery_spec` is explicitly supported. Validate the sink before classifying it.

2. `stdin_payload=False` does not give both paths the same stdin semantics.

`subprocess.run(input=b"")` closes stdin and presents EOF. A pwntools process on which nothing is sent keeps stdin open; `verify_shell_access()` then sends verification commands through it.

A target that reads its file and subsequently reads stdin therefore sees EOF in path 1 but may consume `echo ...` commands as target input in path 2. This is not a file-byte mismatch, but it is a spawn-path divergence. If keeping stdin open is intentional for shell verification, change the contract wording from “stdin gets `b""`” to “the exploit payload is not sent to stdin; fallback stdin remains interactive.”

3. `--input-name` can be silently ignored.

`--input-name p.bin` without `--input-vector`, or with `stdin`/`argv`, is accepted and discarded because the engine only constructs a spec when `input_vector` is non-`None`. Reject incompatible combinations at construction/CLI time.

## Direct answers

**a)** On a fresh target directory, the no-flag path can remain identical if implemented carefully:

- subprocess argv remains `[resolved_binary_path]`;
- subprocess stdin remains exactly `payload`;
- fallback argv remains `[resolved_binary_path]`;
- fallback still calls `sendline(payload)`, including today’s extra newline;
- no delivery validation or filesystem work occurs.

Use `argv is None`, not truthiness, and add the constructor parameters after `env` or make them keyword-only to preserve positional-call behavior. Stale file cleanup is the principal way a previous file attempt could change a later default run.

**b)** For an unmodified input file, yes: empty stays zero bytes, a terminal newline stays one terminal newline, and no fallback newline is added. Under arbitrary target behavior, no—the first execution can mutate the shared file before fallback. Re-materialization before each spawn closes that gap.

**c)** `binary_dir / payload_filename` is correct for both declared semantics:

- `file-fixed`: the target’s cwd is `binary_dir`, so its relative open resolves there.
- `file-argv`: the exact materialized path is passed through `build_argv()`.

Passing an absolute materialized path for `file-argv` is appropriate and preserves the filename extension.

**d)** The proposed negative-plus-positive gate is genuinely falsifiable for the primary `file-argv` subprocess path: this fixture ignores stdin and only prints its flag for the correct file contents. However, it can still pass while:

- only the subprocess path works and fallback is broken;
- `file-fixed` is entirely absent;
- the generated artifact is unusable;
- the implementation keys off `input_name` or a hardcoded fixture name rather than the vector.

Strengthen it by using a randomized filename, holding that filename constant in the negative run, invoking `CanonicalAutopwnEngine` directly, and asserting `technique_used == "variable_overwrite"` plus the exact captured flag. Add separate forced-fallback, `file-fixed`, cleanup/restoration, and artifact-refusal tests.

**e)** The additional Wave-1 silent failures are:

- valid `argv` is neither implemented nor refused;
- malformed late-bound non-file specs bypass validation;
- both legacy fallbacks drop the vector;
- `--input-name` alone is silently ignored.

These are distinct from the already-measured missing file delivery at the verifier spawn.