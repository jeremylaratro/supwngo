# S4b-i plan — independent review (Daybreak Blue, Tier-2 cyber), 2026-11-12

> Recorded verbatim from the codex file-handoff review of
> `docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md`.
> Verdict: NOT APPROVED (3 BLOCKER, 4 MAJOR, 2 MINOR). Resolutions are tracked
> in the plan's "Review response" section. (The reviewer's own note that it
> could not write this file under the read-only sandbox is retained below.)

I completed the review, but could not create `docs/plans/reviews/2026-11-12-s4b-i-angr-subprocess-isolation-review-daybreakblue.md` because the workspace is read-only. The attempted patch was rejected by the sandbox.

# Independent Tier-2 review — S4b-i angr subprocess isolation plan

**Review date:** 2026-11-12  
**Verdict:** **NOT APPROVED — 3 BLOCKERs, 4 MAJORs, 2 MINORs.**

The core isolation choice is sound: use multiprocessing with the `spawn` context, construct the angr project in the child, and return only plain data. File-backed result transfer is also preferable to joining a producer blocked on a full multiprocessing pipe.

The plan is not ready to implement because it omits one actual RT-05 command, cannot implement its promised decompiler-stage behavior with the stated primitive, and chooses a default budget that cannot meet the governing 60-second acceptance window.

## Findings

### 1. BLOCKER — the scope omits the real `strings-analysis` RT-05 timeout

The claim that `strings` is “not on RT-05's five commands” at [plan:184](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:184) is false.

The corrected sprint inventory identifies `snow_scan strings-analysis`, not `explain`, as the timed-out cell at [retest-gap plan:143](/srv/share/dev/supwngo/docs/plans/2026-11-11-retest-gap-closure-plan.md:143). The baseline records it as `TIMEOUT` at 60.1 seconds at [matrix.json:839](/srv/share/dev/supwngo/benchmark/results_retest/baseline-b03cee9/matrix.json:839).

`StringAnalyzer.analyze()` unconditionally calls `_find_string_xrefs()` at [strings.py:157](/srv/share/dev/supwngo/supwngo/analysis/strings.py:157), which builds an unbudgeted `CFGFast()` at [strings.py:508](/srv/share/dev/supwngo/supwngo/analysis/strings.py:508).

The plan therefore cannot close RT-05 as written. `decompile` is useful closure for the separate decompile gap, but does not substitute for `strings-analysis`.

Add the strings-xref site to this increment, returning plain string-address-to-xref data while preserving its current empty-xrefs fallback, or explicitly leave RT-05 open.

### 2. BLOCKER — one `decompile` operation and one final result cannot provide two stage budgets or recover a checkpoint

The primitive has one process lifetime and reads its only result after the child exits at [plan:63](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:63) and [plan:69](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:69). The decompile builder similarly returns only a final result at [plan:100](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:100).

That cannot also deliver the promise at [plan:178](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:178): independently budget CFG and Decompiler and, after killing a hung Decompiler, return metadata obtained from the completed CFG.

The stages are distinct at [decompile.py:355](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:355) and [decompile.py:372](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:372). Killing the sole child loses its in-memory function, CFG, callee list, and stage identity. A single initial `join(seconds)` also cannot reset its clock when CFG finishes.

The plan must select an implementable protocol before coding. For example:

- The child atomically writes a CFG-stage checkpoint and signals the parent.
- The parent then starts the Decompiler-stage clock.
- On stage-two timeout, the parent kills/reaps the child and reads only the completed checkpoint.

Two separate operations are possible, but the second must rebuild CFG unless a persistent-worker protocol is introduced. A single total-operation budget is simpler, but would explicitly abandon the separately-budgeted/partial-result acceptance criterion.

### 3. BLOCKER — a 60-second internal default cannot satisfy a 60-second end-to-end limit

The proposed default is 60 seconds at [plan:102](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:102). The governing acceptance criterion requires `snow_scan analyze/cfg/dataflow/pwn` not to time out under a 60-second harness at [retest-gap plan:101](/srv/share/dev/supwngo/docs/plans/2026-11-11-retest-gap-closure-plan.md:101).

The baseline confirms that the harness cuts off around 60.1 seconds, including [matrix.json:111](/srv/share/dev/supwngo/benchmark/results_retest/baseline-b03cee9/matrix.json:111) and [matrix.json:167](/srv/share/dev/supwngo/benchmark/results_retest/baseline-b03cee9/matrix.json:167).

`proc.join(60)` begins after parent-side loading and process creation. Timeout handling may then add the three-second grace period, followed by capstone/symbol fallback, output formatting, and process exit. The no-option command therefore cannot meet the outer 60-second limit in the timeout case.

Choose a measured default with reserve for spawn/import, terminate/kill/reap, fallback, and output. The plan’s own smoke used 20 seconds. Acceptance tests must exercise the real no-option default, not merely pass a shorter test-only option.

Also validate environment and CLI values as finite and strictly positive. There is no Click name collision with `--angr-timeout`, but `analyze` must accept and forward it through its alias invocation at [cli.py:142](/srv/share/dev/supwngo/supwngo/cli.py:142).

### 4. MAJOR — the static N+1 collapse lacks a one-shot cache, and its caller contract is inaccurate

Static analysis requests callers before function summaries:

- `find_dangerous_functions()` runs at [static.py:155](/srv/share/dev/supwngo/supwngo/analysis/static.py:155).
- It can call `_find_callers()` for every dangerous PLT target at [static.py:200](/srv/share/dev/supwngo/supwngo/analysis/static.py:200).
- `_analyze_functions()` is not called until [static.py:177](/srv/share/dev/supwngo/supwngo/analysis/static.py:177).

Merely replacing both CFG builds with `run_angr_op()` does not collapse them. Because `_find_callers` catches its own exception at [static.py:243](/srv/share/dev/supwngo/supwngo/analysis/static.py:243), later target queries and `_analyze_functions` can retry after timeout and consume multiple complete budgets.

Define a shared lazy summary with explicit states such as unattempted, successful, and attempted-failed/timed-out. Both static consumers must reuse that state. Tests should assert exactly one child operation on success and exactly one on failure, including multiple dangerous imports and the no-dangerous-import path.

There is also an existing bug hidden by the inner catch. At [static.py:258](/srv/share/dev/supwngo/supwngo/analysis/static.py:258), each `Binary.symbols` value is called `func_addr`, but those values are `Symbol` objects, not integers ([binary.py:31](/srv/share/dev/supwngo/supwngo/core/binary.py:31)). Passing an unhashable `Symbol` to `cfg.kb.functions.get()` at [static.py:260](/srv/share/dev/supwngo/supwngo/analysis/static.py:260) fails and is swallowed. The current code therefore does not produce the caller tuples claimed by the plan.

The builder must either preserve today’s effective empty-caller behavior or deliberately fix it with `symbol.address`. If fixed, state that behavioral change and pin it with an exact caller/site test. Pass the parent’s plain `{name: address}` and dangerous-target maps; substituting CFG KB names is not equivalent.

### 5. MAJOR — existing catches provide fallback but cannot provide the required provenance

The broad catches do make timeout-to-fallback safe:

- CFG falls through to capstone at [cfg.py:128](/srv/share/dev/supwngo/supwngo/analysis/cfg.py:128).
- Dataflow calls its heuristic at [dataflow.py:177](/srv/share/dev/supwngo/supwngo/analysis/dataflow.py:177).
- Static returns empty callers or symbol functions at [static.py:269](/srv/share/dev/supwngo/supwngo/analysis/static.py:269) and [static.py:406](/srv/share/dev/supwngo/supwngo/analysis/static.py:406).
- Decompile consumes the error and returns `None` at [decompile.py:388](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:388).

But these catches expose no timeout or backend state to the CLI. Thus the integration lever at [plan:48](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:48) does not by itself implement the visible note and JSON fields promised at [plan:110](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:110).

Define an exception-specific catch/status channel that survives fallback and distinguishes budget exhaustion from an ordinary child error. Every CLI schema must merge that state.

`pwn` is particularly easy to miss: analyze-only JSON is constructed at [cli.py:782](/srv/share/dev/supwngo/supwngo/cli.py:782), whereas full `pwn --json` emits a later strategy report at [cli.py:856](/srv/share/dev/supwngo/supwngo/cli.py:856).

Do not universally report `analysis_backend="capstone"`:

- That is accurate for CFG and dataflow fallback.
- Static falls back to empty xrefs plus `binary.symbols`.
- A stage-two decompiler timeout would retain an angr CFG checkpoint.

Define and test backend/degradation values per command.

### 6. MAJOR — the RED and killability tests are not deterministic as written

The real-hang target is expressly “skip if absent” at [plan:147](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:147). The entire HTB target tree is gitignored because it contains secrets and third-party binaries at [.gitignore:290](/srv/share/dev/supwngo/.gitignore:290). Such a test cannot be the durable RED proof claimed at [plan:155](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:155); it skips in a clean checkout.

The plan also relies on `@pytest.mark.timeout`, but `pytest-timeout` is absent from the declared dev dependencies at [pyproject.toml:63](/srv/share/dev/supwngo/pyproject.toml:63), and `timeout` is not registered in project pytest configuration at [pyproject.toml:139](/srv/share/dev/supwngo/pyproject.toml:139). It happens to be installed on the review host, which is not a repository guarantee.

More importantly, an in-process pytest timeout is the wrong containment mechanism for the C-level hang being tested. Drive the CLI as a subprocess, with the test enforcing a hard `subprocess.run(..., timeout=...)` and cleanup boundary.

The one-second `_sleep` test at [plan:136](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:136) can expire during spawn/import before the test hook starts. Require a child-started handshake or PID record and assert it occurred before accepting the timeout result. Use a budget with measured CI headroom.

`not os.kill(pid, 0)` after `join()` adequately checks the direct child. If the implementation claims whole-tree cleanup, the test must deliberately spawn a descendant and assert that it also dies.

Keep the optional `snow_scan` test as guarded end-to-end evidence, but pair it with committed deterministic tests that force `AnalysisBudgetExceeded` through every fallback and JSON-marker path.

### 7. MAJOR — `decompile --angr` does not necessarily select angr

The CLI’s `--ghidra/--angr` option only supplies a boolean at [cli.py:1972](/srv/share/dev/supwngo/supwngo/cli.py:1972). With `use_ghidra=False`, the dispatcher still tries RetDec at [decompile.py:157](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:157) before reaching angr at [decompile.py:162](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:162). RetDec carries its own 300-second timeout at [decompile.py:288](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:288).

Thus the planned `decompile --angr` integration test can exercise a different backend, and `--angr-timeout` may be ignored for up to 300 seconds on a host with RetDec.

Make backend selection explicit, or directly isolate `_decompile_angr` in the test and document the CLI limitation. Click can distinguish `--angr` from `--angr-timeout`; dispatch semantics, not naming, are the problem.

### 8. MINOR — terminate/kill/join only guarantees direct-child cleanup

For the multiprocessing child itself, the sequence at [plan:70](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:70) is correct: terminate, bounded grace, kill if necessary, and final join. Threads inside that child die with the process.

Inspection of installed angr 9.2.213 found:

- No helper process or worker-thread creation in `CFGFast`.
- Decompiler’s `CompleteCallingConventions` invocation uses its default `workers=0`.

There is therefore no demonstrated current angr grandchild leak.

It is not a general process-tree guarantee, however. `Process.terminate()` and `kill()` target one PID. The project permits any `angr>=9.2.0` without an upper bound at [pyproject.toml:44](/srv/share/dev/supwngo/pyproject.toml:44).

Either narrow the guarantee to the direct child and audited angr version, or establish a child session/process group and kill that group on POSIX, following [test_gdb_probe_pgroup_kill.py:60](/srv/share/dev/supwngo/tests/test_gdb_probe_pgroup_kill.py:60). Even a process group cannot guarantee cleanup of a descendant that creates a new session; a true cross-platform guarantee needs OS-specific job/cgroup containment.

### 9. MINOR — `join(seconds)` is a sound operation clock, but includes serialization

The child serializes its result before exiting at [plan:83](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:83). Therefore `join(seconds)` includes:

- Spawn and module import.
- Project construction.
- CFG/decompiler work.
- Result extraction.
- Pickling and file I/O.

That is sound if `seconds` denotes the complete angr-operation wall budget. It also means a CFG that completed inside its compute budget can be killed while serializing a large result. The assertion that this is only a latency cost and “not a correctness risk” at [plan:175](/srv/share/dev/supwngo/docs/plans/2026-11-12-s4b-i-angr-subprocess-isolation-plan.md:175) is too strong: it can select fallback and change results.

Keep the file handoff; it correctly avoids queue feeder and join-before-drain problems. Treat and describe the budget as end-to-end. The implementation should:

- Use a closed, parent-created 0600 file, or write a sibling then atomically replace.
- Close the parent descriptor before spawn for Windows compatibility.
- Unlink in `finally` across spawn, timeout, crash, unpickle, and interruption paths.

## Claims verified as sound

- `spawn` is preferable to `fork` because it avoids inherited angr state and copied locks.
- The CFG builder’s fields cover all live reads in [_build_cfg_angr](/srv/share/dev/supwngo/supwngo/analysis/cfg.py:137). Parent-side call graphs, recursion, and complexity can be reconstructed from those fields.
- `normalize=True` belongs only to the CFG operation, matching [cfg.py:142](/srv/share/dev/supwngo/supwngo/analysis/cfg.py:142).
- Running `iter_callees` in the child preserves resolved-target, KB-present, deduplicated, call-site-order semantics at [_angr_callgraph.py:42](/srv/share/dev/supwngo/supwngo/analysis/_angr_callgraph.py:42).
- Omitting static’s `instruction_addrs` loop is safe because its body is `pass` at [static.py:248](/srv/share/dev/supwngo/supwngo/analysis/static.py:248).
- Omitting dataflow’s ReachingDefinitions result is output-equivalent because its extraction body is `pass` at [dataflow.py:207](/srv/share/dev/supwngo/supwngo/analysis/dataflow.py:207).
- The dataflow builder must still use the exact parent PLT/symbol maps, or return raw direct-call operands, because `_resolve_call_target` resolves against `Binary.plt` and `Binary.symbols` at [dataflow.py:249](/srv/share/dev/supwngo/supwngo/analysis/dataflow.py:249).
- No reviewed consumer has another hidden live-angr-object access after the proposed serialized boundary. The exceptions are the explicit decompile checkpoint requirement and omitted strings-xref site.

## Approval condition

Revise the plan to close findings 1–3 before implementation. Also make the static one-shot cache, outcome/provenance channel, deterministic tests, and decompile backend selection explicit. With those changes, the subprocess approach is suitable for RT-05 and the angr decompile closure.