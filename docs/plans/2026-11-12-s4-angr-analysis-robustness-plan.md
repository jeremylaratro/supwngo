# S4 — angr analysis robustness (RT-04 explain, RT-05 cfg timeout, functions_called break)

**Date:** 2026-11-12
**Sprint:** S4 of the 2026-09-26 comprehensive-feature-retest gap-closure effort
**Status:** REVIEWED (Daybreak Blue, Tier-2 cyber, 2026-11-12) — S4a cleared to
implement; S4b redesigned per the BLOCKER and split into its own increment.

## Peer review disposition (Daybreak Blue, 2026-11-12)

Review at `docs/plans/reviews/2026-11-12-s4-angr-analysis-robustness-review-daybreakblue.md`.

| # | sev | finding | disposition |
| --- | --- | --- | --- |
| 1 | MINOR | `iter_callees` semantics sound; plan wording wrongly lists "library" targets as skipped — PLT/library functions present in the functions kb ARE yielded | **fixed** — wording corrected below (skip = target `None` or absent from kb) |
| 2 | **BLOCKER** | thread watchdog cannot stop `CFGFast`; a leaked thread keeps mutating `self.blocks`/call graphs/kb after the capstone fallback begins (real race — `_build_cfg_angr` writes `self.blocks` directly) and will not die under the CLI/pytest | **accepted** — S4b redesigned to a **subprocess isolate** (child builds its own project from the binary path, returns serialized results over IPC, terminated on timeout) |
| 3 | HIGH | S4b lumps cfg/explain/decompile under one vague acceptance item; "best partial result" is unrecoverable after a kill | **accepted** — three separate closures, each with its own integration test; CFG and Decompiler budgeted separately; partial recovery only at stage boundaries (see S4b) |
| 4 | MINOR | no other removed-API hazard; all three `functions_called` sites accounted for | noted |
| 5 | MEDIUM | RED-proof "non-empty" oracle too weak; don't use the gitignored HTB path for the primary proof | **accepted** — committed `.c` fixture compiled at test time; assert the exact `main→helper` edge AND that the capstone fallback was not invoked |

**Scope decision (best judgement):** per the effort's per-sprint cadence and
finding #3's "separate the concerns", **S4a lands now** as its own increment
(the removed-API port — low-risk, review-cleared, closes the uniform silent
call-graph degradation across cfg/static/decompile). **S4b** (subprocess-isolated
angr budgeting; closes RT-05 `snow_scan` + the explain/decompile hangs) becomes a
distinct follow-up increment with the redesign recorded below.

## Why the Sep framing is stale (reproduced baseline)

Baseline captured 2026-11-12 against the 7 HTB targets in
`tests/htb-targets/organized/` (artifacts in `benchmark/results_retest/s4-baseline/`):

| command | result |
| --- | --- |
| `explain` | 5/7 rich output (6.5–8.4 KB); **2/7 TIMEOUT** at 90 s (`ancient_interface`, `auth-or-out`) — partial stream then hang |
| `cfg` | 6/7 finish fast via the **silent capstone fallback**; **`snow_scan` TIMEOUT** (rc=124) |
| `decompile` | `sick_rop` **TIMEOUT** (120 s) |

Two corrections to the Sep-2026 report and the prior audit's "shared root cause" note:

1. **RT-04 "explain empty on 4/7" does NOT reproduce.** No command produces empty
   output; the residual failure is a **timeout** on 2 binaries. The empty-output gap
   appears already closed (plausibly by S1's analysis fixes).
2. **`functions_called()` is not one shared cause of the timeouts.** It is removed in
   angr 9.2.213 and raises `AttributeError` at `cfg.py:184`, `static.py:396`,
   `decompile.py:384`, but **all three sites swallow it** (cfg → `build_cfg`'s broad
   `except`; static → `_analyze_functions` try/except; decompile → its try/except).
   The real effect is **uniform silent call-graph degradation** (every `cfg`/`static`
   call-graph is really the capstone fallback with no angr callees), not the
   timeouts. `trace_hits=0` in all captured output confirms nothing surfaces.

The timeouts (RT-05 and the explain/decompile hangs) are a **separate** cause: angr
`CFGFast(normalize=True)` / decompilation are too slow on large or pathological
binaries (e.g. the big static `snow_scan`), hanging with no budget.

## Scope

Two independent workstreams. In scope: RT-04 (explain), RT-05 (cfg snow_scan), and
the `functions_called` call-graph break (quality bug behind cfg/static/decompile).
Out of scope: the protections-detection discrepancy observed during probing (that was
S2/RT-06-07 territory and a separate detector concern), RISC-V/PowerPC (CG-03), and
anything in the deferred `S-libc-binding`.

### S4a — port `functions_called()` to the supported angr API

`func.functions_called()` → iterate `func.get_call_sites()`, resolve each via
`func.get_call_target(cs)` against the functions knowledge base, keep targets that are
real functions (equivalent to the old "resolved callees only"):

```python
def iter_callees(func, functions_kb):
    """Yield callee Function objects of `func`, angr-9.2-safe.

    Replacement for the removed Function.functions_called(). Resolves each call
    site's target against the functions kb and yields the Function for every
    target present in that kb (library/PLT functions included, exactly as the
    old method returned them); only targets that do not resolve (`get_call_target`
    returns None) or are absent from the kb are skipped. Repeated targets are
    de-duplicated, matching the old method's unique-callee set.
    """
    seen = set()
    for cs in func.get_call_sites():
        target = func.get_call_target(cs)
        if target is None or target in seen:
            continue
        seen.add(target)
        callee = functions_kb.get(target)
        if callee is not None:
            yield callee
```

- New module `supwngo/analysis/_angr_callgraph.py` (or a function in an existing
  analysis util) holding `iter_callees`, unit-tested directly.
- Replace the three sites to call `iter_callees(func, kb)` with the kb already in
  scope: `cfg.kb.functions` (cfg.py:174 loop), the equivalent kb in
  `_analyze_functions` (static.py), and the decompiler's kb (decompile.py).
- **Un-silence** where it is now a swallowed `AttributeError`: the three broad
  excepts stay (they guard real angr failures), but with the shim they no longer
  trip on every binary, so cfg/static/decompile regain their real angr call graph.

### S4b — bound the hanging analysis stages (RT-05 + explain/decompile hangs) — SEPARATE INCREMENT

**Diagnosis update (2026-11-12, reproduced with faulthandler):** the three hangs
do NOT share one cause. There are **two independent root causes**, so S4b splits
into two independently-shippable work items:

#### S4b-ii — bound the gdb offset probe (explain hangs: `ancient_interface`, `auth-or-out`) — surgical, light path

The explain hang is **not angr**. `supwngo explain <bin> --no-probe` completes in
both cases (rc=0, 7.5–8.6 KB); the hang is the dynamic probe. faulthandler pins it
to `walkthrough/facts.py:865`, `probe_offset_with_gdb`: a `subprocess.run(["gdb",
…], timeout=60)`. gdb launches the **target as its own inferior (grandchild)**;
when the inferior never crashes/exits, gdb's `run` blocks. `subprocess.run`'s
timeout then kills **only gdb** and its post-timeout drain `communicate()` blocks
on the still-alive inferior that holds the stdout pipe — so the 60 s budget never
takes effect and the outer harness kills it (rc=124 at 90 s).

- Fix: spawn gdb in its **own process group** (`Popen(..., start_new_session=True)`)
  and on `TimeoutExpired` kill the **whole group** (`os.killpg(os.getpgid(pid),
  SIGKILL)`) before draining, so the inferior dies and the pipe reaches EOF. Keep
  the existing `(offset, faulting_value) | None` contract; a timeout returns `None`
  (probe inconclusive), exactly as its other failure paths do.
- Single-function, well-understood bug + standard fix → **light path** (no separate
  peer-review doc): RED-proof + regression.
- **Validation (as built, 2026-11-12).** The fix was first confirmed end-to-end on
  the real targets: `explain ancient_interface` and `explain auth-or-out` went
  **rc=124 (hang) → rc=0** after the patch. For the committed RED-proof, a *real*
  `gdb` fixture proved unsuitable: gdb reparents its inferior into gdb's own
  job-control process group (build-dependent), so a group-kill of gdb's spawned
  session does not deterministically reap the inferior, and a plain sleeping
  inferior does not reproduce the hang under pytest (POSIX `subprocess.run` reaps
  the direct child at its budget). The committed test therefore isolates the fix's
  **mechanism** deterministically: a fake `gdb` on `PATH` backgrounds a
  uniquely-named sleeper that *stays* in gdb's spawned process group, then blocks
  so the probe's `communicate` times out. Pre-fix (`subprocess.run`) kills only the
  direct child and the sleeper survives (**RED**); post-fix (`killpg`) reaps the
  whole group (**GREEN**), and the probe returns at its budget. No committed C
  fixture is needed (the fake gdb is an inline shell script);
  `tests/test_gdb_probe_pgroup_kill.py`.

#### S4b-iii — the generated walkthrough's own offset step (second surface of RT-04) — surgical, light path

S4b-ii bounds the **in-process** probe (`facts.probe_offset_with_gdb`). The
`explain` artifact has a *second*, independent gdb surface: the **emitted
walkthrough script**'s `offset` step, generated by `offset_step()` in
`exploit/walkthrough/common.py`. It measured the offset with its own
`subprocess.run(argv, timeout=60)` and **no `TimeoutExpired` handling at all**,
so a wedged gdb (a) crashed the teaching script the user runs with an uncaught
`subprocess.TimeoutExpired` traceback, and (b) left gdb's inferior alive in gdb's
process group — the same leak, on the generated code. This surfaced as the
regression `test_every_step_runs_standalone`, whose self-contained `wt.py` has no
`facts.py` on its call path, so the S4b-ii fix could not reach it.

- Fix (template, `offset_step`): spawn gdb with `start_new_session=True`, read a
  `SUPWNGO_WALKTHROUGH_GDB_TIMEOUT` budget (default 60 s), and on
  `TimeoutExpired` `os.killpg(os.getpgid(pid), 9)` the whole group then
  `log.failure(...)` + `return False` — a graceful, teachable diagnosis instead
  of a stack trace. The generated script already imports `os`/`subprocess` (no
  `signal`, hence the numeric `9`).
- Single-template bug + the same standard fix → **light path**.
- **Validation (as built, 2026-11-12).** Deterministic RED/GREEN on the real
  rendered artifact, not the template text: render a ret2win walkthrough, discover
  the `offset` step index from the script's own `steps` listing (robust to
  renumbering), and run that step with a fake `gdb` on `PATH` that backgrounds a
  uniquely-named, stdio-detached sleeper kept in gdb's process group, then blocks.
  Pre-fix `common.py` ignores the budget, waits its hard-coded 60 s, exits with an
  uncaught `TimeoutExpired` traceback, and leaks the sleeper (measured: 61 s, 1
  leak, traceback) → the committed test **FAILS (RED)**. Post-fix honours the 2 s
  budget, reaps the group, prints the graceful line, leaks nothing (measured: 3 s)
  → **GREEN**. `tests/test_walkthrough_gdb_probe_timeout.py`.

#### S4b-i — isolate angr CFG/decompile in a budgeted subprocess (RT-05 `snow_scan`, decompile `sick_rop`) — full cycle

angr has no clean cooperative cancel AND a Python-thread watchdog cannot stop the
C-level `CFGFast` work: a leaked thread keeps running and keeps mutating the
analyzer's own `self.blocks` / call graphs / kb after the fallback has begun,
corrupting the result and never dying under the CLI or pytest. **The watchdog
approach is rejected.** Each angr operation runs in an **isolated child process**:

- Add `run_angr_in_subprocess(binary_path, op, seconds, **op_kwargs)` using
  `multiprocessing` with the **`spawn`** start method. The child receives only
  **serializable inputs** (the binary path, the op name, plain kwargs) — never
  `self`, an angr `Project`, a kb, or any live object. The child constructs its
  own `Project`, runs the op, and returns **plain serialized result data** (lists
  of dicts / tuples) over the IPC channel.
- On timeout the parent `terminate()`s the child, waits a short grace period,
  `kill()`s if still alive, and `join()`s — the OS reclaims all CPU/memory, so
  there is no leaked thread and no shared-state race. Raise
  `AnalysisBudgetExceeded` the caller converts to a clean fallback.
- **Two closures, each its own work item + integration test:**
  1. **cfg** (RT-05 `snow_scan`): run `CFGFast` in the subprocess; on timeout fall
     back to `_build_cfg_capstone()` and emit a **visible** note ("angr CFG
     exceeded N s budget; showing linear disassembly") — not a silent DEBUG line.
  2. **decompile** (`sick_rop`): budget the CFG build and the `Decompiler` run
     **separately** — if CFG succeeds but `Decompiler` exceeds budget, return the
     CFG-level function info with a note, rather than nothing.
- Budget default and fallback wording **runtime-configurable** (CLI `--timeout`),
  not host-pinned.

S4b-i carries its own plan + independent peer review before implementation (it is a
new multi-module design, not a mechanical port).

## Test strategy

### S4a (this increment)

- `iter_callees` unit tests driven by a **committed** fixture
  `tests/fixtures/angr_callgraph/two_funcs.c` (a `main` that calls a named
  `helper`), compiled at test time with `-no-pie -fno-stack-protector -O0` (the
  established fixture pattern; `pytest.skip` if `gcc` is absent — but gcc is
  present on the dev host and CI runs none, so this is not the gitignored-HTB
  escape hatch). Assertions: `iter_callees(main, kb)` yields a Function whose
  name is exactly `helper` (the known edge, not merely "non-empty"); an
  unresolved/indirect target is skipped; a repeated target is de-duplicated.
- **RED-proof (strengthened per review #5):** a test that drives the real
  `CFGAnalyzer.build_cfg()` on the committed fixture and asserts **both** (a) the
  resulting `call_graph` contains the exact `main → helper` edge, and (b) the
  capstone fallback was **not** invoked (assert via a spy/flag on
  `_build_cfg_capstone`, so a silently-degraded run cannot pass). This fails on
  base `5ef210a` (`functions_called()` raises → broad except → capstone fallback →
  no angr edge) and passes after the port. The committed fixture makes the proof
  non-skippable and the exact-edge + no-fallback oracle makes it non-vacuous.
- Full regression vs the S3 baseline (`s3-libc-junit.xml`): no NEW deterministic
  failures beyond the known-flaky `test_input_vector_delivery` family + load-flaky
  `test_walkthrough_fmtstr`.

### S4b (next increment) — summarized; detailed in S4b's own plan

- Subprocess helper unit test: a deliberately-slow op is `terminate()`d within ~N s
  and **the child process is asserted no longer alive** (per the BLOCKER); a fast op
  returns its serialized result.
- Three guarded integration tests (skip if the binary is absent): `cfg snow_scan`
  returns within budget + emits the visible fallback note; `explain
  ancient_interface`/`auth-or-out` return a partial + note; `decompile sick_rop`
  returns CFG-level info + note when the Decompiler stage is the one that times out.

## Risks

- **`get_call_target` semantics** may differ subtly from the old resolved-callee set
  (e.g. tail calls, PLT thunks). Mitigation: the unit test pins the kb-present +
  dedupe semantics; byte-level exploit outputs are unaffected (call graph feeds
  analysis display, not payload bytes).
- **S4b subprocess overhead / `spawn` re-import cost** — each budgeted op pays a
  fresh interpreter + angr import. Acceptable: it only runs on the angr path, and it
  is the price of killability (the thread watchdog's race is not acceptable). Keep the
  helper minimal; do not build a general angr-timeout framework.

## Commits (planned)

**S4a (this increment):**
1. `fix(analysis): port functions_called() to get_call_sites for angr 9.2` — shim
   module + three call-site swaps + committed fixture + unit tests + strengthened
   RED-proof + CHANGELOG.

**S4b (next increment, after its own plan + review):**
2. `fix(analysis): isolate angr CFG/decompile in a budgeted subprocess` — subprocess
   helper + three closures + tests + CHANGELOG (fixes RT-05 + explain/decompile hangs).

No PR (effort merges to `main` directly, per the S1–S3 cadence).
