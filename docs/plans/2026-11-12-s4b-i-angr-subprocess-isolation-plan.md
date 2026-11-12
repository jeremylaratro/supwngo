# S4b-i — isolate angr CFG/decompile in a budgeted subprocess (RT-05)

**Date:** 2026-11-12
**Sprint:** S4b-i (the deferred, full-cycle half of S4; S4a and S4b-ii/-iii already merged)
**Band:** P1 (timeouts)
**Owner-model:** planned by Opus (Tier-2); **independent review by Daybreak Blue (Tier-2 cyber) required before implementation** — this plan is a new multi-module design, not a mechanical port.
**Parent plan:** `docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md` (§ S4b-i), which explicitly deferred this to its own plan + review.

## 1. Problem (confirmed, measured 2026-11-12)

`proj.analyses.CFGFast()` over a large statically-linked binary runs uninterruptible
C-level work. On `snow_scan` (877 KB, statically-linked glibc) it never returns within
budget: `analyze`, `cfg`, `dataflow` each measured **rc=124 at 80 s, 0 bytes stdout**
(RT-05). The parent cannot stop it: angr has no cooperative cancel, and a Python-thread
watchdog cannot interrupt the C work — a leaked thread keeps mutating the analyzer's own
`kb`/`blocks` after any fallback begins. **The watchdog approach is rejected.** True
cancellation requires process isolation: run the angr op in a child process and kill the
whole process on timeout; the OS reclaims the C-level work.

## 2. Ground truth (from the 2026-11-12 consumption map; corrects the parent plan's inventory)

Every path goes through `Binary.get_angr_project()` (`core/binary.py:463`), which caches
**one `Project` per `Binary`** but **no CFG** — each call site rebuilds CFGFast from
scratch. The five RT-05 commands reach **five distinct CFGFast sites** (no shared entry):

| Command | CFGFast site(s) | What it extracts (the serialization contract) | Existing fallback on `except Exception` |
|---|---|---|---|
| `cfg` | `analysis/cfg.py:142` (`normalize=True`) | per-block `{addr,size,succ[],pred[],insns[(addr,mnem,op)]}`; per-func `{addr,name,size,block_addrs[],callees(name+addr)}` | `_build_cfg_capstone()` → same `Dict[int,BasicBlock]` via linear disasm |
| `analyze` / `pwn` | `analysis/static.py:246` (`_find_callers`, **once per dangerous PLT func**) **and** `static.py:384` (`_analyze_functions`) | 246: `(caller_name,caller_addr,site_addr)` per target via `block.successors()`; 384: `{name:{address,size,calls[]}}` via `iter_callees` | 246 → empty callers (lists PLT imports as `caller="unknown"`); 384 → `FunctionInfo` from `binary.symbols` only |
| `dataflow` | `analysis/dataflow.py:192` | per-func call-insn records `(address, resolved_name)`; **RD/`func.graph`/`calling_convention` work is dead** (loop body is `pass`) — not serialized | `_analyze_heuristic()` (pure capstone), same dict shape |
| `decompile` (`--angr`) | `analysis/decompile.py:355` (CFG) + `:372` (`Decompiler`) | `{name, addr, code(=dec.codegen.text), calls[]}` — the cleanest boundary | `_decompile_angr` returns `None`; dispatcher already prefers Ghidra |

Corrections to the parent plan's inventory, now superseded by this plan:
- **`analyze` is an alias for `pwn --analyze-only`** (`cli.py:147-149`); it does **not** reach
  `AngrEngine`/`angr_engine.py:84`. That site belongs to `symbolic`, which is **out of RT-05
  scope** and untouched here.
- `pwn`/`analyze` triggers CFGFast **N+1 times** in one run (once per dangerous PLT func in
  `_find_callers`, plus once in `_analyze_functions`). A single budgeted subprocess that
  returns one serialized CFG, reused across both static sites, both fixes the hang **and**
  removes the redundant rebuilds.
- **No `--timeout` reaches any of these sites today; there is no SIGALRM/watchdog/multiprocessing
  anywhere on these paths.** The only `timeout=` precedent in the analysis layer is
  `subprocess.run(..., timeout=300)` for the external Ghidra/RetDec binaries (`decompile.py:194,309`).
- **Dead accesses dropped from the contract:** dataflow's `rd.observed_results` loop
  (`dataflow.py:218-220`, `pass`) and static's `block.instruction_addrs` loop
  (`static.py:252-255`, `pass`).

**Key integration lever:** every site already wraps its angr work in `try/except Exception → fallback`.
A C-level hang raises nothing, so the fallback never fires. If the subprocess primitive raises a
normal `Exception` on timeout, **the existing except clause catches it and runs the existing,
already-tested fallback** — so wiring is "replace the in-process build+extract with a subprocess
call that returns plain data; reconstruct the same objects from that data," with the timeout path
handled by code that already exists.

## 3. Design

### 3.1 The primitive — `supwngo/analysis/_angr_subprocess.py` (new)

```
AnalysisBudgetExceeded(Exception)      # timeout — caller falls back
AngrSubprocessError(Exception)         # child raised — caller falls back

run_angr_op(binary_path: str, op: str, seconds: float, **op_kwargs) -> Any
```

- **Spawn, not fork.** `ctx = multiprocessing.get_context("spawn")` — a fresh interpreter with
  **no inherited angr state and no fork-copied locks**. The child receives only serializable
  inputs (path, op name, plain kwargs) — never `self`, a `Project`, a `kb`, or any live object.
- **Result handoff = a temp file, not a Queue/Pipe.** The child pickles its plain-data result to a
  parent-created `tempfile` path (passed in argv) and exits 0. The parent uses `proc.join(seconds)`
  as the budget clock, then:
  - `proc.is_alive()` after join → **timeout**: `terminate()`, `join(grace=3)`, if still alive
    `kill()`, `join()`, unlink temp, raise `AnalysisBudgetExceeded`.
  - `exitcode == 0` → read+unpickle the temp file, return the result.
  - `exitcode != 0` (child raised/crashed; it writes a `("error", repr)` sentinel before a clean
    exit, or died hard) → raise `AngrSubprocessError`.
  Rationale for a temp file over `mp.Queue`/`Pipe`: the `cfg` payload for a binary whose CFG
  *does* complete can be large (tens of thousands of blocks). A `Queue`/`Pipe` couples result size
  to OS buffer limits and introduces the feeder-thread **join-before-drain deadlock**; a temp file
  has unbounded capacity, no deadlock, and mirrors the Ghidra/RetDec precedent already in
  `decompile.py`. (Considered and rejected: `Queue` with `get(timeout)` as the clock — works for
  small results, but adds a deadlock class for large ones with no benefit.)
- **Child entry is a module-level function** `_angr_child(binary_path, op, op_kwargs, out_path)`
  (spawn pickles by qualified name; it must be importable, not a closure). It sets angr/cle/pyvex
  loggers to CRITICAL, builds its own `Project(path, auto_load_libs=False)`, dispatches `op` to a
  builder, pickles `("ok", data)` to `out_path`, exits. On any exception it pickles `("error", repr(e))`
  and exits non-zero.
- **Measured viability (2026-11-12 smoke):** spawn+import+CFGFast in a child works; a 20 s budget on
  `snow_scan` returns at 20.3 s with the child **confirmed not alive** after terminate/kill/join. The
  `spawn` re-import + angr import overhead is real and is the price of killability (parent-plan Risks §).

### 3.2 The op builders (module-level, run in the child)

Each returns **minimal** plain data for its site (lists/dicts/tuples of `int`/`str`), not a union
payload, to keep serialization proportional to each command's need:

- `op="cfg"` → `{"blocks":[{addr,size,succ[],pred[],insns:[(addr,mnem,op)],calls[]}], "functions":[{addr,name,size,block_addrs[],callees:[(name,addr)]}]}`. The parent reconstructs `BasicBlock`/`Function` dataclasses and the `call_graph`/`reverse_call_graph`/complexity exactly as `_build_cfg_angr` does today (that post-processing is pure-Python on plain fields; it moves to the parent unchanged).
- `op="static_functions"` → `{"functions":{name:{address,size,calls[]}}, "callers":{target_addr:[(caller_name,caller_addr,site_addr)]}}`. One call answers **all** `_find_callers` queries (keyed by target) plus `_analyze_functions`, replacing the N+1 rebuilds with one subprocess.
- `op="dataflow"` → `{func_addr: [(insn_addr, resolved_name)]}` for the requested function(s). (RD work omitted — it is dead.)
- `op="decompile"` → `{"name","addr","code","calls"}` for the selected function, or `None` if the function is not found.

### 3.3 Budget — runtime-configurable (CLAUDE.md: not host-pinned)

- Default resolved as `float(os.environ.get("SUPWNGO_ANGR_TIMEOUT", "60"))` in one place
  (`_angr_subprocess.DEFAULT_ANGR_TIMEOUT`).
- Add a `--angr-timeout FLOAT` Click option (not `--timeout`, which these five commands do not have
  and which carries other meanings elsewhere) to `cfg`, `analyze`, `pwn`, `dataflow`, `decompile`,
  defaulting to that env-derived value, threaded to `run_angr_op(seconds=...)`.

### 3.4 Visible fallback note (not a silent DEBUG line)

When the budget fires, each command emits a **visible** one-line note before its fallback runs, e.g.
`[!] angr CFG exceeded {N}s budget on this binary; showing linear (capstone) disassembly — results
may be incomplete.` In `--json` mode the note becomes a field (`"angr_budget_exceeded": true,
"analysis_backend": "capstone"`) so the degraded result is **machine-visible**, never silently
scored as a successful run (this ties to the review-mandated COMPLETE/PARTIAL/SKIPPED metric).

## 4. Staging (three atomic commits, each merges to main per the S1–S3 cadence)

1. **`feat(analysis): budgeted angr subprocess + cfg command`** — the `_angr_subprocess.py` primitive
   + `op="cfg"` builder, wire `cfg.py:_build_cfg_angr` to it, `--angr-timeout`, visible note. This is
   the **proving closure**: it ships the primitive with its killability test (the BLOCKER) and the
   first integration test (`cfg snow_scan`).
2. **`fix(analysis): budget static + dataflow angr paths (RT-05 analyze/pwn/dataflow)`** — `op="static_functions"`
   (wire `static.py:246`+`384`, collapsing N+1 → 1) and `op="dataflow"` (wire `dataflow.py:192`), reusing
   the now-proven primitive.
3. **`fix(analysis): budget the angr decompile path`** — `op="decompile"` (wire `decompile.py:355/372`).
   Ghidra remains the default decompiler; this only bounds the `--angr` fallback. (RT-03's Ghidra
   substance is S5, separate.)

Rollback: per-commit revert. S4's exit criterion closes only after commits 1–2 (analyze/cfg/dataflow/pwn);
commit 3 is the decompile closure the parent plan folded in.

## 5. Test strategy

**Primitive unit tests** (`tests/test_angr_subprocess.py`, no gitignored targets — gcc fixture or a
pure-sleep op):
- **Killability (the BLOCKER):** a deliberately-slow op (a module-level `op="_sleep"` test hook, or a
  real CFG on a committed slow-enough fixture) is budgeted at ~1 s; assert `run_angr_op` raises
  `AnalysisBudgetExceeded` **and the child process is no longer alive** (capture the child pid via a
  test seam and assert `not psutil/os.kill(pid,0)`), proving the OS reclaimed it — not merely that the
  parent returned.
- **Happy path:** a fast op on a tiny gcc-built fixture returns the expected serialized dict and the
  child exits 0.
- **Child-error path:** an op that raises inside the child surfaces as `AngrSubprocessError`, not a hang.

**Integration tests** (gcc-gated and/or `skip-if-absent` for HTB targets, the established pattern):
- `cfg` on a tiny gcc fixture returns real angr blocks (backend=`angr`, no note); `cfg snow_scan`
  (skip if absent) returns **within budget** with the **visible fallback note** and `analysis_backend
  == "capstone"` — the RT-05 assertion.
- `analyze`/`pwn`/`dataflow snow_scan` (skip if absent) return rc=0 within budget with the budget-exceeded
  marker, not rc=124.
- `decompile --angr` on a tiny fixture returns non-placeholder pseudo-C for a named function.

**RED proof (non-vacuous):** each integration test must FAIL on base (`b77870f`) for the right reason —
on base, `cfg snow_scan` hangs past the test's own `@pytest.mark.timeout` (rc=124 / killed), i.e. the
budget never takes effect; post-fix it returns within budget with the capstone marker. For the tiny-fixture
happy paths, RED is unnecessary (new surface). The killability test's RED form: a watchdog/thread
implementation would leave the child alive → assertion fails; the spawn+kill design passes.

**Regression:** focused (the five commands' test modules + `test_angr_subprocess.py`) per increment;
full ~57-min suite once before the final increment merges. No NEW deterministic failures beyond the
known-flaky `test_input_vector_delivery` family and load-flaky `test_walkthrough_fmtstr`.

## 6. Risks

- **spawn re-import + angr-import overhead per op.** Each budgeted op pays a fresh interpreter + angr
  import (measured: seconds). Acceptable — it runs only on the angr path, and `op="static_functions"`
  *removes* the N+1 rebuild, so `pwn` likely gets **faster** on multi-dangerous-func targets even with
  the overhead. Keep the helper minimal; do not build a general angr-timeout framework.
- **Serialization fidelity.** `iter_callees` and `block.successors()` semantics must be reproduced
  exactly in the child builders; the cfg unit test pins the exact `main → helper` edge (reusing S4a's
  committed `two_funcs.c` fixture) so a degraded serialization cannot pass. Byte-level exploit outputs
  are unaffected (CFG feeds analysis display, not payload bytes).
- **Large-but-completing CFG payloads.** Temp-file pickle is unbounded, so size is not a correctness
  risk; it is a latency cost paid only when CFGFast completes (i.e. the binary is small enough that it
  does). No cap needed for RT-05 (snow_scan never completes → always the fallback path).
- **Double budget on decompile.** CFG build and `Decompiler` run are **two** C-level stages; budget each
  separately (`op="decompile"` with an internal split) so a CFG that succeeds but a `Decompiler` that
  hangs returns CFG-level info + note, not nothing — per the parent plan.

## 7. Out of scope / explicitly deferred

- `symbolic` (AngrEngine CFGFast at `angr_engine.py:84`), `strings`, `diff`, `dynamic`, `vulns/integer`
  CFGFast sites — not on RT-05's five commands. Left unbudgeted here; a follow-up may reuse the primitive.
- RT-03 Ghidra decompile substance (S5). This sprint only prevents the **angr** decompile path from hanging.
- The COMPLETE/PARTIAL/SKIPPED matrix classifier change (S-wide metric) — this plan only emits the
  machine-visible marker the classifier will consume.
