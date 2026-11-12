# S4b-i — isolate angr CFG/decompile in a budgeted subprocess (RT-05)

**Date:** 2026-11-12 (revised after Daybreak Blue review — see §8)
**Sprint:** S4b-i (the deferred, full-cycle half of S4; S4a and S4b-ii/-iii already merged)
**Band:** P1 (timeouts)
**Owner-model:** planned by Opus (Tier-2); **independently reviewed by Daybreak Blue (Tier-2 cyber)**
on 2026-11-12 — verdict NOT APPROVED (3 BLOCKER / 4 MAJOR / 2 MINOR); this revision closes them.
Review recorded at `docs/plans/reviews/2026-11-12-s4b-i-angr-subprocess-isolation-review-daybreakblue.md`.
**Parent plan:** `docs/plans/2026-11-12-s4-angr-analysis-robustness-plan.md` (§ S4b-i), which deferred this to its own plan + review.

## 1. Problem (confirmed, measured 2026-11-12)

`proj.analyses.CFGFast()` over a large statically-linked binary runs uninterruptible C-level work.
On `snow_scan` (877 KB, static glibc) it never returns within budget: `analyze`, `cfg`, `dataflow`,
`strings-analysis` each measured **TIMEOUT at 60.1 s, 0 bytes** in the baseline matrix
(`benchmark/results_retest/baseline-b03cee9/matrix.json`). The parent cannot stop it: angr has no
cooperative cancel, and a Python-thread watchdog cannot interrupt the C work (a leaked thread keeps
mutating `kb`/`blocks` after any fallback begins). **Watchdog rejected.** True cancellation needs
process isolation: run the angr op in a child process and kill the whole process on timeout; the OS
reclaims the C-level work.

## 2. Ground truth (from the 2026-11-12 consumption map + review verification)

Every path goes through `Binary.get_angr_project()` (`core/binary.py:463`), caching **one `Project`
per `Binary`** but **no CFG** — each site rebuilds CFGFast from scratch. **Six** CFGFast sites back
the RT-05 commands (no shared entry):

| Command | CFGFast site | What it needs (serialization contract) | Existing fallback |
|---|---|---|---|
| `cfg` | `cfg.py:142` (`normalize=True`) | per-block `{addr,size,succ[],pred[],insns[(addr,mnem,op)]}`; per-func `{addr,name,size,block_addrs[],callees(name+addr)}` | `_build_cfg_capstone()` (capstone linear) |
| `analyze`/`pwn` | `static.py:384` (`_analyze_functions`) | `{name:{address,size,calls[]}}` via `iter_callees` | `FunctionInfo` from `binary.symbols` |
| `analyze`/`pwn` | `static.py:246` (`_find_callers`) | **nothing — provably dead** (see below) | empty callers |
| `dataflow` | `dataflow.py:192` | per-func call-insn `(insn_addr, op_str)` records | `_analyze_heuristic()` (capstone) |
| `strings-analysis` | `strings.py:512` (`_find_string_xrefs`) | flat `(insn_addr, op_str)` records over all insns | empty xrefs (string `.references` stay `[]`) |
| `decompile --angr` | `decompile.py:355`+`:372` | `{name, addr, code(=codegen.text), calls[]}` | `_decompile_angr` returns `None` |

**`_find_callers` (static.py:246) is dead and will be removed from the angr path.** Verified: its
first loop body is `pass` (static.py:252-255); its second loop iterates `self.binary.symbols.items()`
binding `func_addr` to a **`Symbol` dataclass**, not an int (`binary.py:31`), then calls
`cfg.kb.functions.get(Symbol)` — a `Symbol` is unhashable (`@dataclass` → `__hash__=None`), so every
lookup raises and is swallowed by the inner `except Exception: continue` (static.py:266). The function
**always returns `[]` today**, after paying a full CFGFast build. So S4b-i replaces its body with
`return []` (behavior-preserving) and does **not** route it through the subprocess at all — removing one
hang source and the N-rebuild problem. The latent correctness bug (callers never computed) is **filed
separately**, not fixed here (scope discipline); a test pins the `[]` + no-subprocess contract.

Corrections to the parent plan's inventory (now superseded): `analyze` is an alias for `pwn
--analyze-only` (`cli.py:147-149`) and does **not** reach `AngrEngine`/`angr_engine.py:84` (that is
`symbolic`, out of RT-05 scope). Dead accesses dropped from the contract: dataflow's
`rd.observed_results` loop (`dataflow.py:218-220`, `pass`) and static's `instruction_addrs` loop.

**Integration lever:** every site already wraps angr in `try/except Exception → fallback` that a
C-level hang never triggers. The subprocess raises a normal `Exception` on timeout → the existing
except runs the existing, tested fallback. So wiring is "replace build+extract with a subprocess call
returning plain data; reconstruct from it" with the timeout path already handled — **plus** an explicit
provenance channel (§3.4) so the degradation is machine-visible (the broad except alone cannot do that).

## 3. Design

### 3.1 The primitive — `supwngo/analysis/_angr_subprocess.py` (new)

```
AnalysisBudgetExceeded(Exception)   # timeout — caller falls back, marks backend degraded
AngrSubprocessError(Exception)      # child raised/crashed — caller falls back
run_angr_op(binary_path, op, seconds, **op_kwargs) -> Any
```

- **Spawn, not fork:** `multiprocessing.get_context("spawn")` — fresh interpreter, no inherited angr
  state, no fork-copied locks. Child receives only serializable inputs (path, op, plain kwargs).
- **Child in its own session for whole-tree reaping (MINOR-8):** the module-level child entry
  `_angr_child(binary_path, op, op_kwargs, out_path)` calls `os.setsid()` first (POSIX), sets
  angr/cle/pyvex loggers to CRITICAL, builds its own `Project(path, auto_load_libs=False)`, dispatches
  `op`, pickles `("ok", data)` to `out_path`, exits 0; on any exception pickles `("error", repr(e))`
  and exits non-zero. Audited angr 9.2.213 spawns no helper processes and `Decompiler` uses
  `workers=0`, so there is no current grandchild; `setsid`+group-kill is insurance against the
  unbounded `angr>=9.2` pin, mirroring the gdb fix (`tests/test_gdb_probe_pgroup_kill.py`).
- **Result handoff = a parent-created temp file (not Queue/Pipe):** avoids the queue-feeder /
  join-before-drain deadlock and bounds nothing by OS buffer size; mirrors the Ghidra/RetDec precedent
  in `decompile.py`. Hygiene (MINOR-9): create the temp file `0600`, **close the parent fd before
  spawn** (Windows), and **`unlink` in `finally`** across the spawn / timeout / crash / unpickle /
  interrupt paths.
- **Reap sequence:** `proc.join(seconds)` is the **end-to-end** budget clock (it includes spawn,
  import, Project load, the op, and result serialization — §3.3/MINOR-9). After join: if
  `proc.is_alive()` → timeout: `os.killpg(os.getpgid(proc.pid), SIGKILL)` (fallback `proc.terminate()`),
  `join(3)`, `proc.kill()` + `join()` if still alive, raise `AnalysisBudgetExceeded`; elif
  `exitcode == 0` → unpickle and return; else → `AngrSubprocessError`.
- **Validation:** `seconds` must be a finite float `> 0` (reject NaN/inf/≤0 at the boundary).
- **Measured viability (2026-11-12 smoke):** spawn+import+CFGFast in a child works; a 20 s budget on
  snow_scan returns at 20.3 s with the child **confirmed not alive** after terminate/kill/join.
- **Measured budget validation (commit 1, 2026-11-12):** `cfg snow_scan --angr-timeout 30` completes
  the full timeout→kill→capstone-fallback→output path in **31.7 s end-to-end** (backend switches to
  capstone, `angr_budget_exceeded=true`), ~28 s under the 60 s harness cut. The 30 s default is
  confirmed; no lowering needed.

### 3.2 The op builders (module-level, in the child) — minimal plain data per op

- `op="cfg"` → `{"blocks":[...], "functions":[...]}` (fields per the table); parent reconstructs
  `BasicBlock`/`Function` + call_graph/complexity exactly as `_build_cfg_angr` does (pure-Python
  post-processing moves to the parent unchanged).
- `op="static_functions"` → `{name:{address,size,calls[]}}` (the `_analyze_functions` summary only;
  `_find_callers` is removed from the angr path, so no caller data).
- `op="dataflow"` → `{func_addr:[(insn_addr, op_str)]}` for the requested function; parent runs
  `_resolve_call_target` against its own `Binary.plt`/`Binary.symbols` and the TAINT tables (resolution
  stays in the parent — the child never needs plt/symbols).
- `op="strings_xrefs"` → flat `[(insn_addr, op_str)]` over all instructions; parent substring-matches
  `hex(string.addr)[2:] in op_str` and fills each string's `.references`, exactly as today.
- `op="decompile"` → `{name, addr, code, calls}` for the selected function, or `None` if not found.
  **Single whole-op budget** (BLOCKER-2): CFG build + `Decompiler` run under one child lifetime; on
  timeout the child is killed and the op raises `AnalysisBudgetExceeded` → `_decompile_angr` returns
  `None` (its existing fallback). The parent plan's "separately budget the two stages and return
  CFG-level info if only the Decompiler hangs" is **explicitly dropped as a non-goal** — one child +
  one final result cannot reset a mid-flight clock or recover an in-memory checkpoint without a
  persistent-worker or checkpoint-signal protocol whose complexity is unjustified for the `--angr`
  fallback (Ghidra remains the default decompiler).

### 3.3 Budget — runtime-configurable, with reserve under the 60 s harness (BLOCKER-3)

- `DEFAULT_ANGR_TIMEOUT = float(os.environ.get("SUPWNGO_ANGR_TIMEOUT", "30"))` — **not 60**: the retest
  harness cuts at ~60.1 s, and `join(seconds)` begins only after parent load, with terminate/kill/reap
  (≤3 s), the capstone/symbol fallback, and output still to follow. **30 s is the ceiling; commit 1
  measures the worst-case snow_scan timeout path end-to-end and lowers the default if it does not fit
  under 60 s with margin.** Acceptance tests exercise the **real no-option default**, not a shorter
  test-only value.
- `--angr-timeout FLOAT` Click option on `cfg`, `analyze`, `pwn`, `dataflow`, `strings-analysis`,
  `decompile`, defaulting to the env-derived value. **`analyze` must forward it** through its
  `ctx.invoke(pwn, …, angr_timeout=…)` alias (cli.py:147-149). Values validated finite/positive.

### 3.4 Provenance channel — explicit, per-command, machine-visible (MAJOR-5)

A broad `except` gives fallback but no state. Each wired site catches `AnalysisBudgetExceeded`
**specifically** (distinct from `AngrSubprocessError`/other) and records a status on its analyzer
(`angr_budget_exceeded: bool`, `analysis_backend: str`). The CLI merges that into output:

- Human: a one-line `[!] angr <op> exceeded <N>s on this binary; using <fallback> — results may be
  incomplete.`
- `--json`: `"angr_budget_exceeded": true, "analysis_backend": "<value>"`.

Backend values are **per command, not universally "capstone"**: `cfg`/`dataflow` → `"capstone"`;
`static`/`pwn` → `"symbols"` (empty-xref + `binary.symbols` fallback); `strings-analysis` →
`"no_xrefs"`; `decompile` → `"none"`. The marker is threaded into **both** `pwn` JSON paths — the
analyze-only emit (`cli.py:782`) **and** the full strategy report (`cli.py:856`). This is the marker
the S-wide COMPLETE/PARTIAL/SKIPPED classifier will consume (classifier change itself is out of scope).

## 4. Staging (atomic commits, each merges to main per the S1–S3 cadence)

1. **`feat(analysis): budgeted angr subprocess + cfg command`** — `_angr_subprocess.py` primitive
   (spawn, setsid/killpg, temp-file handoff, validation) + `op="cfg"`, wire `cfg.py:_build_cfg_angr`,
   `--angr-timeout`, provenance channel, visible note. Ships the primitive's **deterministic
   killability + fallback tests** and the `cfg` RED proof. **Measures and fixes the default budget.**
2. **`fix(analysis): budget static + dataflow + strings angr paths (RT-05)`** — `op="static_functions"`
   (wire `static.py:384`; replace `_find_callers` body with `return []`), `op="dataflow"` (wire
   `dataflow.py:192`), `op="strings_xrefs"` (wire `strings.py:512`), provenance for each.
3. **`fix(analysis): budget the angr decompile path`** — `op="decompile"` (wire `decompile.py:355/372`,
   single whole-op budget). Ghidra stays the default decompiler.

RT-05's S4 exit closes after commits 1–2 (analyze/cfg/dataflow/pwn/strings). Rollback: per-commit revert.

## 5. Test strategy — deterministic and committed (MAJOR-6, MAJOR-7)

**Dependency fix:** add `pytest-timeout` to `[dev]` in `pyproject.toml` and register the `timeout`
marker (it is used by S4b-ii/-iii and here but was never declared). Hang tests that drive a command
use `subprocess.run(..., timeout=...)` with a hard cleanup boundary — **not** an in-process
`pytest.mark.timeout`, which cannot contain a C-level hang in the test process.

**Primitive unit tests** (`tests/test_angr_subprocess.py`, no gitignored targets):
- **Killability (the BLOCKER) with a handshake:** a module-level `op="_slow"` child that first writes a
  `started` sentinel (records its PID) then sleeps; the test waits for the sentinel (so the budget
  cannot expire during spawn/import), budgets ~2 s, asserts `run_angr_op` raises
  `AnalysisBudgetExceeded`, the child PID is gone (`os.kill(pid,0)` → `ProcessLookupError`), **and** a
  descendant the child deliberately spawned is also gone (proves group reaping).
- **Happy path:** a fast `op="cfg"` on a tiny gcc-built fixture returns the expected dict; child exits 0.
- **Child-error path:** an op that raises inside the child surfaces as `AngrSubprocessError`, not a hang.
- **Validation:** non-finite/≤0 `seconds` rejected.

**Integration tests — committed & deterministic via a sub-millisecond budget** (the key device that
removes the snow_scan dependency): run each wired command on a **tiny gcc fixture** with
`--angr-timeout 0.001`, so even a fast CFGFast exceeds the budget → the timeout path fires
deterministically on any host. Assert rc=0, the **visible note**, the `--json` marker, and the correct
per-command `analysis_backend`. Also a **happy-path** run (generous budget, no fixture skip) asserting
`backend=="angr"`, no marker, and real angr output (the `cfg` test pins the exact `main → helper` edge
from S4a's committed `two_funcs.c`, so a degraded serialization cannot pass).
- `decompile`: test **`_decompile_angr` directly** (not via the CLI dispatcher, which tries RetDec
  first when `--angr` is set — MAJOR-7); document that CLI limitation.
- **Guarded end-to-end evidence (not the durable proof):** skip-if-absent `cfg/analyze/dataflow/
  strings snow_scan` returning rc=0 within the real default budget with the degradation marker — the
  RT-05 acceptance, but secondary to the committed tiny-budget tests.

**RED proof (non-vacuous):** the tiny-budget integration tests fail on base `b77870f` because the
unbudgeted CFGFast ignores `--angr-timeout` → no marker / no backend switch (and on snow_scan, a hard
`subprocess.run(timeout=…)` in the test shows base rc=124). Post-fix: marker present, backend switched,
rc=0.

**Regression:** focused (the wired commands' test modules + `test_angr_subprocess.py`) per increment;
full ~57-min suite once before the final increment merges. No NEW deterministic failures beyond the
known-flaky `test_input_vector_delivery` family and load-flaky `test_walkthrough_fmtstr`.

## 6. Risks

- **spawn re-import + angr-import overhead per op** (seconds). Acceptable — angr path only; removing
  `_find_callers`'s CFG build and collapsing to one `static_functions` op makes `pwn` **faster** on
  multi-dangerous-func targets. Keep the helper minimal; no general angr-timeout framework.
- **Budget includes serialization (MINOR-9):** killing during serialization of a large completed CFG
  selects the fallback and so **can change results**, not merely latency. For RT-05 this is moot
  (snow_scan never completes → always fallback); for completing CFGs the budget is end-to-end and the
  default leaves ample room. Documented, not claimed away.
- **Serialization fidelity:** child builders must reproduce `iter_callees` + `normalize=True` (cfg
  only) exactly; the exact-edge cfg test guards it. Byte-level exploit outputs are unaffected (CFG
  feeds analysis display, not payload bytes).
- **Direct-child vs tree cleanup:** `setsid`+`killpg` covers the audited angr; a descendant that calls
  `setsid` itself would escape (no current angr path does). Guarantee is scoped to the audited version.

## 7. Out of scope / explicitly deferred

- `symbolic` (`angr_engine.py:84`), `diff`, `dynamic`, `vulns/integer` CFGFast sites — not RT-05
  commands; left unbudgeted (a follow-up may reuse the primitive).
- RT-03 Ghidra decompile substance (S5). This sprint only stops the **angr** decompile path hanging.
- The `_find_callers` latent correctness bug (callers never computed) — filed separately; S4b-i only
  preserves its effective `[]` behavior while removing the hang.
- Decompile two-stage/partial-recovery budgeting (BLOCKER-2) — dropped as a non-goal.
- The COMPLETE/PARTIAL/SKIPPED classifier change — this plan only emits the marker it consumes.

## 8. Review response (Daybreak Blue, 2026-11-12)

| # | Sev | Finding | Resolution |
|---|---|---|---|
| 1 | BLOCKER | `strings-analysis` is a real RT-05 timeout (snow_scan TIMEOUT 60.1 s via `strings.py:512`), omitted | **Added** as the 6th site + `op="strings_xrefs"` in commit 2 (§2, §3.2, §4). Verified against `matrix.json`. |
| 2 | BLOCKER | one child + one result cannot two-stage-budget decompile | **Dropped** the two-stage promise; single whole-op budget → `None` fallback (§3.2, §7). |
| 3 | BLOCKER | 60 s internal default cannot meet the 60 s harness | Default **30 s** ceiling, measured-and-lowered in commit 1; validate finite/positive; `analyze` forwards `--angr-timeout`; tests use the real default (§3.3). |
| 4 | MAJOR | static N+1 collapse lacks a cache; `_find_callers` Symbol bug | `_find_callers` angr path is **provably dead → `return []`**, removed from subprocess scope; one `static_functions` op; latent bug filed separately; test pins `[]`+no-subprocess (§2, §5). |
| 5 | MAJOR | existing catches give no provenance; backend ≠ universally capstone; both pwn paths | **Explicit provenance channel**, per-command backend values, threaded into both `pwn` JSON paths (§3.4). |
| 6 | MAJOR | RED/killability tests non-deterministic (gitignored target, pytest-timeout undeclared, 1 s races spawn) | Committed **tiny-budget (`0.001`)** tests on a gcc fixture; `subprocess.run(timeout=)` for hangs; **declare `pytest-timeout`**; killability **handshake**+descendant assertion (§5). |
| 7 | MAJOR | `decompile --angr` may hit RetDec first | Test **`_decompile_angr` directly**; document the CLI backend-selection limitation (§5). |
| 8 | MINOR | terminate/kill reaps only the direct child | `setsid` in child + `killpg` in parent; guarantee scoped to audited angr 9.2.213 (§3.1). |
| 9 | MINOR | `join(seconds)` includes serialization; file hygiene | Budget documented as **end-to-end**; result-change caveat kept honestly; `0600` temp, close-fd-before-spawn, `unlink` in `finally` (§3.1, §6). |
