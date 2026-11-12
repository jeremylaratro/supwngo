# S5 — RT-03: real Ghidra decompilation output (2026-11-12)

## Goal / exit criterion

From `docs/plans/2026-11-11-retest-gap-closure-plan.md`:

> **S5 decompile — RT-03 — P1 —** `decompile` returns real output via ghidra on
> ≥1 target; angr path no longer raises.

The **angr half is already closed** (S4a fixed `'Function' has no attribute
functions_called` → `iter_callees`; S4b-i put angr's CFGFast/Decompiler in a
budgeted subprocess that degrades gracefully instead of raising/hanging). What
remains is the **ghidra half**: `Decompiler._decompile_ghidra` silently returns
`None`, so `decompile` falls through to the angr path and never emits real
Ghidra pseudo-C.

## Root cause (RT-03, measured 2026-11-12)

`_decompile_ghidra` / `_create_ghidra_script` are broken three ways, all of
which make the subprocess produce no output file → the method returns `None`:

1. **`.py` GhidraScript on a PyGhidra-less Ghidra.** The emitted script is
   Python; Ghidra 12.1.3_PUBLIC on this host has no PyGhidra, so it errors
   `REPORT SCRIPT ERROR: ... Ghidra was not started with PyGhidra. Python is
   not available` and writes nothing.
2. **No `-scriptPath`.** Even as `.py`, Ghidra could not locate the postScript
   written into the temp dir because that dir was never added to the script
   search path.
3. **Output/returncode ignored.** `subprocess.run(..., timeout=300)` result is
   never checked for returncode/stderr; a 300 s ceiling far exceeds any sane
   command budget and cannot be interrupted cleanly.

A fourth, newly-discovered hazard (claude-mem #65777): **`-scriptPath` pointed
at a directory with many files makes Ghidra hang** — postScript resolution
enumerates *every* file in each script-path dir to classify it as a script.
Pointing at `/tmp` (~12 k entries) hung >400 s at the `Execute script` phase.
The script must live in a **dedicated, near-empty directory.**

## Validated approach (de-risked 2026-11-12, EXIT=0)

A dependency-free **Java GhidraScript** in its own directory decompiles `main`
of a gcc `-no-pie -O0` fixture in ~30 s wall (loaded host) and writes
`[{"name","address","return_type","code"}]`:

```json
[{"name":"main","address":4198791,"return_type":"undefined",
  "code":"\nvoid main(undefined4 param_1)\n\n{\n  entry_main(param_1);\n  return;\n}\n"}]
```

That shape is exactly what the existing `_parse_ghidra_output` already consumes,
so the parser is reused unchanged.

### Design

- **Ship `supwngo/analysis/ghidra_scripts/SupwngoDecompile.java`** — a stable,
  version-controlled `GhidraScript`. Stable path ⇒ Ghidra caches the compiled
  `.class` per host (first run pays compile, later runs are fast). Its own
  directory ⇒ no big-dir scan hang. Package it as package-data so it ships on
  install.
  - `getScriptArgs()`: `arg0` = target selector, `arg1` = output JSON path.
  - `arg0` semantics: empty ⇒ `main` (fallback: entry function, else first
    function); `0x…`/decimal ⇒ `getFunctionManager().getFunctionAt(addr)`;
    otherwise ⇒ `getGlobalFunctions(name)[0]`.
  - Uses `DecompInterface.decompileFunction(f, 60, new ConsoleTaskMonitor())`,
    `getDecompiledFunction().getC()`, `Address.getOffset()` (primitive `long`),
    with a hand-rolled JSON string escaper (no external JSON lib).
  - Always writes a JSON array (possibly `[]`) so the Python side can tell "ran
    but found nothing" from "never ran".
- **Rewrite `_decompile_ghidra`:**
  - Resolve the script dir as `Path(__file__).parent / "ghidra_scripts"`.
  - Fresh temp **project** dir per call; output JSON written **inside that temp
    dir** (not a shared scratch path).
  - `cmd = [analyzeHeadless, project_dir, "TempProject", "-import", binpath,
    "-scriptPath", scripts_dir, "-postScript", "SupwngoDecompile.java", arg0,
    out_json, "-deleteProject"]`.
  - Launch via `subprocess.Popen(..., start_new_session=True)` and
    `communicate(timeout=deadline)`; on `TimeoutExpired`, `os.killpg(
    os.getpgid(p.pid), SIGKILL)` then return `None`.
  - **Deadline** from `SUPWNGO_GHIDRA_TIMEOUT` (default **180 s** — Ghidra is a
    heavyweight decompiler with fixed JVM+analysis overhead; this is a bounded,
    killable ceiling, not the 60 s matrix budget). Always interruptible.
  - On completion: require returncode-sane **and** output file exists,
    non-empty, parses to a non-empty list → `_parse_ghidra_output`; set
    `self.analysis_backend = "ghidra"` and return the function. Otherwise log a
    returncode/stderr tail and return `None` (→ retdec → angr, unchanged).
- **Replace `_create_ghidra_script`** — it no longer emits a `.py` string. The
  shipped `.java` is the artifact; the helper (if kept) only returns the arg0
  selector string for a given `(func_name, func_addr)`. Remove the dead Python
  template.
- **Provenance:** success ⇒ `analysis_backend="ghidra"`; the existing
  `angr_budget_exceeded` / angr-fallback markers are untouched.

## Files touched

| File | Change |
| --- | --- |
| `supwngo/analysis/ghidra_scripts/SupwngoDecompile.java` | **new** — Java GhidraScript (validated) |
| `supwngo/analysis/decompile.py` | rewrite `_decompile_ghidra`; replace `_create_ghidra_script`; set `analysis_backend="ghidra"` on success |
| `pyproject.toml` / `setup.py` | package-data so the `.java` ships on install |
| `tests/test_decompile_ghidra_output.py` | **new** — RED→GREEN on the ghidra path |
| `CHANGELOG.md` | `Fixed` entry under `[Unreleased]` |

## Test strategy

- **RED proof (non-vacuous):** on the current tree, a test that drives
  `Decompiler(bin).decompile(func_name="main", use_ghidra=True)` against a real
  ELF shows the ghidra subprocess produces **no output file** (assert the
  method returns `None` / `analysis_backend != "ghidra"`), i.e. the bug is real
  and the test sees it. Captured before the fix.
- **GREEN:** after the fix, the same call returns a `DecompiledFunction` with
  non-empty `code` and `analysis_backend == "ghidra"`.
- **Hermetic unit test:** monkeypatch the subprocess boundary to feed a canned
  Ghidra JSON array and assert `_parse_ghidra_output` + provenance wiring,
  independent of a real Ghidra install (so it runs in CI-less local suite).
- **Guarded integration test:** real `analyzeHeadless` on the smallest HTB
  target (`sick_rop`, 4.8 KB) **and** the in-repo gcc fixture; `skip` if
  `analyzeHeadless` is absent or the binary symlink is missing. Give it a
  generous per-test timeout (Ghidra is slow); mark it slow.
- **Full suite** must stay at its known baseline (2199 pass / 16 skip, the 2
  pre-existing unrelated failures) — no transitive breakage from the removed
  `.py` template.

## Risks & mitigations

- **Wall-clock > 60 s matrix budget.** Honest and documented: Ghidra is
  heavyweight; the fix makes the ceiling **bounded and killable** rather than a
  300 s silent hang, and the default `decompile` still has the graceful angr
  fallback. The ≥1-target criterion is about *correctness*, which is met.
- **Compile cost on first run per host.** Amortized by the stable script path
  (Ghidra caches the `.class`); only the first invocation pays it.
- **Packaging the `.java`.** Must be listed as package data or it won't ship;
  the resolver falls back cleanly (returns `None` → angr) if the file is
  missing, so a packaging miss degrades, not crashes.
- **`getFunctionAt` on a thunk/no-function address** ⇒ empty `[]` ⇒ `None` →
  angr fallback. Acceptable.

## Out of scope

- retdec path (not installed here).
- Making ghidra the fast default or fitting the 60 s budget (perf, not RT-03).
- Multi-function / whole-program decompile beyond the existing cap.

## Peer review (Daybreak Blue, `xhigh`) — resolutions

Independent review raised 8 blocking items; all addressed before implementation:

1. **Timeout cleanup leak/zombie.** `_run_ghidra_headless` uses
   `Popen(start_new_session=True)` + `communicate(timeout=)`; on `TimeoutExpired`
   it calls module-level `_kill_process_group` (mirrors the existing
   `facts.py` helper): `killpg(pgid, SIGKILL)` → fallback `proc.kill()` →
   `communicate(5)`/`wait(5)` to drain + reap. A defensive `except Exception`
   also kills before returning.
2. **Fake "ghidra success."** `analysis_backend` flips to `"ghidra"` only after
   `_parse_ghidra_output` returns a function whose `code.strip()` is non-empty;
   `[{}]` and whitespace-only code degrade to the fallback.
3. **`[]` vs failure.** `_read_ghidra_output` returns a list (possibly `[]`) on a
   valid array, `None` on missing/empty/malformed/non-list; `_decompile_ghidra`
   branches `None` (never ran) vs `[]` (ran, found nothing) with distinct logs.
4. **Missing-resource fallback.** `_decompile_ghidra` does an `is_file()`
   preflight on the packaged `.java` and returns `None` without launching Ghidra.
   The glob is added to `pyproject.toml`, `setup.py`, and `MANIFEST.in`.
5. **Ambiguous selector.** Switched to tagged selectors `name:<n>` / `addr:<x>`
   (`_ghidra_selector`), name-over-address precedence (for `decompile_all`, which
   passes both), `func_addr is not None` so `0x0` is honoured, and
   `Long.parseUnsignedLong` in Java for full 64-bit addresses.
6. **JSON escaper.** Java escapes `"`, `\`, and all U+0000–U+001F and writes via
   `OutputStreamWriter(..., UTF_8)`. The Python parse side is tested with escaped
   quotes/backslashes/newlines/tabs/control char; the Java escape side is covered
   by the opt-in real-Ghidra tests.
7. **Env override.** `_resolve_ghidra_timeout` rejects `NaN`/inf/≤0/unparseable
   (→ default 180 s) and hard-caps at 900 s, so "bounded" holds.
8. **RED proof direction + slow tests.** The committed tests assert the *fixed*
   behaviour (`analysis_backend == "ghidra"`, non-empty code) and fail on the old
   tree (captured RED: the real CLI returned `analysis_backend: angr` + sentinel,
   `REACHED_GHIDRA: False`). The two real-Ghidra tests are opt-in
   (`SUPWNGO_GHIDRA_TESTS=1`); 30 hermetic seam-level tests run by default.

Non-blocking suggestions (hermetic kill/reap + `ProcessLookupError` + malformed
+ empty-list + empty-code + missing-resource tests; bounded stdout/stderr tails;
try/finally disposal) are all incorporated.
