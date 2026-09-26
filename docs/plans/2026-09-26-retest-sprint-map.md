# Sprint Map — Post-Retest Improvements (26SEP2026)

Based on comprehensive 7-binary retest findings documented in
`docs/reports/2026-09-26-comprehensive-feature-retest.md`.

## Sprint 1: Win function detection unification (HIGH — solve rate)

**Problem:** `profile_stage.py:WIN_FUNCTIONS` (21 names) is narrower than
`WinFunctionFinder.WIN_NAMES` (31 names) in `offset_finder.py`. The profile
stage runs first and sets `context.win_function`; if it misses, `Ret2WinExecutor`
never fires. `WinFunctionFinder` also has `_find_by_file_ops()` (detects functions
that open `flag.txt`), but the profile stage doesn't use it.

**Fix:** Replace the inline name-scan in `profile_stage.run_static_analysis()` with
a call to `WinFunctionFinder.find_all()`, unifying both detection paths.

**Impact:** rocket_blaster_xxx ret2win should be detected (fill_ammo).

**Option not taken:** Merging the lists manually — fragile, two lists drift again.

## Sprint 2: SROP stack-writable fallback (HIGH — solve rate)

**Problem:** SROP gate checks for writable `.bss`/`.data` sections to plant
`/bin/sh`. Minimal static binaries like sick_rop have only `.text` but the stack
is writable at runtime. SROP should fall back to using `read()` to plant `/bin/sh`
on the stack.

**Fix:** In the SROP executor's `is_applicable()`, if no writable data section
exists but a `read`/`SYS_read` gadget is available and `syscall;ret` exists,
allow the technique with a stack-write strategy.

**Impact:** sick_rop SROP should go from SKIP to attempted.

**Option not taken:** Adding `.text` writability check — `.text` is never writable,
and checking /proc/self/maps at runtime would need dynamic analysis.

## Sprint 3: Libc file validation (MEDIUM — robustness)

**Problem:** `detect_shipped_libc()` finds the path but doesn't check file size.
A 0-byte libc (from bad extraction) causes ret2libc to fail silently.

**Fix:** Add a size/magic check in `detect_shipped_libc()` — reject files < 1KB
or not starting with ELF magic `\x7fELF`.

**Impact:** Better error messages; prevents wasted technique attempts.

## Sprint 4: explain command PIE support (MEDIUM — coverage)

**Problem:** `explain` produces empty output for 4/7 binaries (all PIE-enabled).

**Fix:** Investigate and fix the explain codepath for PIE binaries.

## Sprint 5: pwn recommendation sorting (LOW — correctness)

**Problem:** pwn command sorts strategies by priority number (1,2,3...) not by
confidence score. VARIABLE_OVERWRITE (conf=0.5, pri=1) ranks above ROP_EXECVE
(conf=0.8, pri=2).

**Fix:** Sort by confidence descending, break ties by priority ascending.

## Results (26SEP2026, PR #21)

Sprints 1-3 and 5 implemented and merged. Sprint 4 deferred (requires investigation).

| Sprint | Status | Measured Impact |
|--------|--------|----------------|
| 1. Win function unification | **DONE** | fill_ammo detected on rocket_blaster_xxx; ret2win ATTEMPTED (offset mismatch due to menu) |
| 2. SROP gate widened | **DONE** | sick_rop SROP ATTEMPTED → PARTIAL (3-stage mprotect+read+execve script generated) |
| 3. Libc validation | **DONE** | 0-byte libc rejected; valid libc found → ret2libc_leak SUCCEEDED on rocket_blaster_xxx |
| 4. explain PIE support | DEFERRED | needs investigation |
| 5. Strategy sorting | **DONE** | confidence-first sorting applied |

**Canonical pipeline solve rate: 0/7 → 1/7** (rocket_blaster_xxx via ret2libc_leak, SHELL_ACCESS verified).

sick_rop SROP went from SKIP to PARTIAL — the three-stage exploit script is generated
but verification fails (likely timing/interaction issue in the multi-stage read-rax
pattern). Next step: tune the script's timing and validate the mprotect+read chain.

## Queued (post-sprint, per user request)

1. CLI deconfliction: pwn/autopwn/exploit/solve command merge
2. `--strategy` / `--all-strategies` flags for exploitation commands
