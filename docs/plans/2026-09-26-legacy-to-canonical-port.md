# Legacy → Canonical Engine Port Plan (26SEP2026)

Port the three capabilities that let the legacy engine solve targets the canonical
pipeline cannot. All three fixes reuse patterns already present in the codebase.

## Root Cause Analysis

| Target | Legacy technique | Canonical failure | Root cause |
|---|---|---|---|
| sick_rop | variable_overwrite | Wall-clock timeout (126 combos never reached) | In `--all-strategies`, negative_index_write (118s) + int_truncation_bypass (96s) burn the budget before variable_overwrite runs |
| ancient_interface | ROP (ret2libc variant) | Can't drive interactive menu | Generated scripts use `io.sendline(payload)`, no menu navigation |
| sick_rop | — | SROP PARTIAL (3-stage script deadlocks) | Multi-part I/O timing in verification subprocess |

## Sprint 1: Disassembly-guided variable_overwrite (sick_rop)

**Problem:** 14 buffer sizes × 9 magic values = 126 process spawns. Each takes ~1s.
With `--all-strategies` the technique runs last (LAST_TECHNIQUES) and the budget
is already burned.

**Fix:** Before brute-forcing, scan the binary's disassembly for `cmp` immediates
(the comparison constants the binary actually checks). Test those first. The
Ret2WinExecutor already has `_discover_args()` using `comparison_immediates()` from
`analysis/static.py` — reuse that.

**Files:** `supwngo/exploit/pipeline/executors/stack_techniques.py`

**Option not taken:** Moving variable_overwrite out of LAST_TECHNIQUES — that would
speed up this case but slow down every other target where it wastes 126 spawns.
Smarter candidate selection is better than reordering.

## Sprint 2: Menu-aware delivery for ROP executors (ancient_interface)

**Problem:** `Ret2LibcLeakExecutor` and `Ret2WinExecutor` generate scripts that
do `io.sendline(payload)` directly. Menu-driven binaries need `discover_menu()` →
send menu choice → then send payload.

**Fix:** When `context.profile_has_menu` is True, inject menu navigation into
generated scripts. The heap executors already have `discover_menu()` and the
`menu_cmd()` pattern in `heap_techniques.py`. Port this into the script builder
used by ROP executors.

**Files:** `supwngo/exploit/pipeline/executors/rop_techniques.py`,
`supwngo/exploit/pipeline/script_builder.py` (if exists), `delivery.py`

**Option not taken:** Making every executor pwntools-native (no script generation).
Script-based verification is more trustworthy since the artifact the user gets IS
the thing that was tested.

## Sprint 3: SROP verification I/O fix (sick_rop)

**Problem:** Three-stage SROP script (mprotect → read → execve) deadlocks during
`verify_script()`. The script does multiple `io.send()` calls with timing-sensitive
read() calls, and the verification subprocess's stdin piping doesn't match.

**Fix:** Add explicit `io.recv()` between stages to synchronize, and use
`deliver_parts()` settle timing in the generated script.

**Files:** `supwngo/exploit/pipeline/executors/rop_techniques.py` (SropExecutor)

## Measurement

Re-run `--all-strategies` on all three targets after each sprint.
Target: canonical solves ≥3/7 without legacy fallback.
