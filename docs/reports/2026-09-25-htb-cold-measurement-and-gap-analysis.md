# HTB cold measurement + comprehensive gap analysis — 25SEP2026

Scope: cold out-of-sample measurement of supwngo autopwn against 8 official HackTheBox
pwn challenges, followed by a comprehensive gap analysis across bugs, missing
capabilities, code health, and CLI surface. This document supersedes the earlier
`2026-09-25-capability-gap-analysis.md` by incorporating real held-out measurement data.

Every claim is labelled **measured** (instrument ran), **recorded** (read from an
artefact), or **inferred** (reasoned from the above).

---

## 0. Executive summary

**0 of 6 autopwn-applicable HTB challenges solved. 2 Easy challenges that supwngo has
the techniques to solve were missed due to specific bugs in technique gating and
pipeline orchestration.**

| Metric | Value |
| --- | --- |
| Total challenges | 8 |
| Autopwn-applicable (userspace ELF) | 6 |
| Solved | **0** |
| Should-have-solved (technique exists) | **2** (Sick ROP, Rocket Blaster XXX) |
| Stretch-solvable (capability exists but immature) | **1** (Bon-nie-appetit) |
| Beyond current scope | **3** (Device Control, Sabotage, Auth-or-out) |
| Non-applicable (kernel .ko, PHP .so) | 2 (knote, superfast) |

The in-sample benchmark is 13/13. The held-out score is **0/6**. The gap is not missing
techniques — it is bugs in the gating, orchestration, and failure-handling code that
prevent existing techniques from being applied.

---

## 1. Per-challenge results

### 1.1 Sick ROP (Easy) — FAILED

- **Binary:** 4,832 bytes, static, No PIE, No Canary, NX
- **rc=0, elapsed=160s, verdict=FAILED**
- **Intended technique:** SROP (sigreturn → mprotect → shellcode)
- **What supwngo did:** All 17 executors skipped ("not applicable"). Only
  `variable_overwrite` attempted — brute-forced 14 × 9 candidates for 158s on a binary
  with no symbols, no canary, no PIE.
- **Root cause:** `SropExecutor.is_applicable()` requires `/bin/sh` in the binary
  (`self._binsh(context) is not None`). `sick_rop` has zero `/bin/sh` strings — it's a
  canonical SROP target designed to not have that string. The gate is inverted: SROP
  exists precisely for targets lacking convenient strings.
- **Secondary:** `blocking_unknowns: []` and `strategy_warnings: []` on a total failure.
  No technique name appears in the log — every skip says "not applicable to this target"
  with no reason.
- **Fix complexity:** Medium — widen SropExecutor gate to allow targets with writable
  sections where `/bin/sh` can be planted via a chained `read()` call.

### 1.2 Rocket Blaster XXX (Easy) — FAILED

- **Binary:** amd64, No Canary, NX, No PIE, Full RELRO, RUNPATH='./glibc/'
- **rc=0, elapsed=93s, verdict=FAILED**
- **Intended technique:** ret2win with 3 arguments (`pop rdi/rsi/rdx` → `fill_ammo`)
- **What supwngo did:** All 17 executors produced attempts with status `None`. No
  technique reached DELIVERY. `blocking_unknowns: []`, `strategy_warnings: []`.
- **Root cause (inferred):** The binary has a non-standard win function (`fill_ammo`)
  requiring 3 specific magic-value arguments (`0xdeadbeef`, `0xdeadbabe`, `0xdead1337`).
  supwngo's `ret2win` executor likely did not detect or parameterize this function. The
  RUNPATH glibc may have compounded offset resolution issues.
- **Fix complexity:** Medium — ret2win needs argument discovery (cross-reference binary
  constants with function parameters).

### 1.3 Device Control (Medium) — FAILED (correctly diagnosed)

- **Binary:** amd64, Full RELRO, Canary, NX, PIE — all protections
- **rc=0, elapsed=7s, verdict=FAILED**
- **Intended technique:** Format string leak → one_gadget via RBP overwrite (ncurses I/O)
- **What supwngo did:** Fast, correct failure — 16 SKIPPED, 1 FAILED
  (`variable_overwrite`), correct diagnosis: "PIE base not leaked", "Stack canary
  enabled - need canary leak". Best output of any target.
- **Capability gap:** ncurses I/O interaction, brute-force ASLR byte, one_gadget
  constraint satisfaction. These are beyond current automated scope.
- **Fix complexity:** High — requires ncurses interaction engine (out of scope for
  near-term).

### 1.4 Bon-nie-appetit (Medium) — TIMEOUT

- **Binary:** amd64, Full RELRO, Canary, NX, PIE, ships glibc 2.27
- **rc=124, elapsed=900s, verdict=TIMEOUT, zero JSON output**
- **Intended technique:** Heap off-by-one → tcache poisoning → `__free_hook` → system
- **What supwngo did:** 160 target launches, 14 gadgets cached, ran full 900s timeout.
  No JSON output produced — the "always generates a fallback template" guarantee failed
  under wall-clock exhaustion.
- **Capability gap:** Tcache poisoning with off-by-one overflow. The heap library
  (`exploit/heap/`) has the primitives but they're unreachable from the pipeline.
- **Fix complexity:** High — needs new heap executor wired into pipeline + libc path
  threading for glibc 2.27.

### 1.5 Ancient Interface / Sabotage (Medium) — TIMEOUT

- **Binary:** amd64, Full RELRO, Canary, NX, PIE
- **rc=124, elapsed=900s, verdict=TIMEOUT, zero JSON output**
- **Intended technique:** Integer overflow in custom Malloc → heap overflow → env var
  corruption → PATH hijack → `system("panel")`
- **Capability gap:** Environment variable corruption via heap overflow is not a standard
  exploitation technique. Not in supwngo's technique space.
- **Fix complexity:** N/A — out of scope for automated pipeline.

### 1.6 Auth-or-out (Medium) — TIMEOUT (killed at 805s)

- **Binary:** amd64, Full RELRO, Canary, NX, PIE, custom heap allocator
- **rc=143, elapsed=805s, verdict=KILLED (stale process)**
- **Intended technique:** UAF in custom allocator → heap overflow → function pointer
  overwrite → system
- **Capability gap:** Custom allocator reversal. Not automatable without RE of
  non-standard allocator internals.
- **Fix complexity:** N/A — out of scope for automated pipeline.

---

## 2. Category 1 — Bugs, gaps, and performance problems

### 2.1 Exit code always 0 (measured)

**32 of 33 CLI commands always return exit code 0** regardless of success or failure.
Only `report` has `ctx.exit(1)`. This means:
- Shell scripts cannot tell if autopwn succeeded or failed
- CI/CD integration is impossible
- The test harness had to parse JSON to detect failure

### 2.2 Timeout produces zero output (measured)

When autopwn hits the wall-clock timeout (rc=124), it produces **no JSON output at
all**. The "always generates a fallback template" guarantee fails under timeout. Two of
six targets produced zero bytes of output — a complete instrument failure.

### 2.3 SROP gate inverted (measured)

`SropExecutor.is_applicable()` at `rop_techniques.py` requires `/bin/sh` to already
exist in the binary. This is backwards — SROP's primary use case is targets lacking
convenient strings, where the attack plants `/bin/sh` via a chained `read()` into `.bss`.
The gate makes SROP inapplicable to canonical SROP targets.

### 2.4 No strategy-level progress reporting (measured)

During 900s runs, the only log output is pwntools `Starting local process` / `Stopped
process`. No technique names, no stage indicators, no progress. An operator watching
the tool run cannot tell what it's trying.

### 2.5 Diagnostic fields empty on total failure (measured)

`blocking_unknowns: []` and `strategy_warnings: []` on targets where everything failed.
`device_control` was the exception — it correctly reported "PIE base not leaked". The
other failures produced empty diagnostic fields, which is worse than no field.

### 2.6 Skip reasons are non-specific (measured)

Every skipped executor emits "not applicable to this target" with no reason. There are
16 different executors with 16 different gates, and they all produce the same message.
The information about which precondition failed exists at the gate but is discarded.

### 2.7 No installed console script (measured)

`which supwngo` → not found. Running from outside the repo root requires
`PYTHONPATH=/srv/share/dev/supwngo python3 -m supwngo.cli`. This caused a void first
run in the test harness (all targets failed in <1s with `ModuleNotFoundError`).

### 2.8 Hardcoded libc version (recorded)

`libc_version="2.31"` hardcoded at `fsop.py:214` and `off_by_one.py:396`. These
constants will produce wrong offsets on any other libc version.

### 2.9 No loader threading (measured)

Zero mentions of `patchelf`, `LD_LIBRARY_PATH`, `--library-path` in the codebase.
Targets shipping their own glibc (3 of 6 HTB targets) cannot have offsets correctly
resolved. The tool computes offsets from one libc but executes against another.

### 2.10 ret2win argument discovery missing (inferred)

`Rocket Blaster XXX` requires calling `fill_ammo(0xdeadbeef, 0xdeadbabe, 0xdead1337)`.
supwngo's ret2win executor does not discover required arguments from the binary's
constant references. This is a textbook-easy challenge that should be solvable.

---

## 3. Category 2 — Feature gaps that would enable solves

### 3.1 SROP without `/bin/sh` (would solve: Sick ROP)

Add an SROP strategy that writes `/bin/sh` to a writable section (`.bss` or `mmap`'d
page) via a chained `read()` sigreturn frame, then calls `execve`. This is the standard
SROP technique.

### 3.2 ret2win with argument matching (would solve: Rocket Blaster XXX)

Detect win functions by binary analysis (functions that call `open`/`read`/`write` on
flag patterns, or `system`/`execve`), extract required argument values from comparison
constants in the function, and build the ROP chain to satisfy them.

### 3.3 Heap technique pipeline integration (would improve: Bon-nie-appetit)

The heap library (`exploit/heap/`, 4,341 lines) is unreachable from the pipeline.
`build_default_registry()` registers 17 executors, none of which are house-of-*,
tcache poisoning, or fastbin dup orchestration. Wiring these requires new executors
plus corpus targets per technique.

### 3.4 Libc path threading + mismatch detection

`--libc-path` option that runs the target against the specified glibc via `patchelf` or
`LD_LIBRARY_PATH`. Detect when the libc used for offset computation differs from the
one loaded at runtime. Retire the hardcoded `libc_version="2.31"`.

### 3.5 Custom I/O interaction models

Device Control uses ncurses. Other challenges use menu-driven I/O. supwngo currently
assumes stdin/stdout line-oriented I/O. A pluggable interaction model would expand
target coverage.

### 3.6 Input format diversity

The challenge set includes a BMP-based challenge concept. supwngo has no capability to
craft structured file inputs (BMP, PNG, ELF, etc.) as attack vectors. File format
fuzzing with structure-aware mutators would expand coverage.

---

## 4. Category 3 — Code health and tool surface

### 4.1 Unreachable modules (measured: 48 of 198, 24%)

| Package | Unreachable modules | Lines |
| --- | --- | --- |
| `exploit/heap` | 11 | 4,341 |
| `ai` | 5 | 2,977 |
| `distributed` | 5 | 2,690 |
| `windows` | 5 | 2,205 |
| `reporting` | 5 | 2,077 |
| `embedded` | 4 | 1,521 |
| `containers` | 3 | 1,317 |
| `api` | 3 | 858 |
| `macos` | 2 | 568 |
| `payloads` | 2 | 319 |

### 4.2 ai/ and distributed/ (5,667 lines, 0 tests, 0 CLI surface)

Complete-looking subsystems with no way to reach them. `ai/` has LLM analyzer, vuln
predictor, pattern learner, advisor. `distributed/` has coordinator, worker, seed
sharing, coverage merge. Either surface and test them or remove them from the shipped
package.

### 4.3 README overclaims (measured)

README claims "Heap exploitation techniques (tcache poisoning, fastbin dup, House of *)"
under Exploit Generation. House-of-* has no CLI and no pipeline surface.
`build_default_registry()` registers 17 executors, none of which are house-of-* variants.

### 4.4 Option inconsistency (measured, assessed)

`--libc` exists on 7 of 30 commands: exploit, rop, pwn, template, autopwn, explain,
solve. Most analysis commands (`analyze`, `checksec`, `cfg`, `dataflow`,
`strings_analysis`) are pure static analysis that don't use a libc file.
**Assessment (26SEP2026):** The 7 commands with `--libc` are the exploitation/interaction
commands where it matters. Adding `--libc` to `heap_analysis` or `symbolic` would require
underlying module changes, not just CLI wiring — deferred as low priority.

### 4.5 ~~33 commands, 22 have --json, 11 do not~~ **RESOLVED** (PR #12, #14)

~~Commands WITHOUT `--json`: fuzz, triage, exploit, rop, symbolic, libc-id, checksec,
cyclic, cyclic-find, batch, template, decompile, version.~~ All 30 commands now have
`--json` (PR #12 fixed stdout pollution, PR #14 added the flag to all 11 missing
commands).

### 4.6 Stale local branches (measured: 8)

8 local branches beyond main, plus 5 locked worktrees in `.claude/worktrees/`. These
should be cleaned up.

### 4.7 exploit/heap/ vs exploit/pipeline/executors/heap_techniques.py (recorded)

Two separate heap code paths: the library (4,341 lines, unreachable) and the pipeline
executor (370 lines, inline reimplementation). They are complementary but disconnected.

### 4.8 Massive code duplication (measured, partially resolved)

The codebase has significant redundant implementations:

| Concept | Copies | Files | Status |
| --- | --- | --- | --- |
| Shellcode generator | **3** | `shellcode.py`, `constrained_shellcode.py`, `restricted_shellcode.py` | 3 distinct roles; name collision **fixed** (PR #11) |
| Exploit verifier | **2** | `verify.py`, `verification.py` | Intentional: static vs runtime verification |
| Seccomp analyzer | **2** | `seccomp.py`, `seccomp_advanced.py` | Enum duplication **fixed** (PR #11) |
| Auto-exploiter | **2** | `auto.py` (2,942 lines), `enhanced_auto.py` (1,432 lines) | Open |
| Canary bypass | **2** | `exploit/canary_bypass.py`, `vulns/canary_bypass.py` | Open (detection vs exploitation) |
| HeapLayout class | **2** | `exploit/heap/layout.py`, `vulns/heap_advanced.py` | Different fields; no runtime conflict |
| verify_shell() | **3** | `auto.py` (×2), `verification.py`, `pipeline/verifier.py` | Open |
| cyclic/offset | **3** | `utils/helpers.py`, `exploit/offset_finder.py`, scattered | Open |
| base/advanced vuln detector | **3 pairs** | `heap.py`/`heap_advanced.py`, `integer.py`/`integer_advanced.py`, `race.py`/`race_advanced.py` | Open |

### 4.9 Hardcoded libc offsets and paths (measured)

Beyond the already-known `libc_version="2.31"` at `fsop.py:214` and `off_by_one.py:396`:

- `exploit/heap/tcache.py:415-416` — `__malloc_hook` at `0x3ebc30`, `__free_hook` at
  `0x3ed8e8` (libc 2.27/2.31 specific)
- `exploit/heap/house_of_modern.py:79-81` — hardcoded IO jumps offsets
- `exploit/auto.py:2669-2675` — commented-out puts/system/binsh offsets
- `kernel/modprobe.py:535` — `DEFAULT_CORE_PATTERN_OFFSET = 0x1a90e40`
- `exploit/enhanced_auto.py:1234` — `offset = 72  # CHANGE THIS`
- Hardcoded libc search paths duplicated at `auto.py:1232-1234`, `auto.py:1454-1456`,
  and `pipeline/executors/_shared.py:222`

### 4.10 Zero test coverage for ~15,000+ lines (measured)

12 packages/sub-packages have **zero** test coverage: `ai/`, `api/`, `containers/`,
`distributed/`, `embedded/`, `macos/`, `windows/`, `payloads/`, `remote/`, most of
`fuzzing/`, all of `symbolic/`, and `utils/`. Additionally, `exploit/auto.py` (2,942
lines) and `exploit/enhanced_auto.py` (1,432 lines) have no dedicated tests.

### 4.11 ~~48+ module-level `def exploit()` functions~~ (FALSE POSITIVE)

~~Scattered across the codebase are 48+ functions named `exploit()` defined at module
scope.~~ **Correction (26SEP2026):** AST analysis confirmed zero actual module-level
`exploit()` functions. All 51 `grep` matches are inside triple-quoted string templates
(generated exploit scripts). No name collision or maintenance risk.

---

## 5. Sprint roadmap

### Sprint 0 — Housekeeping (commit pending work, clean branches) — COMPLETE (PR #3)

**Goal:** Clean slate. Commit the pending `report` command feature, clean up stale
branches and worktrees, delete the earlier gap analysis (superseded by this document).

- [x] Commit feature 1 (`report` command) on `feat/report-command` branch, PR, merge
- [x] Delete stale local branches that have been merged or superseded
- [x] Clean locked worktrees (5 stale worktrees removed)
- [x] Run full test suite to establish green baseline (1100 pass)

### Sprint 1 — Exit codes and failure reporting — COMPLETE (PR #4)

**Goal:** Every CLI command signals failure correctly. Operators and scripts can
distinguish success from failure.

- [x] Add `ctx.exit(1)` to `autopwn`, `exploit`, and `solve` failure paths
- [x] Add specific skip reasons to every executor gate (replace "not applicable to this
  target" with the actual precondition that failed)
- [x] SROP gate widened: accept targets with writable sections (not just `/bin/sh`)
- [x] Two-stage SROP strategy implemented (read → plant `/bin/sh` → execve)
- [x] Tests for exit code behavior updated
- [ ] Timeout fallback (deferred — requires signal handler complexity)
- [ ] Strategy-level progress logging (deferred)

### Sprint 2 — ret2win argument discovery — COMPLETE (PR #5)

**Goal:** Solve the two Easy HTB challenges that supwngo should already handle.

- [x] Add ret2win argument discovery: scan win function disassembly for `cmp`
  instructions with immediate constants, build ROP chain setting rdi/rsi/rdx
- [x] Expand `WinFunctionFinder` name patterns and add file-ops detection
- [x] Falls back to no-args call if gadgets unavailable
- [ ] Add `sick_rop` and `rocket_blaster_xxx` as regression test targets (HTB
  archives no longer on system)
- [ ] Re-run autopwn against both to verify fixes (deferred to Sprint 8)

### Sprint 3 — Libc path threading — COMPLETE (PR #6)

**Goal:** Targets shipping custom glibc work correctly.

- [x] `Binary.detect_shipped_libc()` — inspects ELF interpreter, RUNPATH, RPATH,
  and common layouts (glibc/, lib/) to find shipped libc.so.6
- [x] `Binary.libc_env()` — builds env dict with LD_LIBRARY_PATH
- [x] Auto-detection wired into autopwn pipeline (orchestrator, verifier, executors)
- [x] ELF interpreter, RUNPATH, RPATH parsed during pyelftools loading
- [x] `console_scripts` entry point already works (`pip install -e .` done earlier)
- [ ] Mismatch detector (deferred — needs cross-validation logic)
- [ ] Retire hardcoded `libc_version="2.31"` (deferred — heap library depends on it)

### Sprint 4 — CLI option consistency + --json parity — PARTIAL (PR #12, #14)

**Goal:** Uniform CLI surface. Lower priority than capability fixes.

- [ ] Add `--libc` to all analysis commands where meaningful
- [x] Add `--json` to the 11 commands missing it — PR #14 (all 30 commands
  now have `--json`)
- [x] Fix `--json` producing mixed console+JSON output (Bug B-4) — PR #12
- [ ] Standardize option naming

### Sprint 5 — Heap executor skip diagnostics — COMPLETE (PR #8)

**Goal:** All heap executors report why they declined a target.

- [x] Heap executors were already registered in the pipeline (TcachePoisonGotExecutor,
  UAFExecutor, DoubleFreeExecutor, ScanfCanaryBypassExecutor)
- [x] Added `skip_reason()` to all four heap/bypass executors
- [x] Fixed stale `test_version_consistency.py` reference to deleted api/server.py
- [ ] Corpus targets for heap techniques (deferred — needs menu-driven test binaries)

### Sprint 6 — Dead code audit — COMPLETE (PR #7)

**Goal:** Every shipped module is either reachable+tested or removed.

- [x] Removed all 7 dead packages: ai (2,977), api (858), containers (1,317),
  distributed (2,690), embedded (1,521), macos (568), windows (2,205)
- [x] 12,136 lines removed, 27 files deleted
- [x] Zero import references from any live code path confirmed
- [x] Associated TestLLMAnalyzer test class removed
- [ ] Reachability regression test (deferred — needs CI)

### Sprint 7 — CI + containerized execution — PARTIAL (PR #10)

**Goal:** Tests enforced on every push. Results reproducible in a container.

- [x] Add `.github/workflows/ci.yml` running pytest + CLI verification — PR #10
- [ ] Create Dockerfile with pinned libc, patchelf, and all tool dependencies
- [ ] Document container-based usage

### Sprint 9 — Code duplication consolidation — COMPLETE (PR #11)

**Goal:** Eliminate name collisions and semantic confusion from duplicate definitions.

- [x] `SeccompAction` enum in `seccomp.py` now imports from `seccomp_advanced.py`
  (correct kernel BPF constants replace opaque `auto()` values)
- [x] `ShellcodeConstraints` in `restricted_shellcode.py` renamed to
  `RestrictedShellcodeConstraints` to eliminate name collision
- [x] Public API exports unchanged — downstream code unaffected
- [ ] Remaining naming collisions (HeapLayout, base/advanced detector pairs) —
  lower priority, no runtime conflicts

### Sprint 10 — Hardcoded offset cleanup + dead code removal — COMPLETE (PR #13)

**Goal:** Remove hardcoded libc offsets from heap exploit code; clean dead verify_shell
template.

- [x] `TcacheExploiter.hook_overwrite_targets()` now accepts optional `libc` ELF
  parameter; resolves `__free_hook`/`__malloc_hook`/etc. from libc symbols when
  available, falls back to hardcoded Ubuntu 18.04 offsets otherwise
- [x] Hardcoded offsets extracted to `_FALLBACK_OFFSETS` class variable with
  provenance annotation (Ubuntu 18.04 glibc 2.27)
- [x] Dead `get_shell_verification_code()` removed from `auto.py` — never called;
  canonical template is `create_verified_exploit_script()` in `verification.py`
- [ ] `house_of_modern.py` IO jumps offsets — same pattern, lower priority
  (unreachable from pipeline)

### Sprint 8 — Re-measurement + documentation — BLOCKED

**Goal:** Re-run the HTB cold measurement with all fixes applied. Update gap analysis
with new results.

- [ ] Re-run autopwn against all 6 applicable HTB targets (BLOCKED: HTB archives
  no longer on system)
- [ ] Compare pre/post results
- [ ] Update this document with post-fix measurements
- [ ] Tag `v2.1.0` with the improvements

### Sprint 11 — Fast wins (README + progress logging) — COMPLETE

**Goal:** Fix README overclaims and add operator-visible progress logging.

- [x] Remove "House of *" from README Exploit Generation claims (line 55) — only
  tcache poisoning and fastbin dup are pipeline-reachable
- [x] Add `logger.info` calls to orchestrator prologue stages (static analysis,
  dynamic profiling, leak acquisition) with timing
- [x] Add `logger.info` before and after each technique attempt in
  `_attempt_techniques()` with outcome and duration
- [x] Log strategy selection with technique count and order

### Sprint 12 — Cyclic dedup — COMPLETE

**Goal:** Eliminate duplicate `cyclic`/`cyclic_find` in `utils/helpers.py`; redirect
all callers to the authoritative `exploit/offset_finder.py` implementation.

- [x] Redirect `analysis/dynamic.py`, `vulns/stack_bof.py`, `exploit/primitives.py`
  imports to `exploit/offset_finder.py`
- [x] Remove `cyclic`/`cyclic_find` from `utils/helpers.py`
- [x] Update tests (`test_core.py`) to use `offset_finder` version

### Sprint 13 — Timeout fallback output — COMPLETE

**Goal:** Bug 2.2 — when autopwn is killed by wall-clock timeout (rc=124), emit
partial JSON output instead of zero bytes.

- [x] Register SIGTERM handler in `autopwn` and `solve` commands to convert signal
  to SystemExit, allowing output path to execute
- [x] Wrap `engine.run()` in try/except for KeyboardInterrupt/SystemExit
- [x] Generate universal template on interrupt for partial output
- [x] JSON output includes `"interrupted": true` field; handoff report built
  with error fallback if interrupted too early

### Sprint 14 — Empty diagnostic fields on total failure — COMPLETE

**Goal:** Bug 2.5 — `blocking_unknowns` empty when all techniques SKIPPED.

- [x] `derive_blocking_unknowns()` now falls back to SKIPPED techniques when
  no attempts reached FAILED/PARTIAL/ERROR (total-skip runs)
- [x] Test updated: total-skip produces diagnostics; mixed runs still gate
  on FAILED/PARTIAL/ERROR only

### Remaining backlog (sorted by speed × complexity)

| Item | Bug/Gap | Complexity | Status |
| --- | --- | --- | --- |
| ~~Diagnostic fields empty on failure~~ | 2.5 | Medium | **DONE** (PR #17) |
| Dockerfile + container docs | Sprint 7 | Medium | Partial |
| house_of_modern IO offsets | 4.9 | Low (unreachable) | Deferred |
| Heap pipeline integration | 3.3 | High | Open |
| auto.py / enhanced_auto.py base | 4.8 | High | Open |
| Test coverage for ~15k lines | 4.10 | Very High | Open |
| HTB re-measurement | Sprint 8 | Medium | BLOCKED |

---

## 6. HTB challenge writeup summary (for reference)

| Challenge | Difficulty | Vuln Type | Required Technique | In supwngo's scope? |
| --- | --- | --- | --- | --- |
| Sick ROP | Easy | Stack BOF | SROP + mprotect + shellcode | YES (fixed in PR #4) |
| Rocket Blaster XXX | Easy | Stack BOF | ret2win with 3 args | YES (fixed in PR #5+#6) |
| Device Control | Medium | Format string + BOF | fmtstr leak + one_gadget (ncurses) | PARTIAL |
| Bon-nie-appetit | Medium | Heap off-by-one | tcache poison → __free_hook | STRETCH |
| Sabotage | Medium | Integer overflow | heap overflow → env corruption → PATH hijack | NO |
| Auth-or-out | Medium | UAF (custom allocator) | UAF → func ptr overwrite | NO |
| knote | N/A | Kernel module | kernel exploitation | N/A (not userspace) |
| superfast | N/A | PHP extension | PHP-specific | N/A (not an ELF executable) |
