# Comprehensive Feature Re-test — 26 September 2026

## Overview

Full re-test of all supwngo commands against 7 HackTheBox ELF binaries.
Test harness ran ~20 commands per binary with `--json` output, plus supplemental
tests for `exploit --auto`, `onegadget`, and `race-analysis`.

**Results directory**: `tests/htb-targets/results-20260926-094216/`

## Test Matrix

| Binary              | Diff | Arch     | Protections                            | Vuln Type           |
|---------------------|------|----------|----------------------------------------|---------------------|
| sick_rop            | Easy | x86-64   | No RELRO, No Canary, NX, No PIE       | Stack BOF → SROP    |
| rocket_blaster_xxx  | Easy | x86-64   | Full RELRO, No Canary, NX, No PIE     | ret2win (fill_ammo) |
| snow_scan           | Easy | x86-64   | Partial RELRO, Canary*, NX, No PIE    | Stack BOF → SROP    |
| ancient_interface   | —    | x86-64   | Partial RELRO, Canary, NX, No PIE     | Stack BOF via read  |
| auth-or-out         | Med  | x86-64   | Full RELRO, Canary, NX, PIE           | UAF (custom alloc)  |
| sabotage            | Med  | x86-64   | Full RELRO, Canary, NX, PIE           | Integer overflow     |
| bon-nie-appetit     | Med  | x86-64   | Full RELRO, Canary, NX, PIE           | Heap off-by-one     |

*snow_scan canary is a false positive per HTB writeup.

## Command Coverage Matrix

```
Command              anc_int  auth-out  bon-nie   rocket    sabotage  sick_rop  snow_sc
───────────────────────────────────────────────────────────────────────────────────────
analyze              ✓ 1.3K   ✓ 1.0K   ✓ 1.3K   ✓ 1.2K   ✓ 1.9K   ✓  558    EMPTY
checksec             ✓  219   ✓  209   ✓  213   ✓  218   ✓  206   ✓  206   ✓  211
rop                  ✓  394   ✓  380   ✓  384   ✓  574   ✓  377   ✓  384   ✓  747
cfg                  ✓ 1.0K   ✓ 3.4K   ✓ 3.4K   ✓  702   ✓ 3.5K   ✓   68   EMPTY
dataflow             EMPTY    ✓  128   ✓  128   ✓  130   ✓  128   EMPTY    EMPTY
strings-analysis     ✓  128   ✓  151   ✓  104   ✓  231   ✓  129   ✓   58   EMPTY
heap-analysis        ✓   98   ✓   98   BAD      ✓   98   ✓ 2.7K   BAD      BAD
integer-analysis     ✓  120   ✓  123   BAD      ✓  120   ✓  122   BAD      BAD
imports              ✓ 5.5K   ✓ 11K    ✓ 9.7K   ✓ 7.7K   ✓ 13K    ✓ 1.0K   ✓ 234K
addresses            ✓ 10K    ✓ 8.2K   ✓ 9.9K   ✓ 6.8K   ✓ 15K    ✓  457   ✓ 1.1K
leaks                EMPTY    EMPTY    EMPTY    EMPTY    EMPTY    EMPTY    EMPTY
report               ✓  442   ✓  440   ✓  448   ✓  444   ✓  425   ✓  434   ✓  436
template             ✓  101   ✓   95   ✓   99   ✓  102   ✓   92   ✓   92   ✓   93
decompile            ERROR    ERROR    ERROR    ERROR    ERROR    ERROR    EMPTY
explain              EMPTY    EMPTY    EMPTY    ✓ 43K    EMPTY    ✓ 36K    ✓ 42K
autopwn              TOUT     TOUT     FAIL     FAIL     FAIL     TOUT     FAIL
solve                TOUT     TOUT     FAIL     FAIL     FAIL     TOUT     FAIL
pwn                  ✓ 10K    ✓ 10K    ✓ 10K    ✓ 10K    ✓ 10K    ✓ 3.8K   EMPTY
symbolic             ✓  169   ✓  163   ✓  167   ✓  170   ✓  160   ✓  160   ✓  161
offset               EMPTY    EMPTY    FAIL     FAIL     FAIL     ✓ OK     FAIL
exploit --auto       ✓ OK+    EMPTY    FAIL     ✓ OK+    FAIL     ✓ OK+    FAIL
```

Legend: ✓=produced data, EMPTY=no output, ERROR=error JSON, FAIL=ran but failed,
TOUT=timed out, OK+=success, BAD=invalid JSON

## Exploitation Results

### Canonical Pipeline (autopwn/solve)

| Binary             | Success | Techniques Attempted | Non-Skip | Best Outcome |
|--------------------|---------|---------------------|----------|--------------|
| sick_rop           | ✗       | 15                  | 0        | All SKIPPED  |
| rocket_blaster_xxx | ✗       | 17                  | 3        | ret2libc FAILED, variable_overwrite FAILED, format_string PARTIAL |
| snow_scan          | ✗       | 17                  | 2        | srop PARTIAL, variable_overwrite FAILED |
| ancient_interface  | ✗       | 9                   | 0        | All SKIPPED (timeout) |
| auth-or-out        | ✗       | 9                   | 0        | All SKIPPED (timeout) |
| sabotage           | ✗       | 17                  | 3        | scanf_canary_bypass PARTIAL, format_string PARTIAL, variable_overwrite FAILED |
| bon-nie-appetit    | ✗       | 17                  | 2        | variable_overwrite FAILED, format_string PARTIAL |

**0/7 solved by canonical pipeline.**

### Legacy Engine (exploit --auto)

| Binary             | Success | Technique          |
|--------------------|---------|-------------------|
| sick_rop           | ✓       | variable_overwrite |
| rocket_blaster_xxx | ✓       | ROP               |
| ancient_interface  | ✓       | ROP               |
| snow_scan          | ✗       | —                 |
| auth-or-out        | ✗       | —                 |
| sabotage           | ✗       | scanf_canary_bypass (failed) |
| bon-nie-appetit    | ✗       | —                 |

**3/7 solved by legacy engine.**

### Manual solve with --libc flag (user-reported)

| Binary             | Success | Technique     | Notes                          |
|--------------------|---------|--------------|--------------------------------|
| rocket_blaster_xxx | ✓       | ret2libc_leak | Required explicit `--libc` flag |

## Key Findings

### Critical Gaps

1. **Canonical pipeline solves 0/7 targets vs legacy engine's 3/7.**
   The canonical `CanonicalAutopwnEngine` has stricter precondition gates than
   the legacy `AutoExploiter`, resulting in more SKIPs and fewer attempts. The
   legacy engine tries techniques more aggressively. The CLI deconfliction task
   (queued) should merge the best of both engines.

2. **Shipped libc auto-detection finds the file but it was 0 bytes.**
   rocket_blaster_xxx ships `./glibc/libc.so.6` but the zip extraction produced
   a 0-byte file. The `detect_shipped_libc()` method correctly finds the path,
   but the technique fails reading offsets from the empty file. Fixed by
   re-extracting the inner zip. The solve command succeeds when `--libc` is
   provided explicitly (user-confirmed on Sep 25).

3. **ret2win detector too narrow.**
   `WIN_FUNCTIONS` is a hardcoded list of 21 names (`win`, `flag`, `shell`, etc.).
   rocket_blaster_xxx's win function is `fill_ammo` — not in the list. The
   `strings-analysis` command correctly found `./flag.txt` in the binary, but no
   cross-reference links this to the function that opens it.

4. **SROP gate rejects binaries without .bss/.data sections.**
   sick_rop is a minimal static binary with only `.text` and no writable data
   sections in ELF headers. SROP skip reason: "no '/bin/sh' string and no
   writable section to plant one." But SROP can use the stack (writable at
   runtime) via `read()` syscall to plant "/bin/sh" — the technique should
   account for this.

5. **`explain` fails silently for 4/7 binaries.**
   Empty JSON output for ancient_interface, auth-or-out, bon-nie-appetit,
   sabotage. No error message in the JSON — the command just produces no stdout.
   Succeeds for 3/7 (sick_rop, rocket_blaster_xxx, snow_scan).

6. **`decompile` fails for all 7 binaries.**
   Returns `{"error": "Decompilation failed"}` for 6/7 and empty output for 1/7.
   angr's decompilation is unreliable on both small static binaries and dynamically
   linked PIE binaries.

### Minor Gaps

7. **`exploit --vuln-type` doesn't exist.**
   The test harness used `--vuln-type bof/fmtstr/heap/integer` which is not a
   valid flag. The exploit command uses `--auto` and `--crash` instead. All 28
   exploit variant tests (4 per binary) failed with "No such option: --vuln-type".

8. **`leaks` command returns empty for all 7 binaries.**
   The leak detection command produces no output regardless of binary type.

9. **`offset` succeeds for only 1/7 (sick_rop).**
   Offset detection requires the binary to crash on plain cyclic input. Binaries
   with menu interactions (rocket_blaster_xxx), custom input formats (snow_scan's
   BMP), or canaries (auth-or-out, sabotage, bon-nie-appetit, ancient_interface)
   prevent automatic offset discovery.

10. **`analyze` misreports stripped status.**
    ancient_interface: `file` says "stripped" but analyze reports `Stripped=False`.

11. **`analyze` reports `uses_tcache: true` for static binary sick_rop.**
    Static binaries don't use tcache. This is a false positive in the tcache
    detection heuristic.

12. **`pwn` recommendation sorts by priority, not confidence.**
    For rocket_blaster_xxx, VARIABLE_OVERWRITE (conf=0.5) is recommended over
    ROP_EXECVE (conf=0.8) because VARIABLE_OVERWRITE has priority 1 while
    ROP_EXECVE has priority 2.

13. **`pwn` doesn't suggest SROP for sick_rop.**
    Only 2 strategies listed (VARIABLE_OVERWRITE, STACK_PIVOT). SROP is the
    correct technique for this binary.

14. **heap-analysis produces invalid JSON for 3/7 binaries.**
    sick_rop, bon-nie-appetit, and snow_scan produce unparseable JSON from the
    heap analysis command.

15. **integer-analysis produces invalid JSON for 3/7 binaries.**
    Same binaries as heap-analysis.

16. **Custom allocator blindness.**
    auth-or-out uses `ta_alloc`/`ta_free`/`ta_calloc` instead of standard
    malloc/free. heap-analysis finds 0 alloc sites, 0 vulnerabilities.

17. **`report` finds 0-1 findings across all binaries (all Low/Informational).**
    Despite known vulnerabilities in every binary, the vuln detectors don't flag
    them. The detectors rely on pattern matching that doesn't catch real-world
    vulnerability patterns.

18. **`dataflow` times out on static binaries.**
    Empty output for sick_rop and snow_scan (both statically linked).

19. **`cfg` times out on snow_scan (large static binary).**
    CFG analysis can't handle the hundreds of functions in a statically-linked
    binary within the 60s timeout.

### Working Well

- **checksec**: 7/7 correct, fast, reliable
- **rop**: 7/7 produced results, found key gadgets (syscall;ret, pop rdi/rsi/rdx/rax)
- **imports**: 7/7 produced results, correct dangerous function identification
- **addresses**: 6/7 produced useful data (sick_rop edge case with no sections)
- **template**: 7/7 generated exploit script templates
- **symbolic**: 7/7 produced output (though minimal — just notes)
- **pwn**: 6/7 produced strategy recommendations (snow_scan was empty/timeout)
- **version/cyclic/cyclic-find**: All working correctly
- **explain**: When it works (3/7), produces excellent 30-40KB walkthroughs
- **strings-analysis**: Correctly found `./flag.txt` in rocket_blaster_xxx

## Recommendations for Next Sprint

### High Priority (directly impacts solve rate)
1. **Merge legacy and canonical engines** (queued: CLI deconfliction)
   — Legacy AutoExploiter solves 3/7 vs canonical's 0/7
2. **Improve ret2win detection** — scan for functions that reference flag strings
   (`./flag.txt`, `flag`, etc.) via cross-reference, not just function name matching
3. **Fix SROP gate for stack-writable targets** — when binary has `read` syscall
   and writable stack, SROP should attempt using stack as writable target

### Medium Priority
4. **Fix explain for PIE binaries** — 4/7 produce empty output
5. **Fix heap-analysis/integer-analysis JSON output** — 3/7 produce invalid JSON
6. **Fix leaks command** — 0/7 produce any output
7. **Fix stripped detection** — analyze misreports for ancient_interface
8. **Fix pwn recommendation sorting** — should prefer highest confidence

### Low Priority
9. **decompile** — angr decompilation is unreliable; consider ghidra bridge
10. **Custom allocator detection** — auth-or-out's ta_alloc/ta_free
11. **Menu-aware offset detection** — for binaries requiring interaction before overflow
