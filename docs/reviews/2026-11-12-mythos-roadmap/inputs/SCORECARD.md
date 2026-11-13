# S6 baseline scorecard — 2026-11-12 (current tree, commit 1741b34)

Each cell is the raw CLI result: `supwngo <cmd> <target> --json` (`template` also writes the
script). 240 s outer timeout per cell. Host was loaded (15-min load 16–26 on 32 cores, 12 users)
so wall times are inflated. Expected method is the known-solution technique.

## Tally against the owner's PASS criteria (orchestrator's reading)

| Target | Right method listed? | Recommended? | template -t auto | decompile (default) | offset |
|---|---|---|---|---|---|
| sick_rop | no (SROP missing) | no (STACK_PIVOT) | ret2system (wrong: static, no libc) | FAIL (Ghidra 180 s cap → angr failed) | CRASH (TimeoutExpired) |
| rocket_blaster_xxx | no (no RET2WIN) | no (ROP_EXECVE) | ret2system (wrong: ret2win) | FAIL (Ghidra cap → angr 32-char failure sentinel reported as success) | none |
| snow_scan | yes (SROP) | yes | ret2system (wrong: static) | FAIL (Ghidra cap → no backend) | none |
| ancient_interface | yes (ROP_EXECVE) | yes | ret2system (plausible) | FAIL (angr sentinel; Ghidra did not produce `main`) | none |
| auth-or-out | no (no UAF/heap method) | no | ret2system (wrong) | OK (Ghidra, 1100 chars, 43 s) | n/a stack; none |
| sabotage | no (no integer method; NEGATIVE_SIZE_BYPASS is listed on every target) | no | ret2system (wrong) | OK (Ghidra, 546 chars, 35 s) | n/a stack; none |
| bon-nie-appetit | no (no heap method) | no | ret2system (wrong) | OK (Ghidra, 784 chars, 30 s) | n/a stack; none |
| **Total** | **2/7** | **2/7** | constant `ret2system` 7/7 | **3/7** | **0/7** (1 crash) |

Cross-target observations:
- `pwn` emits an *identical* 8-strategy list (ROP_EXECVE, ROP_SYSTEM, STACK_PIVOT, RET2DLRESOLVE, RET2PLT,
  VARIABLE_OVERWRITE, FORMAT_STRING, NEGATIVE_SIZE_BYPASS) for 5 of 7 targets regardless of bug class.
- RET2DLRESOLVE is listed on all four Full-RELRO targets: `strategy.py:454` compares
  `protections.relro == "full"` but `core/binary.py:381-391` produces `"Full RELRO"`.
- `template -t auto` returns `ret2system` for 7/7 (the `tech_map` default in `cli.py`).
- The three Ghidra timeouts all happened during a high-load window (see BRIEF §7); the three Ghidra
  successes took 30–43 s.
- No target has a PE equivalent yet; the PE criterion is unmeasured.

## sick_rop
- **Expected:** SROP (stack BOF)
- **pwn:** rec **STACK_PIVOT**; listed: STACK_PIVOT, VARIABLE_OVERWRITE
- **template -t auto:** `ret2system` (2385 B)
- **decompile (default -f main):** angr `None` 0 chars; error: Decompilation failed
- **offset:** ERROR no JSON (JSONDecodeError); stderr: subprocess.TimeoutExpired: Command '['tests/htb-targets/organized/sick_rop']' timed out after 5 seconds
- **wall:** pwn 6s, template 13s, decompile 189s, offset 29s

## rocket_blaster_xxx
- **Expected:** RET2WIN (fill_ammo) (stack BOF)
- **pwn:** rec **ROP_EXECVE**; listed: ROP_EXECVE, ROP_SYSTEM, STACK_PIVOT, RET2DLRESOLVE, RET2PLT, VARIABLE_OVERWRITE, FORMAT_STRING, NEGATIVE_SIZE_BYPASS
- **template -t auto:** `ret2system` (2360 B)
- **decompile (default -f main):** angr `main` 32 chars **(failure sentinel)**
- **offset:** none — Could not determine offset with any method
- **wall:** pwn 6s, template 13s, decompile 190s, offset 5s

## snow_scan
- **Expected:** SROP (stack BOF (BMP parser))
- **pwn:** rec **SROP**; listed: SROP, ROP_EXECVE, MPROTECT_SHELLCODE, STACK_PIVOT, VARIABLE_OVERWRITE
- **template -t auto:** `ret2system` (2356 B)
- **decompile (default -f main):** none `None` 0 chars; error: Decompilation failed
- **offset:** none — Could not determine offset with any method
- **wall:** pwn 33s, template 3s, decompile 215s, offset 2s

## ancient_interface
- **Expected:** ROP (stack BOF via read)
- **pwn:** rec **ROP_EXECVE**; listed: ROP_EXECVE, ROP_SYSTEM, STACK_PIVOT, RET2DLRESOLVE, RET2PLT, VARIABLE_OVERWRITE, FORMAT_STRING, NEGATIVE_SIZE_BYPASS
- **template -t auto:** `ret2system` (2369 B)
- **decompile (default -f main):** angr `main` 32 chars **(failure sentinel)**
- **offset:** none — Could not determine offset with any method
- **wall:** pwn 6s, template 17s, decompile 37s, offset 89s

## auth-or-out
- **Expected:** UAF (custom allocator) (heap)
- **pwn:** rec **ROP_EXECVE**; listed: ROP_EXECVE, ROP_SYSTEM, STACK_PIVOT, RET2DLRESOLVE, RET2PLT, VARIABLE_OVERWRITE, FORMAT_STRING, NEGATIVE_SIZE_BYPASS
- **template -t auto:** `ret2system` (2336 B)
- **decompile (default -f main):** ghidra `main` 1100 chars
- **offset:** none — Could not determine offset with any method
- **wall:** pwn 7s, template 17s, decompile 43s, offset 89s

## sabotage
- **Expected:** integer overflow (integer)
- **pwn:** rec **ROP_EXECVE**; listed: ROP_EXECVE, ROP_SYSTEM, STACK_PIVOT, RET2DLRESOLVE, RET2PLT, VARIABLE_OVERWRITE, FORMAT_STRING, NEGATIVE_SIZE_BYPASS
- **template -t auto:** `ret2system` (984 B)
- **decompile (default -f main):** ghidra `main` 546 chars
- **offset:** none — Could not determine offset with any method
- **wall:** pwn 6s, template 3s, decompile 35s, offset 3s

## bon-nie-appetit
- **Expected:** heap off-by-one (heap)
- **pwn:** rec **ROP_EXECVE**; listed: ROP_EXECVE, ROP_SYSTEM, STACK_PIVOT, RET2DLRESOLVE, RET2PLT, VARIABLE_OVERWRITE, FORMAT_STRING, NEGATIVE_SIZE_BYPASS
- **template -t auto:** `ret2system` (2344 B)
- **decompile (default -f main):** ghidra `main` 784 chars
- **offset:** none — Could not determine offset with any method
- **wall:** pwn 4s, template 2s, decompile 30s, offset 2s


## Harness defect found after the run (orchestrator, 2026-11-12 18:02)

rocket_blaster_xxx, sabotage and bon-nie-appetit request the relative interpreter
`./glibc/ld-linux-x86-64.so.2` (`readelf -l`). `tests/htb-targets/organized/` holds the bare binaries with
**no `glibc/` directory**, and the scorecard ran from the repo root, so **these three targets cannot execute
at all** (`gdb run` → `zsh: no such file or directory`, exit 127). Their dynamic results (`offset`, and any
dynamic step inside `pwn`/`template`) are therefore **VOID**, not tool failures. The original challenge
directories (`tests/htb-targets/<uuid>/challenge/`) do ship `glibc/`.

This is also a tool defect: `offset` reports "Could not determine offset with any method" instead of "target
cannot execute (interpreter not found)" — a silent probe failure that reads as a negative result. Static
evidence for rocket_blaster_xxx: Ghidra P-code resolves `main`'s `read(0, stack:-40, 102)` → offset 40,
matching the disassembly ground truth (`lea rax,[rbp-0x20]`, `mov edx,0x66`).
