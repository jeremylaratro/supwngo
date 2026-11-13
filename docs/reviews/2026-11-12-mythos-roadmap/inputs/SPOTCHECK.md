# Orchestrator spot-checks of the dimension reviews (2026-11-12)

Each claim was re-checked by the orchestrator against the tree, or at runtime through the scorecard.

| Claim | Source | Verdict | Evidence |
|---|---|---|---|
| `--win/--ret2/--rop` exist but only on autopwn/explain/solve | D1-F5, D4-F7 | CONFIRMED | `cli.py:66` `target_override_options`, applied at `cli.py:2840, 3238, 3449` |
| CI workflow file exists | D1-F13, D5-F5 | CONFIRMED (file); no runner per owner policy | `.github/workflows/ci.yml` (commit e8a250d) |
| angr decompile returns a 32-char failure sentinel as success | D2-F5, D2-H3 | CONFIRMED in code and at runtime | `_angr_subprocess.py:244`; scorecard: rocket_blaster_xxx and ancient_interface `code == "// Decompilation failed for main"`, backend `angr`, no error |
| `"fill_ammo"` hard-coded in `WIN_NAMES` | D2-F11, D4-F4 | CONFIRMED | `offset_finder.py:887` |
| RELRO string mismatch makes the ret2dlresolve gate never reject | D1-F3 | CONFIRMED in code and at runtime | `binary.py:381-391` yields `"Full RELRO"`; `strategy.py:454` compares `== "full"`; scorecard: RET2DLRESOLVE listed on all 4 Full-RELRO targets |
| `vulns/heap.py` and `vulns/integer.py` static detect are `return []` | D2-F1 | CONFIRMED | `heap.py:109`, `integer.py:96` |
| `stack_bof` drops read/recv when canary and PIE are both on | D2-F1 | CONFIRMED | `stack_bof.py:154-157` |
| `UAFDetector` constructs `UAFVuln(name=…)`, which raises `TypeError` | D2-F7 | CONFIRMED | `uaf.py:105-110`; `UAFVuln` (`uaf.py:33`) inherits required `vuln_type`/`severity` from `Vulnerability` (`detector.py:63-70`) and has no `name` field |
| `VARIABLE_OVERWRITE` appended unconditionally | D1-F2, D4-F11 | CONFIRMED | `strategy.py:266-272` |
| DGX Spark is ARM64; target runner must be x86-64 | D5-R5 | CONFIRMED | Sparks are GB10 (ARM64); the analysis host is x86_64 |
| `pwn` emits the same strategy list regardless of bug class | D1-F2 | CONFIRMED at runtime | scorecard: identical 8-strategy list on 5/7 targets |
| The Ghidra 180 s cap is per-invocation cost + contention, not a hang | D1-H3, D2-H2 | CONSISTENT | re-run alone took 34 s; `application.log` shows uniform 5–20× phase slowdown under load (BRIEF §7) |

Not re-checked (accepted as UNVERIFIED reviewer inference): D1-F10 dead-module list, D1-F13 Dockerfile build
failure, D2-F3 PIE image-base mismatch at runtime, D4-F6 exit-code survey, D5-F4 historical report claims.

## Additional verified facts (after D3)

- **BRIEF §4 "0/7" is stale (D3-F1).** It is the 2026-09-26 figure. The tree's CHANGELOG records the canonical
  pipeline reaching SHELL_ACCESS on 7/7 HTB targets by 2026-09-28, with techniques that differ from the
  write-up labels on 3 targets (rocket_blaster_xxx → ret2libc_leak, snow_scan → container_file_rop,
  sabotage → env_path_hijack). **Not re-measured at 1741b34**; the scorecard has no `solve` column. Note the
  interpreter defect in SCORECARD.md: a re-measure must run targets from their challenge directory.
- **Experiment D2-H1 (static offset from Ghidra frame + high P-code), partial results**
  (scratch GhidraScript dumping per-function stack variables and input-sink call arguments, resolving
  `PTRSUB(sp, c)` to a stack offset relative to the return-address slot):
  - rocket_blaster_xxx: `main` → `read(0, stack:-40, 102)` ⇒ offset **40**, = disassembly truth; length 102 >
    40+8 ⇒ overflow shown statically. `fill_ammo` calls `open`+`read`+`printf` (evidence-based payoff).
  - sick_rop (hand-written asm, args pushed on the stack): Ghidra recovers **no stack variables** and the
    `read` arguments resolve to unconstrained registers ⇒ estimator B abstains; a prologue estimator
    (`push rbp; mov rbp,rsp; sub rsp,0x20` with the buffer at the frame bottom) gives 40 = truth.
  - ancient_interface (stripped, canary): `FUN_00401b12` reads 4095 into `stack:-4120` (no overflow);
    `FUN_0040189b` (canary) reads into `INT_ADD(stack_base, accumulated_count)` — the accumulator bug. The
    resolver must follow base+index and report `reaches ∈ {canary, ret}` rather than a single number.
  - Each Ghidra run took 26–44 s cold (import + analysis + whole-program decompile) on the loaded host.
  - snow_scan and the two mingw PE fixtures were still running when the synthesis started.
- **D3-F1 CONFIRMED from artifact.** `benchmark/results_htb/full-rescore-FINAL-20260928.json` (gitignored, local):
  score 7/7, 3/3 reps per target, every rep `shell_proven: true`, `echo_ambiguous: false`; techniques
  eintr_accumulator_rop, objptr_hijack, heap_strlen_ofb1, ret2libc_leak, env_path_hijack, srop_symtab_pivot,
  container_file_rop. `tests/htb-targets/organized/` is a symlink farm into the challenge directories (which
  ship `glibc/`); `htb_rescore.py` copies the challenge directory and runs with `cwd` = that copy. A re-run at
  1741b34 was started 2026-11-12 ~18:08.
- **Experiment D2-H1, final** (6 binaries; truth from disassembly):

  | Binary | Ghidra P-code sink record | Static offset | Truth | Result |
  |---|---|---|---|---|
  | rocket_blaster_xxx (ELF64, dyn) | `main`: `read(0, stack:-40, 102)` | 40 | 40 | exact; len 102 ⇒ overflow |
  | vuln64.exe (mingw PE32+) | `vuln`: `fgets(stack:-72, 256, …)` | 72 | 72 (`lea rax,[rbp-0x40]`) | exact |
  | vuln32.exe (mingw PE32) | `vuln`: `fgets(stack:-76, 256, …)` | 76 | 76 (`lea eax,[ebp-0x48]`) | exact |
  | sick_rop (static, hand asm) | args pushed on stack → unresolved | abstain (prologue fallback: 40) | 40 | needs estimator A |
  | ancient_interface (stripped, canary) | `read(0, INT_ADD(stack_base, count), …)` | abstain (base+index) | accumulator bug | needs base+index + canary reach |
  | snow_scan (static, 877 KB) | bug is a copy loop, not a sink call | abstain | — | needs loop-copy pattern / FID |

  Win functions were identified behaviourally on both PE fixtures (`win` → `system`) and on rocket_blaster_xxx
  (`fill_ammo` → `open`/`read`). Cold cost: 26–86 s for small binaries; **427 s for snow_scan** (913 functions,
  mostly static libc, whole-program decompile) ⇒ library identification (FunctionID) and per-function budgets
  are prerequisites for whole-program export on static binaries. Image base reported per program
  (ELF non-PIE 0x400000, PE64 0x140000000, PE32 0x400000).
- **HYP-9 measured (after SYN draft).** `scripts/htb_rescore.py --reps 3 --timeout 300` at 1741b34, run with
  `cwd` = challenge copy: **SCORE 7/7, 21/21 reps `shell_proven: true`, `echo_ambiguous: false`, 0 hard errors.**
  Techniques unchanged from 2026-09-28 (eintr_accumulator_rop, objptr_hijack, heap_strlen_ofb1,
  ret2libc_leak, env_path_hijack, srop_symtab_pivot, container_file_rop). Wall 7–71 s per rep. So `solve`
  has not regressed; the `pwn`/`template`/`offset` surfaces remain the PASS gap. This was measured on the
  same 7 targets the executors were written from (DEC-5 applies: it is smoke, not generalisation evidence).
