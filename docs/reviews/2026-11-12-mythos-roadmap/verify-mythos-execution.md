## 0. Verdict

- **The roadmap's structure survives, but its "Today" baseline, three SP-01 premises and one SP-03 premise do not.** Its three bets and the sprint order hold up; the details below must change before SP-01 starts.
- **The baseline was partly an artefact of how the scorecard was run.** From challenge-directory copies, `offset` returns the correct 40 on sick_rop and rocket_blaster_xxx with no crash, and default `decompile` is 5/7, not 3/7. Method (2/7) and the constant `ret2system` template (7/7) reproduce exactly.
- **Two S0 targets cannot execute even from their challenge directory.** sabotage and bon-nie-appetit ship a 0-byte loader, so "all seven S0 loaders must resolve" is wrong.
- **Bet 1 (Ghidra P-code distance) held on new fixtures with zero wrong answers.** It was exact on 8 of 23 and abstained on 15. The abstentions show three gaps the roadmap did not plan for: fortified sinks at `-O2`, no sink names in stripped static binaries, and the unimplemented callee shape.
- **The SP-03 cache design is broken as written.** Ghidra refuses any project path with a component starting with `.`, so `~/.cache/supwngo/…/ghidra/` cannot hold a project. Reopening a persisted project is also no faster than a cold run on small binaries.
- **The sandbox bet held.** bubblewrap works unprivileged on this host, including for Ghidra, provided `/tmp` is a private tmpfs.
- **The instruments are weaker than assumed.** Three of my own SP-02a RED proofs pass on the broken tree as written. One existing unit test passes only because of the angr sentinel. Three test files run the installed live-repo CLI, not the checkout under test.
- **Execution found two "failure as success" cases the roadmap missed.** `pwn` on a PE returns SHELLCODE at 0.9 with exit 0, and the angr fallback never produces code on this host because of a one-argument bug.

Not done: `autopwn` was left out of HYP-4, no SROP stub fixtures were built, and the depth-1 caller export, the SP-02c REDs and the passcard mutant table were not written. Parts of the session were cut short by safety stops, so those items are listed in §9, not claimed.

## 1. Execution log summary

All artefacts are under `/tmp/mythos-verify/work/`. Load is the 1-minute average at start.

| What | Wall | Load | Artefacts |
|---|---|---|---|
| Full unit suite, `nice -n 10 python3 -m pytest -q` | 3156 s | 12.9 → 43.2 | `logs/pytest-full.log` |
| Rerun of the 2 failed tests alone | 98 s | ~45 | (inline) |
| S0 scorecard, 7 × {pwn, template, offset, decompile}, cwd = challenge copy | 1–73 s per cell | 13–22 | `scorecard/run1/`, `logs/scorecard-run1.log` |
| S0 decompile rerun with a non-hidden `TMPDIR` | 23–104 s per cell | 17–21 | `scorecard/run2/` |
| Ghidra frame export, 22 fixtures in one JVM (dir import) | 143 s | 8.8 | `d2h1/out/A.log`, `d2h1/out/*.jsonl` |
| Ghidra frame export, one static ELF | 358 s | 15.2 | `d2h1/out/B.log` |
| DWARF and breakpoint truth | <2 min | ~15 | `d2h1/truth.py`, `d2h1/bp2.py`, `d2h1/out/truth.json`, `d2h1/score.py` |
| Ghidra warm ×5 and cold ×2 on one binary | 17 s to >300 s | 28–38 | `d2h1/outw/`, `d2h1/outc/` |
| bubblewrap probe, and Ghidra inside bubblewrap | <1 s; 63 s | 50–58 | `bwrap/`, `bwrap/gh2/run2.log` |
| HYP-5 rename and decoy | ~1 min | ~15 | `hyp/hyp5.py`, `hyp/hyp5.out` |
| HYP-10 on sick_rop (static analysis only) | <10 s | ~21 | `hyp/hyp10.py`, `hyp/hyp10.out` |
| HYP-4, three engines on 6 fixtures | ~4 min | ~30 | `hyp/h4/` |
| HYP-14 import graph and coverage | ~3 min | ~20 | `hyp/hyp14*.py`, `hyp/cov/` |
| HYP-22 AST scan | <5 s | — | `hyp/hyp22.py`, `hyp/hyp22.out` |
| SP-01b RED tests, current tree and prototype | 29 s each | 20–35 | `tests/test_sp01b_red.py`, `logs/sp01b-red-*.log` |
| SP-02a RED tests, current tree and prototype | 1.4 s; 140 s | ~35 | `tests/test_sp02a_red.py`, `logs/sp02a-red-*.log` |
| SP-02b behavioural checks | <1 min | ~45 | `sp02b/` |
| Default-function and PE checks | 34–214 s | 28–47 | `deffn/` |
| Prototype patches (15 labelled `PROTOTYPE(mythos-verify)` sites) | — | — | `proto/supwngo/` |

- **Prototype location.** I patched a copy at `work/proto/`, not the tree, so the unit baseline and scorecard ran against unmodified code.
- **Processes.** No process of mine is left running. The two `java` processes on the host are 19 days old and not mine.
- **Live repo.** Nothing was written under `/srv/share/dev/`. Three unit-test files did import code from it; see §5 item 3.

## 2. Claim verification

| Claim | Roadmap location | Verdict | Evidence |
|---|---|---|---|
| Method 2/7 on S0 | §0, §1.6 | CONFIRMED-BY-EXECUTION | `scorecard/run1-summary.txt`: snow_scan SROP and ancient_interface ROP_EXECVE correct; the other five wrong. |
| Constant `ret2system` template on 7/7 | §0 | CONFIRMED-BY-EXECUTION | Same file: `technique=ret2system` on all seven. |
| Offset 0 correct in 4 valid cells, one crash | §0, §1.6 | WRONG | `offset ./sick_rop --json` → `offset: 40, method: "GDB - stack value at RSP+0"`; same for rocket_blaster_xxx. 3/3 further reps on sick_rop returned 40. No traceback in 28 cells. |
| Three cells VOID because targets could not execute from the repo root | §0 | WRONG in detail | rocket_blaster_xxx runs from its directory (rc 0). sabotage and bon-nie-appetit do not (rc 126): `glibc/ld-linux-x86-64.so.2` is 0 bytes. Two VOID, not three. |
| "All seven S0 loaders must resolve" | §6 SP-01a.4 | WRONG | Same evidence. The tree already documents this as I-17 (`tests/test_fmtstr_probe_unspawnable.py:17-29`). |
| Decompile 3/7 | §0, §1.6 | WRONG (now 5/7) | `scorecard/run2`: Ghidra succeeded on rocket_blaster_xxx, snow_scan, auth-or-out, sabotage, bon-nie-appetit at load 17–21. |
| angr sentinel returned as code | §0 | CONFIRMED-BY-EXECUTION | ancient_interface: `backend=angr`, 32 chars, `// Decompilation failed for main`, rc 0. |
| Exit 0 with an `error` object | §0 | CONFIRMED-BY-EXECUTION | sick_rop decompile: `{"error": "Decompilation failed"}`, rc 0. |
| Silent "no offset" when the target cannot execute | §0 | CONFIRMED-BY-EXECUTION | sabotage offset: "Could not determine offset with any method" in 1.5 s; also on my `noexec` fixture. |
| `"fill_ammo"` at `offset_finder.py:887` | §0 | CONFIRMED-BY-EXECUTION | The identifier-lint test lists it. |
| RELRO mismatch lists RET2DLRESOLVE on Full RELRO | SP-01b.4 | CONFIRMED-BY-EXECUTION | `hyp5.out`: `r2w_fullrelro`, `relro: "Full RELRO"`, RET2DLRESOLVE listed. |
| RELRO site list includes `got_plt.py:106, 259, 310` | SP-01b.4 | WRONG | Those compare a pwntools-sourced value (`"Full"`) and are correct. The lint as I wrote it reports 18 hits and cannot go green; narrowed to `Protections` receivers it reports 13. |
| Removing `fill_ammo` turns the identifier lint green | SP-01b.6 | WRONG | 14 hits today: 12 in docstrings, 2 in code (`offset_finder.py:887`, `walkthrough/families/heap_strlen.py:598`). |
| Post-analysis override patch cannot produce RET2WIN (B-5) | §0 Bet 2, SP-02a.3 | CONFIRMED-BY-EXECUTION | `test_post_analysis_patch_cannot_produce_ret2win` passes on both trees. |
| RT-08 gate widening alone leaves `recommended` at STACK_PIVOT | §5 S6 disposition | CONFIRMED-BY-EXECUTION | `hyp10.out`: after widening, ranking is STACK_PIVOT 0.65, SROP 0.6, VARIABLE_OVERWRITE 0.5. |
| `template -t auto` builds a suggester with no gadget finder | §0 | CONFIRMED-BY-EXECUTION | Same file: without a finder the suggester recommends ROP_EXECVE on sick_rop; with one, STACK_PIVOT. |
| `template` executes the target | DEC-9 | CONFIRMED-BY-EXECUTION | `sp02b/marker`: `ran.marker` gained 2 lines after `template -t auto`. |
| `--offset 0` is dropped | SP-02b | CONFIRMED-BY-EXECUTION | With `--offset 0` the target still ran twice. |
| `-t ret2win` with no payoff falls through to the leak script | SP-02b | CONFIRMED-BY-EXECUTION | Output is byte-identical to the `-t auto` script (`cmp`), while the JSON says `"technique": "ret2win"`. |
| `decompile` cannot open a PE because `Binary.load` is ELF-only | SP-01b.5, B-7 | WRONG | `decompile ./pe_syms.exe -f vuln --json` → Ghidra backend, correct pseudo-C, 76 s at load 47. `Binary.load` degrades silently instead of failing. |
| No-`-f` decompile forces `main` and fails on no-`main` binaries | SP-01b.5 | CONFIRMED-BY-EXECUTION | `deffn/nomain.json`: "Decompilation failed". Stripped `nomain_dyn`: angr names `main` at the true address but returns the sentinel. |
| P-code distance exact on compiler-built direct sinks, ELF and PE | DEC-2, HYP-1 | CONFIRMED-BY-EXECUTION | 8/8 exact on direct `-O0` ELF (canary, PIE) and direct PE32/PE64 at `-O0` and `-O2`. |
| 427 s static cost is mostly whole-program decompile (HYP-23) | SP-03 risks | CONFIRMED-BY-EXECUTION, with a caveat | Static hello-sized ELF: analysis 134 s, script decompile 203 s, total 358 s. Analysis alone is already close to the 180 s gate. |
| bubblewrap needs an owner action (HYP-24, Q10) | SP-01a.3 | WRONG (works) | `kernel.apparmor_restrict_unprivileged_userns = 0`; the probe hid truth, denied writes and denied network. |
| Facts store at `~/.cache/supwngo/<sha>/…/ghidra/` | SP-03 | WRONG | `analyzeHeadless …/dot/.cache/proj …` → `Path element starting with '.' is not permitted`. |
| Expected unit baseline about 2230 passed, 18 skipped | task brief | CONFIRMED-BY-EXECUTION | 2229 passed, 2 failed, 18 skipped. Both failures pass when rerun alone. |
| Engine imports at `cli.py:296,370,413,457`; fallback at `:2953,3565` | DEC-14, deletion schedule | CONFIRMED-BY-READING | `sed` of each line shows the named import. |
| `pie_base_offset()` has no caller | HO-01 | CONFIRMED-BY-READING | grep finds only the definition. |
| `solve` 7/7, 21/21 `shell_proven` | §0 | UNVERIFIABLE here | Not re-run. |
| OFF-S 3/3 on S0 stack targets by M1 | §1.6 | UNVERIFIABLE today | Needs the unbuilt affine and wrapper shapes. |

## 3. Hypotheses tested

| HYP | Result | Evidence | Decision impact |
|---|---|---|---|
| HYP-2 (warm ≤ 30 s) | Inconclusive under load; the premise behind it is weak | Warm: 16.8, 33.1, >300 (hung at "Opening project"), 24.9, 18.5 s. Cold on the same binary: 215 s and 25 s. Load 28–38. | Reopening saves almost nothing on small binaries; JVM start dominates. Export everything in the one cold run; do not persist projects for small dynamic binaries. |
| HYP-2 side result | One JVM imported and exported 22 binaries in 143 s (6.5 s each) | `d2h1/out/A.done` | Corpus runs (SP-03A, passcard) should use directory import. |
| HYP-4 (engines disagree) | Held | `pwn`/`template`/`explain` agree on 2 of 6 fixtures. On sick_rop: STACK_PIVOT, `ret2system`, and `solve`'s SROP. `autopwn` not run. | SP-05 unification stays a priority. |
| HYP-5 (name-driven) | Held, and worse than stated | `objcopy --redefine-sym win=zq_payoff_7`: RET2WIN → ROP_EXECVE. A benign function named `secret` gets RET2WIN at 0.95. `explain` uses a third name list and gives a different verdict on the decoy. | Add the decoy to SP-02a fixtures. `WIN_FUNCTIONS` contains `vuln_func`, `flag` and `secret`. |
| HYP-10 | Held | See §2. | Role tiering is required, as planned. |
| SROP rax-control negative | Not tested by execution | The executor's wrapper check is a regex over one instruction shape (`srop_nowrite_techniques.py:127-171`), read only. | See AMD-12. |
| HYP-14 (≥ 30% of `exploit/` unreachable) | Falsified in its import-graph form | Following `__init__` re-exports, 0 of 127 `exploit/` modules are unreachable (6 modules, 3% package-wide). Six commands on one fixture execute 25% of statements; `kernel/`, `schema/`, `symbolic/` execute 0%. | Reachability must be measured by coverage over the passcard. `--version` takes 1.07 s. |
| HYP-22 (other stringly-typed bugs) | Split | RELRO: 6 live mismatches (`strategy.py:454, 976`, `imports.py:499`, `pie_bypass.py:191`, `leak_finder.py:329`, `chainer.py:299`). `arch`: 29 comparisons, all consistent. The two suite failures pass when quiet. | Drop the `arch`/`os` lint extension. The flake is contention. |
| HYP-23 | Held, with thin headroom | See §2. | G4's 180 s static cap is at risk even for a minimal export. |
| HYP-24 | Held | See §2; Ghidra inside bubblewrap gave the correct `read(0, stack:-88, 400)` in 63 s at load 58. | Q10 is closed. Ghidra ignores `TMPDIR`, so the sandbox must mount a private `/tmp`. |
| D2-H1 static offset | 8 exact, 0 wrong, 15 abstain of 23 | Table below. | G1 is plausible; G3 (`-O2` coverage) fails today for a fixable reason. |
| B-5 override path | Yes, by injecting before `analyze()` | About 45 prototype lines; 11/11 SP-02a tests pass on the prototype. | SP-02a design confirmed. |
| B-11 deletion consumers | Confirmed | `auto`, `enhanced_auto`, `generator` are imported by `cli.py`; `chainer` by `auto.py`; `templates` only by `supwngo/__init__.py:51`. | SP-12a/b order stands. |

**D2-H1 detail** (stripped binaries; truth from DWARF, cross-checked by breakpoint where it ran):

| Cell | n | Exact | Wrong | Abstain | Why abstained |
|---|---|---|---|---|---|
| Direct, ELF `-O0` (canary × PIE) | 4 | 4 | 0 | 0 | — |
| Direct, ELF `-O2` | 4 | 0 | 0 | 4 | Ubuntu gcc fortifies `read` into `__read_chk`, which is not in the sink list. |
| Direct, mingw PE32/PE64, `-O0` and `-O2` | 4 | 4 | 0 | 0 | — |
| Callee sink, ELF and PE | 8 | 0 | 0 | 8 | Destination is a parameter; the depth-1 summary is not built. |
| Copy loop | 2 | 0 | 0 | 2 | Correct abstention. |
| Static ELF | 1 | 0 | 0 | 1 | No sink is named in a stripped static binary. |

Breakpoint truth agreed with DWARF on all 13 cells where my gdb script ran correctly. My first attempt broke on the symbol `read` and failed on all four `-O2` builds, because the call is `__read_chk`.

## 4. RED-test validation for SP-01 and SP-02

| Test | Fails on current tree? | Vacuous? | Prototype passes? |
|---|---|---|---|
| Refine timeout | Y, `TimeoutExpired` propagates | As I specified it ("monkeypatch `subprocess.run`"), it first failed for the wrong reason: the patch caught an unrelated `file -b` call. It must filter on `argv[0]`. | Y |
| Descendant survives timeout | Y, the forked child is still alive | No | Not prototyped |
| Target not executable | Y, generic error and no `error_code` | No | Y |
| `offset --json` negative exits 2 | Y, exit 0 | No, but `CliRunner` needs `mix_stderr=False` | Y |
| `decompile --json` failure exits 2 | Y, exit 0 | No | Y |
| angr tagged union, 4 worker cases | Y, no `status` key | No | Y |
| Parent rejects the sentinel | Y, sentinel returned as code | Only if the test feeds the legacy reply; feeding a new-style failure reply passes today | Y |
| Full RELRO has no RET2DLRESOLVE | Y | No (asserts the fixture really is Full RELRO) | Y |
| RELRO lint as written in the roadmap | Y, 18 hits | Cannot go green; flags correct pwntools comparisons | N, by design |
| RELRO lint, `Protections` receivers only | Y, 13 hits | No | Not prototyped |
| Identifier lint | Y, 14 hits | Stays red after the planned one-line fix | Not prototyped |
| Default function on no-`main` fixtures | Y (CLI run, not a pytest) | No | Not prototyped |
| EOF spin | Not run | — | — |
| SP-02a: override gives top-1 RET2WIN (`--win`, `--winfun`, `--ret2`, `--eip`) | Y, no such option | No | Y |
| SP-02a: `--ret2 --rop` is not RET2WIN | **N, passes** | **Vacuous**: the option is rejected, so RET2WIN is trivially absent | Y |
| SP-02a: libc symbol as `--win` is not RET2WIN | **N, passes** | **Vacuous**, same reason | Y |
| SP-02a: unresolvable override exits 2 | **N, passes** | **Vacuous**: click's own usage error also exits 2 | Y |
| SP-02a: non-vacuous variants of the three above | Y | No | Y |
| SP-02a: no persistence | Y | No | Y |
| SP-02b: no execution (marker) | Y (CLI check) | No | Not prototyped |
| SP-02b: zero offset; `-t ret2win` with no payoff | Y (CLI check) | No | Not prototyped |
| SP-02b SROP positive and negative; SP-02c; passcard mutants | Not written | — | — |

The prototype also turns one existing test red: `test_decompile_angr_happy_path_uses_subprocess_and_returns_function`. It passes today only because the sentinel counts as "a function".

## 5. New findings from execution

1. **The angr decompile fallback never returns code on this host.**
   - The worker builds `CFGFast()` without `normalize=True`. With it, the same function decompiles; without it, `codegen` is false.
   - Repro: `hyp/` probe output in the session; any `decompile --angr` cell in `scorecard/run2`.
2. **`pwn` on a PE reports a confident method with exit 0.**
   - Repro: `python3 -m supwngo.cli pwn ./pe_direct_O0_x86_64.exe --json` in `deffn/` → `"arch": ""`, `No-NX`, SHELLCODE at 0.9.
3. **Three unit-test files test the installed CLI, not the checkout.**
   - `tests/test_cfg_angr_budget.py:38`, `test_decompile_angr_budget.py:43` and `test_static_dataflow_strings_angr_budget.py:51` use `shutil.which("supwngo")`.
   - That resolves to `~/.local/bin/supwngo`, which runs `/usr/bin/python3` (3.10) against an editable install of `/srv/share/dev/supwngo`.
   - Any branch's result on those tests reflects the live repo. The SP-01b exit-code change would look unfixed.
4. **Ghidra rejects project paths containing a dot-directory, and the tool hides the reason.**
   - With `TMPDIR=<cell>/.tmp`, decompile went from 5/7 to 0/7. The warning shows only the JVM banner; the real error is on Ghidra's stdout.
   - Repro: `scorecard/run1` against `run2`; `ghidra/repro2/ghidra.stdout:40`.
5. **A killed Ghidra leaves `PA.lock`, and one reopen hung for over 300 s.** Later opens recovered. Repro: `d2h1/outw/warm3.log`.
6. **Ubuntu gcc at `-O2` fortifies the sink and removes the bug.** `read(0, buf, 400)` into 72 bytes becomes `__read_chk(…, 72)`. A generator that does not pass `-U_FORTIFY_SOURCE` produces non-vulnerable "positives".
7. **`template` discards what it measures.** After running the target twice it still emits `offset = 0  # <-- FIND THIS` (`sp02b/t_z:41`).
8. **`offset` reads stale core files.** It globs `core*` in the cwd and in `/tmp` (`offset_finder.py:432-440`); the repo root holds 45 `core.*` files.
9. **PIE addresses differ by backend.** Ghidra reports auth-or-out `main` at `0x101971`, angr at `0x401971` (`run2` against `run1`). This confirms the image-base mismatch DEC-10 addresses.
10. **The original sick_rop crash did not reproduce.** I could not find its trigger. The gdb method succeeds first on every run from a copy.

## 6. Roadmap amendments

- **AMD-1 — §0, §1.6 "Today".** Replace the offset, decompile, ROBUST and TIME cells with §8. Evidence: `scorecard/run1`, `run2`.
- **AMD-2 — SP-01a.4 pre-flight.** A loader must be a regular, non-empty, executable file. Delete "all seven S0 loaders must resolve"; sabotage and bon-nie-appetit are VOID for execution cells until the loader helper exists. Move `run_with_loader` (CG-04) from SP-02c to SP-01a, since two executors already do this privately.
- **AMD-3 — SP-01a.1 isolation.** No scratch path may contain a dot-component. The sandbox mounts a private tmpfs on `/tmp`. Add a control cell: a known-good Ghidra decompile that must pass, or the run is invalid. Evidence: finding 4.
- **AMD-4 — SP-03 store.** Keep exported JSON in the cache; do not keep Ghidra projects there, and do not design around `-process -noanalysis` for small binaries. Add "stale lock after kill" to the cache tests. Evidence: HYP-2, finding 5.
- **AMD-5 — SP-04a sink table and SP-02c generator.** Add the `__*_chk` variants. The generator sets fortify explicitly per variant; a fortified build is a patched twin, not a positive. Evidence: finding 6.
- **AMD-6 — SP-01b angr.** Fix `normalize=True` in the same commit as the tagged union, and rewrite the happy-path test to assert real code. Evidence: finding 1.
- **AMD-7 — SP-01a, before the baseline.** Change the three test files to `sys.executable -m supwngo.cli`. Evidence: finding 3.
- **AMD-8 — §2 contract, SP-01b, SP-07.** Exit 2 collides with click's usage error. Either use a different code for negative results, or require every test to assert the JSON `error.code`. Evidence: §4.
- **AMD-9 — SP-02a RED proofs.** Every "must not produce X" proof first asserts exit 0 and a parsed document. Add the `secret`/`vuln_func` decoy fixture.
- **AMD-10 — SP-01b, PE.** Add `unsupported_format` (exit non-zero) for `pwn`, `template`, `offset` and `report` on PE now, not in SP-03. Move the PE default-function tests and a PE DECOMP baseline into SP-01. Correct B-7's stated reason. Evidence: findings 2 and the PE decompile in §2.
- **AMD-11 — DEC-9, SP-04.** The crash-driven finder is correct on plain overflows. Keep it as a first-class `--dynamic` confirmer, not a one-release legacy path. Fix the `core*` glob in SP-01b.
- **AMD-12 — SP-02b `rax_control`.** Do not move the executor's regex "verbatim" into the selector; it encodes one target's instruction shape and is the structural cheat §1.5 warns about. Specify the evidence semantically. The negative fixture must also make the return value uncontrollable, otherwise it may be a true positive. This is from reading, not execution.
- **AMD-13 — SP-01b.4.** Remove `got_plt.py:106, 259, 310` from the replacement list. The lint targets `Protections` receivers only.
- **AMD-14 — SP-01b.6.** The identifier lint needs a decision on docstrings and an explicit inventory; a one-line removal leaves 13 hits.
- **AMD-15 — HYP-14, M3.** Restate HYP-14 as statement coverage over the passcard. Record `--version` at 1.07 s against the 0.5 s target.
- **AMD-16 — SP-03A gates.** G3 is measured with fortify off and on. Add a gate line for the static axis: with no FunctionID, coverage is 0, so the FID probe result decides whether the static axis is in M1 at all.
- **AMD-17 — SP-04a tier-3 truth.** Break on the callsite address taken from the disassembly, never on a symbol.
- **AMD-18 — §11 Q10 and HYP-24.** Closed: bubblewrap works. Remove the owner question.

## 7. Updated sprint-map rows

| ID | Goal | Scope | Depends | Eff. | Exit criterion | Closes |
|---|---|---|---|---|---|---|
| SP-01 | **SP-01a:** isolated passcard v0, truth, mutants, baseline, loader helper, test-entry-point fix. **SP-01b:** the honesty fixes, now including PE refusal and the angr CFG fix. | a: as before, plus `run_with_loader`, the three `which("supwngo")` test files, a Ghidra control cell, no dot-paths, private `/tmp`. b: as before, plus `Binary.load` format check, `_angr_subprocess.py` (`normalize=True`), `core*` glob, PE default-function tests | — | M+ (a grows by about 2 days) | a: as before, plus the control cell passes in every run and the unit suite imports only the checkout. b: as before, plus `pwn`/`template`/`offset` on PE exit non-zero with `unsupported_format`; angr fallback returns real code on the tiny fixture; every negative-result test asserts `error.code` | as before, plus AMD-2, 3, 6, 7, 8, 10, 13, 14 |
| SP-02 | unchanged | b: `rax_control.py` specified semantically, not copied from the executor. c: generator sets fortify per variant; `run_with_loader` removed (now SP-01a) | SP-01 | L | as before, plus every "must not" RED asserts the option was accepted; the name-decoy fixture is never RET2WIN | as before, plus AMD-5, 9, 12 |
| SP-03A | unchanged | Directory-import batch runs; fortify on and off; static axis reported separately | SP-02c | S | The five gates, with G3 split by fortify and a static-axis coverage line | as before, plus AMD-16 |
| SP-03 | Facts v1: cached exported JSON, sandboxed; no persisted Ghidra project for small binaries | as before, minus `ghidra/` in the store | SP-03A | L | as before, minus "later single-function requests use `-process -noanalysis`"; plus a stale-lock test | as before, plus AMD-4 |
| SP-04 | unchanged | a: sink table gains `__*_chk`; `offset_finder.py` stays as the `--dynamic` confirmer permanently; `truth_bp.py` breaks on addresses | SP-03 | L | as before | as before, plus AMD-5, 11, 17 |

## 8. Measured baseline

**S0, from challenge-directory copies** (2026-11-12, load 13–22):

| Target | `pwn` top-1 | `template -t auto` | `offset` | `decompile` (default) |
|---|---|---|---|---|
| sick_rop | STACK_PIVOT (wrong) | `ret2system` (wrong) | **40, correct** | FAIL: error object, exit 0 |
| rocket_blaster_xxx | ROP_EXECVE (wrong) | `ret2system` (wrong) | **40, correct** | OK, Ghidra, 23 s |
| snow_scan | SROP (correct) | `ret2system` (wrong) | none (not a stack-return target) | OK, Ghidra, 104 s |
| ancient_interface | ROP_EXECVE (correct) | `ret2system` (plausible) | none (canary) | FAIL: angr sentinel as success |
| auth-or-out | ROP_EXECVE (wrong) | `ret2system` (wrong) | none (non-stack) | OK, Ghidra, 29 s |
| sabotage | ROP_EXECVE (wrong) | `ret2system` (wrong) | VOID, 0-byte loader | OK, Ghidra, 25 s |
| bon-nie-appetit | ROP_EXECVE (wrong) | `ret2system` (wrong) | VOID, 0-byte loader | OK, Ghidra, 24 s |

- **Method:** 2/7.
- **Template:** constant on 7/7.
- **Offset:** 2 correct of 3 valid stack-return cells; 0 crashes; 2 VOID reported as "could not determine".
- **Decompile:** 5/7. No PE baseline was taken; one mingw PE64 function decompiled correctly with `-f`.
- **ROBUST:** 28/28 cells emit one JSON document with no traceback, and 28/28 exit 0, including the two decompile failures and every failed offset.
- **TIME:** `pwn` 5–35 s, `template` 1–18 s, `offset` 1–33 s, `decompile` 23–104 s. Not a quiet host; no quorum.

**Unit suite:** 2229 passed, 2 failed, 18 skipped in 3156 s (load 12.9 at start, 43.2 at end; my own jobs added to it). Both failures are wall-budget timeouts and pass alone in 98 s.

**Ghidra:** 22 small binaries in one JVM in 143 s at load 8.8. A single small binary, cold: 25 s and 215 s at load 28–38. A minimal static ELF: 358 s at load 15.

## 9. Remaining unknowns

| Unknown | Cheapest next experiment |
|---|---|
| Does the depth-1 caller pass a P-code stack reference on the 8 callee fixtures? | Extend the exporter to record every call that passes a stack argument and rerun on `d2h1/projA`. I started this and it was cut off. |
| Does P-code answer on `-O2` ELF once `__read_chk` is a sink, and with fortify off? | Add the names, rebuild 4 fixtures with `-U_FORTIFY_SOURCE`, rerun the batch (about 2 min). |
| SROP gate: positive with a wrapper, negative without rax control | Build the two static stubs and run `analyze()`. Not built this session. |
| HYP-4 with `autopwn` | Run `autopwn --json` on the six `hyp/h4` fixtures and compare the winning technique. |
| Why the original scorecard crashed on sick_rop | Rerun `offset` from the repo root on a quiet host and under load, logging which finder method ran. |
| Does `solve` still score 7/7 at this tree? | `scripts/htb_rescore.py --reps 1` from copies (about 10 min). |
| Is Ghidra's 300 s project-open hang a lock race or load? | Ten warm opens on a quiet host, five of them right after a `kill -9`. |
| Does FunctionID name `read` in the static fixture? | The SP-03A FID probe against the host `libc.a`. |
| Passcard mutant table, SP-02c REDs, EOF-spin RED | Write them as scratch tests as in §4; none was attempted. |