# Round 5 delta review — v4.2

Scope was limited to §8 and the two inline edits. Review was read-only; no tests were run.

## Findings

### N5-1 — HIGH — Stripped MinGW default selection returns the CRT startup, not user `main`

**Plan line:** [plan:780](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:780)

The proposed PE order `main → entry → first_reachable` is not sound for the stripped fixture. `AddressOfEntryPoint` identifies `mainCRTStartup`/`WinMainCRTStartup`, not the source-level `main`. Once Ghidra has a function at that entry—which it normally will—the `entry` step succeeds and `first_reachable` is unreachable. Returning that function is valid CRT pseudo-C but silently the wrong semantic default.

`selected_by="entry"` makes the mechanism observable, but the command still returns a success envelope. Unless truth deliberately accepts the CRT startup, this can be scored as a false success.

**Evidence:**

- The existing Java fallback selects `main`, otherwise the first defined function: [SupwngoDecompile.java:87](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:87).
- It then decompiles and emits whichever function was selected: [SupwngoDecompile.java:109](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:109).
- VERIFY established only explicit `-f vuln` PE decompilation, not PE default selection: [verify-mythos-execution.md:67](/srv/share/dev/supwngo/docs/reviews/2026-11-12-mythos-roadmap/verify-mythos-execution.md:67).

**Concrete fix:** Add a proved MinGW-specific recovery step before `entry`, for example `main → mingw_crt_main_arg → entry`, with its own `selected_by`. The stripped fixture must assert the planted user-function address and code anchor, not merely non-empty code. If user-main recovery cannot be proved, either decline or explicitly return the CRT entry without counting it as a user-main DECOMP pass. Remove `first_reachable` or define a non-vacuous role for it; generic BFS through CRT initialization is not a sound main detector.

---

### N5-2 — HIGH — V-10’s arithmetic is conditionally correct, but `backend_base` and PE `RVA` are undefined

**Plan line:** [plan:786](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:786)

The ELF formula is correct only if `backend_base` means the actual base used for that analyzed image:

- PIE/Ghidra: `0x101971 − 0x100000 + 0 = 0x1971`.
- PIE/angr: `0x401971 − 0x400000 + 0 = 0x1971`.
- ET_EXEC where Ghidra image base and minimum `PT_LOAD.p_vaddr` are both `0x400000`: the subtraction and addition cancel, correctly preserving `0x401971`.

But neither backend currently reports its base. An implementation using the observed constants `0x100000` and `0x400000` would corrupt ET_EXEC addresses. The PE expression also does not define how `RVA` is derived; adding `ImageBase` to an already absolute Ghidra address would double-base it.

**Evidence:**

- Ghidra emits only raw `f.getEntryPoint().getOffset()`: [SupwngoDecompile.java:119](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:119).
- angr emits only raw `func.addr`: [_angr_subprocess.py:248](/srv/share/dev/supwngo/supwngo/analysis/_angr_subprocess.py:248).
- angr creates its project with default loader rebasing: [_angr_subprocess.py:72](/srv/share/dev/supwngo/supwngo/analysis/_angr_subprocess.py:72).
- `DecompiledFunction` carries no backend-base metadata: [decompile.py:100](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:100).
- ELF `PT_LOAD` virtual addresses are available from parsed segments: [binary.py:303](/srv/share/dev/supwngo/supwngo/core/binary.py:303).

**Concrete fix:** Define and transport:

- Ghidra `backend_base = currentProgram.getImageBase().getOffset()`.
- angr `backend_base = proj.loader.main_object.mapped_base`.
- ELF file base as `min(PT_LOAD.p_vaddr)`—or preferably the loader’s validated linked base.
- PE `RVA = backend_addr − backend_base`, then `normalized = file_ImageBase + RVA`.

Apply the inverse mapping to explicit `-f 0x...` selectors as well. Add independent-oracle tests for PIE, ET_EXEC, PE32+, and preferably PE32; cross-backend equality alone can pass when both outputs are equally wrong.

---

### N5-3 — MEDIUM — V-8 does not pin command-specific refusal documents

**Plan line:** [plan:773](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:773)

The plan says all three commands return `error_code="unsupported_format"`, while the accepted envelope contract requires:

- `offset`: `success:false` plus non-empty `error_code`.
- `pwn`/`template`: non-empty top-level `error`.

V-13 likewise says tests inspect `error_code` for offset and `error` for the other commands. The fields are compatible if `pwn` and `template` contain both, but that requirement is not stated. None of these product branches exists today.

**Evidence:**

- Command-specific envelopes: [plan:320](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:320).
- V-13’s split assertion: [plan:798](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:798).
- Current `OffsetResult.to_dict()` has no `error_code`: [offset_finder.py:53](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:53).
- Current `pwn` emits only its success report: [cli.py:872](/srv/share/dev/supwngo/supwngo/cli.py:872).
- Current `template` emits only its success document: [cli.py:1251](/srv/share/dev/supwngo/supwngo/cli.py:1251).

**Concrete fix:** Specify the exact JSON:

- `offset`: ordinary `OffsetResult` failure with `success:false`, non-empty `error`, `error_code:"unsupported_format"`, and exit 2.
- `pwn`/`template`: `{"error":"Unsupported binary format","error_code":"unsupported_format"}` and exit 2.

Perform detection before `Binary.load` and before template output creation. Also pin human-mode behavior: readable diagnostic plus exit 2, without JSON unless `--json` was requested.

---

### N5-4 — MEDIUM — “By magic bytes” is insufficiently strict for PE

**Plan line:** [plan:772](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:772)

Treating `MZ` alone as PE is unsafe. A DOS executable, malformed file, or truncated `MZ` input may have no valid PE header. This does not change the three refusal commands—they reject both PE and unknown—but it matters to V-9, which would otherwise parse `AddressOfEntryPoint` from invalid offsets.

**Evidence:**

- `Binary.load` currently swallows both pwntools and pyelftools parse failures: [binary.py:240](/srv/share/dev/supwngo/supwngo/core/binary.py:240), [binary.py:346](/srv/share/dev/supwngo/supwngo/core/binary.py:346).
- `decompile` proceeds after that silent degradation: [cli.py:2051](/srv/share/dev/supwngo/supwngo/cli.py:2051).

**Concrete fix:** Define PE detection as:

1. `MZ`;
2. readable, in-bounds `e_lfanew`;
3. `PE\0\0` at that offset;
4. complete COFF and optional headers;
5. optional-header magic `0x10b` or `0x20b`.

Everything else is `unknown`. Add malformed/truncated `MZ`, out-of-range `e_lfanew`, missing PE signature, PE32, and PE32+ tests.

---

### N5-5 — MEDIUM — V-11’s test can be masked by a successful fallback

**Plan line:** [plan:790](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:790)

The current Ghidra runner discards stdout, and `decompile()` subsequently attempts RetDec and angr. After V-7, angr may successfully decompile the dot-path fixture; in that case there is no failure envelope in which to assert the Ghidra error.

**Evidence:**

- Ghidra stdout is assigned to `_out` and discarded: [decompile.py:291](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:291).
- Only a bounded stderr tail is logged: [decompile.py:302](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:302).
- Failure falls through to RetDec and angr: [decompile.py:233](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:233).
- The CLI currently emits only the generic error: [cli.py:2129](/srv/share/dev/supwngo/supwngo/cli.py:2129).

**Concrete fix:** Replace the Boolean runner result with a structured result carrying state, stdout, stderr, and the first bounded `ERROR` line. Preserve that diagnostic through fallback attempts and include it only if the overall operation fails. The dot-path test must force RetDec unavailable and angr to a tagged failure—or test the Ghidra seam directly—so a successful fallback cannot make it vacuous.

---

### N5-6 — MEDIUM — The Ghidra control fixture is committed, but its oracle is unspecified

**Plan line:** [plan:733](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:733)

V-2 does answer “committed or built”: it says a committed ELF. It does not identify the fixture path, function selector, address, required backend, or code anchor. “PASS” is therefore not reproducible, despite controlling whether an entire run is accepted.

**Evidence:**

- Normal DECOMP scoring requires an accepted address, meaningful code, and anchors: [plan:339](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:339).
- Name selection is exact and returns `null` when not found: [SupwngoDecompile.java:78](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:78).
- The CLI resolves `-f` against `Binary.symbols`: [cli.py:2060](/srv/share/dev/supwngo/supwngo/cli.py:2060).

**Concrete fix:** Pin, for example:

- committed binary and source paths;
- SHA-256 of the committed ELF;
- exact `-f ghidra_control` selector;
- normalized expected address;
- `analysis_backend=="ghidra"`;
- non-sentinel code containing a planted call such as `puts`;
- rc 0 and one JSON document.

State explicitly that the control is an acceptance precondition and is excluded from semantic and ROBUST denominators.

---

### N5-7 — MEDIUM — RLIMIT_CORE=0 will break an existing core-consuming test unless it is named and updated

**Plan line:** [plan:749](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:749)

The grep claim that no test exercises `_find_with_coredump` is true, but one existing test directly uses pwntools’ `p.corefile`. It will inherit the session’s zero soft limit and fail before reaching its current assertion.

**Evidence:**

- The test launches a crashing target and reads `p.corefile.fault_addr`: [test_solve_command.py:277](/srv/share/dev/supwngo/tests/test_solve_command.py:277).
- Its wrapper subprocess currently has no `preexec_fn`: [test_solve_command.py:285](/srv/share/dev/supwngo/tests/test_solve_command.py:285).
- Root `conftest.py` already establishes process-wide settings at import: [conftest.py:63](/srv/share/dev/supwngo/conftest.py:63).

**Concrete fix:** Name `test_guided_fallback_resumes_to_success_with_supplied_offset` in V-4 and require its wrapper subprocess to raise its soft core limit in `preexec_fn`, run with `cwd=tmp_path`, and remove the resulting core afterward. Add a focused test proving the suite process remains at soft limit zero while the opted-in child receives a non-zero limit.

---

### N5-8 — MEDIUM — The PE rows leave passcard schema and denominators inconsistent

**Plan line:** [plan:817](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:817)

Two PE fixtures contributing DECOMP and ROBUST add two DECOMP cells and two ROBUST cells. Earlier text still fixes the instrument at seven targets, 28 ROBUST cells, and 14 offset/decompile cells. The truth schema also has no explicit per-file metric allowlist explaining why method/template/OFF do not run for these PE files.

**Evidence:**

- Existing counts are 28 ROBUST and seven cells for other metrics: [plan:357](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:357).
- SP-01b still requires only 14 offset/decompile ROBUST cells: [plan:673](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:673).
- The truth schema currently assumes the general method/distance/decompile/stage shape: [plan:34](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:34).

**Concrete fix:** Add an explicit `metrics: [decomp, robust]` or a dedicated PE-DECOMP schema. State whether the mutant self-test remains the original seven-ELF matrix. Update post-fix totals to nine DECOMP cells, seven offset cells, 16 combined offset/decompile cells, and 30 total ROBUST cells unless the PE rows are intentionally reported outside the main passcard denominator.

---

### N5-9 — LOW — V-8 contradicts the unchanged scope statement

**Plan line:** [plan:773](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:773)

The scope still says `pwn` and `template` are measured but not changed. V-8 changes both commands. The only inline supersession marker was added to §4.4, and V-8 says it corrects §4.4 rather than §1.

**Evidence:**

- Unchanged scope statement: [plan:24](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:24).
- §8 says amendments override the sections they name: [plan:722](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:722).

**Concrete fix:** Amend §1 to say that `pwn` and `template` are otherwise unchanged except for V-8’s non-ELF refusal, or add an explicit §8 supersession marker there.

## Confirmed delta claims

- V-1’s three inline cell paths are correctly changed to non-dot components.
- V-3’s three `which("supwngo")` file/line references are exact.
- V-7 targets the correct decompile-specific `CFGFast()` call at [_angr_subprocess.py:226](/srv/share/dev/supwngo/supwngo/analysis/_angr_subprocess.py:226); the separate CFG operation already uses `normalize=True`.
- V-8 correctly identifies why PE reaches false-success paths: `Binary.load` catches parser failures and returns a degraded object.
- V-4’s claim specifically about `_find_with_coredump` coverage is correct, but N5-7 identifies the separate core consumer.

VERDICT: APPROVE WITH CHANGES