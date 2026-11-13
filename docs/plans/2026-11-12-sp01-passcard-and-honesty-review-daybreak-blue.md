## Verdict — REJECT

- The passcard’s OFF contract is internally contradictory: `snow_scan` is both `VOID(no-truth)` and required to fail the constant-offset mutant, while a truth-echo cannot “PASS every non-VOID cell” under the proposed ABSTAIN rules.
- The offset design still hides uncertainty: timeouts become “no crash,” the helper omits several execution paths, relative paths break after changing `cwd`, and the preflight misses the corpus’s existing non-executable interpreters.
- The RELRO lint cannot become green as written: it deliberately catches correct pwntools/GOTAnalysis comparisons that the plan says to retain, while missing several real `Protections.relro` comparisons.
- The no-`-f` decompile change would crash at `hex(None)`, omits RetDec and model propagation, and lacks reliable ELF/PE entry-point resolution.
- Removing only `fill_ammo` will not satisfy the identifier lint; at least ten target-slug string constants remain in `supwngo/`.

Static review only; I did not execute any target binary.

## Blocking

### B-1: The scoring contract and self-test are inconsistent

Evidence:

- A null truth value is globally defined as VOID at [plan:49](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:49).
- A known non-stack target with no reported offset is ABSTAIN, while any reported number is FAIL at [plan:67](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:67).
- `snow_scan` is explicitly `{kind: indexed_base_ptr, value: null}` and VOID at [plan:89](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:89).
- Nevertheless, the constant `offset=0` mutant must fail OFF 7/7 and the truth-echo must PASS every non-VOID cell at [plan:96-100](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:96).

Under those rules, `snow_scan` is either VOID, making 7/7 impossible, or a known “no fixed offset” case, making line 92 wrong. Correctly declining a non-stack offset is ABSTAIN, so the truth-echo also cannot PASS every non-VOID cell.

Required change:

- Use a discriminated truth state such as `known_value`, `known_absent`, `unknown`, and `not_applicable`; do not overload `null`.
- Specify scoring for ERROR and VOID in the net score.
- Decide whether “correctly reports no fixed saved-RIP offset” is PASS, ABSTAIN, or VOID and make the self-test match.
- Add independent negative mutants for METHOD-L and TEMPLATE; the current self-test proves neither metric can fail.
- Exercise every verdict, malformed output, unmapped vocabulary, duplicate JSON, timeout, and contradictory rc/envelope combination.

### B-2: `_run_target` does not cover all execution paths and must be tri-state

The direct `OffsetFinder` executions are at [offset_finder.py:402-426](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:402), [offset_finder.py:502-520](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:502), and the uncaught refine loop at [offset_finder.py:541-556](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:541). But the file also executes targets through pwntools at:

- [offset_finder.py:649](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:649)
- [offset_finder.py:744](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:744)
- [offset_finder.py:797](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:797)
- [offset_finder.py:823](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:823)
- [offset_finder.py:1199](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:1199)

Thus one helper added only to `OffsetFinder` does not satisfy “every target execution.” The proposed signature also cannot naturally represent GDB/core analysis, file-input temporary files, and direct target execution.

More importantly, treating timeout as “no crash” is dishonest. Binary search then treats unknown evidence as false and can return a fabricated crash threshold at [offset_finder.py:565-569](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:565).

Required change:

- Introduce a low-level process runner plus a target-input adapter.
- Return structured states such as `CRASH`, `EXITED`, `TIMEOUT`, and `SPAWN_ERROR`; never collapse timeout/spawn error into `False`.
- Normalize `self.binary_path` to an absolute path before changing `cwd`; it is currently retained as supplied at [offset_finder.py:173](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:173). Otherwise `dir/prog` becomes `dir/dir/prog`.
- Cover stdin, argv, and file inputs explicitly.
- Use `Popen(start_new_session=True)`, group-kill, then `communicate()`/`wait()` to reap. Add a descendant-leak test.
- Either include `InteractiveOffsetFinder`/`QuickExploit` in the refactor or narrow the plan’s claim to the `supwngo offset` path.

The current core search is also unsafe: it scans the current directory and global `/tmp` for `core*` at [offset_finder.py:432-440](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:432), permitting stale or unrelated cores to supply an offset. Only analyze a core attributable to the just-run PID/invocation.

### B-3: `cwd` is right for GDB, but the PT_INTERP preflight is underspecified

Using the resolved binary’s parent as the GDB/inferior cwd is correct for this corpus: relative `PT_INTERP` and `RUNPATH=./glibc` depend on that cwd. It is not sufficient by itself.

The repository already documents relative interpreters that exist but are zero-byte and non-executable at [test_fmtstr_probe_unspawnable.py:17-29](/srv/share/dev/supwngo/tests/test_fmtstr_probe_unspawnable.py:17). Such a loader produces EACCES even when the binary itself is executable, as asserted at [test_fmtstr_probe_unspawnable.py:112-133](/srv/share/dev/supwngo/tests/test_fmtstr_probe_unspawnable.py:112). Copying the challenge directory preserves that defect.

Correct preflight behavior must be:

- No PT_INTERP: acceptable for static and static-PIE ELF.
- PIE/ET_DYN: no special path rule beyond its actual PT_INTERP.
- ELF32/ELF64: pyelftools supports both, but loader class/machine compatibility and host support still matter.
- Absolute interpreter: check the absolute host path.
- Relative interpreter: resolve against the exact execution cwd.
- Validate target and loader as regular, non-empty, executable files; existence alone is insufficient.
- Reject unsupported PE/non-native execution explicitly rather than treating “no PT_INTERP” as runnable.

Only execution-dependent cells should be VOID. `pwn`, `template`, and `decompile` should not all be discarded merely because bare target execution is impossible.

The ROBUST 7/7 exit criterion at [plan:175-179](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:175) must define how preflight VOID cells affect its denominator.

### B-4: The RELRO migration and lint are type-incorrect

The core display values are `"No RELRO"`, `"Partial RELRO"`, and `"Full RELRO"` at [binary.py:76-104](/srv/share/dev/supwngo/supwngo/core/binary.py:76). The lowercase comparisons in StrategySuggester are therefore real bugs at [strategy.py:449-456](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:449) and [strategy.py:964-979](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:964).

But not every `.relro` is that display field:

- `GOTAnalysis.relro` is an independent model populated from pwntools `ELF.relro` at [got_plt.py:31-39](/srv/share/dev/supwngo/supwngo/exploit/got_plt.py:31) and [got_plt.py:100-106](/srv/share/dev/supwngo/supwngo/exploit/got_plt.py:100). Its `"Full"` comparisons at [got_plt.py:256-261](/srv/share/dev/supwngo/supwngo/exploit/got_plt.py:256) and [got_plt.py:308-312](/srv/share/dev/supwngo/supwngo/exploit/got_plt.py:308) are correct.
- `ret2dlresolve` also compares pwntools `ELF.relro == "Full"` correctly at [ret2dlresolve.py:360-366](/srv/share/dev/supwngo/supwngo/exploit/rop/ret2dlresolve.py:360).
- `ProtectionFacts.relro` is a separate normalized fact object at [facts.py:93-111](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/facts.py:93).
- The CVSS helper accepts a generic string argument rather than a `Protections` object.

The proposed AST rule would flag the correct GOTAnalysis and pwntools comparisons, including the explicitly exempted ret2dlresolve site. It also misses comparisons through a local variable, `.lower()`, `startswith()`, and boolean expressions. The plan additionally omits current core-Protections consumers such as [rop_techniques.py:1513](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:1513), [heap_techniques.py:237](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:237), and [heap_strlen_ofb1_techniques.py:1009](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_strlen_ofb1_techniques.py:1009).

Required change:

- Limit the lint to receiver shapes proven to be core `Protections`, such as `.protections.relro`, with explicit typed allowlists for pwntools and GOTAnalysis.
- Or introduce a shared normalizer used by each model and lint against ad hoc normalization only within that model’s scope.
- Add tests covering all three display levels, `DetailedProtections`, pwntools values, and GOTAnalysis.
- Consider fixing `_relro_str` itself: it currently discards pwntools’ exact level and infers runtime RELRO from section writability at [binary.py:381-391](/srv/share/dev/supwngo/supwngo/core/binary.py:381), which is not generally equivalent to post-relocation page protection.

### B-5: The default-decompile change is incomplete and would crash

After removing the forced `"main"` at [cli.py:2070-2071](/srv/share/dev/supwngo/supwngo/cli.py:2070), the next line evaluates `hex(func_addr)` while it is `None` at [cli.py:2073](/srv/share/dev/supwngo/supwngo/cli.py:2073). The intended CLI test therefore will not reach `_decompile_ghidra`.

Further omissions:

- `DecompiledFunction` has no `selected_by` field at [decompile.py:100-111](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:100).
- The Ghidra parser drops unknown fields at [decompile.py:396-418](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:396).
- RetDec runs before angr at [decompile.py:233-244](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:233) and fabricates the name `"main"` when no function is supplied at [decompile.py:468-476](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:468).
- Ghidra currently has only main→first at [SupwngoDecompile.java:87-96](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:87), and its JSON contains no provenance at [SupwngoDecompile.java:119-123](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:119).

The installed Ghidra 12.1.3 `Program` API has no `currentProgram.getEntryPoint()` method. Its ELF/PE loaders create an `entry` symbol; blindly taking the first “external entry point” is also wrong because ELF globals/weak symbols and PE exports are external entry points too.

Required change:

- Render no-selector status as `default`, not `hex(None)`.
- Define and propagate `selected_by` through worker data, Ghidra JSON, `DecompiledFunction`, and CLI JSON.
- Resolve the loader-created header entry deterministically and test real no-main ELF, PE32, and PE32+ fixtures under the installed Ghidra.
- Add deterministic angr tests for main, exact `proj.entry`, and address-sorted first non-PLT/non-simprocedure.
- Either implement equivalent RetDec semantics or bypass/remove RetDec for the default-selection contract.

### B-6: Exit-code changes require existing test updates

The production changes are reasonable, but the plan’s regression claim is incomplete.

`retest_matrix.py` invokes `decompile` at [retest_matrix.py:53-70](/srv/share/dev/supwngo/scripts/retest_matrix.py:53), records rc but classifies only JSON contents at [retest_matrix.py:73-85](/srv/share/dev/supwngo/scripts/retest_matrix.py:73). It does not depend on rc 0. `htb_rescore.py` invokes only `solve` at [htb_rescore.py:98-115](/srv/share/dev/supwngo/scripts/htb_rescore.py:98), and `run_bench.py` invokes only `autopwn` at [run_bench.py:430-450](/srv/share/dev/supwngo/benchmark/run_bench.py:430).

However, existing tests explicitly require rc 0 for JSON failures at:

- [test_decompile_angr_budget.py:111-122](/srv/share/dev/supwngo/tests/test_decompile_angr_budget.py:111)
- [test_decompile_angr_budget.py:147-163](/srv/share/dev/supwngo/tests/test_decompile_angr_budget.py:147)

Those assertions must be changed to rc 2. The human-mode timeout assertion at line 134 can remain 0 because the plan changes only `--json`.

There are no other internal product callers of `Decompiler` beyond the CLI and `decompile_all`; the latter already accepts `None` at [decompile.py:596-616](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:596). Returning `None` for an angr sentinel restores the documented Optional contract at [decompile.py:219-244](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:219).

### B-7: The identifier lint will not pass after the intended fix

Removing `fill_ammo` at [offset_finder.py:881-889](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:881) is correct, but the proposed AST scan also includes docstrings. Existing string constants contain target slugs, including:

- [verifier.py:181-193](/srv/share/dev/supwngo/supwngo/exploit/pipeline/verifier.py:181)
- [env_path_techniques.py:1](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/env_path_techniques.py:1)
- [objptr_hijack_techniques.py:958](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/objptr_hijack_techniques.py:958)
- [heap_strlen_ofb1_techniques.py:1](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_strlen_ofb1_techniques.py:1)
- [heap_strlen.py:598](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap_strlen.py:598)

I found eleven current AST string-constant hits for the seven slugs plus `fill_ammo`; removing `fill_ammo` leaves ten.

A raw comment count is also gameable: replacing one forbidden comment with another preserves the count. Generic forbidden names such as `main`, `win`, `flag`, `success`, or `read` would create severe false positives.

Required change:

- Use an exact inventory of `(path, token, context-kind)` rather than a numeric ratchet, or move all target-specific rationale into tests/docs and require zero in product code.
- Restrict `forbidden_symbols` to target-specific identifiers such as `fill_ammo`, not generic exploitation vocabulary.
- Add a positive control proving a newly inserted slug/symbol is rejected, and a negative corpus of legitimate generic names.
- State whether docstrings are prohibited; AST treats them as string constants, not comments.

### B-8: The family taxonomy conflates vulnerability cause and exploitation method

Some mappings are reasonable: `ROP_SYSTEM → ret2libc` and `container_file_rop → rop_syscall` describe terminal execution. Others describe causes or enablers:

- `NEGATIVE_SIZE_BYPASS → integer` is a primitive and is generically proposed merely when `read`/`scanf` exists at [strategy.py:473-483](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:473).
- `HEAP_EXPLOIT → heap` is extremely broad and is not currently emitted anywhere in `StrategySuggester.analyze()`’s construction sequence at [strategy.py:223-276](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:223).
- The proven `auth-or-out` technique is `objptr_hijack`, not simply “heap,” as recorded at [full-rescore-FINAL-20260928.json:53-90](/srv/share/dev/supwngo/benchmark/results_htb/full-rescore-FINAL-20260928.json:53).
- The proven ancient route is `eintr_accumulator_rop` ending in `system("/bin/sh")`, so `ret2libc` is defensible, while its underflow is a separate primitive.

Required change:

- Separate at least `vuln_family`, `control_family`, and `terminal_family`, or make `methods_accept` explicitly terminal-only.
- Add `indirect_call_hijack`/`object_pointer_hijack` instead of flattening `objptr_hijack` to `heap`.
- Define whether duplicates after mapping count once in METHOD-L precision.
- Add mapping-coverage tests against every `ExploitApproach`, every template choice, and all registered solve technique IDs.

## Non-blocking

### N-1: The referenced roadmap file is absent

The plan cites `docs/roadmaps/2026-11-12-mythos-roadmap.md` at [plan:3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:3), but that path does not exist in the working tree. The available source is the untracked synthesis draft, whose SP-01 definition begins at [synthesis-draft-mythos.md:264](/srv/share/dev/supwngo/docs/reviews/2026-11-12-mythos-roadmap/synthesis-draft-mythos.md:264). Commit or correct the governing reference before implementation.

### N-2: Preserve both baselines

Updating `passcard-htb.json` in place leaves the pre-fix baseline available only through Git history. Prefer immutable `pre-sp01` and `post-sp01` artifacts or one report containing both runs, their Git SHAs, schema version, Python/tool versions, host architecture, and command line.

### N-3: ROBUST should validate exit/envelope consistency

Exactly one JSON document, no traceback, and no timeout is insufficient. `rc=127` plus a clean JSON object would currently pass ROBUST. Record and validate allowed rc/envelope pairs, while leaving the full cross-command `ok == (exit == 0)` contract to SP-07.

### N-4: The passcard is not an anti-gaming boundary

Truth lives in the same repository and subprocesses can read it. Anchor substring checks can be satisfied by comments, TEMPLATE can lie in its `"technique"` field, and OFF trusts a reported integer without RIP proof. That is acceptable only if SP-01 explicitly labels HTB-7 as smoke. Held-out custody, semantic template verification, and RIP proof belong in later sprints.

### N-5: Move unrelated cleanup

- HO-01’s dead `pie_base_offset()` really has no code callers; only its definition remains at [rop_techniques.py:128](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:128). Move it to the cleanup sprint or an independent hygiene commit.
- I-45 is valid: the three captured literals are at [corpus_uafread.yaml:395-397](/srv/share/dev/supwngo/benchmark/corpus_uafread/corpus_uafread.yaml:395), [corpus_offbyone.yaml:457-463](/srv/share/dev/supwngo/benchmark/corpus_offbyone/corpus_offbyone.yaml:457), and [corpus_libhijack.yaml:258-261](/srv/share/dev/supwngo/benchmark/corpus_libhijack/corpus_libhijack.yaml:258). Make that a standalone pre-baseline redaction commit.

### N-6: Copying a directory is isolation, not sandboxing

`copytree`, private TMPDIR, and process groups prevent test-tree writes and simplify cleanup, but do not constrain filesystem, network, or syscalls. Restrict SP-01 to trusted corpus artifacts and document this; bubblewrap/container execution can remain in SP-07.

## Claim checks

| # | Claim | Status | Evidence |
|---:|---|---|---|
| 1 | The cited Mythos roadmap exists at the stated path. | **WRONG** | [plan:3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:3); only the synthesis draft is present. |
| 2 | PyYAML is already a dependency. | **CONFIRMED** | [pyproject.toml:60](/srv/share/dev/supwngo/pyproject.toml:60). |
| 3 | `htb_rescore.py` copies the challenge directory and runs from the copy. | **CONFIRMED** | [htb_rescore.py:98-115](/srv/share/dev/supwngo/scripts/htb_rescore.py:98). |
| 4 | Copying plus `cwd=workspace` fixes all relative-interpreter targets. | **WRONG** | Some copied loaders are zero-byte/non-executable: [test_fmtstr_probe_unspawnable.py:17-29](/srv/share/dev/supwngo/tests/test_fmtstr_probe_unspawnable.py:17). |
| 5 | The refine loop has an uncaught `TimeoutExpired`. | **CONFIRMED** | [offset_finder.py:541-556](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:541). |
| 6 | The named helper coverage lists every target-execution path in `offset_finder.py`. | **WRONG** | Additional pwntools executions occur at [offset_finder.py:649](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:649), [744](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:744), [797](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:797), [823](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:823), and [1199](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:1199). |
| 7 | Current offset failure collapses to “Could not determine offset with any method.” | **CONFIRMED** | [offset_finder.py:231-234](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:231). |
| 8 | `OffsetResult` currently lacks `error_code` and `kind`. | **CONFIRMED** | [offset_finder.py:27-41](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:27). |
| 9 | `offset --json` currently exits 0 on negative results. | **CONFIRMED** | It emits JSON and returns normally at [cli.py:931-958](/srv/share/dev/supwngo/supwngo/cli.py:931). |
| 10 | JSON can remain unchanged except for `error_code`. | **WRONG** | OFF requires `kind`, but current serialization contains neither at [offset_finder.py:53-63](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:53). |
| 11 | angr returns failure comments as successful code. | **CONFIRMED** | [\_angr_subprocess.py:239-255](/srv/share/dev/supwngo/supwngo/analysis/_angr_subprocess.py:239). |
| 12 | The parent currently accepts that sentinel. | **CONFIRMED** | It checks only `found` and constructs a function at [decompile.py:510-520](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:510). |
| 13 | `decompile --json` currently emits an error object and exits 0. | **CONFIRMED** | [cli.py:2129-2136](/srv/share/dev/supwngo/supwngo/cli.py:2129). |
| 14 | No `-f` currently forces `main`. | **CONFIRMED** | [cli.py:2057-2071](/srv/share/dev/supwngo/supwngo/cli.py:2057). |
| 15 | Java currently selects main, then the first function. | **CONFIRMED** | [SupwngoDecompile.java:87-96](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:87). |
| 16 | Java currently emits `selected_by`. | **WRONG** | Output fields are only name/address/return_type/code at [SupwngoDecompile.java:119-123](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:119). |
| 17 | Core RELRO display strings disagree with StrategySuggester’s lowercase comparisons. | **CONFIRMED** | [binary.py:381-391](/srv/share/dev/supwngo/supwngo/core/binary.py:381), [strategy.py:454](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:454). |
| 18 | The proposed RELRO comparison-site list is complete. | **WRONG** | It omits multiple pipeline consumers, including [rop_techniques.py:1513](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:1513) and [heap_techniques.py:237](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:237). |
| 19 | `got_plt.py` sites are core `Protections.relro` comparisons. | **WRONG** | They use `GOTAnalysis.relro`, sourced from pwntools, at [got_plt.py:31-39](/srv/share/dev/supwngo/supwngo/exploit/got_plt.py:31) and [got_plt.py:100-106](/srv/share/dev/supwngo/supwngo/exploit/got_plt.py:100). |
| 20 | `ret2dlresolve.py:365` is a correct pwntools comparison. | **CONFIRMED** | [ret2dlresolve.py:360-366](/srv/share/dev/supwngo/supwngo/exploit/rop/ret2dlresolve.py:360). |
| 21 | The proposed AST lint permits the retained ret2dlresolve comparison. | **WRONG** | Its exact `.relro` versus string shape is what the proposed lint forbids. |
| 22 | There are roughly 15 current AST hits. | **CONFIRMED** | A direct AST inventory finds 16 comparison operands/nodes, including correct pwntools/GOTAnalysis sites. |
| 23 | `fill_ammo` is hard-coded at the cited location. | **CONFIRMED** | [offset_finder.py:881-889](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:881). |
| 24 | `pie_base_offset()` has zero code callers. | **CONFIRMED** | Only the definition remains at [rop_techniques.py:128](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:128); other hits are documentation. |
| 25 | The three captured-flag literals exist. | **CONFIRMED** | [corpus_uafread.yaml:395-397](/srv/share/dev/supwngo/benchmark/corpus_uafread/corpus_uafread.yaml:395), [corpus_offbyone.yaml:457-463](/srv/share/dev/supwngo/benchmark/corpus_offbyone/corpus_offbyone.yaml:457), [corpus_libhijack.yaml:258-261](/srv/share/dev/supwngo/benchmark/corpus_libhijack/corpus_libhijack.yaml:258). |
| 26 | The recorded pre-fix score is METHOD-R0 2/7, DECOMP 3/7, OFF 0/7. | **CONFIRMED** as recorded evidence | [SCORECARD.md:9-18](/srv/share/dev/supwngo/docs/reviews/2026-11-12-mythos-roadmap/inputs/SCORECARD.md:9). |
| 27 | The exact future truth YAML, family mappings, default-function sets, and decompile anchors are correct. | **UNVERIFIABLE** | Those files do not yet exist; several labels are judgement calls and the taxonomy is currently inconsistent. |

## RED-test validity

| RED proof | Fails current tree? | Passes only with intended fix? | Assessment |
|---|---|---|---|
| Constant shim: METHOD-R0 fails ≥5/7 | **Yes**, logically | Mostly | `ROP_SYSTEM→ret2libc` matches rocket and ancient, so exactly five failures is plausible. Pin exact expected targets. |
| Constant shim: OFF fails 7/7 | **No under the written rules** | No | `snow_scan` is declared VOID. Resolve B-1 first. |
| Truth-echo passes every non-VOID cell | **No under the written rules** | No | Correct non-stack absence scores ABSTAIN, not PASS. |
| “Parses as JSON” cannot distinguish shims | **Yes** | Yes, but narrow | `retest_matrix.classify()` considers any non-error JSON OK at [retest_matrix.py:73-85](/srv/share/dev/supwngo/scripts/retest_matrix.py:73). This tests the scorer, not the subprocess harness. |
| Refine raises `TimeoutExpired` | **Yes**, with careful sequencing | Yes | Call `_find_with_binary_search` directly or control `_check_gdb`/coredump calls. Post-fix assertion must reject fabricated evidence, not merely avoid raising. |
| Missing relative PT_INTERP returns `target_not_executable` | **Yes** | Only if asserted strictly | Assert exact code, interpreter path, and that merely adding a default `error_code` field cannot satisfy the test. |
| Relative interpreter works from another cwd | **Yes** | Yes with a positive control | Resolve the binary path first; otherwise the cwd fix creates a doubled relative path. Assert the copied loader is executable and the target actually reaches the crash path. |
| Offset JSON failure exits 2 | **Yes** | Yes | Prefer a monkeypatched finder for the rc contract plus a separate real EOF/hang fixture for process handling. |
| angr `codegen=None` returns `ok:false` | **Yes** | Yes | Parameterize missing codegen and thrown exception; assert `code is None`, error recorded, and parent returns `None`. |
| Decompiler returns `None` → CLI rc 2 | **Yes** | Yes after test updates | Update existing JSON-failure assertions at test lines 118 and 160. |
| Full-RELRO fixture omits RET2DLRESOLVE | **Yes** | Yes | Assert the fixture is dynamic and is actually detected as Full RELRO before checking the strategy, preventing a vacuous pass. |
| RELRO AST scan | **Yes** | **No** | The intended implementation leaves the pwntools ret2dlresolve comparison and should leave GOTAnalysis comparisons, so the stated lint remains red. |
| No-`-f` selector becomes empty | **Yes** | **No as planned** | The current tree forces main, but removing it causes `hex(None)` at CLI line 2073. Fix that first. |
| Ghidra no-main fixture selects entry | **Yes**, if the tool test runs | Not yet | Must validate Java compilation and entry resolution on ELF and PE; a skipped optional Ghidra test is not a release gate. |
| Identifier AST scan | **Yes** | **No** | Removing `fill_ammo` leaves at least ten slug-bearing string constants. Replace the count ratchet with a precise inventory or zero policy. |