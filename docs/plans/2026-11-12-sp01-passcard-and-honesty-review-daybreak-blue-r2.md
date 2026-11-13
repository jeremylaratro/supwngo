## Verdict — REJECT

- v2 substantially improves the runner, preflight, decompile, taxonomy, identifier-lint, and baseline designs; B-2, B-3, B-5–B-8 are effectively addressed.
- The mutant oracle is still inconsistent: `list_all` uses the wrong precision denominator, `abstain_all` contradicts ROBUST, and several roadmap mutants are missing.
- OFF scoring remains underspecified for a target such as `ancient_interface` with two `known_value` distances but one target-level verdict.
- The isolation deviations are not sound as written: `copy` makes the answer-key mutant non-failing, and keeping the sandbox under `benchmark/` leaves SP-01b’s product offset executions unsandboxed.
- The RELRO inventory is close but incomplete; the proposed lint also misses an existing alias/wrapper shape.

## Prior-item disposition table

| Prior item | Disposition | Evidence |
|---|---|---|
| B-1 scoring contract | **PARTIAL** | Four truth states and score arithmetic are now defined in [plan §2.1](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:43) and [§3.6](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:209). However, §3.7’s METHOD-L precision is wrong, `abstain_all` conflicts with ROBUST, and multiple distance facts are not aggregated. Current output has one primary `offset`/future `kind`, plus a separate `canary_offset`: [offset_finder.py](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:27). |
| B-2 runner coverage and tri-state | **RESOLVED** | [Plan §4.1](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:277) adds four process states, absolute paths, all three input adapters, tri-state search, process-group cleanup and core attribution. The cited current direct paths are real: [core runner](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:402), [bisect](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:502), [refine](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:541). |
| B-3 preflight | **RESOLVED** | The six rules and execution-only VOID behavior are explicit in [plan §3.5](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:192), and ROBUST keeps all seven targets in its denominator at [§5](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:524). The existing zero-byte-loader premise is documented at [test_fmtstr_probe_unspawnable.py](/srv/share/dev/supwngo/tests/test_fmtstr_probe_unspawnable.py:17). |
| B-4 RELRO migration | **PARTIAL** | The typed normalizer and source correction in [plan §4.3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:358) fix the original type contradiction. The inventory misses the core-`Protections` alias comparison at [heap_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:251), and the specified AST rule does not catch its local alias—or the `str(getattr(...) or "").lower()` wrapper used at [line 237](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:237). |
| B-5 default decompile | **RESOLVED** | [Plan §4.4](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:419) fixes `hex(None)`, adds `selected_by`, bypasses RetDec for the empty selector, defines deterministic Ghidra/angr order, and adds mandatory tool-tier tests. The current omissions are accurately located at [cli.py](/srv/share/dev/supwngo/supwngo/cli.py:2070), [decompile.py model](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:100), [parser](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:396), and [Java selector](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:87). |
| B-6 existing rc tests | **RESOLVED** | The two required edits are named in [plan §4.2](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:343). Current rc-0 assertions are exactly at [test line 118](/srv/share/dev/supwngo/tests/test_decompile_angr_budget.py:118) and [line 160](/srv/share/dev/supwngo/tests/test_decompile_angr_budget.py:160). |
| B-7 identifier lint | **RESOLVED** | v2 distinguishes code strings from inventoried comments/docstrings and adopts a zero policy in [plan §4.5](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:483). Static AST inspection confirmed exactly two non-docstring string hits: [offset_finder.py](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:887) and [heap_strlen.py](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap_strlen.py:598). The separate “36 lines/12 files” count is wrong, but does not invalidate the design. |
| B-8 taxonomy | **RESOLVED** | [Plan §2.2](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:57) separates method and vulnerability axes, preserves `objptr_hijack`, defines deduplication, and inventories all three vocabularies. The current enum really has 15 entries at [strategy.py](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:34), and registry names are available through [registry.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/registry.py:31). |
| N-1 roadmap path | **NOT RESOLVED** | [Plan line 3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:3) still cites `docs/roadmaps/...`, which is absent. The supplied governing file is [roadmap-final-mythos.md](/srv/share/dev/supwngo/docs/reviews/2026-11-12-mythos-roadmap/roadmap-final-mythos.md:315). |
| N-2 preserve baselines | **RESOLVED** | Immutable pre/post artifacts and provenance are specified at [plan §3.2](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:152), [§3.8](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:263), and [§5](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:538). |
| N-3 rc/envelope consistency | **PARTIAL** | Allowed pairs and contradiction mutants now exist at [plan §3.6](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:227) and [§3.7](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:253). But “document with `error` or `error_code`” must mean a nonempty, command-specific failure envelope: `OffsetResult.to_dict()` always contains `error`, including success responses, at [offset_finder.py](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:53). |
| N-4 smoke/anti-gaming limits | **RESOLVED** | S0 is explicitly smoke at [plan §1](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:20), and v0 limitations are listed at [§3.6](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:230). |
| N-5 unrelated hygiene | **RESOLVED** | I-45 is a standalone first commit at [plan §3.1](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:123); HO-01 is a standalone SP-01b commit at [§4.6](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:508). `pie_base_offset()` still has only its definition at [rop_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:128). |
| N-6 copying is not sandboxing | **PARTIAL** | v2 honestly labels the copy backend and `answer_key_exposed` at [plan §3.3](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:155). It nevertheless lets that run satisfy the baseline and answer-key mutant exits, so it remains isolation rather than a sandbox and conflicts with the roadmap’s baseline rule at [roadmap §6](/srv/share/dev/supwngo/docs/reviews/2026-11-12-mythos-roadmap/roadmap-final-mythos.md:376). |

## Claim checks table

| Claim | Status | Evidence |
|---|---|---|
| The cited canonical roadmap exists at `docs/roadmaps/...`. | **WRONG** | That path is absent; the available roadmap is [roadmap-final-mythos.md](/srv/share/dev/supwngo/docs/reviews/2026-11-12-mythos-roadmap/roadmap-final-mythos.md:315). |
| `template` defaults output into its cwd. | **CONFIRMED** | [cli.py:1245](/srv/share/dev/supwngo/supwngo/cli.py:1245). |
| `bwrap` and Ghidra 12.1.3 are installed; RetDec is not installed in the searched locations. | **CONFIRMED** | `/usr/bin/bwrap` and `/opt/ghidra/support/analyzeHeadless` exist and are executable; Ghidra’s `application.properties` reports 12.1.3. No configured/common RetDec binary exists. |
| `OffsetFinder` retains a relative path and has the cited direct execution sites. | **CONFIRMED** | Path at [offset_finder.py:173](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:173); target executions at [404](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:404), [506](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:506), and [545](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:545); GDB at [280](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:280). |
| `InteractiveOffsetFinder`/`QuickExploit` have no callers outside `offset_finder.py`. | **CONFIRMED** | Repository-wide Python search found only definitions/internal calls; the external CLI uses `OffsetFinder` at [cli.py:929](/srv/share/dev/supwngo/supwngo/cli.py:929). |
| Current bisect collapses timeout to no-crash and can return the threshold; core search includes cwd and global `/tmp`. | **CONFIRMED** | [offset_finder.py:502](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:502), [565](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:565), and [432](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:432). |
| `OffsetResult` lacks `kind`/`error_code`; offset JSON failure exits 0. | **CONFIRMED** | [offset_finder.py:27](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:27), [serialization](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:53), and [cli.py:934](/srv/share/dev/supwngo/supwngo/cli.py:934). |
| The angr worker emits sentinels as successful code, the parent accepts them, and decompile JSON failure exits 0. | **CONFIRMED** | [\_angr_subprocess.py:239](/srv/share/dev/supwngo/supwngo/analysis/_angr_subprocess.py:239), [decompile.py:510](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:510), [cli.py:2129](/srv/share/dev/supwngo/supwngo/cli.py:2129). |
| Only the two named tests depend on decompile JSON rc 0; internal scripts do not. | **CONFIRMED** | Assertions at [test line 118](/srv/share/dev/supwngo/tests/test_decompile_angr_budget.py:118) and [160](/srv/share/dev/supwngo/tests/test_decompile_angr_budget.py:160); `retest_matrix` classifies JSON at [line 73](/srv/share/dev/supwngo/scripts/retest_matrix.py:73), while [htb_rescore.py](/srv/share/dev/supwngo/scripts/htb_rescore.py:98) runs `solve` and [run_bench.py](/srv/share/dev/supwngo/benchmark/run_bench.py:430) runs `autopwn`. |
| `_relro_str` discards pwntools’ exact level and infers it from `.got.plt` writability. | **CONFIRMED** | Exact pwntools value enters at [binary.py:368](/srv/share/dev/supwngo/supwngo/core/binary.py:368); it is treated as truthy and re-derived at [381](/srv/share/dev/supwngo/supwngo/core/binary.py:381). |
| The listed broken core-`Protections` comparisons are correctly classified. | **CONFIRMED** | Examples: [strategy.py](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:454), [imports.py](/srv/share/dev/supwngo/supwngo/analysis/imports.py:398), [leak_finder.py](/srv/share/dev/supwngo/supwngo/vulns/leak_finder.py:329), [chainer.py](/srv/share/dev/supwngo/supwngo/exploit/chainer.py:294). |
| The RELRO consumer inventory is complete. | **WRONG** | It omits the core-`Protections` alias at [heap_techniques.py:251](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:251), compared at line 252. The lint’s stated alias limitation therefore has more than the one `imports.py` occurrence claimed. |
| GOTAnalysis, pwntools, ProtectionFacts, DetailedProtections and CVSS receiver classifications are correct. | **CONFIRMED** | [GOTAnalysis](/srv/share/dev/supwngo/supwngo/exploit/got_plt.py:31), [pwntools ret2dlresolve](/srv/share/dev/supwngo/supwngo/exploit/rop/ret2dlresolve.py:360), [ProtectionFacts](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/facts.py:93), [DetailedProtections](/srv/share/dev/supwngo/supwngo/analysis/protections.py:37), [CVSS string API](/srv/share/dev/supwngo/supwngo/reporting/cvss.py:414). |
| Current no-`-f` decompile, RetDec fallback and `selected_by` omissions are described accurately. | **CONFIRMED** | [cli.py:2057](/srv/share/dev/supwngo/supwngo/cli.py:2057), [RetDec fabrication](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:468), [model](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:100), [parser](/srv/share/dev/supwngo/supwngo/analysis/decompile.py:396), [Java output](/srv/share/dev/supwngo/supwngo/analysis/ghidra_scripts/SupwngoDecompile.java:119). |
| Ghidra 12.1.3 `Program` lacks `getEntryPoint()`, and `imageBase + (e_entry − min PT_LOAD.vaddr)` matches its standard ELF entry mapping for PIE and non-PIE. | **CONFIRMED** | Installed `Program.java` exposes `getImageBase()` but no `getEntryPoint()`. Ghidra’s installed sources compute the ELF base as the minimum `PT_LOAD`, use `0x100000` for ordinary 64-bit ET_DYN, and create entry at `e_entry + programImageBase − elfImageBase`. Caveat: prelinked ELF uses its prelink base and should be excluded or handled explicitly. |
| Ghidra will expose the `__libc_start_main` argument as a constant P-code input on `nomain_dyn`. | **UNVERIFIABLE** | The approach is plausible, but this is toolchain/analyzer behavior. The mandatory real-Ghidra fixture in [plan §4.4](/srv/share/dev/supwngo/docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md:470) is the appropriate proof. |
| `Binary.load` is currently unsuitable for PE default-selection tests. | **CONFIRMED** | It runs pwntools ELF and pyelftools ELF loaders only at [binary.py:175](/srv/share/dev/supwngo/supwngo/core/binary.py:175); CLI calls it before decompilation at [cli.py:2051](/srv/share/dev/supwngo/supwngo/cli.py:2051). |
| There are only two non-docstring forbidden string hits. | **CONFIRMED** | [offset_finder.py:887](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:887) and the string spanning [heap_strlen.py:598](/srv/share/dev/supwngo/supwngo/exploit/walkthrough/families/heap_strlen.py:598), with the slug on line 606. |
| Comments/docstrings contain “36 lines in 12 files.” | **WRONG** | Raw `rg` gives 36 lines/12 files only because it includes the two code-string hits. AST plus tokenization finds 34 documentation lines in 11 files, containing 37 `(line, token)` occurrences. |
| `pie_base_offset()` has zero callers. | **CONFIRMED** | Only its definition exists at [rop_techniques.py:128](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:128). |
| The three I-45 captured literals exist at the cited locations. | **CONFIRMED** | [uafread](/srv/share/dev/supwngo/benchmark/corpus_uafread/corpus_uafread.yaml:395), [offbyone](/srv/share/dev/supwngo/benchmark/corpus_offbyone/corpus_offbyone.yaml:457), [libhijack](/srv/share/dev/supwngo/benchmark/corpus_libhijack/corpus_libhijack.yaml:258). |
| `ancient_interface` has `buf_to_ret=4120` and `buf_to_canary=4104`. | **CONFIRMED** | Static disassembly shows the function at `0x40189b`, buffer at `rbp-0x1010`, canary at `rbp-8`, and loop at `0x401a00–0x401a36`; the source buffer is at [ancient_interface.c:214](/srv/share/dev/supwngo/tests/htb-targets/a12c7393-371d-449e-b43d-b1e55dd9d35f/challenge/ancient_interface.c:214). The separate “Ghidra P-code agrees” claim is **UNVERIFIABLE** without the tool run. |
| Expected unit baseline is about 2230/18. | **UNVERIFIABLE** | Static inspection cannot establish the current collected/executed suite count. |

## Mutant arithmetic

| Expectation | Assessment |
|---|---|
| `const` METHOD-R0 and TEMPLATE fail exactly five | **Consistent.** `ret2libc` is accepted only by rocket and ancient; the other five fail. |
| `const` OFF: three FAIL, four VOID | **Consistent at target level.** Known-value targets are sick, rocket and ancient; unknown targets are snow, auth, sabotage and bon. Sabotage and bon also have unusable shipped loaders, but they were already VOID from missing truth. |
| `truth_echo` OFF VOID set | **Consistent as a target set:** snow, auth, sabotage and bon. The VOID reason for sabotage/bon should be pinned as preflight rather than `no-truth` if preflight takes precedence. |
| `list_all` precision `≤ 1/14` | **Wrong.** There are 15 method families. With all 15 reported, per-target precision is `1/15` or `2/15`; macro/micro target-family precision is `10/105 = 2/21`, not `≤1/14`. If precision considers only the top three, the result depends on unspecified confidence/priority ordering. `METHOD-SPAM=15` is correct. |
| `list_none` METHOD-L FAIL 7/7 | **Consistent.** |
| `unmapped` and `vuln_axis` METHOD-R0 FAIL 7/7 | **Consistent** with §2.2/§3.6. |
| `abstain_all`: “no PASS anywhere” | **Wrong as written.** A well-formed rc-2 decline should make ROBUST PASS. METHOD-L and DECOMP have no ABSTAIN verdict in §3.6. Scope this statement to the semantic metrics that support abstention. |
| Sentinel/comment-anchor/wrong-address mutants | **Consistent.** |
| rc/envelope and timeout mutants | **Consistent**, provided failure envelopes are defined semantically rather than by mere presence of the always-present `error` key. |
| Coverage of the roadmap mutant table | **Incomplete.** v2 omits the empty-body DECOMP mutant, TIME zero-valid-samples/quorum mutant, and the `.debug` sibling and generator-source arms of the answer-key mutant. The copy-backend version does not catch the answer-key mutant at all. |

OFF also needs one explicit aggregation rule for `ancient_interface`: either score `(target, kind)` cells separately, or define a target PASS as all scored distance facts matching and specify how `offset`, `kind`, and `canary_offset` encode those facts.

## Deviations

### Copy-backend S0 baseline

Not sound as an accepted SP-01a baseline. It is acceptable as a labelled diagnostic artifact, but it cannot satisfy “100% mutants caught”: the answer-key mutant succeeds and the test merely confirms `answer_key_exposed: true`. That weakens a RED proof rather than recording a measurement limitation.

Either require `bwrap`/dedicated-uid isolation before accepting the baseline, or call the copy result an “unisolated observation” that does not satisfy SP-01a exit.

### Sandbox remains under `benchmark/` until SP-03

Not sound. SP-01b already has a product consumer: `OffsetFinder` executes the target through GDB, core and direct probes at [offset_finder.py:280](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:280), [404](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:404), and [506](/srv/share/dev/supwngo/supwngo/exploit/offset_finder.py:506). Keeping only a benchmark sandbox means arbitrary binaries supplied to `supwngo offset` remain unsandboxed.

The roadmap’s `supwngo/core/sandbox.py` placement should remain in SP-01; `core/proc.py` can stay the lower-level process primitive.

### Confidence deferred to SP-04

Sound. No current SP-01 consumer or passcard metric uses confidence, and SP-04 introduces the static estimator that can give it a defensible meaning. Amend the roadmap’s SP-01 field list so this is an explicit schema decision rather than silent noncompliance.

## New blocking items (B2-n)

### B2-1: The mutant oracle is not internally satisfiable

The METHOD-L precision expectation is arithmetically wrong, `abstain_all` contradicts ROBUST, ordering for `list_all` is unspecified, and mandatory roadmap mutants are missing. Consequently “100% of §3.7 rows” does not prove the intended instrument.

### B2-2: Multiple distance facts lack a scoring/output contract

`ancient_interface` has two `known_value` facts, while expectations are pinned only per `(target, metric)` and `OffsetResult` has one primary `kind`. Without an aggregation and field-mapping rule, truth-echo PASS and OFF exact/net values are not reproducible.

### B2-3: The answer-key RED proof is vacuous under the allowed baseline backend

The `copy` backend permits the answer-key open, yet the row counts as meeting expectations. The plan also says both “copy the challenge directory” and “only target, loader and libc are in the cell”; binding the whole copied directory would expose sources/debug siblings. Define an allowlisted staging layout and test denial of truth, `.debug` siblings and generator sources.

### B2-4: SP-01b product target executions would remain outside the sandbox

Deferring `supwngo/core/sandbox.py` to SP-03 leaves the newly refactored offset runner executing untrusted binaries with only process-group cleanup. This violates the governing SP-01/DEC-25 architecture and makes the planned implementation materially less isolated than specified.

## Non-blocking (N2-n)

### N2-1: RELRO inventory and lint need one more pass

Add [heap_techniques.py:251](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:251), and make the lint understand aliases and `str(getattr(...) or "").lower()` or explicitly inventory those shapes.

### N2-2: Identifier documentation count is stale

Replace “36 lines in 12 files” with the generated inventory rather than a hand-maintained summary. Current documentation-only totals are 34 physical lines in 11 files.

### N2-3: ROBUST envelopes should be command-specific

For example: offset success requires `success=true`, rc 0 and empty error fields; offset failure requires `success=false`, rc 2 and a nonempty `error_code`; decompile failure requires rc 2 plus a nonempty top-level `error`.

### N2-4: Scope the entry-RVA calculation

The formula is correct for the planned ordinary PIE/non-PIE fixtures. State that prelinked ELF is unsupported or derive Ghidra’s original ELF image base instead of assuming it is always `min(PT_LOAD.p_vaddr)`.

### N2-5: Fix the canonical roadmap reference

Point line 3 at the actual committed roadmap path or add the promised canonical copy before implementation.

## Required edits before implementation

1. Correct and fully define §3.7: precision formula/aggregation, list ordering, abstain scope, and the missing roadmap mutants.
2. Define OFF cell granularity and how multiple distance kinds map to the JSON envelope.
3. Make isolated execution mandatory for the accepted baseline; define an allowlisted cell layout and restore all three answer-key probes.
4. Put the reusable sandbox in `supwngo/core/` during SP-01 and route product offset executions through it.
5. Complete the RELRO inventory/lint and correct the roadmap path, identifier count, and command-specific ROBUST envelopes.