# Retire hardcoded target values; identify payoff functions by analysis (2026-11-13)

Status: **rev 3.1, APPROVED** by Daybreak Blue round 4 (`…-r4.md`), with no blockers. Implementation starts when
SP-01b merges.

History: Rev 1 was reviewed by Daybreak Blue (REWORK, `…-review-daybreak-blue-r1.md`), and every finding
is answered in §9. Round 2 (`…-r2.md`) verified 5 of 6 as resolved. It found finding 3 partial (strip twins)
and one new HIGH (the manifest lifecycle). Both are fixed in rev 3 (§9). Round 3 (`…-r3.md`) resolved the strip twins and found the inventory wording
partial; rev 3.1 fixes that wording.

## 0. Owner directive (verbatim, 2026-11-13)

> "supwngo has a list of win names for win functions form htb challenges. They are hardcodes. That is out of
> scope. We need to be able to use clever ghidra and gdb scripts to dynamically evaluate what the win function
> is on the fly for individual binaries. There should never be hardcoded values that only apply to hack the box"

The directive is recorded as:
- standing goal **G-7** in `docs/plans/2026-11-12-session-goals-checklist.md`;
- roadmap §14 **directive W, AMD-19..22**, in this PR. Those amendments resolve the roadmap contradictions
  (r1 finding 5).

## 1. Scope

The directive is in directive-F scope: payoff identification is the core of F-1 `ret2win`. Per AMD-22, the scope
is every hardcoded target value in product behaviour, and generated exploit code counts as product behaviour:

| Class | Meaning |
|---|---|
| **A** | Selecting a payoff function by symbol name: list scans, exact lookups such as `symbols["win"]`, substring matches, name tie-breaks. |
| **A′** | A generated-script default that names a payoff function. |
| **B** | Comparison or argument constants guessed from a fixed list instead of read from the binary. |
| **C** | Platform-specific success or flag patterns (`htb{…}` and similar). |
| **D** | Prose naming evaluation targets, in comments and docstrings. Covered by the SP-01b §4.5 inventory; not decision logic, so out of scope here. |

## 2. The inventory is a committed, machine-generated manifest (r1 finding 1)

- **`scripts/audit_target_values.py`** runs pinned AST and token searches over `supwngo/**/*.py`, covering:
  - string constants in collections that are compared against symbol names;
  - subscripts and `.get()` on symbol tables with constant keys;
  - `in`/`startswith`/`==` tests of symbol names against constants;
  - integer collections used as comparison or argument candidates;
  - regex and string constants containing platform flag prefixes;
  - string constants inside generated-script templates.
- **Two files, with different lifecycles.**
  - **Baseline inventory** (`tests/data/target_values_baseline.json`), generated once at the W-0 merge base.
    Each entry has a stable ID, the original `path:line`, a class, and a closure status: `open`, `migrated` (with
    the phase that closed it) or `allowed` (with a justification).
    - **Fixed after W-0:** the entry set (no entry is added or deleted) and each entry's ID, original
      `path:line` and class.
    - **The only mutable field** is the closure status. It moves one way: from `open` to `migrated` or
      `allowed`, never back.
    - **A test enforces both rules** against the W-0 commit's copy of the file (`git show <W-0>:<path>`).
    - A closed entry is a tombstone.
  - **Current hits**: regenerated on every test run by the same pinned scan.
- **Red at W-0.** A test fails in any of these cases:
  - a current hit has no matching baseline entry, or a baseline entry is classified only as `open`;
  - an `open` baseline entry no longer matches any current hit, so it is stale and must be closed explicitly.
    Closed tombstones are exempt from the stale check.
- **Red at W-5 exit.** A test fails while any baseline entry is still `open`, or the current scan has any hit that
  is not `allowed`.
- **Rev-1 omissions** are listed here only as seeds; the generated manifest is the denominator. Reviewer-found
  sites:
  - A: `offbyone_techniques.py:806,859,900,920-927`.
  - A′: `templates.py:697`, `canary_bypass.py:502`.
  - B: `fmtstr_techniques.py:46,205-224`.
  - C: `tester.py:83,95`; `walkthrough/facts.py:60`; `fmtstr_techniques.py:107`; `loop_counter_techniques.py:791`;
    `oob_read_techniques.py:125`; `input_shape_techniques.py:310`; `heap_and_bypass.py:217,377,494`;
    `symlink_write_techniques.py:798`; `path_traversal_techniques.py:971`; `toctou_techniques.py:873`;
    `canary_leak_techniques.py:332`; `heapuafread_techniques.py:386-387`; `weak_prng_techniques.py:656`.
- **Second falsifier.** The behavioural twin tests in §5 catch any dependence the textual audit misses.

## 3. Approach

1. **One payoff API.** `supwngo/analysis/payoff.py` is the only way any consumer obtains a payoff function.
   Every class-A site calls it, and seam tests prove each one does (§5).
2. **Static evidence** comes from a dedicated headless-Ghidra script beside `SupwngoDecompile.java`, with the
   angr worker as the fallback.
   - The evidence is behavioural: what the function calls, which constants and strings it uses, and what refers
     to it. It never uses the function's name.
   - It works the same on stripped binaries.
   - Addresses use the SP-01b V-10 convention.
3. **Constants are read from the binary.** A required argument is emitted only when a compare operand slices back
   to a formal parameter, and the provenance records that slice. Otherwise the result is `args: unknown` with a
   reason. Unrelated immediates never become arguments.
4. **Success detection without platform patterns.**
   - Where the tool controls the run environment, it plants its own random marker and checks for it.
   - Elsewhere it uses a platform-neutral flag shape that the operator can override.
   - A marker must not be satisfiable by a plain echo of input; that oracle was shown to be foolable earlier in
     this repo.
5. **Dynamic confirmation.** Candidates run under gdb inside the sandbox through the reusable runner (§4 W-0):
   private workspace, no network, PID namespace, bounded time, nothing written outside the workspace.
   - It uses the constants (step 3) and the planted marker (step 4), so it comes after both.
   - Only an observed receipt promotes a candidate to the top tier.
   - PE and non-runnable targets stay static, and the reason is stated.
6. **Deterministic ranking.** Tier, then evidence strength, then address. Names are never used (AMD-20).
7. **Operator overrides stay** (`--win`/`--winfun`/`--ret2`/`--eip`). They are owner PASS path (a).
8. **Cost control.**
   - Evidence is cached per binary, keyed by file SHA-256, script version and backend version, and invalidated
     when any of them changes.
   - Each call has an explicit time budget: one static pass, at most *K* candidates confirmed, at most *T*
     seconds each. *K* and *T* are recorded in the output.
   - A second call on the same binary spawns zero Ghidra processes.

## 4. Phases (one PR; each phase is a commit with its RED test; order fixed by dependencies)

All counts refer to the **payoff corpus v0** built in W-0. That corpus is:

- **Generator.** `benchmark/gen/payoff/` builds from seeded templates. Function names come from a seeded
  namespace that is checked to be disjoint from every forbidden token and every in-tree string constant.
- **Dev positives: 32 ELF.** 4 payoff shapes × PIE on/off × stripped/unstripped × 2 seeds. The shapes are:
  shell-exec; file-disclosure; argument-checked with 1 argument; argument-checked with 3 arguments.
- **Twins: 32.**
  - 16 rename twins (`objcopy --redefine-sym`) of the unstripped positives.
  - 16 strip twins (`strip`) of the same unstripped positives.
  - Each twin is paired with its original in the truth file.
- **Decoys, in every positive:**
  - a do-nothing function;
  - a file-copy function over a parameter-supplied path;
  - a function containing unrelated comparison constants.
- **Negatives: 8.** No payoff function exists.
- **PE: 8.** mingw builds of the positives' sources, for the static tier.
- **Held set: 16 ELF.** Generated at gate time from a seed the orchestrator supplies through the environment.
  The seed is never committed, and the held set is not used for tuning. Full custody under DEC-22 is still
  SP-02c's job.

| Phase | Content | Done when (exact denominators) |
|---|---|---|
| **W-0** | Inventory manifest (§2). Payoff corpus v0 and its truth (payoff RVA, required args). Reusable sandboxed analysis runner, extracted from SP-01b's `OffsetFinder` runner into `supwngo/core/`. Rename- and strip-twin harness. `scripts/check_htb_rescore.py` (W-6). | The inventory test is red on any unclassified current hit and on any stale `open` baseline entry. Corpus builds 32 positives + 32 twins + 8 negatives + 8 PE, with truth for every binary. The runner passes the SP-01b process and hide tests from its new home. The checker fails on a doctored report (6/7, 20/21, a timeout). |
| **W-1** | Static evidence, ranking and cache (`payoff.py` plus the Ghidra script). | On every positive (32/32), rename twin (16/16) and strip twin (16/16), top-1 equals the truth RVA, and **no answer is an abstention**. Decoys are top-1 on 0/32. All 8/8 negatives have no hypothesis-tier candidate. PE top-1 equals truth on 8/8. A second call spawns 0 Ghidra processes. The budget is recorded in the output. |
| **W-2** | Constants from the binary (class B). | `required_args` equal truth on all 16/16 argument-checked positives, with parameter-slice provenance. Unrelated-constant decoys give `args: unknown` on 32/32. Class-B baseline entries are all `migrated`. |
| **W-3** | Success detection (class C). | Every class-C baseline entry is `migrated`, or `allowed` with a justification. Planted-marker oracle: positive control passes; an input-echo decoy fails. No platform token appears in any non-comment product string (lint). |
| **W-4** | Dynamic confirmation. | Receipts on 32/32 runnable dev positives. 0 receipts on decoys (0/96) and negatives (0/8). 0 surviving processes and 0 writes outside the workspace. Per-binary wall time within the recorded budget. |
| **W-5** | Migrate every class A/A′ consumer to `payoff.py`; delete the lists; generated scripts require the payoff as an input (`inputs_required`) instead of naming one. | Every class-A/A′ baseline entry is `migrated`, and the current scan has no class-A/A′ hit. A seam test per consumer, counted from the baseline inventory, proves the consumer uses the API. Four planted mutants are each killed by the suite (4/4): exact-name lookup, substring match, name tie-break, and a name scan in an executor that no CLI test reaches. `pwn`, `solve`, `template` and `explain` give the truth RVA (not merely equal outputs) on all 16 rename-twin
pairs and all 16 strip-twin pairs, without abstaining. |
| **W-6** | Regression gate. | Held set: top-1 equals truth on ≥ 15/16, every miss explained. `scripts/check_htb_rescore.py` passes on `htb_rescore --reps 3`: exactly 7/7, 21/21 `shell_proven`, 0 timeouts and hard errors, and wall time within bound. A 1-rep canary also passed after W-1, W-4 and W-5. Full suite: no new genuine failures. Passcard S0 delta reported. |

## 5. Enforcement (r1 finding 4)

- **Single API at the seams.** Each consumer's seam test patches `payoff.py` to return a candidate at a random
  address. The test asserts that this address, and only this address, reaches the consumer's output.
- **Mutants.** The four W-5 mutants must each fail the suite. A mutant that survives means the enforcement is
  incomplete, and the PR is blocked.
- **Twins assert the truth RVA and non-abstention.** Equal outputs are not enough, because both twins abstaining
  would also be equal.
- **Seeded names.** The name namespace is disjoint from the forbidden tokens. A lucky match therefore cannot pass
  a twin test.
- **Lint as hygiene.**
  - The §4.5 identifier lint gains each evaluation target's own function names, distinctive strings and
    comparison constants, generated from the binaries into the hidden truth directory.
  - Platform tokens are forbidden in non-comment string constants.
  - The lint's existing generic negatives (`win`, `flag`, …) stay as lint negatives. The behavioural tests, not
    the lint, are what forbid name-based selection.
- **SP-06** keeps the planted structural cheat as the last check.

## 6. Sequencing (r1 finding 2)

1. SP-01b merges first. It supplies the gdb runner (1b.1), the structured Ghidra runner (1b.7) and address
   normalisation (1b.6).
2. W-0 absorbs the focused prerequisites so the sprint does not wait for SP-02c and SP-03 (AMD-19):
   - the payoff corpus with its dev/held split;
   - the reusable runner;
   - the evidence cache and the budgets.
3. The phase order W-1 → W-2 → W-3 → W-4 puts constants and marker plumbing before dynamic confirmation.
4. SP-01b's hygiene commit (removing one entry, plus the identifier lint) lands first, unchanged.

## 7. Risks

- **Solve regression.** Some solves may lean on today's name scan. The canaries after W-1, W-4 and W-5 catch it
  early. Any loss blocks the merge.
- **Ghidra latency in consumers.** Every consumer goes through the cached API with budgets. The canary wall time
  is checked against the bound.
- **Ghidra unavailable.** The angr fallback is used; when neither backend produces evidence, the result abstains
  with a reason.
- **Corpus monoculture.** The held set and the twins are partial controls. The broader generator stays SP-06's
  job.

## 8. Files

- **New:**
  - `supwngo/analysis/payoff.py`, plus the Ghidra payoff script under `supwngo/analysis/ghidra_scripts/`;
  - the runner module in `supwngo/core/`;
  - `scripts/audit_target_values.py`, `scripts/check_htb_rescore.py`;
  - `benchmark/gen/payoff/`, `tests/data/target_values_baseline.json`;
  - tests.
- **Changed:** every class A/A′/B/C site in the baseline inventory; `supwngo/exploit/offset_finder.py` (the runner moves
  out); the identifier-lint test.

## 9. Disposition of review r1

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | BLOCKER | Inventory incomplete; generated code is behaviour | **Fixed.** Machine-generated manifest with class A′. W-0 fails on unclassified or stale entries. The reviewer's sites are seeds only. |
| 2 | BLOCKER | Prerequisites missing when pulled forward | **Fixed.** W-0 absorbs the corpus with its dev/held split, the reusable runner, the cache and the budgets (AMD-19). Constants and marker come before dynamic confirmation. |
| 3 | HIGH | Done-when can pass vacuously | **Fixed.** Pinned denominators. Truth RVA plus non-abstention. Unrelated-constant negatives. Provenance. Positive controls. |
| 4 | HIGH | Enforcement would not catch reintroduction | **Fixed.** Seam tests per consumer. 4 planted mutants. Seeded disjoint names. Truth-RVA assertions. |
| 5 | HIGH | Roadmap contradictory | **Fixed in this PR.** Roadmap §14 directive W, AMD-19..22, with inline markers at SP-04b, the sprint-map dependency and the cut order. |
| 6 | MEDIUM | 7/7 guard not enforceable | **Fixed.** `check_htb_rescore.py` asserts exact counts, 0 timeouts and hard errors, and a wall bound. 1-rep canaries after W-1, W-4 and W-5. |

### Round 2 (Daybreak Blue, `…-review-daybreak-blue-r2.md`)

| # | Severity | Finding | Disposition |
|---|---|---|---|
| r1-3 | PARTIAL | Twins were rename-only; the checklist requires rename and strip | **Fixed.** 16 explicit strip-twin pairs. W-1 and W-5 run on both kinds of twin, and W-5 runs all four CLIs on both. |
| r2-new | HIGH | The manifest lifecycle contradicts itself: deleted sites become "stale" | **Fixed.** An immutable baseline inventory with stable IDs and tombstones, plus a regenerated current-hit scan. The stale check applies to `open` entries only. |
| r3 | PARTIAL | "Immutable" contradicted the status changes | **Fixed.** Only the entry set and the identity fields are frozen. The status changes one way, from `open` to `migrated` or `allowed`, and a test checks this against the W-0 copy. |

## 10. W-0 execution log (2026-11-13)

W-0 was built as one dependency-ordered set of commits on the trunk branch `feat/w0-payoff-corpus`
(base `main` `4158d5c`), not yet PR'd at time of writing:

| Commit | Content | Its own tests |
|---|---|---|
| `be9f1fc` | Payoff corpus v0 generator + rename/strip-twin harness (`benchmark/gen/payoff/`) | 23 passed |
| `a0f5fc9` | HTB solve-column regression gate (`scripts/check_htb_rescore.py`, W-6 tooling) | 13 passed |
| `5212378` | Target-value inventory manifest + scanner (`scripts/audit_target_values.py`, baseline, test) | 44 passed |
| `83cb0c4` | Reusable sandboxed runner extracted from `OffsetFinder` into `supwngo/core/sandbox_runner.py` | 43 passed |

**Done-when (all met).** Inventory test is RED on an unclassified current hit (names the site) and on a
stale `open` entry (hand-verified on `tester.py` and `W-0095`); corpus builds 32 positives + 32 twins +
8 negatives + 8 PE with truth for each; the runner carries the SP-01b process and hide tests from its new
home; the checker fails on 6/7, 20/21 and a timed-out report. Full test collection on the integrated trunk
is clean (3156 tests, no import/collection error). The `offset --json` output is byte-identical to pre-W-0
`main` (the runner extraction is a pure move: `offset_finder.py` delta is −144/+31, all delegation). A
load-sensitive integrated re-confirm of the sandbox/offset suites on a quiet host is the only verification
left open.

**Runner kept strictly move-only.** The first extraction added an opt-in `reap`/`survivors` surface and
duplicated `benchmark/passcard.py`'s bubblewrap-0.6.1 zombie-reap helpers (`_reap_sandbox_init`,
`_stat_state_comm`). That was removed: no consumer uses it, and two copies of that sharp-edge logic would
rot. When **W-4** needs survivor reaping, add it as a **shared** helper that both `passcard.py` and the
runner call, not a third copy.

**Inventory classification review (for the consuming phases).** The scan froze 157 entries
(A 29, A′ 5, B 69, C 54). Every rev-1 seed is caught and in its expected class. The following edge
classifications are deliberately left `open` for the phase that consumes them to resolve to `migrated` or
`allowed` — they do **not** block the frozen baseline (the entry set and IDs are frozen; only `status`
moves):

- **W-2 (class B) — generic POSIX constants that are almost certainly `allowed`, not target guesses, so
  W-2 must mark them `allowed` rather than try to migrate them:** signal-code sets
  (`offset_finder.py:1048,1073`, `delivery.py:61` `FAULT_SIGNALS`), bad-char lists (`verify.py:477`,
  `stack_bug.py:378`), mask bytes (`reliability.py:621`), crash patterns (`crash_triage.py:446,528`), the
  ioctl-code list (`cli.py:1610`), and slab sizes (`kernel/module.py:68`).
- **W-3/W-5 (class A vs C vs allowed) — substring "hint" lists, not exact payoff names:** `_SECRET_HINTS`
  (`path_traversal:766`, `symlink_write:645`, `toctou:667`, `library_hijack:269`) and `PRIV_HINTS`
  (`uninit_disclosure:386`) are classed A `name_list` but are secret-file / privileged-variable hints;
  resolve to C or `allowed`. `heap_techniques.py:385` (`symbols.get("dispatch_table")`) is A `symtab_get`
  but target-shaped, not a payoff name.
- **A′ false positive to keep in mind:** `walkthrough/families/fmtstr.py:370` `'win'` is an f-string
  fallback name, not generated-script text; it is classed A′ `template_name` because masking replacement
  fields would also drop the real `templates.py:697` template-in-field case. `triage.py:184` is correctly
  A′ (keyword tuple inside a generated script string).
- **Exemptions that change the denominator if touched:** `UNIVERSAL_NAMES`, `UNIVERSAL_PREFIXES`,
  `LIBC_ROOTS` are pinned in the scanner; changing them requires a baseline regeneration.

The baseline adds an `anchor` field (hash of the source line) beyond the spec, for drift-tolerant matching
of a moved hit. The `git show <W-0-sha>` frozen-fields check is a TODO in the test until this set is merged
and the W-0 sha exists.
