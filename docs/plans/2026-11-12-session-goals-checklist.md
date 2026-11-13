# Session goals — sprint-aligned checklist (2026-11-12)

The live checklist for the current work stream. It restates the binding criteria from:

- `docs/roadmaps/2026-11-12-mythos-roadmap.md` §5 (sprint map) and §14 (directive F, gate F, AMD-1..18);
- `docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md` v4.3, §5 and §8.3 (SP-01 exit criteria);
- `docs/plans/2026-11-11-retest-gap-closure-plan.md` (the status log).

Where this file and a source disagree, the source wins; fix this file.

Legend: `[x]` done and verified · `[ ]` open · **Done when** = the completion criterion that closes the item.

---

## 0. Standing goals (apply to every sprint)

- [ ] **G-1 Close the September retest gaps.**
  **Done when:** every RT/CG/HO/I item in the gap-closure plan, Phase 1, is either merged, or re-homed to a named
  sprint with a status in roadmap §5/§14. Today: S1–S5 are merged. S6 and S7 are re-homed: RT-08 → SP-02b,
  HO-01 → SP-01b, HO-02 → SP-02c, CG-04 → SP-02c, I-45 is merged, and CG-01b → SP-07, which is frozen by F.
- [ ] **G-2 Owner PASS bar.**
  **Done when:** every target meets all four parts:
  - the right method;
  - either (a) it works with a supplied component (`--winfun`/`--eip`-style), or (b) a template works with
    manual inputs;
  - decompile works on ELF and PE;
  - the offset is visible.
  Gate F (§6) is the measurable form of this bar for the focus strategies.
- [ ] **G-3 Directive F.** Fix only F-1 `ret2win`, F-2 `ret2libc` and F-3 syscall ROP (`srop`/`rop_syscall`).
  **Done when:** gate F (§6) is met. Until then nothing in §7 ("Frozen") is worked on, except as the smallest
  slice that unblocks a gate-F row. Each such slice is recorded as a roadmap §14 amendment.
- [ ] **G-4 Git hygiene** (checked after every merge).
  **Done when** all three hold:
  - `git worktree list` shows only the main checkout;
  - `git branch -a` shows only `main`, `origin/HEAD` and `origin/main`;
  - `git ls-remote --heads origin` lists only `main`.
- [ ] **G-5 Process.** Each sprint follows these rules:
  - the plan is reviewed by a second model (Daybreak Blue) before implementation;
  - Sonnet agents implement, and the orchestrator reviews every diff;
  - the full suite runs before each PR, compared with the last run on main and with wall-budget failures
    re-run alone;
  - Conventional Commits, and CHANGELOG `[Unreleased]` or an honest `changelog: none`;
  - every commit goes through a PR and is merged to main.
- [ ] **G-7 No hardcoded target values** (owner directive, 2026-11-13). Product code holds no value that only
  applies to an evaluation platform: no payoff-function name lists, no guessed comparison constants, no
  platform-specific flag patterns. Payoff functions are identified per binary by analysis (Ghidra static
  evidence plus sandboxed gdb confirmation). Plan: `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md`.
  **Done when:**
  - the plan's W-0..W-6 are merged;
  - `git grep` finds no payoff-name list;
  - the rename/strip twin test is green for every command that picks a payoff.
- [ ] **G-6 Docs current.**
  **Done when:** at every sprint boundary, the gap-closure status log, roadmap §14 (if amended) and this
  checklist reflect the merged state.

## 1. Done so far

- [x] Gap-closure S1–S5 merged. S5 (Ghidra decompile) is PR #26.
- [x] Mythos 5-2 roadmap, Daybreak Blue review and execution-enabled verify pass merged (PR #29), with
  roadmap §14 AMD-1..18.
- [x] SP-01 plan v4.3 approved after Daybreak Blue rounds 1–5.
- [x] SP-01a, part 1:
  - PR #30: I-45 flag redaction plus guard test; `core/proc.py`; `core/sandbox.py`.
  - PR #31: passcard families, scorer, S0 truth (7 files).
  - PR #32: `sys.executable -m supwngo.cli` (V-3), the core-limit hygiene (V-4), the Ghidra control fixture
    (V-2) and the S0-PE fixtures plus truth (V-15).
- [x] Post-SP-01a regression gate on `3332a0a`: 2533 passed, 18 skipped, 3 failed.
  - All 3 failures are in `test_input_vector_delivery.py` and pass alone (8/8 for the class).
  - The pre-change baseline had a load flake in the same class.
  - Result: 0 genuine failures.

## 2. SP-01a — finish: passcard harness and the pre-fix baseline

Branch: `feat/sp01a-passcard-harness`. Plan: SP-01 §3.3, §3.5–§3.8 and §8.1.

1a.1–1a.4 merged in PR #34 (`992986e`). 1a.5 merged with the baseline PR.

- [x] **1a.1 Staging** — `benchmark/passcard_stage.py` (§3.3).
  - Stage per file: copy the target plus its PT_INTERP/DT_NEEDED closure, and add placeholders.
  - No dot-component paths anywhere in the cell (V-1).
- [x] **1a.2 Preflight** — `benchmark/passcard_preflight.py` (§3.5).
  - A loader or target must be regular, non-empty and executable. Otherwise the cell is VOID with a reason.
- [x] **1a.3 Runner** — `benchmark/passcard.py`.
  - Every cell runs through `sandbox.run`:
    - bind `cell → /tmp/cell`, with cwd `/tmp/cell`;
    - `TMPDIR`, `HOME` and `XDG_CACHE_HOME` point inside the cell;
    - `-o` is forced into the cell;
    - hidden: `benchmark/truth`, `benchmark/gen`, `tests/htb-targets`, the scratch root, `$XDG_RUNTIME_DIR`
      and any `--extra-hide`.
  - Become a subreaper, and run the survivor scan after each cell.
  - Options: `--reps`, `--load-max`, and `--require-time-quorum`, which exits 3 with `time_quorum_failed`.
  - A run is accepted only with `isolation: "bwrap"`.
  - The Ghidra control cell is a precondition of every accepted run (V-2).
  - Report the S0-PE table: 2 DECOMP and 8 ROBUST cells, separate from the 7-ELF matrix (V-15).
  - Write the §3.8 header.
  - One truth loader reads both `s0/` and `s0pe/`, reconciling the `binary:`/`metrics:` schema divergence.
- [x] **1a.4 Mutant self-test** — `benchmark/mutants/*.py` and `tests/test_passcard_selftest.py`.
  - Every §3.7 row is pinned and runs end to end under bwrap.
- [x] **1a.5 Pre-fix baseline** — `benchmark/baselines/passcard-s0-pre-sp01.{json,md}`.
  - Committed before any SP-01b code lands.
  - Done 2026-11-13 on `992986e`: VALID and ACCEPTED, control PASS, isolation `bwrap`, solve 7/7 ingested.
    The first attempt was INVALID because Ghidra timed out on the control cell at load up to about 70; it is
    kept out of tree. Report: `docs/reports/2026-11-13-sp01a-pre-fix-baseline.md`.

**Done when** (SP-01 §5 and §8.3, SP-01a):
- `sandbox.available()` reports `bwrap`, and all 4 self-check probes behave, each with its unsandboxed control.
- Every §3.7 mutant row meets its pinned expectation: 100% of mutants caught, and the answer-key shim denied.
- Mapping coverage is green.
- Preflight results for all 7 S0 cells are reported, with every VOID explained.
- The Ghidra control cell passes in every accepted run.
- The baseline is committed under bwrap with the §3.8 header, the `solve` column, VOID flags and the S0-PE table.
- The full suite shows no new genuine failures against the `3332a0a` run.
- The PR is merged and G-4 holds.

**Status 2026-11-13: met.**
- PR #34 delivered the harness, the self-test (every §3.7 mutant caught) and mapping coverage. The full
  suite on `c2f2bc4` gave 2686 passed, 19 skipped and 1 load flake, against `3332a0a`.
- The baseline header shows `bwrap` with all 4 self-check probes true and the control cell PASS.
- Every VOID is explained in the report, §4.

## 3. SP-01b — the honesty fixes (one commit and one RED test per fix)

Branch: `fix/sp01b-honesty`. Plan: SP-01 §4 and §8.2.

- [ ] **1b.1 `offset`** runs through `proc.run`, the sandbox and preflight (§4.1). It reports `isolation`, and gdb
  works under bwrap.
- [ ] **1b.2 angr** uses `CFGFast(normalize=True)`. The fallback returns real code on the tiny fixture (V-7).
- [ ] **1b.3 RELRO**: core reads plus both lints (§4.3). No stale allowlist entries.
- [ ] **1b.4 Default decompile selection** (§4.4).
  - The PE order is main → `mingw_crt_main_arg` → entry, and truth is the user `main` (V-9).
- [ ] **1b.5 PE refusal**: `pwn`, `template` and `offset` return `unsupported_format` with exit 2 and the JSON
  error field (V-8, V-13).
- [ ] **1b.6 Address normalisation**: `rva = addr − backend_base`, then `address = file_base + rva`, and the
  inverse for `-f 0x…` (V-10).
- [ ] **1b.7 Structured Ghidra runner result**, plus a seam test with a forced fallback failure (V-11).
- [ ] **1b.8 Answer-key leak and identifier lint** (§4.5).
- [ ] **1b.9 HO-01**: delete the dead `pie_base_offset()` (§4.6). `git grep` shows 0 callers.
- [ ] **1b.10 Post-fix baseline**: `passcard-s0-post-sp01.{json,md}`, with the per-metric delta in the PR body.

**Done when** (SP-01 §5 and §8.3, SP-01b):
- **ROBUST** passes on all 14 `offset`/`decompile` S0 cells, and no sentinel scores as success.
- **Processes:** the descendant and hidden-path tests are green, and no process survives any passcard cell.
- **`offset --json` isolation** is `"bwrap"` or `"outer"` under the passcard, and `"bwrap"` when run directly.
- **RELRO:** RET2DLRESOLVE is listed on 0 Full-RELRO S0 targets, counted with `readelf`, and on the Full fixture.
- **Decompile fixtures** pass under `SUPWNGO_REQUIRE_GHIDRA=1`. This covers the ELF fixtures (freestanding and
  stripped-dynamic, no `main`) and the PE default-function fixtures.
- **PE:** `pwn`, `template` and `offset` give `unsupported_format` with exit 2 on both PE fixtures.
- **Addresses:** both backends report the same normalised address on PIE, and the oracle tests pass for ELF PIE,
  ELF ET_EXEC and PE32+.
- **S0-PE table:** 8/8 ROBUST, `pe_sym` DECOMP PASS, and `pe_strip` DECOMP PASS or the recorded V-9 cut-line FAIL.
- **`solve`:** `scripts/htb_rescore.py --reps 3` stays at 7/7, with 21/21 `shell_proven`.
- **Unit suite:** no new genuine failures against the pre-branch run.
- The PR is merged and G-4 holds. **This closes M0's SP-01 half.**

## 4. SP-02 — scoped to F-1..F-3 by directive F

Each sub-sprint gets its own plan in `docs/plans/`, reviewed by Daybreak Blue before code.

### SP-02a — Overrides and `KnownFacts` (F-1 and F-2 components only)

- [ ] `supwngo/core/known.py` and `cli_options.py`:
  - `--win`, `--winfun`, `--ret2`, `--eip`;
  - a supplied libc, and leak or base addresses;
  - wired through `strategy.py` and `cli.py`.
- [ ] Every "must not produce X" RED proof first asserts that the option was accepted (AMD-9).
- [ ] Add the `secret`/`vuln_func` decoy fixture (AMD-9).

**Done when:**
- `pwn --win/--winfun/--ret2/--eip` gives top-1 RET2WIN on 100% of random-name payoff fixtures.
- `--ret2 --rop` gives RET2WIN on 0%.
- The overrides appear verbatim in `template`, with COMP-A1 ≥ 95%.

### SP-02b — Syscall-ROP evidence, role tiering, honest `template` (the three focus builders only)

- [ ] `supwngo/analysis/rax_control.py` provides semantic `rax`-control evidence, not the executor's one-shape
  regex. Its negative fixture makes the return value uncontrollable (AMD-12).
- [ ] SROP and `rop_syscall` are gated on a `syscall` gadget plus proven `rax` control. Role tiering is fixed so
  that SROP outranks the stack pivot when the evidence holds (RT-08, re-scoped).
- [ ] `template` keeps the offset it measures, instead of emitting `offset = 0`.
- [ ] `template` never executes the target unless `--measure` is given.

**Done when:**
- SROP is listed on 0 no-`rax`-control fixtures.
- `template -t auto` equals `pwn` top-1 through a compatible builder, or exits 2, on 100%.
- `template` executes the target in 0 cells without `--measure`.

### SP-02c — Focus suite, tiered truth, held-out split, passcard v1, gate, tag

- [ ] Add a generator under `benchmark/gen/` for F-1..F-3. It covers these axes:
  - amd64 ELF, PIE on and off, `-O0` and `-O2`, stripped and unstripped;
  - randomized names and sizes;
  - `read`, `gets`, `fgets` and `scanf` sinks, with fortify set explicitly per variant (AMD-5);
  - mingw PE builds of the same sources.
- [ ] Generate the negatives (near-misses and patched twins) and a sealed held-out split, with tiered truth.
- [ ] A patchelf run helper so F-2 targets run against a supplied libc and loader (CG-04).
- [ ] Passcard v1 and `scripts/ci/gate.sh`.
- [ ] Tag 2.2.0 (HO-02).

**Done when:**
- Each focus strategy has ≥ 40 dev positives, ≥ 20 sealed held-out positives and ≥ 20 negative controls.
- Truth extraction fails on ≤ 10% per axis.
- ≥ 3 held-out templates are sealed.
- `make gate` runs.
- 2.2.0 is tagged. **This closes M0.**

## 5. SP-03A → SP-06 — focus slices only (roadmap §14, "focus path")

- [ ] **SP-03A Ghidra feasibility spike** (≤ 3 days).
  - Covers the five §6 gates, plus AMD-16: G3 is measured with fortify on and off, and a static-axis line is set
    by the FID probe.
  - **Done when:** DEC-2 is confirmed, or the Bet 1 pivot is recorded before any `facts/` code exists.
- [ ] **SP-03 Minimal facts**, only as far as F.decompile and the PE load need. The store keeps exported JSON
  only, and there is a stale-lock-after-kill test (AMD-4).
  - **Done when:**
    - DECOMP ≥ 95% on the focus suite for ELF and PE;
    - a second call spawns 0 Ghidra processes;
    - changing any manifest field invalidates the cache;
    - malicious fixtures cannot write outside scratch or open a socket.
- [ ] **SP-04a Static distance and static-first `offset`**, including PE.
  - Breakpoint truth breaks on callsite addresses, never on symbols (AMD-17).
  - The sink table includes the `__*_chk` sinks (AMD-5).
  - The crash-driven finder stays as the `--dynamic` confirmer (AMD-11).
  - **Done when:**
    - every unsupported shape abstains with a reason;
    - breakpoint truth agrees with DWARF truth on ≥ 98% of runnable ELF;
    - the F.offset row (§6) holds.
- [ ] **SP-04b Payoff tiers**, for win-function detection (F-1). **Pulled forward by G-7.**
  - It runs immediately after SP-01b, before SP-02, and is no longer in the cut order.
  - Names are never consulted, not even as a tie-break.
  - It absorbs the sandboxed dynamic confirmation for payoff functions.
  - Plan: `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md`.
  - **Done when:** that plan's W-0..W-6 table holds. This includes top-1 identical across rename and strip twins,
    and 0 decoys ranked top-1.
- [ ] **SP-05 Plan v1 and honest templates** for the three focus strategies.
  - **Done when:**
    - every recommendation cites a function and a site;
    - cross-command agreement is 100%;
    - unfilled scripts exit 2 on 100%;
    - strict mode rejects unused inputs.
- [ ] **SP-06 Generator v1 and the held-out report** for the focus suite only. The public tier, comparative table
  and nightly lane are deferred.
  - **Done when:** the first held-out report is published, and a planted structural cheat passes lint but fails
    held-out.

## 6. Gate F — "bulletproof" (exit of the focus path)

Measured per strategy (F-1, F-2, F-3) on the SP-02c suite.

| Row | Done when |
|---|---|
| F.method | Top-1 `recommended` is in the accept set on 100% of dev and ≥ 95% of held-out. The strategy is top-1 on 0 negative controls. |
| F.offset | ELF OFF is exact on 100% of known-value cells. PE static offset is exact on ≥ 95%, and every other PE cell abstains with a reason (0 wrong numbers). |
| F.decompile | DECOMP PASS on 100% of ELF and ≥ 95% of PE. |
| F.component | PASS path (a): with the supplied component, `pwn`/`solve` reaches `shell_proven` on 100% of dev and ≥ 95% of held-out ELF positives. |
| F.template | PASS path (b): `template -t <strategy>` plus scripted manual inputs reaches `shell_proven` on 100% of dev and ≥ 95% of held-out ELF positives. An unfilled template exits 2 and never runs. |
| F.robust | ROBUST 100%, no false success, and 0 flakes across 3 reps. Every held-out miss is listed and explained. |
| F.smoke | `rocket_blaster_xxx`, `ancient_interface`, `sick_rop` and `snow_scan` PASS end to end: method, offset, decompile, and path (a) or (b). |

- [ ] All seven rows hold for F-1.
- [ ] All seven rows hold for F-2.
- [ ] All seven rows hold for F-3.
- [ ] The gate-F suite is wired as a pre-merge regression gate, so a PR that drops any row is blocked.

**Done when:** all four boxes are checked. Only then does any §7 item unfreeze.

## 7. Frozen until gate F

These still have to abstain or decline honestly, but they are not improved:

- every other strategy: heap, format string, integer, environment, `ret2dlresolve`, stack pivot, shellcode,
  `one_gadget` and FSOP;
- the non-focus S0 targets `auth-or-out`, `sabotage` and `bon-nie-appetit`, which are measured but not fixed;
- SP-07 to SP-16, including the LLM hooks, the deletion sprints, CG-01b and the I-2 `solve` deadline;
- any detector work outside the stack-return class.
