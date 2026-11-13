# Retest gap-closure — plan

Closes the gaps from the 26 SEP 2026 comprehensive retest
(`docs/reports/2026-09-26-comprehensive-feature-retest.md`) and the capability-gap
items from `docs/reports/2026-09-25-capability-gap-analysis.md` that the 11 NOV audit
(`docs/reports/2026-11-11-outstanding-work-audit.md`) carried forward, plus the handoff
code-health leftovers. Full 8-phase cycle (multi-item, cross-module, judged by a metric).

- **Base SHA:** `b03cee9` (main).
- **Branch strategy:** each sprint branches from the previous sprint's integrated tip
  (the sprints share the retest matrix as their metric and touch overlapping CLI/analysis
  surfaces, so they are not provably disjoint).
- **Repo contract:** author `jay <jlaratro24@gmail.com>`, **no** Claude/Anthropic
  trailer, PRs opt-in (merge locally, push main), Conventional Commits, CHANGELOG under
  `## [Unreleased]` in the same commit.

## Phase 1 — Objective and gap inventory

**Objective (acceptance criterion, not a single metric):** every confirmed
analysis-command bug below is fixed and proven by a test that would have caught it; the
retest analysis matrix improves from its **measured** baseline of **85/112 OK cells**
(`benchmark/results_retest/baseline-b03cee9/matrix.json`, head `b03cee9`, 60 s timeout);
and no currently-passing test regresses and the corpus solve rates hold (corpus_r2 15/15,
corpus_fsop 3/3).

Provenance: every row's state is **measured** this session unless marked otherwise.
Evidence lives under `benchmark/results_retest/baseline-b03cee9/<binary>/<command>.{json,stderr}`.

### Confirmed bugs — analysis commands

| ID | Retest # | Symptom (measured) | Root cause (measured) | Rel | Cx |
|----|----------|--------------------|-----------------------|-----|----|
| RT-01 | 8 | `leaks` prints nothing, 7/7 | `cli.py:2174` calls `finder.analyze()`; `LeakFinder` has no such method → `AttributeError` swallowed. The class is a live-process leak helper (`leak_with_format_string`, `find_libc_base`, `get_leaks`), not a static analyzer. | 4 | 2 |
| RT-02 | 14, 15 | `heap-analysis` + `integer-analysis` emit unparseable JSON on sick_rop, snow_scan, bon-nie-appetit | pwntools `[ERROR] Address 0x… is not contained in ELF` log lines are written to **stdout** ahead of the JSON object. | 4 | 2 |
| RT-03 | 6 | `decompile` fails 7/7 (4 TIMEOUT, 3 `{"error":"Decompilation failed"}`) | ghidra **is** installed (`/opt/ghidra/support/analyzeHeadless`, named in stderr) but the command runs the angr path, which raises `'Function' object has no attribute 'functions_called'`. | 3 | 3 |
| RT-04 | 5 | `explain` TIMEOUT on auth-or-out, ancient_interface (improved from 4/7 EMPTY → 5/7 OK) | PIE/canary targets drive a slow probe path that exceeds 60 s. | 3 | 3 |
| RT-05 | 18, 19 | snow_scan (large static) TIMEOUT on analyze, cfg, dataflow, pwn, explain | angr CFG construction over a statically-linked glibc exceeds the timeout; several commands build a full CFG eagerly. sick_rop `dataflow` now OK (was EMPTY) — partial pre-existing improvement. | 3 | 4 |

### Confirmed bugs — reported-fact correctness

| ID | Retest # | Symptom (measured) | Root cause | Rel | Cx |
|----|----------|--------------------|------------|-----|----|
| RT-06 | 10 | `protections.stripped` wrong **both** directions: sick_rop (`file`: not stripped) → `True`; ancient_interface (`file`: stripped) → `False` | stripped heuristic in `analysis/protections.py` / `core/binary.py` does not read `.symtab` presence. | 3 | 2 |
| RT-07 | 11 | `uses_tcache: true` on static sick_rop, which imports no malloc (`nm`: 0 tcache/malloc symbols) | tcache heuristic keys on glibc presence/static-link, not on actual allocator use. | 2 | 2 |
| RT-08 | 13 | `pwn` recommends STACK_PIVOT for sick_rop; never suggests SROP, the canonical technique | strategy generator has no SROP rule for static-no-`/bin/sh` BOF targets. | 2 | 3 |
| RT-09 | 16 | `heap-analysis` reports 0 alloc sites / 0 vulns for auth-or-out (custom `ta_alloc`/`ta_free`) | allocator detection matches only `malloc`/`calloc`/`free` names. | 2 | 3 |
| RT-10 | 17 | `report` finds 0 findings for sick_rop, auth-or-out, bon-nie-appetit (each has a known vuln); sabotage now finds 6 | vuln detectors under-match real patterns. Partially improved since Sep. | 3 | 4 |

### Capability-gap items carried into scope

| ID | Source | Item | Rel | Cx |
|----|--------|------|-----|----|
| CG-01 | §3.2 | Retire hardcoded `DEFAULT_LIBC_VERSION="2.31"` (`utils/config.py:33`, consumed by fsop/off_by_one/tcache) and add an offset-libc-vs-loaded-libc **mismatch detector** that refuses rather than emits a confidently-wrong ret2libc. | 4 | 3 |
| CG-02 | §3.1 | `--libc` option consistency: present on 7 commands (measured), absent on neighbours. | 2 | 2 |
| CG-03 | §4 | RISC-V / PowerPC backends absent. **OUT OF SCOPE** — a new-architecture subsystem, not a gap fix; all test targets are x86-64. Declared, backlogged. | 1 | 5 |
| CG-04 | §3.2 | Full `--libc-path` loader threading (patchelf / `LD_LIBRARY_PATH` so the target *runs* against the supplied libc). Assess feasibility in Phase 4; may be its own sprint or deferred. | 3 | 4 |

### Handoff / code-health leftovers

| ID | Item | Rel | Cx |
|----|------|-----|----|
| HO-01 | Delete dead `pie_base_offset()` (`rop_techniques.py`, zero callers; superseded by `classify_volunteered_output` + `_rank_pie_leaks`). | 2 | 1 |
| HO-02 | Cut release 2.2.0 (version is 2.1.0 in `__init__.py` + `pyproject.toml`; only tag is v2.1.0). End of effort. | 3 | 1 |
| HO-03 | N2 stack-clash / N3 double-fetch categories. **OUT OF SCOPE** — net-new held-out-corpus categories, not a September retest gap. Backlogged to a separate effort. | 2 | 4 |

### Already fixed (verify-only, no work)

- Retest #12 (pwn sorts by priority not confidence): `pwn` output is now confidence-descending
  (rocket_blaster_xxx: 0.8, 0.7, 0.65, 0.6, 0.6, 0.5, 0.5, 0.3). Confirm a test pins it.

### Owner decisions (resolved with best judgement — see Phase 5 for rationale)

- **D-1 legacy fallback:** keep on by default (`--no-legacy` opts out). No code change.
- **I-45 YAML flag comments:** redact in place with an ordinary commit; **no history rewrite**.
  Small, folded into Sprint 6.
- **Walkthrough gate shape / follower tier / R5 measurement / A-1 / M-1b / B-3:** all
  orthogonal to gap closure; keep backlogged, no code. Recorded, not re-litigated here.

## Phase 2 — Triage

Lanes: **now** = a sprint; **out-of-scope** = declared; **document-and-move-on** = logged.

- **now:** RT-01, RT-02, RT-03, RT-04, RT-05, RT-06, RT-07, RT-08, RT-09, RT-10, CG-01,
  CG-02, HO-01, HO-02.
- **assess then decide:** CG-04 (Phase 4 spike).
- **out-of-scope (declared):** CG-03 (new arch subsystem), HO-03 (held-out categories),
  all tool-hardening/compliance findings (standing policy).
- **document-and-move-on:** the five deferred owner decisions above.

Priority order by band: P0 broken-command bugs (RT-01, RT-02) → P1 correctness
(RT-06, RT-07) and libc (CG-01) → P1 timeouts (RT-05, RT-03, RT-04) → P2 detector depth
(RT-10, RT-08, RT-09) and CG-02 → P3 cleanup/release (HO-01, HO-02).

## Phase 3 — Sprint map

| Sprint | Items | Band | Exit criterion | Rollback |
|--------|-------|------|----------------|----------|
| S1 broken commands | RT-01, RT-02 | P0 | `leaks` OK on ≥1 applicable target or honest "not applicable" JSON; heap/integer-analysis parse as JSON 7/7 | revert branch |
| S2 reported facts | RT-06, RT-07 | P1 | stripped correct 7/7 vs `.symtab`; uses_tcache false on static-no-malloc | revert branch |
| S3 libc correctness | CG-01a, CG-02 | P1 | 2.31 constant retired to a resolver; offset-byte paths refuse on unknown libc and feature/feasibility verdicts read "unknown" across all importers; `--libc` pinned to the agreed command set. CG-01b mismatch detector + CG-04 split to deferred **S-libc-binding** (see note below). | revert branch |
| S4 timeouts | RT-05, RT-04 | P1 | snow_scan analyze/cfg/dataflow/pwn no longer TIMEOUT at 60 s (OK or fast-skip with reason); explain OK on the 2 PIE targets | revert branch |
| S5 decompile | RT-03 | P1 | `decompile` returns real output via ghidra on ≥1 target; angr path no longer raises | revert branch |
| S6 detector depth | RT-10, RT-08, RT-09 | P2 | report flags the known vuln on ≥2 of the 3 zero-finding targets; pwn lists SROP for sick_rop; heap-analysis sees ta_alloc | revert (per-item) |
| S7 cleanup + release | HO-01, I-45 redaction, S-libc-binding (CG-01b + CG-04) decision, HO-02 | P3 | dead code gone; flags redacted; S-libc-binding scoped or deferred with evidence; 2.2.0 cut | revert branch |

**S3 scope (narrowed after peer review — see `docs/plans/2026-11-11-s3-libc-correctness-plan.md`
and its Daybreak Blue review):** S3 ships **CG-01a** (the honest `supwngo.utils.libc`
resolver + refuse/tri-state across all seven `DEFAULT_LIBC_VERSION` importers) and **CG-02**
(the `--libc` surface pin). The CG-01 **mismatch detector** (now **CG-01b**: offset-libc vs
loaded-libc — it needs build-ID identity, provenance, remote semantics, and central binding at
~6 offset-consumption sites) is entangled with **CG-04** (loader threading: patchelf /
`LD_LIBRARY_PATH` so the target actually *runs* against the supplied libc). Both are too large
for a sprint item and are split into a deferred **S-libc-binding** sprint, to be scoped and
decided in **S7** with the spike evidence.

### Sprint status log

- **2026-11-12 — S4 timeouts: DONE (merged to `main`).** All of S4 has landed:
  **S4a** (port `functions_called()` → `iter_callees`, the shared angr-API fix),
  **S4b-ii/-iii** (RT-04 — the `explain` gdb-probe + walkthrough-offset hangs on
  `ancient_interface`/`auth-or-out`), and **S4b-i** (RT-05 — `cfg`, `analyze`/`pwn`,
  `dataflow`, `strings-analysis` and `decompile --angr` now run angr's
  `CFGFast`/`Decompiler` in a budgeted spawn subprocess that is process-group-killed
  on timeout, then degrade visibly via `analysis_backend`/`angr_budget_exceeded`).
  S4b-i merge: `b981c09` (branch `feat/s4b-i-angr-subprocess`, 6 commits). Full
  suite on the branch: 2199 passed / 16 skipped; the 2 failures are the pre-existing
  **I-2** `solve` timeout and a load-induced input-vector flake (passes in isolation).
  Latent follow-up filed as **B-4** (`_find_callers` never computes callers).
  Per-sprint plans: `2026-11-12-s4-angr-analysis-robustness-plan.md` (parent) +
  `2026-11-12-s4b-i-angr-subprocess-isolation-plan.md`.
- **2026-11-12 — S5 decompile (RT-03): DONE (merged to `main`).** `decompile` now
  returns real Ghidra pseudo-C instead of silently falling back. Three root causes
  fixed: (1) the emitted GhidraScript was `.py`, but Ghidra 12.x without PyGhidra
  cannot run Python scripts — replaced with a committed Java GhidraScript
  (`supwngo/analysis/ghidra_scripts/SupwngoDecompile.java`, packaged via
  `pyproject.toml`/`setup.py`/`MANIFEST.in`); (2) `analyzeHeadless` was invoked
  without `-scriptPath`/`-postScript`, so the script never ran — now wired with a
  tagged selector (`name:`/`addr:`/empty→main); (3) the subprocess ignored
  returncode/stderr and used a 300 s timeout — now a bounded, process-group-killed
  spawn honoring `SUPWNGO_GHIDRA_TIMEOUT` (default 180 s, hard-capped 900 s) with
  `analysis_backend` provenance (`angr`→`ghidra`). Also diagnosed + documented the
  **scriptPath file-scan hang** (Ghidra enumerates every file in each `-scriptPath`
  dir; a crowded dir like `/tmp` hangs >400 s) — the `.java` lives in its own
  near-empty package dir. GREEN proof: CLI returns `analysis_backend: ghidra` with
  real pseudo-C on `bon-nie-appetit` (784 chars) and the gcc fixture; `sick_rop`
  (no `main` symbol) degrades to `None` gracefully. Merge: PR #26 `c8527fa`
  (branch `fix/s5-ghidra-decompile`, 3 commits). Full suite: 2230 passed / 18
  skipped / 1 pre-existing load flake (passes in isolation) — no regression.
  30 hermetic + 2 opt-in real-ghidra tests added
  (`tests/test_decompile_ghidra_output.py`). Peer-reviewed by Daybreak Blue
  (8 blocking items, all resolved). Plans:
  `2026-11-12-s5-ghidra-decompile-plan.md` +
  `2026-11-12-s5-ghidra-decompile-review-daybreak-blue.md`.
- ~~Next: **S6** (detector depth — RT-10/08/09), then S7 (cleanup + 2.2.0).~~
- **2026-11-12 — re-scoped by the owner PASS criteria + Mythos 5-2 review.**
  - **New PASS bar (owner).** The tool must output the right method, plus either (a) work given a supplied
    component (`--winfun`/`--eip`-style overrides) or (b) emit a template that works with manual inputs.
    Decompile must work on ELF and PE, and the offset must be visible on every target.
  - **Baseline at 1741b34.** `docs/reviews/2026-11-12-mythos-roadmap/inputs/SCORECARD.md` scores:
    - method 2/7;
    - `template -t auto` a constant `ret2system` 7/7;
    - offset 0/7, with one crash;
    - decompile 3/7, with two angr failure sentinels reported as success.
  - **Solve at HEAD** was re-measured the same day: `htb_rescore --reps 3` gives 7/7, 21/21 reps
    `shell_proven`.
  - **Review.** A five-dimension Mythos 5-2 review produced a synthesis roadmap. Daybreak Blue reviewed it
    adversarially and Mythos folded in the changes. Records are in `docs/reviews/2026-11-12-mythos-roadmap/`
    and the result is `docs/roadmaps/2026-11-12-mythos-roadmap.md`.
  - **S6 is superseded.** RT-08 moves into **SP-02b**, re-scoped: SROP is gated on `rax`-control evidence
    (`supwngo/analysis/rax_control.py`), not on the syscall-return gadget substring, and comes with role
    tiering. RT-09 and RT-10 are dropped as drafted; their intent moves to **SP-05** and **SP-09**
    (evidence-graded detectors over the facts KB, with name-free allocator roles).
  - **S7 is split.**
    - The **I-45** in-place redaction of three corpus YAML flag comments goes into SP-01a.
    - The **HO-01** `pie_base_offset()` deletion goes into SP-01b.
    - The **HO-02** 2.2.0 tag moves to the end of SP-02.
    - **S-libc-binding** is placed by the roadmap: CG-04 loader threading becomes patchelf-run targets in
      SP-02c/SP-06; the CG-01b mismatch detector goes with the local libc-database in SP-07.
    - Broader dead-code removal and packaging go to **SP-12a/b/c**, staged behind deprecation.
  - **Verify pass.** A single-thread Mythos 5-2 pass, with execution allowed, re-reviewed the final roadmap on
    a scratch copy of the repo. It is recorded at
    `docs/reviews/2026-11-12-mythos-roadmap/verify-mythos-execution.md`, and its amendments are in §14 of the
    roadmap.
    - It corrected the baseline: offset is 2/3 correct on valid stack-return cells, and decompile is 5/7.
    - It confirmed that bubblewrap works unprivileged here, Ghidra included.
    - It found the honesty bugs below, which SP-01 plan §8 adopts as V-1..V-14:
      - `pwn` on PE answers SHELLCODE with exit 0;
      - angr `normalize=True`;
      - dot-path cells break Ghidra;
      - PIE addresses differ by backend.
  - **Owner directive F (2026-11-12).** Pick 2-3 strategies and do not move on until they are bulletproof.
    - The focus is F-1 `ret2win`, F-2 `ret2libc` and F-3 syscall ROP (`srop`/`rop_syscall`).
    - Gate F and the focus path are in roadmap §14. All other strategies and SP-07+ are frozen until gate F is
      met.
  - **Next: SP-01** (passcard v0 and the honesty fixes):
    `docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md`. Plan v4.1 is approved: Daybreak Blue round 4 was APPROVE WITH CHANGES,
    after rounds 1–3 were REJECT. All four rounds are recorded beside the plan.
    - v4.2 adds the verify-pass deltas in §8.
    - v4.3 applies round 5, which reviewed that delta: APPROVE WITH CHANGES, N5-1..N5-9.
    - SP-01a implementation started on 2026-11-12.
- **2026-11-12 — SP-01a part 1 merged (PRs #30, #31, #32; main `3332a0a`).**
  - Merged: I-45 redaction, `core/proc.py`, `core/sandbox.py`, passcard families, the scorer, S0 truth,
    V-3/V-4 test hygiene, the Ghidra control fixture (V-2) and the S0-PE fixtures (V-15).
  - Full suite on `3332a0a`: 2533 passed, 18 skipped, 3 failed. All 3 are `test_input_vector_delivery.py` load
    flakes that pass alone (8/8). Result: 0 genuine failures.
  - **Next:** the SP-01a harness (staging, preflight, `passcard.py`, mutants, self-test), then the pre-fix
    baseline. The live checklist is `docs/plans/2026-11-12-session-goals-checklist.md`.
- **2026-11-13 — SP-01a: DONE (PR #34, `992986e`, plus the baseline PR).**
  - PR #34 merged the passcard harness: staging, preflight, `benchmark/passcard.py` under `bwrap`, the mutant
    self-test and mapping coverage. Full suite on `c2f2bc4`: 2686 passed, 19 skipped, 1 load flake.
  - **Pre-fix baseline** `benchmark/baselines/passcard-s0-pre-sp01.{json,md}` on `992986e`: VALID and
    ACCEPTED, control PASS, isolation `bwrap`, solve 7/7 (21/21 `shell_proven`).
    - S0: METHOD-R0 2/7, TEMPLATE 2/7, OFF 2 PASS + 2 ABSTAIN + 4 VOID, DECOMP 2/7, ROBUST 22/28.
    - S0-PE: DECOMP 1/2, ROBUST 5/8.
    - The first attempt was INVALID: Ghidra timed out on the control cell at load up to about 70.
    - Report, including each failure's owning SP-01b item:
      `docs/reports/2026-11-13-sp01a-pre-fix-baseline.md`.
  - **Owner directive W (2026-11-13): no hardcoded target values.** Product code must not keep
    evaluation-platform payoff-name lists, guessed constants or flag patterns.
    - The plan was approved after 4 Daybreak Blue rounds and merged in PR #35 (`6baeedf`):
      `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md`.
    - Roadmap §14 AMD-19..22 pull SP-04b forward to run right after SP-01b. Checklist goal G-7.
  - **Next:** SP-01b (`fix/sp01b-honesty`). The offset, RELRO and hygiene lanes are reviewed; the
    decompile lane is in progress. Then directive W (W-0..W-6), then the focus path to gate F.

## Phase 4 — Research (reproduced this session)

Findings confirmed by running the real CLI and reading source:

- **RT-01 root (corrected):** the CLI imports the **static** `vulns.leak_finder.LeakFinder`,
  whose entry point is `find_all_leaks()` (not the live-process class the Phase-1
  prose described). `--fingerprint`/`--chain` also called nonexistent methods; the
  real surface is `get_best_leak_for`, `fingerprint_libc`, and `finder.chains`.
- **RT-02 root (confirmed + mechanism):** pwntools' console handler streams to
  `context.log_console` (default `sys.stdout`); `ELF.read` logs
  `[ERROR] Address 0x… is not contained in ELF` at ERROR level **before** raising,
  and `log_level="error"` does not filter it. Neither a logger `setLevel` nor
  `sys.stdout` reassignment works (pwnlib binds the stream via the context knob).
  The only robust fix is `context.log_console = sys.stderr`, restored symmetrically
  in `_reset_console` (else JSON mode leaks into later human-mode logging — flagged
  by review).
- **Cross-sprint dependency (new, from review):** the obsolete angr
  `Function.functions_called()` API breaks **both** `analysis/cfg.py:184` and
  `analysis/static.py:396` — it is a *shared* root behind RT-03 (decompile angr
  path) and part of the S4 timeout/err surface. The angr-API repair must land
  before or within S4, not be siloed in S5.
- **S3 blast radius (new, from review):** `DEFAULT_LIBC_VERSION` is imported by
  more than the three Phase-1 consumers — also `tester.py`, `exploit/heap/techniques.py`,
  `large_bin.py`, `house_of_spirit.py`. The resolver must define `unknown` /
  `not-applicable` semantics for every importer. The mismatch detector must be
  enforced at the ret2libc offset-consumption site (`rop_techniques.py:~563`,
  `_shared.py:local_libc_path`), not in config/CLI, or it is decorative.
- **S4 inventory correction (from review):** the TIMEOUT cell is
  `snow_scan strings-analysis` (always builds `CFGFast()` at `analysis/strings.py:508`),
  **not** `snow_scan explain` (which measured OK). Fix the row before S4.
- **S5 guards (from review):** `analysis/decompile.py:172` ignores returncode/stderr,
  checks only for an output file, and uses a 300 s internal timeout exceeding the
  60 s matrix budget. Needs: unique project dir, `-scriptPath/-postScript`,
  sub-budget deadline + process-group kill, explicit backend-failure classes,
  `backend:"angr|ghidra"` provenance.

## Phase 5 — Per-sprint plans, baselines, peer review

**Peer review:** `benchmark/results_retest/manifests/codex-out/retest-plan-review_*.md`
(t2-cyber, gpt-daybreak-blue, xhigh). Verdict: **BLOCKER on the overall plan** until
Phases 4/5/8 were filled (done here) and the harder sprints re-scoped per below. S1's
roots were confirmed correct. Dispositions:

- **S1 (built + verified this session):** RT-01 + RT-02. Semantic gate met — stdout is
  exactly one JSON document; `leaks --json total` equals a direct
  `LeakFinder.find_all_leaks()` count; all three `leaks` modes run. New tests
  `test_cli_json_mode_pwnlib_redirect.py` and `test_cli_leaks_command.py` proven
  RED on base b03cee9. The `_reset_console` restore closes the flagged redirect-leak
  regression.
- **S2:** use `.symtab` *presence*, not symbol count; gate tcache on actual allocator
  use (a static binary may embed a real malloc). Positive + negative fixtures each.
- **S3:** inventory every `DEFAULT_LIBC_VERSION` importer; define the agreed `--libc`
  command set explicitly; enforce the mismatch detector at offset consumption; prove
  the legacy fallback cannot bypass the refusal; `NOT_APPLICABLE` on static/no-libc,
  `UNVERIFIABLE` (never `MATCH`) when the loaded libc can't be established.
- **S4:** prefer lazy/targeted CFG over whole-binary builds; budgets are the final
  containment layer and must emit `complete:false` + visited/dropped coverage, never
  count a capped result as full OK. Land the shared angr-API fix here.
- **S5:** Ghidra guards above; a passing test requires non-placeholder pseudo-C for the
  requested function, not merely a JSON object.
- **S6:** split bounded fixes (SROP gate extension at `exploit/strategy.py:394`; named
  `ta_alloc/ta_calloc/ta_free` allocator modeling with provenance) from open-ended
  `report` depth (scope to 1–2 named detector integrations + honest
  `execution_complete` vs `coverage_complete`). Do not gate on "2/3 targets have
  something" alone.
- **S7:** split housekeeping from the release commit/tag (a tag is not rolled back by
  "revert branch"). I-45 redaction lives here (resolving the Phase-1 line-75 vs
  line-104 inconsistency in favour of S7).

## Phase 8 — Benefit

- **Transport metric:** re-run `scripts/retest_matrix.py` and compare OK cells to the
  **measured** 85/112 baseline. Label it "JSON transport OK," not capability.
- **Semantic metric (review-mandated):** extend the matrix classifier with `COMPLETE`
  / `PARTIAL` / `SKIPPED` and require rc=0 for success, so a `{"status":"skipped"}` or
  an empty-finding cell is not scored as recovered capability. Each sprint additionally
  carries its own content assertion (counts equal a direct analyzer call; expected
  finding type + evidence address; backend identity; completeness metadata).
- **Regression floor (every sprint):** full suite green vs the base manifest
  (`benchmark/results_retest/manifests/baseline-*`), all previously-OK matrix cells
  still OK, corpus_r2 15/15, corpus_fsop 3/3.

### S1 benefit (measured)

`leaks --json` moved from EMPTY on 7/7 targets to a parseable JSON document on 7/7;
`heap-analysis`/`integer-analysis --json` moved from BAD_JSON to OK on the 3
contaminating targets (sick_rop, snow_scan, bon-nie-appetit) — **+13 analysis cells**
toward the matrix OK count, content verified equal to the direct analyzer output.
