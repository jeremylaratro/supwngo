# supwngo — synthesis roadmap, sprint map and plan (Mythos 5-2, 2026-11-12)

Nothing was executed for this synthesis. Claims carry a `path:line` I read myself unless marked *(reviewer-cited)*, where I rely on the review, or UNVERIFIED.

### 0. Executive summary

- **Where it really is.** On the owner's PASS criteria the tool scores method 2/7 (1/7 discriminative), offset 0/7 with one crash, decompile 3/7 and a constant `ret2system` template on 7/7 (SCORECARD). The one engine with recorded solves (`solve`, 7/7 claimed in CHANGELOG) was not measured at this commit (D3-F1).
- **Why.** The commands PASS is measured on (`pwn`, `template`, `offset`) never consult vulnerability facts. `pwn` ranks from protections, gadgets and imports with literal confidences (`strategy.py:272,279,412-413`). `template -t auto` builds a suggester with no gadget finder and defaults unknowns to `ret2system` (`cli.py:1221-1231`). `offset` is crash-only (`offset_finder.py:210-234`).
- **The tool reports failure as success in four confirmed places.** These are the angr sentinel (`_angr_subprocess.py:244-246`), exit 0 with an `error` object (`cli.py:2129-2134`), a silent "no offset" when the target cannot execute (SCORECARD harness defect), and a leaked answer key (`offset_finder.py:887`).
- **Thesis.** "Best in existence" is not reachable by breadth. The defensible niche is an offline, binary-only, facts-backed toolbox in which every method, offset and finding is either oracle-confirmed or explicitly labelled a hypothesis. It gives a static distance for every stack sink on ELF and PE, and has a verifier an agent cannot talk past (D2 §4, D4-F3).
- **Bet 1 — one Ghidra whole-program facts export per binary, cached by sha256.** Decompile, static offset, payoff discovery, allocator roles and PE all become queries over it (D1-R3, D2-R1, D4-R3). The spot-check already shows offset 40 on rocket_blaster_xxx from P-code.
- **Bet 2 — one plan, four renderers.** `pwn`, `template`, `offset`/`report` and `autopwn` render the same `MethodPlan`. Templates declare machine-fillable inputs, and operator overrides are asserted facts honoured everywhere (D1-R2, D3-R2/R6/R7).
- **Bet 3 — measurement first, then the oracle as a product.** A PASS scorecard runs on a generated corpus with build-derived truth and a held-out seed. After that come `facts`/`verify`/`try` behind one JSON contract, and only then LLMs as closed-set proposers (D5-R1/R2/R3, D4-R1/R2/R5).
- **Stop: per-target work.** No new executors, walkthrough families or variant corpora written from one HTB target. No per-target exit criteria. No name lists.
- **Stop: polishing demoted code.** `walkthrough/` (29k LoC), `kernel/` and FIRST_TECHNIQUES seat negotiation are frozen. The executor-substrate refactor (D1-R6) is rejected.
- **Stop: process without numbers.** Multi-round review is reserved for measurement instruments and cross-engine interfaces. "OK cells" and self-reported `shell_confirmed` are retired as KPIs (`htb_rescore.py:206`).
- **S6 is replaced.** RT-08 is re-scoped into SP-02. RT-09 and RT-10 are dropped as drafted, and their intent lands in SP-09 on top of facts.
- **Sequence.** SP-01/02 make the baseline honest and measured, SP-03–06 deliver PASS on stack bugs for ELF and PE with a held-out number, SP-07–11 cover contract, non-stack and verification, SP-12 deletes, and SP-13–16 add LLM hooks and PE hardening.

### 1. North star and scorecard

**Product statement.** supwngo is a verified, offline, machine-drivable analyst and agent toolbox for binary RE/VR. Given an ELF or PE it produces a cached facts base, decompilation, and evidence-graded findings. It produces a ranked `MethodPlan` whose preconditions are each marked confirmed, operator-supplied or missing. It gives the exact controlling distance (offset) of the primitive, and a template that declares what it still needs. It can also verify an exploit script with an unforgeable receipt. Autonomous exploitation is one consumer of the plan (the executor/verifier stage), not the headline.

#### 1.1 Truth manifest

One `truth.yaml` per target (smoke) or emitted by the generator (corpus), merging D3-R1 and D5-R1:

```yaml
format: elf|pe        arch: amd64|i386      runnable: true|false
vuln_class: CWE-121   vuln_function: <addr|name>   sink: <callsite addr>
methods_accept: [srop, rop_syscall]     methods_reject: [ret2libc]
distance: {kind: buf_to_ret, value: 40}  canary_distance: null
components: {win: 0x..., ret2: null, args: [], libc: null}
decompile_anchors: {vuln: [read], main: [vuln]}
input_vector: stdin|argv|file|menu
```

#### 1.2 Metrics

Metric IDs are words, so they do not collide with milestones `M0…`. Scoring is +1 correct, 0 explicit abstain, −1 confident wrong (the AIxCC accuracy penalty, D5 §4). Both accuracy and net score are reported.

| Metric | Computation | Notes |
|---|---|---|
| **METHOD-R** (headline) | Top-1 `recommended.family` ∈ `methods_accept`, and every precondition of that plan is `confirmed` or `operator`. Abstaining ("no recommendation: evidence insufficient") scores 0. | Until SP-05 there are no preconditions; reported as METHOD-R0 (label only). |
| **METHOD-L** (diagnostic) | An accept-set member appears in the top 3 of the evidence-backed list. List precision = \|listed ∩ accept\| / \|listed\|. The `speculative` tier is excluded. | The top-3 cap and precision term close the "list everything" hole (D2-Q2, D3-F12, D4-F11). |
| **OFF-S** | Static `distance{kind,value}` equals truth exactly. Scored per kind; stack kinds are `buf_to_ret` and `buf_to_canary`. | Wrong-unlabelled rate reported separately; target ≤ 2%. |
| **OFF-D** | Breakpoint-at-sink measurement equals truth (runnable ELF only). | From SP-11. |
| **RIP** | Payload built from the reported offset plus a marker PC; gdb or core shows PC == marker. | CGC Type-1 proof (D5-R1 M3b). Runnable, canary absent or supplied. |
| **DECOMP** | Fraction of `decompile_anchors` functions with non-sentinel pseudo-C containing their anchors. Also: the default invocation (no `-f`) returns a user function. | Backend and seconds recorded. |
| **COMP-A** (criterion a) | Withhold one component, rerun with `--win/--ret2/--offset … --strict-overrides`. A1: plan and template contain the value verbatim. A2: `verify` reaches `shell_proven` or the flag under `benchmark/attribution.py`. | A2 runnable ELF only. |
| **COMP-B** (criterion b) | Template's declared inputs == truth-required minus auto-resolved; auto-resolved values == truth; filled from truth it reaches proof; unfilled it exits 2. | Golden-fill (D3-R7). |
| **ROBUST** | No traceback, one JSON document, exit code matches `ok`, no sentinel as success, budget respected, "target cannot execute" stated explicitly. | Per cell. |
| **TIME** | Cold and warm p50/p95 per command, with load average recorded. Cells run above a load threshold are flagged invalid, not failed. | BRIEF §7 contention. |

#### 1.3 Resolved disagreements

- **Top-1 vs listed.** The headline is top-1 with confirmed preconditions (D4-Q2, D3-R2). "Listed" survives only as top-3 with precision. A method may also appear under `speculative[]`, which never scores.
- **What "right" means.** Truth is an accept-set at family granularity (D3-F1). By default a technique that produces a `shell_proven` solve is added to the target's accept-set after review (owner question 1).
- **Offset for heap and integer targets.** "Offset" becomes the controlling distance of the actual primitive, with a `kind` (`chunk_to_next_size`, `record_to_fnptr`, `buf_to_var`, `index_bound`; D3-R3, D5-Q5). Stack and non-stack are reported as separate columns. "Offset on all" is operationalised as: every target has an exact distance of its truth kind or an explicit abstain with a reason, and never an unlabelled guess. A saved-RIP offset on a heap target is not scored.

#### 1.4 Evaluation sets

| Set | Source | Role |
|---|---|---|
| **S0 smoke** | HTB-7, run from challenge directories (SCORECARD harness defect) | Reported every run; never an exit criterion, never tuned on. |
| **T0-dev** | Generator, dev seeds (mini in SP-02, ≥ 300 binaries in SP-06) | Development and exit criteria. |
| **T0-held** | Same generator, owner-held seed, ≥ 150 binaries; held-out by template as well as by seed (D2-R7) | Aggregates only; sprint gates on the dev-minus-held gap. |
| **T0-PE** | mingw x64/x86 builds of the same sources; MSVC later | PE DECOMP and OFF-S; a slice of both dev and held. |
| **T1 public** | ROP Emporium, how2heap at pinned glibc, about 40 labelled; fetch by URL + sha256 | Dev only. Never used to score LLM modes (contamination). |
| **T2 precision** | cb-multios patched twins and a Juliet subset (≈ 100 pairs, not D5's 500) | Detector precision and recall, from SP-09. |

#### 1.5 Anti-overfitting rules

1. No identifier from any evaluation binary may appear in non-comment code under `supwngo/`; a lint test enforces it. Today there are 37 occurrences in 12 files (my grep), mostly comments, so comments get a count ratchet.
2. Every sprint exit criterion is a delta on T0 or T1. S0 is reported beside it.
3. A measured held-out set is burnt and becomes dev. The seed rotates quarterly (D5-R3).
4. Metamorphic invariance is part of the gate: rename, strip and compiler change must not change method or distance (D5-R2, D3-R10).
5. Every instrument ships with a planted mutant it must catch (D5-R1). An instrument that has never failed is not trusted.
6. LLM-assisted scores are reported separately and count only on fresh T0 (D5-R4).

#### 1.6 Targets per milestone

Baseline is today's SCORECARD. T0 values for M0 are whatever SP-02 records.

| Metric (set) | Today (S0) | M0 | M1 | M2 | M3 |
|---|---|---|---|---|---|
| ROBUST (T0 + S0) | 1 crash, 2 sentinels | 100% | 100% | 100% | 100% |
| DECOMP (T0 ELF / PE) | 3/7; PE unmeasured | baseline | ≥ 95% / ≥ 95% | hold | hold |
| OFF-S stack, -O0 / -O2 (T0-dev) | 0/7 | baseline | ≥ 90% / ≥ 75%, wrong ≤ 2% | ≥ 95% / ≥ 85% | hold |
| OFF-S stack (T0-PE) | — | baseline | ≥ 85% | ≥ 90% | hold |
| OFF non-stack kinds (T0-dev) | — | — | — | ≥ 60% | hold |
| METHOD-R stack classes (dev / held) | 2/7 | baseline | ≥ 80% / gap ≤ 10 pts | hold | hold |
| METHOD-R all classes (dev / held) | — | — | — | ≥ 70% / ≥ 60% | + LLM lift, separate |
| COMP-B golden-fill (ELF stack positives) | 0 | — | ≥ 80% | ≥ 80% all classes with a plan | hold |
| COMP-A1 / A2 | unmeasured | A1 on `pwn`/`template` | ≥ 95% / ≥ 70% | ≥ 95% / ≥ 80% | hold |
| RIP (runnable ELF stack) | — | — | — | ≥ 80% | hold |
| TIME facts cold p95 / warm | 30–190 s / n.a. | — | ≤ 90 s / ≤ 2 s (quiet host) | hold | hold |

Smoke expectations, derived from code and UNVERIFIED by execution: OFF-S 4/4 on the stack targets by M1, and DECOMP 7/7.

### 2. Target architecture

```
                 ┌────────────────────────── CLI / machine contract ───────────────────────────┐
                 │ envelope supwngo.tool/v1 · exit 0/2/1 · tools --json · (generated MCP)       │
                 │ facts | decompile | offset | pwn | template | report | verify | try | autopwn│
                 └──────────────┬───────────────────────────────┬───────────────────────────────┘
                                │ renderers                     │ oracles
┌──────────── per-binary KB  ~/.cache/supwngo/<sha256>/ ────────▼──────────────┐
│ facts.v1 (typed, provenance: static|measured|operator|unknown)               │
│  program · functions · frames · callsites(args) · strings+xrefs · decomp     │
│  + asserted facts from --win/--ret2/--offset/--known/--facts                 │
└───▲───────────────▲───────────────▲──────────────────────┬───────────────────┘
    │ analyzers (budgeted, killable subprocess, cached)    │ queries
 loader(lief/      ghidra_export   gadgets   libsig(FID)   ▼
 pyelftools)       (Java, 1 pass)            [SP-08]   detectors → Finding{class, site, grade E1..E3}
                                                       stack_layout → SinkRecord{distance, reaches}
 angr: optional, directed, budgeted helper             payoff → ranked payoff functions
                                                           │
                                                           ▼
                                   Planner: Finding × TechniqueSpec → MethodPlan[]
                                   {family, technique_id, evidence[], facts{}, required_inputs[],
                                    distance, script_builder}
                                           │                         │
                     pwn / template / offset / report        autopwn: execute plan via executors
                     (static by default)                     └─► PipelineVerifier (receipt, shell_proven)
                                                                  bubblewrap, no network
 LLM layer (off by default): closed-set proposals → Hypothesis queue → oracle → fact | refuted
```

- **Knowledge base.** One directory per sha256. The first version has three hard-wired analyzers (`loader`, `ghidra_export`, `gadgets`) and about 25 fact keys. There is no merge algebra and no provides/requires scheduler until a fourth analyzer needs one. This trims D1-R1 on its own stated risk.
- **Detectors** are queries over facts, graded E1 (site-level static), E2 (argued, cited lines) or E3 (dynamically confirmed). Import-only evidence (E0) is never a finding (D2-R3).
- **Planner.** `TechniqueSpec` is declarative and sits beside each executor. Executors gain `plan(context, execute=False)`, which formalises the existing `_gate` returns (`srop_nowrite_techniques.py:195-254`).
- **A caveat D3-R2 missed.** Executor gates are not all static. They read `context.profile_has_menu`, which is set by running the target (`profile_stage.py:199-234`; `scripts/gate_sweep.py:22-25`). Static mode must treat such inputs as `unknown` and list them in `required_inputs`.
- **Renderers.** `template` renders `script_builder` with declared inputs. `explain` is frozen and later becomes a thin narrator of the plan.
- **Oracles.** `verify` exposes `PipelineVerifier.verify_via_tester`, and `try` runs one executor with supplied facts (D4-R2).
- **Deleted.** `auto.py`, `enhanced_auto.py`, `generator.py`, `chainer.py`, orphaned `templates.py`, the zero-importer modules in D1-F10, six of the seven win lists, four of the five offset finders, the RetDec path, `driller.py`, the honggfuzz and libFuzzer wrappers, and `schema/` except the `Provenance` vocabulary.
- **Demoted.** `StrategySuggester` (fallback for un-specced families, then removed), angr (optional), FIRST_TECHNIQUES (a prior, not a list to maintain), `walkthrough/` and `kernel/` (frozen).

### 3. Decision register

| ID | Decision | Rationale | Reversible? | Revisit if |
|---|---|---|---|---|
| DEC-1 | The product is the verified toolbox; autonomous exploitation is the executor stage (default 1). | D4-F3: a bare agent already solves the easy corpus. PASS criteria do not require autonomy. | Yes | HYP-12 shows the toolbox adds neither cost nor solve benefit. |
| DEC-2 | Ghidra is the system of record; angr is an optional helper (default 2). | Loads PE natively, works offline; spot-check gives offset 40 on rocket. | Costly after SP-04 | HYP-1 or HYP-2 falsified. |
| DEC-3 | The exporter stays Java. PyGhidra is evaluated but not depended on. | Ghidra 12.1.3 here has no PyGhidra (BRIEF §5). | Yes | An offline PyGhidra install is proven and halves exporter maintenance. |
| DEC-4 | Offline-first; LLM off by default (default 3). | Hard platform requirement. | No | — |
| DEC-5 | HTB-7 is smoke only (default 4). | D5-F2: four executors were written from one target each. | No | — |
| DEC-6 | The headline is METHOD-R (top-1, confirmed preconditions, wrong-answer penalty). METHOD-L is top-3 with precision. | Closes the list-everything loophole. | Yes | Owner wants top-k. |
| DEC-7 | Truth is an accept-set; a `shell_proven` solve by another technique is accepted after review. **OWNER** (default: accept). | D3-F1: three of seven labels differ from the tool's recorded solves. | Yes | Owner requires write-up labels. |
| DEC-8 | "Offset" = primitive distance with a `kind`; stack and non-stack are reported separately. **OWNER** (default as stated). | The metric is undefined on 3/7 otherwise. | Yes | Owner wants saved-RIP only. |
| DEC-9 | `pwn`, `template`, `offset` and `report` are static by default; execution needs `--measure` or `--dynamic`. Flips in SP-04/05. **OWNER** (default: static). | `template` silently executes today (`auto.py:2759`); the platform handles untrusted binaries. | Yes | Owner prefers dynamic by default on trusted hosts. |
| DEC-10 | Canonical address space is RVA plus preferred base, computed in the exporter from `getImageBase()`. | Avoids depending on a loader flag that is UNVERIFIED on 12.1.3 (D2-R1). Fixes D2-F3 by construction. | Yes | — |
| DEC-11 | Static offset uses the Ghidra frame and P-code as primary, with a narrow capstone prologue fallback inside Ghidra function bounds. | The spot-check shows Ghidra abstains on hand-written asm while a prologue estimator gets 40. D3-R3's full Estimator A is rejected: it rebuilds function recovery, another private analyser. | Yes | HYP-3 shows agreement of two full estimators is needed for trust. |
| DEC-12 | PE scope is decompile, offset and protections, static only, with truth from mingw DWARF. No Qiling or wine until Windows exploitation is in scope. | PASS says "decompile + offset for now". | Yes | Owner un-scopes; or PE truth cannot be validated without execution (SP-06 check). |
| DEC-13 | MSVC-built PE fixtures in SP-16. **OWNER** (default: mingw only until the owner supplies a toolchain or binaries). | D5-Q6: mingw overstates readiness. | Yes | Owner supplies them earlier; then they join SP-06. |
| DEC-14 | Deletion is allowed behind a reachability test (default 5). The legacy fallback is removed in SP-11 and the files in SP-12. | Legacy measured 0/7 attributed. | Git | — |
| DEC-15 | `schema/`: keep about 200 lines of `Provenance`, delete the rest in SP-12. | Orphaned (D1-F4). Two provenance vocabularies must not both survive (D4-Q7). | Git | — |
| DEC-16 | `kernel/` and `walkthrough/` are frozen. `kernel/` moves to an extra in SP-12. **OWNER** for outright deletion (default: freeze). | Off the PASS path. | Yes | Owner names kernel as a goal. |
| DEC-17 | No executor-substrate refactor (D1-R6) and no "`cli.py` ≤ 300 lines" goal (D1-R8). Commands move out as they are touched. | Effort L on demoted code; a line count is a vanity metric. | Yes | A new technique still costs over 1k lines after SP-10. |
| DEC-18 | CI is a local gate (`make gate`, systemd timer) on the x86-64 host. `.github/workflows/ci.yml` is reduced to calling the same script. | Owner policy is local-only; Sparks are ARM64. No sharding across Sparks (rejects part of D1-R7). | Yes | A reserved runner appears. |
| DEC-19 | Process (default 6): one-page plans for S work; multi-round review only for instruments and cross-engine interfaces; "no number, no sprint". | D5-F9. | Yes | Post-merge errata rise (HYP-18). |
| DEC-20 | No in-tree agent; MCP is a generated wrapper, last. | The owner's agents use a shell (BRIEF §5); D4-R11. | Yes | — |
| DEC-21 | Cloud models are an evaluation arm only, and only on generated T0 fixtures. **OWNER** (default as stated). | Offline requirement; contamination on public targets. | Yes | — |
| DEC-22 | Held-out custody: the seed sits in an owner-only path outside every agent worktree; the harness prints aggregates. **OWNER** to name the custodian. | D5-R3. | Yes | — |
| DEC-23 | LLM method reordering (D4-R7) and LLM prose (D4-R10) are not built. | They optimise attempts-to-solve and cosmetics, both demoted. | Yes | Autonomous solving returns as a goal. |
| DEC-24 | Tag 2.2.0 at the end of SP-02 (baseline committed); then tag by milestone with the passcard table in the CHANGELOG. | D5-R8. | Yes | — |

### 4. Roadmap

#### M0 — Honest baseline (SP-01, SP-02; about 2 weeks)

- **Objective.** The tool stops lying and every later claim is measured.
- **Done when.** ROBUST is 100% on S0 and T0-mini. A passcard baseline is committed where every metric has at least one FAIL and the planted mutant is caught. `solve` is re-measured gated on `shell_proven`. Overrides work on `pwn` and `template` (COMP-A1). `template -t auto` equals `pwn`'s recommendation or exits 2.
- **Deliverables.** `benchmark/passcard.py`, truth files, T0-mini generator, the eight correctness fixes, `make gate`, tag 2.2.0.
- **Tests.** HYP-9, HYP-10, HYP-13.

#### M1 — PASS on stack bugs, ELF and PE, with a held-out number (SP-03 to SP-06)

- **Objective.** Bets 1 and 2 on the class that covers 4/7 of smoke and all of the PE scope.
- **Done when.** The §1.6 M1 column is met.
- **Deliverables.** Facts v1 and cache, `facts` command, static distance, payoff detection, Plan v1 with honest templates, generator v1, held-out custody, nightly lane.
- **Tests.** HYP-1 to HYP-6, HYP-14.

#### M2 — All classes, one contract, proof (SP-07 to SP-11)

- **Objective.** Non-stack classes get plans and distances, static and stripped binaries work, and the oracle becomes public.
- **Done when.** The §1.6 M2 column is met; the contract test passes for every command; `verify` refuses all eight `broken_*` scorer fixtures (D4-R2); the legacy fallback is off.
- **Tests.** HYP-7, HYP-8, HYP-11, HYP-12 (pilot), HYP-15, HYP-16.

#### M3 — Smaller and smarter (SP-12 to SP-14)

- **Objective.** Delete what the plan replaced; add LLM hooks that must beat `--llm off`.
- **Done when.** `supwngo/exploit/` ≤ 70k LoC; `--version` < 0.5 s; the reachability test is green; each shipped hook meets its lift threshold on held-out renamed variants with zero hallucinated-value incidents (HYP-19); the two-arm agent evaluation is published.

#### M4 — Reach (SP-15, SP-16)

- **Objective.** Parser and menu reachability; PE beyond mingw; release 3.0.
- **Done when.** Targets are set at the M3 exit from measured gaps. SP-15 is cancelled if HYP-17 shows reachability is not the binding constraint.

#### Stop-doing list

1. Per-target executors and variant corpora authored from the target they evaluate.
2. Name lists for win functions and allocators.
3. New `walkthrough/` families.
4. FIRST_TECHNIQUES seat tuning (`orchestrator.py:101-537`).
5. "OK cells" and `shell_confirmed` as evidence.
6. Instruments living in `/tmp`.
7. Reviews of interfaces that have no producer or consumer.
8. `scripts/auto_implement.sh` (an unattended `--dangerously-skip-permissions` loop, D5-F8).

#### Deletion schedule

| When | What | Guard |
|---|---|---|
| SP-02 | `scripts/auto_implement.sh`, `setup_cron.sh`, `test_accuracy.py` | No importer. |
| SP-05 | `tech_map` (`cli.py:1224-1231`); `generate_exploit_script` use by `template`; `exploit/templates.py` | COMP-B at least as good as before on T0. |
| SP-09 | PLT-presence detectors, `uaf.py`, `off_by_one.py`, `heap_advanced.py` site finders, the regex list at `decompile.py:627-637` | T2 precision and recall not worse. |
| SP-11 | Legacy fallback in `autopwn`/`solve` (`cli.py:2953, 3565`); `exploit --auto` deprecated | `solve` proof rate on corpora not worse. |
| SP-12 | `auto.py`, `enhanced_auto.py`, `chainer.py`, `generator.py`, the D1-F10 list, `schema/` minus Provenance, RetDec path, `driller.py`, honggfuzz/libFuzzer wrappers, duplicate win lists and offset finders, `setup.py`, `requirements.txt`; `kernel/` to an extra | Reachability test; `run_bench` non-regression. |

### 5. Sprint map

Effort: S ≤ 3 days, M ≈ 1 week, L ≈ 1.5–2 weeks of agent-assisted work. Every exit criterion is measured by `passcard` on the named set, with S0 reported alongside.

| ID | Goal | Scope | Depends | Eff. | Exit criterion | Closes |
|---|---|---|---|---|---|---|
| SP-01 | Passcard v0 and the five "lies" | `benchmark/passcard.py`, `benchmark/truth/`, `offset_finder.py`, `_angr_subprocess.py`, `decompile.py`, `SupwngoDecompile.java`, `core/binary.py` + RELRO consumers, identifier lint | — | M | Baseline committed; planted constant-`ret2system` mutant fails METHOD-R on ≥ 5/7; ROBUST 100% on S0 for `offset`/`decompile`; RET2DLRESOLVE listed on 0 Full-RELRO fixtures; lint green | D5-F1, D5-R1 (v0), D3-F5 (crash), D2-F5, D2-R8 (part), D1-F3, D1-H6, D2-F4 (default), D2-F11, D4-F4, D3-F11 |
| SP-02 | Method-surface honesty, passcard v1, T0-mini, gate | `strategy.py`, `cli.py` (`pwn`/`template`/`offset`), `auto.py` (minimal), `benchmark/gen/`, `htb_rescore.py`, `scripts/ci/gate.sh` | SP-01 | M | T0-mini: ≥ 60 binaries (≥ 16 PE) at 100% truth extraction or counted abstain; `template -t auto` == `pwn` top-1 or exit 2 on 100%; COMP-A1 ≥ 95% on ret2win fixtures; `solve` column committed, gated on `shell_proven`; tag 2.2.0 | RT-08 (re-scoped), D3-F2, D3-F7, D1-F5, D3-F10, D4-F7, D3-F4 (honesty), D3-R1, D5-F4, D5-F6, D5-R5 (pre-merge lane), D5-R7 (part) |
| SP-03 | Facts v1: one Ghidra pass, cached; `facts`; `decompile` over facts; PE loads | `supwngo/facts/`, `SupwngoExport.java`, `decompile.py`, `cli.py` | SP-02 | L | DECOMP ≥ 95% on T0-mini ELF and PE; cold p95 ≤ 90 s, warm ≤ 2 s on a quiet host; second call spawns 0 Ghidra processes; 0 tracebacks on PE | D1-R3, D2-R1, D4-R3, D1-F6, D2-F2, D2-F3, D2-F4, D4-F9, D2-F13 (part), D1-R1 (thin) |
| SP-04 | Static distance, payoff detection, static-first `offset` | `analysis/stack_layout.py`, `analysis/payoff.py`, `cli.py` `offset`, `strategy.py` win scan | SP-03 | M | OFF-S stack on T0-mini ≥ 90% (-O0), ≥ 75% (-O2), ≥ 85% PE, wrong-unlabelled ≤ 2%; payoff top-1 ≥ 90% with identical output after symbol rename | D2-R2, D3-R3 (B + narrow A), D3-R4, D3-F3, D3-F5, D1-F9, D5-H5 |
| SP-05 | Plan v1 for the stack family; honest templates; overrides as asserted facts | `supwngo/plan/`, `cli.py` (`pwn`/`template`/`offset`/`report`), `cli_options.py` | SP-04 | L | On T0-dev stack classes: METHOD-R ≥ 80% and ≥ 30 pts over the majority-label baseline; cross-command agreement 100%; COMP-B ≥ 80%; no emitted script contains an unfilled zero offset; unfilled scripts exit 2 on 100% | D1-R2 (slice), D3-R2, D3-R6, D3-R7, D1-F1, D1-F2, D3-F12, D4-F11, D5-R1 (COMP) |
| SP-06 | Generator v1, held-out custody, public tier, nightly, pinned environment | `benchmark/gen/`, `benchmark/history/`, `tools.lock.toml`, `supwngo doctor`, Dockerfile | SP-02 (parallel with 03–05) | L | ≥ 300 dev and ≥ 150 held-out binaries (≥ 60 PE); reference solver fed truth reaches proof on ≥ 95% of ELF positives; first held-out report with dev-minus-held gap per metric; 7 consecutive nightlies with an identical skip set | D2-R7, D5-R2, D5-R3, D5-R4 (T0/T1), D3-R10, D5-R5, D5-R6, D5-F2, D5-F3, D5-F7, D2-F15 |
| SP-07 | Machine contract and public oracles | envelope decorator, exit codes, `tools --json`, `verify`, `try`, bubblewrap runner, local libc-database | SP-05 | M | Contract test `ok == (exit == 0)` and one-document stdout for 100% of commands on T0; `verify` refuses 8/8 `broken_*` fixtures and credits the control; 0 outbound connections in the suite; agent-arm pilot run | D4-R1, D4-R2, D1-R8 (envelope), D4-F6, D4-F8, D4-F10, D1-F11, D1-F12 |
| SP-08 | Static and stripped binaries | `facts` `libsig` analyzer (FunctionID `.fidb` from libc-database), per-function canary, syscall-wrapper roles | SP-03, SP-06 | M | On static T0 builds ≥ 90% of libc sinks named; OFF-S and METHOD-R on the static/stripped axes within 15 pts of dynamic/unstripped; per-function canary false positives 0 on static no-canary fixtures | D2-R6, D2-F14, D2-R8 (canary) |
| SP-09 | Detectors as evidence-graded queries; `report` renders them | `supwngo/detect/` (stack, format string, allocator role, dangling slot, integer, off-by-one), cwe_checker bake-off, `reporting/adapter.py` | SP-05, SP-06 | L | T0-held: stack/format recall ≥ 0.7 and precision ≥ 0.6 at E1+; heap/integer recall ≥ 0.4; 0 E1+ findings on ≥ 95% of patched twins; `report` names the bug function on ≥ 70% of dev | D2-R3, D2-F1, D2-F6, D2-F7, D2-F8, D2-F12, RT-09 and RT-10 (re-scoped), D3-F8, D3-F9 |
| SP-10 | Non-stack plans from executor gates | `contracts.py` `plan()`, `TechniqueSpec` for heap/integer/UAF/data-only executors, distance kinds | SP-05, SP-09 | L | METHOD-R all classes ≥ 70% dev and ≥ 60% held; OFF non-stack ≥ 60%; gate-derived plans beat `StrategySuggester` on T0 | D3-R9, D3-F6, D1-R2 (rest), D1-F7 (ordering as prior) |
| SP-11 | Dynamic confirmation; `autopwn` executes the plan; legacy fallback off | breakpoint-at-sink confirmer, RIP proof, orchestrator global deadline, `cli.py:2953,3565` | SP-07, SP-10 | M | OFF-D agrees with OFF-S on ≥ 98% where both answer; RIP ≥ 80% of runnable ELF stack positives; `solve` proof rate on corpora not below SP-02's; COMP-A2 ≥ 80% | D3-R5, D2-R4 (ELF), D1-F7 (deadline), I-2 |
| SP-12 | Deletion and packaging | per §4 schedule; reachability test; empty eager imports; `pyproject` only; docs → `ARCHITECTURE.md` + `ROADMAP.md` | SP-11 | M | `exploit/` ≤ 70k LoC; `--version` < 0.5 s cold; reachability test green; passcard unchanged | D1-R5, D1-R9, D1-R10, D1-F4, D1-F10, D1-F13, D1-F14, D2-F9, D4-F1, D5-R7, D5-R8, D5-F9 |
| SP-13 | LLM substrate and hook 1 (payoff nomination) | `supwngo/llm/` (client, router, ledger, hypothesis), injection fixtures | SP-07, SP-06 | M | Adversarial-stub run: 0 builder inputs without an oracle record in 1,000 runs; `replay` byte-identical; hook 1 top-3 recall ≥ 90% on renamed held-out, beating `--llm off` by ≥ 10 pts, else deleted | D4-R4, D4-R5, D4-R6 (hook 1), D4-F2, D4-F5 |
| SP-14 | Hooks 2–3 and the two-arm agent evaluation | role labelling, vulnerability-hypothesis triage; `AgentFollower` on the local provider | SP-13, SP-09 | L | Verified heap/integer recall +25 pts over SP-09 on held-out with ≤ 10% of verified claims wrong on twins, else hook deleted; two-arm report published | D2-R5, D4-R6 (hooks 2–3), D4-R9 |
| SP-15 | Input reachability (conditional) | menu/format recipes; AFL++ QEMU cmplog for parsers; LLM grammar hook | SP-11, SP-14 | L | Fraction of menu/format T0 targets where execution reaches the vulnerable function: +30 pts over the SP-11 baseline | D4-R8, D2-F10, D2-R4 (rest) |
| SP-16 | PE hardening and release 3.0 | MSVC fixtures (if supplied), `/GS` cookie, PE protections, generated MCP wrapper, `explain` as plan narrator or frozen | SP-08, SP-12 | M | PE (mingw + MSVC) DECOMP ≥ 95%, OFF-S ≥ 85%; MCP tool list == manifest | D2-R9, D1-R4 (grown), D4-R11 |

**S6 draft disposition.**

- **RT-08 — keep, re-scoped (SP-02).** The three-line gate widening alone leaves `recommended` at STACK_PIVOT. SROP is built at 0.6 (`strategy.py:582`), below the 0.65 literal at `strategy.py:770`, which D3-F7 attributes to STACK_PIVOT, under the sort at `strategy.py:279`. The steps would still say "Find/write '/bin/sh'" (`strategy.py:586`). SP-02 adds role tiering and an honest rax-control note, and tests through `analyze()` instead of the draft's tautological boolean test.
- **RT-09 — drop as drafted.** "≥ 1 alloc site" is not a PASS metric, and regexes on names fail on stripped binaries and on `dealloc`-style names (D3-F8). The intent returns in SP-09 as name-free allocator-role inference over facts (HYP-8).
- **RT-10 — drop as drafted.** The section is empty (`S6-PLAN-DRAFT.md:170`). The intent returns in SP-05 (`report` shows plans) and SP-09 (evidence-graded findings).
- **S7 (cleanup + 2.2.0).** The tag moves to the end of SP-02; cleanup becomes SP-12.

**Rejected or trimmed recommendations.**

- D1-R6: an L refactor of demoted code.
- D1-R7: sharding across Sparks. They are ARM64; the runner is the passcard with `--jobs`.
- D1-R4 as an upfront `Image` protocol: it grows from `facts.program` instead.
- D2-R7's ≥ 800 binaries: start at 450 and grow when variance demands it.
- D2-R9's AArch64 cell: not on this roadmap.
- D5-R4's 500 Juliet pairs: 100 in SP-09.
- D4-R7 and D4-R10: see DEC-23.

### 6. Detailed plans for the first four sprints

#### SP-01 — Passcard v0 and the five lies

**Goal.** A committed, falsifiable baseline, and zero cells where the tool crashes or reports failure as success.

**Order of work.** The harness comes first (day 1) and the baseline is committed before any fix, so each fix lands as a visible delta.

**Files.**
- New: `benchmark/passcard.py`, `benchmark/truth/<target>.yaml` (7), `benchmark/baselines/passcard.json`, `tests/test_passcard_selftest.py`, `tests/test_no_target_identifiers.py`, `tests/fixtures/src/{eof_spin.c, nomain.S, fullrelro.c}`.
- Changed: `supwngo/exploit/offset_finder.py`, `supwngo/analysis/_angr_subprocess.py`, `supwngo/analysis/decompile.py`, `supwngo/analysis/ghidra_scripts/SupwngoDecompile.java`, `supwngo/cli.py`, `supwngo/core/binary.py`, and the RELRO consumers listed below.

**Design.**

1. **Passcard v0.**
   - Invocation: `passcard.py --set smoke|t0 --truth DIR --out DIR --jobs N --timeout 240`.
   - One subprocess per target and command, with its own process group, `cwd` set to the challenge directory (this fixes the SCORECARD interpreter defect), `TMPDIR` and `XDG_CACHE_HOME` isolated, and load average recorded per cell.
   - It scores METHOD-R0, METHOD-L, OFF (dynamic for now), DECOMP, ROBUST and TIME. Output is JSONL plus a markdown table. The verdict vocabulary is `PASS|FAIL|ABSTAIN|ERROR|VOID`.
   - A pre-flight marks a cell `VOID` when the target's `PT_INTERP` does not resolve.
2. **Offset crash.** Wrap the refine-loop `subprocess.run` calls at `offset_finder.py:545-556` exactly as `test_crash` is wrapped at `:504-520`, and kill the process group. Add `confidence`, `kind` and `error_code` to `OffsetResult`. `find_offset` first checks the interpreter and returns `error_code="target_not_executable"`. `offset --json` exits 2 on a negative result (`cli.py:934-935`).
3. **angr sentinel.** At `_angr_subprocess.py:240-246` return `{"found": True, "ok": False, "error": …, "code": None}`. `Decompiler._decompile_angr` returns `None` when `ok` is false. Optionally try `normalize=True` and `cfg.model` (D2-F5's probable cause, UNVERIFIED); keep it only if a fixture then yields real C.
4. **RELRO.** Add a `Relro` enum (`NONE|PARTIAL|FULL`) on `Protections`; `relro` stays as the display string. Replace every comparison my grep found:
   - `strategy.py:454, 976`; `leak_finder.py:329`; `imports.py:400, 499`; `pie_bypass.py:191`; `chainer.py:299`; `got_plt.py:106, 259, 310`.
   - Normalise the already-correct sites in `format_string.py`, `bypass.py`, `protections.py` and the executors.
   - This is wider than D1-F3 listed.
5. **`-f main` default.** `cli.py:2070-2071` stops forcing `main`; with no `-f` it sends an empty selector. The Java fallback (`SupwngoDecompile.java:87-96`) becomes `main` → function at program entry → first function, and emits `selected_by`. The angr path gets the same order.
6. **Answer-key leak.** Remove `"fill_ammo"` from `offset_finder.py:887`. The lint test parses `supwngo/**/*.py` and fails on any evaluation-target slug or symbol in string literals or identifiers. Comments are counted against a committed ratchet (37 total today).

**Tests and RED proofs.**

| Item | RED proof (fails on `1741b34`) |
|---|---|
| Passcard | A shim CLI returning constant `ret2system` and `offset=0` must fail METHOD-R on ≥ 5/7 truth entries and OFF on 7/7. A shim echoing truth must pass. A harness that scored "parses as JSON" (the `retest_matrix.py` failure, D5-F1) would not distinguish the two. |
| Offset | Unit: monkeypatch `subprocess.run` to crash during the bisect and raise `TimeoutExpired` in refine; old code propagates. Fixture: `eof_spin` (loops on EOF); `offset --json` must emit one JSON document with exit 2. |
| Not executable | `fullrelro.c` built with `-Wl,--dynamic-linker=./nope/ld.so`; expect `error_code == "target_not_executable"`. Old code says "Could not determine offset with any method". |
| Sentinel | Stub `Decompiler` whose `codegen` is `None`; expect `ok: False` and CLI exit ≠ 0. Old code returns 32 characters as code. |
| RELRO | Full-RELRO fixture; `StrategySuggester(...).analyze()` must not contain RET2DLRESOLVE. AST lint: no `.relro` compared to a string literal outside `core/`; about 20 hits today. |
| Default function | Hermetic: capture the selector passed to `_decompile_ghidra`; old value is `name:main`. Tool tier: `nomain.S` gives non-empty code with `selected_by == "entry"`. |
| Lint | Red today on `offset_finder.py:887`. |

**Risks.**
- Changing the exit code of `offset`/`decompile` may break existing harness cells. Mitigation: `run_bench` and `retest_matrix` read JSON, not exit codes (D4-F6, UNVERIFIED); grep the callers first.
- Truth labels are judgement calls. Mitigation: accept-sets are versioned and the DEC-7 default is noted in the file header.

**Exit.** As in the sprint map.

**Rollback.** Each fix is its own commit; the passcard is additive.

#### SP-02 — Method-surface honesty, passcard v1, T0-mini, gate

**Goal.** `pwn` and `template` stop emitting constants, PASS (a) is exercisable on the scored commands, and a non-HTB set exists so SP-03/04 are measured on something other than seven targets.

**Files.** `supwngo/exploit/strategy.py`, `supwngo/cli.py`, `supwngo/cli_options.py` (new home for the override decorator), `supwngo/exploit/auto.py` (three minimal patches), `benchmark/gen/{templates/*.c, build.py, truth_dwarf.py}`, `benchmark/passcard.py`, `scripts/htb_rescore.py`, `scripts/ci/gate.sh`, `Makefile`.

**Design.**

1. **Role tiering (RT-08 re-scoped).**
   - `ExploitStrategy` gains `role ∈ {terminal, enabler, speculative}` and `evidence: list[str]`.
   - STACK_PIVOT is an `enabler`. VARIABLE_OVERWRITE (unconditional, `strategy.py:272`), import-only FORMAT_STRING (`:464-471`) and NEGATIVE_SIZE_BYPASS (`:473-483`) are `speculative`.
   - `report.recommended` is the best `terminal`. `pwn --json` gains `speculative[]`. `report.strategies` keeps every entry, so the orchestrator's ordering (`orchestrator.py:1118`) is unchanged.
   - SROP gate: `has_syscall and (has_sigreturn or has_syscall_ret)`, with `rax_control: "pop"|"syscall_return"`. The steps are rewritten for the syscall-return path, with no "/bin/sh write" step when there is no writable segment.
   - This is rule-based, not confidence tuning. On a static binary without pop gadgets ROP_EXECVE is already rejected (`strategy.py:414`), so SROP becomes the only terminal.
2. **Overrides on `pwn`, `template`, `offset`.**
   - Move `target_override_options` (`cli.py:66-109`) to `cli_options.py`. Add aliases `--winfun` → `--win` and `--eip`/`--ret` → `--ret2`, plus `--strict-overrides`. The flag turns the warn-and-fallback documented in the `--win` help text (`cli.py:106-107`) into exit 2.
   - Extract the report patch at `orchestrator.py:1088-1094` into `apply_win_override(report, override)` and call it from `pwn`. `pwn` also gains `--offset`.
   - `template` passes the resolved win and offset into the generator.
3. **`template` honesty (minimal; replaced in SP-05).**
   - `-t auto` builds the suggester with a `GadgetFinder`, as `pwn` does (`cli.py:869`).
   - The map is total. An approach with no template exits 2 with `error.code="no_template_for_method"` instead of defaulting (`cli.py:1231`).
   - `auto.py:2761` becomes `if offset is not None`.
   - `auto.py:2776-2802`: a requested `ret2win` with no win function exits 2 with `missing_inputs:["win"]` instead of emitting the leak script.
   - JSON becomes `{requested, selected_method, emitted_template, inputs_resolved{}, inputs_required[], executes_target: true}`.
4. **Passcard v1.** Adds COMP-A1, COMP-B scaffolding (declared inputs compared with truth; golden-fill arrives with SP-05), and a `solve` column.
   - `htb_rescore.py:206` gates on `shell_proven`, not `shell_confirmed`.
   - Three reps, run from challenge directories, artefacts appended to `benchmark/history/*.jsonl` (un-ignored).
5. **T0-mini.**
   - Four structurally different stack templates: `gets` into a local, `read` with an over-long length, menu-gated `fgets`, and a struct-adjacent variable. Each has a payoff function named from a wordlist disjoint from every in-tree win list, plus a patched twin.
   - Axes: `-O0/-O2` × PIE × canary × {ELF64, mingw PE64, PE32}. That is ≥ 60 binaries.
   - Truth: build with `-g`, read the buffer location and CFA at the sink PC, then strip. ELF uses pyelftools. PE uses `x86_64-w64-mingw32-objdump --dwarf`. The objdump parser is cross-validated against pyelftools on the ELF twins.
   - Non-computable locations are dropped with a counted reason.
   - The method label comes from a template × protections table.
6. **Gate.** `make gate` runs the unit tier without `-x`, then the passcard on T0-mini (and S0 if present), compares against `benchmark/baselines/passcard.json`, and blocks any PASS→FAIL flip not listed in the PR. `SUPWNGO_REQUIRE_TARGETS=1` makes a missing-fixture skip a failure (D5-R5).

**Tests and RED proofs.**
- Tiering: a stub static binary with `syscall; ret`, no pops and `leave; ret`; `analyze().recommended.approach is SROP`. Old tree gives STACK_PIVOT. A negative stub with no syscall must not list SROP.
- Overrides: on a ret2win fixture whose payoff has a random name, `pwn --win 0x… --strict-overrides --json` recommends ret2win with the address. Old tree: no such option. `template --win X` output contains the address verbatim. `--win nosuchsym --strict-overrides` exits 2.
- Template: on a static fixture `-t auto` must not emit `ret2system` (old tree does). `--offset 0` must appear in the script (old tree drops it).
- T0-mini truth: a reference payload built from truth reaches the payoff on ≥ 95% of runnable ELF positives. A mutated truth (off by 8) must fail that check.
- `htb_rescore`: a synthetic result with `shell_confirmed=True, shell_proven=False` must score UNSOLVED (old tree: SHELL_ACCESS).

**Risks.**
- The `solve` 7/7 may have regressed (HYP-9). Response: record it and do not repair before SP-11.
- The DWARF-on-PE parser may be fragile. Response: restrict the mini set to locations it handles and report the extraction rate.
- A `pwn --json` shape change. Mitigation: additive keys only.

**Exit.** As in the sprint map.

**Rollback.** Tiering sits behind `StrategyReport.to_dict(legacy=True)` for one release.

#### SP-03 — Facts v1

**Goal.** One Ghidra analysis per binary, persisted. `decompile` on ELF and PE becomes a lookup.

**Files.** New `supwngo/facts/{model.py, store.py, ghidra.py, loader.py}` and `supwngo/analysis/ghidra_scripts/SupwngoExport.java` (the directory must stay near-empty, `decompile.py:246-253`). Changed: `supwngo/analysis/decompile.py`, `supwngo/cli.py` (`facts`, `decompile`).

**Design.**

- **Store.** `${XDG_CACHE_HOME:-~/.cache}/supwngo/<sha256>/` containing `meta.json`, `program.json`, `functions.jsonl`, `strings.jsonl`, `decomp/<rva>.c` and `ghidra/` (the persisted project).
  - `meta.json` holds `{schema:"facts/v1", exporter_version, ghidra_version, image_base, wall_s, loadavg, degraded[]}`.
  - Writes are atomic (temp + rename) under `flock`, so parallel callers wait instead of double-analysing (D1-F11).
  - The cache key is sha256 + exporter version + Ghidra version.
- **Export.** One `analyzeHeadless -import … -postScript SupwngoExport.java OUT` run with `stdin=DEVNULL` (the current `Popen` at `decompile.py:280-286` inherits stdin), `-analysisTimeoutPerFile`, and no `-deleteProject`. Later single-function requests use `-process -noanalysis` against the persisted project.
- **Schema.**
  ```
  program:  {format, arch, bits, entry_rva, image_base_ghidra, protections{nx,pie,relro:enum,canary_symbol}}
  function: {rva, name, size, is_thunk, is_external, is_library:null, callers[], callees[],
             frame:{uses_fp, locals:[{name, off_ret, size, type}], canary_check:bool},
             callsites:[{rva, callee, args:[{kind:const|stack|global|reg|unknown, value}]}],
             decomp: path|null}
  string:   {rva, value(≤256 bytes, escaped), xrefs:[{from_rva, func_rva}]}
  ```
  All addresses are RVAs (DEC-10). `off_ret` is relative to the return-address slot, which is Ghidra's native stack reference (D3-R3). Every record carries `provenance: static` and `producer: ghidra_export@<version>`.
- **Decompile budget.** Non-thunk, non-external functions in order: entry-reachable first, then the rest, until `--budget` (default 120 s). Leftovers are marked `decomp: null` and fetched on demand. `meta.degraded` records `decomp_incomplete`.
- **CLI.**
  - `supwngo facts BIN [--json] [--section program|funcs|frame|callsites|strings|xrefs|decomp] [-f FUNC] [--refresh] [--budget S] [--no-decomp]`.
  - `decompile BIN [-f X]` reads facts. Default selection is `main` → first argument of `__libc_start_main` → entry → largest entry-reachable user function.
  - `--angr` is explicit, never a silent fallback. `--legacy-backend` keeps the old path for one release.
- **Format sniffing.** `loader.py` reads magic bytes and uses lief for PE headers, so `facts` and `decompile` do not depend on `Binary.load`. D1-F9 and D2-F13 report that it is ELF-only (`binary.py:186-190`, reviewer-cited).

**Tests and RED proofs.**
- Structural goldens on six fixtures (dynamic PIE ELF, static no-libc asm, stripped, canary, mingw PE64, PE32). The function named in truth is present; the frame local for the buffer has `off_ret` equal to DWARF truth; the `read`/`fgets` call site has its destination argument with `kind=stack`. The comparison is against independent truth, and an exporter mutant that shifts `off_ret` by 8 must fail.
- Cache: with `Popen` counted, the second call spawns 0 Ghidra processes. Two concurrent processes produce 1 export. A truncated `functions.jsonl` triggers re-export. A forced timeout leaves no partial store and yields `degraded:["timeout"]` with exit 2.
- PE: `facts` and `decompile` on PE fixtures produce 0 tracebacks. `report`/`pwn` on PE exit 2 with `unsupported_format`.
- PIE: `decompile -f 0x<rva>` and `-f name` return the same function on a PIE fixture (D2-F3 regression).

**Risks.**
- **Java API coupling to Ghidra 12.x.** Mitigation: schema version, goldens, `supwngo doctor` checks the version.
- **Static 877 KB binaries exceed the budget.** Mitigation: the decompile budget and deferral, analyser tuning; SP-08 library marking shrinks the set.
- **Host contention** (load 26, BRIEF §7). Mitigation: TIME cells above a load threshold are flagged invalid; the nightly runs off-peak.
- **Warm path is still a JVM start for uncached functions.** The "≤ 2 s warm" criterion applies to cached lookups only; HYP-2 measures `-process`.

**Exit.** As in the sprint map.

**Rollback.** The package is additive; `--legacy-backend` remains.

#### SP-04 — Static distance, payoff, static-first `offset`

**Goal.** "See the offset on all" for stack sinks on ELF and PE without executing anything, and ret2win without an answer key.

**Files.** New `supwngo/analysis/stack_layout.py` and `supwngo/analysis/payoff.py`. Changed: `supwngo/cli.py` (`offset`), `supwngo/exploit/offset_finder.py` (becomes the `--dynamic` confirmer), `supwngo/exploit/strategy.py` (`_analyze_special_conditions` uses `payoff`).

**Design.**

- **Sink table.**
  - Imports by identity: `read`, `gets`, `fgets`, `scanf %s`, `recv`, `strcpy`, `memcpy`, `fread`; on PE `ReadFile`, `gets`, `fgets`, `scanf`.
  - Raw `syscall` with constant `eax=0`.
  - In-binary syscall wrappers (a function whose body sets a constant `eax` and executes `syscall`), which get a role. This covers no-libc static binaries before SP-08.
- **Record.**
  ```
  SinkRecord{func_rva, callsite_rva, sink, dest:{kind:stack|stack_indexed|global|unknown, off_ret},
             length:{kind:const|unbounded|accumulated|unknown, value},
             canary:{present, off_ret}, reaches:[locals|canary|saved_bp|ret],
             distance:{kind:buf_to_ret, value}, canary_distance,
             estimator:ghidra_frame|prologue|both, agree:bool|null,
             provenance:static, abstain_reason:null|str}
  ```
- **Estimator B (primary).** From `facts.callsites[].args`. A `PTRSUB(sp, c)` destination gives `distance = -off_ret`. A base-plus-index destination (the ancient_interface accumulator shape in SPOTCHECK) gives `dest.kind=stack_indexed`, `length.kind=accumulated` and a `reaches` set, not a single number.
- **Estimator A′ (narrow fallback).** A capstone pass inside the Ghidra function bounds: prologue (`push rbp; mov rbp,rsp; sub rsp,N`) plus the nearest `lea r,[rbp-X]` or `[rsp+Y]` feeding the sink. It runs when B abstains; SPOTCHECK shows it gives 40 on the hand-written asm case.
  - When both answer, `agree` is recorded. On disagreement the tool emits both, labelled, with no `primary` (HYP-3).
  - It abstains on `alloca`, inlined `rep movs`, or an untracked stack pointer.
- **`offset` CLI.** Static-first. Output is `{distances:[SinkRecord…], primary}`. Ranking: reaches `ret` and length greater than distance, then reaches `canary`, then the rest.
  - `--dynamic` runs the existing finders as a non-fatal confirmation.
  - `--vuln-func` and `--sink` narrow the search.
  - Exit 2 when every record abstains, with reasons.
- **Payoff.** Score functions by:
  - calls `system`/`exec*`, or an `open → read → write/puts` chain within the function;
  - cross-references to flag-like or `/bin/sh` strings;
  - unreachability from entry in the call graph.
  - Compare constants on parameters become `required_args`. Names break ties only. Output is the top three with evidence.
  - `strategy.py:178-182` is no longer consulted by `pwn`. The other lists die with their modules in SP-10 to SP-12.

**Tests and RED proofs.**
- Exactness against DWARF truth on T0-mini, per build axis. The truth is independent, and SP-02's reference-payload check already validated it.
- Abstention: `alloca` and `-O2` inlined-copy fixtures must return `abstain_reason`, never a number. A mutant that returns the first `sub rsp` value plus 8 (today's `_read_frame_size` heuristic, `walkthrough/facts.py:632-657`, reviewer-cited) must fail the canary and `-O2` cells.
- Rename invariance: `objcopy --redefine-sym` twins give byte-identical `payoff` and `offset` output modulo names. A name-list finder (the `WIN_NAMES` approach at `offset_finder.py:881-889`) fails this.
- Decoy: a do-nothing `win()` beside a randomly named real payoff; top-1 must be the real one.
- Over-match: a function that only calls `read` must not be a payoff. The current `_find_by_file_ops` flags it (`offset_finder.py:969-973`).

**Risks.**
- **`-O2` frames.** Response: abstain with a reason; the −1 penalty applies only to wrong answers.
- **Multiple sinks in one function.** Response: emit all, ranked; never a bare number.
- **PE `/GS` and SEH frames.** Response: mingw only for now; cookie detection is in SP-16.
- **Statically linked libc sinks are unnamed until SP-08.** Response: syscall-wrapper roles cover part; the gap is measured on the static axis.

**Exit.** As in the sprint map.

**Rollback.** `offset --legacy` keeps the crash-driven path for one release.

### 7. Tools and technologies to add

| Tool | Decision | Sprint | Offline install path | Reason |
|---|---|---|---|---|
| Ghidra Java exporter | Adopt now | SP-03 | Already installed; script in-tree | Basis of Bet 1. |
| PyGhidra | Optional, evaluate | SP-08 spike | Wheel shipped inside the Ghidra distribution (UNVERIFIED for 12.1.3) into the wheelhouse | Only if it cuts exporter maintenance; not a dependency (DEC-3). |
| Ghidra FunctionID | Adopt | SP-08 | Build `.fidb` headlessly from static libcs in the local libc-database mirror | Names libc in static/stripped binaries (D2-R6). |
| Ghidra BSim | Later | after M3 | Ships with Ghidra | A fuzzier fallback only if FunctionID coverage fails (HYP-15). |
| Ghidra Version Tracking | Later | — | Ships with Ghidra | Patch-diffing; would replace `analysis/diff.py`. Not on the PASS path. |
| rizin | Optional | SP-08 | Static release tarball, sha256-pinned | Second opinion on function boundaries; FLIRT fallback. Not a second backend. |
| Qiling / Unicorn | Skip for now | revisit SP-16 | pip wheelhouse | PE dynamic confirmation is out of scope (DEC-12). Remove the unused `unicorn` hard dependency in SP-12 (D1-F13, reviewer-cited). |
| wine | Optional | SP-06 | Distro packages mirrored | Only to validate that PE fixtures crash at the truth offset; never in the product path. |
| AFL++ (QEMU mode, cmplog, QASan) | Later, conditional | SP-15 | Source tarball + vendored QEMU, built in the image | Parser targets, if HYP-17 holds. One fuzzer only. |
| cwe_checker | Evaluate, then adopt or skip | SP-09 | `cargo vendor` tarball; Ghidra 12 compatibility UNVERIFIED | Baseline for D2-R3; adopt its checks where it beats ours on T2. |
| one_gadget | Keep, pin | SP-06 | Ruby gem mirrored | Already wrapped (`cli.py:845-847`). |
| seccomp-tools | Adopt, small | SP-10 | Ruby gem mirrored | A sandbox fact that changes method choice. |
| patchelf / pwninit | Adopt patchelf; skip pwninit | SP-02 / SP-06 | Distro package | Run targets against shipped loaders; replaces the snap-loader accident (D5-F7). pwninit downloads from the network. |
| libc-database mirror | Adopt | SP-07 | rsync a snapshot to a local path; `libc_database_url` defaults to it | Removes `libc.rip` calls (`remote/libc_db.py:41-42`, reviewer-cited). |
| pwndbg | Adopt, test harness only | SP-11 | Release tarball with vendored dependencies | Scripted RIP proof. Plain gdb Python suffices in the product. Not GEF as well. |
| mingw-w64 | Adopt (installed) | SP-02 | Installed | PE fixtures with DWARF truth. |
| MSVC | Owner question | SP-16 | Owner-supplied binaries or a Windows build VM | Real PE is mostly MSVC (DEC-13). |
| bubblewrap | Adopt | SP-07 | Distro package | No-network sandbox for `verify`/`try` and the passcard. Lighter than containers. |
| Containers | Adopt for reproducibility | SP-06 | `ubuntu:22.04` by digest + wheelhouse + `tools.lock.toml` | The corpora are pinned to glibc 2.35 (D5-F7). |
| RetDec, Triton, SymCC/SymQEMU, BAP, LibAFL, honggfuzz/libFuzzer wrappers | Skip / remove | SP-12 | — | Duplicates or dead integrations (D2 tools table). |
| IDA, Binary Ninja | Skip | — | — | Licensed. The facts schema allows a backend later. |
| angr / angrop | Demote to optional extra | SP-12 | Wheelhouse | Directed, budgeted helper only (DEC-2). |

### 8. LLM integration plan

**Position.** No hook ships before the deterministic baseline it must beat exists (SP-09) and before held-out renamed variants exist (SP-06). Every hook has a kill criterion against `--llm off`. Offsets, addresses, gadgets, libc identification, verification and scoring are never model outputs (D4 capability table).

#### Hooks, in priority order

| # | Hook | Attach point | Closed-set output | Oracle | Role | Success measure | Kill criterion |
|---|---|---|---|---|---|---|---|
| 1 | Payoff nomination | `analysis/payoff.py`, after deterministic ranking, when top-1 evidence is weak | ≤ 3 function ids from the facts candidate list | Static: the function reaches exec/open-write or references a flag-like string. Dynamic: a ret2win receipt through `try`. | `bulk` | Top-3 recall ≥ 90% on renamed held-out; confirmed-false ≤ 5% on decoys | Lift < 10 pts over `--llm off` |
| 2 | Role labelling (allocator, free, parser, menu handler) | SP-09 allocator-role query, on stripped or unnamed functions | Enum label per candidate function id | A gdb trace at the candidate addresses: the allocator returns distinct writable pointers, and a freed pointer is returned again later | `bulk` | Non-zero sites on all custom-allocator variants; zero on controls | Deterministic inference (HYP-8) already ranks the pair top-3 |
| 3 | Vulnerability-hypothesis triage | Per function, over facts decomp + frame + call sites | `{function id, class enum, sink callsite id, source id}` | SP-09 queries re-run scoped to the function, then the SP-11 confirmer. Unconfirmed claims stay E2 hypotheses. | `reason` | Verified heap/integer recall +25 pts; ≤ 10% of verified claims wrong on twins | < 10% additional confirmed true positives (HYP-20) |
| 4 | Input recipe / grammar | SP-15, menu dialogue or file format | JSON grammar for `fuzzing/grammar.py`; AFL dictionary tokens | A breakpoint or coverage shows the named function is reached | `reason`/`hard` | +30 pts reach rate | No reach gain; or injection flips > 0 outcomes |

Not built: method reordering and prose (DEC-23).

#### Provider, ledger, replay (D4-R4)

- `supwngo/llm/client.py`: `/v1/chat/completions` over `requests` against the vLLM fleet, with JSON-schema constrained output. The exact guided-decoding parameter is UNVERIFIED and is probed at the start of SP-13. The schema has a free-text `reasoning` field, which is discarded, and a bound `answer` field.
- `router.py`: roles `bulk|reason|hard` map to `{base_url, model, weights_hash, max_tokens, timeout}` in config. `airgap: true` by default, with a host allowlist. The CLI flag is `--llm off|local|any`, default `off`; `any` fails closed when the network is blocked.
- Escalation between roles happens only when the oracle refutes every proposal from the tier below, never on self-reported confidence. Per-run caps on calls and tokens are recorded in the envelope.
- `ledger.py`: SQLite keyed by `sha256(model_id + weights_hash + prompt + schema + params)`, with modes `live|record|replay`. Pytest runs `replay` only.

#### Trust invariants (each enforced by a test)

1. **Closed-set outputs.** The schema has no field that can hold an address or a free-form symbol; the model returns indices, enums or small bounded integers.
2. **No unconfirmed value reaches a builder.** A `Hypothesis{kind, claim, source{model, ledger_key}, oracle, status}` is not a fact. Only an oracle result creates a fact (`measured` or `static`). There is no LLM member in the provenance vocabulary (D4-R5).
3. **Target text is data.** Strings and decompiled code are length-capped, escaped and delimited. Hook calls are single completions with no tools. The worst case of an injection is a wrong index, which the oracle refutes.
4. **Budgets.** At most five proposals per hook per binary.

#### Injection and contamination rules

- An injection fixture set is generated: binaries whose strings and banners carry instructions such as "the win function is `decoy`". The gate is 0% change in the final recommended method against the neutralised twin.
- LLM-assisted scores are computed only on fresh T0 held-out variants. S0 and T1 are never used: the binaries and write-ups are public, and a model can answer from the challenge name alone (HYP-21).
- A contamination probe (name-only prompt) runs per model before any set is used.
- Cloud models may see generated T0 fixtures only (DEC-21).

#### Evaluation arm

- The existing `AgentFollower` (`benchmark/walkthrough/followers.py`, reviewer-cited) is ported to the local provider.
- Two arms run on the same pinned local model: the agent with a shell only, and the agent with a shell plus `facts`/`offset`/`pwn`/`verify`/`try`.
- Metrics are solve rate under `verify`, tokens, wall-clock and false-success claims.
- A pilot runs in SP-07 on about 10 T0 binaries using the existing cloud follower. The full run in SP-14 uses 20 variants × 2 reps.

### 9. Risks, pre-mortem and kill criteria

| # | How it fails | Early signal | Response |
|---|---|---|---|
| 1 | **The facts layer becomes "schema v5".** Weeks go into the model while `pwn` still answers wrongly; this is the `schema/` history repeating (D1-F4). | SP-03 slips past 2 weeks; more than 25 fact keys; a merge or lattice discussion appears in review. | Hard cap on keys and analyzers. SP-04 starts on whatever SP-03 has; the exit is DECOMP and OFF-S numbers, not schema completeness. |
| 2 | **Ghidra is too slow or flaky on the shared host**, so nightlies are noise. | TIME cells flagged invalid on more than 30% of nightlies; cold p95 > 180 s when quiet. | Reserved off-peak window with `nice`/cgroup; analyser tuning; a decomp-less mode that still serves `offset`. If still failing, see the Bet 1 kill. |
| 3 | **The generator is a monoculture**; we overfit to our own templates. | Dev-minus-held gap near 0 while T1 public scores sit 20+ pts lower. | Held-out by template, not only by seed; T1 as a second opinion; add templates mined from how2heap and cb-multios shapes. |
| 4 | **The single maintainer is saturated**; planner, generator and contract all land half-done. | Two consecutive sprints miss their exit; passcard baselines not updated. | The sprint map is strictly ordered. SP-06 is the only parallel track and is agent-heavy. Cut M4 first, then SP-14, then SP-08. |
| 5 | **Non-stack classes do not yield to static plans**; gates need dynamic menu facts and heap METHOD-R stays low. | SP-10 held-out METHOD-R below 50% on heap/integer; most plans carry `unknown` preconditions. | Scope non-stack to "class + primitive site + distance kind + required inputs" (DEC-8) and rely on `--measure` for the rest. Bring hook 3 forward. Do not write more executors. |

**Kill and pivot criteria per bet.**

- **Bet 1 (Ghidra facts).** If, after SP-04, OFF-S at -O0 on T0-dev is below 80%, or cold p95 exceeds 180 s on a quiet host: keep `facts` for decompile and add a second estimator (angr variable recovery or rizin). If PE DECOMP is below 80%, PE is descoped to "decompile via Ghidra, offset best-effort" and the owner is told.
- **Bet 2 (one plan).** If, after SP-10, held-out METHOD-R fails to beat the majority-label baseline by ≥ 20 points: stop planner work, ship `pwn` as "findings + distances + required inputs" with no single recommendation, and move selection to the agent.
- **Bet 3 (toolbox and oracle, then LLM).** If the two-arm evaluation shows the toolbox improves neither solve rate nor cost by ≥ 25% (HYP-12): narrow the product to `facts` + `verify` + corpus and freeze `plan`/`template` at their PASS level. Any hook that does not beat `--llm off` by its threshold is deleted in the sprint that measures it.

### 10. Hypotheses register

| ID | Claim (sources) | Cheapest experiment | Falsifier | Sprint | If falsified |
|---|---|---|---|---|---|
| HYP-1 | Ghidra frame + P-code gives the exact stack distance on ≥ 90% of -O0 and ≥ 75% of -O2 fixtures (D2-H1, D1-H4, D4-H6, D5-H5, D3-H4). | SP-04 against DWARF truth. | Below 80% at -O0, or no better than the dynamic finders on runnable ELF. | SP-04 | Bet 1 kill path: add a second estimator. |
| HYP-2 | The Ghidra cost is per-invocation plus contention; `-process` on a persisted project is ≤ 30 s (D1-H3, D2-H2; already CONSISTENT in SPOTCHECK). | Time cold vs `-process -noanalysis` on a quiet host. | Warm > 30 s on a small dynamic binary. | SP-03 | Precompute all decomp at export; investigate script and JVM flags. |
| HYP-3 | Agreement between the frame and prologue estimators predicts correctness (D3-H5). | Same data as HYP-1. | More than 2% of agreeing pairs wrong. | SP-04 | `agree` is not a confidence signal; require OFF-D for "confirmed". |
| HYP-4 | The engines disagree on most binaries today (D1-H1). | Four-way agreement of `pwn`/`template`/`explain`/`autopwn` on T0-mini. | Agreement ≥ 80%. | SP-02 | SP-05 unification drops to polish; do SP-09 first. |
| HYP-5 | Method selection and win detection are name-driven (D3-H6, D5-H2). | Rename twins in T0-mini; compare METHOD and payoff before SP-04. | Drop under 10 pts. | SP-02 (baseline), SP-04 | Payoff rewrite loses priority to detectors. |
| HYP-6 | Performance falls sharply from -O0 to -O2; rbp-regex logic is a dead end (D2-H7, D5-H3). | Passcard split by optimisation level. | Under 10 pts of difference. | SP-04, SP-06 | Less urgency to replace executor-internal objdump scraping. |
| HYP-7 | Static executor gates classify better than `StrategySuggester` (D3-H2, D1-H7). | `gate_sweep.py`-style sweep of `is_applicable` over T0 with the dynamic profile disabled. | Gates not above the suggester on T0, or most need dynamic facts. | SP-05 (spike), SP-10 | Plans for non-stack classes come from SP-09 detectors, not gates. |
| HYP-8 | Allocator roles are inferable without names (D2-H6). | On stripped custom-allocator fixtures, rank by pointer-returning results stored to global tables. | True pair outside the top 3 on more than 30%. | SP-09 | LLM hook 2 becomes the primary route. |
| HYP-9 | `solve` still reproduces its recorded HTB results under `shell_proven` (D3-H1, D5-H10). | `htb_rescore --reps 3` from challenge directories. | Any target below 2/3, or the solved set shrinks under `shell_proven`. | SP-02 | Record it; `autopwn` gets no repair before SP-11; the "7/7" claim is struck from docs. |
| HYP-10 | RT-08 as drafted leaves `recommended` unchanged (D3-H3). | The SP-02 hermetic test through `analyze()`. | Recommended becomes SROP with the gate change alone. | SP-02 | Role tiering is unnecessary for this case; keep it for the constant-list problem. |
| HYP-11 | Breakpoint-at-sink recovers distances where cyclic crashing returns none (D3-H7). | Runnable T0 canary and menu fixtures. | Fewer than half recovered. | SP-11 | OFF-D is limited to crashable targets; reachability (SP-15) becomes a prerequisite. |
| HYP-12 | Agent + toolbox beats agent alone on cost, and possibly solve rate (D4-H1). | SP-07 pilot; SP-14 full two-arm run. | Under 25% improvement in tokens and wall-clock, and no solve gain. | SP-07, SP-14 | Bet 3 pivot. |
| HYP-13 | The held-out gap is large for the existing executor families (D5-H4, D1-H5). | Cold-measure the archived R3 set if recoverable; else T0-held under `solve`. | Held-out within 10 pts of in-sample. | SP-06 | FIRST_TECHNIQUES encodes real signal; keep it as planner priors, not just "frozen". |
| HYP-14 | ≥ 30% of `exploit/` is unreachable from any command (D1-H2). | Import-graph reachability + coverage over the passcard. | Under 15%. | SP-07 (measure) | SP-12 shrinks to legacy engines only. |
| HYP-15 | FunctionID from libc-database static libraries names ≥ 90% of libc sinks in static builds (D2-R6). | Static T0 builds across three glibc versions. | Under 70%. | SP-08 | rizin FLIRT or BSim; or syscall-role only. |
| HYP-16 | cwe_checker beats first-cut queries on some CWE classes (D2 §4, D3 §4). | Run both on T2. | It loses on every class or cannot run on Ghidra 12 offline. | SP-09 | Skip it; keep our own queries. |
| HYP-17 | Reaching the sink (menu or format) is the binding constraint for dynamic confirmation (D2-H8, D4-R8). | Count SP-11 confirm failures by cause. | Under 30% of failures are reachability. | SP-11 | Cancel SP-15. |
| HYP-18 | Review rounds do not predict fewer errata (D5-H8). | Count errata per merged unit across SP-01–06, reviewed vs light. | Reviewed units show ≤ half the rate. | SP-06 | Restore two-round review for M-sized work. |
| HYP-19 | Closed-set outputs + oracles drive hallucinated-value incidents to zero (D4-H3). | Adversarial stub, 1,000 runs. | Any builder input without an oracle record. | SP-13 | No hook ships until fixed. |
| HYP-20 | Local-model triage adds verified recall on heap/integer (D2-H5, D4-H4, D3-H8, D4-H2). | SP-14 on held-out, with the cloud arm on T0 to separate "idea wrong" from "model too weak". | Under 10% additional confirmed true positives locally, and also on cloud. | SP-14 | Delete hook 3. If only local fails, record the model gap and keep the hook off by default. |
| HYP-21 | Models are contaminated on HTB-7; naive integration is injectable (D4-H5, D5-H9, D4-H7). | Name-only prompts; injection fixtures without invariants. | ≤ 1/7 answered; under 5% flip rate. | SP-13 | The S0 exclusion stays regardless; delimiting drops in priority, the closed-set rule stays. |
| HYP-22 | The "load flake" is contention (D5-H6); more stringly-typed comparisons are live bugs (D1-H6); the Dockerfile cannot reproduce results (D5-H7). | 10 serial runs on a quiet host; the AST lint from SP-01 extended to `arch`/`os`; build the image. | Any failure when quiet; RELRO is the only mismatch; the image reproduces. | SP-01, SP-06 | Quarantine the test by name; drop the lint extension; keep the Dockerfile. |

### 11. Open questions for the owner

Only questions that block or reorder sprints are listed. The team proceeds on the stated default.

1. **Accept-sets (DEC-7; affects SP-01 truth files and every METHOD number).** If `solve` gets a proven shell with a technique other than the write-up's, is that "the right method"? *Default: yes, added to `methods_accept` after review.*
2. **Offset on non-stack bugs (DEC-8; affects SP-04 and SP-10).** Is "see the offset" the controlling distance of the actual primitive, with a kind? *Default: yes; stack and non-stack are reported separately.*
3. **Execution by default (DEC-9; affects SP-04/05).** May `pwn`, `template` and `offset` run the target without being asked? *Default: no; static by default, `--measure`/`--dynamic` opt-in, and `verify`/`try` always sandboxed.*
4. **Held-out custody (DEC-22; blocks the SP-06 exit).** Who holds the held-out seed, in a path no development agent can read? Can the archived R3–R5 corpora be recovered as a one-shot blind set? *Default: the owner's account holds the seed; R3–R5 are treated as lost unless supplied.*
5. **A quiet measurement window (blocks TIME gates from SP-03).** The x86-64 host ran at load 16–26 with 12 users during the scorecard. Can the nightly have a reserved off-peak slice or cgroup? *Default: run at night, flag cells above a load threshold as invalid, and gate TIME only on valid cells.*
6. **MSVC PE (DEC-13; reorders SP-16 versus SP-06).** Must MSVC-built binaries pass, and can you supply a toolchain or a set of binaries with PDBs? *Default: mingw only until supplied.*
7. **Local models (blocks SP-13).** Which model IDs and context lengths are served on the Sparks, and does the deployed vLLM support JSON-schema guided decoding? *Default: probe at SP-13 start and design to the weakest served model.*
8. **Cloud exposure (DEC-21; affects the SP-07 pilot and SP-14).** May cloud models see generated T0 fixtures and their decompilation for evaluation? *Default: yes for T0 only; never owner targets.*
9. **Frozen scope (DEC-16; affects SP-12 size).** Are `kernel/` (6k LoC) and `walkthrough/` (29k LoC) allowed to be frozen now, with `kernel/` moved to an extra and `explain` reduced to a plan narrator later? *Default: freeze both; no deletion without your word.*