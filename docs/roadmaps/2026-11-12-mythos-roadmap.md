> **Canonical roadmap.** This file is the Mythos 5-2 final roadmap (`docs/reviews/2026-11-12-mythos-roadmap/roadmap-final-mythos.md`, Status: FINAL) as adopted by the project. Amendments are appended in §14: orchestrator amendments from the SP-01 plan review, and those from the execution-enabled verify pass. It supersedes `docs/roadmaps/ROADMAP.md` for sequencing.

Status: FINAL (folded Daybreak Blue review), 2026-11-12

# supwngo — final roadmap, sprint map and plan (Mythos 5-2, 2026-11-12)

Nothing was executed for this synthesis or for the fold. Claims carry a `path:line` I read myself unless marked *(reviewer-cited)*, *(orchestrator-measured)* (SPOTCHECK / FOLD-NOTES / SCORECARD) or UNVERIFIED. Every draft citation the review marked WRONG was re-read in the tree before being changed; section 12 gives the disposition per review item.

### 0. Executive summary

- **Where it really is.**
  - `solve` reaches 7/7 on the HTB smoke set at `1741b34`, with 21/21 reps `shell_proven` and 0 hard errors *(orchestrator-measured, HYP-9)*. This is in-sample: the executors were written from these seven targets, so it is smoke, not generalisation evidence (DEC-5).
  - On the owner's PASS criteria the scored surfaces are far behind: method 2/7 (1/7 discriminative), decompile 3/7, and a constant `ret2system` template on 7/7 (SCORECARD).
  - Offset is 0 correct in 4 valid cells with one crash. The other 3 cells are VOID, not failures, because those targets could not execute from the repo root (SCORECARD:87-98).
- **Why the gap.** The commands PASS is measured on never consult vulnerability facts.
  - `pwn` ranks from protections, gadgets and imports with literal confidences (`strategy.py:272,279`).
  - `template -t auto` builds a suggester with no gadget finder and defaults unknowns to `ret2system` (`cli.py:1221,1231`).
  - `offset` is crash-only (`offset_finder.py:210-234`).
- **The tool reports failure as success in four confirmed places.**
  - The angr sentinel (`_angr_subprocess.py:244-246`).
  - Exit 0 with an `error` object (`cli.py:2129-2134`).
  - A silent "no offset" when the target cannot execute (SCORECARD:96-97).
  - A leaked answer key (`offset_finder.py:887`).
- **Thesis.** The defensible niche is an offline, binary-only, facts-backed toolbox in which every method, offset and finding is oracle-confirmed or explicitly labelled a hypothesis, with a verifier an agent cannot talk past. "Best in existence" is replaced by a per-release comparative table (§1.4).
- **Bet 1 — one Ghidra facts export per binary, cached. This is now provisional.**
  - The P-code experiment is exact on 3/3 compiler-built cases: ELF64 40, mingw PE64 72, PE32 76.
  - It abstains on 3/3 hard cases (hand-written asm, base+index accumulator, copy loop) and took 427 s cold on a static binary (SPOTCHECK:49-63).
  - DEC-2 is therefore gated by a three-day feasibility spike (SP-03A). The export is minimal: no whole-program decompile.
- **Bet 2 — one plan, four renderers.** Operator overrides become run-scoped `KnownFacts` injected before planning. The draft's post-analysis patch could not have produced RET2WIN (`strategy.py:227-228` against `orchestrator.py:1088-1094`).
- **Bet 3 — measurement first, then the oracle as a product.**
  - The passcard runs every cell sandboxed, with truth unreadable by the tool.
  - Coverage and selective accuracy are reported separately, and no case is dropped from a denominator.
  - Each metric has planted mutants it must catch.
- **Analysis of untrusted binaries is sandboxed from the first sprint** (DEC-25), not from SP-07.
- **Commitment horizon.** Only M0 and M1 are committed. M2 is planned. M3 and M4 are options re-decided at the M1 exit with one maintainer's measured velocity (DEC-26).
- **Stop: per-target work.** No new executors, walkthrough families or variant corpora written from one HTB target. No per-target exit criteria. No name lists.
- **Stop: polishing demoted code.** `walkthrough/`, `kernel/` and FIRST_TECHNIQUES seat negotiation are frozen. The executor-substrate refactor (D1-R6) is rejected.
- **Stop: process without numbers.** "OK cells" and self-reported `shell_confirmed` are retired as KPIs (`htb_rescore.py:206`).
- **S6 is replaced.** RT-08 is re-scoped into SP-02. RT-09 and RT-10 are dropped as drafted; their intent lands in SP-09 and SP-05.
- **Sequence.**
  - SP-01 and SP-02: honest, isolated, measured baseline.
  - SP-03A: Ghidra go/no-go.
  - SP-03 to SP-06: PASS on a declared stack subset for ELF and mingw PE, with a held-out number.
  - SP-07 to SP-11: contract, non-stack classes, verification.
  - SP-12a/b/c: staged deletion behind deprecation.
  - SP-13 to SP-16: local-only LLM hooks and PE hardening.

### 1. North star and scorecard

**Product statement.** supwngo is a verified, offline, machine-drivable analyst and agent toolbox for binary RE/VR. Given an ELF or PE it produces:

- a cached facts base, decompilation, and evidence-graded findings;
- a ranked `MethodPlan` whose recommendation cites a function and site, with each precondition marked confirmed, operator-supplied or missing;
- the exact controlling distance (offset) of the primitive;
- a template that declares what it still needs;
- an unforgeable receipt when it verifies an exploit script.

Autonomous exploitation is one consumer of the plan, not the headline.

#### 1.1 Truth manifest

One `truth.yaml` per target (smoke) or emitted by the generator (corpus). Truth, sources and debug siblings live outside every path the tool process can read (§6, SP-01a).

```yaml
format: elf|pe   arch: amd64|i386   runnable: true|false   compiler: gcc|mingw|msvc|asm
vuln_class: CWE-121   vuln_function: <addr|name>   sink: <callsite addr>   shape: <template id>
methods_accept: [srop]   methods_reject: [ret2libc]   methods_basis: solver_proven|construction|reviewed
distance: {kind: buf_to_ret, value: 40, index_term: null, truth_tiers: [dwarf, disasm, bp]}
canary_distance: null
components: {win: 0x..., ret2: null, args: [], libc: null}
decompile_anchors: {vuln: {addr: 0x..., calls: [read], min_calls: 1}}
input_vector: stdin|argv|file|menu   input_recipe: [<bytes to reach the sink>]
```

#### 1.2 Metrics

Scoring is +1 correct, 0 explicit abstain, −1 confident wrong. Every metric reports three numbers over the full denominator: coverage (answered / all), exact (correct / all) and selective accuracy (correct / answered). Nothing is removed from a denominator.

| Metric | Computation | Notes |
|---|---|---|
| **METHOD-R** (headline) | Top-1 `recommended.family` ∈ `methods_accept`. From SP-05 it must also cite the vulnerable function and site, with every precondition `confirmed` or `operator`. | Until SP-05 it is reported as METHOD-R0 (label only). Scored only where `methods_basis` is `solver_proven` or `construction`. A confirmed recommendation on a patched twin scores −1. |
| **METHOD-L** (diagnostic) | An accept-set member in the top 3 of the evidence-backed list. List precision = \|listed ∩ accept\| / \|listed\|. | `speculative[]` is capped at 3 by contract. METHOD-SPAM is the mean number of listed families, evidence-backed plus speculative, on patched twins. |
| **OFF-S** | Static `distance{kind, value}` equals truth exactly, per kind and per shape. | Wrong-labelled rate (wrong / answered) target ≤ 2%. |
| **OFF-D** | Breakpoint-at-sink measurement equals truth (runnable ELF only). | Benchmark side from SP-04a; product from SP-11. |
| **RIP** | Payload built from the reported offset plus a marker PC; gdb or core shows PC == marker. | Runnable ELF; canary absent or supplied. |
| **DECOMP** | Counted per anchor function when all of these hold: the returned address equals the truth address; the code is non-sentinel; call-anchor recall is 100% on call expressions with comments stripped; the body has at least `min_calls` calls; `selected_by` is present. Also scored: the default invocation returns the truth user function. | Backend and seconds recorded. |
| **COMP-A** | Withhold one component and rerun with the override plus `--strict-overrides`. A1: plan and template contain the value verbatim with operator provenance. A2: `verify` reaches `shell_proven` or the flag. | A2 runnable ELF only. |
| **COMP-B** | Template's declared inputs == truth-required minus auto-resolved; auto-resolved values == truth; filled from truth it reaches proof; unfilled it exits 2. | Golden-fill, from SP-05. |
| **ROBUST** | No traceback; one JSON document; exit code matches `ok`; no sentinel as success; budget respected; no surviving child process; "target cannot execute" stated; target executed only when asked. | Per cell. |
| **TIME** | Cold and warm p50/p95 per command, with load average recorded. Cells above the load threshold are invalid. | Quorum: at least 20 valid cold and 20 valid warm samples per gated command, otherwise the measurement run fails. |

#### 1.3 Resolved disagreements

- **Top-1 against listed.** The headline is top-1 with confirmed preconditions. "Listed" survives only as top-3 with precision. `speculative[]` never scores positively, is capped, and is counted by METHOD-SPAM.
- **What "right" means.**
  - Truth is an accept-set at family granularity.
  - On generated sets the accept-set is derived from construction plus reference solvers that reach proof when fed truth. No human edits it.
  - On S0 smoke a `shell_proven` solve by another technique is added after review (DEC-7). S0 never gates, so that review cannot move a gated number.
- **Offset for non-stack-return primitives.**
  - "Offset" is the controlling distance of the actual primitive, with a `kind`.
  - Stack kinds are `buf_to_ret` and `buf_to_canary`. An optional affine `index_term` covers indexed writes: `bytes_to_ret = value − n`.
  - Non-stack-return kinds are `indexed_base_ptr`, `chunk_to_next_size`, `record_to_fnptr`, `buf_to_var` and `index_bound`.
  - Every target gets an exact distance of its truth kind or an explicit abstain with a reason. A saved-RIP offset on a non-stack-return target is not scored.

#### 1.4 Evaluation sets

| Set | Source | Role |
|---|---|---|
| **S0 smoke** | HTB-7, each cell run in a disposable copy of its challenge directory | Reported every run; never an exit criterion; never tuned on. |
| **T0-mini** | Generator, dev templates, SP-02c (≥ 90 binaries, ≥ 24 mingw PE) | Exit criteria for SP-02 to SP-05, and the SP-03A spike. |
| **T0-dev** | Generator, dev templates and seeds (SP-06) | Development and exit criteria. Size is set by confidence interval (SP-06). |
| **T0-held** | Held-out templates (sealed in SP-02c) plus an owner-held seed | Aggregates only; sprint gates use the dev-minus-held gap. |
| **T0-PE** | mingw x64/x86 builds of the same sources | PE DECOMP and OFF-S. Every column is labelled by compiler and cookie scheme. MSVC arrives only with SP-16. |
| **T1 public** | ROP Emporium and how2heap at pinned glibc, about 40 labelled; fetched by URL + sha256 with licence recorded | Dev only. Never used to score LLM modes. |
| **T2 precision** | cb-multios patched twins and a Juliet subset (about 100 pairs) | Detector precision and recall, from SP-09. |

Stack-return targets in S0 are sick_rop (40), rocket_blaster_xxx (40) and ancient_interface (`buf_to_ret` 4120, `buf_to_canary` 4104; FOLD-NOTES §2). snow_scan is not a stack-return target: its primitive is a low-byte rewrite of a fill-loop base pointer in a VLA frame, kind `indexed_base_ptr` (FOLD-NOTES §3).

**Comparative table.** From SP-06 every milestone report has one row per baseline, stating win, tie, lose or abstain per metric:

- supwngo at the previous tag;
- raw Ghidra (DECOMP only);
- cwe_checker (detection only, from SP-09);
- agent without the toolbox (from SP-14).

#### 1.5 Anti-overfitting rules

1. **Held-out performance is the enforcement mechanism.** The identifier lint is hygiene only: no evaluation-binary identifier in non-comment code under `supwngo/`, with a comment ratchet. SP-06 plants one structural cheat that passes the lint and must fail held-out.
2. Every sprint exit criterion is a delta on T0 or T1. S0 is reported beside it.
3. A measured held-out set is burnt and becomes dev. The seed rotates quarterly.
4. **Metamorphic rules.**
   - Rename and strip must not change method, distance or payoff identity.
   - A compiler or optimisation change produces a new variant scored against its own truth. Only the vulnerable function and the payoff identity must stay invariant.
5. Every metric ships with planted mutants covering positive, negative, abstain, error, timeout and answer-key cases (§6, SP-01a). An instrument that has never failed is not trusted.
6. The generator publishes a per-axis count manifest. Truth-extraction failures are capped at 10% per axis cell and stay visible; a silently missing axis fails the generator gate.
7. LLM-assisted scores are reported separately and count only on fresh T0-held.

#### 1.6 Targets per milestone

"M1 shapes" are the shapes SP-04 declares supported:

- a direct sink with a stack destination;
- a depth-1 callee sink;
- an affine indexed destination;
- an rbp-framed custom syscall wrapper.

"All shapes" adds byte-copy loops, `alloca`/VLA, call depth ≥ 2 and frame-pointer-less custom ABIs. At M1 these must abstain; they are counted and reported.

| Metric (set) | Today (S0) | M0 | M1 | M2 |
|---|---|---|---|---|
| `solve` proof (S0, in-sample) | 7/7, 21/21 `shell_proven` | hold | hold | hold |
| ROBUST (T0 + S0) | 1 crash, 2 sentinels, 3 VOID mis-reported | 100% | 100% | 100% |
| DECOMP (T0 ELF / mingw PE) | 3/7; PE unmeasured | baseline | ≥ 95% / ≥ 95% | hold |
| OFF-S exact, M1 shapes, -O0 / -O2 (T0-dev) | 0 of 4 valid | baseline | ≥ 90% / ≥ 60%; wrong-labelled ≤ 2% | ≥ 95% / ≥ 80% |
| OFF-S exact, all shapes (T0-dev) | — | baseline | reported; wrong-labelled ≤ 2% | M1 value + 15 pts |
| OFF-S exact, M1 shapes (T0-PE, mingw) | — | baseline | ≥ 85% | ≥ 90% |
| OFF non-stack-return kinds (T0-dev) | — | — | — | ≥ 60% |
| METHOD-R stack classes (dev / held) | 2/7 (R0) | baseline | ≥ 80%; gap ≤ 10 pts | hold |
| METHOD-R all classes (dev / held) | — | — | — | ≥ 70% / ≥ 60% |
| COMP-B golden-fill (ELF stack positives) | 0 | — | ≥ 80% | ≥ 80% on all classes with a plan |
| COMP-A1 / A2 | unmeasured | A1 ≥ 95% on `pwn`/`template` | ≥ 95% / ≥ 70% | ≥ 95% / ≥ 80% |
| RIP (runnable ELF stack) | — | — | — | ≥ 80% |
| TIME facts cold p95 / warm cached (quiet host, quorum met) | 30–190 s / n.a. | — | dynamic ≤ 90 s, static ≤ 180 s / ≤ 2 s | hold |

M3 values are set at the M2 exit.

Smoke expectations by M1 are derived from code and the P-code experiment, and are UNVERIFIED for the fallback path:

- OFF-S 3/3 on the stack-return targets (40, 40, 4120 with canary 4104);
- snow_scan abstains with reason `loop_copy_indexed_base_ptr`;
- DECOMP 7/7.

### 2. Target architecture

```
                 ┌────────────────────────── CLI / machine contract ───────────────────────────┐
                 │ envelope supwngo.tool/v1 · exit 0/2/1 · tools --json · (generated MCP)       │
                 │ facts | decompile | offset | pwn | template | report | verify | try | autopwn│
                 └───────┬──────────────────────┬───────────────────────────────┬───────────────┘
   KnownFacts (run-scoped, immutable,           │ renderers                     │ oracles
   operator provenance, NEVER persisted) ──┐    │                               │
┌──────────── per-binary KB  ~/.cache/supwngo/<sha256>/<manifest-hash>/ ────────▼──────────────┐
│ facts.v1 (derived only; provenance: static|measured)                                         │
│  program · functions(+is_library, canary slot) · frames · candidate callsites(args)          │
│  strings+xrefs · decomp on demand                                                            │
└───▲───────────────▲───────────────▲──────────────────────┬───────────────────────────────────┘
    │ analyzers: budgeted, killable, SANDBOXED (bwrap: no net, ro fs, rlimits), cached
 loader(lief/      ghidra_export   gadgets   libsig(FID)   ▼ queries (+ KnownFacts overlay)
 pyelftools)       (Java, minimal)           [min SP-03,   detectors → Finding{class, site, grade E1..E3}
                                              broad SP-08] stack_layout → SinkRecord{distance, reaches}
 angr: optional, directed, budgeted helper                 payoff → candidate | hypothesis | proven
                                                               ▼
                                   Planner: Finding × TechniqueSpec × KnownFacts → MethodPlan[]
                                   {family, technique_id, site, evidence[], facts{}, required_inputs[],
                                    distance, script_builder}
                                           │                         │
                     pwn / template / offset / report        autopwn: execute plan via executors
                     (static by default)                     └─► PipelineVerifier (receipt, shell_proven)
                                                                  same sandbox, no network
 LLM layer (off by default, local only for gates): closed-set proposals → Hypothesis queue
            → assertion-specific oracle → fact | refuted
```

- **Knowledge base.**
  - One directory per binary sha256 plus an analysis-manifest hash. The manifest covers exporter version, Ghidra version, analysis options, loader and language id, `.fidb` hashes and schema version.
  - It holds derived facts only. There are three hard-wired analyzers and about 25 fact keys; there is no merge algebra and no scheduler.
- **KnownFacts.** Operator assertions (`--win`, `--ret2`, `--offset`, later `--vuln-func`, `--sink`, `--buffer`, `--canary-offset`, `--known`) form an immutable run-scoped overlay. It is never written to the cache, so a bad `--win` cannot affect a later invocation.
- **Sandbox.** `supwngo/core/sandbox.py` is one runner used by the passcard, the Ghidra export, target execution, and `verify`/`try`. It gives no network, a read-only filesystem except a scratch directory, CPU, memory and file-size limits, and a process-group kill.
- **Detectors** are queries over facts, graded E1 (site-level static), E2 (argued, cited lines) or E3 (dynamically confirmed). Import-only evidence is never a finding.
- **Planner.** `TechniqueSpec` is declarative and sits beside each executor. Executors gain `plan(context, execute=False)`, which formalises the existing `_gate` returns (`srop_nowrite_techniques.py:195-254`). Executor gates can read dynamic facts such as `context.profile_has_menu` (`profile_stage.py:199-234`); static mode treats these as `unknown` and lists them in `required_inputs`.
- **Renderers.** `template` renders `script_builder` only when the builder implements the selected technique; otherwise it reports the required inputs and exits 2.
- **Oracles.** `verify` exposes `PipelineVerifier.verify_via_tester`. `try` runs one executor with supplied facts.
- **Deleted, staged (SP-12a/b/c) after consumer migration and one release of deprecation.**
  - Engines and generators: `auto.py`, `enhanced_auto.py`, `generator.py`, `chainer.py`, `exploit/templates.py`.
  - Dead code and duplicates: the zero-importer modules in D1-F10, six of the seven win lists, four of the five offset finders.
  - Integrations: the RetDec path, `driller.py`, the honggfuzz and libFuzzer wrappers.
  - `schema/` except the `Provenance` vocabulary.
- **Demoted.** `StrategySuggester` (fallback for un-specced families), angr (optional), FIRST_TECHNIQUES (a prior), `walkthrough/` and `kernel/` (frozen).

**Correction to the draft.** `exploit/templates.py` is not orphaned. It is a public eager import at `supwngo/__init__.py:51`, and `auto`'s names are exported at `supwngo/__init__.py:52`.

### 3. Decision register

| ID | Decision | Rationale | Reversible? | Revisit if |
|---|---|---|---|---|
| DEC-1 | The product is the verified toolbox; autonomous exploitation is the executor stage. | PASS criteria do not require autonomy; `solve` already does 7/7 in-sample. | Yes | HYP-12 shows the toolbox adds neither cost nor solve benefit. |
| DEC-2 | Ghidra is the system of record, **provisional until SP-03A passes its gates**. angr is an optional helper. | Exact on 3/3 compiler-built cases including PE; abstains on 3/3 hard cases; 427 s on a static binary (SPOTCHECK:49-63). | Cheap until SP-03 starts | SP-03A fails any gate (§6). |
| DEC-3 | The exporter stays Java. PyGhidra is evaluated but not depended on. | Ghidra 12.1.3 here has no PyGhidra (BRIEF §5). | Yes | An offline PyGhidra install is proven. |
| DEC-4 | Offline-first; LLM off by default; every sprint gate runs with `--llm off` or `local`. | Hard platform requirement. | No | — |
| DEC-5 | HTB-7 is smoke only. | Executors were written from these targets; the 7/7 is in-sample. | No | — |
| DEC-6 | The headline is METHOD-R (top-1, cited site, confirmed preconditions, wrong-answer penalty). | Closes the list-everything loophole. | Yes | Owner wants top-k. |
| DEC-7 | Truth is an accept-set. On generated sets it is derived from construction plus reference solvers. On S0 a `shell_proven` solve is accepted after review. **OWNER** (default: accept). | Three of seven write-up labels differ from the proven solves. | Yes | Owner requires write-up labels. |
| DEC-8 | "Offset" = primitive distance with a `kind`; stack-return and other kinds are reported separately. **OWNER** (default as stated). | snow_scan has no fixed saved-RIP offset (FOLD-NOTES §3). | Yes | Owner wants saved-RIP only. |
| DEC-9 | `pwn`, `template` and `report` never execute the target without `--measure`. `template` flips in SP-02b; `offset` becomes static-first in SP-04. **OWNER** (default: static). | `template` executes today (`auto.py:2759 → :303 → :396`). | Yes | Owner prefers dynamic by default on trusted hosts. |
| DEC-10 | Canonical address space is RVA plus preferred base, computed in the exporter from `getImageBase()`. | Fixes D2-F3 by construction. | Yes | — |
| DEC-11 | Static distance uses Ghidra frame and P-code def-use as primary. The fallback is narrow: instruction-level, rbp-framed functions only, with a proven def-use chain to the sink. Unsupported shapes abstain. | Full Estimator A (D3-R3) rebuilds function recovery. | Yes | HYP-3 or HYP-1. |
| DEC-12 | PE scope is decompile, offset and protections, static only, on **mingw PE32/PE32+**. Results are "static-validated", never "dynamically confirmed". | PASS says "decompile + offset for now"; no wine in the product. | Yes | Owner un-scopes. |
| DEC-13 | No generic "Windows PE" claim before MSVC `/GS` fixtures pass (SP-16). **OWNER** to supply a toolchain or binaries. | mingw overstates readiness. | Yes | Supplied earlier: they join SP-06. |
| DEC-14 | Deletion follows consumer migration, a one-release deprecation, and import-contract plus CLI reachability tests. One module family per PR. No LoC gate. | The live `exploit` command imports the engines (`cli.py:296,370,413,457`). | Git | — |
| DEC-15 | `schema/`: keep about 200 lines of `Provenance`; delete the rest in SP-12c. | Orphaned (D1-F4). | Git | — |
| DEC-16 | `kernel/` and `walkthrough/` are frozen. `kernel/` moves to an extra in SP-12c. **OWNER** for outright deletion. | Off the PASS path. | Yes | Owner names kernel as a goal. |
| DEC-17 | No executor-substrate refactor and no "`cli.py` ≤ 300 lines" goal. | Effort L on demoted code. | Yes | A new technique still costs over 1k lines after SP-10. |
| DEC-18 | CI is a local gate (`make gate`, systemd timer) on the x86-64 host. | Owner policy; the Sparks are ARM64. | Yes | A reserved runner appears. |
| DEC-19 | Process: one-page plans for S work; multi-round review only for instruments and cross-engine interfaces; "no number, no sprint". | D5-F9. | Yes | HYP-18. |
| DEC-20 | No in-tree agent; MCP is a generated wrapper, last. | D4-R11. | Yes | — |
| DEC-21 | Cloud models are an optional reporting arm on generated T0 fixtures only; never a gate. **OWNER** (default as stated). | Offline requirement. | Yes | — |
| DEC-22 | Held-out custody: templates and seed in an owner-only path hidden from every tool and agent process. **OWNER** to name the custodian; needed at the SP-02c exit. | The split must exist before SP-03 tunes on the corpus. | Yes | — |
| DEC-23 | LLM method reordering and LLM prose are not built. | They optimise demoted goals. | Yes | — |
| DEC-24 | Tag 2.2.0 at the end of SP-02 (HO-02), scoped in its notes as "honest baseline": the passcard table with every FAIL listed and no PASS claim. 2.3.0 is the first release that claims a stack-template milestone (M1). | Orchestrator placement; honesty of the claim comes from the notes. | Yes | — |
| DEC-25 | **New.** Every analysis of, and every execution of, a target runs in the sandbox from SP-01a (passcard) and SP-03 (Ghidra). | Ghidra, objdump and parsers process attacker-controlled files. | No | — |
| DEC-26 | **New.** Commitment horizon is M1. M2 is planned; M3 and M4 are options re-decided at the M1 exit. | One maintainer; 16 sprints is not a commitment. | Yes | — |
| DEC-27 | **New.** Operator facts are a run-scoped overlay and are never cached. Strict mode rejects unresolvable and unused inputs. | Prevents cache poisoning. | No | — |

### 4. Roadmap

#### M0 — Honest, isolated baseline (SP-01, SP-02; about 3 weeks)

- **Objective.** The tool stops lying; the instrument cannot be gamed or leak truth; every later claim is measured.
- **Done when.**
  - ROBUST is 100% on S0 and T0-mini.
  - The passcard baseline is committed with the `solve` column (7/7, 21/21) and VOID flags, and every mutant in the SP-01a table is caught.
  - Overrides produce a top-1 RET2WIN on `pwn` and appear verbatim in `template` (COMP-A1).
  - `template -t auto` equals `pwn`'s recommendation through a compatible builder, or exits 2.
  - `template` executes the target in 0 cells without `--measure`.
- **Deliverables.** `benchmark/passcard.py`, `supwngo/core/sandbox.py`, `supwngo/core/proc.py`, truth files, the T0-mini generator with tiered truth, the sealed held-out templates, the correctness fixes, `make gate`, tag 2.2.0.
- **Tests.** HYP-4, HYP-5 (baseline), HYP-10, HYP-24.

#### M1 — PASS on the declared stack subset, ELF and mingw PE, with a held-out number (SP-03A, SP-03 to SP-06)

- **Objective.** Bets 1 and 2 on the stack-return class.
- **Done when.** The §1.6 M1 column is met. Unsupported shapes abstain instead of guessing.
- **Deliverables.** The spike report, facts v1 (minimal) with cache governance, static distance, payoff tiers, Plan v1 with honest templates, generator v1, held-out report, nightly lane, comparative table.
- **Tests.** HYP-1, HYP-2, HYP-3, HYP-6, HYP-13, HYP-23.

#### M2 — All classes, one contract, proof (SP-07 to SP-11; planned)

- **Done when.** The §1.6 M2 column is met; the contract test passes for every command; `verify` refuses all eight `broken_*` scorer fixtures; the legacy fallback is off with corpus proof not regressed.
- **Tests.** HYP-7, HYP-8, HYP-11, HYP-14, HYP-15, HYP-16, HYP-17.

#### M3 — Smaller and smarter (SP-12a/b/c, SP-13, SP-14; option)

- **Done when.**
  - Import-contract and CLI reachability tests are green before and after each deletion PR.
  - `--version` runs in under 0.5 s.
  - Each shipped hook meets its lift threshold on T0-held with `--llm local` and zero unsound promotions.
  - The local two-arm agent evaluation is published.

#### M4 — Reach (SP-15, SP-16; option)

- **Done when.** Targets are set at the M3 exit. SP-15 is cancelled if HYP-17 shows reachability is not the binding constraint.

#### Stop-doing list

1. Per-target executors and variant corpora authored from the target they evaluate.
2. Name lists for win functions and allocators.
3. New `walkthrough/` families.
4. FIRST_TECHNIQUES seat tuning (`orchestrator.py:1114-1115`).
5. "OK cells" and `shell_confirmed` as evidence.
6. Instruments living in `/tmp`.
7. Reviews of interfaces that have no producer or consumer.
8. `scripts/auto_implement.sh`.
9. LoC targets as exit criteria.

#### Deletion schedule

| When | What | Guard |
|---|---|---|
| SP-01b | The dead `pie_base_offset()` (`rop_techniques.py:128`; no other reference in `*.py`) — HO-01 | `git grep` shows zero callers. |
| SP-02 | `scripts/auto_implement.sh`, `setup_cron.sh`, `test_accuracy.py` | No importer. |
| SP-05 | `tech_map` (`cli.py:1224-1231`); `template`'s use of `generate_exploit_script`. `exploit/templates.py` is not deleted here. | COMP-B on T0 at least as good as before. |
| SP-09 | PLT-presence detectors, `uaf.py`, `off_by_one.py`, `heap_advanced.py` site finders, the regex list at `decompile.py:627-637` | T2 precision and recall not worse. |
| SP-11 | Legacy fallback in `autopwn`/`solve` (`cli.py:2953, 3565`) | `solve` proof on S0 stays 7/7 (21/21) and corpus proof does not regress. |
| SP-12a | Nothing deleted. `exploit` command migrated off the engines; public names become lazy `__getattr__` shims that emit `DeprecationWarning` (`supwngo/__init__.py:51-52`; `exploit/__init__.py:3,56,188`). | Import-contract test; compatibility table published. |
| SP-12b | `auto.py`, `enhanced_auto.py`, `generator.py`, `chainer.py`, `exploit/templates.py`, one PR each, one release after SP-12a | Import-contract and reachability tests; passcard and `run_bench` unchanged. |
| SP-12c | D1-F10 list, `schema/` minus Provenance, RetDec path, `driller.py`, fuzzer wrappers, duplicate win lists and offset finders, `setup.py`, `requirements.txt`; `kernel/` to an extra | Same guards. |

### 5. Sprint map

Effort: S ≤ 3 days, M ≈ 1 week, L ≈ 1.5–2 weeks of agent-assisted work. Every exit criterion is measured by `passcard` on the named set, with S0 reported alongside.

| ID | Goal | Scope | Depends | Eff. | Exit criterion | Closes |
|---|---|---|---|---|---|---|
| SP-01 | **SP-01a (PR 1):** isolated passcard v0, truth, mutants, baseline. **SP-01b (PR 2):** the honesty fixes. | a: `benchmark/passcard.py`, `benchmark/truth/`, `supwngo/core/sandbox.py`, corpus YAML redaction. b: `supwngo/core/proc.py`, `offset_finder.py`, `_angr_subprocess.py`, `decompile.py`, `SupwngoDecompile.java`, `cli.py`, `core/binary.py` + RELRO consumers, `rop_techniques.py`, lint | — | M+ | a: baseline committed before any fix, with the `solve` column and VOID flags; 100% of the mutant table caught; the answer-key shim is denied. b: ROBUST 100% on S0 for `offset`/`decompile`; child and descendant PIDs gone after timeout; RET2DLRESOLVE listed on 0 Full-RELRO fixtures; default decompile returns the truth function on freestanding and stripped-dynamic no-`main` ELF fixtures; lint green | D5-F1, D5-R1 (v0), D3-F5, D2-F5, D2-R8 (part), D1-F3, D1-H6, D2-F4, D2-F11, D4-F4, D3-F11, **I-45**, **HO-01**, B-1, B-2, B-3, B-7 |
| SP-02 | **SP-02a:** `KnownFacts` and overrides. **SP-02b:** SROP evidence, role tiering, non-executing honest `template`. **SP-02c:** T0-mini, tiered truth, held-out template split, passcard v1, gate, tag. | a: `supwngo/core/known.py`, `cli_options.py`, `strategy.py`, `cli.py`. b: `supwngo/analysis/rax_control.py`, `strategy.py`, `cli.py`, `auto.py` (minimal). c: `benchmark/gen/`, `passcard.py`, `htb_rescore.py`, `scripts/ci/gate.sh`, patchelf run helper | SP-01 | L | T0-mini ≥ 90 binaries (≥ 24 PE) with a per-axis manifest and ≤ 10% truth-extraction failure per axis; `pwn --win/--winfun/--ret2/--eip` gives top-1 RET2WIN on 100% of random-name payoff fixtures and `--ret2 --rop` on 0%; SROP on 0 no-rax-control fixtures; `template -t auto` == `pwn` top-1 through a compatible builder, or exit 2, on 100%; `template` executes the target in 0 cells without `--measure`; COMP-A1 ≥ 95%; ≥ 3 held-out templates sealed; tag 2.2.0 | RT-08 (re-scoped), D3-F2, D3-F7, D1-F5, D3-F10, D4-F7, D3-F4, D3-R1, D5-F4, D5-F6, D5-R5 (pre-merge), D5-R7 (part), **HO-02**, **CG-04** (patchelf run against a supplied libc/loader), B-4, B-5, B-6, B-9 |
| SP-03A | Ghidra feasibility gate (spike; new) | Scratch exporter over T0-mini; sandboxed Ghidra; time split; minimal FID probe | SP-02c | S | The five gates in §6. Pass: DEC-2 confirmed. Fail: Bet 1 pivot (§9) before any `facts/` code exists | B-10, HYP-1 (first read), HYP-23, HYP-24 |
| SP-03 | Facts v1 (minimal): cached, sandboxed, governed; `facts`; `decompile` over facts; PE loads | `supwngo/facts/`, `SupwngoExport.java`, `decompile.py`, `cli.py` | SP-03A | L | DECOMP ≥ 95% on T0-mini ELF and mingw PE; cold p95 ≤ 90 s dynamic and ≤ 180 s static, warm cached ≤ 2 s, quorum met; second call spawns 0 Ghidra processes; malicious fixtures cannot write outside scratch or open a socket; changing any manifest field invalidates the cache; per-function canary false positives 0 on no-canary fixtures | D1-R3, D2-R1, D4-R3, D1-F6, D2-F2, D2-F3, D2-F4, D4-F9, D2-F13 (part), D1-R1 (thin), D2-R8 (canary), B-10, N-5 |
| SP-04 | **SP-04a:** static distance and static-first `offset`, benchmark breakpoint truth. **SP-04b:** payoff tiers. | a: `analysis/stack_layout.py`, `cli.py` `offset`, `benchmark/gen/truth_bp.py`. b: `analysis/payoff.py`, `strategy.py` win scan | SP-03 (SP-04b: SP-01b, per AMD-19) | L | a: §1.6 M1 OFF-S row on T0-mini per shape and axis; every unsupported-shape fixture abstains with a reason; breakpoint truth agrees with DWARF truth on ≥ 98% of runnable ELF. b: payoff top-1 ≥ 90%, identical after rename, 0 file-copy decoys ranked top-1 | D2-R2, D3-R3 (B + narrow A′), D3-R4, D3-F3, D3-F5, D1-F9, D5-H5, B-8, N-4 |
| SP-05 | Plan v1 for the stack family (ret2win, ROP, SROP); honest templates; KnownFacts everywhere | `supwngo/plan/`, `cli.py` (`pwn`/`template`/`offset`/`report`), `cli_options.py` | SP-04 | L | T0-dev stack classes: METHOD-R ≥ 80% and ≥ 30 pts over the majority-label baseline; every scored recommendation cites a function and site; cross-command agreement 100%; COMP-B ≥ 80%; unfilled scripts exit 2 on 100%; strict mode rejects unused inputs | D1-R2 (slice), D3-R2, D3-R6, D3-R7, D1-F1, D1-F2, D3-F12, D4-F11, D5-R1 (COMP) |
| SP-06 | Generator v1, held-out report, public tier, nightly, pinned environment, comparative table | `benchmark/gen/`, `benchmark/history/`, `tools.lock.toml` (source, version, hash, licence, redistribution status), `supwngo doctor`, Dockerfile | SP-02c (parallel with 03–05) | L | Start ≥ 200 dev / ≥ 100 held, growing until the 95% CI half-width is ≤ 8 pts on every gated cell; reference solvers fed truth reach proof on ≥ 95% of ELF positives; first held-out report; the planted structural cheat passes lint and fails held-out; 7 consecutive nightlies with an identical skip set | D2-R7, D5-R2, D5-R3, D5-R4, D3-R10, D5-R5, D5-R6, D5-F2, D5-F3, D5-F7, D2-F15, **CG-04** (corpus-wide), N-3 |
| SP-07 | Machine contract and public oracles | envelope decorator, exit codes, `tools --json`, `verify`, `try`, local libc-database | SP-05 | M | Contract test `ok == (exit == 0)` and one-document stdout for 100% of commands; `verify` refuses 8/8 `broken_*` fixtures and credits the control; 0 outbound connections in the suite; offset-libc against loaded-libc mismatch detected on 100% of planted mismatches | D4-R1, D4-R2, D1-R8 (envelope), D4-F6, D4-F8, D4-F10, D1-F11, D1-F12, **CG-01b** |
| SP-08 | Broad static and stripped coverage | Multi-version FunctionID `.fidb` from the libc-database mirror; syscall-wrapper roles | SP-03, SP-07 | M | Static T0 builds across three glibc versions: ≥ 90% of libc sinks named; OFF-S and METHOD-R on the static/stripped axes within 15 pts of dynamic/unstripped | D2-R6, D2-F14 |
| SP-09 | Detectors as evidence-graded queries; `report` renders them | `supwngo/detect/` (stack, loop copy, format string, allocator role, dangling slot, integer, off-by-one), cwe_checker bake-off | SP-05, SP-06 | L | T0-held: stack/format recall ≥ 0.7 and precision ≥ 0.6 at E1+; heap/integer recall ≥ 0.4; 0 E1+ findings on ≥ 95% of patched twins; `report` names the bug function on ≥ 70% of dev | D2-R3, D2-F1, D2-F6, D2-F7, D2-F8, D2-F12, RT-09 and RT-10 (re-scoped), D3-F8, D3-F9 |
| SP-10 | Non-stack plans from executor gates | `contracts.py` `plan()`, `TechniqueSpec` for heap/integer/UAF/data-only executors, distance kinds, seccomp fact | SP-05, SP-09 | L | METHOD-R all classes ≥ 70% dev and ≥ 60% held; OFF non-stack-return kinds ≥ 60%; gate-derived plans beat `StrategySuggester` on T0 | D3-R9, D3-F6, D1-R2 (rest), D1-F7 (prior) |
| SP-11 | Deterministic input recipes; dynamic confirmation; `autopwn` executes the plan; legacy fallback off | `--recipe` and menu/file recipes from the existing profile stage; breakpoint confirmer (port of `truth_bp.py`); RIP proof; global deadline; `cli.py:2953,3565` | SP-07, SP-10 | L | Recipe reaches the sink on ≥ 80% of runnable menu/file T0 fixtures; OFF-D agrees with OFF-S on ≥ 98% where both answer; RIP ≥ 80%; S0 `solve` stays 7/7 (21/21) and corpus proof does not regress; COMP-A2 ≥ 80% | D3-R5, D2-R4 (ELF), D1-F7 (deadline), I-2 |
| SP-12a | API and CLI migration; deprecations (split from SP-12) | `exploit` command onto plan and executors; lazy deprecated exports; compatibility table | SP-11 | M | Import-contract test green for every name in both `__all__` lists; every CLI command reachable; `--version` < 0.5 s | B-11, D1-R9, D1-F13 |
| SP-12b | Legacy engines removed, one PR each (split from SP-12) | Per the schedule, one release after SP-12a | SP-12a | M | Contract and reachability tests green before and after each PR; passcard unchanged | D1-R5, D1-F10 (part), D4-F1 |
| SP-12c | Dead modules and packaging (split from SP-12) | Per the schedule; `pyproject` only; docs → `ARCHITECTURE.md` + `ROADMAP.md` | SP-12b | M | Same guards | D1-R10, D1-F4, D1-F14, D2-F9, D5-R7, D5-R8, D5-F9 |
| SP-13 | LLM substrate (local only), oracle-soundness suite, hook 1 | `supwngo/llm/` (client, router, ledger, hypothesis), injection fixtures | SP-07, SP-06 | M | Each oracle refutes 100% of its planted-false claims; adversarial stub: 0 builder inputs without a sound-oracle record in 1,000 runs; `replay` byte-identical; 0 egress; hook 1 meets its row in §8 or is deleted | D4-R4, D4-R5, D4-R6 (hook 1), D4-F2, D4-F5, B-12 |
| SP-14 | Hooks 2–3 and the local two-arm agent evaluation | Role labelling, hypothesis triage; `AgentFollower` on the local provider | SP-13, SP-09, SP-11 | L | Verified heap/integer recall +25 pts over SP-09 on held-out with ≤ 10% of verified claims wrong on twins, else the hook is deleted; local two-arm report published | D2-R5, D4-R6 (hooks 2–3), D4-R9 |
| SP-15 | Input reachability beyond recipes (conditional) | AFL++ QEMU cmplog; LLM grammar hook under the `UntrustedInput` trust model | SP-11, SP-14 | L | Reach rate on menu/format T0 targets +30 pts over SP-11; 0 injection-flipped outcomes | D4-R8, D2-F10, D2-R4 (rest) |
| SP-16 | PE hardening and release 3.0 | MSVC fixtures (if supplied), `/GS` cookie, SEH frames, indirect imports, generated MCP wrapper | SP-08, SP-12c | M | PE DECOMP ≥ 95% and OFF-S ≥ 85%, reported per compiler and cookie scheme; MCP tool list == manifest | D2-R9, D1-R4 (grown), D4-R11 |

**S6 draft disposition.**

- **RT-08 — keep, re-scoped (SP-02b).**
  - The three-line gate widening alone leaves `recommended` at STACK_PIVOT: SROP is built at 0.6 (`strategy.py:582`), below the pivot's 0.65 (`strategy.py:768-770`), under the sort at `strategy.py:279`.
  - Widening on `_has_syscall_ret` is also unsound. That flag is a substring test on gadget text (`strategy.py:360`) and says nothing about setting `rax` to 15.
- **RT-09 — drop as drafted.** The intent returns in SP-09 as name-free allocator-role inference (HYP-8).
- **RT-10 — drop as drafted.** The intent returns in SP-05 and SP-09.
- **S7 leftovers.** I-45 → SP-01a; HO-01 → SP-01b; HO-02 → end of SP-02; CG-04 → SP-02c and SP-06; CG-01b → SP-07; cleanup → SP-12a/b/c.

**Rejected or trimmed recommendations.**

- D1-R6: an L refactor of demoted code.
- D1-R7: sharding across Sparks; they are ARM64.
- D1-R4 as an upfront `Image` protocol.
- D2-R7's ≥ 800 binaries: size is set by confidence interval instead.
- D2-R9's AArch64 cell.
- D5-R4's 500 Juliet pairs: 100 in SP-09.
- D4-R7 and D4-R10: see DEC-23.

### 6. Detailed plans for the first four sprints

#### SP-01 — Isolated passcard v0 (SP-01a) and the honesty fixes (SP-01b)

**Goal.** A committed, falsifiable, ungameable baseline, then zero cells where the tool crashes or reports failure as success.

**Order of work.** SP-01a merges first and commits the baseline against the untouched tool. Each SP-01b fix then lands as its own commit with a visible passcard delta.

The task-level plan is `docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md`, which is not in this export. Where it differs from this section on isolation, the mutant table, the process helper or the decompile selector order, amend that plan before starting.

##### SP-01a (PR 1)

**Files.** New: `benchmark/passcard.py`, `benchmark/truth/<target>.yaml` (7), `benchmark/baselines/passcard.json`, `benchmark/mutants/*.py` (shim CLIs), `supwngo/core/sandbox.py`, `tests/test_passcard_selftest.py`, `tests/test_sandbox.py`. Changed: three corpus YAML files (I-45).

**Design.**

1. **Cell isolation.**
   - Each cell runs in a disposable copy of the challenge directory under a scratch root, with `cwd` set to the copy.
   - `-o`/`--output` always points into the scratch root. Today `template` writes into `cwd` by default (`cli.py:1245-1249`).
   - `TMPDIR`, `HOME` and `XDG_CACHE_HOME` are isolated. Each cell is a new session and is group-killed on timeout.
2. **Truth is unreadable by the tool.**
   - `sandbox.run()` uses bubblewrap: `--unshare-net`, read-only bind of `/`, tmpfs over `benchmark/truth`, `benchmark/gen` and the held-out path, and a read-write bind of the cell directory only.
   - Only the stripped target binary and its shipped loader and libc are copied into the cell.
   - Truth, sources and unstripped or debug siblings stay with the scorer.
3. **Fallback if user namespaces are blocked.** The 6.8 kernel suggests an AppArmor restriction; this is UNVERIFIED (HYP-24). The fallback is a dedicated unprivileged uid with truth at mode 0700 under the maintainer's uid; this needs an owner action (§11 Q10). A run without either is labelled `isolation: none` and cannot become a baseline.
4. **Pre-flight.** Resolve `PT_INTERP` relative to the cell's `cwd` inside the sandbox. If it does not resolve the cell is `VOID`. All seven S0 loaders must resolve.
5. **Scoring.** METHOD-R0, METHOD-L, METHOD-SPAM, OFF (dynamic for now), DECOMP (the full §1.2 definition), ROBUST and TIME with quorum. Verdicts are `PASS|FAIL|ABSTAIN|ERROR|VOID`. Output is JSONL plus a markdown table.
6. **`solve` column.** Ingest the HYP-9 artefact (7/7, 21/21 `shell_proven`, per-rep technique and wall time) with its commit, command line and working-directory convention. Re-running it is a nightly job, not sprint work.
7. **I-45.** Redact the three captured-flag literals in corpus YAML comments in place.

**Mutant table.** Each row is a RED proof for the instrument. The selftest fails if any row is not caught; the truth-echo shim must pass everything.

| Metric | Planted mutant | Must result in |
|---|---|---|
| METHOD-R0 | Constant `ret2system` | FAIL on ≥ 5/7 |
| METHOD-L / SPAM | Lists every family | Precision FAIL; SPAM above cap |
| OFF | `offset = 0`; truth + 8 | FAIL on all; FAIL on all |
| DECOMP | Sentinel string; anchors only inside comments; empty body; wrong function at right name | FAIL each |
| ROBUST | Traceback; two JSON documents; `error` object with exit 0; leaves a sleeping grandchild | FAIL each |
| Timeout | Hangs past the budget | ERROR; process group gone |
| TIME | Zero valid samples | Run fails (quorum) |
| Abstain | Always abstains | Coverage 0, exact 0; never PASS |
| Answer key | Opens `truth.yaml`, a `.debug` sibling and a generator source by absolute path | Each `open` denied; the cell still runs |
| VOID | Target with an unresolvable interpreter | VOID, not FAIL |

A harness that scored "parses as JSON" (the `retest_matrix.py` failure, D5-F1) fails the first row.

##### SP-01b (PR 2)

**Files.** New: `supwngo/core/proc.py`, `tests/test_no_target_identifiers.py`, `tests/fixtures/src/{eof_spin.c, fork_sleeper.c, nomain.S, nomain_dyn.c, fullrelro.c}`. Changed: `offset_finder.py`, `_angr_subprocess.py`, `decompile.py`, `SupwngoDecompile.java`, `cli.py`, `core/binary.py` and the RELRO consumers, `rop_techniques.py`.

**Design.**

1. **Target-run helper.**
   - `proc.run_target(argv, input, timeout) -> RunResult{rc, out, err, timed_out}` uses `Popen(start_new_session=True)`. On timeout it calls `os.killpg(SIGKILL)` and reaps.
   - Correction to the draft: `test_crash` is not a model to copy. It swallows the timeout with `except Exception` and has no process group (`offset_finder.py:502-520`).
   - Every `subprocess.run` of the target in `offset_finder.py` moves to the helper. The refine loop is the confirmed unguarded site (`:541-556`); audit the gdb and core-dump paths in the same commit.
2. **Offset result.** Add `confidence`, `kind` and `error_code` to `OffsetResult`. *(Amended by AMD-O1, §14: `confidence` is deferred to SP-04; SP-01 adds `kind`, `error_code` and `isolation`.)* `find_offset` first checks the interpreter and returns `error_code="target_not_executable"`. `offset --json` exits 2 on a negative result (`cli.py:934-935`).
3. **angr contract.** The subprocess response becomes a total tagged union validated at the parent: `{"status": "ok"|"missing_function"|"decompiler_failed"|"exception"|"timeout", …}`. Only `ok` carries `code`. `_decompile_angr` returns `None` otherwise. `decompile --json` failure exits 2 (`cli.py:2129-2134`).
4. **RELRO.** Add `Protections.relro_kind: Relro` (`NONE|PARTIAL|FULL`); `relro` stays as the display string. Replace the semantic string comparisons, re-grepping first:
   - `strategy.py:454, 976`; `leak_finder.py:329`; `imports.py:400, 499`; `pie_bypass.py:191`; `chainer.py:299`; `got_plt.py:106, 259, 310`.
   - Legacy JSON keeps `relro` unchanged.
5. **Default function.**
   - `cli.py:2070-2071` stops forcing `main` and sends an empty selector.
   - Java order (`SupwngoDecompile.java:87-96`): `main` → the function whose address is the first argument of the `__libc_start_main` call in the entry function → the entry function when the image has no libc start call → the first non-thunk, non-external function reachable from entry.
   - The start-call argument is read from the decompiled entry's call P-code.
   - Emit `selected_by ∈ {symbol, libc_start_main_arg, entry, first_reachable}`. The angr path uses the same order.
   - PE is not testable here: `decompile` calls `Binary.load` (`cli.py:2051`), which is ELF-only. The PE32/PE64 default-selection tests land in SP-03.
6. **Answer-key leak.** Remove `"fill_ammo"` from `offset_finder.py:887`. The lint fails on any evaluation-target slug or symbol in string literals or identifiers and ratchets comments. It is hygiene, not the anti-overfitting control (§1.5).
7. **HO-01.** Delete `pie_base_offset()` at `rop_techniques.py:128`.

**Tests and RED proofs (all fail on `1741b34`).**

| Item | RED proof |
|---|---|
| Refine timeout | Unit, calling `_find_with_binary_search` directly. The patched runner returns a crash code for lengths ≥ N during the bisect, then raises `TimeoutExpired` on the first refine call. Old code propagates the exception; new code returns `success=False` with `error_code="timeout"`. |
| Process group | `fork_sleeper` forks a child that sleeps 60 s and writes both PIDs to the cell. After the timeout neither PID exists. Old code leaves the grandchild. |
| EOF spin | `eof_spin` loops on EOF. `offset --json` emits one JSON document with exit 2. This is a robustness and exit-code test only, since the bisect swallows this timeout. |
| Not executable | `fullrelro.c` built with `-Wl,--dynamic-linker=./nope/ld.so`; expect `target_not_executable`. Old code says "Could not determine offset with any method" (`offset_finder.py:231-234`). |
| angr union | Five cases (ok, missing function, `codegen is None`, exception, timeout) give five distinct statuses. Old code returns the 32-character sentinel as code. |
| RELRO | Full-RELRO fixture: `analyze()` must not contain RET2DLRESOLVE. AST lint: no `.relro` compared to a string literal outside `core/`. One test per enum value plus a legacy-JSON round trip. |
| Default function | `nomain.S` (freestanding) returns the entry function with `selected_by == "entry"`. `nomain_dyn` (stripped, dynamically linked, user code only reachable through the start call) returns the truth function with `selected_by == "libc_start_main_arg"`. An entry-only selector returns `_start` here and fails. |
| Lint | Red today on `offset_finder.py:887`. |

**Risks.**
- **bubblewrap may not work on this host.** Probe on day 1; use the fallback uid.
- **Exit-code changes may break harness callers.** Grep the callers first; D4-F6's survey is UNVERIFIED.
- **The start-call argument may not resolve on some toolchains.** Fall through to `first_reachable` and record `selected_by`. This step is the cut line if SP-01b overruns; it must then lead SP-02.

**Exit.** As in the sprint map. **Rollback.** Each fix is its own commit; SP-01a is additive.

#### SP-02 — Overrides (a), method and template honesty (b), T0-mini and gate (c)

**Goal.** `pwn` and `template` stop emitting constants and stop executing targets. PASS (a) works on the scored commands. A non-HTB set exists with truth that cannot be shaped by dropping hard cases.

SP-02c touches only `benchmark/` and `scripts/`, so an agent can run it in parallel with a and b.

##### SP-02a — `KnownFacts` and overrides

**Files.** New `supwngo/core/known.py`, `supwngo/cli_options.py`. Changed: `strategy.py`, `cli.py` (`pwn`, `template`).

**Design.**

1. Move `target_override_options` (`cli.py:66-109`) to `cli_options.py`. Add aliases `--winfun` → `--win` and `--eip`/`--ret` → `--ret2`. Add `--strict-overrides`, which turns the documented warn-and-fallback (`cli.py:106-107`) into exit 2.
2. `KnownFacts{win, ret2, offset, provenance="operator"}` is frozen and built once per run with the existing resolver, `resolve_target` (`pipeline/target_overrides.py:201`). It applies the destination rules the pipeline already uses (`orchestrator.py:736-742`):
   - an explicit `--win` takes precedence;
   - a `--ret2` destination doubles as the win target;
   - a `--rop` gadget or a libc-relative target never does.
3. **Injection before planning.**
   - Correction to the draft: extracting the report patch at `orchestrator.py:1088-1094` cannot work. RET2WIN is appended only during `analyze()` when `report.has_win_function` is already true (`strategy.py:227-228`).
   - `StrategySuggester.__init__` gains `known=None`. `_analyze_special_conditions` (`strategy.py:303-311`) consults `known.win` before the name scan.
   - RET2WIN is then built in the normal path with `evidence=["operator:--win"]`. It is the recommended terminal, and unmet needs (canary, PIE leak) appear in `required_inputs`.
4. `pwn` gains the override options and `--offset`. `template` gains the override options. `offset` gains none until SP-04, where they affect a result.
5. The orchestrator keeps its own post-analysis patch for now. It is the measured 7/7 path, and its migration to `KnownFacts` is in SP-05 behind the `solve` column.

**RED proofs.**
- A fixture whose payoff has a random name: `pwn --win 0x… --strict-overrides --json` has top-1 RET2WIN with that address and operator provenance. The same holds for `--winfun`, `--ret2` and `--eip`. Old tree: no such option.
- `--ret2 0x… --rop` must not produce RET2WIN. A libc symbol as `--win` must not produce RET2WIN.
- `--win nosuchsym --strict-overrides` exits 2.
- Run `pwn --win X`, then run `pwn` with no override. The second run shows no trace of X, because nothing is persisted.

##### SP-02b — SROP evidence, role tiering, honest non-executing `template`

**Files.** New `supwngo/analysis/rax_control.py`. Changed: `strategy.py`, `srop_nowrite_techniques.py` (imports only), `cli.py` (`template`), `auto.py` (minimal).

**Design.**

1. **`RaxControl` evidence.** `find_rax_control(binary, gadget_finder)` returns a list of `{kind, addr, evidence}`:
   - `pop_rax` (today's only route, `strategy.py:362-370`);
   - `sigreturn_gadget` (`mov eax, 0xf; syscall`);
   - `count_returning_wrapper`, which is the executor's analysis moved verbatim (`srop_nowrite_techniques.py:153-171`, with `_objdump_lines` and `_find_bare_syscall`). The executor imports it back, so there is one implementation.
   - `read_return` (re-entering a read and sending 15 bytes) is recorded as a hypothesis only. It puts SROP in `speculative[]`, never in the terminal tier.
2. **SROP gate.** SROP is a terminal iff a syscall gadget exists and at least one non-hypothesis `RaxControl` exists. `_has_syscall_ret` is no longer evidence of anything. The steps are rendered from the evidence kind, with no "/bin/sh write" step when there is no writable segment.
3. **Role tiering.** `ExploitStrategy` gains `role ∈ {terminal, enabler, speculative}` and `evidence`.
   - STACK_PIVOT is an enabler.
   - VARIABLE_OVERWRITE (`strategy.py:272`), import-only FORMAT_STRING and NEGATIVE_SIZE_BYPASS are speculative.
   - `recommended` is the best terminal. With no terminal it is `null` with an `abstain_reason`.
   - `speculative[]` is capped at 3. `report.strategies` keeps every entry, so orchestrator ordering (`orchestrator.py:1118`) is unchanged.
4. **`template`.**
   - `-t auto` builds the suggester with a `GadgetFinder` and `KnownFacts`, as `pwn` does (`cli.py:869`).
   - A builder-compatibility table replaces `tech_map` defaults:

     | Approach | Legacy builder | Condition |
     |---|---|---|
     | RET2WIN | `ret2win` | A win address is known. |
     | SHELLCODE | `shellcode` | — |
     | ROP_SYSTEM | `ret2system` | `system@plt` exists. |
     | SROP | `srop` | `rax_control.kind == pop_rax` and `/bin/sh` is present. This is what that builder consumes (`auto.py:2794-2800`). |
     | Anything else, including ROP_EXECVE and wrapper-based SROP | none | Exit 2, `error.code="no_template_for_method"`, with `inputs_required`. |

   - **No execution.** `generate_exploit_script` gains `measure=False`, which skips `_find_offset()` (`auto.py:303`, which runs the target at `:396`). `--measure` opts in.
   - `auto.py:2761` becomes `if offset is not None`.
   - A requested technique whose builder condition fails exits 2 instead of falling through to the leak script (`auto.py:2792-2793, 2801-2802`).
   - With missing inputs no file is written. `--allow-incomplete` writes a script that exits 2 at start and lists them.
   - JSON: `{requested, selected_method, builder, inputs_resolved{}, inputs_required[], executes_target}`.

**RED proofs.**
- **Positive.** A static stub with `syscall; ret`, no `pop rax`, a write-style count-returning wrapper, and `leave; ret`: `analyze().recommended.approach is SROP` with `rax_control == "count_returning_wrapper"`. Old tree: STACK_PIVOT.
- **Negative, replacing the draft's unsound test.** The same stub without the wrapper: SROP is not a terminal and `recommended is None`. A stub with no syscall gadget must not list SROP at all.
- **No execution.** A fixture that creates `ran.marker` when executed: after `template -t auto` the marker is absent. Old tree creates it.
- **Zero offset.** Force discovery to return a non-zero value and pass `--offset 0`. `inputs_resolved.offset == 0` with operator provenance and the rendered assignment is 0. Old tree drops the zero.
- **No cross-technique rendering.** On a static wrapper-SROP fixture `-t auto` exits 2 with `no_template_for_method`. Old tree emits `ret2system`.
- `-t ret2win` with no payoff exits 2 with `inputs_required:["win"]`. Old tree emits the leak script.

##### SP-02c — T0-mini, tiered truth, held-out split, passcard v1, gate

**Files.** `benchmark/gen/{templates/, build.py, truth_dwarf.py, truth_disasm.py, solvers/, manifest.py}`, `benchmark/passcard.py`, `scripts/htb_rescore.py`, `scripts/ci/gate.sh`, `Makefile`.

**Design.**

1. **Dev templates (8), structurally different.**
   - `gets` into a local;
   - `read` with an over-long length;
   - menu-gated `fgets`;
   - a struct-adjacent variable;
   - caller buffer with the sink in a callee;
   - an indexed accumulator read loop;
   - a byte-copy loop;
   - a hand-written asm function with stack-passed arguments to a syscall wrapper (ELF64 only).
   - Each has a payoff function named from a wordlist disjoint from every in-tree win list, a file-copy decoy, and a patched twin.
2. **Axes.** `-O0/-O2` × PIE × canary × {ELF64 dynamic, ELF64 static, mingw PE64, mingw PE32}. At least 90 binaries, of which at least 24 are PE. `manifest.py` writes the per-axis count; the gate fails if a declared axis cell is empty.
3. **Tiered truth, with nothing dropped.**
   - Tier 1: DWARF location and CFA evaluated at the sink PC from the `-g` build. ELF uses pyelftools; PE uses `x86_64-w64-mingw32-objdump --dwarf`, cross-validated against pyelftools on ELF twins.
   - Tier 2: an independent derivation from the unstripped disassembly at the known sink call. For the asm template the frame size is a template parameter, so truth is by construction.
   - Tier 3 (native breakpoint) arrives in SP-04a.
   - A variant whose tiers disagree, or whose tier 1 is not computable, stays in the set as `truth_unavailable`. It counts against the 10% per-axis cap and is listed in the report.
   - PE truth is labelled `static-validated`.
4. **Method labels.**
   - `methods_accept` is the set of families whose reference solver, fed truth, reaches proof on the runnable ELF build. SP-02 ships ret2win and ret2libc solvers; more arrive in SP-06.
   - `methods_reject` is the set of families structurally impossible by construction.
   - METHOD is scored only on cells with at least one solver-proven accept family. PE cells carry no method label.
5. **Input recipes.** The generator emits `input_recipe` for menu templates, so dynamic truth and later OFF-D can reach the sink.
6. **Held-out split.** A template registry carries `split: dev|held`. At least three held templates are authored from a written shape spec in a separate session and sealed in the custody path (DEC-22) before SP-03 starts. Nothing reads them until SP-06.
7. **Passcard v1.** Adds COMP-A1, COMP-B scaffolding, coverage / exact / selective reporting per axis, the twin penalty, and the "executed without `--measure`" check.
8. **`htb_rescore.py:206`** gates on `shell_proven`, not `shell_confirmed`. The measured 21/21 does not change, but the gate must not depend on that.
9. **CG-04.** A `run_with_loader(binary, libc, ld)` helper using patchelf on a copy, used by the reference solvers and the passcard.
10. **Gate.** `make gate` runs the unit tier without `-x`, then the passcard and its selftest on T0-mini (and S0 if present). It blocks any PASS→FAIL flip not listed in the PR. `SUPWNGO_REQUIRE_TARGETS=1` makes a missing-fixture skip a failure.

**RED proofs.**
- A reference payload built from truth reaches the payoff on ≥ 95% of runnable ELF positives; truth mutated by 8 fails.
- A generator mutant that drops every `-O2` variant fails the manifest check.
- A generator mutant that marks 30% of an axis `truth_unavailable` fails the cap.
- A synthetic result with `shell_confirmed=True, shell_proven=False` scores UNSOLVED. Old tree: SHELL_ACCESS.

**Risks.**
- **DWARF-on-PE parser fragility.** The cap makes it visible. If an axis exceeds 10%, fix the parser or remove the axis explicitly in the manifest with a reason.
- **`template` now exits 2 on most targets until SP-04 supplies static distances.** This is the honest state (DEC-9). `--measure` and `--offset` remain.
- **`pwn --json` shape change.** Additive keys only; `to_dict(legacy=True)` for one release.

**Exit.** As in the sprint map. **Rollback.** Tiering and `KnownFacts` sit behind `legacy=True` and optional parameters.

#### SP-03A — Ghidra feasibility gate (spike, ≤ 3 days)

**Goal.** Decide DEC-2 on evidence before any `facts/` code exists.

**Method.** A scratch GhidraScript, extended from the experiment in SPOTCHECK, runs under `sandbox.run()` over all of T0-mini and reports per shape and axis. It deliberately does not decompile the whole program.

**Predefined gates.**

| # | Gate | Threshold |
|---|---|---|
| G1 | Exact distance on direct-sink shapes at -O0, ELF and PE | ≥ 90% exact; 0 wrong-labelled |
| G2 | Wrong-labelled rate over every answered case, all shapes and axes | ≤ 2% |
| G3 | Coverage on -O2 frame-pointer-less direct sinks | ≥ 50% answered (reported; feeds the M1 target) |
| G4 | Cold wall time, quiet host, minimal export | p95 ≤ 90 s dynamic; ≤ 180 s static, at least 3 static fixtures |
| G5 | Operates inside the sandbox with no network and a read-only install | 100% of runs |

**Also measured, not gating.**
- The split of cold time between import and analysis and decompile on static binaries (HYP-23).
- Whether a `.fidb` built from the build host's `libc.a` can be produced headlessly in under a day, and what fraction of static sinks it names. This is an early read on HYP-15.
- Per-function canary-slot recognition on canary fixtures.
- Whether P-code stack references are consistently relative to the return-address slot. The experiment found this on 3/3; it is not an invariant in any committed code and stays UNVERIFIED until the spike reports.

**Outcome.** Pass: proceed to SP-03. Fail on G1, G2 or G5: take the Bet 1 pivot (§9). Fail on G4 only: ship `facts` with decompile strictly on demand, restricted to candidate functions, and re-measure.

#### SP-03 — Facts v1 (minimal)

**Goal.** One Ghidra analysis per binary, persisted and sandboxed. `decompile` on ELF and mingw PE becomes a lookup.

**Files.** New `supwngo/facts/{model.py, store.py, ghidra.py, loader.py}` and `supwngo/analysis/ghidra_scripts/SupwngoExport.java`. Changed: `decompile.py`, `cli.py` (`facts`, `decompile`).

**Design.**

- **Store.** `${XDG_CACHE_HOME:-~/.cache}/supwngo/<sha256>/<manifest-hash>/` holds `meta.json`, `program.json`, `functions.jsonl`, `strings.jsonl`, `decomp/<rva>.c` and `ghidra/`.
  - The manifest is `{schema, exporter_version, ghidra_version, analysis_options, loader, language_id, fidb_hashes[]}`. Any change produces a new directory.
  - Writes are atomic under `flock`.
  - Operator facts are never written here (DEC-27).
- **Governance.** A size quota (default 2 GB) with LRU eviction; `facts --purge [SHA]`; `--no-cache`; `cache.retain_decomp=false` for proprietary inputs; a checksum per file, with corruption triggering a re-export.
- **Export.** One `analyzeHeadless` run under `sandbox.run()`, with a read-only binary and install, a read-write scratch project and no network.
  - It uses `stdin=DEVNULL`; the current `Popen` inherits stdin (`decompile.py:280-286`).
  - It uses `-analysisTimeoutPerFile` and no `-deleteProject`.
  - Later single-function requests use `-process -noanalysis`.
- **What is exported.**
  - Program metadata.
  - All functions with bounds, thunk and external flags, callers and callees.
  - Per-function canary: `canary: {present, slot_off_ret}`, from the TLS guard load stored to a stack slot and checked before return (ELF), or the `__stack_chk_guard` load (mingw).
  - Candidate callsites only: calls to sink imports, in-binary syscall wrappers and raw `syscall` sites, with P-code arguments.
  - Strings with cross-references.
- **What is decompiled eagerly.** Only the default-selected function, functions containing a candidate callsite, and their depth-1 callers, within `--budget` (default 120 s). Everything else is `decomp: null` and fetched on demand.
- **Library marking.** `is_library: true|false|null`. `true` comes from thunks, externals, or a FunctionID match when a `.fidb` is configured. The minimal host-`libc.a` database ships here only if SP-03A showed it is cheap; otherwise it waits for SP-08 and static sinks rely on syscall-wrapper roles.
- **Schema.**
  ```
  program:  {format, arch, bits, compiler_hint, entry_rva, image_base_ghidra,
             protections{nx, pie, relro_kind, canary_symbol}}
  function: {rva, name, size, is_thunk, is_external, is_library, callers[], callees[],
             frame:{uses_fp, locals:[{name, off_ret, size, type}]}, canary:{present, slot_off_ret},
             callsites:[{rva, callee, role, args:[{kind:const|stack|stack_indexed|param|global|reg|unknown,
                                                  value, index_term}]}],
             decomp: path|null}
  string:   {rva, value(≤256 bytes, escaped), xrefs:[{from_rva, func_rva}]}
  ```
  All addresses are RVAs (DEC-10). The exporter normalises `off_ret` to the return-address slot explicitly, and the goldens test it against DWARF. Every record carries `provenance: static` and `producer`.
- **CLI.**
  - `supwngo facts BIN [--json] [--section …] [-f FUNC] [--refresh] [--budget S] [--no-decomp] [--purge]`.
  - `decompile BIN [-f X]` reads facts, using the SP-01b selection order, now on PE as well.
  - `--angr` is explicit, never a silent fallback. `--legacy-backend` stays for one release.
- **Format sniffing.** `loader.py` reads magic bytes and uses lief for PE headers, so `facts` and `decompile` do not depend on the ELF-only `Binary.load` (`cli.py:2051`).

**Tests and RED proofs.**
- **Structural goldens** on eight fixtures: dynamic PIE ELF, static no-libc asm, stripped, canary, callee-sink, indexed loop, mingw PE64, PE32. The frame local's `off_ret` equals DWARF truth; the sink's destination argument has the right `kind`; the canary slot equals truth. An exporter mutant that shifts `off_ret` by 8 fails.
- **Cache.**
  - The second call spawns 0 Ghidra processes.
  - Two concurrent processes produce 1 export.
  - A truncated file triggers re-export.
  - A changed analysis option produces a new manifest directory.
  - A forced timeout leaves no partial store and exits 2.
  - Exceeding the quota evicts the least recently used entry.
- **Sandbox.** A fixture run that tries to write outside scratch and open a socket is denied both.
- **PE.**
  - `facts` and `decompile` on PE produce 0 tracebacks.
  - The default selection returns the truth function on PE32 and PE64.
  - `report` and `pwn` on PE exit 2 with `unsupported_format`.
- **PIE.** `decompile -f 0x<rva>` and `-f name` return the same function.

**Risks.**
- **Java API coupling to Ghidra 12.x.** Schema version, goldens, and `supwngo doctor`.
- **Static binaries.** The 427 s measurement included whole-program decompile. The minimal export and G4 address it; HYP-23 quantifies it.
- **Host contention.** The TIME quorum; the nightly runs off-peak.
- **Schema growth.** A hard cap of about 25 keys; SP-04 starts on whatever SP-03 has.

**Exit.** As in the sprint map. **Rollback.** The package is additive; `--legacy-backend` remains.

#### SP-04 — Static distance (a), payoff tiers (b), static-first `offset`

**Goal.** An exact, labelled distance for every supported stack shape on ELF and mingw PE without executing anything; an explicit abstain on everything else; ret2win without an answer key.

**Files.** New `supwngo/analysis/stack_layout.py`, `supwngo/analysis/payoff.py`, `benchmark/gen/truth_bp.py`. Changed: `cli.py` (`offset`), `offset_finder.py` (becomes the `--dynamic` confirmer), `strategy.py`.

**Design (SP-04a).**

- **Sink table.** Imports by identity (`read`, `gets`, `fgets`, `scanf %s`, `recv`, `strcpy`, `memcpy`, `fread`; on PE `ReadFile`, `gets`, `fgets`, `scanf`), raw `syscall` with a constant number, and in-binary syscall wrappers with a role.
- **Record.**
  ```
  SinkRecord{func_rva, callsite_rva, sink, shape,
             dest:{kind:stack|stack_indexed|param|global|unknown, off_ret, index_term},
             length:{kind:const|unbounded|accumulated|unknown, value},
             canary:{present, slot_off_ret}, reaches:[locals|canary|saved_bp|ret],
             distance:{kind, value, index_term}, canary_distance,
             estimator:pcode|insn|both, agree:bool|null, via:[callee chain],
             provenance:static, abstain_reason:null|str}
  ```
- **Supported shapes at M1.**
  1. **Direct.** The destination is a P-code stack reference in the function containing the sink; `distance = −off_ret`.
  2. **Depth-1 callee.** The sink's destination is a formal parameter of the callee by P-code def-use, and the caller passes a stack reference. The distance is in the caller's frame, with `via` recorded. Depth ≥ 2 abstains.
  3. **Affine indexed.** A destination of base plus index, the ancient_interface shape, gives the exact base distance plus an `index_term`. On that target the expectation is `buf_to_ret` 4120 and `buf_to_canary` 4104 (FOLD-NOTES §2), with `length.kind=accumulated`.
  4. **Custom wrapper, rbp-framed.** Instruction-level estimator A′ runs only when P-code abstains, inside Ghidra's function bounds, on functions with a standard rbp prologue.
     - It maps the wrapper's argument slots from the wrapper body.
     - It proves by def-use within the calling block that the value stored to or pushed into the destination slot is `lea r,[rbp−X]`.
     - It never assumes "buffer at frame bottom".
- **Canary.** `buf_to_canary` uses the per-function slot from facts. If a canary is present but its slot is unknown, `canary_distance` abstains while `buf_to_ret` may still answer.
- **Abstain with a reason** on byte-copy loops (`loop_copy`), `alloca`/VLA, frame-pointer-less custom ABIs, untracked stack pointer, depth ≥ 2, and PE functions with SEH or `/GS` frames. snow_scan abstains here; it moves to SP-09 and SP-10 as `indexed_base_ptr`.
- **Agreement.** When both estimators answer, `agree` is recorded. On disagreement both are emitted, labelled, with no `primary` (HYP-3).
- **`offset` CLI.** Static-first. Output is `{distances:[SinkRecord…], primary}`.
  - `--dynamic` runs the existing finders as a non-fatal confirmation.
  - Manual escape hatches enter `KnownFacts`: `--vuln-func`, `--sink`, `--buffer OFF|NAME`, `--canary-offset`. They appear verbatim with operator provenance, and strict mode rejects unused ones.
  - Exit 2 when every record abstains, with reasons.
- **Benchmark breakpoint truth (tier 3).** `truth_bp.py` drives gdb in the sandbox on runnable ELF with the `input_recipe`. It breaks at the sink callsite, reads the destination, and compares it with the return slot captured at function entry. The product confirmer in SP-11 is a port of this.

**Design (SP-04b).**

- **Three tiers.**
  - `candidate`: any evidence.
  - `payoff_hypothesis`: reaches `system`/`exec*`, or an `open → read → write` chain whose opened path is a flag-like constant string and whose output goes to stdout or a socket.
  - `payoff_proven`: only a dynamic receipt, from SP-07.
- A generic `open → read → write` over a parameter-supplied path is a file copier and stays a `candidate`. A function that only calls `read` is nothing; today's `_find_by_file_ops` flags it (`offset_finder.py:946-979`, reviewer-cited).
- `required_args` are emitted only when a compare operand slices back to a formal parameter by P-code. Otherwise `args: unknown` goes into `required_inputs`.
- Unreachability from entry and names break ties only. Output is the top three with evidence and tier.
  *(Amended by AMD-20: names are never consulted. AMD-19: SP-04b is pulled forward to follow SP-01b.)*
- `strategy.py`'s name scan (`:303-311`) is no longer consulted by `pwn` when facts exist. *(Amended by AMD-22:
  every name scan is deleted.)*

**Tests and RED proofs.**
- **Exactness** against tiered truth on T0-mini, per shape and axis, with all three numbers.
- **Abstention.** Every unsupported-shape fixture returns an `abstain_reason`, never a number. A mutant returning the first `sub rsp` value plus 8 fails the canary, `-O2`, callee and wrapper cells.
- **Wrapper def-use.** A decoy asm fixture whose frame-bottom local is not the buffer passed to the wrapper. A "frame bottom" estimator answers wrongly; A′ must give the real distance or abstain.
- **Rename invariance.** `objcopy --redefine-sym` twins give identical output modulo names. A name-list finder fails.
- **Payoff decoys.** A do-nothing `win()` beside a randomly named real payoff; a file-copy function; an argument-checked payoff whose `required_args` must equal truth.

**Risks.**
- **`-O2` coverage below target.** Abstention costs coverage, not correctness. The M1 `-O2` target is 60%, and G3 gives an early read.
- **Depth-1 summaries mis-attribute parameters.** A `param` kind is accepted only on a proven def-use chain; otherwise abstain.
- **Static sinks unnamed until SP-08.** Wrapper roles cover part; the static axis is reported.

**Exit.** As in the sprint map. **Rollback.** `offset --legacy` keeps the crash-driven path for one release.

### 7. Tools and technologies to add

Every row gains `licence` and `redistribution` fields in `tools.lock.toml` (SP-06). An artefact without them cannot enter a release.

| Tool | Decision | Sprint | Offline install path | Reason |
|---|---|---|---|---|
| bubblewrap | **Adopt now** | SP-01a | Distro package; unprivileged user namespaces UNVERIFIED on this host (HYP-24) | The sandbox for passcard cells, Ghidra, target runs, `verify`/`try`. |
| Ghidra Java exporter | Adopt after SP-03A | SP-03 | Already installed; script in-tree | Basis of Bet 1. |
| Ghidra FunctionID | Probe, then adopt | SP-03A probe; minimal SP-03; broad SP-08 | `.fidb` built headlessly from the build host's `libc.a`, then from the libc-database mirror | Names libc in static and stripped binaries. |
| PyGhidra | Optional, evaluate | SP-08 spike | Wheel inside the Ghidra distribution (UNVERIFIED for 12.1.3) | Only if it cuts exporter maintenance. |
| Ghidra BSim / Version Tracking | Later | after M3 | Ships with Ghidra | Fallback for FunctionID; patch-diffing. |
| rizin | Optional | SP-03A fallback, SP-08 | Static release tarball, sha256-pinned | Second estimator if Bet 1 pivots; FLIRT fallback. |
| Qiling / Unicorn | Skip for now | revisit SP-16 | pip wheelhouse | PE dynamic confirmation is out of scope. Remove the unused `unicorn` hard dependency in SP-12c. |
| wine | Optional | SP-06 | Distro packages mirrored | Benchmark-only check that PE fixtures crash at truth; never in the product. |
| AFL++ (QEMU, cmplog) | Later, conditional | SP-15 | Source tarball + vendored QEMU | Parser targets, if HYP-17 holds. |
| cwe_checker | Evaluate | SP-09 | `cargo vendor` tarball; Ghidra 12 compatibility UNVERIFIED | Detection baseline and comparative row. |
| one_gadget | Keep, pin | SP-06 | Ruby gem mirrored | Already wrapped (`cli.py:845-860`). |
| seccomp-tools | Adopt, small | SP-10 | Ruby gem mirrored | A sandbox fact that changes method choice. |
| patchelf | Adopt | SP-02c / SP-06 | Distro package | CG-04: run targets against shipped loaders. pwninit is skipped because it downloads. |
| libc-database mirror | Adopt | SP-07 | rsync snapshot to a local path | CG-01b; removes `libc.rip` calls (`remote/libc_db.py:41-42`, reviewer-cited). |
| gdb (Python) / pwndbg | gdb now; pwndbg test-only | SP-04a / SP-11 | Distro; release tarball | Breakpoint truth and RIP proof. |
| mingw-w64 | Adopt (installed) | SP-02c | Installed | PE fixtures with DWARF truth. |
| MSVC | Owner question | SP-16 | Owner-supplied | Required before any generic PE claim (DEC-13). |
| Containers | Adopt for reproducibility | SP-06 | `ubuntu:22.04` by digest + wheelhouse + `tools.lock.toml` | Corpora are pinned to glibc 2.35. |
| RetDec, Triton, SymCC, BAP, LibAFL, honggfuzz/libFuzzer wrappers | Skip / remove | SP-12c | — | Duplicates or dead integrations. |
| IDA, Binary Ninja | Skip | — | — | Licensed. |
| angr / angrop | Demote to optional extra | SP-12c | Wheelhouse | Directed, budgeted helper only. |

### 8. LLM integration plan

**Position.**

- No hook ships before the deterministic baseline it must beat exists and before held-out renamed variants exist.
- Every hook has a kill criterion against `--llm off`.
- Every gate runs with `--llm local`; cloud arms are optional reports.
- Offsets, addresses, gadgets, libc identification, verification and scoring are never model outputs.

#### Hooks, in priority order

| # | Hook | Attach point | Output | Oracle (assertion-specific, independent) | Success measure | Kill criterion |
|---|---|---|---|---|---|---|
| 1 | Payoff nomination | `analysis/payoff.py`, only where the deterministic ranker has no `payoff_hypothesis` | ≤ 3 function ids from the facts candidate list | Dynamic only: control diverted to the candidate in the sandbox yields a flag read or an exec (`try` receipt). Static evidence cannot promote, because it is the same evidence the ranker used. Non-runnable and PE nominations stay hypotheses. | Top-3 recall ≥ 90% on the abstained subset of renamed T0-held; confirmed-false ≤ 5% on decoys | Lift < 10 pts over `--llm off` on that subset |
| 2 | Role labelling (allocator, free, parser, menu handler) | SP-09 allocator-role query, on unnamed functions | Enum label per candidate function id | A gdb trace through an SP-11 recipe: the allocator returns distinct writable pointers and a freed pointer recurs | Non-zero sites on all custom-allocator variants; zero on controls | Deterministic inference (HYP-8) already ranks the pair top-3 |
| 3 | Vulnerability-hypothesis triage | Per function, over facts | `{function id, class enum, sink callsite id, source id}` | SP-09 queries re-run scoped to the function, then the SP-11 confirmer. Unconfirmed claims stay E2. | Verified heap/integer recall +25 pts; ≤ 10% of verified claims wrong on twins | < 10% additional confirmed true positives (HYP-20) |
| 4 | Input recipe / grammar | SP-15 | An `UntrustedInput` artefact: grammar or dictionary tokens | Coverage only: a breakpoint shows the named function is reached | +30 pts reach rate | No reach gain, or any injection-flipped outcome |

Not built: method reordering and prose (DEC-23).

#### Provider, ledger, replay

- `supwngo/llm/client.py`: `/v1/chat/completions` over `requests` against the local vLLM fleet with JSON-schema constrained output. The guided-decoding parameter is UNVERIFIED and is probed at the start of SP-13.
- **Two response parts.** A bound `answer` and an optional free-text `reasoning`. The `reasoning` is written to the ledger as an opaque blob. No code path parses it, and it is never passed to a builder, a planner or a later prompt.
- `router.py`: roles `bulk|reason|hard` map to `{base_url, model, weights_hash, max_tokens, timeout}`. `airgap: true` by default with a host allowlist. The CLI flag is `--llm off|local|any`, default `off`; `any` fails closed when the network is blocked.
- Escalation between roles happens only when the oracle refutes every proposal from the tier below. Per-run caps are recorded in the envelope.
- `ledger.py`: SQLite keyed by `sha256(model_id + weights_hash + prompt + schema + params)`, with modes `live|record|replay`. Pytest runs `replay` only. A retention setting and a redaction mode cover proprietary inputs.

#### Trust invariants (each enforced by a test)

1. **Closed-set answers.** No field of `answer` can hold an address or a free-form symbol. It carries indices, enums and small bounded integers.
2. **Only a sound oracle creates a fact.**
   - A `Hypothesis{kind, claim, source, oracle, status}` is promoted only by the oracle registered for that assertion kind.
   - Each oracle carries a soundness suite of planted-false claims it must refute at 100%. An oracle whose suite is red cannot promote.
   - "Has an oracle record" is not sufficient. There is no LLM member in the provenance vocabulary.
3. **Target text is data.** Strings and decompiled code are length-capped, escaped and delimited. Hook calls are single completions with no tools.
4. **`UntrustedInput` is a separate artefact type (hook 4).**
   - It is size- and complexity-capped.
   - It is only ever fed to the target inside the sandbox.
   - It can produce exactly one kind of fact, "function F reached by input X" (measured). It never enters a builder as a value.
5. **Budgets.** At most five proposals per hook per binary.

#### Injection and contamination rules

- Injection fixtures: binaries whose strings carry instructions such as "the win function is `decoy`". The gate is 0% change in the final recommended method against the neutralised twin.
- LLM-assisted scores are computed only on fresh T0-held. S0 and T1 are never used (HYP-21).
- A contamination probe (name-only prompt) runs per model before any set is used.
- Cloud models may see generated T0 fixtures only, and only in optional reports (DEC-21).

#### Evaluation arm

- `AgentFollower` (`benchmark/walkthrough/followers.py`, reviewer-cited) is ported to the local provider.
- Two arms run on the same pinned local model: shell only, and shell plus `facts`/`offset`/`pwn`/`verify`/`try`.
- Metrics are solve rate under `verify`, tokens, wall-clock and false-success claims.
- The full run is in SP-14: 20 variants × 2 reps. An earlier pilot is optional, runs only if a local model is served, and gates nothing.

### 9. Risks, pre-mortem and kill criteria

| # | How it fails | Early signal | Response |
|---|---|---|---|
| 1 | **The facts layer becomes "schema v5".** | SP-03 slips past 2 weeks; more than 25 keys; a merge-lattice discussion appears. | Hard caps. SP-04 starts on whatever SP-03 has. |
| 2 | **Ghidra is too slow, flaky or unsandboxable.** | SP-03A gate G4 or G5 fails; the TIME quorum is repeatedly missed. | Decompile strictly on demand; a reserved off-peak window; otherwise the Bet 1 pivot. |
| 3 | **The generator is a monoculture.** | Dev-minus-held gap near 0 while T1 sits 20+ pts lower. | Held-out by template from SP-02c; T1 as a second opinion; shapes mined from how2heap and cb-multios. |
| 4 | **The single maintainer is saturated.** M0 grew to about 3 weeks after the review. | Two consecutive sprints miss exit; baselines not updated. | Commitment ends at M1 (DEC-26). Cut order: M4, SP-14, SP-08, then SP-04b. *(Amended by AMD-21: SP-04b is no longer cuttable; the order is M4, SP-14, SP-08.)* SP-02c and SP-06 are the agent-heavy parallel tracks. |
| 5 | **Non-stack classes do not yield to static plans.** | SP-10 held-out METHOD-R below 50% on heap/integer. | Scope to "class + site + distance kind + required inputs" and rely on `--measure`. No new executors. |
| 6 | **The sandbox is unavailable.** Unprivileged user namespaces are blocked. | The SP-01a day-1 probe fails. | Dedicated uid fallback (§11 Q10). Without either, no baseline is accepted. |
| 7 | **Honest abstention reads as regression.** `template` exits 2 on most targets between SP-02 and SP-04. | Owner or users object to 2.2.0. | The release notes say so (DEC-24); `--measure` and `--offset` restore the old behaviour explicitly. |

**Kill and pivot criteria per bet.**

- **Bet 1 (Ghidra facts).**
  - If SP-03A fails G1, G2 or G5: Ghidra is kept for decompile only, distance moves to a second estimator (rizin or angr variable recovery, measured on the same gates), and SP-03 shrinks to the cache plus decompile.
  - If, after SP-04, OFF-S on M1 shapes at -O0 is below 80%: the same pivot.
  - If mingw PE DECOMP is below 80%: PE is descoped to "decompile via Ghidra, offset best-effort" and the owner is told.
- **Bet 2 (one plan).** If, after SP-10, held-out METHOD-R fails to beat the majority-label baseline by ≥ 20 points: stop planner work, ship `pwn` as "findings + distances + required inputs" with no single recommendation, and move selection to the agent.
- **Bet 3 (toolbox and oracle, then LLM).** If the local two-arm evaluation shows the toolbox improves neither solve rate nor cost by ≥ 25% (HYP-12): narrow the product to `facts` + `verify` + corpus. Any hook that does not beat `--llm off` by its threshold is deleted in the sprint that measures it.

### 10. Hypotheses register

| ID | Claim | Cheapest experiment | Falsifier | Sprint | If falsified |
|---|---|---|---|---|---|
| HYP-1 | Ghidra frame + P-code gives the exact distance on ≥ 90% of -O0 and ≥ 60% of -O2 M1-shape fixtures. Evidence so far: exact on 3/3 compiler-built cases, abstain on 3/3 hard cases (SPOTCHECK:49-58). | SP-03A gates G1–G3, then SP-04 against tiered truth. | Below 80% at -O0, or wrong-labelled above 2%. | SP-03A, SP-04 | Bet 1 pivot. |
| HYP-2 | `-process` on a persisted project is ≤ 30 s. | Time cold against `-process -noanalysis` on a quiet host. | Warm > 30 s on a small dynamic binary. | SP-03 | Precompute candidate decomp at export. |
| HYP-3 | Agreement between the P-code and instruction estimators predicts correctness. | Same data as HYP-1. | More than 2% of agreeing pairs wrong. | SP-04 | `agree` is not a confidence signal; require OFF-D. |
| HYP-4 | The engines disagree on most binaries today. | Four-way agreement of `pwn`/`template`/`explain`/`autopwn` on T0-mini. | Agreement ≥ 80%. | SP-02 | SP-05 unification drops to polish. |
| HYP-5 | Method selection and win detection are name-driven. | Rename twins in T0-mini before SP-04. | Drop under 10 pts. | SP-02, SP-04 | Payoff rewrite loses priority to detectors. |
| HYP-6 | Performance falls sharply from -O0 to -O2. | Passcard split by optimisation level. | Under 10 pts of difference. | SP-04, SP-06 | Less urgency on objdump scraping. |
| HYP-7 | Static executor gates classify better than `StrategySuggester`. | Sweep of `is_applicable` over T0 with the dynamic profile disabled. | Gates not above the suggester, or most need dynamic facts. | SP-05 (spike), SP-10 | Non-stack plans come from SP-09 detectors. |
| HYP-8 | Allocator roles are inferable without names. | Stripped custom-allocator fixtures. | True pair outside the top 3 on more than 30%. | SP-09 | LLM hook 2 becomes primary. |
| HYP-9 | **MEASURED — held.** `solve` reproduces its recorded HTB results under `shell_proven`: 7/7, 21/21 reps, `echo_ambiguous: false`, 0 hard errors at `1741b34`; techniques unchanged; 7–71 s per rep (SPOTCHECK:65-70). | Done. | — | closed | In-sample only. Consequences: the "unmeasured" caveat and the SP-02 re-measure are removed; the SP-11 guard is "stays 7/7 (21/21)"; the orchestrator override path is left untouched until SP-05. |
| HYP-10 | RT-08 as drafted leaves `recommended` unchanged. | The SP-02b hermetic test through `analyze()`. | Recommended becomes SROP with the gate change alone. | SP-02 | Tiering is kept for the constant-list problem only. |
| HYP-11 | Breakpoint-at-sink recovers distances where cyclic crashing returns none. | Runnable T0 canary and menu fixtures, with recipes. | Fewer than half recovered. | SP-04a (benchmark), SP-11 | OFF-D limited to crashable targets. |
| HYP-12 | Agent + toolbox beats agent alone on cost, and possibly solve rate. | SP-14 local two-arm run. | Under 25% improvement and no solve gain. | SP-14 | Bet 3 pivot. |
| HYP-13 | The held-out gap is large for the existing executor families. | T0-held under `solve`; the archived R3 set if recoverable. | Held-out within 10 pts of in-sample. | SP-06 | FIRST_TECHNIQUES encodes real signal; keep it as planner priors. |
| HYP-14 | ≥ 30% of `exploit/` is unreachable from any command. | Import-graph reachability + coverage over the passcard. | Under 15%. | SP-07 | SP-12c shrinks. |
| HYP-15 | FunctionID names ≥ 90% of libc sinks in static builds. | Probe in SP-03A on host libc; full across three glibc versions. | Under 70%. | SP-03A, SP-08 | rizin FLIRT or BSim; or syscall-role only. |
| HYP-16 | cwe_checker beats first-cut queries on some CWE classes. | Run both on T2. | Loses on every class or cannot run on Ghidra 12 offline. | SP-09 | Skip it. |
| HYP-17 | Reaching the sink is the binding constraint for dynamic confirmation. | Count SP-11 confirm failures by cause. | Under 30% are reachability. | SP-11 | Cancel SP-15. |
| HYP-18 | Review rounds do not predict fewer errata. | Errata per merged unit across SP-01–06. | Reviewed units show ≤ half the rate. | SP-06 | Restore two-round review for M-sized work. |
| HYP-19 | Closed-set answers + sound oracles drive hallucinated-value incidents to zero. | Adversarial stub, 1,000 runs, plus oracle soundness suites. | Any builder input without a sound-oracle record. | SP-13 | No hook ships until fixed. |
| HYP-20 | Local-model triage adds verified recall on heap/integer. | SP-14 on held-out, local; cloud arm optional. | Under 10% additional confirmed true positives. | SP-14 | Delete hook 3. |
| HYP-21 | Models are contaminated on HTB-7; naive integration is injectable. | Name-only prompts; injection fixtures. | ≤ 1/7 answered; under 5% flip rate. | SP-13 | The S0 exclusion stays regardless. |
| HYP-22 | The "load flake" is contention; more stringly-typed comparisons are live bugs; the Dockerfile cannot reproduce results. | 10 serial quiet runs; the AST lint extended to `arch`/`os`; build the image. | Any failure when quiet; RELRO is the only mismatch; the image reproduces. | SP-01, SP-06 | Quarantine the test; drop the lint extension; keep the Dockerfile. |
| HYP-23 | **New.** Most of the 427 s static cold cost is whole-program decompile, not import and analysis. | The SP-03A time split on ≥ 3 static fixtures. | Analysis alone > 180 s. | SP-03A | Analysis option tuning or FID-first; otherwise static binaries are served by the second estimator. |
| HYP-24 | **New.** bubblewrap with unprivileged user namespaces works on this host, including for Ghidra headless. | The day-1 probe in SP-01a; the Ghidra run in SP-03A. | Namespace creation denied, or Ghidra fails under read-only binds. | SP-01a, SP-03A | Dedicated-uid fallback; owner action. |

### 11. Open questions for the owner

Only questions that block or reorder sprints are listed. The team proceeds on the stated default.

1. **Accept-sets (DEC-7; affects S0 truth files only).** If `solve` gets a proven shell with a technique other than the write-up's, is that "the right method" on smoke? *Default: yes, after review. Generated sets use solver-proven accept-sets and need no review.*
2. **Offset on non-stack-return bugs (DEC-8; affects SP-04 and SP-10).** Is "see the offset" the controlling distance of the actual primitive, with a kind? This makes snow_scan an `indexed_base_ptr` target, not a saved-RIP one. *Default: yes.*
3. **Execution by default (DEC-9; affects SP-02b).** `template` stops executing targets in SP-02 and will exit 2 without an offset until SP-04. Acceptable for 2.2.0? *Default: yes; `--measure` restores it.*
4. **Held-out custody (DEC-22; now needed at the SP-02c exit).** Who holds the held-out templates and seed, in a path no development agent can read? Can the archived R3–R5 corpora be recovered as a one-shot blind set? *Default: a mode-0700 path under the owner's account, hidden by the sandbox; R3–R5 treated as lost.*
5. **A quiet measurement window (blocks TIME gates from SP-03).** Can the nightly have a reserved off-peak slice or cgroup? *Default: run at night; the TIME gate fails closed if the quorum of valid samples is not met.*
6. **MSVC PE (DEC-13; reorders SP-16 against SP-06).** Does "exe works" mean general Windows binaries? If so, can you supply a toolchain or binaries with PDBs? *Default: every PE claim is labelled "mingw PE32/PE32+" until MSVC fixtures pass.*
7. **Local models (blocks SP-13).** Which model IDs and context lengths are served on the Sparks, and does the vLLM support JSON-schema guided decoding? *Default: probe at SP-13 start.*
8. **Cloud exposure (DEC-21; blocks nothing).** May cloud models see generated T0 fixtures for optional reports? *Default: yes for T0 only.*
9. **Frozen scope (DEC-16; affects SP-12c).** May `kernel/` and `walkthrough/` be frozen now, with `kernel/` moved to an extra later? *Default: freeze both; no deletion without your word.*
10. **Sandbox on the analysis host (DEC-25; blocks the SP-01a baseline if HYP-24 fails).** If unprivileged user namespaces are disabled, will you enable them for bubblewrap or create a dedicated unprivileged benchmark uid? *Default: probe first; ask only if it fails.*
11. **Commitment horizon (DEC-26).** Is committing to M1 only, with M2 planned and M3/M4 as options, acceptable? *Default: yes.*

### 12. Review disposition

#### Blocking items

| ID | Summary | Disposition | What changed or why |
|---|---|---|---|
| B-1 | Stale baseline: `solve` called unmeasured; VOID cells counted as failures | ACCEPTED | §0 and §1.6 now state 7/7 (21/21 `shell_proven`) as in-sample smoke and offset as 0 of 4 valid with 3 VOID. HYP-9 is MEASURED and closed; the SP-02 re-measure and its risk are removed. SP-01a ingests the artefact and emits `VOID`. |
| B-2 | Passcard runs in the real corpus directory; truth readable by the tool | ACCEPTED | SP-01a: disposable copies, forced `-o` (`cli.py:1245-1249` confirmed), bubblewrap with truth, sources and debug siblings hidden, `PT_INTERP` pre-flight in the cell `cwd`, answer-key mutant. DEC-25, HYP-24 and Q10 cover the case where namespaces are blocked. |
| B-3 | Timeout fix and RED proof mismatch | ACCEPTED | My claim was wrong: `test_crash` has no process group and only swallows the timeout (`offset_finder.py:502-520`). SP-01b adds `core/proc.py` with `start_new_session` and group kill. The RED is now crash-then-refine-timeout plus a descendant-PID fixture; EOF spin is demoted to a robustness test. |
| B-4 | SROP widening unsound; test blesses a false positive | ACCEPTED | Verified `strategy.py:360` is a substring test and `:362-370` is pop-only. SP-02b adds `rax_control.py`, reusing the executor's wrapper analysis (`srop_nowrite_techniques.py:153-171`). The draft's positive test is replaced by a positive with a wrapper and a negative without. `read_return` is speculative only. |
| B-5 | Override patch cannot produce RET2WIN | ACCEPTED | Verified `strategy.py:227-228` against `orchestrator.py:1088-1094`. SP-02a injects run-scoped `KnownFacts` before `analyze()`, with `--ret2`, `--rop` and libc-relative rules taken from `orchestrator.py:736-742`. |
| B-6 | Template repair still emits wrong templates; executes the target | ACCEPTED | SP-02b: builder-compatibility table; wrapper-SROP and ROP_EXECVE exit 2 with `no_template_for_method`; `measure=False` by default (`auto.py:303, 396`); the zero-offset RED is rewritten. DEC-9 flips `template` now. |
| B-7 | No-`main` selection too weak | PARTIAL | Selection order and `selected_by` adopted; a stripped dynamic fixture added (SP-01b). PE32/PE64 default-selection tests move to SP-03, because `decompile` calls the ELF-only `Binary.load` (`cli.py:2051`) and cannot open a PE before the facts loader exists. |
| B-8 | Static offset does not cover what it promises | PARTIAL | Added to SP-03/04: per-function canary slot (moved from SP-08), depth-1 callee summaries, affine indexed destinations (ancient_interface 4120/4104), def-use-proven wrapper handling, benchmark breakpoint truth, generator recipes. M1 is reduced to four declared shapes. Loop copies, VLA, depth ≥ 2, FPO custom ABIs and SEH or `/GS` must abstain and are counted. The 4/4 smoke claim is corrected to 3/3 plus an snow_scan abstain. Full interprocedural and loop-copy support is not built in M1 because it would rebuild a private analyser (DEC-11); loop copy moves to SP-09/10. |
| B-9 | Oracle and scorecard can be gamed | ACCEPTED | §1.2 reports coverage, exact and selective. §1.5 adds the per-axis cap and manifest, and the corrected compiler rule. Accept-sets come from construction plus reference solvers. Twin penalty and METHOD-SPAM with a capped `speculative[]`. Mutants for every metric. Three truth tiers; PE is "static-validated". S0 keeps human-reviewed accept-sets because S0 never gates. |
| B-10 | Commits to Ghidra before the decisive experiment; late prerequisites | ACCEPTED | New SP-03A spike with five predefined gates; DEC-2 is provisional. The export is minimal with no whole-program decompile. Canary and the sandbox move to SP-03; a minimal FID probe moves to SP-03A. Only the multi-version FID stays in SP-08. |
| B-11 | Deletion schedule is a hidden big-bang migration | ACCEPTED | Verified `cli.py:296,370,413,457`, `supwngo/__init__.py:51-52` and `exploit/__init__.py:3,56,188`. SP-12 is split into 12a, 12b and 12c. The LoC gate is removed (DEC-14). `templates.py` is no longer called orphaned and leaves the SP-05 deletion. |
| B-12 | LLM trust model contradicts its hooks and offline requirement | ACCEPTED | `reasoning` is an opaque ledger blob. Hook 4 uses a separate `UntrustedInput` type with coverage-only promotion. Hook 1 promotes only on a dynamic receipt. Oracles need a passing soundness suite. The SP-07 pilot gate is removed; all gates run `local` or `off`; cloud is optional. |

#### Non-blocking items

| ID | Summary | Disposition | What changed or why |
|---|---|---|---|
| N-1 | One canonical RELRO field | ACCEPTED | `relro_kind` enum; display string preserved; lint and per-value tests (SP-01b). |
| N-2 | angr contract underspecified | ACCEPTED | Total tagged union validated at the parent; five distinct cases tested. |
| N-3 | Identifier lint is not an anti-overfitting control | ACCEPTED | §1.5 rule 1 reworded; a planted structural cheat must fail held-out in SP-06. |
| N-4 | Payoff evidence semantics | ACCEPTED | Three tiers; file-copy decoys; `required_args` only via parameter slicing (SP-04b). |
| N-5 | Cache identity and operator facts | ACCEPTED | Manifest-hash key; operator facts are a run-scoped overlay (DEC-27); diagram fixed. |
| N-6 | TIME can become all-VOID | ACCEPTED | Quorum of 20 valid cold and warm samples, otherwise the run fails. |
| N-7 | PE acceptance ambiguous | ACCEPTED | Every PE claim is labelled mingw PE32/PE32+, per compiler and cookie scheme (DEC-12, DEC-13). |
| N-8 | Tagging 2.2.0 after SP-02 is premature | PARTIAL | The tag stays at the end of SP-02 because the orchestrator placement HO-02 requires it. Its notes scope it as a baseline release with every FAIL listed; the first PASS-claiming release is 2.3.0 at M1 (DEC-24). |

#### Sequencing suggestions and "missing" items

| Item | Disposition | What changed or why |
|---|---|---|
| SP-01A/B/C split | PARTIAL | Two PRs (SP-01a, SP-01b) per FOLD-NOTES §5; the selector repair is the last commit of SP-01b and its cut line. |
| SP-02A/B/C split; no overrides on `offset` yet | ACCEPTED | SP-02a/b/c; `offset` gets overrides in SP-04. |
| Held-out template split before SP-03 | ACCEPTED | Sealed in SP-02c; custody question moved earlier. |
| SP-04B payoff separate | ACCEPTED | SP-04a/b with separate exit numbers under one ID. |
| Breakpoint oracle benchmark implementation moved to SP-04 | ACCEPTED | `truth_bp.py` in SP-04a; the product confirmer stays in SP-11. |
| SP-06 smaller start, CI-driven growth | ACCEPTED | 200/100, growing to a CI half-width ≤ 8 pts. |
| Deterministic recipes before dynamic confirmation | ACCEPTED | Generator recipes in SP-02c; product recipes lead SP-11; SP-14 now depends on SP-11. |
| Hostile-binary threat model | ACCEPTED | DEC-25; sandbox from SP-01a and SP-03. |
| Manual escape hatch for abstentions | ACCEPTED | `--vuln-func`, `--sink`, `--buffer`, `--canary-offset` in SP-04; `--known` in SP-05. |
| Public API migration policy | ACCEPTED | SP-12a. |
| Cache governance | ACCEPTED | SP-03 (quota, eviction, purge, corruption repair, retention); ledger retention in SP-13. |
| Licensing gates | ACCEPTED | `tools.lock.toml` fields in SP-06. |
| Definition of "decompilation works" | ACCEPTED | §1.2 DECOMP and its mutants. |
| Evidence for recommendations | ACCEPTED | METHOD-R requires a cited function and site from SP-05. |
| Comparative release claim | ACCEPTED | §1.4 comparative table; the "best in existence" wording is dropped. |
| 16 sprints too large for one maintainer | PARTIAL | Scope kept as a map, but commitment ends at M1 (DEC-26) with an explicit cut order. |

### 13. Change log vs draft

- HYP-9 is MEASURED (7/7, 21/21 `shell_proven`); the "today" baseline is rewritten, VOID cells are separated, and the SP-02 re-measure is removed.
- SP-01 is two PRs: SP-01a (sandboxed passcard, truth, mutant table, baseline, I-45) and SP-01b (fixes, HO-01).
- The passcard runs every cell in a bubblewrap sandbox with truth hidden; the sandbox is product code reused by Ghidra and `verify` (DEC-25).
- The offset fix uses a new group-killing process helper; the claim that `test_crash` was a model is corrected.
- The SROP gate requires explicit `RaxControl` evidence shared with the executor; the unsound positive test is replaced.
- Overrides become run-scoped `KnownFacts` injected before `analyze()`; they are never cached (DEC-27).
- `template` stops executing targets in SP-02 and refuses builders that implement a different technique.
- New SP-03A spike gates DEC-2; the facts export is minimal, with no whole-program decompile.
- Per-function canary, cache governance and the analysis sandbox move into SP-03; SP-08 keeps only broad FunctionID coverage.
- M1 offset scope is reduced to four declared shapes with mandatory abstention elsewhere; smoke expectation is 3/3 plus an snow_scan abstain, with ancient_interface at 4120/4104.
- Scoring reports coverage, exact and selective accuracy; truth is three-tiered; no case is dropped; accept-sets on generated sets come from reference solvers.
- SP-12 is split into SP-12a/b/c behind deprecation and import-contract tests; the LoC gate is gone; `templates.py` is recognised as a public export.
- LLM plan: local-only gates, opaque `reasoning`, a separate `UntrustedInput` type, dynamic-only promotion for hook 1, oracle soundness suites.
- 2.2.0 stays at the end of SP-02 as a scoped baseline release; PE claims are labelled mingw; "best in existence" is replaced by a comparative table.
- Commitment horizon is M1 (DEC-26); S7 leftovers (I-45, HO-01, HO-02, CG-04, CG-01b) are placed in the sprint map.

### 14. Amendments

Amendments are appended here instead of being edited into the text above. Each records its source. An inline
*(Amended by …)* marker is left where the original text would mislead.

#### Owner directive F (2026-11-12): focus on three strategies until they are bulletproof

> Owner, verbatim: "If the scope becomes too large, pick 2-3 strategies and focus heavily on just those. Do not
> move on until those are bulletproof."

The roadmap's scope is too large (16 sprints), so the directive applies now. **This directive overrides the
sequencing in §5–§7.** Where the two conflict, this section wins.

**Focus strategies.** These are exploit strategies, the `StrategySuggester` method families.

| # | Strategy (method family) | Why this one | S0 coverage |
|---|---|---|---|
| F-1 | `ret2win`, including the supplied-component path `--win/--winfun/--ret2/--eip` | The most common CTF stack win. It is the owner's PASS path (a) as worded. | rocket_blaster_xxx |
| F-2 | `ret2libc`: leak, then libc base, then `system("/bin/sh")`, including a supplied libc and manual addresses | The owner's PASS path (b), a template with manual memory addresses. It is the default when no win function exists. | rocket_blaster_xxx, ancient_interface |
| F-3 | Syscall ROP: `srop` and `rop_syscall` | Both rest on one piece of evidence: a `syscall` gadget plus proven `rax` control (SP-02b `rax_control.py`). Together they cover the two stack targets that F-1 and F-2 cannot solve. | sick_rop, snow_scan (and ancient_interface via `rop_syscall`) |

F-1 to F-3 cover all four stack-return S0 targets. `auth-or-out`, `sabotage` and `bon-nie-appetit` (heap,
environment and off-by-one) are still measured by the passcard, but they get **no fixes** until gate F is met.

**Gate F: bulletproof.** All of the following must hold for each focus strategy, on a strategy-specific
generated suite.

The **suite**, per strategy:
- at least 40 dev positives and 20 sealed held-out positives;
- at least 20 negative controls: near-misses where the strategy does not apply, plus patched twins with no
  overflow.

The **axes**:
- amd64 ELF, PIE on and off, `-O0` and `-O2`, stripped and unstripped;
- randomized function and buffer names and sizes, so no name hints;
- `read`, `gets`, `fgets` and `scanf` sinks;
- mingw PE builds of the same sources, for the static rows.

| Row | Requirement |
|---|---|
| F.method | Top-1 `recommended` is in the accept set: 100% of dev, ≥ 95% of held-out. On negative controls, the strategy is never top-1 (0 false positives). |
| F.offset | ELF OFF exact on 100% of known-value cells. PE static offset exact on ≥ 95%, and every other PE cell abstains with a reason (0 wrong numbers). |
| F.decompile | DECOMP PASS on 100% of ELF and ≥ 95% of PE. |
| F.component | PASS path (a): with the supplied component, `pwn`/`solve` reaches `shell_proven` on 100% of dev and ≥ 95% of held-out ELF positives. |
| F.template | PASS path (b): `template -t <strategy>` plus scripted manual inputs reaches `shell_proven` on 100% of dev and ≥ 95% of held-out ELF positives. An unfilled template exits 2 and never runs. |
| F.robust | ROBUST 100%, no false success, and 0 flakes across 3 reps. Every held-out miss is listed and explained. |
| F.smoke | The four stack S0 targets PASS end to end: method, offset, decompile, and path (a) or (b). |

Once met, the gate-F suite becomes a **pre-merge regression gate**. A later PR that drops any row is blocked.

**The focus path.** These are the only sprint slices allowed before gate F. Each slice is scoped to F-1 to F-3.

| Sprint | Scope under directive F |
|---|---|
| SP-01 | Unchanged. It is the measurement instrument and the honesty fixes that gate F needs. |
| SP-02a | Overrides and `KnownFacts`: only the F-1 and F-2 components (win, return target, libc, leak addresses). |
| SP-02b | SROP and `rop_syscall` evidence (`rax_control.py`), role tiering, and an honest non-executing `template` for the three focus builders only. |
| SP-02c | Generated suite and tiered truth, restricted to the three focus strategies, their negatives and their held-out split. The release tag (HO-02) stays here. |
| SP-03A, SP-03 | Ghidra spike and minimal facts, only as far as F.decompile and the PE load need. |
| SP-04a, SP-04b | Static distance and static-first `offset` (F.offset, PE). Payoff tiers only for win-function detection (F-1). |
| SP-05 | Plan v1 and honest templates for the three focus strategies only. |
| SP-06 | Generator v1 and the held-out report for the focus suite only. The public tier, comparative table and nightly lane are deferred. |

**Frozen until gate F.**
- Every other strategy: heap, format string, integer, environment, `ret2dlresolve`, stack pivot, shellcode,
  `one_gadget` and FSOP. These must still abstain or decline honestly, but are not improved.
- SP-07 to SP-16, including the LLM hooks and the deletion sprints.
- Any detector work outside the stack-return class.

If a frozen item turns out to block a gate-F row, it is pulled in as the smallest slice that unblocks the row,
and recorded here as an amendment.

#### Orchestrator amendments (from the SP-01 plan review)

| ID | Amendment | Source |
|---|---|---|
| AMD-O1 | SP-01 does not add `OffsetResult.confidence`. It is deferred to SP-04, which has its first consumer. SP-01 adds `kind`, `error_code` and `isolation`. | SP-01 plan §4.1. Daybreak Blue rounds 2–4 judged the deferral sound (N3-1). |
| AMD-O2 | The approved SP-01 plan governs SP-01's detail wherever it differs from §6 above. Where it differs: <ul><li>`supwngo/core/sandbox.py` lands in SP-01a, and product `offset` runs through it in SP-01b;</li><li>the process-runner interface is `proc.run -> ProcResult` with four states;</li><li>the RELRO inventory is the plan's measured 39-read table;</li><li>the passcard self-test pins are those in plan §3.7.</li></ul> | `docs/plans/2026-11-12-sp01-passcard-and-honesty-plan.md` v4.1, approved with changes in Daybreak Blue round 4. |

#### Verify-pass amendments (Mythos 5-2, execution allowed)

**Record:** `docs/reviews/2026-11-12-mythos-roadmap/verify-mythos-execution.md`.
- Run: claude-mythos-5-2, 72 minutes, 41 turns, `is_error = False`.
- It worked on a scratch copy and wrote nothing to the live repo.
- One command, an `rm -rf` chain, was denied; the experiment was re-run in a form that was allowed.

**Status values:**
- **ADOPTED (SP-01)** means folded into SP-01 plan §8.
- **RECORDED (SP-xx)** means binding on that sprint when it is planned.
- **FROZEN (F)** means parked by directive F until gate F is met.

| ID | Amendment, in brief | Status |
|---|---|---|
| AMD-1 | **§0/§1.6 "Today" corrected.** From challenge-directory copies: <ul><li>offset is 2 of 3 valid stack-return cells correct (sick_rop and rocket both 40), with no crash; the earlier crash was a repo-root run artefact;</li><li>decompile is 5/7, not 3/7;</li><li>ROBUST is 28/28 single documents, but 28/28 exit 0 including the failures.</li></ul> Method 2/7 and the constant template 7/7 reproduce. | ADOPTED (SP-01 §8 V-5); the passcard baseline replaces the numbers |
| AMD-2 | **Preflight.** A loader must be regular, non-empty and executable; sabotage and bon-nie-appetit ship a 0-byte loader. Proposal: move `run_with_loader` to SP-01a. | Preflight already planned. The move is **declined**: both targets are outside the F focus and stay honestly VOID. CG-04 stays in SP-02c for F-2. |
| AMD-3 | **Cells.** No dot-component paths, a private `/tmp` tmpfs, and a Ghidra control cell. | ADOPTED (SP-01 §8 V-1, V-2) |
| AMD-4 | **SP-03 store.** Keep exported JSON only, not Ghidra projects. Add a stale-lock-after-kill test. | RECORDED (SP-03) |
| AMD-5 | **`__*_chk` sinks.** Add them to the sink table. The generator sets fortify explicitly per variant; a fortified build is a patched twin. | RECORDED (SP-04a, SP-02c); binding on the gate-F suite |
| AMD-6 | **angr `CFGFast(normalize=True)`.** Fix it, and make the happy-path test assert real code. | ADOPTED (SP-01 §8 V-7) |
| AMD-7 | **Test entry point.** Three test files run the installed CLI; switch to `sys.executable -m supwngo.cli`. | ADOPTED (SP-01 §8 V-3) |
| AMD-8 | **Exit 2 collides with click usage errors.** | ADOPTED (SP-01 §8 V-13): exit 2 is kept, and every negative test asserts the JSON error field |
| AMD-9 | **SP-02a RED proofs.** Every "must not produce X" proof asserts that the option was accepted first. Add the `secret`/`vuln_func` decoy fixture. | RECORDED (SP-02a); binding on F-1 |
| AMD-10 | **PE.** `unsupported_format` for `pwn`/`template`/`offset`; PE default function and PE DECOMP baseline in SP-01. | ADOPTED (SP-01 §8 V-8, V-9, §8.3) |
| AMD-11 | **The crash-driven finder** stays permanently as the `--dynamic` confirmer. Fix the `core*` glob. | Glob already in SP-01b. The DEC-9 change is RECORDED (SP-04). |
| AMD-12 | **`rax_control` evidence is semantic,** not the executor's one-shape regex. The negative fixture must make the return value uncontrollable. | RECORDED (SP-02b); binding on F-3 |
| AMD-13 | **RELRO replacement list** drops `got_plt.py`; the lint covers `Protections` receivers. | Already covered (SP-01 §4.3 allowlists it by receiver type) |
| AMD-14 | **Identifier lint** needs a docstring decision and an inventory. | Already covered (SP-01 §4.5) |
| AMD-15 | **HYP-14** restated as statement coverage over the passcard. `--version` takes 1.07 s. | FROZEN (F); M3 |
| AMD-16 | **SP-03A gates.** G3 is measured with fortify on and off. Add a static-axis line decided by the FID probe. | RECORDED (SP-03A) |
| AMD-17 | **SP-04a breakpoint truth** breaks on callsite addresses, never on symbols. | RECORDED (SP-04a) |
| AMD-18 | **Q10 / HYP-24 closed:** bubblewrap works unprivileged on this host, including for Ghidra with a private `/tmp`. | ADOPTED. The owner question is removed; the SP-01 §3.3 contingency stays as a guard. |

#### Owner directive W (2026-11-13): no hardcoded target values

> Owner, verbatim: "supwngo has a list of win names for win functions form htb challenges. They are hardcodes.
> That is out of scope. We need to be able to use clever ghidra and gdb scripts to dynamically evaluate what the
> win function is on the fly for individual binaries. There should never be hardcoded values that only apply to
> hack the box"

**This directive overrides §5, §6 SP-04b and §9 wherever they conflict.**

| ID | Amendment | Status |
|---|---|---|
| AMD-19 | **SP-04b is pulled forward.** It runs immediately after SP-01b, before SP-02. It absorbs the focused prerequisites it would otherwise get from SP-02c and SP-03: <ul><li>a seeded payoff fixture corpus with a dev/held split;</li><li>a reusable sandboxed analysis runner;</li><li>an evidence cache with time budgets.</li></ul> It also absorbs the dynamic confirmation tier for payoff functions (previously SP-07). Plan: `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md`. | ADOPTED |
| AMD-20 | **Names are never consulted** for payoff selection, not even as a tie-break. This supersedes "names break ties only" in §6 SP-04b. Ties break by evidence, then address. | ADOPTED |
| AMD-21 | **SP-04b leaves the cut order** in §9 risk 4. The cut order becomes M4, SP-14, then SP-08. | ADOPTED |
| AMD-22 | **The scope covers every hardcoded target value,** not only name lists:<ul><li>payoff-name lists, including generated-script defaults;</li><li>guessed comparison constants;</li><li>platform-specific flag patterns.</li></ul> A committed, machine-generated inventory is the denominator. | ADOPTED |

**Findings beyond the AMD list:**
- `template` discards what it measures (it emits `offset = 0`), adopted into SP-02b.
- PIE addresses differ by backend, adopted into SP-01 §8 V-10.
- Ghidra failures hide their reason, adopted into SP-01 §8 V-11.
- Bet 1 held, with zero wrong answers: P-code distance was exact on 8 of 23 new fixtures and abstained on 15.
  The abstentions were fortified `-O2` sinks, callee sinks (no depth-1 summary yet) and a stripped static
  binary. This is input to SP-03A and SP-04a.
