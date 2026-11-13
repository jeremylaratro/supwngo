
# Synthesis — the supwngo roadmap, sprint map and plan (Mythos 5-2)

You are the synthesis reviewer. Five adversarial dimension reviews of supwngo have been written by
independent reviewers. Your job is to turn them into **one bulletproof roadmap + sprint map + plan** that
makes supwngo the best automated binary RE/VR tool for the owner's actual goals. You are the decision
maker: resolve conflicts between reviews, cut what does not earn its place, and sequence the rest.

## Inputs (read all of them first)

- `_review/BRIEF.md` — owner ask, PASS criteria, measured state, infrastructure, **§7 corrections**.
- `_review/SCORECARD.md` — today's 7-target × {pwn, template, decompile, offset} measurement.
- `_review/SPOTCHECK.md` — which reviewer claims the orchestrator re-verified.
- `_review/S6-PLAN-DRAFT.md` — the sprint that was about to start (RT-08/09/10).
- `_review/reviews/D1.md` … `D5.md` — Architecture/scalability (D1), RE/VR depth (D2),
  Exploitation + PASS criteria (D3), LLM integration (D4), Evaluation/benchmarks/process (D5).
- The code itself: verify any claim you rely on for a sequencing decision (`path:line`).

## Decisions already taken by the orchestrator (owner has authorised "whatever is needed")

Treat these as defaults. Overturn one only with evidence, and say so explicitly.
1. **Product definition:** supwngo is first a *verified, offline, machine-drivable analyst/agent
   toolbox* that meets the PASS criteria (right method + completable artefact + decompile + offset on ELF
   and PE). Autonomous end-to-end exploitation stays, demoted to a verifier/executor stage behind the
   same plan — not the headline metric.
2. **Ghidra is the system of record** for whole-program facts (installed; loads PE natively; offline).
   angr becomes an optional, budgeted, directed helper.
3. **Offline-first.** LLM hooks are off by default, use the local OpenAI-compatible vLLM fleet, and are
   closed-set proposers confirmed by an oracle. Cloud models are an evaluation arm only.
4. **The seven HTB targets are a smoke set, not a tuning set.** Generalisation is measured on a generated
   corpus with build-derived ground truth and a held-out split.
5. **Deletion is allowed** once a replacement path exists and a reachability test guards it (git keeps
   history). The owner's earlier decision D-1 (legacy fallback) is resolved as: remove after `template`
   and `autopwn` no longer depend on it.
6. **Process:** branch + PR per sprint, Conventional Commits, CHANGELOG, local tests, written plan with
   peer review for non-trivial sprints — but plans for S-sized work are ≤ 1 page, and every sprint exit
   criterion is a measured delta on a named set (no per-target exit criteria).
7. Sprint capacity: one maintainer + AI agents; plan in sprints of ~1 week of agent-assisted work.

## Required output (markdown, this exact structure; be concrete; ~6,000–9,000 words)

### 0. Executive summary
≤ 12 bullets: where supwngo really is, the thesis for "best in existence" (a *defensible niche*, not
breadth), the three bets, and what we stop doing.

### 1. North star and scorecard
- The product statement (one paragraph).
- The **PASS scorecard definition**: metrics (method listed / recommended with confirmed preconditions,
  offset exact static/dynamic, RIP-control proof, decompile anchors, criterion (a) with supplied
  components, criterion (b) template with machine-fillable placeholders, robustness, wall time), how each
  is computed, on which sets, and the target value per milestone. Resolve the reviewers' disagreements on
  top-1 vs listed, and on what "offset" means for heap/integer targets.
- Evaluation sets (smoke / dev / held-out / PE / public tiers) and the anti-overfitting rules.

### 2. Target architecture
The end-state shape in one diagram (ASCII) and ≤ 1 page of text: per-binary knowledge base / facts
export, analyzer registry, detectors as evidence-graded queries, planner, renderers (pwn / template /
explain / autopwn), oracle/verify, machine contract (JSON envelope, `facts`, `verify`, `try`, tool
manifest, optional MCP), LLM layer. State what is deleted or demoted.

### 3. Decision register
Numbered `DEC-n`: each decision (including the defaults above and every owner question raised by the
reviewers that changes the roadmap), the chosen answer, rationale, reversibility, and what would make us
revisit it. Mark the ones that genuinely need the owner (`OWNER`), with the default we proceed on.

### 4. Roadmap (phases / milestones)
3–5 milestones (`M0`…), each with: objective, the scorecard target values that define "done", key
deliverables, and the hypotheses it tests. Include a "stop doing" list and a deletion schedule.

### 5. Sprint map
A table of every sprint (`SP-01` … ~`SP-16`): goal, scope (modules/commands), depends-on, effort
(S/M/L), exit criterion (falsifiable, measured), and which review findings/recommendations it closes
(by ID, e.g. D2-R1, D3-F4). The **first two sprints must be executable tomorrow** and must fix the
cheap, high-confidence correctness defects confirmed in SPOTCHECK/SCORECARD (offset crash, angr
sentinel, RELRO strings, `-f main` default, `fill_ammo` leak, SROP gate, overrides on pwn/template,
`template -t auto` default) *and* stand up the PASS scorecard harness so every later sprint is measured.
Say explicitly what happens to the S6 draft (RT-08/09/10): keep, re-scope, fold in, or drop each item.

### 6. Detailed plans for the first four sprints
For each: goal, files/modules touched, design (interfaces, data shapes, flags), test strategy with a
non-vacuous RED proof per item, risks and mitigations, exit criterion, and rollback.

### 7. Tools and technologies to add
Table: tool, decision (adopt now / later / optional / skip / remove), sprint, offline install path,
reason. Cover at least: PyGhidra or Java exporter, Ghidra FunctionID/BSim, rizin, Qiling/Unicorn, wine,
AFL++ (QEMU mode, cmplog, QASan), cwe_checker, one_gadget, seccomp-tools, patchelf/pwninit,
libc-database mirror, pwndbg, mingw-w64 (and MSVC question), bubblewrap/containers for sandboxing.

### 8. LLM integration plan
The hook list in priority order (attach point, closed-set output, oracle, model role, success
measure, kill criterion), the provider/ledger/replay design, the trust invariants, and the evaluation
arm (agent alone vs agent + supwngo). Make the injection and contamination rules explicit.

### 9. Risks, pre-mortem and kill criteria
The five most likely ways this roadmap fails, the early signal for each, and the response. Kill or
pivot criteria for each bet.

### 10. Hypotheses register
Merge and deduplicate the reviewers' hypotheses into `HYP-n` with: claim, cheapest experiment, falsifier,
the sprint that runs it, and what decision flips if it is falsified.

### 11. Open questions for the owner
Only the ones that block or reorder sprints, each with the default the team proceeds on meanwhile.

## Rules
- Be adversarial with the reviews too: they can be wrong, overlap, or over-reach for a single maintainer.
  Where you reject a recommendation, say which and why in one line.
- Cite review IDs (`D1-R3`) and `path:line` for every non-obvious claim. Mark UNVERIFIED inferences.
- Read-only; stay inside this directory; do not invent files, APIs or results.
- Prefer fewer, sharper bets. Every sprint must move a scorecard number or remove a named risk.
