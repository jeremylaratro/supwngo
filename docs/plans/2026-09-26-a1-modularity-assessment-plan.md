# Sprint A-1 — modularity assessment of the canonical pipeline

Phase 5 artifact. Closes **A-1** (USER DIRECTIVE, 2026-09-26: *"I want a standardized
TO DO / queue, and I want modularity assessment added to it."*). Queue entry:
`docs/process/2026-09-26-standard-work-queue.md`.

**Deliverable is a finding plus a proposal. Refactoring is explicitly excluded** — this
sprint changes no production code.

**Provenance labels**: `measured` (ran it), `recorded` (prior artifact, cited),
`inferred` (reasoned, not observed).

---

## 1. Problem restated

Sprint 2′ added **one** capability — deliver a payload somewhere other than stdin — and
touched **8 production files** to do it (`measured`, from the commits themselves):

| file | commit |
|---|---|
| `exploit/pipeline/contracts.py` | `4d838ec`, `4e65232` |
| `cli.py`, `core/context.py`, `exploit/pipeline/orchestrator.py`, `exploit/pipeline/templates.py`, `exploit/pipeline/verifier.py`, `exploit/verification.py`, `exploit/pipeline/executors/stack_techniques.py` | `aaa0834` |

B-3 is queued to add a *second* transport-adjacent capability (container envelopes) and
its plan already predicts touching `contracts.py` plus a new module plus the CLI. If one
capability costs 8 files, the question the user is asking is whether that is the
architecture or an accident — and that question is answerable with evidence rather than
taste.

## 2. Scope

**In scope.** A measured assessment of how much the pipeline's structure costs per new
capability, the specific seams responsible, and a proposal ranked by cost-to-benefit.

**Explicitly out of scope.**
- **Any refactor.** Not one production line changes in this sprint. The user scoped A-1
  to a finding + proposal, and a proposal that arrives already implemented is not a
  proposal.
- Tool hardening / trustworthiness of supwngo. Deliberate constants (magic-value tables,
  technique allowlists, cheat-sheet data) are **features**, not weaknesses, and findings
  about them are out of scope.
- Rewriting `EnhancedAutoExploiter`. Its construction sites are *evidence* here, not a
  work item.
- Test-suite architecture. Production modularity only.

## 3. Method — two candidates weighed

### Method A (chosen): change-cost probes against named candidate capabilities

Pick a fixed set of capabilities the roadmap actually implies, and for each, **trace what
would have to change** — by reading the code, not by guessing — producing a count of
files, functions, and *decision points* (places where a new case must be registered), plus
the seam that forces each one.

The probe set, chosen because each is either queued or already half-built:

| probe | capability | already implied by |
|---|---|---|
| P1 | a **5th delivery sink** (e.g. env-var, or a socket) | `INPUT_VECTOR_CHOICES` is a closed set |
| P2 | a **container envelope** | B-3, and `DeliverySpec.container` is already a reserved field |
| P3 | a **new technique** that needs a non-stdin sink | `FILE_DELIVERY_ALLOWLIST` gates this centrally |
| P4 | a **third success oracle** | two exist today with different fd-0 semantics (G-W3-1) |
| P5 | swapping the **engine** (`EnhancedAutoExploiter` ↔ `CanonicalAutopwnEngine`) behind one interface | the port this whole effort is about; 4 construction sites, no capability contract |

*Why chosen:* it measures **the cost of the change the user cares about**, and every
number is checkable by a reader who disagrees. It also has a built-in calibration point:
P2's prediction can be compared against B-3's *actual* cost once B-3 ships, which makes
this assessment falsifiable after the fact rather than merely plausible.

### Method B (rejected): static coupling metrics

Import graph, fan-in/fan-out per module, cyclomatic complexity, maybe a dependency-cycle
report.

*Rejected:* it measures the shape of the code, not the cost of a change. A module can
have low coupling and still force an 8-file edit, because the thing that spread Sprint 2′
across 8 files was not coupling — it was **a closed enum plus a central allowlist plus a
duplicated placement rule**, three decision points that a coupling metric renders as
"one import each". Optimising a metric that does not track the cost would be the classic
mistake here.

**What would flip the decision to B:** if the five probes disagree with each other and
share no common seam, the problem is diffuse rather than localised, and a whole-graph
view would be the better instrument. The probes are designed so that outcome is
visible rather than hidden.

## 4. The six seeded evidence points (to be verified, not assumed)

The queue entry seeded six observations. A-1's first job is to **re-verify each on disk**
and label it, because a seeded observation is a hypothesis:

| # | seeded claim | status entering the sprint |
|---|---|---|
| E1 | 8 production files for one transport capability | **`measured`** (§1, from the commits) |
| E2 | `FILE_DELIVERY_ALLOWLIST` is a central allowlist seam | `recorded` — verify it is the only gate |
| E3 | the sink set is a closed enum; a new transport costs ~4 files | `inferred` — P1 measures it |
| E4 | argv-placement logic is duplicated, and the duplication is what let H1 drift | `recorded` — H1 is confirmed; verify the duplication still exists post-fix |
| E5 | `EnhancedAutoExploiter` has 4 construction sites and no capability contract | `recorded` — re-run the sweep, since a **narrow grep cannot carry a broad negative** (an earlier sweep of mine matched only `CanonicalAutopwnEngine(` and missed these 4 sites entirely) |
| E6 | two success oracles with different fd-0 semantics | **`measured`** (G-W3-1, proven on HEAD) |

Each verification states its **match identity** — exactly what was searched for — so a
reader can re-run it. An unverified seed is reported as unverified, not quietly promoted.

## 5. Sub-components

| # | output | content |
|---|---|---|
| A0 | verification log | E1–E6 re-verified, each with its match identity and resulting label |
| A1 | probe table | P1–P5: files, functions, decision points, and the seam forcing each |
| A2 | seam inventory | every seam the probes implicate, each with: what it closes over, how many probes it appears in, and what a new case must do to register |
| A3 | proposal | ranked options per seam, each with cost, blast radius, what it would have made Sprint 2′ cost instead, and **the option not taken** |
| A4 | falsification hook | A2/A3's prediction for P2 recorded as a number **before** B-3 ships, so B-3's actual cost either confirms or refutes this assessment |

## 6. What makes this assessment able to be wrong

A "modularity assessment" is the archetypal deliverable that cannot fail. Three
structural commitments, made before the work:

1. **Every probe count is a number a reader can re-derive**, with the files named. Not
   "tightly coupled" — "5 files, 3 decision points, `INPUT_VECTOR_CHOICES` forces 2 of
   them".
2. **A2's prediction for P2 is recorded before B-3 is implemented** (A4). If B-3 ships at
   a materially different cost, this assessment was wrong and the erratum goes beside it.
   This is the only part of A-1 that can be checked by reality rather than by review.
3. **A null result is a reportable outcome.** If the probes show the 8-file cost was
   dominated by *tests and CLI surface* rather than by a structural seam, the finding is
   "the architecture is adequate and Sprint 2′'s cost was the one-time price of a new
   axis" — and A-1 recommends **no** refactor. That conclusion must be as publishable as
   a list of seams, or the assessment is just a justification for work already wanted.

## 7. Test plan

A-1 ships no code, so Phase 7's regression obligation is trivially satisfied — but it is
stated rather than skipped: **no production file is modified**, proven by
`git diff --stat` on the sprint branch showing only files under `docs/`.

The verification gates that *do* apply:

| id | asserts | how it can go RED |
|---|---|---|
| T-A0 | each E1–E6 verification names its match identity and the search is re-runnable | a claim with no stated search → the log is incomplete by inspection |
| T-A1 | each probe's file list is complete: every file named actually requires a change, and a spot-check capability implemented on paper touches nothing outside the list | name a file that needs no change → the probe overstates cost |
| T-A2 | `git diff --stat` shows **zero** production files changed | touch one production file → the gate fails, which is the scope guard made mechanical |

## 8. Benefit metric (Phase 8), baseline measured now

A-1's benefit is not a success rate; claiming one would be dishonest. Its metric is
**decision quality**, and the honest form is:

| metric | baseline | target | provenance |
|---|---|---|---|
| **M-A1** | candidate capabilities whose change-cost is known before committing to them: **0 of 5** | **5 of 5**, each with named files and seams | `measured` (no such assessment exists) |
| **M-A2** | seams with a stated cost-to-remove and a recorded option-not-taken: **0** | every seam implicated by ≥2 probes | — |
| **M-A3** | the P2 prediction's accuracy once B-3 ships | *unmeasurable until B-3* | recorded now, checked later (A4) |

**M-A3 is the only metric that can independently refute this sprint**, which is why it is
recorded now instead of after.

## 9. Rollback

Documentation-only; rollback is deleting the documents. The proposal creates no
obligation — acting on A3 is a separate, separately-approved sprint, and A-1 explicitly
does not pre-authorise it.

## 10. Review gate

Peer review at the same tier before the assessment is treated as decided, with
tool-hardening and constant-table findings declared out of scope in the prompt. The three
things most likely wrong:

1. Are the five probes the *right* five — do they cover the capabilities the roadmap
   actually implies, or are they chosen to make a seam look expensive?
2. Does the change-cost method miss a class of modularity problem that only a whole-graph
   view would show (the Method-B question, asked adversarially)?
3. Is the null result in §6.3 genuinely reachable from the evidence, or is the sprint
   structured so that "there are seams" is the only possible conclusion?

---

# REVISION 2 — after round-1 peer review (NOT-APPROVED)

Review: `docs/plans/2026-09-26-a1-plan-review-r1-sol.md` (Sol 5.6, xhigh; 3 Critical,
4 High, 2 Medium). **All nine findings accepted.** One of them (H3) is corroborated by a
refutation I produced while verifying the review — see R2.4, which is the most valuable
thing to come out of this round.

## R2.1 — The capability unit was not frozen, so results were not reproducible (C1)

P1 permitted "an env-var **or** a socket" sink — integrations with radically different
costs — and Sprint 2′ was counted as "one capability" though it added three sinks, CLI
surface, verifier behaviour and artifact parity. Two analysts following the plan could
reach opposite conclusions.

**Fix — each probe is frozen to one concrete acceptance contract at a pinned base SHA.**
The base SHA for all probes is **`37a8d9b`** (the Sprint 2′ docs commit, i.e. the tree as
it stands entering A-1).

| probe | frozen acceptance contract (one, concrete) |
|---|---|
| P1 | a **`SINK_ENV` sink**: payload delivered via a named environment variable; engine accepts `--input-vector env --input-name VAR`; verifier delivers it; the generated artifact reproduces it. *(Socket is explicitly not this probe.)* |
| P2 | a **BMP container envelope** per B-3's §2 scope, container selected by `DeliverySpec.container` |
| P3 | **`negative_index_write` permitted on `file-argv`** — chosen because the review proved its executor also hardcodes stdin, so this probe measures a *real* two-part cost |
| P4 | a **third success oracle**: "target wrote a named file", selectable alongside the two existing ones |
| P5 | `EnhancedAutoExploiter` and `CanonicalAutopwnEngine` both reachable **behind one interface** with no call-site `if` on engine type |

**A "mandatory change"** is defined, because the count is meaningless otherwise: a file
whose edit is required for the frozen contract's behaviour to hold. Excluded from the
count: tests, docs, CHANGELOG, and any edit that is stylistic or discretionary. A
**decision point** is a place where a new case must be *registered* to be recognised (an
enum member, an allowlist entry, a dispatch branch, a template case).

Counts are reported **per probe and never aggregated across probes** — the review's point
that a sink and an engine swap are not like-grained is accepted, so there is no "average
files per capability" figure anywhere in the deliverable.

## R2.2 — The gates were omission-blind (C2)

T-A1's red-proof caught an *unnecessary* named file but not a *missing* one, and its
"paper spot-check" was authored from the same assumptions under test. A probe listing 2
of the 5 files it truly needs would have passed.

**Fix:**

- Each probe's file set is derived **twice, independently**: once forward (from the
  acceptance contract, tracing what must change) and once backward (from each candidate
  file, asking what breaks if it is *not* changed). The gate is **exact set equality**
  between the two derivations; a disagreement is reported, not reconciled silently.
- **T-A1′ red-proof is by DELETION** — remove a genuinely required entry from a probe's
  set and the backward derivation must surface it. Proving RED by *adding* an unnecessary
  file, as Revision 1 did, exercises the wrong direction.

## R2.3 — The scope gate was unsound (C3)

`git diff --stat` ignores committed changes and untracked files: modify `orchestrator.py`,
commit it alongside the assessment, and the gate reads empty.

**Fix — T-A2′** records the sprint base SHA and checks the union of
`git diff <base>...HEAD --name-only`, `git diff --name-only`, `git diff --cached
--name-only`, and `git ls-files --others --exclude-standard`, then asserts every path is
under `docs/`. The four untracked junk paths already present (`exploit.bin`,
`report_output/`, `solve_output/`, `tests/htb-targets/`) are recorded in a baseline
manifest so the gate is not permanently red for a pre-existing condition — and so that
list cannot quietly grow.

## R2.4 — H3 is accepted, and I proved it on myself before accepting it

The review warned that a repeatable search does not make a broad negative true, and cited
a production factory at `enhanced_auto.py:1431` that my seeded **E5** had missed.
I verified it. `git grep -n "EnhancedAutoExploiter(" -- '*.py'` returns **6** hits:
four in `cli.py` (306, 392, 2787, 3358), one docstring example (`enhanced_auto.py:103`),
and **a real factory at `enhanced_auto.py:1431` constructing it with `**kwargs`**.

So **E5's seeded count of "4 construction sites" is REFUTED — there are 5 production
sites.** This is the second time this session that one of my narrow greps carried a broad
negative it could not support. It also *strengthens* E5's actual point: a factory taking
`**kwargs` is the sharpest available evidence for "no capability contract".

**Fix:** every "only"/"no contract"/"nothing else" claim in the deliverable declares its
**search universe at the pinned SHA**, uses symbol *and* reference searches plus
alias/factory/wrapper forms, and includes a call-path read. Any broad negative that
cannot be shown exhaustive stays **`inferred`** and is labelled as such at the point of
use.

## R2.5 — A-1's deliverables did not satisfy A-1's own queue exit (H1)

Verified against `docs/process/2026-09-26-standard-work-queue.md`: the exit clause
requires (a) a coupling metric per capability, (b) each seam a new capability must cut
through, (c) **for every seam, "right seam" or "modularity defect"**, and (d) **at most
three** proposed changes, each with the capability it would newly make additive.
Revision 1's A1–A4 required **neither (c) nor (d)**.

*(The review also read the exit as requiring retrospective coupling across Sprint 1 and
B-3; that is its extrapolation rather than the queue's text. R2.6 adopts the Sprint-1 part
anyway because it is a good idea, and B-3's actual cost is deferred per the user's
sequencing decision.)*

**Fix:** deliverable A3 is restructured and a traceability gate added:

- **A3 caps proposals at THREE**, each naming the capability it would make additive.
- **A2 classifies every seam as `right seam` or `modularity defect`, with the reason.**
  A seam that is load-bearing by design is a *finding*, not a defect — and saying so is
  how this assessment avoids being a justification for work already wanted.
- **T-A3 (new):** a clause-by-clause traceability table mapping (a),(b),(c),(d) to the
  section that satisfies it. A clause with no section is an incomplete sprint, and A-1 is
  **not** marked closed in the queue until all four are mapped.

## R2.6 — A4 is calibration, not falsification; use a held-out change instead (H2)

The review is right that B-3's future cost cannot independently refute this assessment —
matching a number while naming the wrong seams, or diverging because B-3's scope grew,
both mislead. And "materially different" was undefined.

**Fix, two parts:**

1. **A4 is relabelled `calibration`**, with the predicted file/function/decision-point
   sets pre-registered per probe, scored later by **precision and recall** against the
   actual change, and with discretionary implementation work separated from mandatory
   architectural edits. It is no longer described as refutation.
2. **New: A5, a held-out retrospective validation** on a completed change the method
   never saw. **Sprint 1 (`ae0cd73`, disassembly-guided `variable_overwrite`) is the
   held-out case**, and it is a strong one — `measured`, from the commit itself, it
   touched **exactly one production file** (`executors/stack_techniques.py`).

   The method must predict "1 file, 0 decision points" for Sprint 1 *before* looking at
   the commit's file list, and predict Sprint 2′'s 8 files likewise. **If it cannot
   reproduce both, the method is wrong and A-1 says so.** This is real independent
   validation, unlike a prediction about work not yet done.

## R2.7 — The null result and the Method-B trigger are now executable (H4)

Revision 1 stated both but made neither reachable, and tied the null result partly to
test cost that §2 had excluded from scope.

**Fix — three executable thresholds, evaluated after A1/A2 and before A3:**

| trigger | condition | mandatory consequence |
|---|---|---|
| **Null result** | no seam appears in ≥2 probes' mandatory sets | A-1 reports *"the architecture is adequate; Sprint 2′'s 8 files were the one-time price of a new axis"*, proposes **no** refactor, and stops |
| **Method B required** | probes implicate ≥4 distinct seams with no overlap | the whole-graph view is run before any proposal is written; a diffuse problem is not localised by more probes |
| **Seam is a defect** | a seam appears in ≥2 probes **and** removing it would reduce another probe's mandatory file count | eligible for A3; otherwise classified `right seam` |

The test-cost clause is **removed** from the null criterion, since tests are out of scope.

**The contrast that makes the null genuinely reachable:** Sprint 1 cost **1** production
file and Sprint 2′ cost **8** (both `measured`). The cost is therefore *not uniform*, so
"the pipeline is poorly modularised" is not the only conclusion the evidence supports —
it may be specifically the **transport axis** that is expensive while technique-internal
work is cheap. A-1 must be able to reach that finding, and now can.

## R2.8 — Provenance corrections (M1) and a defined benefit (M2)

**M1, corrected at the point of use:**

| item | was | now |
|---|---|---|
| E6 (two oracles, differing fd-0 semantics) | `measured` | **`recorded`** — cited from the G-W3-1 artifact; promoted only if re-run at the pinned SHA |
| M-A1 baseline ("no such assessment exists") | `measured` | **`inferred`** — an open-world absence |
| E1 (8 files) | `measured` | **numerator `measured`** (the file list, from the commits); **denominator `inferred`** (that this constitutes exactly *one* capability) |
| E5 (construction sites) | `measured`, 4 | **`measured`, 5** — corrected per R2.4 |
| M-A2 | *(no label)* | **`measured`** once A2 exists; the count is checkable |

**M2 — benefit is defined quantitatively**, not narratively: *benefit* = the reduction in
**mandatory files + functions + decision points summed over the frozen five probes** if
the change were made; *cost* = the same three counts for making the change. Shared edits
are counted once (no double-counting across probes), and any counterfactual saving carries
a stated uncertainty. Ranking is by benefit/cost on those numbers, and the ranking table
prints the numbers so a reader can re-rank.

## R2.9 — Status

Revision 2 goes to round 2. Round budget: 1 spent, **2 remain**. A-1 still changes **no
production code**; T-A2′ is the mechanical guard on that.

---

# REVISION 3 — after round-2 peer review (NOT-APPROVED)

Review: `docs/plans/2026-09-26-a1-plan-review-r2-sol.md` (Sol 5.6, xhigh; 3 Critical,
3 High, 2 Medium). **All eight accepted.** C3 is the important one and it is correct: I
broke my own held-out validation by writing the answer down.

**Round budget: 2 spent, 1 remains.**

## R3.1 — Each probe's behavioural contract, stated inline (C1)

R2.1 froze probe *names* but P2 still said "per B-3 §2", which requires a two-format
registry — so one analyst counts BMP plus wiring and another counts registry + BMP + WAV +
shared finalisation, both faithfully. And P3 was textually satisfiable by an allowlist edit
alone, though its executor also hardcodes stdin.

**Fix — each probe now states its own contract inline, and nothing is by reference.**
Every probe declares: entry point, target state, payload byte domain, the verifier receipt
it must produce, whether the generated artifact must replay, its negative control, and an
explicit **included/excluded** list for CLI surface, registry, second formats, and engine
selection. Base SHA remains `37a8d9b`.

| probe | contract (abbreviated; full form in the deliverable) | explicitly EXCLUDED |
|---|---|---|
| P1 `SINK_ENV` | `--input-vector env --input-name VAR`; `ret2win` payload (arbitrary bytes incl. NUL); verifier receipt records `delivered_bytes`; artifact must replay | any second env-like sink; sockets |
| P2 BMP envelope | `DeliverySpec.container="bmp"` wraps a `ret2win` payload for a `file-argv` sink; one format only | **the registry abstraction, WAV, and shared finalisation** |
| P3 `negative_index_write` on `file-argv` | allowlist membership **and** the executor's hardcoded stdin delivery both changed; receipt proves file delivery | new techniques; other executors |
| P4 third oracle | "target wrote a named file" selectable beside the existing two; one oracle | changing either existing oracle's semantics |
| P5 engine interface | both engines reachable behind one interface, **zero** call-site `if` on engine type, all 5 construction sites converted | behaviour changes in either engine |

**"Mandatory function"** is now defined alongfile and decision point: a function whose body
must change for the contract's behaviour to hold — not a function merely called.

## R3.2 — A genuinely independent second derivation (C2)

R2.2's two derivations shared my own candidate-file universe, so a file I never considered
(`templates.py`, in the review's example) appears in neither and exact equality passes
vacuously. Proving RED by deleting a known entry only tests the comparator.

**Fix:**

1. **The second derivation is produced by a peer model that is not shown my candidate
   set** — it receives only the probe contract and the repo, and traces from entry point to
   observable output. The two sets are compared **only after both exist**, and their
   **union is adjudicated** with a written reason per disputed file.
2. **A concealed-ground-truth validation case** proves the procedure detects omissions: one
   probe is run against a *completed* change whose true mandatory set is known but withheld
   from both derivations until they are registered. If the procedure misses a file the real
   change required, the procedure is reported as inadequate rather than its output
   published.

## R3.3 — A5 was not held out, because I disclosed the answer (C3)

The review is right, and this is a self-inflicted defect: Revision 2 wrote *"it touched
**exactly one production file** (`executors/stack_techniques.py`)"* into the plan, and §1
had already listed Sprint 2′'s eight files by name. A method returning one arbitrary file
for Sprint 1 and eight arbitrary files for Sprint 2′ would pass a count gate while naming
every seam wrongly.

**Fix:**

- **Sprint 1 (`ae0cd73`) and Sprint 2′ are relabelled `calibration`.** Their answers are
  public in this document; they can tune the method, never validate it.
- **A5′ — a genuinely blind held-out case.** Selected now by a stated rule, *before* any
  prediction, with **only its SHA and subject recorded and its diff deliberately not
  inspected**:

  > **Rule:** the most recent `feat:` commit touching `supwngo/exploit/pipeline/` that is
  > an ancestor of `ae0cd73`.
  > **Result: `1e26373` — "feat: add --strategy and --all-strategies flags to solve and
  > autopwn".**

  Its file/function/decision-point **identities** are pre-registered as a prediction, then
  the diff is unblinded once and scored by **precision and recall** against an
  independently adjudicated mandatory set. Counts alone do not score; identities do.
- If the prediction is registered after any inspection of `1e26373`'s diff, A5′ is void and
  must be reported void. The honesty of this gate is the gate.

## R3.4 — Threshold precedence, and single-probe seams can be defects (H1)

R2.7's triggers overlapped: five probes each implicating one distinct expensive seam fired
**both** "null result" (no seam in ≥2 probes) and "Method B required" (≥4 seams, no
overlap), and every such seam was auto-classified `right seam` merely because one probe
sampled its axis.

**Fix — explicit precedence and a cost ceiling:**

1. **Method B first.** If probes implicate ≥4 distinct seams with no overlap, the
   whole-graph view runs **before** any null or defect decision. A diffuse result is never
   resolved by declaring adequacy.
2. **Null requires more than non-overlap.** Permitted only after every probe's mandatory
   cost is **≤2 files and ≤1 decision point** *and* every seam is classified intrinsic with
   a reason. Non-overlap alone is not sufficient.
3. **A single-probe seam can be a `modularity defect`** if its own mandatory cost exceeds
   that ceiling — recurrence is evidence, not a requirement.
4. Reductions in **functions or decision points** count, not only files.

## R3.5 — Benefit is a vector, not a sum (H2)

R2.8 added files + functions + decision points into one number — dimensionally invalid —
and deduplicated recurring future edits, so a proposal removing the *same* edit from all
five probes scored one unit while a proposal removing two decision points from one probe
outranked it.

**Fix:** benefit is reported as a **per-probe vector** — (file-edit *occurrences*,
function-edit *occurrences*, decision points) — with **occurrences counted per probe, not
deduplicated**, against a separate one-time implementation-cost vector. Ranking is
**Pareto**; where Pareto leaves ties, weights are pre-registered with a sensitivity check.
No scalar score appears anywhere.

## R3.6 — The scope gate's untracked baseline (H3)

`git ls-files --others --exclude-standard` emits **leaf paths**, not the three directory
names I baselined, so R2.3's four-entry baseline would leave T-A2′ permanently red — and
prefix-exempting the directories would let `tests/htb-targets/new_file.py` hide behind the
baseline.

**Fix — T-A2″** snapshots the **exact leaf-path output** at sprint start into a recorded
manifest and asserts `current_untracked − baseline_untracked == ∅`. No directory is ever
treated as a wildcard. The comparison is set difference over exact paths, stated in the
test.

## R3.7 — Deliverable location and the null branch's wording (M1, M2)

- **M1:** the queue exit requires the assessment under **`docs/research/`**. T-A3 now gates
  that the final artifact exists at `docs/research/<date>-a1-modularity-assessment.md` and
  that its path is recorded beside the queue closure. Appending to this plan does not
  satisfy A-1.
- **M2:** the null branch may no longer assert *"Sprint 2′'s eight files were the one-time
  price of a new axis"* as fact. It reports that the evidence is **consistent with** an
  axis-specific cost, labels that `inferred`, and lists competing explanations — and it may
  not be stated at all until Method B has resolved a diffuse result.

## R3.8 — Status

Revision 3 goes to round 3, the final round. A-1 still changes **no production code**;
T-A2″ is the mechanical guard.

---

# ESCALATION — round 3 exhausted, design escalated, NOT implemented

Review: `docs/plans/2026-09-27-a1-plan-review-r3-sol.md` (Sol 5.6, xhigh; 3 Critical,
3 High, 2 Medium). **Round budget: 3 of 3 spent.**

The reviewer names three separate recurrences — C1 is *"the same defect class as R2 C3
recurring again"*, C2 is *"the third occurrence of the R1 C1 / R2 C1 defect"*, and H2
*"repeats R1 H4 and R2 H1"* — and in each case recommends escalating the design rather than
patching. **A-1 is therefore NOT implemented** and returns to planning.

## The two defects that decide it

**1. A5′ was still not held out, for a reason I should have caught.** `1e26373` is an
**ancestor of the probe base SHA `37a8d9b`**, so its implementation is already present in
the tree the prediction is made from. Grepping the current tree for `--strategy` yields the
answer directly; precision and recall would score perfectly while predicting nothing from
the pre-change architecture. Recording only the SHA was not enough — **the code was in the
room.**

Escalated design: the evaluator must be isolated to the commit's **parent tree**, with no
descendant-tree and no history access, given a **fully frozen behavioural contract** rather
than a subject line, and a **separate custodian** unblinds and scores. That needs a second
party by construction; it is not a wording change.

**2. The probe contracts were post-hoc, three rounds running.** Deferring each contract's
"full form" to the deliverable means the contract can be narrowed to fit whatever the trace
found — and both derivations then agree because they share the retrospectively narrowed
contract.

Escalated design: an **immutable preregistration phase** that publishes and hashes every
probe's complete contract *before* any tracing, with the deliverable forbidden from
completing or reinterpreting them.

## Also blocking, and mechanical

**P1's contract is impossible.** It required arbitrary payload bytes *including NUL*
through an environment variable, but POSIX environment entries are NUL-terminated and
Python raises `ValueError: embedded null byte`. No implementation could satisfy it, so
"5/5 probes" was unreachable — or an analyst silently adds encoding and changes the
capability being measured. P1 must freeze an environment-safe byte domain or pick a
binary-safe sink.

**P2 is incompatible with its own calibration target.** R3.1 excluded the registry, WAV and
shared finalisation from P2; B-3 necessarily includes all three. Scoring P2 against B-3
would report missing identities that P2 was told to omit.

**Ranking remains undefined.** "Pareto, then pre-registered weights, and no scalar score"
does not produce a reproducible ordering — Pareto-incomparable proposals get no order, and
weights chosen after seeing the vectors justify any preferred answer.

**Provenance, again:** hypothetical probe costs are `inferred`/`predicted`, not `measured`,
however many derivations agree. Two analysts agreeing about a counterfactual is still a
counterfactual.

## Honest accounting

A-1's difficulty is not the analysis — it is that **a self-assessment of one's own
architecture, validated by predictions one can check in advance, has no honest gate without
a second party.** Three rounds converged on that. The escalated design needs an isolated
evaluator and a custodian, which is a materially different sprint from "read the code and
write a finding".

**Status: NOT APPROVED, NOT IMPLEMENTED, returned to planning.**
