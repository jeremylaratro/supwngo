# Path to 5/7 (v2) — HTB challenges and their challenge-alike variations

**Date:** 2026-09-27
**Status:** **SUPERSEDED — NOT-APPROVED at review (Sol 5.6, 5 CRITICAL / 4 HIGH). Do
not implement from this document.** Retained unchanged below as the reviewed artifact
of record. Live plan: **[v3](2026-09-27-path-to-5of7-plan-v3.md)**; review:
**[r1-v2-sol](2026-09-27-5of7-plan-review-r1-v2-sol.md)**.

> **What v2 got right and wrong.** The reviewer affirmed the ordering principle —
> "the high-level measure → diagnose → implement ordering is sound" — and showed v2
> **does not enforce it**. Six findings verified against the code, all confirmed:
> the T-1′ harness runs the legacy engine on every failing target (`cli.py:3342-3366`),
> so v2's timing-derived diagnoses are void; ablation by executor cannot separate
> sub-routes that share a technique name (`rop_techniques.py:829-842`); I-12 targeted
> a classifier the canonical profiler never calls; every red-proof was one-sided
> (an always-red reducer satisfied all of them); and the SROP chain has a **second**
> defect (`rop_techniques.py:991,996` — `mprotect` never executes) that a
> trace-only exit would have passed over. v2 also proposed revising the user's 5/7
> target downward, which is not mine to do; v3 withdraws that branch.
>
> Because the structure survived and its enforcement did not, v2 was **revised into
> v3** rather than superseded the way v1 was.

**Original status line:** PLAN — not approved, not started. **Implementation is gated on the
user's sign-off** (user directive, 2026-09-27: "make a recommendation on next steps
but do not start until I sign off").
**Supersedes:** [2026-09-27-path-to-5of7-plan.md](2026-09-27-path-to-5of7-plan.md)
(NOT-APPROVED at R1 — see [the review](2026-09-27-5of7-plan-review-r1-daybreak.md)).
**Directive (user, 2026-09-27):** "create an actionable plan to generate viable,
generalizable strategies that will bring those numbers up to at least 5/7 solves for
both" — clarified to **HTB ≥5/7 AND challenge-variations ≥5/7**.

---

## 1. What changed, and why this plan is shaped differently

v1 was organised around **capabilities to build**. R1 demonstrated that its list of
missing capabilities was partly wrong: one item was already implemented, and the
premise generating the rest (protection defeat is the blocker) was a correlation
dressed as a diagnosis. Every one of the four CRITICAL findings I checked against
the code was confirmed.

v2 is therefore organised around **facts to establish before committing to build
anything**, with exactly two exceptions — the items already diagnosed down to a
specific line of code.

The structural rule this plan adopts:

> **No sprint may claim a solve it has not first diagnosed.** A sprint either (a)
> repairs a defect located at a `file:line`, or (b) is a **spike** whose deliverable
> is evidence, not capability. Infrastructure is scheduled only after a spike
> justifies it.

This costs schedule certainty and buys the thing v1 lacked: the plan can no longer
finish all its sprints and still miss both gates.

### The honest consequence

**This plan does not promise 5/7.** It promises two seats with named mechanisms, and
a measurement that determines whether a fifth and sixth are reachable at all —
early, cheaply, and before the expensive infrastructure is written. If the spikes
come back negative, the correct output is a re-plan and a revised target, not a
sprint that ships anyway. Stating a number I cannot presently support would repeat
exactly the error R1 caught.

---

## 2. Definition of done

| gate | statement | current |
|---|---|---|
| **T-1′** | canonical pipeline solves **≥5/7** HTB targets, no legacy fallback, ≥2/3 reps, flag or shell attributed to a per-run secret | **1/7** (`20260927-142133Z`) |
| **T-2** | canonical pipeline solves **≥5/7** *classes* of the challenge-alike variation corpus, under the fail-closed reducer defined in Sprint 0 | **not measurable** — no reducer exists |
| **M-1a** | no per-target corpus regression | 13/13 eligible at 5/5 (`20260927-140103Z`) |

T-2 is the load-bearing half. A capability that solves the exact upstream binary and
nothing shaped like it is not counted.

---

## 3. Measured baseline (carried forward, unchanged)

HTB re-score, run `20260927-142133Z`, 3 reps, per-rep planted secret, harness
validated with a positive control (`SOLVED` 2/2, reproducing the planted secret) and
a negative control (`/bin/true`, `NOT_SOLVED` 2/2):

| target | verdict | technique | time | PIE | canary | RELRO | link |
|---|---|---|---|---|---|---|---|
| `rocket_blaster_xxx` | **SOLVED** 3/3 | `ret2libc_leak` (SHELL) | 18.7s | no | **no** | full | dyn |
| `sick_rop` | NOT_SOLVED | — | 148.7s | no | no | none | **static** |
| `snow_scan` | NOT_SOLVED | — | 19.4s | no | yes | partial | dyn |
| `bon-nie-appetit` | NOT_SOLVED | — | 3.5s | **yes** | yes | **full** | dyn |
| `sabotage` | NOT_SOLVED | — | 6.0s | **yes** | yes | **full** | dyn |
| `ancient_interface` | INCONCLUSIVE | — | TIMEOUT ×3 @300s, ×1 @1100s | no | yes | partial | dyn |
| `auth-or-out` | INCONCLUSIVE | — | TIMEOUT ×3 @300s | **yes** | yes | **full** | dyn |

Two observations that constrain the plan:

- **Four targets fail in under 20 seconds.** They are not losing to a search budget;
  they are being *declined* by every executor. Budget work cannot move them.
- **Two targets never finish.** `ancient_interface` was measured at 64.7–70% CPU with
  live child processes at timeout — a search-space problem, not the G-3 deadlock
  class. These two are invisible to diagnosis until the budget work lands, which is
  why the budget sprint is early rather than last.

**Structural note on attribution:** only `ancient_interface` and `snow_scan` ship a
`flag.txt`, and only `rocket_blaster_xxx` has a flag path compiled in (`./flag.txt`)
— which it does not ship. `FLAG_CAPTURED` is therefore structurally impossible for 5
of 7; those are shell-popping challenges and `SHELL_ACCESS` is the only honest
credit. The harness already implements this distinction.

---

## 4. What R1 established as fact (verified, not accepted)

These four facts are the plan's new foundation. Each was checked by reading the
cited code, not by trusting the citation.

| # | fact | cite | consequence for this plan |
|---|---|---|---|
| F1 | The SROP read-return `rax` route **is implemented**; its chain miscomposes the arguments. `chain = p64(read_addr) + p64(syscall_gadget) + bytes(frame)`, and `sick_rop`'s `read` is a stack-arg wrapper reading `rsi`/`rdx` from `[rsp+8]`/`[rsp+16]` — the zeroed head of the frame → `read(0,0,0)` returns 0, never 15 | `rop_techniques.py:794-800, 830-833, 905` | G-4 refiled as a **bug**. Becomes Sprint 3: a targeted repair, not a build |
| F2 | `bon-nie-appetit` ships **glibc 2.27**; `sabotage` ships **glibc 2.35** | `strings` on each target's bundled `glibc/libc.so.6` | `__free_hook`/`__malloc_hook` were removed in 2.34. A single "hook overwrite" strategy cannot serve both targets. Kills v1's shared-target assumption |
| F3 | A recovered image base is written to `leaks["pie"]` but every consumer gates on `leaks["binary_base"]` | `orchestrator.py:560` vs `core/context.py:360,400` | **Filed as I-11, P0.** Any PIE sprint would have "succeeded" at recovery while changing nothing downstream. Must precede all PIE work |
| F4 | `identify_leak_type` returns `"binary"` for all of `0x55…`, which is also where a PIE process's heap lives; its `"heap"` branch only covers `< 0x100000000` | `remote/leak.py:194-197` | **Filed as I-12, P1.** Range classification cannot fix overlapping ranges. Needs provenance + static offset |

F3 and F4 were in no queue and no plan. They are the reason the sequencing changed:
v1 would have built a leak pipeline on top of a classifier that cannot classify and
a context key nothing reads, and its exit criterion ("the pipeline recovers a PIE
base") would have passed anyway.

---

## 5. Sequencing

R1's finding 8 is adopted: later infrastructure must not be able to hide earlier
failure, and measurement must exist before the thing it measures.

```
Sprint 0  measurement contract + P0 correctness      ── blocks everything
Sprint 1  budget discipline                          ── unblocks diagnosis of 2 targets
Sprint 2  root-cause spikes (5 routes, parallel)     ── decides what Sprint 4+ is
Sprint 3  G-4 SROP staging repair                    ── independent, runs alongside
Sprint 4+ determined by Sprint 2 output              ── deliberately unscheduled
Final     dual re-score (T-1′ and T-2)
```

Sprints 0 and 1 are pure enablement and claim no solve. Sprint 3 is independent of
0–2 and can run concurrently. **Sprint 4 is intentionally not specified**: writing
it now would be reasserting v1's guesses under a new heading.

---

## 6. Sprint 0 — the measurement contract, and the two P0 defects

**Closes:** I-11, I-12, and the T-2 reducer gap (R1 finding 2).
**Claims no solve.** Exit is measurement capability plus two correctness fixes.

### 6.1 The T-2 reducer (fail-closed)

R1's finding 2 is correct in substance, and sharper than its own citation. The cited
`run_bench.py:1083` sits inside a docstring that *already* reports two numbers —
`solved` (credited in ≥1 rep) and `reliability` (k/N) — and explicitly warns that
"reporting best-of-N without reliability would be gaming the metric." So the harness
is not naively one-rep-`SUCCESS`. The real gap is that **nothing commits to which
number T-2 keys on**, and keying on `solved` would credit a 1/5 target.

The reducer must therefore be committed, in code, before the corpus is authored:

| requirement | why |
|---|---|
| exact class → variant census, declared in the manifest | a class silently losing a variant must not read as a pass |
| every mandatory variant at **≥2/3 reps** (keys on `reliability`, never on `solved`) | a 1/5 flake is not a capability |
| any `VOID` or missing leg ⇒ the **class** is red | fail-closed; absence is not evidence |
| **behavioural attribution**: the credited technique must match the class's declared primitive | this is the defect the Rocket mapping exposes — Rocket is solved by `ret2libc_leak` while its declared T-2 class is "ret2win with arguments" |
| **per-class ablation**: disabling the claimed primitive must turn that class RED while unrelated techniques stay available | without this, T-2 cannot distinguish "the capability works" from "an easier route existed" |

The ablation requirement is the one that actually answers R1. It is also a red-proof
by construction: a class that stays green with its own primitive disabled is proof
that the class measures nothing.

**Method chosen:** ablation by executor-registry exclusion (a run flag naming
techniques to withhold), because it needs no change to the executors themselves and
therefore cannot be accused of weakening them.
**Method not taken:** structurally excluding alternate routes by authoring variants
that contain *only* the intended bug. Rejected as primary because it makes the corpus
less challenge-alike — real challenges do contain incidental overflows — but it is
retained as a secondary control for classes where ablation proves ambiguous.
**What would flip it:** if withholding a technique measurably changes unrelated
targets' behaviour (shared state between executors), ablation is unsound and the
structural-exclusion method becomes primary.

### 6.2 I-11 — canonicalize the leak key

One key, one meaning. `needs_leak()` and the orchestrator must agree.
**Red-proof:** plant a base through the orchestrator's write path, assert
`needs_leak()` flips to `False`; delete the canonicalization and the test must fail.
This is the specific shape R1 demanded — assert the *downstream state change*, not
the leak's presence.

### 6.3 I-12 — typed leaks with provenance

Replace range-guessing with `(raw_value, source_action, expected_symbol,
static_offset, confidence)` and compute `base = leak - static_offset`, validated
against the ELF's own segment layout.
**Red-proof, per the standing "wrong-but-present" rule:** feed a `0x55…` **heap**
pointer where a code pointer is expected. The gate must reject it. A classifier that
accepts it is the exact bug being fixed, so this test must be written first and seen
to fail.

### 6.4 Sprint 0 exit

- [ ] T-2 reducer committed, with the ablation harness, and proven able to go RED
- [ ] I-11 fixed, downstream-state red-proof passing
- [ ] I-12 fixed, wrong-but-present red-proof passing
- [ ] full suite at or above the recorded baseline (currently 1315 passed / 16 skipped / 14 deselected), counts read from the output by me, not relayed

---

## 7. Sprint 1 — budget discipline

**Closes:** the two `INCONCLUSIVE` targets' *invisibility*, not the targets.
**Claims no solve.**

`ancient_interface` and `auth-or-out` consume the outer timeout before any executor
reports. Until that stops, no spike against them can produce evidence, and any A/B
observation taken from a partial run is unreliable — which is precisely why R1 moved
this ahead of the sprints that depend on repeated experiments.

**Method chosen:** global wall-clock budget with per-technique sub-budgets, so an
expensive technique yields to the next instead of consuming the run. Every truncated
technique must report *that it was truncated* — a technique cut off at its budget and
a technique that exhausted its search are different results, and conflating them is
the I-7 defect class recurring at a different layer.
**Method not taken:** raising the outer timeout. Already falsified — `ancient_interface`
timed out at 1100s too, so the budget is not the binding constraint, the allocation is.
**What would flip it:** if per-technique attribution shows one technique legitimately
needs >300s and succeeds when given it, the sub-budget becomes a per-technique
configuration rather than a cap.

**Exit:** both targets produce a complete per-technique skip/failure report within
the outer timeout. That report is the input to Sprint 2 — it is the first time
anyone will have seen why these two fail.

---

## 8. Sprint 2 — root-cause spikes (the decision point)

**Claims no solve. Produces evidence.** This is the sprint that replaces v1's
guesses.

R1's finding 3 defines the deliverable: for each candidate route, establish **four
separate facts** before any shared infrastructure is designed.

| # | fact to establish |
|---|---|
| 1 | **disclosure primitive** — what concretely leaks an address, by which action |
| 2 | **derived base** — which symbol, which static offset, validated against segments |
| 3 | **corruption primitive** — what concretely writes attacker-controlled data where |
| 4 | **terminal control target + trigger** — what is overwritten, and what causes it to execute |

A route that cannot produce all four is a **NO-GO**, recorded as such with its
blocking fact. A NO-GO is a successful spike: it costs days instead of a sprint.

### 8.1 The five routes, with what is already known against them

| route | known-hostile facts (measured) | what the spike must settle |
|---|---|---|
| `sick_rop` | **already diagnosed** — F1. Not a spike; see Sprint 3 | — |
| `bon-nie-appetit` | glibc **2.27** (hooks live). Clears its pointer after deletion; `create` is **size/data** while the generic script sends **index/size** | whether a UAF exists at all given the pointer clear, and what the real action schema is |
| `sabotage` | glibc **2.35** (hooks **removed**). Only `scanf` is one `%lu` length — so the generated `scanf_canary_bypass` script is a **detector false positive**, not a near-miss | what the terminal control target is when hooks do not exist and RELRO is full |
| `snow_scan` | non-PIE, canary, partial RELRO. B-3's exit criterion is **reaching** the parser's memory-unsafe path, **not solving** it (`2026-09-26-b3-container-registry-plan.md:61`) | whether crash control is achievable past the parser, and what the primitive is |
| `auth-or-out` | **custom stack-arena allocator** (`ta_alloc`/`ta_free`/`insert_block`/`compact`) and an application function pointer. A glibc tcache/GOT retarget is not its primitive | whether the custom allocator has an exploitable state confusion, and whether the function pointer is reachable |
| `ancient_interface` | **stripped** — no local function symbols. Imports `timer_create`/`sigaction`/`strdup`/`getchar` | whether a win target can be *discovered* without symbols; this is a semantic-discovery problem, not a protection problem |

Note what this table does to v1's arithmetic: v1 grouped Bonnie, Sabotage and Auth
as one "PIE + heap" problem with a shared solution. The measured facts show **three
different terminal-control problems** with three different allocators and two
different glibc generations. They do not share a fix.

### 8.2 Sprint 2 exit

- [ ] each of the 5 routes has a written 4-fact record or a NO-GO with its blocking fact
- [ ] each GO route names its terminal control target **and** the trigger, concretely
- [ ] leverage is recomputed from demonstrated chains — never from protection flags
- [ ] Sprint 4+ is authored **from this output**, and reviewed before implementation

**Method chosen:** manual reference-exploit spike per route (write the exploit by
hand, then ask what the engine would need to derive it). This is the only method that
produces all four facts, and a working hand exploit is an unambiguous oracle for the
engine's later attempt.
**Method not taken:** symbolic/concolic triage to find the primitives automatically.
Rejected as primary — it answers "is there a path" and not "what is the terminal
control target", and on a stripped or custom-allocator target it is likely to burn
the sprint. Retained as the fallback for `ancient_interface` specifically, where
symbol-free discovery is the actual problem and manual RE is the expensive path.
**What would flip it:** if two routes' hand exploits turn out to share a primitive
after all, merge their infrastructure — but on demonstrated evidence, which is what
v1 lacked.

---

## 9. Sprint 3 — repair the SROP staging (G-4)

**Independent of Sprints 0–2; can run concurrently. Claims one seat: `sick_rop`.**

This is the plan's highest-confidence item because it is the only one diagnosed to a
line. Per F1, the technique selection is right and the argument staging is wrong.

**The repair:** compose the chain against the wrapper's **measured** ABI — place the
length where the wrapper actually reads it (`[rsp+16]` for `rdx` in `sick_rop`'s
shape) rather than assuming a register convention, and fix the stage transition so
the frame is consumed by `rt_sigreturn` rather than by the `read`.

**The exit criterion is behavioural, not a shell:** the generated script's observed
syscall sequence must contain `read(..., 15) = 15` followed by syscall 15. R1 is
right that a shell-only exit would let a chain that silently degrades to
`read(0,0,0)` read as "no offset candidate verified" — which is exactly how this bug
survived a full measured run and got filed as a missing capability.

**Ride-along:** I-9 (the `failure_reason` asserting a 248-byte-frame size bound the
target refutes — the read accepts 768 bytes). Same file, same technique, and the
false hint actively misdirects diagnosis of this very bug.

**Generalization obligation (R1 finding 7):** `read`-return is one mechanism;
`write`-return is a different one and does not follow automatically. Either it gets
its own implemented and witnessed path, or it is not claimed. Variants must include
at least one stack-arg wrapper with a *different* slot layout, so the fix cannot be
"hardcode `[rsp+16]`".

**Method chosen:** derive the slot layout from the wrapper's disassembly at plan time.
**Method not taken:** sweeping candidate slot assignments. Rejected — it would
"work" on `sick_rop` by luck and teach the engine nothing transferable, which fails
T-2 by construction.
**What would flip it:** if wrapper shapes prove too varied to derive reliably, a
bounded sweep over *derived* candidates (not arbitrary ones) becomes acceptable,
with the prune-accounting discipline from I-7.

---

## 10. Generalization obligations (R1 finding 7)

v1's variation corpus was authored before implementation and visible throughout it,
so the engine could be tuned to the complete acceptance set. That is not a
generalization test; it is a fitting exercise.

| obligation | requirement |
|---|---|
| **two matrices** | a *development* matrix (visible) and a separately generated **sealed acceptance** matrix, revealed only after the engine is frozen |
| **census** | exact variant count per class, declared up front — no "several variants" |
| **held-out members** | ≥2 per counted class, each meeting the ≥2/3 reliability threshold |
| **perturbation** | compiler flags, field reordering, optimization level, and prompt/verb wording varied independently |
| **one mechanism per class** | tcache ≠ fastbin; hook ≠ saved-return; read-return ≠ write-return. v1 mixed these inside single rows, so passing one would have credited the others |
| **branch isolation** | held-out corpora stay on their own branches and are **never merged to `main`**, per the standing constraint |

The corpus design is part of Sprint 0, before any of it is authored, because a corpus
authored without a sound reducer records a baseline that cannot support T-2 — the
defect that returned M-1b to planning once already.

---

## 11. Honest arithmetic

| seat | target | mechanism | confidence | basis |
|---|---|---|---|---|
| 1 | `rocket_blaster_xxx` | `ret2libc_leak` | **held** | measured 3/3, `20260927-142133Z` |
| 2 | `sick_rop` | SROP read-return `rax`, staging repaired | **high** | F1, diagnosed to `rop_techniques.py:905` |
| 3–5 | one or more of Bonnie / Sabotage / Snow / Auth / Ancient | **unknown** | **undetermined** | Sprint 2 decides |

**2 seats with named mechanisms. Three seats undetermined.** v1 claimed four and
arrived at four by counting a capability that already existed; R1 showed its ceiling
was 4/7 even on its own terms.

The three remaining seats are not a matter of effort allocation — they are a matter
of whether the primitives exist in those binaries in a form the engine can derive.
Sprint 2 answers that in days. **If it returns fewer than three GO routes, the
correct response is to report that and revise T-1′, not to ship a sprint that cannot
reach it.** I would rather bring the user a measured NO-GO than a fifth seat
assembled from optimism, which is what v1 did.

---

## 12. Test plan and red-proofs

Per the standing rule that every new gate must be *proven* able to go RED, and the
positive-control-first discipline:

| gate | red-proof |
|---|---|
| T-2 reducer | a class with a withheld mandatory variant must go red; a 1/3-reliability variant must go red; **a class whose own primitive is ablated must go red** |
| I-11 | delete the key canonicalization → the downstream-state test fails |
| I-12 | feed a `0x55…` heap pointer as a code pointer → rejected (write this test first, watch it fail) |
| Sprint 1 budgets | a technique truncated at its budget must be *reported* as truncated, distinguishably from exhausted |
| Sprint 3 | assert the **syscall sequence**, not the shell; a chain degraded to `read(0,0,0)` must fail loudly |

Regression obligation: the same suite command before and after, counts read by me
from the output. Pre-existing failures stay named and explicitly deselected
(`test_i2_attempt_duration`, `test_solve_command::…test_guided_fallback_resumes_to_success_with_supplied_offset`
= 14 deselected), never quietly absorbed.

---

## 13. Out of scope (declared here, repeated in every delegated prompt)

Security, hardening, and trustworthiness **of the tool itself**. Deliberate
constants — magic-value lists, cheat-sheet tables, technique allowlists, format
header templates, win-function name lists — are **features, not weaknesses**.
Corpus vulnerabilities are never weakened and harness verification is never relaxed
to make a target pass. Nothing is self-scored.

---

## 14. Recommendation

1. **Sprint 0 + Sprint 3 first, in parallel.** Sprint 0 is pure correctness and
   measurement (I-11 and I-12 are real bugs regardless of the 5/7 target, and I-11 is
   P0 because it silently voids any PIE work). Sprint 3 is the only seat diagnosed to
   a line and is independent of everything else.
2. **Then Sprint 1**, because two targets cannot be diagnosed until they stop
   consuming the timeout.
3. **Then Sprint 2, and treat its output as a decision gate** — including the
   possibility that it revises T-1′ downward. Sprint 4+ gets authored and reviewed
   from Sprint 2's evidence, not now.
4. **Do not author the variation corpus until Sprint 0's reducer is committed.**

Peer review of this plan (rotating the reviewer, per the ~60/40 split) before
implementation, then the user's sign-off.
