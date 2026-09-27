# Path to 5/7 (v3) — HTB challenges and their challenge-alike variations

**Date:** 2026-09-27
**Status:** PLAN — not approved, not started. **Implementation is gated on the
user's sign-off.**
**Supersedes:** [v2](2026-09-27-path-to-5of7-plan-v2.md) (NOT-APPROVED, 9 findings —
[review](2026-09-27-5of7-plan-review-r1-v2-sol.md)), which superseded
[v1](2026-09-27-path-to-5of7-plan.md) (NOT-APPROVED, 8 findings —
[review](2026-09-27-5of7-plan-review-r1-daybreak.md)).
**Directive (user, 2026-09-27):** **HTB ≥5/7 AND challenge-variations ≥5/7.**

---

## 1. Revision history and what each review changed

| rev | reviewer | verdict | what it changed |
|---|---|---|---|
| v1 | Daybreak Blue, xhigh | NOT-APPROVED (4C/4H) | Premise invalid — "every unsolved target has PIE/a canary" was a correlation, not a diagnosis. Its best seat (GAP-R) was a capability that already existed. **Superseded, not revised.** |
| v2 | Sol 5.6, xhigh | NOT-APPROVED (5C/4H) | **Sequencing affirmed** ("the high-level measure → diagnose → implement ordering is sound") but **not enforced**. Measurement path runs the legacy engine; ablation was at the wrong granularity; every red-proof was one-sided. **Revised into v3.** |

v2 is revised rather than superseded because the reviewer explicitly endorsed its
ordering principle and attacked its *enforcement*. That is patchable inside the
structure. This is round 2 of the 3-round cap for this plan lineage.

Of v2's 9 findings I verified 6 against the code by reading the cited lines. **All 6
confirmed**, and two of them named defects that were in no queue.

---

## 2. Definition of done — two separate ledgers

v2 collapsed both gates into one "seat count". They are conjunctive gates with
different evidence, and merging them flattered the state of the work.

### T-1′ ledger (HTB) — target ≥5/7

| target | state | mechanism | basis |
|---|---|---|---|
| `rocket_blaster_xxx` | **held** | `ret2libc_leak` | measured 3/3, `20260927-142133Z` |
| `sick_rop` | **candidate** | SROP read-return `rax` | diagnosed to two lines; **unimplemented repair** |
| `bon-nie-appetit` | undetermined | — | Sprint 2 decides |
| `sabotage` | undetermined | — | Sprint 2 decides |
| `snow_scan` | undetermined | — | Sprint 2 decides |
| `auth-or-out` | undetermined | — | Sprint 2 decides |
| `ancient_interface` | undetermined | — | Sprint 2 decides |

**1 held, 1 candidate, 5 undetermined.**

### T-2 ledger (variations) — target ≥5/7 classes

**0 held.** Not "2". The reducer, the census, the variants, and the sealed
acceptance results do not exist, so no class can be held yet. Note further that
`rocket_blaster_xxx`'s held T-1 seat **cannot be carried across**: its measured
mechanism is `ret2libc_leak` while its proposed T-2 class was "ret2win with
arguments". Those are different capabilities and one does not credit the other.

A state becomes **held** only when its own gate's reliability threshold passes.

---

## 3. Sprint −1 — re-baseline on a canonical-only path (NEW, blocks everything)

**Closes:** I-13. **Claims no solve.**

v2 built its sequencing on per-target runtimes from run `20260927-142133Z`. Those
runtimes are not canonical runtimes.

**Measured.** `scripts/htb_rescore.py` invokes `supwngo.cli solve`, which runs
`EnhancedAutoExploiter` whenever the canonical pipeline fails and no
`--input-vector` was declared (`cli.py:3342-3366`; same fallback in `autopwn` at
`cli.py:2771`). The harness declares none, so **the legacy engine ran on all six
non-solving targets.** The harness docstring's claim that withholding `--libc`
satisfies T-1's "without legacy fallback" is a non-sequitur.

**What survives.** The solve count, and this is checked rather than assumed: a
legacy success is labelled `f"legacy:{...}"` (`cli.py:3362`), and the only technique
string recorded anywhere in the run is `ret2libc_leak` ×3. **No target was credited
to legacy. 1/7 stands.**

**What does not.** Every diagnosis drawn from the timings:

- "the two timeouts are canonical search-space exhaustion" — **withdrawn.** The
  legacy sweep also ran inside that window. v2's Sprint 1 justification is void
  until re-measured.
- "four targets are declined by every executor in under 20s" — the *conclusion*
  (not budget-bound) survives, because both engines declined fast. The attribution
  to canonical specifically does not.

**Exit:**

- [ ] a canonical-only path that **cannot instantiate** the legacy engine (a flag or
      API entry, not a convention)
- [ ] the harness asserts no reported technique carries a `legacy:` prefix — the
      property was observable before but never asserted, so "no legacy credit" was
      true by luck rather than construction
- [ ] the canonical attempt report is preserved on timeout (otherwise the two
      timing-out targets stay undiagnosable)
- [ ] **HTB baseline re-measured**, and §2's ledger updated from it

**Method chosen:** a dedicated canonical-only entry point.
**Method not taken:** an env-var opt-out of the fallback. Rejected — it leaves the
legacy import reachable, so nothing *structurally* prevents the contamination, and
this item exists because a convention was trusted instead of a guarantee.

---

## 4. Sprint 0 — measurement contract and the P0 correctness defects

**Closes:** I-11, I-12, the T-2 reducer gap. **Claims no solve.**

### 4.1 The reducer: ablate **sub-routes**, not executors

v2 proposed ablation by executor-registry exclusion. That closes cross-executor
substitution (`ret2libc_leak` standing in for `ret2win`) but **not** substitution
*inside* an executor. `SropExecutor` contains the read-return branch and the
`pop rax` branch (`rop_techniques.py:829-842`) and **both report the technique name
`srop`**. So a "read-return SROP" variant that happens to contain a usable
`pop rax` would be solved by the easier branch, attributed `srop`, and removing the
whole executor would still turn the class red. Every v2 reducer condition passes
while read-return support is absent.

**The fix:** a stable **mechanism identifier** — `srop/read_return_wrapper` vs
`srop/pop_rax` — recorded on the attempt, with ablation targeting the sub-route
while sibling routes stay enabled.

**This adopts the repo's existing ablation discipline rather than inventing one**
(`docs/reports/CORPUS1-ABLATION-24SEP2026.md`), which already encodes: one
parametrised chain per target with a single keyword flipped (no separate
reimplementation that could be independently wrong); **intact arm first**, and a
target whose intact chain does not produce the flag is reported `NOT MEASURABLE`
with its ablations explicitly uninterpreted; fresh random secret per target; every
emitted byte captured. Its governing rule is the one T-2 needs:

> "The exploit works" is not evidence a target is sound.
> **"Nothing less than the exploit works"** is.

Reducer requirements: exact class→variant census declared in the manifest; every
mandatory variant at **≥2/3 reps**, keyed on `reliability` and never on `solved`; any
`VOID`/missing leg ⇒ the class is red; attribution matched on the **mechanism ID**;
per-class sub-route ablation with an intact arm first, reporting `NOT_MEASURABLE`
rather than a pass when the intact arm is not green.

### 4.2 I-11 — one image-base fact (exit changed)

v2's exit — canonicalize the key, assert `needs_leak()` flips — was too weak, and
the review is right about why. Consumers are **split, not uniformly wrong**:

| site | keys on | cite |
|---|---|---|
| `needs_leak()` | `leaks["binary_base"]` | `core/context.py:358-360`, `:400` |
| orchestrator write | `leaks["pie"]` | `orchestrator.py:560` |
| handoff fact-checks | `leaks["pie"]` | `handoff.py:193-196` |
| `Ret2LibcLeakExecutor` | neither — probes privately | `rop_techniques.py:421` |
| `tcache_poison_got` | neither — **refuses all PIE regardless** | `heap_techniques.py:172` |

Renaming a key would pass the `needs_leak()` red-proof while changing no executor's
behaviour. Known facts are also applied only *after* the profiling/leak prologue
(`orchestrator.py:303`), so the ordering is wrong even for the consumer that reads
the key.

**Exit:** a planted, validated base must change an executor's **resolved**
gadget/GOT/control-target addresses and unlock an attempt that otherwise skips.
Guided facts applied before any stage that should consume them.

### 4.3 I-12 — fix the classifier the canonical engine actually uses

v2 filed this against `remote/leak.py`. **The canonical profiler does not call it.**
There are three independent overlapping-range classifiers:

| classifier | used by | cite |
|---|---|---|
| `delivery.classify_address` | **the canonical profiler**, `shellcode_techniques` | `delivery.py:322`; `profile_stage.py:174,177` |
| `AutoLeakFinder`'s own | the active leak path | `auto_leak.py:339` |
| `remote/leak.py:identify_leak_type` | legacy/`remote` only | `remote/leak.py:172,194-197` |

Same defect in each: a PIE process's heap is mapped immediately after its image, so
the `0x55…` region labelled "PIE" is also the heap. Worse, the active PIE helper can
bind a symbol on **matching low page bits alone** (`rop_techniques.py:119`), so a
page-offset coincidence yields a confidently wrong base.

**Exit:** route all three through one typed API (or replace each), with **paired
canonical-path controls** — a provenance-correct code pointer accepted *and
consumed*, a same-range heap pointer rejected.

### 4.4 Every gate gets a GREEN control, not only a RED one

v2's red-proofs were **one-sided**: an always-red reducer satisfied all of them, an
I-12 that rejects every pointer satisfied its test, a scheduler that truncates
everything satisfied the budget proof. This is the mirror image of the failure mode
this project has hit repeatedly, and I produced the inverse of it.

| gate | RED control | GREEN control (new) |
|---|---|---|
| T-2 reducer | withheld mandatory variant → red; 1/3 reliability → red; sub-route ablated → red | a synthetic exact census is **green intact**, and an unrelated class **stays green** under that ablation |
| I-11 | delete canonicalization → resolved addresses unchanged → fail | planted base **changes a resolved address and unlocks a skipped attempt** |
| I-12 | same-range heap pointer → rejected | provenance-correct code pointer → **accepted and consumed** |
| Sprint 1 budgets | a truncated technique reports *truncated*, distinguishably | **at least one bounded technique completes normally** |
| Sprint 3 | chain degraded to `read(0,0,0)` fails loudly | attributed shell in ≥2/3 reps (§6) |

---

## 5. Sprint 1 — budget discipline

**Claims no solve.** **Justification deferred to Sprint −1's re-baseline** — the
original evidence for it was contaminated (§3).

If the re-baseline still shows the two targets exhausting the timeout in canonical
search, proceed: a global wall-clock budget with per-technique sub-budgets, where a
truncated technique must report *that it was truncated* — conflating "cut off at its
budget" with "exhausted its search" is the I-7 defect class at a different layer.

**Exit:** both targets produce a complete per-technique report within the outer
timeout; ≥1 technique completes normally and ≥1 is truncated, distinguishably.
**Method not taken:** raising the outer timeout — already falsified,
`ancient_interface` timed out at 1100s too.
**What would flip the whole sprint:** the re-baseline showing canonical finishes
quickly on both targets, in which case this sprint is unnecessary and the two
targets go straight to Sprint 2.

---

## 6. Sprint 3 — repair the SROP staging (G-4), stronger exit

**Claims one candidate seat: `sick_rop`.** Independent of Sprints 0–2.

v2 weakened this exit to "witness `read(...,15)=15` then syscall 15", below the work
queue's own requirement. The review is right, and the reason is that **the chain has
a second, independent defect** I verified:

- **Defect A (argument staging).** `chain = p64(read_addr) + p64(syscall_gadget) +
  bytes(frame)` (`rop_techniques.py:940`), but `sick_rop`'s `read` is a
  stack-argument wrapper reading `rsi`/`rdx` from `[rsp+8]`/`[rsp+16]` — the zeroed
  head of the frame. It executes `read(0,0,0)` → returns 0, never 15.
- **Defect B (stage transition).** In the no-`/bin/sh` path, `frame1.rax =
  SYS_mprotect` but `frame1.rip = vuln_func` (`rop_techniques.py:991,996`). After
  `rt_sigreturn` restores the frame, **no `syscall` instruction executes**, so
  `mprotect` never runs. `rip` must reach the syscall gadget.

Repairing only A would witness syscall 15 and still not solve the target — exactly
the intermediate-witness trap.

**Exit (restored to the queue's strength):** the required syscall trace **and** a
successful stage transition **and** an attributed shell in **≥2/3 T-1 reps**.

**Ride-along:** I-9 (the `failure_reason` asserting a 248-byte-frame size bound the
target refutes — the read accepts 768 bytes), same file, same technique, and the
false hint actively misdirects diagnosis of these very bugs.

**Method — corrected.** v2 said "derive the slot layout at plan time." That cannot
generalize: plan-time derivation is fitting to `sick_rop`. **Wrapper layout must be
derived at runtime** from the callee's own prologue. Variants must include ≥1
stack-arg wrapper with a *different* slot layout, so the fix cannot be "hardcode
`[rsp+16]`".
**Generalization:** `read`-return and `write`-return are different mechanisms and get
different mechanism IDs. `write`-return needs its own implemented, witnessed path or
it is not claimed.

---

## 7. Sprint 2 — root-cause spikes (the decision point)

**Claims no solve. Produces evidence.**

### 7.1 A GO requires a working exploit, not a written record

v2's exit accepted a four-fact prose record. A plausible narrative is not evidence.

**A GO requires:** a reproducible reference exploit, the target's hash, an observed
primitive trace, and an attributed shell/flag result. **A NO-GO requires** the
blocking fact named. A NO-GO is a successful spike — it costs days, not a sprint.

### 7.2 The four facts, with justified `N/A` permitted

v2 required all four facts universally and would have marked viable non-PIE routes
NO-GO for lacking a base leak they never needed.

| # | fact | may be `N/A`? |
|---|---|---|
| 1 | disclosure primitive | yes, with justification (non-PIE, no ASLR dependency) |
| 2 | derived base | yes, same |
| 3 | corruption primitive | **no** |
| 4 | terminal control target + trigger | **no** |

And the terminal question must be **route-appropriate** — saved return address,
function pointer, dispatch-table entry, environment/PATH corruption — **not
universally "a win function"**.

### 7.3 The five routes

| route | measured facts already against it | what the spike settles |
|---|---|---|
| `bon-nie-appetit` | glibc **2.27** (hooks live). Clears its pointer after deletion; `create` is **size/data**, generic script sends **index/size** | whether a UAF exists given the pointer clear; the real action schema |
| `sabotage` | glibc **2.35** — hooks **removed**. Only `scanf` is one `%lu` length, so the generated `scanf_canary_bypass` is a **detector false positive**, not a near-miss | the terminal control target when hooks do not exist and RELRO is full |
| `snow_scan` | non-PIE, canary, partial RELRO. B-3's exit is **reaching** the parser's unsafe path, **not solving** it (`2026-09-26-b3-container-registry-plan.md:61`) | whether crash control is achievable past the parser |
| `auth-or-out` | **custom stack-arena allocator** (`ta_alloc`/`ta_free`/`insert_block`/`compact`) plus an application function pointer. A glibc tcache/GOT retarget is not its primitive | state confusion in the custom allocator; reachability of the function pointer |
| `ancient_interface` | binary is **stripped**, but **its C source ships** (`…/challenge/ancient_interface.c`) — the only target that does. It has a **command dispatch table** (`:47`) and a signal-sensitive read path (`:214`) — **no hidden win function**, so "find the win target" was the wrong terminal question | whether a dispatch-table entry or the signal path is the terminal control target, and whether it is derivable **without** the source |

v1 grouped Bonnie, Sabotage and Auth as one "PIE + heap" problem. The measured facts
show **three different terminal-control problems**, across two glibc generations and
two allocators. They do not share a fix.

### 7.4 Anti-fitting boundary (source and writeups ship)

`tests/htb-targets/` contains **official writeup PDFs for the set** and source for
`ancient_interface`. These are legitimate as **ground truth for validating a spike**
— did the engine derive the right primitive? — and are **forbidden as engine input or
as a basis for tuning the engine to a specific target**. Any capability justified by
a writeup must be demonstrated on a sealed variation that no writeup covers, or it is
fitting to the acceptance set and fails T-2 by construction.

### 7.5 Exit

- [ ] each route: a GO with a reproducible exploit + hash + trace + attributed
      result, or a NO-GO with its blocking fact
- [ ] leverage recomputed from demonstrated chains, never from protection flags
- [ ] Sprint 4+ authored **from this output** and reviewed before implementation

**Method chosen:** manual reference exploit per route, then ask what the engine must
derive to reach it. A working hand exploit is an unambiguous oracle.
**Method not taken:** symbolic/concolic triage as primary — it answers "is there a
path", not "what is the terminal control target". Retained as the fallback for
`ancient_interface`, where symbol-free derivation is the actual problem.

---

## 8. Governance: what happens if the spikes return fewer than three GO routes

v2 said T-1′ would be "revised downward". **That is withdrawn.** 5/7 is a
user-set acceptance criterion and lowering it is not mine to do — changing it
requires explicit user authorization. Presenting a goal change as a plan outcome is
how a plan finishes successfully while the project fails.

**Corrected continuation rule.** Sprints −1 through 2 are a **feasibility phase**,
not the complete path to 5/7. On their completion:

1. Implement the best three demonstrated routes.
2. If fewer than three GO routes exist: **expand the route search** (further spikes,
   or the concolic fallback), or **report the fixed goal as BLOCKED with the measured
   reason and request direction.**
3. Never alter either 5/7 gate without the user's explicit authorization.

---

## 9. Generalization obligations

| obligation | requirement |
|---|---|
| **two matrices** | a *development* matrix (visible) and a separately generated **sealed acceptance** matrix, revealed only after the engine is frozen |
| **census** | exact variant count per class, declared up front |
| **held-out members** | ≥2 per counted class, each at ≥2/3 reliability |
| **perturbation** | compiler flags, field reordering, optimization level, prompt/verb wording, varied independently |
| **one mechanism per class** | tcache ≠ fastbin; hook ≠ saved-return; `read`-return ≠ `write`-return; and these are distinguished by **mechanism ID**, which is what makes the distinction enforceable rather than documentary |
| **branch isolation** | held-out corpora stay on their own branches, **never merged to `main`** |

Corpus design belongs to Sprint 0, before any of it is authored: a corpus authored
without a sound reducer records a baseline that cannot support T-2 — the defect that
already returned M-1b to planning once.

---

## 10. Test plan

Regression: the same suite command before and after, counts read by me from the
output, never relayed from a delegate. Pre-existing failures stay named and
explicitly deselected (`test_i2_attempt_duration`,
`test_solve_command::…test_guided_fallback_resumes_to_success_with_supplied_offset`
= 14 deselected), never quietly absorbed. Current baseline: **1315 passed, 16
skipped, 14 deselected, 0 failed.**

Every new gate carries both controls from §4.4. A gate with only a RED control is
treated as unbuilt.

---

## 11. Out of scope (declared here, repeated in every delegated prompt)

Security, hardening, and trustworthiness **of the tool itself**. Deliberate
constants — magic-value lists, cheat-sheet tables, technique allowlists, format
header templates, win-function name lists — are **features, not weaknesses**. Corpus
vulnerabilities are never weakened and harness verification is never relaxed to make
a target pass. Nothing is self-scored.

---

## 12. Recommendation

1. **Sprint −1 first, alone.** Until the HTB baseline is re-measured on a
   canonical-only path, every runtime-derived diagnosis is unreliable — including the
   justification for Sprint 1. It is small and it gates the rest.
2. **Then Sprint 0 and Sprint 3 in parallel.** Sprint 0 is correctness and
   measurement (I-11 and I-12 are real bugs independent of the 5/7 target). Sprint 3
   is the only candidate seat diagnosed to specific lines, and is independent.
3. **Then Sprint 1**, if and only if the re-baseline still shows the timeouts.
4. **Then Sprint 2, as a decision gate** — with §8's continuation rule, which does
   not permit lowering the goal.
5. **Do not author the variation corpus until the reducer with mechanism IDs is
   committed.**

Peer review of v3 before implementation, then the user's sign-off.
