# Standard work queue — schema + live queue

**Created 2026-09-26. Living document.** The date in the filename is its creation
date (per the repo's dated-artifact convention), not a snapshot — edit this file in
place rather than cloning it per sprint.

This is the **single canonical queue** for supwngo. If an item is not here, it is not
queued; if it is here, it carries an ID that every plan, commit, review, and test can
cite. It supersedes ad-hoc "next up" lists inside individual sprint plans, which may
now reference IDs but must not invent new ones.

---

## 1. Schema — every item, every field

```
### <ID> — <one-line title>

| field | value |
|---|---|
| type        | gap \| bug \| issue \| target \| gate \| assessment |
| relevance   | 1-5 (how much it moves the stated target) |
| complexity  | 1-5 (effort x blast radius x uncertainty) |
| priority    | P0 \| P1 \| P2 \| P3 (derived, then adjusted once by hand) |
| lane        | now \| next \| later \| document-and-move-on \| out-of-scope |
| status      | open \| in-sprint \| blocked \| owes \| done \| superseded |
| evidence    | `file:line`, a command + its output, or a cited doc |
| provenance  | measured \| recorded \| inferred |
| exit        | the observable condition that makes it done |
| owes        | a named review round, sweep, or measurement still outstanding |
| blocks / blocked-by | other IDs |
```

### ID namespaces

| prefix | meaning |
|---|---|
| `G-` | **gap** — a missing capability |
| `B-` | **bug** — wrong behavior |
| `I-` | **issue** — friction, debt, docs; includes pre-existing failures |
| `T-` | **target** — a goal, becomes a Phase-8 metric, never a sprint |
| `M-` | **gate** — a measurement that must pass before work ships |
| `Q-` | **quality** — test-strength / coverage debt (a gate that cannot go red) |
| `A-` | **assessment** — a scoped investigation whose deliverable is a finding, not code |

Suffix letters (`G-2b`) denote a decomposition of a parent item. A superseded item
keeps its ID and gains a `SUPERSEDED — see <ID>` line; IDs are never reused.

### Queue rules (these are the point of the standard)

1. **Nothing enters without an ID, evidence, and a provenance label.** A gap with no
   `file:line`, no command output, and no citation is `inferred`, and is triaged as
   such. `grep` before asserting something is missing.
2. **Nothing leaves `now` until its `exit` condition is observed**, and the observation
   is recorded next to the item — not in chat.
3. **An `owes` entry is an unmeasured claim, not a managed risk.** An item with a
   non-empty `owes` may not be reported as done, however green it looks.
4. **Re-triage inline when the evidence changes.** Strike the old score, keep it
   visible, and say what measurement moved it (see `B-3`, whose complexity went
   `4 → 2` on measured research). Never silently rewrite a score.
5. **Pre-existing failures are listed by name** (the `I-` namespace) and excluded
   explicitly from a sprint's gates. They are never quietly absorbed into a sprint or
   deselected to make a number look right.
6. **Out-of-scope classes are declared once here and repeated in every delegated
   prompt.** For this repo: tool-hardening, compliance controls, and "security of the
   tool itself" are out of scope, and deliberate constants (magic-value lists,
   cheat-sheet tables, technique allowlists) are **features**, not weaknesses.

---

## 2. Live queue

### Lane: `now`

*(empty — Sprint 2′ Wave 3 is mid-verification; see `M-1a`/`M-1b` below for what it
owes before it can close.)*

### Lane: `next`

#### B-3 — `snowscan` stacks three format gates behind the argv gate

| field | value |
|---|---|
| type | bug |
| relevance | 4 — what stands between a working file channel and `snowscan` actually solving, i.e. between Sprint 2′ and `T-1` |
| complexity | ~~4~~ → **2** — a fully accepted BMP is built and confirmed against the real target (20×20, 8bpp, 54-byte header → `[01]…[20] PASS`, `rc=0`); the synthesizer is ~15 lines of `struct.pack` |
| priority | ~~P2~~ → **P1** (raised twice: format validation *masks* the signal a vector probe needs, so B-3 is a prerequisite of reliable detection, not a follow-on; and measured research dropped complexity 4→2) |
| lane | next |
| status | **owes** |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:178` + the measured BMP research addendum |
| provenance | measured |
| exit | a container-envelope registry delivers a payload inside an accepted BMP **and** an accepted WAV, each proven by a target that refuses a bare payload |
| owes | **plan is at Revision 1 and NOT-APPROVED — one review round outstanding.** Do not start implementation before it clears. |
| blocked-by | Sprint 2′ commit |

#### A-1 — modularity assessment of the canonical pipeline *(NEW — user directive, future sprint)*

| field | value |
|---|---|
| type | assessment |
| relevance | 4 — the entire legacy→canonical port rests on the premise that capabilities are modular. That premise has never been measured, and this session produced evidence against it. |
| complexity | 2 — read-only analysis over existing code plus retrospective data already on disk; the deliverable is a written finding plus a proposed seam, not a refactor |
| priority | **P1** |
| lane | next *(explicitly NOT today — scheduled for a future sprint)* |
| status | open |
| provenance | the seed observations below are `measured`; the conclusion is unmeasured by construction |
| exit | a written assessment in `docs/research/` that (a) reports the coupling metric per capability, (b) names each seam that a new capability must cut through, (c) for every seam says *right seam* or *modularity defect*, and (d) proposes at most three changes, each with the capability it would newly make additive |
| owes | nothing yet |
| blocked-by | Sprint 2′ commit (its diff is part of the evidence) |

**Why this item exists, with the evidence already in hand:**

- **Coupling metric, measured.** Adding *one* payload-transport capability (Sprint 2′
  Wave 1+2) touched **8 production files** — `cli.py`, `core/context.py`,
  `pipeline/contracts.py`, `pipeline/orchestrator.py`, `pipeline/verifier.py`,
  `pipeline/templates.py`, `pipeline/executors/stack_techniques.py`,
  `exploit/verification.py`. A modular pipeline would have absorbed a new transport in
  one or two. The assessment should compute "files touched per capability added" across
  Sprint 1, Sprint 2′, and B-3 — that retrospective data already exists in git.
- **The central-allowlist seam.** `FILE_DELIVERY_ALLOWLIST` is a module-level constant
  in `orchestrator.py`: a new executor that wants non-stdin delivery must be added to a
  set in a file it otherwise has nothing to do with. Deliberate constants are features
  here, so this is *not* automatically a defect — but whether the capability should be
  declared **by the executor** rather than **about** the executor is exactly the
  question to answer.
- **The closed-sink enum.** The four sinks live in `contracts.py` with a `container`
  field already reserved; adding a transport currently means editing `contracts.py`,
  `verifier.py`, `templates.py`, and `cli.py` together. B-3 (container envelopes) is the
  next capability that will pay this cost, so measuring it before B-3 lands is the
  cheapest moment.
- **Duplicated placement logic, already partly addressed.** "Where does the payload go
  in argv" existed twice (verifier and script renderer) and drifted — that drift is
  round-3's H1. Wave 2/3 converged both on `DeliverySpec.build_argv()` via a throwaway
  sentinel. Whether that pattern should be generalized (one renderer, many back-ends)
  is a finding this assessment should reach.
- **The legacy engine is not behind an interface.** `EnhancedAutoExploiter` has **4
  construction sites** and no capability contract, which is why a declared vector could
  be laundered back to stdin by a fallback path. Any claim that the port is "modular"
  has to account for that.
- **Two engines, two verification paths.** `ExploitVerifier` (payload) and
  `PipelineVerifier.verify_script` (artifact) are both success oracles with different
  fd-0 semantics — see `G-W3-1`. Whether that is one abstraction or two is a
  modularity question, not only a correctness one.

**Explicitly out of scope for A-1:** tool hardening, and any refactor. A-1 produces a
finding and a proposal; the refactor, if any, becomes its own `G-` item with its own
plan and review round.

### Lane: `later`

#### G-2b — command-shell protocols are undriveable

| field | value |
|---|---|
| type | gap | relevance | 4 — unblocks `ancient_interface` |
| complexity | 4 — needs per-target protocol inference; approach unproven |
| priority | **P2** — **spike-first**: infer-the-protocol is the unproven part |
| lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:77` |
| provenance | recorded |
| exit | a spike that drives one command-shell target end to end, or a written refutation |

#### G-2c — banner/handshake targets need pre-payload synchronization

| field | value |
|---|---|
| type | gap | relevance | 3 — partly handled by existing settle discipline |
| complexity | 2 — extends `deliver_parts()` |
| priority | **P1** | lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:80` |
| provenance | recorded |
| exit | a banner target solves with the payload delivered only after the handshake, proven by a control that fails without the wait |

#### G-2d — network-input targets are unreachable

| field | value |
|---|---|
| type | gap | relevance | 2 — no target in this set exercises it |
| complexity | 4 — socket lifecycle, unproven |
| priority | **P3** | lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:83`; the `socket` sink is *reserved* at `docs/plans/2026-09-26-sprint2prime-input-vector-plan.md:535` |
| provenance | inferred — **no target exercises it** |
| exit | a socket sink delivers to a listening target, with the reserved contract field honored |

#### G-3 — SROP three-stage script deadlocks under script verification

| field | value |
|---|---|
| type | gap | relevance | 4 — would add `sick_rop` toward `T-1` |
| complexity | 4 — root cause not yet diagnosed |
| priority | **P2** — **spike-first push-down**: no sprint until a reproduction isolates the deadlock |
| lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:92` |
| provenance | recorded |
| exit | a minimal reproduction that names which side of the deadlock is waiting, then a fix |

#### I-1 — `test_i2_attempt_duration` fails on `main`

| field | value |
|---|---|
| type | issue (pre-existing) | relevance | 2 | complexity | 2 — test-construction fix |
| priority | **P2** | lane | later | status | open |
| evidence | **`measured` 2026-09-26**: with the repo's deselect expression overridden, 6 tests in `tests/test_i2_attempt_duration.py` fail with `AttributeError: 'CanonicalAutopwnEngine' object has no attribute '_force_all'`. This is why they are deselected. |
| provenance | measured |
| exit | the tests exercise the real force-all path under its current name, and are re-selected |

#### I-2 — `test_solve_command::test_guided_fallback_resumes_to_success_with_supplied_offset` times out

| field | value |
|---|---|
| type | issue (pre-existing) | relevance | 2 | complexity | 3 — 90s timeout, cause unknown |
| priority | **P3** | lane | later | status | open |
| evidence | **`measured` 2026-09-26**: `subprocess.TimeoutExpired` after 90s on `supwngo.cli solve … hardoffset` |
| provenance | measured |
| exit | the cause is named and either fixed or the budget justified in the test |

#### I-4 — provenance conflation + dead `instruction_address`

| field | value |
|---|---|
| type | issue | relevance | 2 — describes a win, cannot cause one; measured 0/6 corpus reachability |
| complexity | 3 — one contract change, 2 production consumers + 3 test refs + 1 benchmark tool |
| priority | **P2** | lane | later | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:245` (raised by peer review round 1) |
| provenance | measured |
| exit | provenance kinds are distinguishable at the point of use, and the dead field is removed or populated |

#### I-5 — `record.offset` reads as minimal but is first-win-under-ordering

| field | value |
|---|---|
| type | issue | relevance | 1 | complexity | 1 — state the rationale at the loop |
| priority | **P3** | lane | **document-and-move-on** | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:246` |
| provenance | measured |
| exit | the loop says what the value means; no behavior change |

#### G-W3-1 — the fd-0 discipline diverges between verification and the generated artifact

| field | value |
|---|---|
| type | gap | relevance | 3 — latent; no corpus or fixture target currently exercises it |
| complexity | 3 — plumbs the verification level into script generation, and must change all four sinks together |
| priority | **P2** | lane | later | status | open |
| evidence | **`measured`**: the subprocess path gives the child EOF (`input=payload` for stdin, `input=b""` for the non-stdin sinks) while every generated artifact leaves stdin open and goes to `io.interactive()`. Identical on HEAD for the stdin default, so the class is pre-existing, not introduced by Sprint 2′. Pinned as one rule by `TestFdZeroDisciplineIsOneRuleForEverySink`. |
| provenance | measured |
| exit | the artifact reproduces the fd-0 discipline of whichever spawn path actually won, for all four sinks, without starving `verify_script`'s `SHELL_ACCESS` oracle |
| blocked-by | a target that waits for EOF on stdin before opening its declared input — **that is what would flip this from latent to measured loss** |

#### I-3 — `explain` command probe hangs on interactive binaries

| field | value |
|---|---|
| type | issue | relevance | 1 — `explain` is not on the `T-1` path | complexity | 3 — unknown |
| priority | **P3** | lane | **document-and-move-on** | status | open |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:225` |
| provenance | recorded |

#### Q-1 — the embedded-token transport form has no committed compiled fixture

| field | value |
|---|---|
| type | quality | relevance | 2 | complexity | 2 |
| priority | **P3** | lane | later | status | open |
| evidence | adding a 13th input-vector fixture ripples into the foundation suite's `EXPECTED_VERDICTS == FIXTURE_NAMES` table; the form is covered by a purpose-built ad-hoc target and by argv-parity tests, not by a committed fixture |
| provenance | measured |
| exit | either a committed fixture with the verdict table updated, or a recorded decision that argv-parity coverage is sufficient |

---

## 3. Gates (must pass before work ships)

#### T-1 — canonical pipeline solves ≥3/7 HTB targets without legacy fallback

| field | value |
|---|---|
| type | target | status | open — **1/7 at last measurement**; legacy solves 3/7 |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:13` |
| provenance | measured |
| note | Sprint 2′ **does not advance T-1** — `snowscan` stays unsolved behind `B-3`. Said plainly rather than implied. |

#### M-1a — per-target corpus regression gate

| field | value |
|---|---|
| type | gate | status | **open — NOT YET RUN for Sprint 2′ Wave 3** |
| exit | 13/13 eligible targets SUCCESS at 5/5 reps, compared **per target** (never in aggregate) against `main` @ `311ff25`, run `20260926-164613Z`, with the two known VOID corpus faults excluded by name: `11_heap_uaf_leak` (`corpus_missing_liveness_gate`) and `13_off_by_one` (`corpus_trivially_solvable`) |
| provenance | baseline is `measured` |
| note | These two VOIDs are **corpus faults and must not be "fixed"** to make a number move. |

#### M-1b — challenge-alike variation benchmark *(user directive, 2026-09-26)*

| field | value |
|---|---|
| type | gate | status | **specified, not measured** |
| evidence | spec at `docs/plans/2026-09-26-sprint2prime-input-vector-plan.md`, section "M-1b" |
| provenance | the harness facts are `measured`; the matrix is unrun |
| exit | a `benchmark/corpus_vectors/` corpus run through the **same** `run_bench.py` verdict machinery, per variant, with the vulnerability held constant and only the ingress varied; and both negative controls (`90_neg_argv_echo_no_open`, `91_neg_config_flag_stdin_payload`) scoring **FAILED** |
| owes | an optional per-target `cli_args:` manifest key (measured gap: `run_supwngo` accepts `extra_args`, nothing supplies them per target) and builder `case` entries |
| note | **Every target in `benchmark/corpus/` takes its payload on stdin**, so M-1a structurally cannot measure this wave's capability. M-1b is the capability gate; M-1a is the regression gate. Neither substitutes for the other. |

---

## 4. Recently closed

| ID | what closed it |
|---|---|
| G-1 | Sprint 1 — disassembly-guided `variable_overwrite` (committed) |
| B-1 | merged-candidate cap + gate tests (`89dbbc9`) |
| B-2 | Sprint 2′ — operator-declared transport replaces inverted auto-detection; the probe is advisory-only |
| G-2′ | Sprint 2′ Waves 1–3 — declared vector now reaches a real spawn (6/6 mechanisms vs 0/6 on the default) |

---

## 5. Out of scope (declared here, repeated in every delegated prompt)

- Security, hardening, and trustworthiness **of the tool itself**.
- Compliance / control-framework findings.
- Deliberate constants — magic-value lists, cheat-sheet tables, technique allowlists —
  are **features**. Measurement problems get fixed in the **corpus**, never by
  weakening a gate or a corpus vulnerability.
- Self-scoring. A verdict comes from the harness, never from the engine's own report.

---

## Appendix A — items added after the queue's first publication

#### I-7 — an undeliverable candidate aborted the whole sweep instead of being pruned — **CLOSED**

| field | value |
|---|---|
| type | bug |
| relevance | 5 — it made an entire delivery transport read as non-functional |
| complexity | 1 — the search continues past an infeasible candidate instead of dying on it |
| priority | **P1** |
| lane | now (closed same day it was found) |
| status | **closed** |
| provenance | **measured 2026-09-27**, run `20260927-124751Z` |
| exit | met — `24_ingress_argv_direct` solves at `offset=64 magic=0x5afef11e`, provenance `recovered_immediate` |

**How it was found.** By the ingress corpus on its first clean run, which is the
concrete argument for having built it: row `24_ingress_argv_direct` scored
`FAILED (0/5 reps)` while the other four new transports scored `SUCCESS (5/5)`.
M-1a structurally could not have found this — every target in `benchmark/corpus/`
reads stdin, so the argv gate is unreachable from that corpus.

**Root cause.** `VariableOverwriteExecutor` swept candidate gate constants and
called `verifier.verify_payload` with no exception handling
(`stack_techniques.py:121-125` at `8d76e14`). `PipelineVerifier` correctly refuses
a NUL-bearing payload on `SINK_ARGV` — an argv token is a NUL-terminated C string
at the syscall boundary — but that `ValueError` propagated out of the sweep.
Candidates are ordered smallest-first, so a small recovered immediate (or the
fallback `0x1337` → `37 13 00 00`) killed the technique on an early candidate and
`0x5AFEF11E`, which is NUL-free and wins, was never reached. The technique
reported `ERROR` with an **empty** `failure_reason`, so the run was also
undiagnosable from its own report.

**Fix.** A single predicate, `contracts.payload_representable(sink, payload)`, now
owns the rule. The verifier asks it and raises; the executor asks it first and
prunes, counting what it pruned and reporting the count in `failure_reason` — an
exhausted search and a search that could not attempt N candidates over this
transport are different results, and the second is a transport limit rather than
an absent gate constant.

**The option not taken:** wrapping `verify_payload` in `except ValueError`. One
source of truth, and it would absorb future undeliverability reasons for free —
but `build_argv()`'s five configuration gates raise the same type, so a
misconfigured spec would be silently recorded as an exhausted search. That is the
same failure mode that made an invalid manifest row read as "the argv transport
does not work" earlier the same day. What would flip the decision: enough
distinct undeliverability reasons to make a predicate unwieldy, at which point a
dedicated exception type (not bare `ValueError`) becomes the better carrier.

**Red-proofed.** Deleting the prune fails
`test_it_reaches_a_later_candidate_after_pruning_an_earlier_one` and
`test_an_exhausted_argv_sweep_reports_how_many_it_could_not_try` (2 failed, 9
passed) on the assertion that the executor handed the verifier bytes the sink
cannot carry. A first draft of that test was **vacuous** — it used `0xdeadbeef`,
which sits at index 1 in `FALLBACK_MAGIC_VALUES`, ahead of the NUL-bearing
`0x1337` at index 4, so the sweep won before reaching the candidate it was
supposed to prune and passed with the prune deleted. Fixed by selecting a winner
that sits after it, plus
`test_the_ordering_this_module_depends_on_still_holds` to keep a future reorder
from quietly restoring the tautology.

**Left open deliberately.** `Ret2WinExecutor` has the same shape — it packs a
64-bit win address, which for a non-PIE binary always contains NUL bytes, so
`ret2win` is genuinely undeliverable over `SINK_ARGV` rather than merely
mispruned. That wants a clear SKIP with a stated reason, not a prune, and it is
not what the measurement demonstrated. Filed as **I-8** rather than fixed here.

#### I-8 — `ret2win` over `SINK_ARGV` should SKIP with a reason, not sweep and fail

| field | value |
|---|---|
| type | issue |
| relevance | 2 — affects report honesty, not any solve: the technique cannot work over this sink either way |
| complexity | 1 |
| priority | **P3** |
| lane | document-and-move-on |
| status | open |
| provenance | **inferred 2026-09-27** — reasoned from the pack width, not observed in a run |
| exit | `ret2win` on `SINK_ARGV` reports SKIPPED naming the 64-bit-address/NUL reason, instead of exhausting a sweep it could never win |

A 64-bit win address packs with high NUL bytes for any realistic non-PIE image
base, so every candidate is unrepresentable in an argv token. After I-7 the
sweep now prunes them all and reports an exhausted search with a full prune
count, which is accurate but reads as a failed attempt rather than an
inapplicable technique.

#### I-6 — walkthrough libc resolution is session-state dependent, and fails silently

| field | value |
|---|---|
| type | issue |
| relevance | 3 — it does not affect a solve, but it silently converts a *measurable* fact into "could not determine", which is exactly the claim the walkthrough family exists to make honestly |
| complexity | 2 — the fix is to distinguish the failure, not to change how resolution works |
| priority | **P2** |
| lane | later |
| status | open |
| provenance | **measured 2026-09-26** |
| exit | `_default_libc` distinguishes "this target has no libc" from "resolution did not complete", and the walkthrough renders the second as a *failed measurement* naming the cause, not as an absence |

**Evidence (measured, via a temporary instrumented build of `facts.py`):**

`collect_facts` resolves the libc through `_default_libc` (`facts.py:696`), which reads
pwntools' `ELF.libc`. That property reaches `pwnlib.elf.elf.ELF._populate_libraries` →
`_patch_elf_and_read_maps`, which **patches shellcode into the target's entry point,
executes the target, and parses `/proc/self/maps`**. Its own docstring says it returns
`{}` when it cannot inject — so on failure `libs` is empty, `libc` is `None`, and **no
exception is ever raised**. `_default_libc`'s `except Exception: return None` therefore
never fires, and there is nothing anywhere to attribute.

Instrumented full-suite run recorded 155 `NO-LIBC` events with no exceptions, e.g.
`NO-LIBC elf=ELF('benchmark/corpus/11_heap_uaf_leak/heap_uaf_leak')` ×7 — for a target
whose libc resolves fine when the same file runs alone.

Downstream, `probe_allocator` reports `safe_linking` as UNKNOWN with the reason
"no libc path was resolved for this target", which is **honest but indistinguishable
from a target that genuinely has no libc**, and it grows the rendered
"Could not determine:" list by one name.

**Why this is filed and not fixed in Sprint 2′:** the walkthrough family is outside this
sprint's scope, and nothing Sprint 2′ changed causes it. The demonstrated failure
(`tests/test_walkthrough_heap.py::test_the_final_summary_lists_what_could_not_be_determined`,
which failed only in full-suite context) was closed at the **test** boundary by pinning
the libc with `ldd` and skipping explicitly when `ldd` names none — three states, not
two. Red-proofed: an unreadable pinned libc reproduces the original failure signature
exactly (1 failed, 51 passed), so the pinning is load-bearing and the gate is not vacuous.

**Same defect class as round-3 H3** (`docs/plans/2026-09-26-wave2-impl-review-r3-daybreak.md`):
a failure of *delivery/measurement* rendered as a failure of *the thing being measured*.
H3 was fixed in production because it sat in the sprint's own code path; this one is
filed with its evidence.
