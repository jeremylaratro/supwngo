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
| type | target | status | open — **1/7 at last measurement**; ~~legacy solves 3/7~~ **legacy measures 0/7 attributed, 1/7 self-reported** |
| evidence | `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md:13`; legacy figure corrected by `docs/research/2026-09-27-legacy-baseline-measured.md` |
| provenance | measured |
| note | Sprint 2′ **does not advance T-1** — `snowscan` stays unsolved behind `B-3`. Said plainly rather than implied. |
| note | **Erratum 2026-09-27.** The ≥3/7 threshold was set to match legacy's recorded score; legacy is now measured at 0/7 attributed, so the *threshold's justification* is void even though the number stands. T-1 is superseded by **T-1′ (HTB ≥5/7)** and **T-2 (variations ≥5/7)** per the user's 2026-09-27 directive. Canonical at 1/7 is equal-or-ahead of legacy on both criteria — **there is no legacy capability to port**, so every remaining seat must come from new capability. |

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

#### G-4 — SROP's read-return `rax` chain is composed against the wrong calling convention

> **ERRATUM, 2026-09-27 (same day as filing).** This item was originally filed as a
> **gap** titled *"SROP cannot use a syscall's return value as a register
> primitive"*, asserting that the capability did not exist and that "no increase in
> its budget or candidate list can reach it." **That assertion is false and the
> original title is withdrawn.** The capability is implemented: `SropExecutor`
> detects a `read` function, sets `use_read_for_rax` when no `pop rax` gadget is
> found, and dispatches `_script_read_rax`
> ([rop_techniques.py:794-800, 830-833, 905](../../supwngo/exploit/pipeline/executors/rop_techniques.py)).
> The 1/7 baseline of run `20260927-142133Z` was therefore measured **after** the
> proposed capability already existed, so building it again would have bought
> nothing. The real defect is narrower and is stated below. Caught by peer review
> (Daybreak Blue R1, finding 4 — see
> [the review](../plans/2026-09-27-5of7-plan-review-r1-daybreak.md)); the error was
> mine, from filing a "missing capability" without grepping for it first, which is
> the failure mode the methodology's Phase-1 rule exists to prevent.

| field | value |
|---|---|
| type | **bug** (was: gap) |
| relevance | **5** — it is the binding constraint on `sick_rop`, one of legacy's three solves, and therefore directly on **T-1** |
| complexity | 3 — repair the stack composition and the stage transition, not a new technique |
| priority | **P1** |
| lane | now (candidate for the next sprint) |
| status | open |
| provenance | **measured 2026-09-27**, run `20260927-142133Z` + disassembly + source read |
| exit | the generated script's **observed syscall sequence** on `sick_rop` contains `read(..., 15) = 15` followed by syscall 15 (`rt_sigreturn`), and `sick_rop` solves |

**Measured — the actual defect.** `_script_read_rax` emits

```
chain = p64(read_addr) + p64(syscall_gadget) + bytes(frame)
```

`sick_rop`'s `read` is a **stack-argument wrapper**, not a register-convention
function: `vuln` does `push $0x300; push %r10; call read`, and the wrapper loads
`rsi` from `0x8(%rsp)` and `rdx` from `0x10(%rsp)`. On entry via this chain,
`[rsp]` is `syscall_gadget` (the return address), so `[rsp+8]` and `[rsp+16]` are
the **first two quadwords of the sigreturn frame**, which are zero in a fresh
`SigreturnFrame`. The call therefore executes `read(0, 0, 0)`, which returns **0,
not 15**, and the following `syscall` runs with `rax=0` — `SYS_read` again, never
`rt_sigreturn`. The technique is right; its argument staging is wrong.

The fix is to compose the chain against the wrapper's measured ABI (place the
length where the wrapper reads it) and to assert the syscall sequence rather than
only the final shell, so a chain that silently degrades to `read(0,0,0)` cannot
read as "no offset candidate verified".

**Update, 2026-09-27 — the staging defect is a CLASS with ≥3 instances, not one line**
(measured; surfaced by peer review R3 finding 9). Every `SigreturnFrame` in the
multi-stage path sets `rax` for a syscall while pointing `rip` at a *function entry*
rather than a syscall *instruction*, so the syscall it staged never executes:

| frame | sets | points `rip` at | cite | consequence |
|---|---|---|---|---|
| `frame1` | `rax = SYS_mprotect` | `vuln_func` | `:991,996` | `mprotect` never runs |
| `frame2` | `rax = SYS_read` | `vuln_func` | `:1010,1014` | the `/bin/sh` plant never runs |

Plus a separate continuation bug: `frame1.rsp = rw_target + 0x400` (`:998`), so after
the `syscall; ret` gadget completes it returns through an **unstaged word** on the
newly-writable page — nothing placed a return target there.

**Consequence for the exit.** Repairing the argument staging alone would witness
`read(...,15) = 15` and syscall 15 and still crash before stage 2. The exit therefore
requires the trace **and** the stage transition **and** an attributed shell in ≥2/3
reps, and the repair must specify for every frame the complete continuation state:
syscall RIP, post-syscall return word, RSP location, re-entry, and where the next
chain is staged. My earlier characterisation of this item as "diagnosed to two lines"
is **withdrawn** — the confidence attached to the `sick_rop` seat was overstated.

**Measured.** `sick_rop` is 4832 bytes / **26 instructions**. The complete set of
instructions touching `rax`:

```
401000:  mov $0x0,%eax      (read)
401017:  mov $0x1,%eax      (write)
401045:  push %rax
401014, 40102b: syscall
```

There is **no `pop rax` gadget and no writable-section trick that helps**.
`rt_sigreturn` requires `rax == 15`, and the only primitive in the binary that can
produce an arbitrary `rax` is **`read`'s own return value**: invoke `read` and send
exactly 15 bytes, so the syscall returns 15 into `rax`, then transfer to `syscall`.
`SropExecutor` already selects exactly this route (`use_read_for_rax`); the
disassembly above establishes that the route is the only one available, **not** that
it is absent.

This is a semantic fact about syscall return values, not a search-space point. The
current executor sweeps *offsets*, so no increase in its budget or candidate list
can fix a chain whose arguments land in the wrong stack slots — which is why this is
a composition bug rather than a tuning issue.

Supporting measurement that rules out the competing explanation: `vuln` calls
`read` with length `$0x300` = **768 bytes** into a 32-byte frame
(`sub $0x20,%rsp`), and the epilogue is `leave; ret`, so the return address sits at
offset **40** — a value already in `COMMON_RET_OFFSETS`. Neither the frame size nor
the offset list is the constraint.

#### I-9 — SROP's failure_reason states a hypothesis the binary refutes

| field | value |
|---|---|
| type | bug |
| relevance | 3 — no effect on any solve, but it actively misdirects diagnosis, which is worse than saying nothing |
| complexity | 1 |
| priority | **P2** |
| lane | now (ride along with G-4) |
| status | open |
| provenance | **measured 2026-09-27** |
| exit | the reason either states a fact about the target or declines to speculate; it never asserts a bound it did not check |

`srop` on `sick_rop` reports:

> built a real rt_sigreturn frame and generated a script, but no offset candidate
> produced a verified shell (a 248-byte frame plus the offset may simply not fit in
> this target's read)

The parenthetical is **false for this target** and checkable from the binary: the
`read` accepts 768 bytes, so a 248-byte frame at offset 40 uses ~288 of 768. A
human following that hint would go looking for a size problem that does not exist,
and would not find G-4.

**Same defect class as I-6 and round-3 H3** — a failure of *measurement* rendered as
a failure of *the thing measured*. Here the executor did not measure the read
length at all; it guessed, and the guess is presented in the same voice as the
established facts around it. The fix is to gate the speculative clause on an actual
check of the target's input length, or drop it.

**Also recorded:** the same run shows `srop`'s recorded skip reason in
`docs/reports/2026-09-26-comprehensive-feature-retest.md` ("no '/bin/sh' string and
no writable section to plant one") is **out of date** — SROP no longer declines at
that gate, it builds a real frame and fails at offset verification. Erratum noted
here beside the claim rather than only in a chat message.

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

#### I-13 — the T-1′ harness cannot enforce "without legacy fallback", so target timings are not canonical timings

| field | value |
|---|---|
| type | bug |
| relevance | **5** — it does not change the 1/7 score, but it invalidates every *diagnosis* drawn from per-target runtimes, which is what the next sprint's sequencing was built on |
| complexity | 2 — a canonical-only path plus an assertion in the harness |
| priority | **P0** |
| lane | now (must precede any budget or spike work) |
| status | open |
| provenance | **measured 2026-09-27** (source read + report JSON), surfaced by peer review of plan v2, finding 1 |
| exit | the harness runs a path that **cannot instantiate** `EnhancedAutoExploiter`, asserts no reported technique carries a `legacy:` prefix, preserves the canonical attempt report on timeout, and the HTB baseline is **re-measured** on it |

**Measured.** `scripts/htb_rescore.py` invokes `supwngo.cli solve`. That command runs
the legacy engine whenever the canonical pipeline fails and no `--input-vector` was
declared (`cli.py:3342-3366`; the same fallback exists in `autopwn` at `cli.py:2771`).
The harness passes no `--input-vector`, so **the legacy engine ran on all six
non-solving targets.** The docstring's claim that withholding `--libc` satisfies
T-1's "without legacy fallback" is a non-sequitur — `--libc` does not gate the
fallback — and is corrected in the same change.

**What survives and what does not.** The solve *count* is unaffected and this is
checkable, not assumed: a legacy success is labelled `engine.technique_used =
f"legacy:{...}"` (`cli.py:3362`), and the only technique string recorded anywhere in
run `20260927-142133Z` is `ret2libc_leak` ×3. **No target was credited to legacy, so
1/7 stands.** What does not survive is the diagnosis layered on the timings:

- "`ancient_interface` and `auth-or-out` exhaust the timeout in canonical search" is
  **not established** — the legacy sweep also ran inside that window. The budget
  sprint's justification must be re-derived after re-baselining.
- "four targets are declined by every executor in under 20s" is a claim about
  canonical **and** legacy combined. The conclusion that these are not budget-bound
  survives (both engines declined fast); the attribution to canonical does not.

**Class note.** This is the *measurement* side of the same defect class as I-6, I-9
and G-4: a property that was never checked, rendered in the same voice as the
properties that were. The harness observed the technique string but never *asserted*
on it, so "no legacy credit" was true by luck rather than by construction.

#### I-11 — one image-base fact, several producers and several consumers, none agreeing

| field | value |
|---|---|
| type | bug |
| relevance | **5** — it silently voids *any* future PIE-base recovery, so it blocks 3 of the 4 unsolved HTB targets before the first line of that work is written |
| complexity | 1 — canonicalize one key, or teach `needs_leak` both |
| priority | **P0** |
| lane | now (must precede any PIE work) |
| status | open |
| provenance | **measured 2026-09-27** (source read), surfaced by peer review R1 finding 6 |
| exit | a **planted, validated** base changes an executor's *resolved* gadget/GOT/control-target addresses and permits an attempt that otherwise skips; key canonicalization alone does **not** close this |

> **Correction, 2026-09-27 (same day as filing).** Filed originally as "a recovered
> image base is written to a key nothing reads", asserting that *every* consumer gates
> on `binary_base`. **That is overstated.** Consumers are split, not uniformly wrong,
> which makes the defect larger rather than smaller. Caught by peer review of plan v2,
> finding 3.

**Measured.** There is no single image-base fact. There are at least four views of it:

| site | keys on | cite |
|---|---|---|
| `ExploitContext.needs_leak()` | `leaks["binary_base"]` | `core/context.py:358-360`, again `:400` |
| orchestrator known-facts write | `leaks["pie"]` | `orchestrator.py:560` |
| handoff fact-checks | `leaks["pie"]` | `handoff.py:193-196` |
| `Ret2LibcLeakExecutor` | neither — probes and computes PIE info **privately** | `rop_techniques.py:421` |
| `tcache_poison_got` | neither — **refuses every PIE target outright**, whatever is stored | `heap_techniques.py:172` |

So a recovered base satisfies the handoff's view, leaves `needs_leak()` still
returning `True`, and is invisible to both executors that would have to consume it.
Known facts are additionally applied only **after** the profiling/leak prologue
(`orchestrator.py:303`), so the ordering is wrong even for the consumer that does read
the key.

**Why the obvious fix is not the fix.** Renaming one key would make the
`needs_leak()` red-proof pass while changing no executor's behaviour: the heap
executor still refuses PIE, and ret2libc still runs its own private probe. That is
the failure mode this item exists to prevent, so its exit criterion is deliberately
an *end-to-end* one — a planted base must change a resolved address and unlock an
attempt that otherwise skips. Recovery and consumption are separate facts and only
the second one is worth anything.

#### I-12 — `identify_leak_type` cannot distinguish a PIE image pointer from a heap pointer

| field | value |
|---|---|
| type | bug |
| relevance | 4 — it does not break a current solve (nothing consumes it yet, per I-11) but it is the classifier any PIE work would build on, and it is wrong in exactly the case that work needs |
| complexity | 2 — needs provenance, not a wider range check |
| priority | **P1** |
| lane | now (rides with I-11) |
| status | open |
| provenance | **measured 2026-09-27** (source read), surfaced by peer review R1 finding 6 |
| exit | **paired** controls on the *canonical* path: a provenance-correct code pointer is accepted **and consumed**, while a same-range heap pointer is rejected. Rejection alone does not pass — it is satisfiable by rejecting everything |

> **Correction, 2026-09-27 (same day as filing).** Filed originally against
> `remote/leak.py:identify_leak_type`. **The canonical pipeline does not call that
> function.** Fixing it would have left the live defect untouched. Caught by peer
> review of plan v2, finding 4.

**Measured — there are three independent overlapping-range classifiers**, and the
one I filed against is the only one the canonical engine never uses:

| classifier | used by | cite |
|---|---|---|
| `delivery.classify_address` | **the canonical profiler** — and `shellcode_techniques` | defined `delivery.py:322`; called `profile_stage.py:174,177`, `shellcode_techniques.py:68` |
| `AutoLeakFinder`'s own classifier | the active leak path | `auto_leak.py:339` |
| `remote/leak.py:identify_leak_type` | legacy / `remote` only — **not the canonical profiler** | `remote/leak.py:172,194-197` |

The defect is the same in each: on amd64 a PIE process's **heap is mapped
immediately after its image**, so the `0x55…` region a classifier labels "PIE" is
also where the heap lives, and the `"heap"` branch (`remote/leak.py:196`) only
catches `address < 0x100000000`, which a PIE-adjacent heap never satisfies. A leaked
heap pointer is therefore classified as an image pointer **unconditionally**, and
page-aligning it yields a heap page. Worse, the active PIE helper can then bind a
symbol to it on **matching low page bits alone** (`rop_techniques.py:119`), so a
page-offset coincidence produces a confidently wrong base.

Range classification cannot fix this, because the ranges genuinely overlap — no
choice of bounds separates them. The distinguishing information is **provenance**:
which action produced the pointer, which symbol it is expected to be, and that
symbol's static offset, so `base = leak - known_offset` can be validated against the
ELF's own segment layout. A classifier that can only say "this number looks like a
binary address" cannot make the judgement its callers need.

**Scope consequence:** the fix must route all three paths through one typed API, or
enumerate and replace each. Fixing one and testing that one is how a repair passes
while the live path stays broken.

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

---

#### D-1 — the legacy fallback's value is now an open decision, not an assumption

| field | value |
|---|---|
| type | issue (decision owed) |
| relevance | **4** — it does not change any score, but it decides whether a second exploitation engine stays on the operator path, and that engine is a live source of measurement contamination (see `I-13`) |
| complexity | 2 — the measurement is done; what remains is a recorded decision plus, if removal is chosen, deleting one block in each of two CLI commands |
| priority | **P2** |
| lane | later — **must not** ride along with any sprint that is being scored, because removing it changes the operator path mid-measurement |
| status | open |
| provenance | **measured 2026-09-27**, `docs/research/2026-09-27-legacy-baseline-measured.md` |
| exit | a recorded decision — keep, remove, or demote to an explicit `--legacy` opt-in — with the reason stated. "Keep because it might help" does not satisfy this; the measurement says it does not help on these seven targets. |

**Measured.** `EnhancedAutoExploiter` was run alone against all seven HTB targets with
a probe validated in both directions (negative control `/bin/true` → `NOT_SOLVED`;
positive control `benchmark/corpus/15_win_function` → `ret2win`/`FLAG_CAPTURED`). It
scored **0/7** under attributed crediting and **1/7** under the self-report criterion
the withdrawn "3/7" figure used. Two targets (`ancient_interface`, `auth-or-out`)
consumed the full 600 s timeout.

**Why this is a decision and not a fix.** Three facts pull in different directions and
none of them is mine to weigh unilaterally:

1. The fallback adds **no measured solve** on this corpus, and it is reached on every
   canonical failure (`cli.py:3393`, `cli.py:2799`), so it costs wall-clock on exactly
   the runs that are already slowest.
2. It is the mechanism behind `I-13` — it contaminated per-target timings and forced
   `--no-legacy` to exist so measurement could be structural.
3. But "0/7 on seven HTB targets" is **not** "worthless in general". The corpus is seven
   binaries; absence of benefit here is weak evidence about an arbitrary operator target,
   and `--no-legacy` already removes it from every *measured* path.

**Option not taken, and what would flip it.** I did not remove the fallback. Removing a
working operator code path on the strength of a seven-binary corpus would be scope creep
past what the measurement supports, and `--no-legacy` already closes the measurement
hole that actually mattered. What would flip it: a run of the ingress/variation corpora
showing the fallback also contributes nothing there, or a demonstration that its
unconditional invocation is what pushes a target over the harness timeout — either
would make removal a correctness fix rather than a preference.

**Deliberately not in scope here:** the fallback's *own* robustness. Per the standing
exclusion, hardening the tool is out of scope; this item is about whether the path
should exist at all.
