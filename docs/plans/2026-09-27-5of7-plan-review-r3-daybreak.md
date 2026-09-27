# Peer review R3 (final round) — `2026-09-27-path-to-5of7-plan-v3.md`

| field | value |
|---|---|
| reviewer | Daybreak Blue (`gpt-daybreak-blue-latest`), `model_reasoning_effort=xhigh`, `--sandbox read-only` |
| subject | `docs/plans/2026-09-27-path-to-5of7-plan-v3.md` (committed `ba857ed`) |
| round | **3 of 3 — the cap** |
| verdict | **NOT-APPROVED** — 4 CRITICAL, 6 HIGH, 1 MEDIUM |
| date | 2026-09-27 |

**Disposition, recorded by the author of the plan (me).**

Two of its findings correct claims I had made, and I verified both against the code:

| finding | verification | outcome |
|---|---|---|
| 9 — the SROP diagnosis is incomplete | `rop_techniques.py:1010,1014`: `frame2.rax = SYS_read` with `frame2.rip = vuln_func` — **the same defect as frame1**. Plus `frame1.rsp = rw_target+0x400` (`:998`) returns through an unstaged word | **CONFIRMED.** "Diagnosed to two lines" was too strong. It is one defect *class* with ≥3 instances. Corrected in v3 and in G-4 |
| 10 — "legacy ran on all six" exceeds the artifact | the two timing-out reps were SIGKILLed with no JSON; the recorded legs carry `level=None technique=None` and no phase evidence | **CONFIRMED.** Narrowed to: legacy **ran** on the four targets that completed, and was **reachable and may have contaminated timing** on the two that timed out. The conclusion that those timings must be discarded is unaffected |

The remaining nine findings are all one thing: **the executable gates are gameable.**
Unreliable scoring (`2/10` passing a "≥2/3" bar), post-implementation corpus
definition, route substitution inside an executor, and cross-commit ledger assembly.
They are correct and they are adopted — see v3 §4.5.

**The finding I most needed to hear, and the one that decided what happens next:**

> "The present ledgers — 1 held HTB target, 1 candidate, 5 undetermined, and 0
> variation classes — are honest, not under-claimed. … The problem is not refusal to
> guarantee research success; it is that the executable gates still permit unreliable
> scoring, post-implementation corpus definition, route substitution, and
> cross-commit aggregation."

That distinction is the whole result of this review round. The plan's *substance* is
sound and its arithmetic is honest; what remains unsound is the *apparatus* that would
score it. Those are different kinds of problem and they do not both block the same
thing.

**Escalation, per the 3-round rule.** This was round 3 of a maximum 3, and the
standing rule is that a 4th round escalates the design rather than patching it. The
escalation is a reordering, not a rewrite:

- **No reviewer can tell me whether `bon-nie-appetit` is exploitable.** Only a spike
  can. Three review rounds have now produced a much better measurement apparatus and
  **zero additional solved targets**, which is the actual gate the user set.
- **A spike's output cannot be gamed by a weak gate**, because its deliverable is a
  working reference exploit or nothing. So the spikes are precisely the work that does
  *not* need the gate hardening to land first.
- Therefore: **the spikes start now**, and the gate requirements from this review are
  folded into Sprint 0 and implemented alongside them rather than ahead of them.

The gate hardening is not deferred or waived — it is required before any number is
reported as a score. It is descheduled from the critical path because it gates
*claiming* a result, not *producing* one.

---

V3 is not yet sound enough to implement as the final path. I found four remaining critical false-green paths. The present ledgers—1 held HTB target, 1 candidate, 5 undetermined, and 0 variation classes—are honest, not under-claimed. Most cited code facts are accurate, but two SROP/legacy assertions are incomplete or unsupported.

1. CLASS: HTB GATE NOT FAIL-CLOSED  
Severity: CRITICAL

Failure scenario: The existing reducer marks a target `SOLVED` after any two successful reps, irrespective of total reps. Thus 2/10 passes despite being below 2/3. It also accepts an arbitrary `--target` subset, discovers targets from an unpinned symlink directory, and always exits zero—even at 0/7 ([htb_rescore.py](/srv/share/dev/supwngo/scripts/htb_rescore.py:56), [verdict](/srv/share/dev/supwngo/scripts/htb_rescore.py:162), [configurable reps](/srv/share/dev/supwngo/scripts/htb_rescore.py:174), [unconditional success exit](/srv/share/dev/supwngo/scripts/htb_rescore.py:214)). Five targets at 2/10 could therefore be recorded as 5/7 while the required reliability is absent. Sprint −1 also has no positive control: a canonical-only entry point that performs no attempts would exclude legacy, produce no legacy-prefixed technique, and permit the ledger to be “updated.”

Fix: Commit a fail-closed T-1 reducer with an immutable manifest of exactly seven names and SHA-256 hashes, exactly three completed reps per target, `successes/reps >= 2/3`, and missing/timeout/parse legs counted red. Require a nonzero exit unless the absolute score is ≥5/7. Assert the exact expected attempt census and use Rocket or a canonical synthetic fixture as the positive control for the canonical-only path.

2. CLASS: MECHANISM ABLATION NOT BEHAVIORALLY BOUND  
Severity: CRITICAL

Failure scenario: Mechanism IDs plus the adopted CORPUS1 discipline do not, as written, close the substitution hole. CORPUS1 ablates steps in hand-written reference chains—it asks whether the target requires a step—and does not execute supwngo ([ablate.py](/srv/share/dev/supwngo/benchmark/ablation/ablate.py:10), [same-chain control](/srv/share/dev/supwngo/benchmark/ablation/ablate.py:19)). Engine-route necessity is a separate question. Moreover, v3’s positive control requires only an unrelated class to remain green ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:194)). An ablation switch could still disable the entire `SropExecutor`; the read-return class goes red and an unrelated ret2win class stays green. A mechanism ID assigned at executor entry could meanwhile label a `pop_rax` solve as `read_return_wrapper`. Current attempts have only a technique field, demonstrating where this new binding must be added ([contracts.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/contracts.py:428)); the two SROP branches are genuinely co-resident ([rop_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:829)).

Fix: Require two independent gates:

- Target-chain ablation proves that the corpus member requires the intended primitive.
- Engine-route knockout disables exactly one executed branch.

Add a same-executor sibling positive: under `srop/read_return_wrapper` knockout, a `srop/pop_rax` fixture must still solve and report `srop/pop_rax`. Bind the mechanism ID at branch selection to the successful attempt, receipt, and artifact. A mutation deleting the intended branch while leaving its label machinery intact must turn only its mapped class red.

3. CLASS: CLASS REGISTRATION ORDER IS INVERTED  
Severity: CRITICAL

Failure scenario: Sprint 3 may implement SROP in parallel with Sprint 0 ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:390)), but the variation corpus need only wait until the reducer is committed ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:396)). Therefore its SROP variants can be designed after seeing the repair. Conversely, mechanisms for the five undetermined targets are not established until the later Sprint 2 spikes ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:288)). Sprint 0 cannot pre-register meaningful challenge-alike classes for mechanisms not yet known. This forces either speculative classes or post-implementation corpus design.

There is also no fixed mapping of the seven variation classes to the seven HTB targets/mechanisms. “Exact class→variant census” could be satisfied by choosing seven favorable classes after diagnosis, including multiple easy classes unrelated to the five required HTB seats.

Fix: Enforce this order:

1. Canonical rebaseline.
2. Reducer and mechanism-ID plumbing only.
3. Root-cause/reference-exploit spikes.
4. Bind exactly one class to each of the seven named HTB targets and demonstrated mechanisms; pre-register generators, axes, counts, and development fixtures.
5. Seal acceptance seeds.
6. Implement all capabilities, including SROP.
7. Freeze and score.

A class may count only for its pre-mapped HTB seat/mechanism.

4. CLASS: CROSS-COMMIT LEDGER ASSEMBLY  
Severity: CRITICAL

Failure scenario: Nothing invalidates a held result after later engine changes, and there is no final step running both gates against one clean engine commit. Rocket is held from the historical run ([result](/srv/share/dev/supwngo/benchmark/results_htb/20260927-142133Z.json:120)); Sick ROP would be measured later; future heap or parser routes would be measured later still. A Sprint 4 change can regress Rocket or Sick while their historical ledger entries remain held. T-2 can then run on another frozen commit. The combined ledger says ≥5/7 even though no single build ever achieved either score simultaneously.

Fix: Key every result to engine commit, dirty-tree state, target/variant hashes, manifest hash, harness hash, and configuration. Any engine or harness change invalidates both ledgers. Add one terminal acceptance command on one clean frozen commit that runs the exact seven HTB targets and the sealed seven-class matrix and fails unless both are ≥5/7.

5. CLASS: SEALED ACCEPTANCE IS REUSABLE AFTER REVEAL  
Severity: HIGH

Failure scenario: “Separate branch, never merged to main” is not sealing. The author can inspect that branch, or reveal it once, fail, tune against the revealed binaries, freeze again, and rerun. All branch-isolation requirements remain technically satisfied while the acceptance set has become a development set ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:348), [branch rule](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:353)).

Fix: Make reveal one-shot and commit-bound. Record the frozen engine SHA before materializing or releasing hidden seeds. Any engine change after reveal permanently invalidates that matrix and requires a newly generated, previously unseen acceptance matrix. Store the hidden seed/material outside developer-readable branches until the frozen SHA is registered.

6. CLASS: IMAGE-BASE EXIT TESTS ONLY ONE CONSUMER  
Severity: HIGH

Failure scenario: I-11’s exit requires only that a planted base affect “an executor” ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:161)). Ret2win could be repaired and pass while `needs_leak()` still uses `binary_base` ([context.py](/srv/share/dev/supwngo/supwngo/core/context.py:358)), guided facts and handoff still use `pie` ([orchestrator.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:560), [handoff.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/handoff.py:193)), ret2libc privately reprobes, and tcache continues refusing every PIE binary ([heap_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:172)). The exit passes while “one image-base fact” remains false.

Fix: Introduce one typed image-base accessor and prohibit direct raw-key reads/writes outside it. Test every inventoried producer and applicable consumer, including handoff state, strategy/applicability, and resolved addresses. Add a structural test that the obsolete keys are absent from production consumers.

7. CLASS: PROVENANCE ORACLE CAN BE SYNTHETICALLY INJECTED  
Severity: HIGH

Failure scenario: A typed classifier can pass v3’s controls by accepting test-provided `CODE` provenance and rejecting test-provided `HEAP` provenance, while the real profiler still receives only an integer stripped from raw output ([profile_stage.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/profile_stage.py:174)). It therefore has no source for the type used by the test. A fixture-specific value or label can also pass the pair while the low-page collision remains exploitable; the current symbol matcher really does accept matching low 12 bits alone ([rop_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:119)).

Fix: Define how canonical execution derives provenance—preserved output source/label, ELF-range consistency, multiple-pointer consistency, mapped-segment evidence, or a behavioral validation. Feed raw ambiguous target output through `run_dynamic_profile` and the active leak stage. Include a heap pointer deliberately sharing a symbol’s low 12 bits, and require that the accepted code pointer produces the expected base and resolved addresses.

8. CLASS: BUDGET REPORT CENSUS IS UNBOUND  
Severity: HIGH

Failure scenario: Sprint 1 can report one cheap technique as completed and one dummy or arbitrarily selected technique as truncated, omit the actual expensive techniques, call the report “complete,” and satisfy the written exit ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:212)). The scheduler capability over the canonical registry is absent, but both controls pass.

Fix: Define completeness mechanically: for the exact ordered registry snapshot, every eligible/forced technique has exactly one terminal record—completed, skipped with reason, errored, or truncated—with start/end/deadline data. The report must reconcile to the registry census. Demonstrate the same bounded technique completing under a sufficient sub-budget and becoming `TRUNCATED` under a smaller one.

9. CLASS: SROP DIAGNOSIS IS FACTUALLY INCOMPLETE  
Severity: HIGH

Failure scenario: Defects A and B are real, but they are not the complete staging diagnosis. Frame 2 also restores `rax=SYS_read` while setting `rip=vuln`, so that read syscall is never executed ([rop_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:1010), [frame2 transition](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:1014)). In addition, frame 1 sets `rsp` to `rw_target+0x400` ([rop_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:998)); after the `syscall; ret` gadget completes `mprotect`, it returns through an unstaged word on that newly writable page. Repairing the two listed lines still crashes before stage 2.

The end-to-end shell exit should catch this, so this is not another false solve, but “diagnosed to two lines” and the candidate estimate are factually too strong. The exact-target exit could also pass with a hardcoded wrapper layout while the promised runtime derivation remains absent.

Fix: Diagnose and specify the complete continuation state for every frame: syscall RIP, post-syscall return word, RSP location, re-entry, and where the next chain is staged. Require each counted rep’s exact generated artifact—not separate witnesses—to yield the trace, transitions, and shell. Before declaring Sprint 3 complete, the same derivation code must handle two development wrappers with different instruction-derived argument slots.

10. CLASS: LEGACY EXECUTION CLAIM EXCEEDS THE ARTIFACT  
Severity: MEDIUM

Failure scenario: The statement that legacy “ran on all six” is not established by the cited code. Fallback occurs only after `engine.run()` returns ([cli.py](/srv/share/dev/supwngo/supwngo/cli.py:3342)); the harness kills the subprocess at its external timeout and returns without JSON ([htb_rescore.py](/srv/share/dev/supwngo/scripts/htb_rescore.py:103), [timeout return](/srv/share/dev/supwngo/scripts/htb_rescore.py:126)). The stored run shows both Ancient and Auth killed at 300 seconds with no phase or technique evidence ([result](/srv/share/dev/supwngo/benchmark/results_htb/20260927-142133Z.json:6), [Auth](/srv/share/dev/supwngo/benchmark/results_htb/20260927-142133Z.json:44)). They may have reached legacy, but the artifact cannot prove it.

Fix: Record `engine_phase` transitions and include the last phase in graceful timeout reports. Revise the assertion to “legacy was reachable and may have contaminated timing” unless phase evidence proves actual execution. This does not change the valid conclusion that those timings must be discarded.

11. CLASS: NO-GO EXIT REMAINS PROSE-ONLY  
Severity: HIGH

Failure scenario: A GO now requires strong evidence, but a NO-GO requires only that a blocking fact be named ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:268)). All five spikes can therefore close as NO-GO with assertions such as “no terminal target found,” despite incomplete search or an incorrect model. Sprint 2 passes, subsequent implementation scope collapses, and the project proceeds to an open-ended “expand or BLOCKED” branch ([plan](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v3.md:333)).

Fix: Require reproducible negative evidence: enumerated routes searched, trace/artifacts showing where each fails, the exact invariant making the proposed route impossible, and independent review of that invariant. “Not found” is undetermined, not NO-GO.

The factual target inventory otherwise checks out: the CLI fallback and split image-base consumers are cited correctly; Bonnie’s pointer clearing and size/data schema, the bundled glibc 2.27/2.35 distinction, Snow Scan’s protections, Auth’s stack-backed custom allocator, and Ancient Interface’s stripped binary plus shipped source/dispatch table are consistent with the repository. The current 1/1/5 and 0-class ledgers are therefore appropriately conservative. The problem is not refusal to guarantee research success; it is that the executable gates still permit unreliable scoring, post-implementation corpus definition, route substitution, and cross-commit aggregation.

**VERDICT: NOT-APPROVED**