# Peer review — `2026-09-27-path-to-5of7-plan-v2.md`

| field | value |
|---|---|
| reviewer | Sol 5.6 (`gpt-5.6-sol`), `model_reasoning_effort=xhigh`, `--sandbox read-only` |
| subject | `docs/plans/2026-09-27-path-to-5of7-plan-v2.md` (committed `b501972`) |
| round | 2 of a maximum 3 for this plan lineage |
| verdict | **NOT-APPROVED** — 5 CRITICAL, 4 HIGH |
| date | 2026-09-27 |
| reviewer rotation | deliberately **not** Daybreak Blue, which reviewed v1; v2 was a restructure prompted by that review and should not be graded by the model that prompted it |

**Disposition, recorded 2026-09-27 by the author of the plan (me).** I verified six
findings against the code by reading the cited lines. **All six confirmed.** Two name
defects that were in no queue.

| finding | verification | outcome |
|---|---|---|
| 1 — harness runs the legacy engine | `cli.py:3342-3366` runs `EnhancedAutoExploiter` when canonical fails and no `--input-vector` is declared; `htb_rescore.py` declares none. The `--libc` rationale in its docstring is a non-sequitur | **CONFIRMED.** Filed **I-13**, P0. See the scope note below |
| 2 — intermediate witness claimed as capability, plus a second chain defect | `rop_techniques.py:991,996`: `frame1.rax = SYS_mprotect` but `frame1.rip = vuln_func`, so after `rt_sigreturn` **no `syscall` executes** and `mprotect` never runs | **CONFIRMED** — an independent second bug. Sprint 3's exit restored to the queue's strength |
| 3 — F3 overstated; consumers are split | `context.py:358` keys on `binary_base`; `handoff.py:193` keys on `pie`; `rop_techniques.py:421` probes privately; `heap_techniques.py:172` refuses all PIE regardless | **CONFIRMED.** I-11 refiled with an end-to-end exit |
| 4 — I-12 targets a path the canonical engine never uses | canonical profiler calls `delivery.classify_address` (`profile_stage.py:174`, defined `delivery.py:322`); `auto_leak.py:339` is a third classifier; `remote/leak.py` is legacy-only | **CONFIRMED.** I-12 refiled against all three |
| 5 — executor ablation ≠ primitive ablation | `SropExecutor` holds both the read-return and `pop rax` branches (`rop_techniques.py:829-842`) and both report `srop` | **CONFIRMED.** Reducer changed to mechanism IDs |
| 9 — `ancient_interface` has no win function | its C source **ships** (`…/challenge/ancient_interface.c`); command dispatch table at `:47`, signal-sensitive read at `:214`. Official writeup PDFs ship for the whole set | **CONFIRMED.** Terminal question corrected; anti-fitting boundary added |

Finding 5 additionally pointed out that the repo **already has** the ablation
discipline v2 was reinventing (`docs/reports/CORPUS1-ABLATION-24SEP2026.md`): one
parametrised chain with a single keyword flipped, intact arm first, `NOT MEASURABLE`
rather than a silent pass, fresh secret per target. v3 adopts it. That is the
"grep before building" rule catching me a second time in the same effort.

**Scope note on finding 1, stated precisely because the reviewer's phrasing is
broader than the evidence.** The legacy engine did run on all six non-solving
targets, so the *timing-derived diagnoses* are void. But the **solve count is not
contaminated, and this is measured rather than assumed**: a legacy success is
labelled `f"legacy:{...}"` (`cli.py:3362`), and the only technique string recorded
anywhere in run `20260927-142133Z` is `ret2libc_leak` ×3. **1/7 stands.** The
harness's fault is that it never *asserted* on that string — the property held by
luck, not by construction.

**Finding 8 is the one I most needed.** v2 proposed revising T-1′ downward if the
spikes returned fewer than three GO routes. 5/7 is a user-set acceptance criterion
and lowering it is not mine to do. v3 withdraws that branch entirely and replaces it
with: expand the route search, or report the goal BLOCKED with the measured reason
and request direction.

Superseded by [v3](2026-09-27-path-to-5of7-plan-v3.md).

---

The high-level “measure → diagnose → implement” ordering is sound, but v2 does not actually enforce it. The current HTB measurement path executes the legacy engine, Sprint 3 claims an incompletely diagnosed seat, and several exits admit vacuous implementations.

1. CLASS: ENGINE-BOUNDARY CONTAMINATION  
Severity: CRITICAL

The T-1′ harness is not canonical-only. It invokes `supwngo solve` ([htb_rescore.py:105](/srv/share/dev/supwngo/scripts/htb_rescore.py:105)), but `solve` automatically runs `EnhancedAutoExploiter` whenever the canonical engine fails ([cli.py:3340](/srv/share/dev/supwngo/supwngo/cli.py:3340)). Omitting `--libc` does not disable that fallback, contrary to [htb_rescore.py:22](/srv/share/dev/supwngo/scripts/htb_rescore.py:22).

Failure scenario: The canonical engine finishes quickly, then the legacy sweep consumes the 300/1100-second outer timeout. V2 concludes that canonical search-space allocation is the blocker and implements Sprint 1 budgets, but the legacy fallback still consumes the timeout. Thus the “two targets never finish” diagnosis and Sprint 1 sequencing are not established by the cited run. Legacy success is not normally credited by the receipt parser, but its execution still contaminates timing and inconclusive verdicts.

Fix: Add a canonical-only CLI/API path that cannot instantiate the legacy engine; use it in `htb_rescore.py`; assert no reported technique starts with `legacy:`; preserve the canonical attempt report on timeout; then rebaseline before Sprint 1 or any arithmetic based on target runtimes.

2. CLASS: INTERMEDIATE WITNESS CLAIMED AS END-TO-END CAPABILITY  
Severity: CRITICAL

Sprint 3 weakened the repository’s existing G-4 exit. The work queue requires the syscall trace and that `sick_rop` solves ([standard-work-queue.md:355](/srv/share/dev/supwngo/docs/process/2026-09-26-standard-work-queue.md:355)); v2 requires only `read(...,15)=15` followed by syscall 15 ([plan-v2.md:294](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v2.md:294)).

That is especially unsafe because the chain has further defects. The current no-`/bin/sh` path sets `frame1.rax = mprotect` but restores `rip` to `vuln`, not the syscall gadget ([rop_techniques.py:991](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:991)); after `rt_sigreturn`, `mprotect` therefore is not executed. The official bundled Sick ROP writeup uses `frame.rip = syscall_gadget`, `frame.rsp = vuln_ptr`, and initially returns to `vuln`, not directly to the stack-argument `read` wrapper ([writeup PDF, page 6](/srv/share/dev/supwngo/tests/htb-targets/9e4d9110-3b36-410d-8cc2-c63d8f880476.pdf)). The generated implementation instead returns directly to `read` ([rop_techniques.py:940](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:940)).

Failure scenario: The first transition is repaired sufficiently to witness syscall 15, but the restored context never performs `mprotect`, never returns safely for shellcode delivery, or crashes. Sprint 3 passes and seat 2 is claimed while `sick_rop` remains unsolved.

Fix: Restore the stronger exit: required trace, successful `mprotect`/stage transition, and an attributed shell in ≥2/3 T-1 reps. Diagnose the complete target chain before selecting direct-wrapper argument derivation versus `vuln` re-entry. Runtime analysis—not “derivation at plan time”—must derive any wrapper layout used for variations.

3. CLASS: LEAK-STATE CANONICALIZATION WITHOUT REBASE CONSUMPTION  
Severity: CRITICAL

F3 is overstated: consumers do not uniformly gate on `binary_base`. `ExploitContext` checks `binary_base` ([context.py:358](/srv/share/dev/supwngo/supwngo/core/context.py:358)), the handoff layer checks `pie` ([handoff.py:193](/srv/share/dev/supwngo/supwngo/exploit/pipeline/handoff.py:193)), `Ret2LibcLeakExecutor` privately probes and computes its own PIE information ([rop_techniques.py:421](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:421)), and the existing heap executor rejects every PIE target regardless of any stored base ([heap_techniques.py:172](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:172)). Known facts are also applied only after the profiling/leak prologue ([orchestrator.py:303](/srv/share/dev/supwngo/supwngo/exploit/pipeline/orchestrator.py:303)).

Failure scenario: I-11 changes `pie` to `binary_base`; its `needs_leak()` red-proof passes. No executor rebases addresses from that value, the heap executor still refuses PIE, and ret2libc still performs its separate probe. Sprint 0 declares the foundational defect fixed while downstream capability remains absent.

Fix: Define one image-base fact and inventory every producer and consumer. Require an end-to-end test in which a planted validated base changes an executor’s resolved gadget/GOT/control-target addresses and permits an attempt that otherwise skips. Apply guided facts before any stage that should consume them.

4. CLASS: PARTIAL CLASSIFIER REPAIR ON A NON-CANONICAL PATH  
Severity: HIGH

I-12 cites `remote/leak.py`, but the canonical profiler does not use it. It calls `delivery.classify_address` ([profile_stage.py:174](/srv/share/dev/supwngo/supwngo/exploit/pipeline/profile_stage.py:174)), whose active implementation still labels the entire overlapping `0x55…–0x5f…` region as PIE ([delivery.py:322](/srv/share/dev/supwngo/supwngo/exploit/pipeline/delivery.py:322)). `AutoLeakFinder` has another independent overlapping-range classifier ([auto_leak.py:339](/srv/share/dev/supwngo/supwngo/exploit/auto_leak.py:339)). The active PIE helper can then assign a symbol using only matching low page bits ([rop_techniques.py:119](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:119)).

Failure scenario: Tests around `remote.LeakExploiter` reject a heap pointer and Sprint 0 passes, while canonical profiling still stores that pointer as PIE and a page-offset coincidence derives a false base.

Fix: Enumerate and replace all canonical and legacy classification paths, or route them through one typed API. The exit needs paired canonical-path controls: a correctly attributed code pointer must be accepted and consumed, while a same-range heap pointer must be rejected. “Reject the heap pointer” alone can be satisfied by rejecting every pointer.

5. CLASS: EXECUTOR ABLATION MASQUERADING AS PRIMITIVE ABLATION  
Severity: CRITICAL

Registry exclusion closes cross-executor substitution, such as `ret2libc_leak` standing in for `ret2win`, but it does not prove a mechanism within an executor. `SropExecutor` contains both the read-return branch and the `pop rax` branch ([rop_techniques.py:829](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:829)); both report the same technique name, `srop`.

Failure scenario: A “read-return SROP” variant contains a usable `pop rax`. The executor succeeds through that easier route, attribution says `srop`, and removing the entire SROP executor turns the class red. Every v2 reducer condition passes even though read-return support is absent.

Fix: Record a stable mechanism/route identifier such as `srop/read_return_wrapper`, and ablate that sub-route while leaving other SROP routes enabled. Each ablation requires a same-driver intact arm first; if intact is not green, report `NOT_MEASURABLE`. This is already the repository’s established ablation discipline ([CORPUS1-ABLATION:52](/srv/share/dev/supwngo/docs/reports/CORPUS1-ABLATION-24SEP2026.md:52)).

6. CLASS: ONE-SIDED EXIT ORACLES  
Severity: HIGH

Several exits prove only that something can fail:

- An always-red T-2 reducer satisfies every listed reducer red-proof.
- An I-12 implementation that rejects every leak satisfies the heap-pointer test.
- A scheduler that truncates every technique distinctly satisfies the budget red-proof and can produce a “complete” report.
- Sprint 3’s partial syscall trace can pass without exploitation, as above.

Failure scenario: Sprints 0, 1, and 3 all meet their formal exits while the reducer cannot recognize a valid class, no valid PIE leak is accepted, no technique completes, and Sick ROP does not solve.

Fix: Add paired GREEN controls to every gate. For T-2, run a synthetic exact census that is green intact, red only under the intended route ablation, and leaves an unrelated class green. For I-12, accept a provenance-correct code pointer. For budgets, require at least one bounded technique to complete normally and one to be truncated.

7. CLASS: CONJUNCTIVE-GATE ARITHMETIC COLLAPSED INTO ONE SEAT COUNT  
Severity: HIGH

“Two seats” is not the honest current state. The correct ledgers are:

- T-1′: one held seat (`rocket_blaster_xxx`), one high-confidence but unimplemented candidate (`sick_rop`).
- T-2: zero held classes, because the reducer, census, variants, and sealed acceptance results do not exist.

Rocket’s T-1 mechanism is `ret2libc_leak`, while its proposed class was ret2win-with-arguments; therefore even the sole held HTB seat cannot yet be carried into the T-2 ledger.

Failure scenario: Stakeholders read “2 seats” as progress toward both required 5/7 gates, while T-2 remains 0/7 and Sick ROP has only passed an intermediate trace.

Fix: Maintain separate T-1 and T-2 tables with `held`, `candidate`, and `undetermined` states. A seat becomes held only after its own gate’s reliability threshold passes. The decision that three additional HTB routes are presently undetermined is otherwise correct; the available evidence does not justify naming them as held.

8. CLASS: GOAL-ABANDONING DECISION BRANCH  
Severity: CRITICAL

The feasibility uncertainty is honest, but the proposed response is not a path to the user’s fixed goal. V2 says that fewer than three GO routes should cause T-1′ to be revised downward ([plan-v2.md:353](/srv/share/dev/supwngo/docs/plans/2026-09-27-path-to-5of7-plan-v2.md:353)). That changes the requested acceptance criterion rather than satisfying it.

Failure scenario: Sprints 0–3 and all five spikes complete successfully as written; only two routes are GO. The plan then lowers T-1′ and ends below both requested gates. Every scheduled sprint succeeded, but the project goal did not.

Fix: Present Sprints 0–2 as a feasibility phase, not the complete “Path to 5/7.” Its continuation rule must be: implement the best three demonstrated routes; if fewer than three exist, expand the route search or report the fixed goal blocked and request user direction. Changing either 5/7 gate requires explicit user authorization.

9. CLASS: PROSE-ONLY SPIKE EVIDENCE AND OVER-RIGID CHAIN TEMPLATE  
Severity: HIGH

Sprint 2’s formal exit requires only a written four-fact record; it does not require the claimed manual exploit to run. It also says any route missing any of the four facts is NO-GO, even though non-PIE routes such as Snow Scan and Ancient Interface may legitimately require no disclosure or derived image base. Ancient Interface additionally has no hidden “win target” in its shipped source; it has a command dispatch table ([ancient_interface.c:47](/srv/share/dev/supwngo/tests/htb-targets/a12c7393-371d-449e-b43d-b1e55dd9d35f/challenge/ancient_interface.c:47)) and a signal-sensitive read path ([ancient_interface.c:214](/srv/share/dev/supwngo/tests/htb-targets/a12c7393-371d-449e-b43d-b1e55dd9d35f/challenge/ancient_interface.c:214)). Searching for a win function is the wrong terminal question.

Failure scenario: A plausible four-fact narrative is marked GO although its hand exploit never works, or a viable non-PIE route is marked NO-GO solely because it has no unnecessary base leak.

Fix: A GO must include a reproducible reference exploit, target hash, observed primitive trace, and attributed shell/flag result. Permit explicitly justified `N/A` facts. Ask for the terminal control action appropriate to the route—saved return, function pointer, environment/PATH corruption, or equivalent—not universally a win target.

**VERDICT: NOT-APPROVED**