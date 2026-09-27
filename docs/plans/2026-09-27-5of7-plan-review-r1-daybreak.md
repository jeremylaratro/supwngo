# Peer review R1 — `2026-09-27-path-to-5of7-plan.md`

| field | value |
|---|---|
| reviewer | Daybreak Blue (`gpt-daybreak-blue-latest`), `model_reasoning_effort=xhigh`, `--sandbox read-only` |
| subject | `docs/plans/2026-09-27-path-to-5of7-plan.md` (draft, never committed in the reviewed form) |
| round | 1 of a maximum 3 |
| verdict | **NOT-APPROVED** — 4 CRITICAL, 4 HIGH |
| date | 2026-09-27 |
| delivery | non-interactive file handoff, `--output-last-message`, polled to size-stability |

**Disposition, recorded 2026-09-27 by the maintainer of the plan (me).** I
independently verified the four findings that assert the plan is *factually wrong*
rather than merely weak, by reading the cited code rather than accepting the cites.
**All four are confirmed**, and two of them name defects that were not filed
anywhere:

| finding | verification | outcome |
|---|---|---|
| 4 — GAP-R already implemented | `rop_techniques.py:794-800` sets `use_read_for_rax`; `:830-833` dispatches; `:905` defines `_script_read_rax`; chain is `p64(read_addr) + p64(syscall_gadget) + bytes(frame)`, so the stack-arg wrapper reads `rsi`/`rdx` from the zeroed head of the frame → `read(0,0,0)` | **CONFIRMED.** G-4 refiled as a bug with an erratum |
| 3 — glibc hook claim | `bon-nie-appetit` ships **2.27**, `sabotage` ships **2.35** (`strings` on each target's bundled `glibc/libc.so.6`). Hooks were removed in 2.34 | **CONFIRMED** |
| 6 — leak contract mismatch | `core/context.py:360` gates on `leaks["binary_base"]`; `orchestrator.py:560` writes `leaks["pie"]` — different keys | **CONFIRMED**, newly filed as I-11 |
| 6 — leak misclassification | `remote/leak.py:194-195` returns `"binary"` for all of `0x55…`, which is also where a PIE process's heap is mapped; the `"heap"` branch only covers `< 0x100000000` | **CONFIRMED**, newly filed as I-12 |

One cite is imprecise without weakening its finding: finding 2's `run_bench.py:1083`
falls inside a docstring that *already* reports two numbers (`solved` = credited in
≥1 rep, `reliability` = k/N) and explicitly warns that "reporting best-of-N without
reliability would be gaming the metric." The harness is therefore not naively
one-rep-`SUCCESS`. The substantive finding survives intact and is in fact sharper
than the cite: the plan's §6 never committed to **which of the two numbers T-2 keys
on**, and keying on `solved` would credit a 1/5 target.

Because all four CRITICALs are confirmed — including the collapse of the plan's
single highest-confidence seat and the unfounding of its central premise that
protection defeat is the binding blocker — this was treated as a **design
escalation, not a revision**. Rounds 2 and 3 were not spent patching the reviewed
structure. See the superseding plan for what replaced it.

---

The plan is not sound enough to implement. Its scheduled work has a best-case ceiling of 4/7, and several supposed blockers are not the binding causes.

1. **CRITICAL — CLASS: Goal arithmetic without a scheduled fifth capability**

   The three sprints only plausibly claim `rocket_blaster_xxx`, `sick_rop`, `bon-nie-appetit`, and `sabotage`. The proposed fifth seat—`snow_scan` or `ancient_interface`—is not implemented by any sprint. Budget discipline does not add a stripped-binary strategy, and Sprint B does not add a container exploit.

   The existing B-3 design explicitly says that solving `snowscan` is not its exit criterion; it only reaches the parser’s memory-unsafe path ([B-3 plan](/srv/share/dev/supwngo/docs/plans/2026-09-26-b3-container-registry-plan.md:61)).

   **Failure scenario:** Sprints A–C meet all their exits; Rocket, Sick ROP, Bonnie, and Sabotage solve; Snow, Ancient, and Auth still fail. Result: HTB 4/7. The analogous four variation classes pass, producing T-2 4/7. The plan finishes exactly as written but misses both stated gates.

   **Fix:** Add a mandatory fourth capability sprint for an end-to-end fifth solve. For Snow this must cover envelope, crash control, exploit primitive, control transfer, and shell/flag—not merely carriage. Alternatively, Ancient needs both protocol driving and stripped-binary semantic target discovery. Do not approve until one is a scheduled, end-to-end route; ideally schedule both as primary/fallback.

2. **CRITICAL — CLASS: Route-agnostic scoring can credit an absent capability**

   `run_bench.py` proves that the target produced the flag, but it does not enforce the manifest’s claimed technique. Its aggregate also treats one successful rep as `SUCCESS` ([run_bench.py](/srv/share/dev/supwngo/benchmark/run_bench.py:1083)). Section 6 supplies no committed class reducer, exact variant census, reliability threshold, or required-technique ablation.

   The Rocket mapping demonstrates the defect: the canonical target was solved by `ret2libc_leak`, while its T-2 class is “ret2win with arguments.” Either:

   - ret2libc solves those variants, so T-2 credits ret2win generalization while ret2win discovery remains absent; or
   - the variants structurally require ret2win, in which case outside-list/decoy discovery is an unscheduled capability.

   **Failure scenario:** A “menu heap” variant also contains an ordinary stack overflow. Existing ret2libc gets a shell. The intended payload wins, wrong payload fails, the target writes the flag, and attribution reports SUCCESS. The heap class counts even though dialogue-based heap exploitation, PIE recovery, and non-GOT writing were never used.

   **Fix:** Implement a fail-closed T-2 reducer requiring an exact class/variant census, every mandatory variant at a stated reliability such as ≥2/3, no VOID or missing legs, and strict behavioral attribution. Each class also needs a capability ablation: disabling/removing the claimed primitive must turn that class red while unrelated techniques remain available. Structurally exclude easier alternate routes where possible.

3. **CRITICAL — CLASS: Mitigations have been mistaken for exploit primitives**

   PIE and Full RELRO are real constraints, but they are not shown to be the binding blockers for the three grouped targets. The inference “all unsolved targets have PIE/canaries, therefore protection defeat is the cause” is not a causal diagnosis.

   The existing tcache executor additionally requires a win function, a UAF-write shape, a particular create/delete/edit schema, and a disclosed chunk address ([heap_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/heap_techniques.py:172)). Those prerequisites are absent from the claimed diagnosis.

   Concrete counterexamples:

   - Bonnie clears its pointer after deletion and its create operation is size/data, whereas the generic script sends index/size. Removing PIE and Full RELRO would not create the required UAF or arbitrary-write primitive.
   - Sabotage’s only `scanf` use is one `%lu` length input. It does not have the repeated floating-point grade array assumed by the generated canary-skip script. Script generation is a detector false positive, not evidence that only menu confirmation remains.
   - Auth uses a custom allocator backed by a stack arena and an application function pointer. A glibc tcache/GOT retarget is not its primitive.
   - A libc hook is potentially relevant to Bonnie’s glibc 2.27, but not a universal Full-RELRO answer. Sabotage ships glibc 2.35, where legacy malloc/free hooks are not an operative generic target; a saved return address additionally requires a stack leak and a usable arbitrary write.

   **Failure scenario:** Sprint A supplies live dialogue and Sprint B recovers a valid PIE base. The target selector chooses `__free_hook` or a saved return address. No executor can corrupt that location or trigger it, so all three targets remain unsolved despite GAP-P/D/H being declared closed.

   **Fix:** Perform a short reference-exploit/root-cause spike per vulnerability class before designing shared infrastructure. For each route, establish four separate facts: disclosure primitive, derived base, corruption primitive, and terminal control target/trigger. Only then merge genuinely shared layers. Recompute leverage from demonstrated chains, not protection flags.

4. **CRITICAL — CLASS: Existing broken capability misclassified as a missing capability**

   GAP-R is factually wrong. The current SROP executor already detects `read`, selects “syscall return as rax,” and generates `_script_read_rax` ([rop_techniques.py](/srv/share/dev/supwngo/supwngo/exploit/pipeline/executors/rop_techniques.py:794)). The baseline was therefore measured after the proposed capability already existed.

   Its generated chain is malformed for `sick_rop`’s wrapper. That wrapper loads `rsi` from `[rsp+8]` and `rdx` from `[rsp+16]`, but the chain is:

   `read_addr, syscall_addr, zero-leading SigreturnFrame`

   Consequently it executes `read(0, 0, 0)`, returns 0 rather than 15, and never invokes `rt_sigreturn` as intended.

   **Failure scenario:** Sprint C adds another “read return sets rax” planner flag without repairing stack arguments and stage transitions. The executor continues generating essentially the same invalid chain; Sick ROP remains unsolved, eliminating the plan’s highest-confidence new seat.

   **Fix:** Reclassify GAP-R as incorrect SROP staging/calling-convention composition. Trace the generated exploit through the actual wrapper ABI and assert the observed syscall sequence, including `read(..., 15) = 15` followed by syscall 15. Repair the multi-stage stack transition and make the real target solve the sprint exit. The proposed write-return variation needs its own implemented and witnessed path rather than being assumed to follow automatically.

5. **HIGH — CLASS: Transport capability confused with protocol understanding**

   A `Dialogue` object provides timing and branching but does not infer what each action asks for. Menu-number discovery already exists; the missing layer is an action schema/state model.

   **Failure scenario:** Runtime parsing correctly maps “Make an order” to create, but the executor assumes `create(index, size, data)` while the target expects `create(size, data)`. Every subsequent answer is shifted by one prompt. The transcript is complete and Sprint A’s transport works, but no exploit or leak action is usable. A simple fixture with the assumed schema can still satisfy Sprint A’s exit.

   **Fix:** Define a typed menu-action representation covering prompt sequence, argument type, optional data body, indexing policy, and state transition. Discover or derive that schema before exploit planning. Test at least two incompatible schemas with permuted option numbers, prompt wording, and argument counts. Sprint A’s exit should require a derived action sequence to perform a stateful leak/corruption operation, not merely record a dialogue.

6. **HIGH — CLASS: Unproven leak classification and disconnected consumption**

   Address-range classification is inadequate for PIE recovery. On amd64, PIE and heap mappings commonly both occupy the `0x55…` range; `identify_leak_type` can therefore label a heap pointer as binary. Page-aligning an arbitrary code pointer also does not yield the image base unless its static offset is accounted for.

   There is also a contract mismatch: `needs_leak()` checks `binary_base`, while the plan and current orchestration use `leaks['pie']`; current executors largely compute bases privately rather than consuming that field.

   **Failure scenario:** A display action prints heap pointer `0x5555…`. It is classified as PIE, stored in `leaks['pie']`, and Sprint B’s leak exit passes. The selected chain rebases gadgets from a heap page and crashes. Alternatively, the correct base is stored but no downstream executor consumes it, so the selector still emits relative addresses.

   **Fix:** Represent leaks as typed values with provenance: source action, semantic object/symbol, static offset, raw bytes, and confidence. Compute `base = leak - known_offset`, validate mapping/page/segment constraints, canonicalize the context key, and explicitly rebase every consumer. Require randomized-ASLR end-to-end tests showing different raw leaks produce correct bases and successful chains; a wrong-but-present pointer must fail the base proof.

7. **HIGH — CLASS: Finite visible fixtures do not establish generalization**

   Section 6 does not specify how many binaries exist, whether listed alternatives are crossed or cherry-picked, compiler/build variations, or a held-out set. All variants are built before implementation and remain visible during development, so the engine can be tuned to the complete acceptance set.

   Several rows also combine distinct mechanisms rather than variations of one capability: tcache versus fastbin, hook versus saved-return targets, and read-return versus write-return SROP. Passing one does not prove the others.

   **Failure scenario:** The implementation recognizes the exact prompt verbs, sizes, offsets, and layouts in the authored corpus. Every published variant passes, including all causal controls, while a newly compiled equivalent with reordered fields or different optimization fails. T-2 reports 5/7 despite fixture tuning.

   **Fix:** Pre-register an exact development matrix and a separately generated, sealed acceptance matrix. Use multiple held-out binaries per counted class, compiler/layout perturbations, and pairwise or full crossing of independent axes. Freeze the engine before revealing the held-out seeds/binaries. Require every mandatory held-out member to meet the reliability threshold. Keep mechanism changes as separate classes or require explicit support for every branch.

8. **HIGH — CLASS: Dependency order permits later infrastructure to hide earlier failure**

   Budget discipline is placed after the two sprints that depend on repeated menu and leak experiments. The T-2 corpus/reducer is also not designed, even though the prior M-1b effort was returned to planning after recurring payload-blind controls.

   **Failure scenario:** Auth or Ancient consumes the 300-second outer timeout in broad sweeps before a newly added dialogue/leak executor can be exercised consistently. Developers tune A/B using partial runs, then Sprint C changes attempt termination and invalidates those observations. Separately, the variation corpus is authored without a sound reducer, so “baseline before changes” records data that cannot support T-2.

   **Fix:** Sequence the work as: committed T-2 contract/reducer and corpus design → global/per-technique budgets → vulnerability-chain spikes → dialogue/action schema → typed leak/rebase consumption → target-specific corruption/terminal primitives → SROP staging repair → mandatory fifth-seat sprint → final dual rescore. A failed root-cause spike should re-plan the affected route before its infrastructure sprint starts.

**VERDICT: NOT-APPROVED**