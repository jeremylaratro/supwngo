# Path to 5/7 — HTB challenges and their challenge-alike variations

**Date:** 2026-09-27
**Status:** **SUPERSEDED — NOT-APPROVED at peer review R1. Do not implement from this
document.** Retained unchanged as the reviewed artifact of record.

> **Why it was superseded rather than revised.** Review R1
> ([Daybreak Blue](2026-09-27-5of7-plan-review-r1-daybreak.md)) returned 4 CRITICAL
> findings. I verified the four that assert this plan is *factually wrong* rather
> than merely weak, by reading the cited code. **All four are confirmed.** Two of
> them are fatal to this document's structure:
>
> - **GAP-R did not exist as a gap.** `SropExecutor` already implements the
>   read-return `rax` route (`rop_techniques.py:794-800, 830-833, 905`). This plan's
>   single highest-confidence new seat was a capability that was already built and
>   merely miscomposed. G-4 is refiled as a bug, with an erratum, in the work queue.
> - **The central premise is unfounded.** This plan inferred, from "every unsolved
>   target has PIE and/or a canary", that protection defeat is the binding blocker.
>   That is a correlation, not a diagnosis. Sabotage ships **glibc 2.35** (verified),
>   where the `__free_hook` target this plan assumed does not exist; Bonnie's
>   create operation does not match the schema the generic script sends; Auth uses a
>   custom stack-arena allocator. Removing PIE from all three would not produce the
>   primitives they actually lack.
>
> Patching a plan whose premise is wrong produces a plan that is still wrong, so
> rounds 2 and 3 were not spent on it. Two defects the review surfaced were in no
> queue at all and are now filed as **I-11** and **I-12**.
>
> **Live plan: [2026-09-27-path-to-5of7-plan-v2.md](2026-09-27-path-to-5of7-plan-v2.md).**

**Original status line:** PLAN — not approved, not started. Awaiting peer review then sign-off.
**Directive (user, 2026-09-27):** "create an actionable plan to generate viable,
generalizable strategies that will bring those numbers up to at least 5/7 solves
for both." Scope clarified by the user: **HTB ≥5/7 AND challenge-variations ≥5/7.**

The second half is the load-bearing half. A capability that solves the exact
upstream binary and nothing shaped like it is not counted as done.

---

## 1. Definition of done

| gate | condition |
|---|---|
| **T-1′** | canonical solves **≥5 of 7** HTB challenges, no `--libc`, no legacy fallback, ≥2 of 3 reps each |
| **T-2** | canonical solves **≥5 of 7** challenge-alike classes, each class varied per §6, through `run_bench.py`'s attribution |

Both measured on the harnesses already built and validated:
`scripts/htb_rescore.py` (positive + negative control passed, `6b1da1f`) and
`benchmark/run_bench.py`.

---

## 2. Measured baseline (2026-09-27, run `20260927-142133Z`)

Protections cross-checked two ways — `readelf` and `Binary.load(...).protections`
— and they agree exactly on all seven, with `protections_measured=True` throughout.
(My first attempt read all-False because I constructed `Binary(path)` directly
instead of using the `Binary.load()` factory at `binary.py:175`, which is what runs
`_detect_protections()`. The class already carries a `protections_measured` flag for
exactly this confusion; I should have read it. The reader is sound and Sprint B can
rely on it.)

| target | PIE | canary | NX | RELRO | link | verdict | binding blocker |
|---|---|---|---|---|---|---|---|
| `rocket_blaster_xxx` | no | **no** | yes | full | dyn | **SOLVED** 3/3 `ret2libc_leak` SHELL_ACCESS 18.7s | — |
| `sick_rop` | no | no | yes | none | **static** | NOT_SOLVED 149s | **GAP-R** |
| `ancient_interface` | no | yes | yes | partial | dyn | **INCONCLUSIVE** — timeout at 300s ×3 **and at 1100s** | **GAP-B**, **GAP-Y** |
| `snow_scan` | no | yes | yes | partial | dyn | NOT_SOLVED 19s | **GAP-C** (B-3) |
| `auth-or-out` | **yes** | yes | yes | **full** | dyn | INCONCLUSIVE — timeout ×3 | **GAP-P**, **GAP-A** |
| `bon-nie-appetit` | **yes** | yes | yes | **full** | dyn | NOT_SOLVED 3.5s | **GAP-P**, **GAP-D**, **GAP-H** |
| `sabotage` | **yes** | yes | yes | **full** | dyn | NOT_SOLVED 6.0s | **GAP-P**, **GAP-D**, **GAP-H** |

**The single solve is the only target with neither PIE nor a canary.** That is the
explanation, not a coincidence, and it says the blockers are protection-defeat
primitives rather than technique coverage.

---

## 3. What already exists on disk (Phase-4 research, done before proposing anything)

Checked because "the engine cannot leak" is exactly the claim a narrow read gets
wrong. It has substantial leak machinery:

| component | what it does | why it does not close GAP-P |
|---|---|---|
| `exploit/pipeline/leak_stage.py:37` `acquire_leaks` | promotes `leaks['stack'/'libc'/'pie']` from profiling; drives `AutoLeakFinder`'s puts/GOT-ROP path | **returns at line 51 if a libc leak exists**, and the active path targets **libc only**. No code path ever *acquires* `leaks['pie']` — it is only promoted if dynamic profiling happened to find one |
| `leak_stage.py:80` `_send` | `subprocess.run(input=payload+b"\n")`, read all output | **single-shot, stdin-only**. Cannot conduct a multi-step menu dialogue, which is how every one of these targets discloses a pointer |
| `exploit/auto_leak.py` `AutoLeakFinder.auto_leak_libc` | GOT-ROP leak against a local binary | libc base, not image base; assumes a stack-smash offset |
| `remote/leak.py` | `leak_with_format_string`, `leak_with_puts`, `identify_leak_type`, `parse_leak_output` | real primitives, but **not wired into the canonical pipeline's PIE path** |
| `exploit/primitives.py` | `leak_address`, `leak_stack`, `leak_address_at_offset` | ditto |

**Conclusion that shapes the plan:** the missing thing is not leak *primitives*. It
is (a) an *image-base* consumer of them and (b) an I/O layer that can hold a
conversation. That makes GAP-P much cheaper than it looks, and it means the work is
mostly wiring plus one new dialogue abstraction — not a new exploitation technique.

---

## 4. Root-cause taxonomy, with leverage

Leverage = how many of the 6 unsolved targets the gap gates. Ordered by it.

| id | gap | leverage | evidence (all `measured` 2026-09-27) |
|---|---|---|---|
| **GAP-P** | no active **PIE image-base** leak acquisition | **3** (`auth-or-out`, `bon-nie-appetit`, `sabotage`) | `srop`: "PIE enabled — need image-base leak first"; `ret2libc_leak`: "target is PIE but printed no code pointer… a separate PIE-defeating leak primitive would be needed first"; `ret2plt`: "PIE enabled — PLT addresses are relative"; `leak_stage.py:51` |
| **GAP-D** | no **multi-step dialogue** with a target; I/O is one-shot stdin | **3** (same three, plus helps `ancient_interface`) | `leak_stage.py:80`; `uaf`/`double_free`: "generic UAF/double-free sequence did not confirm against this menu layout" |
| **GAP-H** | heap techniques target the **GOT**, which is read-only under Full RELRO | **3** | `tcache_poison_got`: "PIE enabled (GOT addresses not fixed)" — but RELRO is **full** on all three, so the technique fails even after GAP-P. The reported blocker is not the binding one |
| **GAP-R** | SROP cannot use a **syscall return value** as a register primitive | **1** (`sick_rop`) | filed as **G-4**. 26 instructions, no `pop rax`; `rax=15` only reachable via `read`'s return |
| **GAP-B** | no **search-budget discipline**; the sweep does not terminate | **2** (`ancient_interface`, `auth-or-out`) | both timed out 3/3 at 300s; `ancient_interface` also at **1100s**, 70% CPU, one process spawn per attempt |
| **GAP-Y** | no **stripped-binary** strategy | **1** (`ancient_interface`) | `objdump -t` yields **no local function symbols**; win-function discovery is name-based |
| **GAP-C** | no **format/container envelope** for payload delivery | **1** (`snow_scan`) | existing **B-3**, deferred |
| **GAP-A** | no **custom-allocator** model | **1** (`auth-or-out`) | ships `ta_alloc`/`ta_free`/`ta_check`/`compact`/`insert_block` — not glibc |

Two gaps carry most of the value: **GAP-P and GAP-D together gate three targets**,
and GAP-H must land with them or those three still fail.

---

## 5. Strategy: capability-first, three sprints

Deliberately **not** target-by-target. A per-target fix is how an engine becomes
tuned to a fixture, which T-2 exists to catch.

### Sprint A — the conversational I/O layer (GAP-D)

**Problem.** Every remaining target is menu-driven or multi-stage. The pipeline can
send one blob and read the result. It cannot do *send → read → decide → send*.

**Method 1 (chosen): a `Dialogue` transport abstraction.** A small object owning a
live `subprocess`/tube with `send`, `recv_until`, `expect`, and a transcript. The
existing `DeliverySpec` chooses *where* bytes go; `Dialogue` governs *when*. Sinks
stay unchanged, so the ingress work already committed is reused rather than
reworked.

**Method 2 (rejected): extend `_send` to take a list of payloads.** Cheaper, ~20
lines. Rejected because a fixed script cannot branch on what the target said, and
menu indices differ per target — it would encode *this* menu, producing exactly the
fixture-tuning T-2 rejects. **What would flip it:** if menu discovery turned out to
yield a stable index map for every target, a scripted sequence would suffice.

**Sub-components.** `pipeline/dialogue.py` (new); `leak_stage._send` reimplemented
over it; heap executors given the transcript; `verifier` records the transcript in
the receipt so a solve is replayable.

**Exit.** A heap executor can drive a menu it discovered at runtime, and the
transcript is in the receipt.

### Sprint B — image-base recovery (GAP-P) + non-GOT write targets (GAP-H)

**Problem.** Three targets are PIE + Full RELRO. Nothing acquires an image base, and
the one heap write-target on offer (GOT) is read-only on all three.

**Method 1 (chosen): an output-path leak scan, then a hook/stack write target.**
Use the target's own display actions — discovered via Sprint A — to disclose a
pointer, classify it with the existing `remote/leak.py:identify_leak_type`, and
compute the image base. Then retarget tcache poisoning from GOT to libc hooks or a
saved return address, selected by measured RELRO rather than assumed.

**Method 2 (rejected): brute-force the image base.** No leak needed, but ASLR makes
it ~2^28 with a process spawn per try — and GAP-B says the engine already cannot
finish bounded sweeps. **What would flip it:** a target with a partial-overwrite
path needing only low bits.

**Exit.** `leaks['pie']` is actively acquired on at least one PIE target, and a
write-target selector prefers a writable destination over the GOT when RELRO is full.

### Sprint C — the narrow, high-confidence one (GAP-R) + budget discipline (GAP-B)

**Problem.** `sick_rop` needs `rax=15` from `read`'s return value. Separately, two
targets never terminate.

**Method 1 (chosen): a "syscall return as register primitive" step in the SROP
planner**, plus a global attempt budget with an honest INCOMPLETE outcome.

**Method 2 (rejected for GAP-R): hardcode the `sick_rop` recipe.** Would score a
solve this week. Rejected — it is the definition of fixture-tuning, and T-2 would
catch it. **What would flip it:** nothing; this one is a principle.

**Exit.** `sick_rop` solves, and a sweep that cannot finish reports INCOMPLETE with
counts rather than timing out.

---

## 6. Generalization obligations (T-2) — how each capability is proven not tuned

One challenge-alike class per HTB class, each **varied** per the user's design —
same mechanism, different binaries. A capability counts only if it solves the
variants too, not just the fixed point.

| class | fixed point | variations that must also solve |
|---|---|---|
| ret2win w/ args | `rocket_blaster_xxx`-alike | win name in the 21-name list / outside it / decoy name; arity 0, 1, 3 |
| SROP via syscall return | `sick_rop`-alike | `read` length 0x100/0x300; offset 40/56; `rax` set via `read` vs via `write` return |
| menu heap, PIE+Full RELRO | `bon-nie-appetit`-alike | menu order permuted; 3 vs 5 actions; tcache vs fastbin sizes; hook vs return-address target |
| menu heap + `system` | `sabotage`-alike | `system` present vs absent; env-var path vs direct |
| custom allocator | `auth-or-out`-alike | first-fit vs best-fit; with/without `compact` |
| container/format gate | `snow_scan`-alike | BMP vs WAV carrier (per B-3 revision 2) |
| stripped | `ancient_interface`-alike | stripped vs symbols; same code both ways |

**Pre-validation, per the standing mandate.** Every variant is checked 4 ways
before it is scored: intended payload wins; **wrong-but-present** payload at the
same offset does not; bare negative control produces nothing; and a paired
control differing only in the causal lines flips the verdict. This is the check
that caught a gate value the executor's own `0x41` filler would have satisfied.

---

## 7. Realistic arithmetic, stated honestly

| target | route | confidence |
|---|---|---|
| `rocket_blaster_xxx` | have it | **done** |
| `sick_rop` | GAP-R | **high** — cause fully understood, one primitive |
| `bon-nie-appetit` | Sprints A+B | **medium** — textbook shape once PIE+RELRO handled |
| `sabotage` | Sprints A+B | **medium** — `scanf_canary_bypass` already generates a script and fails only at menu-probe confirmation |
| **5th seat** | `snow_scan` (GAP-C/B-3) *or* `ancient_interface` (GAP-Y+B) | **low–medium** for either |
| `auth-or-out` | GAP-A, custom allocator | **low** — deliberately not on the path |

That is 4 confident-to-medium plus a contested fifth seat. **5/7 is achievable but
not comfortable**, and I am not going to claim otherwise. If Sprints A+B deliver
both PIE targets, the fifth seat decides the gate, and `snow_scan` is the better
bet because B-3 already has a design (`WAV` as carriage proof) whereas
`ancient_interface` needs two new gaps closed at once.

**If the gate misses at 4/7, that is the reportable result** — with the per-target
cause — not a reason to relax the definition or re-cut the denominator.

---

## 8. New items this analysis produced

| id | item | priority |
|---|---|---|
| **I-10** | `tcache_poison_got` reports PIE as its blocker while **Full RELRO** is the binding one on all three PIE targets, so the message misdirects: closing GAP-P alone would not make the technique work. Same class as I-9 — a reason that names a real constraint while a more fundamental one goes unmentioned | P2 |
| **GAP-P/D/H/B/Y/A** | filed per §4 | per §4 |

An earlier draft of this section filed a P1 claiming `Binary.protections` was broken.
That was **my** error, not a defect — see §2. Recorded here rather than silently
deleted, because the retraction is the useful part: the class already exposes
`protections_measured` precisely so "never measured" cannot be mistaken for
"measured and all False", and I read the values without reading the flag.

---

## 9. Test plan and pre-registered benefit metric

- **Baseline, measured before any code changes:** HTB **1/7** (`20260927-142133Z`);
  challenge-variations **not yet measured** — the corpus does not exist, so the T-2
  baseline is established by building and running it *before* Sprints A–C, not after.
- **Regression:** M-1a per target (13/13 eligible @ 5/5) and the ingress corpus
  (5/5 transports, `90` FAILED / `91` SUCCESS) after every sprint.
- **Full suite:** current `1315 passed, 16 skipped, 14 deselected`.
- **Red-proof per new gate**, mutating to wrong-but-present, never absence-only.
- **Rollback:** one branch per sprint; each independently revertable.

## 10. Order of work, and what I need from you

1. Peer-review this plan (Daybreak Blue, cyber, xhigh) — not yet done.
2. Build and baseline the T-2 variation corpus *before* the sprints, so the
   generalization metric has a pre-change baseline rather than a retrofitted one.
3. Sprint A (dialogue), then B (image base + non-GOT targets), then C (GAP-R + budget).
4. Re-score both gates; report per target.

Nothing starts until sign-off.
