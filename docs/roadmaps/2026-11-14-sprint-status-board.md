# supwngo — sprint-status board (living, 2026-11-14)

**What this is.** The living execution-status companion to the canonical roadmap. The roadmap
(`docs/roadmaps/2026-11-12-mythos-roadmap.md`, "Mythos 5-2") owns *what* the sprints are and *why*;
this board owns *where each one stands right now*. It is updated as work lands. It does **not**
restate the sprint definitions — it references them by ID (SP-01 … SP-16, W-0 … W-6).

**Anchor (the most-recent authoritative planning).**
- **Master sprint map:** the Mythos 5-2 roadmap (2026-11-12), which "supersedes `ROADMAP.md` for sequencing."
- **As amended in roadmap §14 by:**
  - **Owner directive F (2026-11-12)** — focus on three strategies until bulletproof; **overrides §5–§7 sequencing**;
    **freezes SP-07 → SP-16** until gate F is met.
  - **Owner directive W (2026-11-13), AMD-19 … 22** — no hardcoded target values; **pulls SP-04b forward** to run
    immediately after SP-01b, before SP-02, and expands it into the W-0 … W-6 lane.
- **Active detail:** the directive-W plan (`docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md`, §4 = the
  W-phase breakdown) and the W-1 / W-2 designs (`2026-11-13-w1-payoff-ranker-design.md`,
  `2026-11-13-w2-required-args-design.md`, Rev 11 ACCEPTED).
- **Superseded / done:** every pre-12NOV plan — the September roadmaps (`CUTTING_EDGE_ROADMAP.md`,
  `IMPLEMENTATION_PLAN*.md`, `QUICK_WINS.md`) and the 11NOV retest S-sprints (S1–S5, done; S6 re-scoped into SP-02;
  RT-09/RT-10 dropped-as-drafted). These are not forward-planning inputs.

---

## A. What "the full sprint map" covers — and what it deliberately does not

The commitment horizon commits **only M0 and M1** (M2 planned; M3/M4 are options re-decided at the M1 exit —
DEC-26). On top of that, **directive F freezes SP-07 → SP-16** until gate F is met. So the roadmap leaves
SP-07 → SP-16 as table-rows **by design**, not by omission, and the only sprint slices allowed before gate F are
the directive-F focus path (roadmap §14, "The focus path"):

> SP-01 · SP-02a · SP-02b · SP-02c · SP-03A · SP-03 (to F.decompile + PE-load depth) · SP-04a · **SP-04b** · SP-05
> (three focus strategies only) · SP-06 (focus suite only).

Therefore **"complete the full sprint map" = finalize the active focus path at status level** and keep SP-07 → SP-16
as the frozen, uncommitted rows they are meant to be. Writing §6-style detail for SP-07 → SP-16 now would contradict
directive F and the commitment horizon, so this board does not.

The three focus strategies (directive F): **F-1 ret2win** (incl. supplied-component `--win/--winfun/--ret2/--eip`),
**F-2 ret2libc** (leak → libc base → `system`, incl. supplied libc + manual addresses), **F-3 syscall ROP**
(`srop` / `rop_syscall`). Gate F (roadmap §14) is the pre-merge regression gate they must all pass.

---

## B. Focus-path status board

Legend: ✅ merged · 🚧 in flight · ⬜ not started · 🔒 frozen (directive F). "Exit" = roadmap §5 / §14 criterion;
**PENDING-M** = requires the deferred fresh measurement (§E).

| Sprint / phase | What | Status | Evidence | Exit-criterion state |
|---|---|---|---|---|
| **SP-01a** | Isolated passcard v0, truth, mutants, S0 baseline | ✅ | PRs #30 #31 #32 #34 #36; pre-fix baseline `0326912`/`7f22c21` | Met: baseline committed, mutant table caught, answer-key shim denied |
| **SP-01b** | Honesty fixes (`offset`/`decompile` ROBUST, PID reaping, RELRO, lint) | ✅ | PR #37; post-fix passcard baseline `10272bf` | Met at merge; re-confirm scored surfaces under PENDING-M |
| directive-W plan | Retire hardcoded target values (SP-04b breakdown) | ✅ | PR #35 | Plan ACCEPTED (Daybreak Blue r4) |
| **W-0** | Inventory manifest, payoff corpus v0 + truth, reusable sandboxed runner, twin harness, `check_htb_rescore.py` | ✅ | PR #38; exec log in W-plan §10 (`a0f5fc9` etc.) | Met: inventory red-gates live; corpus 32 pos + 32 twins + 8 neg + 8 PE |
| **W-1** | Static payoff evidence, ranking, cache (`payoff.py` + Ghidra script) | ✅ | PR #39 (`a1cae7f` … `ed38d8e`) | Met at merge; re-confirm top-1 on corpus under PENDING-M |
| **W-2** | Required-args / constants from the binary (class B) | 🚧 | `feat/w2-required-args` @ `e6dc1fe`; design **Rev 11 ACCEPTED**; steps 1–5 committed | Steps 6–7 (ret2win rewire + docs/gate/PR) pending; **gate unverified (load)** |
| **W-3** | Success detection (class C); planted-marker oracle; platform-token lint | ⬜ | — | Not started |
| **W-4** | Dynamic confirmation (gdb-in-sandbox receipts) | ⬜ | — | Not started |
| **W-5** | Migrate class A/A′ consumers to `payoff.py`; delete the name lists; scripts take payoff as input | ⬜ | — | Not started — **this is where W-1/W-2 reach the scored CLI surfaces** |
| **W-6** | Regression gate (held set, `check_htb_rescore` 7/7 21/21, passcard S0 delta) | ⬜ | — | Not started |
| **SP-02a/b/c** | KnownFacts + overrides; SROP/`rop_syscall` evidence + honest non-executing `template`; T0-mini + tag 2.2.0 | ⬜ | — | After the W-lane (AMD-19) |
| **SP-03A** | Ghidra feasibility gate (spike) | ⬜ | — | After SP-02c |
| **SP-03** | Facts v1 (minimal), to F.decompile + PE-load depth | ⬜ | — | After SP-03A |
| **SP-04a** | Static distance, static-first `offset`, benchmark breakpoint truth | ⬜ | — | After SP-03 |
| **SP-05** | Plan v1 + honest templates, **three focus strategies only** | ⬜ | — | After SP-04 |
| **SP-06** | Generator v1 + held-out report, **focus suite only** | ⬜ | — | Parallel from SP-02c |
| **gate F** | Bulletproof regression gate for F-1/F-2/F-3 (roadmap §14) | ⬜ | — | Becomes a pre-merge gate once met |
| **SP-07 … SP-16** | Contract, non-stack classes, verification, deletion, LLM hooks, PE hardening | 🔒 | — | Frozen by directive F; uncommitted (DEC-26). Not detailed by design |

---

## C. SP-04b ↔ W-0 … W-6 mapping (durable)

AMD-19 pulls SP-04b forward and expands its one-line §5 scope ("payoff tiers; top-1 ≥ 90%, identical after rename,
0 file-copy decoys top-1") into the W-plan. The mapping:

| SP-04b concern | W-phase | Done-when (W-plan §4) |
|---|---|---|
| Seeded payoff corpus + dev/held split; reusable sandboxed runner; evidence cache + budgets; inventory denominator | **W-0** ✅ | Inventory red on any unclassified hit / stale `open`; corpus 32+32+8+8 with truth |
| Static payoff evidence, ranking, cache (the "payoff tiers") | **W-1** ✅ | top-1 = truth RVA on 32/32 pos, 16/16 rename, 16/16 strip, **no abstention**; decoys 0/32; neg 8/8 no candidate; PE 8/8; 2nd call 0 Ghidra |
| Guessed comparison constants → required-args from the binary (class B) | **W-2** 🚧 | `required_args` = truth on 16/16 arg-checked pos w/ parameter-slice provenance; decoys `args: unknown` 32/32; class-B entries all `migrated`/`allowed` |
| Success-detection markers (class C) | **W-3** ⬜ | class-C entries `migrated`/`allowed`; marker oracle pos-pass / echo-decoy-fail; platform-token lint clean |
| Dynamic confirmation tier for payoff functions (absorbed from SP-07) | **W-4** ⬜ | receipts 32/32 runnable pos; 0 on decoys (0/96) + neg (0/8); 0 survivors / 0 stray writes |
| Migrate class A/A′ consumers; delete lists; scripts require payoff as input | **W-5** ⬜ | class-A/A′ entries `migrated`, scan clean; per-consumer seam test; 4/4 planted name-lookup mutants killed; `pwn`/`solve`/`template`/`explain` give truth RVA on 16 rename-twins |
| Regression gate | **W-6** ⬜ | held top-1 ≥ 15/16; `check_htb_rescore` 7/7 21/21 0-timeout within budget; full suite no new genuine failures; passcard S0 delta reported |

---

## D. Scorecard & capability measurement (deferred — PENDING-M)

**Why the current scorecard is stale.** Roadmap §0/§1.6 "Today" is measured at `1741b34`. AMD-1 already corrects it
(offset 2/3 valid stack cells, no crash; decompile 5/7; method 2/7 and constant `ret2system` template 7/7 reproduce;
ROBUST 28/28 single-doc but 28/28 exit-0 including failures) and says the committed passcard baseline replaces those
numbers. The **post-SP-01b passcard baseline** (`10272bf`) is the newest committed live baseline.

**Key reconciliation fact.** W-1 (payoff ranking) and W-2 (required-args) add *new capabilities* that are **not yet
consumed by the scored CLI commands** — consumer migration is **W-5**. So a fresh passcard run of the scored surfaces
(`method` / `offset` / `decompile` / `template`) is expected to ≈ the post-SP-01b baseline until W-5 lands; the new
W-lane capability has to be measured on its **own payoff corpus**, not (yet) through `pwn`/`template`.

**Why measurement is deferred, not merely delayed.** Host load is ~30 (1-min). Roadmap §1.2 TIME: *"Cells above the
load threshold are invalid,"* with a 20-valid-cold / 20-valid-warm quorum; §1.6 requires a "quiet host." A passcard
run now would be **methodologically invalid**, and (observed this session) the always-run suite's SQLite
`executescript` stalls under this load. Measurement waits for a quiet host — per the owner's "reconcile now, measure
later" decision and the roadmap's own rules.

### Pass-2 measurement plan (run when the host is quiet)

Gate: 1-min load comfortably below the host core count **and** the passcard's own recorded load-threshold check
passes; otherwise mark the run invalid and retry.

1. **Scored S0 + T0 surfaces (passcard).** Re-run `benchmark/passcard.py` on S0 (and T0-mini where built); record
   method R0, OFF-S, DECOMP, ROBUST, template honesty, with load average per cell. Diff against `10272bf`. Confirms
   SP-01b held and sets the live baseline the focus-path exit criteria are deltas on.
2. **W-lane capability (payoff corpus v0).** Run the W-1 ranker over the 32 positives + 32 twins + 8 negatives + 8 PE:
   top-1 = truth RVA, decoys 0/32, negatives no-candidate, PE 8/8, warm call spawns 0 Ghidra. Run the W-2 extractor
   (Ghidra gate `SUPWNGO_REQUIRE_GHIDRA=1`): `required_args` = truth on the 16 arg-checked positives, decoys
   `args: unknown`. This is the "check supwngo capes" measurement for the pulled-forward SP-04b.
3. **PASS-criteria spot check (owner's a/b bars), ELF + PE.** On the F-1 ret2win S0 target(s): method emitted, offset
   visible, decompile across ELF/exe, and the supplied-component path (a) or template path (b). Record gaps against
   gate-F rows F.method / F.offset / F.decompile / F.component / F.template / F.smoke.

Fill these numbers into this board (§B/§C exit columns) and append the S0 delta to the roadmap as a §14 record. Then
iterate: each measured gap feeds the next focus-path slice.

---

## E. Next active work item

**W-2 steps 6–7** (ret2win rewire in `stack_techniques.py` per design §5.4; docs/CHANGELOG; full gate under
`SUPWNGO_REQUIRE_GHIDRA=1`; push; draft PR incl. parent-plan amendments), gated on a quiet host for the gate run —
then merge with worktree/branch cleanup. After W-2: **W-3 → W-4 → W-5 → W-6**, then **SP-02 → SP-03A → SP-03 →
SP-04a → SP-05 → SP-06 → gate F**. SP-07 → SP-16 stay frozen.

Open reconciliation item before W-2 merge: cross-check claude-mem #65889 ("w2-required-args code review: 9 major
defects") against the Rev-11 design and the committed steps 1–5.
