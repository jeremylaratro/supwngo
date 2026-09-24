# The heap walkthrough family, scoped at detection

Date: 2026-09-24
Branch: `integration/walkthrough-families-consolidated-20260924`
Precedents: `docs/plans/2026-09-24-walkthrough-family-fmtstr.md`,
`docs/plans/2026-09-24-walkthrough-integer-family.md`,
`docs/plans/2026-09-24-walkthrough-families-consolidation.md`

## Note on the spec

The brief points at `docs/plans/2026-09-24-walkthrough-families-fmtstr-heap-integer.md`.
That file does not exist on any ref in this repository — checked with
`git log --all --diff-filter=A --name-only -- docs/plans`. The second wave was
planned per family instead (`…-walkthrough-family-fmtstr.md`,
`…-walkthrough-integer-family.md`), with no combined spec. Scope below is
therefore derived from the brief's own floor/stretch statement plus the two
sibling plans, and the difference is flagged rather than papered over.

## Goal

A `heap` family that says something true and specific about a binary's
allocator, and stops there. The deliverable is **detection and
characterisation**: which allocation and free primitives are reachable from
input, the chunk sizes in play, whether a freed pointer stays reachable (UAF),
whether the allocator is tcache-backed, and whether safe-linking is in effect —
every fact carrying provenance. Plus, in prose, what weaponising the primitive
would require.

Explicitly **not** a claimed shell. `autopwn` already solves
`12_heap_tcache_poison` at 5/5 via `TcachePoisonGotExecutor`; this family is the
explaining layer over code that works, and an overconfident heap walkthrough is
a regression even on the runs where it happens to succeed.

## The central fork: where detection stops being detection

Three options, and the boundary between them is the real decision.

### Option A — characterise only (CHOSEN for the floor)

Steps are measurements the reader runs. The family reports the primitive's
shape, and a closing section names the preconditions weaponisation would need,
pointing at the pipeline executor that does it. No poisoned pointer is ever
computed or sent.

- **For:** cannot overclaim by construction — there is no exploitation payload
  in the artifact to be wrong about. Every claim is backed by a measurement the
  reader just watched. Matches the stated bar exactly.
- **Against:** a reader who wanted 0-to-pwn gets a diagnosis and a pointer, not
  a route. That is a real cost, and it is the one the brief accepts deliberately.

### Option B — characterise, then a guided tcache-poisoning route (STRETCH)

A second route in the same family, gated on every detection fact being PRESENT
rather than UNKNOWN, that computes the mangled pointer and drives the menu — and
whose verdict is **"a controlled address received a controlled value"**, proven
by reading it back through the program's own `show()`, not by a flag search and
not by a shell.

- **For:** teaches the two facts the brief requires to appear in any heap
  exploitation route, and both are the kind of thing only a runnable artifact
  really conveys.
- **Against:** every additional claim is a new way to be wrong, and the failure
  is *silent* — a poisoning sequence that half-works produces plausible output.
  Only attempted if A is solid, and it claims an arbitrary write, never a shell.

### Option C — wrap the working executor's script (NOT TAKEN)

Take `TcachePoisonGotExecutor._script()` — which genuinely lands a shell at 5/5 —
and present it as the walkthrough.

- **Why not:** it would be the most impressive artifact and the least honest one.
  The executor's script is *generated for one target after the pipeline has
  already established the preconditions*; lifting it into a walkthrough presents
  a conclusion as a method. Worse, the two facts the brief insists on
  (`counts[tc_idx] > 0`, and `leave; ret` loading `rbp`) are exactly the
  invariants the executor satisfies incidentally rather than teaches, so the
  reader would copy working code without learning why it works — and would have
  no way to debug it on the next binary.
- **What would flip it:** if the goal were reproducing a solve rather than
  teaching one. It is not.

**Decision: A ships. B is attempted only behind a solid A, and is capped at an
arbitrary-write claim.** What would flip A→B as the floor: a demonstration that
the poisoning route's verdict step can distinguish a real controlled write from
a coincidence on more than one target. One target is an anecdote.

### The line, stated once

> **A route may claim exactly what its own verdict step can prove with a
> differential, and not one step further.**

Detection claims "this primitive exists, here is its shape". The poisoning route,
if it ships, claims "a controlled address received a controlled value". A shell
claim requires the whole chain and that is the executor's job.

## The three-state requirement (design constraint, not polish)

Heap-at-detection is the only family in this wave whose primary output is an
**absence** claim — "no UAF", "not tcache-backed", "the freed pointer is not
reachable". `fmtstr` and `integer` assert presence, so a failed probe there
yields a *missing route*, which is visible. A failed heap probe yields a clean
bill of health, which is invisible and reads as a competent negative result.

So every heap detection fact has three states — **present, absent, not
determined** — and a probe that times out, errors, or exhausts its budget
produces `UNKNOWN` with `resolved_by`, never the absent state.

### This is already enforceable at the data model

`model.Fact` validates that a `Confidence.UNKNOWN` fact carries
`unknown_reason`, `plausible` and `resolved_by`, and carries **no** value; and
that `MEASURED`/`DERIVED` facts carry `Evidence` with a reproducing command. The
machinery exists. What the family must not do is let a probe failure fall through
to a confident negative *before* reaching that machinery.

### Two reusable helpers that must NOT be reused as-is

Verified by reading them, and both are the exact collapse the coordinator
measured on the autopwn side:

1. `heap_techniques.discover_menu()` returns `{}` when the menu is absent **and**
   when `deliver_parts` timed out at its hardcoded `timeout=3.0`. "No menu" and
   "did not finish" are one value. Every heap detection gate downstream of menu
   discovery would inherit that.
2. `heap_techniques.libc_version()` returns `None` for no path given, an
   unreadable file, **and** no version string found. Its caller then does
   `safe_linking = version is None or version >= (2, 32)` — a sane default for an
   executor (it assumes the harder case) but a **fabrication** if a walkthrough
   reports "safe-linking is in effect" as a measured fact. Unreadable libc must
   yield `UNKNOWN`, not an assumption rendered as a measurement.
3. `fmtstr_probe._deliver()` returns `(b"", 0)` on budget exhaustion and kills +
   returns partial output on `TimeoutExpired`. `fmtstr` survives this because its
   facts assert presence; heap would not.

**Therefore:** a new `heap_probe.py` with its own delivery helper returning an
explicit outcome — `COMPLETED` / `TIMED_OUT` / `BUDGET_EXHAUSTED` / `ERROR` —
and an `Observation` tri-state at the probe boundary that cannot be reduced to a
bool. No `if not result:` anywhere in the fact-derivation path.

### Positive control before any absence claim

Absence is only assertable from `COMPLETED` **plus** a positive control proving
the probe could have seen the thing. Concretely: before reporting "no UAF", the
probe must show it drove a create→delete→show cycle that round-tripped. If menu
discovery failed, "no UAF" is NOT_DETERMINED. A negative from a probe that never
demonstrated sensitivity is not a negative.

### Rendering the difference

"No use-after-free was observed" and "the UAF probe did not complete within its
budget" are different sentences and a reader acts differently on each. The
walkthrough must render both, distinctly. A detection walkthrough whose honest
answer is "I could not determine this" is a **success** for this family's bar.

### Proving the not-determined path fires

Patch a probe to hang and to raise, run the family, and show the walkthrough says
so — the same way `fmtstr` marks `FMT_INDEX` UNKNOWN on `probe_arg_index()`
failure and **withholds the `%n` route entirely** rather than guessing. That
withholding behaviour is the pattern to copy. Heap must not reach a weaker
"assume not present" default.

Also: do not pass a timeout flag and assume it took effect. On the autopwn side
`--timeout` does not reach the 8 hardcoded discovery-probe call sites, and a
`min(self.timeout, 2.0)` cap makes it inert above 2s. If heap probing needs a
longer budget, change the call site and say so in the commit.

## Score: 0.25

Between `triage` (0.15) and every route that claims control. Justification from
the ordering recorded in the consolidation note:

- **Above `triage`** because it has measured, binary-specific facts about *this*
  allocator, which is more than the discovery workflow.
- **Below `integer`'s 0.45**, whose rationale states this band's principle —
  *half an exploit should lose to a whole one*. Detection is less than half: it
  proves a primitive's shape without demonstrating control of anything.
- **0.25 specifically**, avoiding 0.30 and 0.35, which are taken by
  non-applicable routes. The uniqueness invariant in
  `tests/test_walkthrough_scores.py` covers every route whether or not it
  currently competes, so those values are unavailable even though nothing would
  break today.

If Option B ships, its route takes **0.50** — above `integer`'s 0.45 partial
(it demonstrates a working write rather than only an offset) and below
`fmtstr`'s 0.55 disclosure. Both values are currently free.

A `heap` detection route scoring 0.25 changes no existing routing: on 11 and 12
the current winner is `triage` at 0.15, so heap takes those two and nothing else
moves. That prediction is checked against the 15-target sweep, not assumed —
`tests/test_walkthrough_route_sweep.py` expectations for 11 and 12 change from
`triage` to `heap`, and the other 13 entries must not move.

## Files touched

- `supwngo/exploit/walkthrough/heap_probe.py` (new) — tri-state probe layer.
- `supwngo/exploit/walkthrough/families/heap.py` (new) — `propose` / `build`.
- `supwngo/exploit/walkthrough/families/__init__.py` — import, `__all__`, docstring.
- `supwngo/exploit/walkthrough/registry.py` — `_families()`.
- `supwngo/cli.py` — `explain --family` help text (the coordination point the
  fmtstr branch silently missed; see the consolidation note).
- `tests/test_walkthrough_heap.py` (new).
- `tests/test_walkthrough_scores.py` — add `heap` to the recorded ordering.
- `tests/test_walkthrough_route_sweep.py` — 11 and 12 become `heap`.
- `CHANGELOG.md`.

## Test strategy

1. **Literal execution, not rendering.** Generate the walkthrough for 11 and 12
   and *run every step*. Every real defect in both prior families was found this
   way and was invisible to review: a closed-tube `EOFError` from a hardcoded
   tube name, five `log.*` calls printing `%%n` literally because pwnlib only
   collapses `%` when args are present, a `recvline()` that returned the banner
   instead of the leak, a generated script that did not parse, and a probe
   desynchronised by a target that echoes input before formatting it.
2. **Tri-state proof.** Patch a probe to hang and to raise; assert the fact is
   UNKNOWN with `resolved_by`, that the rendered text names the
   did-not-complete case in words, and that no absence claim appears.
3. **Positive control.** Assert that a target with no heap primitive at all
   (e.g. `15_win_function`) yields either abstention or a NOT_DETERMINED /
   absent verdict that is distinguishable in the rendered output.
4. **No self-scoring.** `b"flag" in out` is prohibited. Verdicts are
   differentials against a benign run and against a same-length control payload.
5. **Mutation-test every new test** — mutate, watch it go red, revert, report the
   table. Specifically check for guards the fixtures cannot exercise: the fmtstr
   family found one that was *unfalsifiable by construction* because another
   stage always won first. A correct predicate nobody calls is the same defect as
   a wrong one.
6. **Known authoring traps**, from the brief: `common.protection_verdicts` takes
   `TargetFacts` (not `ProtectionFacts`) — the wrong type is an `AttributeError`
   at generation time; a multi-line fragment interpolated into an f-string that
   then passes through `dedent_code` arrives at column 0 and yields
   `IndentationError` in the generated script, so use `splice()` with
   `@@NAME@@` placeholders.
7. **Discrepancy pattern.** Where a measured fact contradicts a tool's summary,
   emit an extra `ProtectionVerdict` *naming the discrepancy* rather than
   silently overriding. Candidate here: a locally loaded libc's version string
   versus the safe-linking behaviour actually observed in the freed chunk's first
   qword.
8. `propose()` returns `max()` over candidate routes, not an `if/elif` chain, so
   condition order cannot silently become scoring. Non-applicable routes carry
   `Rejection.UNMET_PRECONDITION` plus `becomes_viable_if`.
9. Full suite green, with `benchmark/corpus/` **built** — 72 of the two prior
   families' tests skip silently without it.

## Risks

- **The absence-claim trap is the whole risk of this family.** Mitigated
  structurally (tri-state at the probe boundary, positive control before any
  negative) rather than by care.
- **Probe cost.** Heap probing drives a menu over many process spawns. Budget it
  like `fmtstr_probe._Budget` (process count *and* wall-clock, since either alone
  is escapable), and exhaustion yields UNKNOWN rather than an error or a
  negative.
- **Host contention.** Other agents hold gated measurements. No benchmark harness
  run, no parallel sweep; per-target runs and unit tests only.
