# The 85% walkthrough gate cannot currently produce a figure — options and recommendation

Date: 2026-09-24
Status: **DECISION REQUIRED FROM THE MAINTAINER.** One part is already in motion
because it is needed during R5 authoring, which is happening now; the rest is held.
Evidence: `docs/reports/2026-09-24-walkthrough-scorer-first-measurement.md`,
`docs/plans/2026-09-24-walkthrough-follower-tier-decision.md`.

---

## 1. The measured problem

The scorer works. It refuses seven purpose-built cheats including two live
false-credit channels found in review, and it reports three denominators while
naming only one gate-safe. None of that is in question.

The problem is the metric it is asked to compute.

**On the five round-1 targets measured with the agent follower, the informative
denominator is 0.** Not small — zero.

| target | difficulty | walkthrough k/N | bare k/N | verdict |
| --- | --- | --- | --- | --- |
| `02_ret2plt_system` | easy | 1/1 | 1/1 | `UNINFORMATIVE` |
| `04_canary_leak_bypass` | medium | 2/2 | 2/2 | `UNINFORMATIVE` |
| `08_ret2dlresolve` | **hard** | 2/2 | **2/2** | `UNINFORMATIVE` |
| `09_srop` | **hard** | 2/2 | **2/2** | `UNINFORMATIVE` |
| `12_heap_tcache_poison` | hard | 2/2 | 1/2 (one 900 s timeout) | `NOT_MEASURABLE` |

A Tier-3 follower given **only the binary** captured the flag on both of the
corpus's `hard` targets at 2/2. The scorer correctly emits `gate: null`.

**This is structural, not a tuning problem.** The gate asks whether the walkthrough
was *necessary*. Necessity is measured against a follower that is itself a capable
solver, so the metric is a property of the follower tier as much as of the
walkthrough. Strengthen the follower and every walkthrough becomes unnecessary;
weaken it and the figure measures the follower's deficits. There is no follower tier
at which "85% followable" means what it sounds like.

Two secondary facts that constrain any fix:

- **The effect that demonstrably exists is cost, not outcome.** `02`: 34.5 s with the
  walkthrough against 113.6 s without — 3.3×. `12`: credited with the walkthrough
  against a 900 s wall without it. Every measured difference is an effort difference.
- **The walkthrough arm strictly contains the template arm.** `12` is `TEMPLATE_BROKEN`
  — its own embedded template captured nothing in 3/3 — and the agent following that
  walkthrough was credited 2/2 via a GOT overwrite. A reader repairs a broken template
  from the prose around it, so `{walkthrough succeeds} ⊋ {template succeeds}`. Any
  denominator estimated from `TEMPLATE_OK` counts is too pessimistic.

## 2. Options

### A — Weaken the follower until the bare arm fails
Pick a tier whose bare arm misses most targets, restoring a denominator.
**Rejected.** The figure becomes tunable by follower choice, and choosing the tier
that produces a denominator is selecting the instrument to produce the result. It
also measures the weak follower's deficits rather than the walkthrough's quality.
*What would flip it:* a principled, externally fixed reader definition — a named
tier justified before any measurement and never revisited. We do not have one.

### B — Replace the outcome metric with the cost effect
Report walkthrough-minus-bare time-to-flag (or budget-to-flag) with a confidence
bound, over all eligible targets.
**Recommended as a reported figure, not as the gate.** It measures the effect that
exists and never collapses. But "3.3× faster" cannot be thresholded at 85% without
inventing a meaning for the number, and a ratio over a set where both arms sometimes
fail needs censoring rules that are themselves knobs.

### C — Make the outcome budget-relative *(recommended gate shape)*
Both arms get the **same pre-committed budget** B. `FOLLOWABLE` means: credited
within B with the walkthrough, not credited within B without it. This converts the
measured cost effect into an outcome effect and keeps a binary, thresholdable gate.
`12_heap_tcache_poison` already behaves this way by accident — credited with the
walkthrough, 900 s wall without.
**Conditions that make it honest**, all of which must hold or the option is no better
than A: B is committed **before** the measurement; B is reported with the figure and
never adjusted after seeing it; and the run publishes a **sensitivity curve** — success
rate against budget for both arms — so the knob is visible instead of hidden. If the
curves cross or the gap closes as B grows, the report must say so.

### D — Calibrate corpus difficulty by primitive depth *(already in motion)*
R1's `hard` tier is not hard for a capable solver, so R5's must require **two or more
primitives chained before the final redirect**, with depth taken from the reference
exploit rather than from intent. This is the R5 spec's existing rule; what is new is
that it is now the load-bearing one. **Already sent to the R5 generator**, because it
must reach the authoring in progress and it is correct under every option here — a
target an unaided solver trivially captures is uninformative to any version of this
gate. Explicitly *not* tuning against any solver: the criterion is structural, counted
from the reference exploit.

### E — Drop the 85% gate; report the three figures descriptively
**Held as the fallback.** If the informative denominator on R5 is still too small
after C and D, a withheld rate plus a stated denominator is more honest than a
threshold computed over four targets. The scorer already refuses a verdict on too
small a denominator, so this path needs no new code.

## 3. Recommendation

**D + C, with B reported alongside, and E as the declared fallback.** D is in motion.
C is the only shape that keeps a binary gate while measuring an effect that exists. B
is free once C's sensitivity curve is being produced — they read from the same data.

**Two decisions I am not making:**

1. **The value of B.** It must be committed before measuring and it changes what the
   gate means. Defensible anchors: the walkthrough arm's median elapsed on a
   *non-R5* corpus, or a round number well inside the current 900 s wall. Either is
   arguable; picking it after seeing R5 would void the gate.
2. **Whether 85% survives at all.** Under C the number is no longer "fraction of
   walkthroughs that are followable" but "fraction where the walkthrough changed the
   outcome inside B", which is a strictly harder bar. 85% of that may be the wrong
   threshold even if 85% of the original was right. This compounds the already-open
   question of whether 50%/85% are blocking gates or reported targets.

## 4. Unrelated to the metric, and the actually binding constraint

**Coverage, not scoring, is what limits the walkthrough gate today.** Seven of
thirteen round-1 walkthroughs honestly abstain (`family=triage`, offset undetermined)
— designed behaviour, preferable to binary-independent filler, and still no flag. One
more, `03_pie_leak_ret2libc`, teaches a route that dies with `EOFError`: that one is a
route defect rather than a coverage gap, and it is the only bug in that bucket.

So the `fmtstr`/`integer`/`heap` families work is on the critical path for this gate
exactly as the R5 spec's sequencing says, and no choice made in this document
substitutes for it.

## 5. Reproducibility limitation to carry forward

The follower tier is pinned as far as it can be from here — `claude -p`, CLI 2.1.271,
tool allowlist, denied `WebFetch`/`WebSearch`/`Task`, $2.00 budget, 900 s wall,
`--strict-attribution`, variant `verbatim` — **except the model**, recorded as the
mutable alias `sonnet`. Pin the explicit dated identifier instead and record it with
the figure; an alias that silently re-points makes two runs incomparable and leaves no
trace that they are.
