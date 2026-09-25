# Decision: follower tier and what to do about the UNINFORMATIVE collapse

Date: 2026-09-24
Status: **decided for the instrument; one question escalated to the maintainer**
Instrument: `benchmark/walkthrough/`
Design: `docs/plans/2026-09-24-walkthrough-blind-follower-scorer.md`
Measurement: `docs/reports/2026-09-24-walkthrough-scorer-first-measurement.md`

The scorer's necessity control credits a walkthrough only where the walkthrough
arm succeeds **and** the bare arm fails. The plan accepted up front that a
capable follower would make some easy targets `UNINFORMATIVE`. The measured
collapse is larger and differently shaped than that, so the tier question has to
be settled with the data rather than by the plan's assumption.

## 1. What was measured

Agent follower: `claude -p`, model alias `sonnet` (Tier 3, the project's stated
floor), tools `Bash/Read/Write/Edit/Glob/Grep`, web denied, $2.00 budget, 900 s
wall, `--strict-attribution`, variant `verbatim`.

| target | difficulty | template arm | walkthrough arm | bare arm | verdict |
| --- | --- | --- | --- | --- | --- |
| `02_ret2plt_system` | easy | `TEMPLATE_OK` | CREDITED 34.5 s | **CREDITED** 113.6 s | `UNINFORMATIVE` |
| `04_canary_leak_bypass` | medium | `TEMPLATE_BROKEN` | CREDITED 2/2 | **CREDITED 2/2** | `UNINFORMATIVE` |
| `08_ret2dlresolve` | **hard** | `TEMPLATE_BROKEN` | CREDITED 2/2 | **CREDITED 2/2** | `UNINFORMATIVE` |
| `09_srop` | **hard** | `TEMPLATE_OK` | CREDITED 2/2 | **CREDITED 2/2** | `UNINFORMATIVE` |
| `12_heap_tcache_poison` | **hard** | `TEMPLATE_BROKEN` | CREDITED 2/2 | 1/2 + **one 900 s timeout** | `NOT_MEASURABLE` |

Informative denominator: **0 of 4 eligible** (`rate_strict` 0/4, `rate_informative`
withheld — 100% of the eligible set dropped out, far past the 20% ceiling).

The bare arm has not lost a single **valid** trial. It did, once, fail to finish
one: on `12_heap_tcache_poison` its rep-1 trial hit the 900 s wall. The scorer
scored that `FOLLOWER_INVALID` and the target `NOT_MEASURABLE` rather than reading
a timeout as "the bare arm failed" — which is the asymmetric-validity rule doing
exactly the job it exists for, since a bare failure is what *grants* the
walkthrough credit. It is also the single most informative number here: see §2b.

## 2a. Correction: the walkthrough arm's ceiling is NOT the template arm's ceiling

An earlier draft of this document argued that the informative denominator heads to
0 because only **5** of 15 walkthroughs ship a template that captures a flag
(`01`, `02`, `07`, `09`, `15` — the other 8 abstain or teach a route that does not
work), and all 5 are at or below a difficulty the bare follower clears unaided.

**That argument is wrong, and the `12_heap_tcache_poison` measurement is what
refutes it.** `12` is `hard` and its template is `TEMPLATE_BROKEN` — the
walkthrough's own embedded template captured nothing in 3/3 reps. The *agent*
follower given that same walkthrough was credited **2/2**, on a behaviourally
attributed GOT-overwrite route. A reader can repair a broken template from the
prose around it; the template arm cannot. So

```
{walkthrough arm succeeds}  ⊋  {template arm succeeds}
```

and any bound on the informative denominator derived from `TEMPLATE_OK` counts is
too pessimistic. The corrected claim is narrower and rests only on measurements:
**the bare arm won every valid trial on 4 targets spanning `medium` and `hard`,
including two `hard` at 2/2.** That is enough to make the denominator 0 on this
subset. It is *not* enough to prove the denominator is 0 corpus-wide, and this
document no longer claims it is.

## 2b. What the `12` timeout actually says

`12_heap_tcache_poison` is the only target where the arms visibly differ in cost
rather than in outcome, and the difference is large: the walkthrough arm finished
and was credited in both reps, while the bare arm exceeded a 900 s wall in one of
two. Together with `02_ret2plt_system` (34.5 s with, 113.6 s without — 3.3×), the
two measurements that carry timing both point the same way:

> The walkthrough changes what the follower's attempt **costs**, not what it can
> **do**.

That is the finding the pass/fail metric is structurally unable to express, and
it is why option C below is put to the maintainer rather than dismissed.

## 3. The options, weighed

### A. Weaker follower tier — **rejected**

The coordinator's first suggestion, and the intuitive one: a teaching
walkthrough's audience is a reader who cannot already do the exploit, so a weaker
follower measures the intended property better.

Three reasons the data does not support it.

1. **There is no lower tier to move to.** `sonnet` is Tier 3, and the project's
   own routing rule states "Tier 3 is the floor". Going below means `haiku`,
   which is outside the declared tiering and would make the figure incomparable
   to every other number this project reports.
2. **A weaker model weakens both arms.** The necessity test needs "solves with
   the walkthrough" AND "fails without". Lowering capability pushes both toward
   failure. The denominator can collapse from the other end — every target
   `NOT_FOLLOWABLE` because the follower could not follow anything — and that is
   just as uninformative while looking like a damning result.
3. **The measured effect is on effort, not on possibility** (§2b). Both timed
   comparisons — 3.3× on `02_ret2plt_system`, and a credited walkthrough arm
   against a 900 s bare timeout on `12_heap_tcache_poison` — show the walkthrough
   shortening the attempt rather than enabling it. If that is the shape of the
   effect, then *no* choice of model tier separates the arms on a pass/fail
   measure, because the walkthrough is not changing what the follower can do.
   Tuning the tier would be searching for a capability band narrow enough that a
   cost effect reads as a possibility effect — and any band narrow enough to
   produce that is a band the result is an artifact of.

**What would flip this:** a measured run at a lower tier showing a non-empty
`{walkthrough works} ∩ {bare fails}` set of at least
`MIN_INFORMATIVE_TARGETS` (7) **and** a walkthrough arm that is not itself mostly
failing. Both halves are required; either alone is a collapse. Note that §2a makes
this *more* plausible than the first draft allowed: the walkthrough arm succeeds on
targets whose template is broken, so it has more headroom above a weakened bare arm
than a `TEMPLATE_OK` count suggests.

### B. Bound the bare arm — **rejected as specified, adopted in a symmetric form**

As specified ("no web access, bounded attempt or time budget" on the bare arm),
this must not be done, for a reason the plan already committed to in rejecting
best-of-N:

- **It makes the headline number a dial.** Tighten the bare budget → more
  `FOLLOWABLE`. Whoever sets that budget sets the score, and there is no
  principled value to set it to. The R5 gate would become a number someone chose.
- **It breaks the property that makes the comparison valid.** The two arms are
  currently the *identical follower* with an identical prompt differing only by
  the walkthrough paragraph, which is what licenses attributing an outcome
  difference to the walkthrough. Give the arms different allowances and the
  difference is confounded by the allowance. (Web access is already denied in
  **both** arms, for exactly this reason.)

There is a variant that keeps the motivation and drops the flaw: reduce the
follower's affordances **symmetrically, in both arms**. Implemented as
`--affordance {shell,read-only}`; because the tier object is shared by both arms,
a profile cannot tighten one arm and not the other.

- `shell` (default, what was measured): Bash available, so the follower can run
  the binary, run `objdump`/`checksec`/ROPgadget, and **test what it writes**.
  That is an unaided *researcher with a toolchain and a test loop*. The bare
  transcript for `09_srop` ends "Reliable across 3 runs" — it tested its own SROP
  chain three times.
- `read-only`: no Bash. The follower must produce the exploit from reading alone.
  That is much closer to the reader a teaching artifact addresses, and it removes
  the specific affordance — the iteration loop — that most plausibly explains why
  a Tier-3 model beats `hard` targets unaided.

**This is UNMEASURED.** No figure in the repository was produced with it. It is
committed so the choice can be settled by measurement instead of argument, and
the honest next step is to re-run the subset under `--affordance read-only` and
compare — `12_heap_tcache_poison` first, because it is the one target where the
bare arm was already at the edge of its budget (§2b) and so the one where removing
the test loop is most likely to change an outcome rather than a duration.

**What would flip it:** if `read-only` drives the *walkthrough* arm to fail too,
it is a worse instrument than `shell`, not a better one, and should be abandoned
rather than tuned.

### C. Change the measure to speedup — **proposed, not adopted**

Steps or wall-time to solution with versus without the walkthrough. Every target
stays informative; the denominator never collapses; and it measures the effect the
data actually shows — 3.3× on `02_ret2plt_system`, and on `12_heap_tcache_poison` a
credited walkthrough arm against a bare arm that blew a 900 s wall.

Not adopted because the user asked for a `>= 85%` pass-rate gate, and silently
replacing a pass/fail gate with an effect size is exactly the "invent a friendlier
metric" move this benchmark exists to prevent. It is put to the maintainer as a
**companion** measure, not a substitute: report `rate_strict` as the gate and
speedup as the effect size, so a collapsed denominator still yields a number that
means something.

**What it would buy:** a metric that cannot be defeated by a capable follower,
that works on targets where both arms succeed, and that degrades gracefully
instead of going undefined. **What it costs:** it is not a gate. Nothing about
"2.8× faster" says whether the walkthrough is good enough to ship.

## 4. Decided

1. **Tier stays pinned at `sonnet` / Tier 3, `shell` affordance as the recorded
   default.** Reasons in A. The tier and the affordance profile are both written
   into `report.json`, and figures across either are not comparable.
2. **The gate refuses to state a verdict on a denominator too small to support
   one.** New blocker: `informative < MIN_INFORMATIVE_TARGETS`, where the floor is
   **7**, *derived* rather than chosen — at n = 7, 7/7 = 100.0% and 6/7 = 85.7%, so
   one target still passes and it takes two to fail; at n = 6, one target's
   outcome flips a perfect score to a failure (5/6 = 83.3%). 7 is the smallest
   denominator on which a single target cannot decide the gate. Asserted in
   `--selftest` both ways: a denominator of 2 blocks the gate, a denominator of 8
   does not, so the floor cannot silently become a blocker that always fires.
3. **The summary leads with the denominator and spells out the difference between
   the two claims**, verbatim: `rate_informative` is "*f* of the *n* targets where
   a walkthrough **could possibly** have mattered"; `rate_strict` is "*f* of the
   *e* eligible targets, full stop". Quoting the first as the second overstates
   the result by exactly the targets the follower solved unaided.
4. **Both arms are reported per target** — each arm's k/N plus the within-rep
   contingency table — so the collapse is visible rather than hidden in a ratio.
   This was already the behaviour; it is now the stated reason for it.
5. **`--affordance read-only` is available and unmeasured.** Run it before
   choosing between B-symmetric and C.

## 5. Escalated to the maintainer

**The `>= 85%` necessity-controlled pass-rate gate may not be measurable on
round-1 at this follower tier, and if so that is a finding about the corpus and the
follower, not about the scorer.** Measured: 5 targets attempted with the agent
follower, informative denominator **0**. The bare arm won every valid trial across
`medium` and `hard`. Four consequences:

- A `NOT MEASURABLE` gate result on R5 is a live possibility, and the gate now
  says so instead of emitting a number. Whether it happens depends on targets that
  are hard *for the follower*, which is not the same axis as the corpus's own
  `difficulty` label — `12_heap_tcache_poison` is the only target measured so far
  that stressed the bare arm at all.
- Neither a PASS nor a FAIL should be accepted from a denominator below 7. A FAIL
  for "the follower was too good" is as misleading as a PASS from a lenient metric,
  and the gate now refuses both.
- **Do not draw the denominator bound from template-arm coverage.** §2a records the
  measurement that refutes it: the agent follower is credited 2/2 on a `hard`
  target whose walkthrough template is broken. "7 of 13 walkthroughs abstain" is a
  statement about the template arm and does not bound the agent arm.
- If the maintainer wants a number from R5 regardless, option C (cost/speedup as a
  companion) is the only one of the three that survives a collapsed denominator,
  and it needs deciding **before** the measurement, not after seeing it.
