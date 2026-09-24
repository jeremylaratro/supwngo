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

| target | difficulty | walkthrough template works? | bare arm | verdict |
| --- | --- | --- | --- | --- |
| `02_ret2plt_system` | easy | yes | **CREDITED** 113.6 s | `UNINFORMATIVE` |
| `04_canary_leak_bypass` | medium | no (abstains) | **CREDITED 2/2** | `UNINFORMATIVE` |
| `08_ret2dlresolve` | **hard** | no (abstains) | **CREDITED 2/2** | `UNINFORMATIVE` |
| `09_srop` | **hard** | yes | **CREDITED 2/2** | `UNINFORMATIVE` |

Four attempted, four `UNINFORMATIVE`, including **both** `hard` targets at 2/2.
The bare arm has not failed once.

## 2. The decisive fact, which is worse than "the denominator shrinks"

The walkthrough arm has a ceiling independent of the follower. From the template
arm over all 15 round-1 targets, only **5** walkthroughs ship a template that
captures a flag at all: `01_shellcode_stack` (easy), `02_ret2plt_system` (easy),
`07_ret2libc_leak` (medium), `09_srop` (hard), `15_win_function` (easy). The other
8 either abstain (7, `family=triage`, declaring the offset unknown) or teach a
route that does not work (1, `03_pie_leak_ret2libc`).

Intersect that with the bare arm:

- Of those 5, **`02` and `09` are already proven `UNINFORMATIVE`.**
- The remaining 3 are `easy`, `easy`, `medium` — every one **strictly easier than
  `09_srop`**, which the bare follower solved 2/2 unaided.

So the informative denominator on round-1 at this tier is not "near zero". The
expected value is **0 or 1**: the set `{walkthrough works} ∩ {bare fails}` is
plausibly empty. An 85% gate over a denominator of 2 measures nothing; over a
denominator of 0 it is not defined.

This reframes the problem. It is not that a strong follower trims the long tail.
It is that **the walkthroughs that work only cover targets the follower can
already do**, so the necessity test has nothing to bite on.

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
3. **The measured effect is on effort, not on possibility.** On the one target
   where both arms succeeded and timings exist, the walkthrough arm took 34.5 s
   and the bare arm 113.6 s. The walkthrough made the work **3.3× faster**; it did
   not make possible something otherwise impossible. If that is the true shape of
   the effect, then *no* choice of model tier separates the arms, because the
   walkthrough is not changing what the follower can do. Tuning the tier would be
   searching for a capability band in which a speed effect masquerades as a
   possibility effect — and any band narrow enough to produce that is a band the
   result is an artifact of.

**What would flip this:** a measured run at a lower tier showing a non-empty
`{walkthrough works} ∩ {bare fails}` set of at least
`MIN_INFORMATIVE_TARGETS` (7) **and** a walkthrough arm that is not itself mostly
failing. Both halves are required; either alone is a collapse.

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
the honest next step is to run the 4-target subset under `--affordance read-only`
and compare.

**What would flip it:** if `read-only` drives the *walkthrough* arm to fail too,
it is a worse instrument than `shell`, not a better one, and should be abandoned
rather than tuned.

### C. Change the measure to speedup — **proposed, not adopted**

Steps or wall-time to solution with versus without the walkthrough. Every target
stays informative; the denominator never collapses; and it measures the effect
the data actually shows (3.3× on `02`).

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
round-1 at any follower tier, and that is a finding about the corpus and the
engine, not about the scorer.** The engine attempts a flag-reaching route on 6 of
13 scored targets; 5 succeed; all 5 are at or below a difficulty the follower
clears unaided. Three consequences:

- A `NOT MEASURABLE` gate result on R5 is the likely honest outcome unless
  walkthrough coverage improves on targets that are *hard for the follower*. The
  families work in flight (`fmtstr`/`integer`/`heap`) is therefore on the critical
  path for the gate, not merely for coverage.
- Neither a PASS nor a FAIL should be accepted from a denominator below 7. A FAIL
  for "the follower was too good" is as misleading as a PASS for a lenient metric,
  and the gate now refuses both.
- If the maintainer wants a number from R5 regardless, option C (speedup as a
  companion) is the only one of the three that survives a collapsed denominator,
  and it needs deciding **before** the measurement, not after seeing it.
