# Final round (R5): 15 unseen binaries, dual-gated on autopwn and walkthrough

Status: DRAFT — requires review before the corpus is generated
Date: 2026-09-24
Owner: benchmark / capability measurement

## Directive

The final round is a **completely new set of 15 binaries the tool has never seen**,
split across easy / medium / hard, with two acceptance gates:

| gate | threshold |
| --- | --- |
| autopwn (`supwngo solve`, unattended) | **>= 50%** |
| walkthrough (generated 0-to-pwn guide is followable) | **>= 85%** |

This round comes *after* R2, R3 and R4. It is round 5, not a replacement for R4.

## Difficulty split: 5 / 5 / 5

R1 and R4 are both 5 easy / 7 medium / 3 hard. The directive says "split between
easy medium and hard", so R5 is an **even 5 / 5 / 5**. This is a deliberate change
and it makes R5 harder than every prior round: the hard tier goes from 3/15 (20%)
to 5/15 (33%). Do not silently reuse the 5/7/3 generator defaults.

Tier definitions are inherited from `benchmark/corpus.yaml` and must stay
comparable across rounds — a tier is defined by the mitigation set and the number
of chained primitives required, not by how hard the generator found it to write.

### Stratify by primitive depth, not only by difficulty tier

R2's cold measurement (4/15) showed the difficulty labels are **nearly uncorrelated
with pipeline outcome**: easy 2/5, medium 1/6, hard 1/4 — with a `hard` ret2csu
chain credited at 5/5 while an `easy` shellcode-on-writable-stack target produced a
stub in all 5 reps. Mitigations did not separate the groups either; 7 of the 11
failures were also no-PIE/no-canary.

What did predict the outcome was **primitive depth** — how many primitives must be
acquired and chained *before* the final redirect. All four R2 wins were the same
shape: control the return address, then jump to an address already known. Every
failure required acquiring something first (a leak to defeat PIE, a canary
disclosure, a format-string write, heap metadata control, an OOB index).

So a 5/5/5 split by human-intuition difficulty does not control the variable that
actually drives the result, and a round balanced only that way can shift several
points on tier composition alone. R5 must **record primitive depth per target** and
balance on it as well, so the figure is decomposable into "reached the redirect" and
"had to acquire a primitive first." Without that, an R5 miss cannot be attributed.

This is a finding about the measurement instrument, not about one round, and it
applies to any future corpus.

**Depth needs three buckets, not two.** The original decomposition — "reached the
redirect" versus "had to acquire a primitive first" — implicitly assumed every
depth >= 1 failure was a failure *to acquire*. A cross-rep divergence analysis of
R2's 11 failures found otherwise: `01_stack_shellcode_relay` **did obtain its
stack leak and still failed to place shellcode**. So the acquisition succeeded and
the application of it failed, which is a different capability gap with a different
fix and must not be pooled with "could not get a leak".

R5 must therefore record, per failing target, which of three states it reached:

1. never acquired the required primitive,
2. acquired it and failed to apply it,
3. never needed one (depth 0) and still failed.

Without state 2 being separable, an R5 miss rate cannot be read as "cannot obtain
primitives", which is the conclusion the two-bucket decomposition invites and
which R2's target 01 already falsifies.

## Problem 1 (BLOCKING): there is no walkthrough scorer

`benchmark/` contains **zero** references to walkthroughs. The autopwn number has
a hardened harness behind it — secret per-build flags, independent re-execution,
negative controls, behavioural attribution, an ablation suite. The walkthrough
number has nothing. An 85% gate against a metric that does not exist yet is not
measurable, and inventing a lenient one later to clear the gate would be exactly
the failure mode this benchmark was built to prevent.

### Design: blind-follower scoring

A walkthrough counts as **followable** when a fresh agent, given only the
generated walkthrough and the binary, captures that build's secret flag.

- The follower gets the walkthrough and the binary. Nothing else: no session
  context, no supwngo source, no reference exploit, no prior round's notes.
- The follower never receives the flag. Scoring reuses the existing
  secret-flag + independent-re-execution + behavioural-attribution machinery.
  A walkthrough is credited only on an attributed flag-bearing write, on the
  same terms as autopwn.
- Self-scoring is prohibited, as it is for autopwn. The walkthrough engine does
  not grade its own output, and `b"flag" in out` is not a verdict.
- Reported per-tier and as `k/N`, with reps, matching `--reps` semantics.

### Problem 1a (BLOCKING): the walkthrough gate needs its own negative control

If the follower agent is strong enough to exploit the binary *without* the
walkthrough, then 85% measures the follower's competence, not the walkthrough's
quality — the same "validation step that cannot fail" defect already found in
`soundness_probes/drive.py`.

**Control:** the identical follower attempts each binary with the walkthrough
withheld (binary + "capture the flag" only). Credit the walkthrough only where
the walkthrough arm succeeds and the no-walkthrough arm does not. Where both
succeed, the target is **UNINFORMATIVE for the walkthrough gate** and leaves the
walkthrough denominator — it cannot demonstrate the walkthrough contributed
anything. This is the necessity test from `benchmark/ablation/`, applied to
documentation instead of to exploit steps.

Consequence to accept up front: a strong follower will make some easy targets
uninformative, shrinking the walkthrough denominator. A denominator of 15 for the
walkthrough gate should not be assumed.

## Problem 2 (POLICY): a held-out corpus is single-use

R5 can produce a trustworthy unseen number **once**. If it comes in under 50% and
the pipeline is then tuned against R5 and re-measured on R5, the result is no
longer held-out — it is a training score, and the 50% gate becomes unfalsifiable.

Recommended policy, pending confirmation:

1. Measure R5 exactly once. Report the number whatever it is.
2. If a gate is missed, that is the finding. Harden afterwards if desired.
3. Re-measurement after hardening requires a **fresh R6**, not a second pass at R5.

Cost of the alternative (split R5 into a tuning half and a sealed half): 7-8
binaries per half, which is too few to separate capability from noise at the tier
level. Recommendation is measure-once.

## Problem 3: who generates R5

Generation must not be done by an agent that can see the framework's technique
inventory, the prior corpora, or the reference exploits. Otherwise "unseen" means
only "not yet executed", and the corpus inherits the shape of what supwngo
already does — which is how a 100% round-1 score happens.

### R5 must be independently conceived, NOT a re-shaping

R2 turned out to be a **paired shape-variant of R1**: every R2 source header names
the specific R1 target it re-shapes, holding technique family fixed and varying only
the surface mechanic (R2 `02` builds `"/bin/sh"` by concatenation where R1 `02` had a
literal; R2 `14` is a positive OOB *read* where R1 `14` was a negative-index *write*).

That is a genuinely valuable design — of the 11 families R1 solved at 5/5,
re-shaping broke 9 and left 2 standing, which is much stronger overfit evidence than
comparing two unrelated corpora because family composition is removed as an
explanation. But it measures **robustness to adversarial re-shaping of problems the
pipeline already solves**, which is not the same property as generalization to new
problems. R2's 4/15 is therefore an estimate over re-shaped variants, plausibly
closer to a lower bound for arbitrary binaries, since deliberate re-shaping targets
the pipeline's specific assumptions.

**R5 measures the other property, and must be built to.** It is independently
conceived: not a re-shaping of any R1-R4 target, not paired to anything, families
and mechanics chosen without reference to what supwngo has previously met. The
novelty review before sealing must explicitly check for pairing — including
accidental pairing, since a generator asked for "a stack overflow with a canary" may
reinvent an existing target's shape without intending to.

Do not let R5 and R2-R4 numbers be compared as though they measure the same thing.
Both are worth having; conflating them would waste both.

Constraints:
- Isolated generator agent, no access to `supwngo/exploit/`, `benchmark/reference_exploits/`,
  or any prior `corpus.yaml`.
- It is given the tier definitions and the vulnerability-class families, and
  nothing about how supwngo attacks them.
- Input shapes deliberately varied (argv, env, file, multi-stage stdin), since
  input-shape assumptions are a known weak point.
- Reviewed for novelty against R1-R4 before it is sealed.

### Flag delivery must vary WITHIN technique class

Found while specifying R2's comparison instruments, and it is a requirement rather
than a preference.

On R1, `strings`-scrapeable and shell-obtaining turned out to be **the same
property observed twice**: a target is scrape-clean precisely because it obtains a
shell and reads `flag.txt` at runtime instead of carrying a compiled-in flag. So
any attempt to subset R1 by scrape-cleanliness silently subsets it by exploitation
style — the scrape-clean six are exactly its shell-obtaining targets, and the
excluded seven are exactly its arbitrary-read/write primitive targets. That is
systematic bias, not low power: it moves the point estimate in a direction that
cannot be signed, rather than merely widening an interval.

R2 fixed soundness by making delivery **uniform** (0/15 scrapeable, all reading
`flag.txt` at runtime). Strictly better for soundness — and because it is uniform,
it destroys the within-corpus contrast that would let anyone separate delivery
mechanism from technique class. Two desirable properties in direct tension, and
R2 optimised the first without knowing it cost the second. R2 is therefore
permanently unable to separate those axes, whatever is later measured on it.

**R5 requirement:** vary flag delivery *within* each technique class — some
shell-obtaining targets with a compiled-in flag, some primitive targets reading
`flag.txt` — so the corpus is both sound and analysable, and the confound is
separable inside one corpus instead of only across corpora. Keep every target
scrape-resistant; vary the *mechanism*, not the *integrity*.

Do not let this be optimised back out in the name of soundness: a uniform corpus
looks cleaner and measures less.

## Gate arithmetic and the denominator

The VOID mechanism means 15 built targets is not 15 scored targets. R1 lost 2 of
15 to VOID. State the denominator before measuring, not after:

- Both gates are computed over **scored (non-VOID)** targets, consistent with the
  existing harness, and the report states both `x/scored` and `x/15`.
- 50% of 15 = 8; 50% of 13 = 7. This is not a rounding detail.
- Walkthrough additionally excludes UNINFORMATIVE targets per Problem 1a.

**Run the ablation suite and negative controls on R5 before the capability
measurement.** R1 shipped 2 targets that handed over the flag without the
vulnerability. Catching that on R5 *after* measuring would contaminate the one
clean shot at an unseen number. Repair or replace VOID targets before the
measurement run, not after.

### Precondition: no credit may rest on a hardcoded constant sweep

`VariableOverwriteExecutor` (`stack_techniques.py:59-93`) sweeps a fixed list of
nine folklore constants (`0x1337`, `0xdeadbeef`, `0xcafebabe`, …) against 14
buffer sizes, with no recovery step. Two further copies of the list exist at
`input_shape_techniques.py:48` and `enhanced_auto.py:119`. R1's corpus gates on
`0x1337` (`14_negative_index/negative_index.c:54`) and `0xdeadbeef`
(`13_off_by_one/off_by_one.c:34`) — both in all three lists.

The provenance question (were the lists seeded from the corpus?) is unanswerable
and irrelevant. The defect is structural: **a brute-force list can credit any
target whose gate happens to use one of its nine values, and that credit
generalises to nothing.** R5's generator is isolated and may well pick
`0xdeadbeef` for a gate; the sweep would then contribute to the 50% figure as
though it were capability.

Being inert on R1 and R2 does **not** clear this for R5 — different corpus,
different constants. Required before the R5 measurement, whichever is cheaper:

1. Source the executor's candidates from `comparison_immediates()`
   (`input_shape_techniques.py:68`, which already recovers gate constants from the
   target's own `cmp`/`test` instruction stream) instead of the fixed list — the
   real capability, and it generalises to any exact-value gate; **or**
2. Flag and report separately every R5 target credited via a constant sweep, so
   the headline figure never silently includes one.

Option 1 is preferred. The recovery function already exists and works; the gap is
that this executor does not call it.

### Precondition: the attempt ordering is a prior fitted to R1, and must be declared before the figure exists

Measured attribution of which layer fixes each executor's attempt position
(`push()` dedupes, earliest layer wins):

| layer that fixes the position | executors |
| --- | --- |
| `FIRST_TECHNIQUES`, consulted **before** the strategy report | 11 |
| `UNMODELED_TECHNIQUES` | 3 |
| forced last (`LAST_TECHNIQUES`) | 2 |
| **the strategy layer** | **1** (`direct_shellcode`) |

The reason is documented in-code at `orchestrator.py:73-92`: `StrategySuggester`
"put `VARIABLE_OVERWRITE` at priority 1 for all 15 benchmark targets and pushed
`RET2PLT` to priority 4", so Phase 5 layered hardcoded lists over it rather than
fixing the model. The suggester was not imprecise — it was **inverted across the
entire R1 corpus**, and it has been routed around rather than repaired.

This is the same family as the constant sweep above, but it is a **weaker and
different** defect, and the distinction is load-bearing:

- The constant sweep can **manufacture credit** — a flag obtained from a folklore
  list is not capability. That makes it a credit-validity defect.
- The ordering **cannot manufacture a flag**. It decides what is *tried first*
  under a wall-clock budget (`run_bench.py:407`, 360s outer), so it can convert a
  would-be timeout into a solve and vice versa. That makes it a
  **generalisation-claim** defect: an R5 figure produced under an R1-fitted
  ordering measures the ordering's fit as much as the pipeline's reasoning, and
  nothing in the figure separates the two.

Required before the R5 measurement:

1. **Commit this attribution table, unchanged, before the cold run** — it is a
   pre-registration on the same footing as the four non-like-for-like axes, and it
   exists so the caveat cannot be written after seeing whether it was needed.
2. **Run a permuted-ordering ablation arm.** Commit one fixed permutation of
   `FIRST_TECHNIQUES` (reversed is sufficient and needs no judgement) **before**
   arm 1 runs; run it immediately after arm 1 with **no intervening edit of any
   kind**; report the delta as the ordering's contribution. The headline figure is
   **arm 1 only** — arm 2 is an ablation, never a second attempt at the number.

On single-use (Problem 2): arm 2 does not violate it. The corpus is single-use
against *tuning*, and the pipeline carries no state between runs, so two arms
differing only by a pre-committed permutation is the harness's existing ablation
pattern, not a retry. The condition that makes it sound is the one stated above —
no code change lands between the arms. If one does, arm 2 is void and is reported
as void.

**Named and not taken:** fix `StrategySuggester` so the strategy layer earns its
position back, then measure. Rejected for R5 — repairing a model that is inverted
on the only corpus we can calibrate against is an open-ended research task, and
doing it *before* the unseen measurement would tune against R1 in the one place we
have agreed not to. It is the right post-R5 work. **What would flip it:** evidence
that the fitted ordering is worth a large share of the solve count — which is
exactly what arm 2 measures. A large delta turns the suggester from cleanup into
the critical path.

## Both preconditions above govern R3 and R4, not only R5

Written here because this is where the preconditions live, but scoped wrongly if left
attached to R5 alone. **R3 and R4 are held-out corpora with exactly the same two
exposures and exactly the same single-use property.** A cold number can be taken from
each of them once. Measuring either while the constant sweep and the R1-fitted ordering
are unaddressed spends a single-use resource under a known defect — and produces a
figure that has to carry the same caveats R5's would, with no way to re-take it.

So, applying to **every remaining cold measurement (R3, R4, R5)**:

1. **The constant-sweep precondition.** Either source `VariableOverwriteExecutor`'s
   candidates from `comparison_immediates()`, or flag and report separately every
   credited target that a constant sweep won. Option 1 remains preferred and is now
   more clearly worth doing once rather than three times: the recovery function already
   exists, and doing it before R3 makes the fix cover all three rounds.
2. **The ordering precondition.** Commit the layer-attribution table before the run,
   and run the permuted-ordering ablation arm with no intervening edit. The table is
   the same table for all three rounds; the ablation arm is per-round, because the
   delta is a property of the corpus as well as of the ordering.

R1 and R2 are unaffected — both were measured before either exposure was identified,
both have been re-run post-fix and reproduced target-for-target, and neither credited
any target via the constant sweep. **13/13 and 4/15 stand unannotated.** The exposure
is prospective, which is precisely why it must be closed before the next cold run
rather than after.

**Consequence for sequencing: R3 is not ready to measure today.** That is a change from
"R3 follows R2" as a scheduling fact, and it is the cheaper order — one fix ahead of
three measurements instead of three sets of caveats behind them.

## Sequencing

R5 is the last item. It runs after R2, R3, R4 and after the walkthrough second
wave (heap / format-string / integer families are currently guided triage only) —
a walkthrough gate cannot be measured on families the engine does not yet cover.
See `2026-09-24-walkthrough-families-fmtstr-heap-integer.md`.

### Heap is scoped to detection, which the 85% gate cannot score

The second-wave directive sets heap at **detection minimum**, not full 0-to-pwn.
A detection-only walkthrough cannot pass blind-follower scoring by construction:
it does not reach a flag, so the follower captures nothing. With an even 5/5/5
split and heap the canonical hard family, heap targets would otherwise drag the
walkthrough figure below 85% for a reason unrelated to walkthrough quality.

Resolve before generating R5 — recommendation is (1):

1. Heap targets leave the walkthrough-gate denominator and are reported separately
   against a **detection-quality** criterion (primitive, allocator, reachability
   correctly identified).
2. Heap targets stay in and the gate reads "85% of non-heap scored targets".

Declare the choice before measuring, not after the number is known.

## Open questions for the maintainer

1. Confirm measure-once (Problem 2), or authorise a tune/seal split.
2. Are the 50% / 85% figures acceptance gates that block, or targets to measure
   against and report?
3. Confirm the even 5/5/5 split is intended given it raises hard-tier weight.
