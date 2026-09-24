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
