# Review protocol: converge in three rounds

**Date:** 24 Sep 2026
**Applies to:** every plan, reference implementation and instrumentation pass in this
repo that goes through independent review.
**Goal:** all pre-existing defects closed within **three rounds**. A fourth round is
a process failure to be escalated, not a document to grind.

---

## 1. The measured cause of >3 rounds

Not reviewer laziness and not author carelessness. In every multi-round sequence this
repo has run, **the second rejection was driven by a recurrence of a defect class the
first round had already named.**

| sequence | round N finding | round N+1 finding | same class? |
| --- | --- | --- | --- |
| step-3 primitive acquisition | B1: specified a capability that already exists (`comparison_immediates()` already recovered the constant, as candidate #1) | BLOCKING 1: the flagship gate specifies a capability that already exists — *the same function* | **yes** |
| instrumentation pass | B1: I4's carrier (`AttemptRecord`) is not in scope at 7 of 9 call sites | m: the replacement carrier (`context`) is not in scope at 4 of 9 sites, including both sites the proof mandates | **yes** |

**First evidence the rule works.** Told to enumerate all 9 sites *before* choosing a
third carrier, the author found `context` reaches only 4 of 9 — and abandoned the
carrier approach entirely, instrumenting the single chokepoint where the value is
already computed. Zero call-site changes, zero signature changes, no site out of
scope, and the risk rating fell. The enumeration also corrected a round-1 table entry
(a call site sits in a nested closure with neither `self` nor `context`). One sweep
run up front closed a class that had already cost two rounds and would have cost a
third.
| schema v4 (code) | — | 7 of 9 HIGHs were *invisible* to the property suite because each property held the defective dimension constant | (single code round) |

The mechanism is mechanical: **reviews report instances, revisions fix instances, so
the class survives.** A reviewer who writes "`AttemptRecord` is not in scope at
`shellcode_techniques.py:66`" gets back a revision that swaps the carrier and
reproduces the defect somewhere else. Both parties acted in good faith and a round
was spent for nothing.

Two secondary causes, both cheap to remove:

- **Unverified self-claims.** "§5 restored verbatim", "every row labelled", "the
  complete 13-row map" — three separate rounds were spent partly on claims a
  document made *about itself* that a `diff` or a `wc -l` would have refuted.
- **Missing inventory.** Four times a document proposed building something the repo
  already had. A `grep` before writing would have caught every one.

## 2. The rule that does the work

> **Findings are reported and answered by CLASS, not by instance.**

Everything below is an implementation of that sentence.

---

## 3. Author's obligations, before review

Five sections are mandatory. A document missing any of them should be returned
unreviewed — that costs minutes, where a round costs hours.

1. **Inventory.** For every capability, instrument or field proposed: the search
   performed, and what already exists. *"This exists and must be consumed rather
   than built"* is a valid and welcome outcome. State why anything that exists is
   insufficient.
2. **Scope table.** For any mechanism that must be present at *N* sites, enumerate
   **all N** and state what is in scope at each. Not the sites you checked — all of
   them. If you cannot enumerate them, you cannot claim the mechanism works.
3. **No unverified self-claims.** Any claim about the document itself — restored,
   complete, every, all, verbatim — must be accompanied by the command that
   establishes it and its output. Otherwise delete the word.
4. **Positive instance per gate.** Every gate names the artifact that makes it go
   **red**. If no existing artifact can, the gate ships with a fixture or it is not a
   gate. A gate whose subject never occurs in the corpus is unfalsifiable — see
   `validation-that-cannot-fail`.
5. **Table provenance.** Every table states its denominator and how each row was
   extracted. Prefer a structured field over parsing generated text; two undercounts
   in one document (12 rows of 13, and 1 hit instead of 46) both came from parsing
   script text when the run artifacts held the field.

## 4. Reviewer's obligations

Findings are worth little without the sweep. Required per finding:

```
FINDING  <severity>: <one-line defect>
FILE     <path:line verified against>
CLASS    <the general defect this is an instance of>
SWEEP    <the command or procedure that enumerates every other instance>
RESULT   <every other instance found, or "swept, no others">
```

**The reviewer runs the sweep.** Reporting a class without enumerating it pushes the
work onto a revision that will not do it, and buys the next round's rejection.

Three passes that each caught a blocker this session and are therefore mandatory:

- **The letter-vs-spirit test, per requirement.** "Can an implementer satisfy this
  requirement while adding nothing?" This is what exposed a flagship gate satisfiable
  by wiring in a function that already existed. Run it on every *Required* item.
- **Forward consistency.** For each fix, check whether a **later** section still
  assumes the pre-fix state. Fixes land locally and documents reason globally.
- **Sufficiency, separately from correctness.** For each claimed justification, does
  the proposed instrument actually settle it? "Necessary but not sufficient" is a
  finding. A justifying row with no instrument must be withdrawn or instrumented.

And two standing prohibitions:

- **"Addressed" is not evidence.** Verify the fix, never the disposition table.
- **A reflexive rejection costs as much as a reflexive approval.** If it is sound,
  approve it and say so plainly.

## 5. Reviser's obligations

Per finding, answer the class:

```
FINDING  <id>
INSTANCE <what was fixed>
CLASS    <as named by the reviewer>
SWEEP    <command run>
OTHERS   <every other instance found and fixed, or "none">
RADIUS   <every section that referenced the changed material, and its status>
```

A revision that fixes only the named instance is **incomplete by construction** and
should be returned without a new review round.

Disagreement is welcome and has twice been correct this session — a reviewer's
`objdump` finding was withdrawn after the author showed the call was a
`logger.debug()`, and a "risky migration" turned out to *remove* a redundant spawn.
Push back with evidence; do not accept a finding you can refute.

## 5.1 Implementer reports are not evidence

Implementation runs on a cheaper model than planning and review. Its **self-reports
about test outcomes must be re-run by whoever owns the gate**, never relayed.

Measured instance: under an always-pass stub of a new gate function, a Sonnet
implementer reported **5 of 9 tests red**. Seven were red. It also characterised the
suite's positive control as not asserting `.ok` — it does. Both errors ran in the
**safe direction**, which is exactly why they would survive a casual check: an
under-reported red count reads as a weaker gate rather than a broken one, and nothing
about it looks alarming.

So, per implemented item, the owner personally:

- re-runs the mutation and reports **their own** count, not the implementer's;
- verifies scope independently — which files actually changed, against the base
  commit — rather than accepting "only these files were touched";
- restores the tree afterwards and confirms it is clean.

The same asymmetry applies to any delegated verification: a report of a *negative*
result (nothing broke, nothing found, fewer failures than expected) is the cheapest
possible thing for a delegate to produce by accident, and it is the direction the
whole repo's defect history runs in.

## 6. Round budget and the tripwire

| round | purpose |
| --- | --- |
| **1** | Full adversarial review with class sweeps. This is where nearly everything should be found. |
| **2** | Verify the sweeps and the fixes. New findings only if genuinely new — a same-class repeat means the sweep was not done. |
| **3** | Confirmation. Expect approval. |

**Tripwire:** if round *N* produces a finding whose **class** was already named in
round *N−1*, that is a **recurrence**. Log it as such and name whose sweep was
skipped. Recurrences are the metric to drive to zero; they are the only thing that
has ever cost this repo a fourth round.

### 6.1 Required per-round metric: RECURRENCE / NEW / INTRODUCED

Every round after the first reports all three counts. They diagnose different
failures and the remedies are opposite, so an undifferentiated total is useless.

- **RECURRENCE** — the class was named in a prior round. A sweep was skipped. Name
  whose.
- **NEW** — a class no prior round named. This is the only count that measures
  whether *discovery* is converging.
- **INTRODUCED** — created by the previous round's remediation. Exempt from the
  round budget, but must be labelled so it cannot mask a recurrence.

Measured instance that justifies the split: a round-4 review returned **13 HIGH
against round 3's 9**, which looks like a method that is not converging. Decomposed,
it was **6 recurrences / 0 new / 7 introduced**. Discovery had fully converged —
round 4 found no class round 3 had not already named. The remedy was therefore *not*
a better review; it was running the sweeps and containing remediation.

### 6.2 Remediation is a defect source, and new tests are its riskiest output

Of those 7 introduced defects, **5 were inside the 8 properties the remediation
added**. Fixes get the same scrutiny as original work, and a test written to close a
finding is the highest-risk artifact in the change — it is new, unreviewed, and
trusted immediately because it is green.

Corollary: when a round's introduced count approaches its recurrence count, the unit
under review is too large to remediate safely. **Split it** rather than reviewing the
monolith again.

### 6.3 Red is not enough — it must be red for the right reason

"Prove the gate can fail" is necessary and **not sufficient**. A property shown
`[RED]` against a mutant that *disables* a rule proves only that the rule is present.

Measured: for **8 of 8** bound properties in one artifact, a *subtler* mutation of the
same rule survived its property. In the worst case the subtler mutant **was the
pristine implementation** — the canonicaliser already collided enums, tuples, sets and
dataclasses, and its property passed.

So per bound property: name the subtler mutation of the same rule, and either show it
also goes red, or record it as a **known blind spot**. An unrecorded blind spot is
indistinguishable from coverage.

### 6.4 Two mechanical instruments that need no annotation

Dimension variance requires annotation — a property must *declare* what it varies and
holds constant, because nothing can infer intent. Two things do not:

- **Refusal-site coverage.** Patch each error class's `__init__` to record the raising
  site, run the suite, diff against the AST. One artifact had **29 of 107 raise sites
  never fired by any test**, including a branch whose own comment claimed
  `# pragma: no cover - exercised via pytest.raises` while nothing exercised it.
- **Variation that is not binding.** A declared-varying field is not real variation if
  another constraint pins it — varying `process_id` proves nothing while every
  candidate is BUILD-scoped. Check variation *relationally*, at instrumented call
  sites, not by reading the fixture list.

Annotation is still worth it precisely because it can be caught lying: requiring a
per-property `varies` / `holds_constant` declaration converted a vague ask into a
falsifiable claim, and a reviewer immediately named **seven false entries** in it. A
meta-test over those declarations checks the *form* of the claim, never its truth.

**A fourth round escalates rather than proceeds.** If round 3 is not an approval,
stop and report, with the recurrence count. Either the sweeps are not being run, or
the document is carrying too much — a document that needs four reviews is often
three documents. Defects genuinely *introduced* after a round are exempt from the
budget; they are new work, and should be labelled as such so they do not mask a
recurrence.

## 7. Reusable review brief

Paste and fill. The bracketed items are the only parts that change.

```
You are the independent reviewer for [ARTIFACT] at [PATH/COMMIT]. You did not write
it and have no stake in it being approved.

This repo converges reviews in three rounds. The single thing that has ever broken
that is a reviewer reporting an INSTANCE where the defect was a CLASS: the revision
fixes the instance, the class re-emerges wearing a different instance, and a round is
lost. So for every finding, report instance, class, the sweep that enumerates the
class, and the result of RUNNING that sweep yourself.

Verify claims against the code and the run artifacts. Do not accept a claim because
the document is otherwise careful. [LIST THE LOAD-BEARING FACTUAL CLAIMS — confirmed
/ refuted / undeterminable for each.]

Mandatory passes:
1. Letter-vs-spirit, per Required item: can an implementer satisfy this while adding
   nothing? Check whether what it asks for already exists.
2. Forward consistency: for each fix, does a LATER section still assume the pre-fix
   state?
3. Sufficiency: does each proposed mechanism actually settle the justification it is
   attached to? "Necessary but not sufficient" is a finding.
4. Gate falsifiability: for each gate, name the artifact that makes it go red. A gate
   whose subject never occurs is unfalsifiable regardless of how it is worded.
5. Scope completeness: for any mechanism needed at N sites, verify all N — not the
   ones the document checked.

Do not approve because findings were "addressed"; verify the fixes. A reflexive
rejection costs as much as a reflexive approval — if it is sound, approve it plainly.

Output: findings in the FINDING/FILE/CLASS/SWEEP/RESULT block form, classified
BLOCKING / MAJOR / MINOR, ending in an explicit APPROVED or NOT-APPROVED line. If
this is round 2 or later, flag every finding whose class was named in a prior round
as a RECURRENCE and say whose sweep was skipped.
```

changelog: none
