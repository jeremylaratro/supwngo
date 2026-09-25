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

### 5.0 The sweep obligation attaches to the finding, not to the reviewer

**Whoever finds a defect owes its sweep — including when you find it yourself,
mid-work, with no reviewer involved.** This is the protocol's easiest gap to fall
into, because the FINDING/CLASS/SWEEP discipline reads as something a reviewer does
to you.

Measured: of five skipped sweeps in one round, **four were the same pattern — bitten
by an instance, fixed the instance, never enumerated the class.** Each was a defect
the author had discovered personally:

- Found one un-patchable builtin raise, fixed that instance, declared the instrument
  correct. Never enumerated the builtin raises. There were two.
- Found a type collision, widened the property across distinct *types*, never across
  the **subclass relation** — which the dispatch actually keys on.
- Found the "mutant describes pristine behaviour" defect in one property and, in the
  same document, wrote four new mutants without applying the check to them.

That last one is the tell: the author applied a class it had *just discovered* to the
reviewer's findings and not to its own new work. **A class you discover yourself is
still a class.** When you fix something you found, write its sweep before moving on.

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

#### 6.1a NEW is measured against the document set, not against the previous round

A finding already written down in *any* prior review, plan, or caveat list is not
NEW, even if the round that named it never saw that document. Classifying against
"the previous round" only is how a project rediscovers its own recorded caveats and
spends finding slots on them.

**Measured instance.** Round 2 reported the dangling `NEGATIVE_SIZE_BYPASS →
"negative_size_bypass"` mapping as a finding. A peer review had named it
explicitly — by that name — **one day earlier**, in
`docs/reviews/2026-09-23-effectiveness-and-usability.md:19`. The round-2 finding
was a rediscovery of a written-down caveat. A second document,
`PHASE1-BASELINE:110`, already stated the corroborating fact from the opposite
direction ("executors run regardless of which technique a target actually needs").

So the Author's inventory obligation (§3, item 1) extends past `grep`ping the code:
**before labelling a finding NEW, grep the `docs/` tree for it.** The same one-line
check that stops you proposing to build what exists stops you re-finding what you
already knew. A recorded caveat that reaches a second review unfixed is a *triage*
failure, not a discovery success, and mis-labelling it NEW hides that.

#### 6.1b A sweep yields candidates, not findings

The obligation to sweep a class creates its own failure mode: the sweep returns N
hits and the temptation is to report N instances. **Every hit is a candidate until
it is checked against the deliberate-design explanation.** Reporting an
intentional absence as a gap costs exactly what a skipped sweep costs — a wasted
round — and it discredits the sweeps that did find something.

Measured, from one three-direction sweep:

| direction | raw hits | after checking | why |
| --- | --- | --- | --- |
| A: mapping entries with no executor | 1 of 9 | **1, and inert** | a membership guard upstream drops the name before the lookup |
| B: executors absent from the mapping | 9 of 17 | **0 defects** | all 9 are deliberately enumerated in two other lists, one of which names its three in a comment |
| C: silent-skip lookup sites | 4 | **0 live** | the one silent skip is dead on the production path — its only caller pre-filters |

Nine of ten raw hits were correct by design. Reporting direction B as a gap would
have been the round's largest error, produced *by following the protocol*.

Three consequences, all cheap:

- **Assert every enumeration source is non-empty, in the script**, so a vacuous
  sweep raises instead of returning "swept, no others." See
  [[validation-that-cannot-fail]] instance 12 — an absence check whose subject did
  not exist.
- **Report reach, not just presence.** "1 dangling of 9" and "1 dangling of 9, and
  a membership guard makes it unreachable" support different decisions. A finding
  that states presence without reach cannot be prioritised.
- **Record the dead defensive branches you found.** Not as defects — as a note, so
  that nobody later writes a gate asserting "dangling entries are skipped" and
  collects a vacuous pass out of code that cannot execute.

#### 6.1c A masking defect makes every green result collected during its lifetime uninformative

The most expensive discovery of the session, and it is a *counting* rule, not a
debugging tip. A single pre-existing defect — one failed `import pwn` under
`click.testing.CliRunner` poisoning `sys.modules` for the rest of the process —
made an entire family of tests fail for a reason unrelated to what they tested, and
simultaneously **hid a regression somebody introduced on top of it.** Two `fmtstr`
tests caught a wrong tie-break only *after* the import fix stopped masking them.

> **ERRATUM, same day. The `fmtstr` example above is false and is retracted; the
> rule below stands on different evidence.** The author reconstructed the exact
> interim state (conftest without `PWNLIB_NOTERM`, `fmtstr` ranking its rejections,
> `select_route` keyed on `name`) and ran the ordering pair that induces the
> poisoning. Both tests **failed with the defect live and failed with it fixed** — so
> the defect was not hiding them. Measured, not argued.
>
> The rule keeps two real instances from the same work: a third test,
> `test_unreachable_write_target_is_marked_rather_than_offered`, failed *only* with
> the defect live and is a genuine poisoning victim; and the pre-fix **"791 passed /
> 14 skipped"** figure was genuinely collected under the live defect and has been
> **withdrawn — do not cite it.** Everything else was tested for maskability
> one-file-per-process with the defect re-induced and came back green with zero
> poison signatures, because only one test file imports `pwn` through a `CliRunner`.
> So the heap 13/13 and the tie-sweep tables stand rather than being withdrawn.
>
> **The actual cause of the missed tie-break is narrowness, and it is the more useful
> rule:** the mutation table mutated `select_route` and ran only the selector's own
> two test files — never `test_walkthrough_fmtstr.py`, where the tests encoding
> *which route `fmtstr` should pick* live. Every mutant died and the table read as
> thorough, because every test it ran exercised the mechanism rather than the
> behaviour the mechanism decides. **Mutating a shared component means running the
> tests of every caller whose behaviour it decides.** Same shape as the schema
> property-test finding: narrowness reads exactly like correctness. Carried into §6.3.
>
> **And a failure of mine, twice in one session, with one shape.** Both this and the
> refusal-census erratum at `2bc3aba` were an agent's *causal story* written into this
> document because it was well-told, without the discriminating test having been run
> by anyone. New standing rule for me: **no causal claim enters a process document
> until the discriminating experiment exists — either the agent shows it, or I run
> it.** A plausible mechanism is a hypothesis; only the experiment that could have
> come out the other way makes it a finding.

So the rule:

> **Once a masking defect is identified, every green result collected while it was
> live is uninformative — not "probably fine". Re-run them; do not re-read them.**

And its corollary for the round budget: such a round's counts cannot be compared to
the next round's. Label it, do not average it, and do not let a recurrence hide
inside it.

Two secondary lessons from the same diagnosis, both cheap and both general:

- **Diagnose the mechanism, not the correlation.** The first hypothesis — a shared
  pwntools gadget cache — was supported by a clean sample under an isolated
  `XDG_CACHE_HOME`, verified by reading `context.cache_dir`. That verified the
  *redirect was installed*; it never tested whether the redirect *explained the
  symptom*. Confirming an intervention is in place is not evidence it is causal, and
  the discriminating experiment (re-induce the symptom with the intervention live)
  is the one that got skipped. The real variable was import order. See
  [[validation-that-cannot-fail]] instance 14.
- **A broad `except` that renames a failure into a legitimate-looking observation is
  why this cost days instead of minutes.** `Binary._load_with_pwntools` converted
  "pwntools failed to load this ELF" into "this binary has no symbols" — a plausible,
  actionable, wrong fact. Prefer a loud distinct state over a plausible one; an
  exception handler that can produce a *normal-looking* result is the absence-collapse
  pattern with a friendly face.

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

**And the mutant must be run against the right tests — breadth, not only subtlety.**
A mutation table that mutates a shared component and runs only that component's own
tests measures the mechanism, never the behaviour the mechanism decides. Measured: a
tie-break selector was mutated and every mutant died against the selector's two test
files; the wrong tie-break survived because `test_walkthrough_fmtstr.py` — which
encodes *which route `fmtstr` must pick* — was never in the run. The table read as
thorough precisely because it was narrow.

> **Rule: mutating a shared component means running the tests of every caller whose
> behaviour that component decides.** State the caller set in the table, so a missing
> caller is visible rather than inferred. This is the §6.1b lesson in the other
> direction — there, a sweep produced candidates that were not defects; here, a
> mutation suite produced greens that were not coverage.

### 6.4 Additive is not inert — check every artifact compared across runs

"This field is write-only and has no control-flow surface" is the most common
inertness claim in instrumentation work, and it is **false wherever the artifact
containing the field is compared for equality across runs.**

Measured, and caught by a class sweep before it landed: a per-attempt duration field
was claimed inert on exactly that basis. But generated scripts render the record's
free-text notes, and a cross-rep determinism checker hashes those scripts — its
normaliser masked only 10+ digit decimals and 6+ digit hex, so a duration like
`12.473` passed straight through. Injecting one made the checker report `DIVERGENT: 1`
and exit 1, against a clean exit 0 on the real archived run.

The consequence was not a failing test. **It would have destroyed the finding that
ruled out probe truncation as the explanation for a published capability figure** —
an instrumentation pass silently invalidating the evidence that the number it was
built to explain is trustworthy. The claim had held on a sibling instrument only by
luck, because that one had been bound to a structured field for an unrelated reason.

So for any added field, enumerate every artifact it can reach, and for each ask
whether anything **compares that artifact across runs, reps, or hosts**. If so the
field is not inert: put it in a structured channel that comparison excludes, and state
the invariant explicitly rather than leaving it to hold by accident.

### 6.5 Two mechanical instruments that need no annotation

Dimension variance requires annotation — a property must *declare* what it varies and
holds constant, because nothing can infer intent. Two things do not:

- **Refusal-site coverage.** Patch each error class's `__init__` to record the raising
  site, run the suite, diff against the AST. One artifact had **28 of 106 in-scope
  raise sites never fired by any test**.

  (Corrected figures: **2** sites out of scope, not 1 — a builtin `TypeError` and a
  `SystemExit` — and the census had **no category at all for 4 bare re-raises**. The
  never-fired count itself has not been re-measured since. A census that lacks a
  category for a construct it encounters silently mis-files it.)

  > **ERRATUM, same day, left beside the original because the correction is itself a
  > finding.** The second half of that parenthesis is **false**. The census output
  > reads `bare re-raise sites (exempt): 4` — verified by me in the artifact, not
  > relayed: `docs/plans/2026-09-24-schema-unit-1-canonicalisation.md` line 609 at
  > `31291c2`, line 617 at `e6498a7`. The category existed and was labelled *exempt*.
  > **2 out of scope, not 1** stands (the block reads `1`; the sites are `L200
  > TypeError` and `L2154 SystemExit`). **28 of 106 in scope** stands. Never-fired
  > remains un-re-measured.
  >
  > How it got in: an agent's round-1 report said the category was missing, and I
  > wrote it into this document without opening the output. That is
  > [[claim-provenance-at-point-of-use]] and §5.1 in one move — a delegate's claim
  > about an instrument, propagated as measured. The agent then retracted it against
  > itself; I confirmed the retraction in the artifact rather than relaying that too,
  > because the retraction is a delegate claim on identical footing to the original.
  >
  > **The rule this earns: before reporting a category absent from an instrument's
  > output, quote the output.** Note the direction — this is the *second* time this
  > instrument was accused of being worse than it is, both times by the same route,
  > both times erring toward alarm. Errors about a measuring device are not
  > symmetric: an instrument wrongly called broken gets replaced, and its correct
  > readings go with it.

  **And the instrument must report what it cannot instrument as *out of scope*, never
  as *uncovered*.** That sweep first reported 29 of 107 and accused a branch of
  carrying a false `# pragma: no cover - exercised via pytest.raises` comment. The
  comment was true; the sweep could not see the call because the site raises a builtin
  `TypeError` and CPython refuses to patch `__init__` on an immutable type. **A
  coverage tool returning a false negative is the same defect class as a gate that
  cannot fail, aimed at the measuring device** — and it is more dangerous, because a
  false accusation of missing coverage gets acted on. Any coverage or provenance
  instrument needs a third state for "could not measure this site," and its count of
  uncovered things is only trustworthy once that state is non-empty and enumerated.
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
