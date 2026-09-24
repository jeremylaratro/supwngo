# Schema v4 — round-4 review (verbatim)

**Date:** 24 Sep 2026
**Artifact reviewed:** the reference implementation and its property suite at
`085d4e5` — `supwngo/schema/resolve.py`, `supwngo/schema/mutants.py`,
`tests/test_context_resolve_properties.py`, and the generated
`docs/reference/context-resolution-tables.md`, all four **inlined** in the prompt.
**Reviewer:** codex `gpt-5.6-sol`, `model_reasoning_effort=xhigh`, `--sandbox
read-only`, prompt on stdin, instructed **not to read any files**.
**Prompt:** 261,167 bytes / 5,632 lines. Output asserted non-empty before
reading (40,999 bytes) — an exit 0 with an empty output file reads as approval
and has silently skipped a review in this repo before.
**Verdict:** **NOT-APPROVED.** 13 HIGH. Self-classified **RECURRENCES 6 / NEW 0
/ INTRODUCED 7**.

## Disposition: STOP, do not remediate into a round 5

The standing instruction was that if round 4 returned a comparable volume of
HIGHs, say so and stop rather than grind a fifth round. It returned **13 against
round 3's 9** — larger, not smaller. So this review is **recorded and reported,
not remediated**, with two qualifications that matter for deciding what to do
next:

1. **NEW = 0.** Not one finding is a defect class round 3 had not already named.
   The volume is *not* evidence that adversarial review keeps discovering fresh
   problems; it is evidence of two specific process failures, which is a more
   actionable signal:
   - **6 recurrences** — a class round 3 named, whose sweep was not run. Every
     one of these was mine to sweep and I did not.
   - **7 introduced** — defects created *by the round-3 remediation itself*.
     Five of the eight properties I added in round 3 are narrow or dead in
     exactly the way round 3's own lesson warned about. I wrote the sentence
     "narrowness in a property test reads exactly like correctness" and then
     shipped eight properties without applying it to them.
2. **The reviewer's own recommendation is to split the artifact**, not to review
   it again: "I would split canonicalisation, audit-log validation, and property
   breadth into separately reviewed units rather than proceed with another
   monolithic review." That agrees with the protocol's note that a thing needing
   five reviews is often several things.

### Already closed before this review arrived

Finding 1 (`binding=""` accepted on an unbound scope) was found independently by
an author-side sweep of round 3's falsey class and fixed in `085d4e5`, together
with the `identity=""` half the reviewer did not name and the two
constructed-`AppliesTo` sites. That is convergent confirmation of the finding and
of the sweep method; it is **not** evidence the remaining twelve are handled.

### Evidence provenance — every figure labelled serial or concurrent

Two concurrent pytest sessions in this repo have been measured corrupting each
other through shared state (six spurious failures, all passing on isolated
re-run). Any suite total collected inside that window is provisional, and a
`[RED]` proof obtained under a known-bad condition is as untrustworthy as a
green one. So:

| figure | value | collected |
| --- | --- | --- |
| property suite | 75 passed | **concurrent — provisional** |
| repo-wide excl. `test_challenges.py` | 673 passed, 10 skipped | **concurrent — provisional** |
| the nine `[RED]` mutation proofs | **9/9 red** | **serial**, one process, no pytest |
| the two must-pass mutants | 2/2 pass against P9 | **serial**, same process |
| shared-state exposure of the property suite | **0 files** opened outside the worktree across all 29 properties | **serial**, `sys.addaudithook` |

The nine proofs were re-run serially and all nine are red, with the same
classification the meta-test uses — a crash is not a proof, and none crashed.
But the decisive figure is the last one: an `open`-event audit hook filtered to
paths outside this worktree recorded **zero** opens across all 29 properties. No
`~/.supwngo/supwngo.db`, no cache, no shared file of any kind. The suite imports
the whole `supwngo` tree (840 modules, `__init__.py` is eager) and **none** of
`pwnlib`, `angr`, `capstone`, `keystone`, `ropper`, `elftools`, `unicorn`.

So this suite is **structurally** out of reach of the corruption vector, which is
a stronger statement than "I re-ran it alone" — and it held while another agent's
pytest was in fact running. The two repo-wide totals stay labelled provisional
regardless, because they include tests that *do* use shared state and re-running
those is not this artifact's job.

### Author-side finding the reviewer corroborates and this record extends

Running a mechanical refusal-site sweep over the normative module — patch each
error class's `__init__` to record the raising site, run the whole suite, diff
against every `raise` in the AST — gives:

```
constructed-exception raise sites:            107
bare re-raise sites (exempt):                   4
in instrument scope (module error classes):   106
out of instrument scope (builtin raises):       1
NEVER FIRED by any test in the repo:           28 / 106
positive-control coverage of refusals:      78/106 in scope
```

Twenty-eight refusals in a module whose governing rule is *a validation step that
cannot fail is worse than none* have never been observed to fire. This is
strictly mechanical — no annotation — and so it is a **sharper answer to
secondary question 2(a) than the reviewer's**, for refusal coverage specifically:
the reviewer is right that *dimension* variance needs annotation, but *refusal
coverage* does not. The list includes `_closure`'s two cycle/unknown-member
checks, `_validate_log`'s duplicate-`seq` check, all three of `_validate_conflicts`'
late clauses, `_refuse_if_stale`'s `FactStale`, and `ABSENT.__bool__` — whose
source comment claims `# pragma: no cover - exercised via pytest.raises` when
**nothing in the repo exercises it**, an unverified self-claim of the exact kind
the review protocol lists as a secondary cause of extra rounds. Four of the 29
overlap the reviewer's four dead gates; the other 25 it did not name.

This sweep is recorded rather than landed as a gate, because adding code to an
artifact a reviewer has just recommended splitting is the wrong direction.

## What the reviewer answered on the three secondary asks

- **Are the 37 mutants the right mutants?** For **all eight** round-3 bindings, a
  subtler mutation of the same rule survives its bound property — 8 out of 8
  "No", each with the exact edit named. Nine further mutants are too coarse to be
  informative, and four are caught by an easier subrule than the one they claim
  to test. Every surviving mutation corresponds to one of the 13 HIGHs.
- **Does P27 generalise to breadth?** Not fully mechanically: a machine cannot
  infer which dimension a property *intends* to constrain. But it can verify an
  annotated claim, and the reviewer names seven **false** entries in the
  annotation table I had just written — so the three annotation meta-tests are
  themselves a gate that passes a well-formed lie. The concrete fix it specifies
  is relational projections recorded at instrumented call sites, not raw field
  comparison, because `process_id` varying in P6 is not binding variation when
  every candidate is BUILD-scoped.
- **Is the `seq`/`actor` trust boundary correctly scoped?** **No — too broad.**
  Seven internal-consistency properties are expressible in-process and are not
  asserted; three more are genuinely policy-dependent; three are truly out of
  reach without an external trust anchor. The untestable part was being used to
  wave through a testable part, which is exactly what the challenge was for.

## Recorded verbatim below

Everything from here is the reviewer's output unaltered.

---

# VERDICT: NOT-APPROVED

The artifact still has a comparable—and in fact larger—volume of HIGH findings than round 3: 13. That is a significant signal. Three are present implementation defects (`binding=""`, non-injective canonicalisation, and audit histories accepted that no writer can produce); the remainder are mostly narrow or dead remediation controls. The dominant pattern is unchanged: broad-looking properties kill coarse mutants while holding constant the narrower dimension where a plausible defect can live. Given the repository’s rule against a fourth code round, I would split canonicalisation, audit-log validation, and property breadth into separately reviewed units rather than proceed with another monolithic review.

**RECURRENCES: 6**  
**NEW: 0**  
**INTRODUCED: 7**

Counts above are HIGH findings. Lower-severity limitations noted below are not included.

# THE 29-ROW NARROWNESS TABLE

| Property | Dimension claimed | Does the input set vary it? | If not, what is actually proven? | Could this hide a real defect in `resolve.py`? |
|---|---|---:|---|---|
| P1 | Merge disposition over store shape, dedup collisions, terminal siblings, and candidate content | Partial | It varies value, provenance, method, observation time, conditions, identity, and one terminal sibling. Scope, binding, lineage, generation, key family, and multi-terminal histories remain fixed. Its expected set also delegates to `R.dedup_key`, so it does not independently constrain that predicate’s field coverage. | **Yes.** Omitting `derived_from`, scope, or binding from dedup survives. |
| P1b | Validation totality over malformed candidates | Partial | Many malformed shapes are exercised, including falsey list fields and nested unknown fields, but candidate binding is always valid. | **Yes—current defect.** A BUILD candidate with `binding=""` validates. |
| P2 | Merge-order independence of canonical document bytes | Partial | Candidate-batch order varies. The seeded resolution record and derived candidate remain in exactly the same order and count in every permutation. Presence in compared bytes is proven; permutation invariance of those arrays is not. Generation is constant. | **Yes.** Removing only resolution-list sorting survives. Derived-candidate arrival order is also untested. Conflict ordering is harmlessly narrow because I9 already canonicalises it. |
| P3 | Merge idempotence and observation-set union | Yes, for its actual claim | It repeats one exact fixture and then changes only `observation.at`. Contrary to `NARROWNESS`, observation time does vary. Other content dimensions are fixed. | No material defect: `_merge_observations` is content-generic, and isolation is useful here. |
| P4 | Provenance partial order | Yes | All five provenance values, all pairs, and all transitive triples are exercised. | No. Other candidate fields are irrelevant to this pure comparator. |
| P5 | Scope, conditions, and composed-specificity partial orders | Partial | Every scope is present, but in a reduced slice using only measured/assumed and two condition maps; the all-provenance slice uses only three scopes. Cross-interactions between omitted scopes and other provenance values are not enumerated. | Plausible but lower risk: the visible implementation is componentwise lexicographic. |
| P5b | `compare_specificity` reads only its four declared components | **No** | It varies value, method, by, state, observations, and lineage. It does not independently vary key, non-null identity label, binding, generation, or id. The claimed `candidate_id` variation is not a perturbation: `dataclasses.replace` retains the original id. | **Yes**, though several omissions are unreachable in a valid applicable pool. This property alone does not prove its stated exclusion set. |
| P6 | Resolver totality over well-formed contexts | Partial | Identity mode, identity sets, and conditions genuinely affect BUILD candidates. `process_id="p2"` changes a context field but every candidate is BUILD-scoped, so the candidate/context binding relation never changes. | **Yes.** An `applicable()` that ignores binding would pass P6. |
| P7 | Resolution determinism under candidate order | Yes for candidate-bucket order | It physically permutes the bucket and observes both success and refusal. Conditions also vary despite the annotation saying they are held. Context and identity remain fixed. | No significant current gap for its narrow claim. |
| P8 | Resolved witnesses are existing pooled objects | Partial | Unique and agreement-style unpinned resolutions are exercised. Pins and stale/refusal branches are absent; identity and conditions actually vary despite being annotated constant. | Yes, lower severity: cloning only the pinned witness survives. |
| P9 | Asserted facts never silently beat contradictory measured facts | Yes for the guarded relation | Scope, identity-boundness, conditions, provenance, key type, and pin override paths vary. Binding always matches its context; the disagreement value relation is fixed. | No material gap in the contradiction rule itself. Binding applicability belongs elsewhere. |
| P10 | Digest-field partition | Partial | Every top-level `Candidate` field is perturbed. Inside `applies_to`, only identity changes; scope, binding, and conditions are not independently perturbed. Fact key actually varies despite the annotation saying it is held. | Plausible nested-projection defect, but current dataclass projection is generic. |
| P11 | State-machine totality and terminality | Inputs yes; semantics partial | Every declared state/event pair is called, but exact outcomes are not asserted except that terminal states refuse everything. An absent supersede or active append could succeed and P11 itself would accept it. | Yes, though P15’s committed transition table would catch many such changes in the full suite. |
| P12 | Absence is not a false/default value | Partial | All exact `FACT_KEYS` are tested; no prefix-family representative is resolved empty. | Yes, lower risk: a key-family-specific default could survive. |
| P13 | Conflict relation is total and partitioned | Partial | Value, provenance, identity-boundness, conditions, and store size vary in one BUILD context. Scope, binding, context, and `AMBIGUOUS_ACROSS_IDENTITIES` are absent. | Yes, but P25 and the priority reachability test cover parts of the omitted space. The single-context narrowness is real. |
| P14 | Dedup preserves distinct authorities | Yes for provenance | Provenance and both arrival orders vary. All other fields are deliberately identical, which is necessary to isolate provenance. | Harmless for provenance, but it does not establish the broader `CONTENT_FIELDS` claim. |
| P15 | Generated tables reflect runtime and registry enforcement | Partial | Table text covers exact and prefix keys. Actual scope-enforcement probes iterate only `R.FACT_KEYS`, not `_FACT_PREFIXES`. | **Yes.** A prefix-specific `spec_for` error can pass. |
| P16 | Pin folding is a function of sequence, not list or timestamp order | Partial | Two records, their order, adversarial `at`, unpin, and several malformed single records vary. Multiple valid keys and duplicate/gapped sequence histories do not. `observation_at` is falsely claimed: candidate observation time is fixed; only log `at` varies. | **Yes.** Global-single-key folding and duplicate/gap validation defects can survive. |
| P17 | Staleness is computed, transitive, monotone, and cycle-safe | Partial | Retraction, depth, a diamond, and wrong ref key vary. Superseded sources and dangling sources are not exercised. The cycle case exits on digest mismatch before its visited-set claim. | **Yes.** A retraction-only state check or failure to reject a dangling source survives; the cycle termination control is dead. |
| P18 | Equal-specificity disagreement is not time-resolved | Yes | Both timestamp orders and equal timestamps are used while all ordered components remain equal. | No. The constancies are necessary isolation. |
| P19 | Cross-identity equal encodings are not agreement | Yes for the exact predicate | Identity differs and `identity_mode="none"` makes both candidates applicable. It is one pair, but `agreeing()` reads only value and identity. | Harmless narrowness for `agreeing`; it does not independently assert the exact conflict-class label. |
| P20 | Generation and id are store-assigned and arrival-order independent | Partial | Generations 0/1/5, order, and zero-or-one terminal sibling vary. Wrong fresh-store generations are sent through a helper that does not fail if they are accepted. No history contains two terminal siblings. | **Yes.** Two subtler generation defects survive. |
| P21 | Canonicalisation is injective and order-independent | Partial | Several JSON-like evidence values, bytes/string, mapping order, hostile keys, and reserved-key spoofing vary. Accepted cross-type projections—enum/string, tuple/list, set/list, dataclass/mapping—are absent. | **Yes—current defect.** The pristine canonicaliser already has these collisions. |
| P22 | Audit log is referentially sound and consistent with lifecycle state | Partial | Many malformed single records vary. Log count stays one in negative cases; duplicate seq, gaps, duplicate terminal events, and causal supersession history are not varied. | **Yes—partly current defect.** Impossible writer histories validate. |
| P23 | Public candidate/conflict lists are canonical and valid | Partial | Individual malformed conflicts and duplicate/unsorted observations vary. The comment claims an out-of-order conflict-list control, but only a duplicate is appended. | **Yes.** Removing only canonical conflict-list ordering survives. |
| P24 | Supersession requires the same proposition | Partial | Identity, conditions, and scope vary, plus a valid control. Binding never differs within the same scope. | **Yes.** Omitting binding from the proposition comparison survives. |
| P25 | Stored, context-free, context-sensitive, and resolve conflict views agree | Partial | Values, identities, conditions, store size, and identity/condition contexts vary. All candidates are measured and BUILD-scoped, so provenance, scope, and binding relations remain fixed; the claimed context-binding variation is ineffective. | **Yes.** Ordering the measured/asserted guard before joint satisfiability, or ignoring binding exclusivity, survives. |
| P26 | Context validation is total over malformed contexts | Partial | Identities, conditions, mode, `host_id`, and `process_id` vary. `boot_id` and `attempt_id` remain valid and fixed. | **Yes.** Omitting either from the validation loop survives. |
| P27 | Every store invariant has a positive control | Partial | Every invariant name has some control, but not every rule within I7/I9. I5 is tested by calling `_assert_acyclic` directly, not through `validate_store`. | **Yes.** Removing duplicate-seq or canonical-conflict-order checks survives; the I5 store gate remains practically unreachable. |

The harmless or substantially harmless constancies are P3’s candidate content, P4’s non-provenance fields, P9’s exact disagreement values, P14’s non-provenance fields, P18’s ordered fields, and P19’s use of one carefully isolated pair.

# FINDINGS

## 1. Empty binding is accepted on unbound scopes

**FINDING  HIGH — RECURRENCE:** Falsey binding normalisation still accepts an invalid, semantically ignored value.

**WHERE** In `_validate_candidate`:

```python
if applies_to.scope not in _BOUND_SCOPES and applies_to.binding:
    raise SchemaError(...)
```

A BUILD candidate with `binding=""` passes because `""` is falsey, although the rule says that scope “takes no binding.”

**CLASS** Falsey values treated as absence. This is the same class as round 3’s `0`/`""`/`[]` validation finding.

**SWEEP** Inspect every validation conditional in the four artifacts that uses truthiness to distinguish missing from present: `_required_list`, identity/binding validation, method/by, observations, `_stated`, context ids, log text, and pin ids. Compare each with its declared missing sentinel (`None` or `_MISSING`).

**RESULT** This is the remaining actionable instance. `_required_list` now distinguishes falsey inputs correctly; method/by/log/context fields intentionally reject empty strings; `_stated(..., None)` is explicitly documented as unstated. Candidate `identity=""` is questionable but no non-empty candidate-identity rule is stated, so I am not counting it.

**FIX** Replace the condition with:

```python
if applies_to.scope not in _BOUND_SCOPES and applies_to.binding is not None:
```

Add P1b and P27 controls for BUILD `binding=""`, BUILD `binding="x"`, and bound-scope `binding=None`/`""`.

---

## 2. Canonicalisation remains non-injective across accepted Python types

**FINDING  HIGH — RECURRENCE:** The pristine `_jsonable` collapses several distinct accepted evidence values.

**WHERE**

```python
if isinstance(obj, enum.Enum):
    return obj.value
...
if isinstance(obj, (frozenset, set)):
    return sorted(...)
if isinstance(obj, (list, tuple)):
    return [_jsonable(v) for v in obj]
if dataclasses.is_dataclass(obj):
    return {f.name: ...}
```

Examples that currently canonicalise identically include:

- `Provenance.MEASURED` and `"measured"`;
- `("x",)` and `["x"]`;
- `{1, 2}`, `frozenset({1, 2})`, and `[1, 2]`;
- a dataclass and a mapping with the same fields;
- a dataclass with a `__bytes_b64__` field and the tagged encoding of suitable bytes.

**CLASS** Non-injective canonical projection. Round 3 fixed key coercion and bytes/string collision but did not sweep all cross-branch projections.

**SWEEP** Take every accepting branch of `_jsonable`, form the cross-product of branch output shapes, and ask whether two non-equivalent inputs can produce the same JSON value. Also inspect recursive bypasses of the reserved-key check.

**RESULT** Enum/scalar, tuple/list, set/frozenset/list, and dataclass/mapping collisions remain. Scalar JSON primitives are distinct; ordinary mappings are insertion-order independent; bytes cannot collide with ordinary mappings that pass through the mapping branch.

**FIX** Either:

1. define and document an equivalence relation under which these inputs intentionally mean the same evidence, weakening P21’s “distinct values” claim; or
2. tag every non-JSON-native type and reserve the tag namespace recursively.

Extend P21 with representatives from every accepted branch and pairwise canonical-encoding comparison.

---

## 3. P20 does not require wrong fresh-store generations to be refused

**FINDING  HIGH — INTRODUCED:** `_merge_expecting_refusal` silently passes if `merge` accepts a wrong generation on a fresh store.

**WHERE**

```python
def _merge_expecting_refusal(...):
    before = R.canonical_document(s)
    try:
        R.merge(s, {**raw(), "generation": gen})
    except R.SchemaError:
        assert R.canonical_document(s) == before
```

There is no `else: raise AssertionError(...)`.

P20’s later explicit rejection loop runs only after seeding a terminal sibling.

**CLASS** A negative test invokes the rejection path but never asserts that rejection occurred.

**SWEEP** Trace every “expecting refusal” helper and every `try/except SchemaError` in the suite, checking the successful `else` path. Then enumerate generation histories by terminal-sibling count, not merely a boolean.

**RESULT** This helper is the remaining silent-acceptance instance. P1b, P22, P23, P24, P25, and P26 all have explicit success-path failures. P20 also has no case with two terminal siblings.

A subtler defect that passes P20 is:

```python
if stated_gen is not _MISSING and generation > 0 and stated_gen != generation:
    raise SchemaError(...)
```

That silently corrects caller generations on fresh stores while still refusing the terminal-store cases.

Another survivor is replacing `max(c.generation for c in terminal)` with `terminal[0].generation`; every P20 store has at most one terminal sibling.

**FIX** Add the missing `else`, assert rollback, and exercise histories with terminal generations `{0,1}` followed by the expected generation 2.

---

## 4. Log validation accepts histories no public writer can produce

**FINDING  HIGH — INTRODUCED:** `_validate_log` validates records locally but not the lifecycle history they collectively assert.

**WHERE** `_validate_log` checks positive/unique `seq`, ids, keys, class-specific fields, and final target state, but it does not check:

- dense store-assigned sequence numbers;
- duplicate terminal records for one candidate;
- `supersede` replacement having the same `applies_to`;
- whether the replacement was already terminal at the supersession’s sequence;
- generation-chain order.

P22’s negative cases each append one record:

```python
for label, fields in _forged_log_records(...):
    ...
    s.resolutions.append(record)
```

**CLASS** Validation scoped to individual records instead of the relation/history being validated.

**SWEEP** Enumerate every invariant enforced by a writer but reconstructible from stored records: `_next_seq`, `transition`, `supersede`’s same-proposition rule, replacement liveness at event time, one terminal event per candidate, and generation succession.

**RESULT**

- Two otherwise valid records with the same `seq` are not tested.
- `{1,3}` is accepted even though the only writer produces dense `1,2`.
- Two distinct-seq retract records for one retracted candidate are accepted.
- A forged supersede record can name a same-key replacement with different binding/identity/conditions if the target is manually marked superseded.
- A replacement terminal before the supersede record is accepted.
- No property connects terminal-event sequence with sibling generation.

The last four are current implementation gaps, not merely missing tests.

**FIX** Validate a sorted-by-seq replay:

- require the sequence set to be `1..len(records)` unless gaps are explicitly made normative;
- allow at most one terminal transition per candidate;
- require supersede target/replacement `applies_to` equality;
- reject a replacement whose terminal event precedes the supersede;
- require sibling generations to be contiguous and terminal-event order to increase with generation.

Add multi-record P22 cases for each rule.

---

## 5. P23 and P27 do not exercise canonical conflict-list ordering

**FINDING  HIGH — INTRODUCED:** The claimed out-of-order positive control is actually only a duplicate control.

**WHERE**

```python
# A duplicate, and an out-of-order list
s, a, b = _pinned_store()
existing = list(s.conflicts)
if existing:
    s.conflicts.append(existing[0])
    with pytest.raises(R.SchemaError):
        R.validate_store(s)
```

This creates a duplicate. It never creates two distinct valid conflicts in reversed canonical order.

**CLASS** A coarse mutilation trips an earlier clause, leaving a later absence gate unexercised.

**SWEEP** Map each branch in `_validate_conflicts` to the first P23/P27 input that reaches it without violating an earlier branch.

**RESULT**

Covered: record type, class type, key, arity, sorted/distinct ids, dangling ids, cross-key ids, and duplicates.

Not independently covered:

- non-string ids;
- final list canonical ordering:

```python
if list(store.conflicts) != ordered:
    raise SchemaError("I9 conflict list is not in canonical order")
```

Deleting only that final block passes P23 and P27.

**FIX** Build at least two distinct valid `Conflict` records, validate their canonical order, reverse them, and require specifically the final I9 ordering error. Add a mixed-type id control that reaches the string check.

---

## 6. P24 omits binding from the proposition dimensions

**FINDING  HIGH — INTRODUCED:** A supersede implementation comparing identity, scope, and conditions but not binding passes P24.

**WHERE**

```python
variants = [
    ("identity", ...),
    ("conditions", ...),
    ("mutually exclusive conditions", ...),
]
```

The separate scope case changes HOST to BOOT; no case uses the same bound scope with `h1` versus `h2`.

**CLASS** A compound equality rule is tested one field at a time but one field is omitted.

**SWEEP** Enumerate every `AppliesTo` field used by the implementation’s full equality: identity, scope, binding, and conditions. For each, build a pair differing only in that field plus a fully equal success control.

**RESULT** Identity, scope, and conditions are covered. Binding is the sole omitted component.

**FIX** Add two `env.*` HOST candidates differing only in binding and require supersession refusal. Keep values and all other `AppliesTo` fields identical.

---

## 7. P25 never combines mutual exclusion with measured/asserted provenance

**FINDING  HIGH — INTRODUCED:** Moving the contradiction guard before `jointly_satisfiable` passes P25.

**WHERE** Every P25 fixture uses the default measured provenance:

```python
pool_raw = [
    raw(value=72),
    raw(value=72, identity="t_other", ...),
    raw(value=80, ...),
    ...
]
```

The mutually exclusive control is also measured/measured.

**CLASS** An ordered classifier is tested predicate-by-predicate but not at their overlap, so the ordering of the partition remains unconstrained.

**SWEEP** For each ordered predicate in `classify_pair`, construct a pair satisfying it and every earlier predicate that should suppress it: joint unsatisfiability versus equal value, measured/asserted, equal order, and incomparable order. Repeat for binding-based and condition-based unsatisfiability.

**RESULT**

- `measured(stdin)` versus `asserted(argv)` is absent.
- Same-scope candidates with different bindings are absent.
- Consequently, this incorrect edit survives:

```python
if {a.provenance, b.provenance} == {MEASURED, ASSERTED}:
    return CONTRADICTION_MEASURED_ASSERTED
if not jointly_satisfiable(a, b):
    return None
```

**FIX** Add mutually exclusive measured/asserted pairs for both conditions and bindings, and require `None` from `classify_pair` plus absence from all three conflict views.

---

## 8. P26 does not cover two of the four context-binding fields

**FINDING  HIGH — INTRODUCED:** Omitting `boot_id` or `attempt_id` from `validate_context` passes P26.

**WHERE**

```python
("host_id is an int", dataclasses.replace(CTX, host_id=7)),
("process_id is empty", dataclasses.replace(CTX, process_id="")),
```

There are no malformed `boot_id` or `attempt_id` cases.

**CLASS** Repeated-field validation is represented by examples instead of enumerating the field list being validated.

**SWEEP** Compare the implementation loop:

```python
for name in ("host_id", "boot_id", "process_id", "attempt_id"):
```

against malformed and valid controls for every name.

**RESULT** Host and process are covered; boot and attempt are not. Changing the tuple to `("host_id", "process_id")` passes P26.

**FIX** Generate the malformed cases from that same closed field-name tuple, testing both non-string and empty-string values for each field.

---

## 9. I5 remains a practically unreachable `validate_store` gate

**FINDING  HIGH — RECURRENCE:** P27 proves `_assert_acyclic` can fail when called directly, but not that the I5 call inside `validate_store` can ever be reached.

**WHERE**

```python
normalised = validate_candidate(c)  # I1
...
_assert_acyclic(seen_ids, c, set(), done)  # I5
```

and:

```python
controlled = set(mutilations) | {"I5"}
_assert_cycle_detector_fires()  # calls _assert_acyclic directly
```

The handcrafted cyclic candidates retain ids derived before their references were added. A call through `validate_store` therefore fails I1/I2 before reaching I5.

**CLASS** A positive control validates the helper out of context while the integrated absence gate remains shadowed by an earlier validation gate.

**SWEEP** For each `STORE_INVARIANTS` control, identify the actual call stack and first raised invariant. Check especially I2, I5, I5b, I7, and I9, whose validators contain multiple stages.

**RESULT** All controls except I5 enter `validate_store` or a transactional writer that invokes it. I5 alone bypasses the integration point. Removing `_assert_acyclic` from `validate_store` leaves P27 green.

Because content-derived ids make a test-constructible cycle fail I1 first, this is also a direction the valid implementation state cannot practically vary.

**FIX** Choose one honest contract:

- delete I5 from `validate_store`/`STORE_INVARIANTS` and retain `_assert_acyclic` only as a defensive helper with a narrower claim; or
- redesign graph validation so the graph walk is intentionally performed on claimed ids before digest validation, then add a `validate_store`-level positive control.

The present “store invariant with a direct helper control” satisfies neither contract.

---

## 10. Prefix-family scope enforcement is still not tested

**FINDING  HIGH — RECURRENCE:** P15 checks prefix rows as text but probes validation only for exact keys.

**WHERE**

```python
for key, spec in sorted(R.FACT_KEYS.items()):
    for scope in R.Scope:
        probe = raw(key=key, scope=scope, ...)
        ...
```

The corresponding loop never visits `_FACT_PREFIXES`.

**CLASS** Registry breadth is checked in one representation but held narrow at the behavioural boundary.

**SWEEP** Compare every exact-key and prefix-family registry consumer in `spec_for`, `emit_tables`, P12, and P15. Require at least one concrete key per prefix for behavioural probes.

**RESULT**

- Generated text equality covers all seven prefix families.
- Enforcement probing covers none of them.
- Other properties incidentally use `env.*` and `gadget.*`, but do not exhaust their allowed-scope rules.
- `attempt.*`, `leak.*`, `libc.one_gadget.*`, `plt.*`, and `sym.*` have no equivalent behavioural scope matrix.

**FIX** Factor a `(concrete_key, spec)` iterator containing every exact key and one representative per prefix, and use it for the enforcement loop.

---

## 11. P17 tests only one reachable terminal-state cause of staleness

**FINDING  HIGH — RECURRENCE:** A staleness implementation that rejects retracted sources but accepts superseded or missing sources passes P17.

**WHERE**

```python
R.retract(s, src.id, ...)
for c in chain[1:] + [right, join]:
    assert R.is_stale(s, c)
```

No source is superseded or removed. Dangling refs are explicitly valid stores, so this is not an unreachable case.

**CLASS** A multi-cause safety predicate is tested with one representative cause while the property name claims the whole relation.

**SWEEP** Enumerate each early return in `is_stale`: missing source, ref-key mismatch, non-active state by terminal state, digest mismatch, and transitive staleness.

**RESULT**

- Key mismatch: covered.
- `RETRACTED`: covered.
- Transitive propagation and diamond: covered.
- `SUPERSEDED`: not covered.
- Missing source: not covered, despite fragments making it reachable in a valid store.
- Digest mismatch: not reachable through `resolve` without violating candidate integrity or finding a digest collision, so its narrowness is harmless at the validated-store boundary.

**FIX** Add valid-store cases for a dangling ref and a superseded root. Keep digest mismatch as a direct `is_stale` unit case if that public helper’s broader contract is retained.

---

## 12. No property independently constrains the complete dedup projection

**FINDING  HIGH — RECURRENCE:** P14 kills “omit provenance,” but subtler omissions from `dedup_key` survive.

**WHERE**

```python
def dedup_key(c):
    return canonical(c.project(CONTENT_FIELDS))
```

P1 computes its oracle using the same function:

```python
expected = {R.dedup_key(c) for c in s.active(KEY)}
```

P14 varies only provenance. P2 does not merge candidates differing only in lineage, scope, or binding.

**CLASS** The behavioural oracle delegates to the predicate whose field coverage it appears to verify.

**SWEEP** For every component of `CONTENT_FIELDS`, construct a valid pair differing only in that component, merge in both orders, and require two survivors. For `applies_to`, sweep identity, scope, binding, and conditions separately.

**RESULT**

Covered elsewhere: value, provenance, method, by, identity, and conditions.

Not independently covered:

- `derived_from`;
- scope on a multi-scope key;
- binding within one bound scope.

A `dedup_key` omitting only `derived_from` passes P1, P2, P14, and P10.

**FIX** Add a direct projection property:

```python
for each CONTENT_FIELDS component:
    dedup_key(base) != dedup_key(one_component_changed)
```

and behavioural two-order merge controls for lineage, scope, and binding.

---

## 13. P17’s cycle-termination control never reaches the visited-set branch

**FINDING  HIGH — INTRODUCED:** The new cycle control returns stale on digest mismatch before recursion, so deleting cycle detection from `is_stale` still passes it.

**WHERE** `_cyclic_index` adds references after ids/digests were derived:

```python
a2 = dataclasses.replace(a, derived_from=(Ref(... candidate_digest(b)),))
```

but `is_stale` checks:

```python
if candidate_digest(src) != ref.digest:
    return True
if is_stale(store, src, seen):
    return True
```

The changed candidate’s digest no longer equals the stored ref digest.

**CLASS** A test claims to reach a recursion/cycle gate but an earlier guard determines the result.

**SWEEP** Trace both self and mutual cycles through `is_stale` in exact branch order, then repeat after deleting only:

```python
if c.id in seen:
    return False
```

**RESULT** Both current cycle fixtures still return `True` after that deletion. `_assert_acyclic` genuinely reaches its path-set guard; `is_stale` does not.

**FIX** Either remove the claim that `is_stale`’s visited set has a positive control, or test it with an injected digest function/stub store that makes the cyclic refs digest-consistent long enough to recurse. If invalid stores are outside `is_stale`’s contract, delete the defensive cycle claim instead.

# SUBTLER MUTANTS

## The eight round-3 bindings

| Binding | Specific subtler edit | Bound property catches it? |
|---|---|---:|
| `_merge_generation_from_caller -> P20` | In `_assign_generation`, enforce mismatches only when `generation > 0`, silently correcting wrong generations on a fresh store. Separately, use `terminal[0].generation + 1` instead of `1 + max(...)`. | **No / No.** The helper has no acceptance failure, and P20 has at most one terminal sibling. |
| `_jsonable_coerces_keys -> P21` | Keep mapping-key and bytes-tag rules correct, but encode enums as their raw value, tuples as arrays, sets as sorted arrays, and dataclasses as mappings. | **No.** This is already the pristine behaviour; P21 passes despite the collisions. |
| `_validate_log_shape_only -> P22` | Delete only duplicate-sequence rejection, or accept same-key supersede replacements without checking equal `applies_to`. | **No / No.** Negative fixtures have one record; the latter relation is not checked at all. |
| `_validate_conflicts_noop -> P23` | Delete only the final canonical-list-order comparison. | **No.** The alleged out-of-order control is a duplicate. |
| `_supersede_key_only -> P24` | Compare identity, scope, and conditions but omit binding. | **No.** Binding never varies. |
| `_classify_pair_value_only -> P25` | Move the measured/asserted classification before `jointly_satisfiable`; alternatively ignore binding mismatch in `jointly_satisfiable`. | **No / No.** P25 has no asserted candidate and no differing bindings. |
| `_validate_context_noop -> P26` | Validate only `host_id` and `process_id`, omitting `boot_id` and `attempt_id` from the loop. | **No.** Neither omitted field is malformed in P26. |
| `_validate_store_noop -> P27` | Keep I9 generally active but delete only conflict-list ordering; or keep I7 but delete only duplicate-seq rejection. | **No / No.** P27’s I9 control is a non-`Conflict`, and its I7 control is a dangling id. |

Each surviving mutation corresponds to a HIGH finding above.

## Other coarse or overbroad mutants

The noteworthy additional cases are:

- `dedup_ignores_provenance -> P14`: too narrow to establish `CONTENT_FIELDS`; omitting only `derived_from`, scope, or binding survives.
- `unsorted_candidate_array -> P2`: the combined mutant is caught by candidate ordering. Removing only resolution-list sorting survives because the seeded log never changes order.
- `state_allows_resurrection -> P11`: allowing absent supersede, active append, or returning the wrong active terminal state survives P11 itself. P15’s committed table provides secondary coverage.
- `resolve_fabricates_witness -> P8`: fabricating only an operator-pin witness survives P8.
- `conflicts_only_incomparable -> P13`: P13 never reaches `AMBIGUOUS_ACROSS_IDENTITIES`; its “every class” statement names only four of the five `classify_pair` classes.
- `pins_first_wins -> P16`: a variant retaining correct latest-seq folding but collapsing all keys into one global pin survives; P16 has no two-key valid history.
- `specificity_reads_value -> P5b`: reading binding, generation, key, actual identity label, or id is not independently perturbed by P5b.
- `staleness_ignores_dead_sources -> P17`: checking only `RETRACTED`, while ignoring `SUPERSEDED` and missing sources, survives.
- `resolve_returns_default_on_empty -> P12`: returning a default only for a prefix-family key survives because only exact keys are queried.

The broadest mutants caught through an easier subrule rather than the claimed full rule are:

- `conflicts_unvalidated`, caught by a non-`Conflict`, says nothing about later I9 clauses;
- `store_invariants_disabled`, caught by any one control, says nothing about clause-level controls;
- the combined `unsorted_candidate_array`, caught by candidate ordering, says nothing about resolutions;
- `log_shape_only`, caught by referential examples even though duplicate-sequence and causal-history coverage remain absent.

The remaining mutants are reasonably aligned with their bound property: rank-based merge, terminal dedup, non-functional/arrival ids, provenance rank, time tiebreak, both digest mutations, validation funnel removal, observation append, always-refuse, and first-element maximality all alter the exact relation their property observes.

# ANSWERS

## (2a) Can breadth validation be mechanical?

Not completely without annotation. A machine cannot infer which semantic dimension a property intends to constrain or which equivalences are legitimate. It can, however, mechanically verify whether an annotated claim is true.

A concrete implementation would:

1. Run each property under a current-property context.
2. Instrument the public functions it calls—`merge`, `resolve`, `conflicts`, `compare_specificity`, `validate_candidate`, and `validate_store`.
3. At each call, record dimension projections from candidates, stores, and contexts.
4. Assert that each claimed varied projection has cardinality greater than one and each claimed constant projection has cardinality one.
5. For relational dimensions, record the relation, not merely raw fields.

The last point is essential. `process_id` changing in P6 should not count as binding variation when every candidate is BUILD-scoped. The relevant projection is something like:

```python
(
    candidate.applies_to.scope,
    candidate.applies_to.binding,
    context.binding_for(candidate.applies_to.scope),
    candidate.applies_to.binding == context.binding_for(candidate.applies_to.scope),
)
```

Likewise, `terminal_sibling` should record counts and generation sets, not a Boolean; `arrival_order` should be separated into candidate order, resolution-record order, conflict-record order, and dependency arrival order.

The cleanest design is to make each property expose a case generator and define dimension projectors over those cases. Runtime instrumentation is possible, but explicit case generators are easier to review and less likely to count setup data that never reaches the target function.

Branch coverage is complementary, not a replacement. It can prove that a condition toggled, but not that the semantically relevant value relation varied.

## (2b) Can the annotation gate accept false claims?

Yes. The current three meta-tests prove only:

- the table has one row per property;
- names come from a closed vocabulary;
- the declarations are syntactically non-contradictory;
- every dimension has at least one claimant.

A false but well-formed assertion passes. Current examples include:

- P2 claims `log_record_count` varies, but `_seeded_store` always contributes one record and batch merges add none.
- P3 claims `observation_at` is constant, but it explicitly changes `t1` to `t2`.
- P6 and P25 claim context binding variation, but all candidates are BUILD-scoped.
- P8 claims identity and conditions are constant, but both vary in `pool_raw`.
- P10 claims scope and conditions vary, but only identity inside `applies_to` changes.
- P16 claims candidate `observation_at` varies, but it is log `at` that varies.
- P5b’s claimed candidate-id variation is not an independent id perturbation.

The cheap check is the runtime projection recorder above. It would catch false annotations immediately. It still needs hand-authored projectors and target annotations, but it verifies the facts instead of trusting prose.

## (3) Trust-boundary statement

The statement is too broad. Authenticity is not expressible purely in-process, but substantial internal consistency is.

Expressible now:

- sequence numbers are positive, unique, and—if writer reachability is normative—dense from 1;
- at most one terminal event exists per candidate;
- supersede target and replacement describe the same proposition;
- a replacement was not already terminal at the supersede sequence;
- lower-generation siblings reached terminal state before higher generations appeared;
- terminal-event sequence increases along a generation chain;
- every terminal candidate has its matching event, already partly enforced by I8.

Also expressible as a property test is writer reachability: generate histories only through public writers, derive invariants from them, then mutilate one relational fact and require validation failure.

Not inherently valid without an additional policy:

- actor consistency across a causal chain—different operators may legitimately perform successive actions;
- monotonicity of free-text `at`;
- list order matching `seq`, because `seq` is explicitly the semantic order and canonicalisation sorts by it.

Only partly detectable:

- sequence gaps can reveal middle-record deletion or malformed construction, but not deletion of the last record and not a capable forger who renumbers everything;
- retroactive insertion is detectable if it creates a duplicate, gap, or impossible lifecycle order.

Not testable from this process alone:

- whether `actor` corresponds to a real person;
- whether an otherwise self-consistent history was forged wholesale;
- whether a retroactive record and all subsequent sequence numbers were rewritten coherently.

Those require an external trust anchor: a signature/HMAC key unavailable to the mutating process, an externally committed hash-chain head, or append-only storage outside the caller’s capability. An unkeyed hash chain stored in the same document does not solve this; the in-process forger can recompute it.

# THE DEAD GATES

I found four relevant dead or unproved gates:

1. **I5 inside `validate_store` is shadowed by I1/I2.** The direct cycle control proves `_assert_acyclic` can raise, but its handcrafted candidates cannot pass candidate-id validation. The integrated I5 gate is therefore practically unable to go red.

2. **P20’s `_merge_expecting_refusal` does not fail on acceptance.** Its `except` branch checks rollback, but the successful path simply returns.

3. **P17’s `is_stale` cycle control exits on digest mismatch.** It does not reach the visited-set branch it claims to validate.

4. **P23’s out-of-order conflict-list control is not out of order.** It creates a duplicate and trips the earlier duplicate check. The final canonical-order gate has no positive control. The same issue exists for `_validate_log`’s duplicate-sequence gate: all negative P22 histories contain one record.

I also checked the other requested shapes:

- Unknown-field rejection has live controls at candidate, `applies_to`, observation, and derived-ref levels.
- The validation funnel has a genuinely hostile mapping control and can fail.
- The exception swallowing in `test_enumeration_bounds_are_reported` is explicitly reporting-only; it should not be cited as proof of correctness, but `test_property` remains the actual gate.
- I did not find another unknown-field or stale-entry absence check whose only control was already guaranteed by an earlier check beyond the I5, log-sequence, conflict-order, and cycle cases above.