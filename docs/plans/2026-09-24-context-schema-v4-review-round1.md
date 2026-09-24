# Independent plan review, round 1 on v4 — standardized context schema

Verbatim review of **v4 as first drafted** (commit `af7ffb0`) of
`2026-09-24-standardized-context-schema.md`.

- **Date:** 2026-09-24
- **Reviewer:** gpt-5.6-sol, `model_reasoning_effort=xhigh`, `--sandbox read-only`
  (independent same-tier peer; the plan itself was drafted on Opus 5)
- **Method:** plan inlined into the prompt on stdin, plus the
  `DetailedProtections` code facts and the v1/v2/v3 rejection history. The
  reviewer read no filesystem and ran no commands, so it could not be misled
  by stale context.
- **Verdict:** **NOT-APPROVED** — 11 `HIGH`, 2 `MEDIUM`, 1 `LOW`.
- **Disposition:** all 11 `HIGH` and both `MEDIUM` accepted and addressed in
  v4 rev 2; see the plan's "Review record — round 1 on v4" for the per-finding
  resolution. Finding 1 is the structural one: the reviewer is right that a
  plan describing a reference implementation is still prose. It reordered the
  work — the implementation was built and the **code** was re-reviewed in
  round 2 rather than the prose being iterated a fourth time.

---

NOT-APPROVED

1. HIGH — The promised reference implementation is not present

   This is still a prose specification with pseudocode. The actual `merge`, `resolve`, canonicalization, document digest, pin selection, and generated tables are absent. The method change therefore relocates ambiguity into future code rather than closing it. It also contradicts the stated mitigation that the resolver would be inlined for review.

2. HIGH — Merge’s branches are not genuinely disjoint or total

   An invalid incoming value can also match an existing invalid candidate’s dedup key; priority makes the implementation deterministic, but the predicates still overlap. Conversely, validating only the key’s value type/shape does not guarantee that malformed provenance, `applies_to`, IDs, or non-canonicalizable metadata cannot throw an undeclared exception.

   If multiple stored candidates share the dedup key, “some `c`” does not specify which candidate receives the observation. This is reachable through hand-authored documents unless validation explicitly forbids duplicate dedup keys.

3. HIGH — Deduplication mishandles terminal candidates and loses immutable evidence

   Because state is absent from the dedup key, reobserving a fact matching a retracted or superseded candidate updates that terminal candidate and produces no active fact. If active and terminal matches coexist, the mutation target is unspecified.

   The key also omits ID, method, evidence, verification, `derived_from`, author, and observation origin. Two measured values obtained from different sources collapse, with whichever arrived first retaining its dependencies and verification state. A later verified observation can remain permanently represented as `unverifiable`.

4. HIGH — The commutativity claim is false

   Two candidates with equal dedup keys but different IDs, evidence, verification, or dependencies leave different survivors depending on insertion order; those fields are digest-bearing. `last_observed_at` is also order-dependent unless merge explicitly takes a maximum.

   Even two nonduplicate appends reverse the candidate-array order. Canonical JSON does not sort arrays, so a document digest cannot be permutation-invariant unless a separate order-independent document-digest projection is defined. No such projection is specified.

5. HIGH — An ordinary assertion can silently beat a contradictory measurement

   Provenance is consulted only after identity binding, scope, and condition count. A measured build-scoped value of 72 and an asserted process-scoped value of 80, both applicable to the current process, select 80 before provenance incomparability is reached. An identity-bound assertion likewise beats an identity-agnostic measurement.

   P9 only describes an “equally-applicable” pair and does not prohibit this path. The required invariant must apply across all applicable contradictory measured/asserted pairs, not merely pairs tied on the first three components.

6. HIGH — The total scope order encodes a false containment relationship

   `libc_file` and `host` are independent axes. For `libc.system_offset`, consider a correct candidate measured from the exact libc artifact with scope `libc_file` and a conflicting host-scoped candidate bound to the same libc identity. The host candidate wins solely because `host` is later in the tuple, although artifact identity is the relevant validity domain.

   No per-key allowed-scope constraints prevent this input. A product or partial order is required; one global lifetime order is not semantically valid for every key.

7. HIGH — Supersession and pin lifecycle remain undefined

   The functions exist, but no actor, automatic policy, or CLI operation is assigned responsibility for calling them. Equal-maximal conflicts are reported only when that key is resolved; producer-only workflows can accumulate them silently, while dominated contradictions are never reported at all. The promised `conflicts[]` has no computation rule.

   `resolutions[]` is append-only, yet repeated pins for the same key have no current-pin rule. “If `ctx.pins` holds a pin” does not define how multiple historical records become that mapping. Thus resolution is not total over a valid, naturally reachable document.

8. HIGH — Value agreement conflates equal encodings with equal propositions

   Under `--target-identity=none`, two `gadget.pop_rdi` candidates from different builds can both contain integer `0x401234`. They are canonically equal but refer to different instructions and are not evidence of agreement.

   Choosing `min(id)` also selects arbitrary provenance, verification, evidence, and dependency lineage. Random IDs make the witness vary across document construction; content-derived IDs require a specified projection and become circular if ID is included in `DIGEST_FIELDS`. Resolution should preserve the agreeing set or select a witness by a defined semantic rule.

9. MEDIUM — The specificity relation is conditionally valid, but “specificity” is underspecified

   Lexicographic composition is a strict partial order if every component comparator and its equality relation are total/transitive as claimed. Dropping time is appropriately conservative. However, condition count is not logical specificity: two unrelated one-condition predicates compare equal, while two redundant conditions beat one stronger condition. Repeated contradictory measurements at otherwise equal specificity will also refuse indefinitely, which becomes operationally common without an exposed supersession workflow.

10. HIGH — State-excluded digests need one authoritative staleness mechanism

   Excluding state can be sound because a dependent can be declared stale whenever its referenced source is non-active. The plan nevertheless alternates between dynamic recursive staleness, a mutable persisted `stale` field, event-driven closure invalidation, and pin-driven invalidation of “rejected” candidates that remain active. It does not choose one mechanism or define its transactional updates.

   References also require globally unique candidate IDs, but merge neither enforces ID uniqueness nor includes the key in `derived_from`. An ID collision makes dependency resolution ambiguous.

11. HIGH — Several properties and mutant claims are vacuous or false

   P1 checks only the exit type; a total resolver that supersedes on rank still passes it. A rank-based superseder can also be permutation-invariant, so `merge_supersedes_on_rank` need not fail P2.

   A timestamp tiebreak remains invariant under candidate-list permutation, so `specificity_breaks_ties_by_time` does not necessarily fail P7. Ignoring provenance during dedup does not affect P9’s contradictory-value case because different values do not dedup. A fabricated `Selected` default can pass P6’s allowed-return-type check, although P12 may catch it. Dedicated semantic-oracle properties are needed, not merely totality/codomain checks.

12. HIGH — “Exhaustive enumeration” has no defined finite bound

   No maximum store size, batch length, candidate count, condition universe, ID domain, timestamp set, pin count, or dependency-graph depth is stated. “Every batch and every permutation” is infinite without those bounds and factorial even under modest bounds. The five-provenance/six-scope product does not make arbitrary stores bounded. P2 and P7 therefore are not executable exhaustive claims as written; exact bounds and any symmetry reduction must be normative.

13. MEDIUM — The generated-table byte gate provides only drift detection

   It adds real safety only if rendering directly invokes the same comparisons and transitions used at runtime. A generator backed by parallel constants can agree byte-for-byte with itself while disagreeing with resolution. The gate proves neither completeness nor correctness and cannot compensate for the absent reference implementation.

14. LOW — The inlined code counts are internally consistent

   The 22 declared fields, 16 emitted fields, six `_UNMEASURED` fields, and 32-command count are reproduced consistently. No factual contradiction with the supplied code facts is apparent.