# Independent review — standardized context schema, v4 rev 3 (round 3)

- **Date:** 2026-09-24
- **Reviewer:** `gpt-5.6-sol`, `model_reasoning_effort=xhigh`, `--sandbox read-only`
- **Subject:** `docs/plans/2026-09-24-standardized-context-schema.md` (v4 rev 3) plus
  the reference implementation `supwngo/schema/resolve.py`, the mutant bank
  `supwngo/schema/mutants.py`, and the property suite
  `tests/test_context_resolve_properties.py`.
- **Method:** all four artifacts were **inlined into the prompt** and the reviewer
  was instructed not to read any files, so the verdict cannot depend on a stale
  or partial working tree. The reviewer was told the reported test result
  ("53 passed") was **not** to be trusted and was asked to decide for itself
  whether each property can actually fail. Twelve interrogation questions were
  posed, including "name a validation step that cannot fail" and "name an input
  for which `resolve` exits some way other than `Selected` or one of the five
  declared refusals".
- **Verdict:** **NOT-APPROVED** — 9 HIGH, 5 MEDIUM, 2 LOW.
- **Disposition:** see "Review record — round 3 on v4" in the plan. Every HIGH
  reproduced as an executable test before being fixed; the two dead validation
  steps it names were deleted rather than defended.

The review is reproduced **verbatim** below. Nothing is elided, reordered, or
softened.

---

NOT-APPROVED

1. HIGH — `generation` is still caller-controlled, making merge order-dependent

   On a fresh store, merge two same-dedup candidates with `generation=0` and `generation=5`. Whichever arrives first supplies the surviving generation and ID; the second dedupes into it. Reversing arrival order changes canonical bytes. With a retracted generation-0 candidate, an explicitly identified generation-1 candidate succeeds first, while an explicitly identified generation-5 candidate fails if sent first. Also, `merge(validate_candidate(raw))` can fail after retraction because validation necessarily supplies the now-“stale” ID. I6 prevents two equal IDs from persisting, but it does not make generation store-assigned.

2. HIGH — Candidate validation accepts malformed shapes

   Falsey malformed values are silently normalized: `id=0`, `applies_to.conditions=0`, `derived_from=0` on a non-derived candidate, and observation `evidence=0` are accepted. Unknown fields inside `applies_to`, observations, and refs are discarded. Thus the validation funnel controls exception type but does not validate the whole supplied shape.

3. HIGH — Canonicalization is not canonical for allowed evidence

   `_jsonable` stringifies mapping keys. Equal mappings containing keys `1` and `"1"` can canonicalize differently depending on insertion order because their sort keys tie and one projected key overwrites the other. Bytes also collide structurally with strings beginning `b64:`. Since observation union is keyed by this digest, distinct evidence can be discarded and equivalent evidence can become order-dependent.

4. HIGH — Two validation steps provably cannot fail

   `canonical(candidate.value)` cannot fail after every current `FactSpec` has restricted the value to `int`, `bool`, or `str`. Likewise, the `_ID_RE` check immediately after fixed `derive_id()` cannot fail. These violate the explicit non-negotiable constraint against dead validation.

5. HIGH — I7 does not prevent forged pins or validate lifecycle history

   Any caller can append a well-shaped `PinRecord` directly to the public `resolutions` list; `validate_store` accepts it and `resolve` honors it. Candidate existence, candidate/key agreement, known keys, nonempty reasons, required `by_candidate_id`, and consistency with candidate state are not checked. An integer `candidate_id` or `by_candidate_id` makes `_ID_RE.match` leak `TypeError` from `merge`’s pre-write validation instead of `SchemaError`.

   Out-of-order records and sequence gaps are harmless because the fold takes the maximum sequence, and interleaved lifecycle records do not disturb pin ordering. The problem is that sequence values and actors are freely forgeable. A pin whose target later becomes terminal safely raises `PinInapplicable`, but it remains globally active until explicitly unpinned.

6. HIGH — I1–I7 are insufficient to protect the complete store

   `validate_store` does not validate `store.conflicts`, conflict uniqueness, conflict referential integrity, generation histories, or whether a terminal state has a corresponding lifecycle record. It also ignores the normalized candidate returned by `validate_candidate`; consequently, a constructed candidate containing duplicate or noncanonical observations can pass validation because observations are outside the ID digest.

   For example, a malformed object in the public `conflicts` list can survive a conflict-free merge and later break `canonical_document`. Neither `resolve` nor `canonical_document` validates the store. Snapshot/rollback is sound for ordinary failures after the snapshot, but malformed public state can be accepted or can leak non-`SchemaError` exceptions before it.

7. HIGH — `supersede` does not enforce “same proposition”

   It checks only that the keys match. A candidate for another identity, process binding, boot, mutually exclusive condition set, or—for `env.*`—another scope can supersede an unrelated candidate. That silently destroys a still-valid fact. Supersession chains themselves cannot cycle through dead replacements because replacements must be active, but the proposition-equivalence check remains missing.

8. HIGH — Conflict reporting is internally inconsistent

   Equal-valued candidates from different identities make `agreeing()` false and therefore make `resolve()` raise `FactUnresolved`, yet `classify_pair()` returns `None`, so neither `conflicts()` nor `context_free_conflicts()` reports them. P19 tests the refusal but not this reporting hole.

   Conversely, `context_free_conflicts()` records pairs that can never be jointly applicable, such as different process bindings or mutually exclusive conditions. These records persist after lifecycle changes and are not consulted by resolution. The stored list, dynamic context-free view, and context-sensitive view are therefore three different notions of conflict, not one source of truth.

9. HIGH — `resolve` is not total over its public context type

   `ResolveContext` is never validated. With an active identified candidate, `ResolveContext(identities=None)` leaks `TypeError`; malformed condition pairs can leak `ValueError` from `dict()`, and an unknown `identity_mode` is silently treated as strict mode. This contradicts the claim that every exit is `Selected` or one of the five declared refusals. P6 exercises only one well-formed context.

10. MEDIUM — The assertion-versus-measurement rule is correct only for well-formed stores

   With validated state, applicable contradictory measured/asserted candidates remain unresolved under strict mode and `identity_mode="none"`; `try_resolve` does not soften that refusal, and an inapplicable measurement is correctly excluded. A validated pin is the only normal bypass. The forged-log path in finding 5 defeats the claimed “only writer” guarantee.

11. MEDIUM — Several property claims remain materially broader than their tests

   P1b correctly distinguishes `SchemaError` from other exceptions for its listed cases, but misses malformed falsey shapes and malformed existing stores. P2 merely verifies that seeded resolutions and dependencies appear in the document; those structures are fixed across every permutation, and it omits generation variants. P5’s composed-order universe omits three scopes, so a scope-specific defect in `compare_specificity` can pass. P6 and P7 are now non-vacuous against constant refusal, but remain only coarse liveness checks. P13’s oracle delegates to the same runtime component comparators and excludes the cross-identity equal-value ambiguity. P16 does not test most of I7’s missing referential and class-specific rules.

12. MEDIUM — P15 does not re-derive every claimed table cell

   Its `zip` checks do not assert row widths, merge rows are checked only for required-row presence, prefix registry rows are not checked, and neither `depends_on` nor `verification_class` is checked. The exact-key scope test covers only 9 of the 16 registry rows. A synchronized but malformed generator and committed file can therefore pass portions of this gate.

13. MEDIUM — P17’s cycle “unconstructibility” test is vacuous

   `self_ref` retains `solo.id` after changing digest-bearing content, so `validate_store` rejects it at I2 before exercising `_assert_acyclic`. `is_stale` returns true because its digest mismatches before recursion. One hash iteration not returning the starting ID does not prove that cryptographic fixed points or mutual cycles are structurally impossible. The actual `Ref.key` check is sound for an I6-valid store and does not create false staleness.

14. MEDIUM — Store validation is substantially worse than the stated quadratic walk

   Cycle checking restarts DFS for every candidate and performs a linear `by_id` scan for every edge, reaching quartic behavior on dense dependency DAGs. Conflict recording repeatedly performs linear membership checks and sorts a quadratic-sized list, also approaching quartic work. This exposes merge to avoidable size-based denial of service.

15. LOW — Mutation coverage is existential, not comprehensive

   From inspection, each listed bound mutant should fail its named property. Splitting non-functional IDs into P10 and arrival-assigned IDs into P2 is honest: I2 prevents a genuinely random ID implementation from reaching document comparison. `_ArrivalOrderFactStore` is adequate for this sequential test but is unsafe for concurrent or coexisting stores because it resets module-global state.

   `test_every_property_has_a_mutant` is therefore a useful smoke test, but it can be satisfied by one narrowly tailored mutant per property and says nothing about unmutated branches such as generation handling, conflict classification, or I7 referential validation.

16. LOW — The advertised public API and comments are inconsistent

   `pin`, `unpin`, and `context_free_conflicts` are omitted from `__all__`; the module-level purity claim omits the mutations performed by `pin` and `unpin`; and the ref-sorting comment says two refs with the same `(key,id)` but different digests are different facts immediately after validation rejects exactly that case.