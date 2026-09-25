# Independent implementation review, round 2 on v4 — standardized context schema

Verbatim review of the **reference implementation** at commit `670e7f7`:
`supwngo/schema/resolve.py`, `supwngo/schema/mutants.py`,
`tests/test_context_resolve_properties.py` and
`docs/reference/context-resolution-tables.md`.

- **Date:** 2026-09-24
- **Reviewer:** gpt-5.6-sol, `model_reasoning_effort=xhigh`, `--sandbox read-only`
  (independent same-tier peer; the implementation was written on Opus 5)
- **Method:** all four files inlined into the prompt on stdin with an explicit
  "Do NOT read any files / do NOT run any commands" instruction, plus the
  round-1 findings the code claimed to close, the non-negotiable operator
  constraints, and the *reported* test result offered explicitly as something to
  distrust and check against the code. The reviewer read no filesystem and ran
  no commands. Output asserted non-empty before the gate was considered
  satisfied.
- **Verdict:** **NOT-APPROVED** — 11 `HIGH`, 2 `MEDIUM`, 1 `LOW`, 1 `LOW`
  confirming the core order composition is sound.
- **Disposition:** every `HIGH` accepted; none argued away. See the plan's
  "Review record — round 2 on v4" for the per-finding resolution. Three findings
  (part of 8, the `reason_at` half of 9, and parts of 12) described defects that
  a self-audit had **already** fixed in the working tree after `670e7f7` was
  handed over; those are marked as such rather than counted twice, because the
  reviewer was reading the commit it was given and was right about that commit.

The single most consequential finding is 2 + 6 taken together: retract a
candidate and re-merge the same assertion, and the terminal and live siblings
received the *same* id, which then broke `by_id`, pins, dependency lookup, the
conflict record and array ordering simultaneously. That is fixed by a
store-assigned `generation` counter inside the id digest, and ids widened from
48 to 128 bits.

---

NOT-APPROVED

1. HIGH — `merge()` is not total over arbitrary input.
   Its two post-validation branches are disjoint, but validation leaks ordinary exceptions. For example, `observations=1`, `derived_from=1`, or `applies_to.conditions=[("x",)]` raises `TypeError`/`ValueError`, while heterogeneous unknown field names can fail inside `sorted()`. Direct `Observation` and `Ref` instances also bypass their field validation. These must all become `SchemaError`.

2. HIGH — Normal operations produce a store that violates I6.
   Retract a candidate and merge the same semantic candidate again. Because `state` and observations are excluded from `derive_id`, the terminal and new active candidates receive the same ID. `validate_store()` then reports a duplicate ID; `by_id()` becomes ambiguous; the re-observation conflict contains the same ID twice; dependency and transition behavior depends on which duplicate is encountered first.

3. HIGH — The state machine is bypassed by `merge()`.
   An incoming mapping may specify `state="superseded"` or `"retracted"` and is appended directly, despite the transition table allowing only `absent + append -> active`. This also provides another merge-only route to duplicate terminal/active IDs. The transition property tests a table that `merge()` does not actually use.

4. HIGH — `merge()` neither establishes nor checks the advertised store invariants.
   I3 is preserved only when starting from an already-valid store. A directly populated store can contain two active candidates with the same dedup key; `merge()` raises only when the incoming candidate happens to match that key and otherwise leaves the violation untouched. `validate_store()` is never called before or after mutation. Thus the claimed transactional invariant boundary does not exist.

5. HIGH — Lifecycle mutations are not transactional or semantically constrained.
   `retract(store, id, None)` changes the candidate state and then raises `TypeError` in `reason_at()`, leaving an unlogged mutation. `supersede()` permits self-supersession, cross-key supersession, and supersession by a retracted or superseded candidate. Retractions and pins record no actor, contrary to the claimed named-actor lifecycle.

6. HIGH — Twelve-hex-character IDs are inadequate for identity, ordering, and canonicalization.
   A 48-bit digest permits feasible birthday collisions. Distinct active candidates with the same ID are accepted by `merge()`, making `by_id()`, pins, dependency lookup, and witness selection ambiguous. `canonical_document()` sorts candidates only by this truncated ID, so equal-ID entries retain prior list order. The reachable terminal/re-observation duplicate-ID case demonstrates this without requiring a hash collision. Resolutions have the same truncated-digest tie problem.

7. HIGH — Dependency-reference invariants are incomplete.
   `validate_store()` checks cycles but does not verify that `Ref.key` matches the referenced candidate, and `is_stale()` ignores `Ref.key` entirely. A structurally false reference can therefore be considered fresh. `Ref` instances can contain empty or malformed IDs/digests, and refs with the same `(key, id)` but different digests are not canonically ordered because the sort key omits `digest`.

8. HIGH — Conflict and agreement reporting is semantically wrong and is not performed “on every write.”
   No write operation calls `conflicts()`; `FactStore.conflicts` contains only re-observation records, so producer-only writes still silently accumulate ordinary contradictions. An equal-specificity, differing-value pair is labeled `DOMINATED` even though neither candidate dominates the other. `agreements()` also reports equal values across different identities as agreement, directly contradicting `agreeing()` and P19. Superseded re-observations are mislabeled `REOBSERVED_AFTER_RETRACTION`.

9. HIGH — Pin selection is deterministic but not a valid “latest pin” rule.
   `PinRecord.at` is an unvalidated string. A later `"t10"` record loses to `"t9"` lexicographically, and equal or empty timestamps select whichever record has the larger truncated content hash. There is no validated pin/unpin writer or actor field; callers mutate a public list directly. `reason_at()` does not itself affect pins because lifecycle records are ignored, and it does not break byte sorting, but it does not solve pin chronology.

10. MEDIUM — The asserted-versus-measured guard works only because unvalidated records are trusted as operator pins.
    For active applicable candidates, provenance-first ordering plus `contradiction_guard()` does prevent a contradictory assertion from winning; `identity_mode="none"` and `try_resolve()` do not bypass it. An inapplicable measurement does not contradict the current contextual proposition. However, any directly appended `PinRecord` disables the guard, with no actor, validation, or authorization proving it was an explicit operator decision.

11. MEDIUM — The digest partition is locally correct, but its safety assumptions are violated elsewhere.
    The dataclass fields are partitioned as claimed, value changes alter the dependency digest, and excluding state is safe only when IDs uniquely identify immutable candidates and terminal candidates cannot be resurrected or duplicated. The terminal re-observation collision invalidates those assumptions. Selecting `winners[0]` by truncated ID also leaves the singular `witness` semantically arbitrary even though the full witness set is retained. Two identity-agnostic winners with the same value are reasonably agreement for the current context; that is not the defect.

12. HIGH — Several properties are materially toothless or far narrower than claimed.
    P6’s `assert ... or True` permits `FactUnavailable` for every nonempty pool; a resolver that always refuses passes P6 and P7. P8 checks one unique witness twice because its measured candidate dominates the assumed candidate. P13 checks pair presence but never the assigned classes. P17’s alleged cyclic case returns on a digest mismatch before traversing the cycle. P2 omits terminal states, dependencies, `by`, identity variations, resolutions, conflicts, and equal-ID ordering. P5 omits the two-condition case and would not reject a count-based condition comparator merely for treating unrelated singleton conditions as equal. P15 parses only provenance cells, so a constant generator could conceal divergence in scope, transition, or merge tables.

13. HIGH — The mutation claims and meta-test do not establish test effectiveness.
    All 19 mutants with a non-`None` binding appear capable of failing their named fixture, but six properties—P1b, P3, P5b, P6, P7, and P17—have no bound mutant, contradicting “every property is paired.” Catching any `BaseException` counts patch crashes such as `TypeError` or `NameError` as semantic detection. The two must-pass mutants prove only the narrow P9 non-selection outcome: disabling the guard changes the refusal class, while provenance-fourth still changes derived/asserted ordering and same-value witness behavior.

14. HIGH — Verification and dependency metadata are dead declarations.
    `depends_on` and `verification_class` are emitted into documentation but never consulted by validation or resolution. `resolve()` has no loaded-binary or tooling input and performs no read-time verification, despite the comments promising it. A `DERIVED` candidate need not have dependencies, and an instruction or symbol candidate resolves without the declared verification. If another module supplies this enforcement, that required code is absent from the proposed normative implementation.

15. LOW — The core partial-order composition itself is sound.
    On normalized candidates, set inclusion for conditions is a partial order, and the halt-on-first-non-equal lexicographic composition is transitive. The shared visited set in `is_stale()` also does not mask staleness in a collision-free DAG diamond: the first traversal either finds the stale source or fully proves the shared node fresh. Its practical unsoundness comes from ambiguous IDs and insufficient validation, not the diamond traversal rule.
