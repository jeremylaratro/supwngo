<!-- Preserved verbatim from an ephemeral peer-review output file.
     Original path : /tmp/codex-out/schema-v3-review.md
     Written       : 2026-09-24 00:43:36 (file mtime)
     sha256[:16]   : 77cd3bb94a9d1e0a
     Bytes         : 6052
     Subject       : context schema v3
     Rescued       : 2026-09-24, because /tmp does not survive a reboot and
                     this review was not recorded on any branch. Body is unedited;
                     only this header was added. The reviewing model/effort is
                     whatever the body states -- not asserted here. -->

## Prior findings

- **A — Merge behavior internally contradictory: NOT FIXED.** The table has overlapping rows, does not define comparisons against multiple existing candidates, and calls `(applies_to, value)` an “exact duplicate” while ignoring provenance and evidence.
- **B — Different-scope coexistence unrepresentable: FIXED.** Candidate sets retain independently scoped and conditioned values without forcing them into one key→value slot.
- **C — Verification gate unsafe/unimplementable: PARTIALLY FIXED.** The registry and honest `unverifiable` result address non-address facts and missing tooling, but “verify a sample,” per-key overrides, and how successful verification affects identity applicability remain undefined.
- **D — Staleness cascade may not terminate: FIXED.** Validation rejects cycles and dangling references, while invalidation traversal uses a visited set.

- **Provenance mutated to express applicability: FIXED.** Mismatched candidates retain their original provenance and are filtered by applicability.
- **Target identity internally inconsistent: PARTIALLY FIXED.** First-class observed identities fix stale-envelope attribution, but verified digest mismatches still conflict with `resolve()` discarding identity mismatches.
- **Libc identity missing: FIXED.** Libc artifacts now have independent identities carrying their own digest, build ID, and version.
- **Process/attempt scopes lack IDs: FIXED.** The design requires `run_id`, `process_id`, and `attempt_id` references and checks them during resolution.
- **`--resolve` cannot identify same-provenance candidates: FIXED.** Stable candidate IDs provide unambiguous addressing.
- **Concurrent-write safety: FIXED.** A stable sidecar lock covers the complete read-modify-validate-replace transaction.
- **History sidecar is a second authority: FIXED.** Superseded and retracted candidates remain in the normative document.

- **Equal-value dedup versus idempotence: NOT FIXED.** Dedup ignores provenance/evidence and mutates `last_seen`, contradicting strict repeated-merge idempotence and changing the candidate digest unless explicitly excluded.
- **`KNOWN_LOSSY` weakening preservation: FIXED.** Loss is restricted to deprecated fields with migration rules, while unknown fields must survive unchanged.

## Remaining blocking defects

Yes.

1. **`merge()` is not a deterministic function over a candidate set.**  
   The first row—“no candidate with same `applies_to` and same value”—also matches every different-value conflict, overlapping the rank rows. With several existing candidates, an incoming rank may be higher than some, equal to another, and lower than another; the plan never defines whether comparison is against all active candidates, the maximum rank, or candidates grouped by value.

2. **Equal-value dedup has incorrect semantics.**  
   An asserted observation with the same value as an assumed observation is deduplicated into the assumed candidate instead of preserving or upgrading the stronger assertion. Different methods, evidence, verification states, and derivations are likewise collapsed despite not being exact duplicates.

3. **Manual resolution has no normative state transition.**  
   `--resolve <candidate_id>` records a resolution and invalidates rejected dependencies, but the plan does not say whether losers become superseded/retracted, how the key’s unresolved state is cleared, or where `resolve()` consults the recorded selection. As written, the candidates can remain active and the key remain unresolved, so the command may not affect later resolution.

4. **The unresolved state is underspecified and too coarse.**  
   Equal-rank conflicts leave both candidates `active` while “the key is unresolved,” but no normative key-level field or conflict-set representation is defined. A global unresolved flag could also block an unrelated identity or scope whose applicable candidates are unambiguous.

5. **The specificity order is not fully defined.**  
   “Narrower scope” lacks a normative order or partial-order rules; `build`, `libc_file`, and `host` are not self-evidently nested lifetimes. “More conditions matched” does not define treatment of invocation attributes that are absent rather than contradictory. The design also says every candidate names an identity while ranking identity-bound over identity-agnostic candidates.

6. **Identity verification and identity matching remain contradictory.**  
   Successful instruction verification after a digest mismatch is presented as permitting reuse, but resolution still discards the old identity as mismatched. Only `--target-identity=none` explicitly permits such selection, which makes ordinary successful verification ineffective. The sample-selection rule and recorded per-key safety override also lack normative representations.

7. **`last_seen` breaks dependency digests.**  
   `derived_from` records a digest of the candidate’s canonical form, and any source digest change invalidates dependents. Because identical merges update `last_seen`, every repeat observation changes that digest and makes the dependent closure stale unless volatile fields are explicitly excluded from candidate digests.

The merge table plus `resolve()` ordering is therefore **not yet genuinely deterministic and total**. A fully specified resolver may validly return `FactUnresolved`; errors can be part of a total result. Here, however, overlapping merge predicates, undefined set-wide comparisons, undefined scope ordering, and missing persisted-resolution semantics prevent reaching that point.

Specificity can still tie in ways that matter—for example, two applicable candidates can have equally sized but different condition sets, equal rank, and identical timestamps while carrying different values or dependency lineage. Returning `FactUnresolved` for such a tie is acceptable, but it must be defined per applicable conflict set. Even equal-valued candidates can matter because their IDs, evidence, verification results, and `derived_from` lineage differ.

**REJECT**