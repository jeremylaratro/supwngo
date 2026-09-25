<!-- Preserved verbatim from an ephemeral peer-review output file.
     Original path : /tmp/codex-out/schema-v2-review.md
     Written       : 2026-09-24 00:39:05 (file mtime)
     sha256[:16]   : 196cfe32ff9d8f3d
     Bytes         : 6146
     Subject       : context schema v2
     Rescued       : 2026-09-24, because /tmp does not survive a reboot and
                     this review was not recorded on any branch. Body is unedited;
                     only this header was added. The reviewing model/effort is
                     whatever the body states -- not asserted here. -->

1. **Asserted beating measured — NOT FIXED.** The rule “higher rank wins” still makes `asserted > measured`, while a later paragraph says that exact contradiction aborts and CLI assertions win in-process; these rules conflict.

2. **Complete merge table — NOT FIXED.** There is no normative 5×5 outcome matrix covering value equality, rank direction, scope applicability, and abort behavior; the prose leaves most unequal-rank contradictions ambiguous.

3. **Derived-fact dependency/invalidation — PARTIALLY FIXED.** `derived_from` and transitive staleness are introduced, but cycles, missing references, digest changes, and termination behavior are unspecified.

4. **Single mandatory SHA-256 / remote workflow — PARTIALLY FIXED.** Build IDs, scopes, and verification improve the model, but a nonempty SHA-256 remains mandatory and the fallback cannot handle unverifiable, non-address-shaped, libc-dependent, or remote-only facts.

5. **`ExploitContext` plus blocks as two authorities — FIXED.** `facts` is explicitly normative, blocks are evidence only, and `ExploitContext` is a read-only projection with no write-back path.

6. **Byte-identical round trip — FIXED.** The impossible promise is replaced with fixpoint stability, declared volatile fields, and no-silent-drop testing.

## New findings

- **BLOCKING — Merge behavior remains internally contradictory.** “Higher rank wins,” “rank alone never resolves a contradiction,” asserted-versus-measured abort, and CLI asserted wins cannot all be true. Supply an executable normative table for all 25 stored/incoming provenance pairs, subdivided by equal/different value and applicable/disjoint scope, with explicit `keep`, `replace`, `coexist`, `unresolved`, and `abort` outcomes. CLI facts must use the same table.

- **BLOCKING — Different-scope coexistence cannot be represented.** `facts` is an object with one value per fact key, yet the merge rules retain both facts under the same key. Moreover, `build`, `process`, and `attempt` scopes can all apply simultaneously; different scope does not imply non-conflict. Represent facts as candidates with stable IDs or include scope/conditions/target identity in their keys, then define applicability and specificity rules.

- **BLOCKING — The instruction-verification gate is not safe or implementable as written.** “Verify a sample” has no specified sample size, selection rule, required coverage, or empty-sample behavior. Many facts—offsets, protections, symbols, ABI properties, libc offsets, and runtime facts—are not instruction-address claims. Define a per-fact verifier registry with `verified`, `failed`, and `unverifiable` results. Missing tooling and non-address facts must be `unverifiable`, never implicitly successful; safety-critical consumers should abort unless an explicit, narrowly scoped override is recorded.

- **BLOCKING — The staleness cascade is not guaranteed to terminate.** `derived_from` permits cycles and its string encoding is ambiguous because fact keys already contain `@`. Use structured references `{key, digest}`, reject dangling references and cycles transactionally, and implement traversal with a visited set. Specify that supersede, retract, unresolved transition, and source-digest change all invalidate the complete dependent closure.

- **MAJOR — Provenance is being mutated to express applicability.** Demoting an identity-mismatched `asserted` fact to `assumed` rewrites what happened and may leave the fact consumable. Preserve provenance and mark the candidate inapplicable to the current identity; require an explicit reassertion for the new target.

- **MAJOR — Target identity can become internally inconsistent.** The document’s old digest is declared authoritative even after a different local binary is accepted through verification, allowing new measurements from one binary to be stored beneath another binary’s identity. Model target variants explicitly and bind every produced fact to the identity actually observed. Define what `--target-identity=none` permits; otherwise it recreates the blanket bypass under a new name.

- **MAJOR — Libc identity is still missing.** `libc_file` is a dependency class, but only the main binary receives SHA-256/build-ID treatment. Add a separately identified libc artifact and bind libc offsets, gadgets, and derived bases to it.

- **MAJOR — Process and attempt scopes lack identity.** “Refused on reuse in a new run” cannot be implemented without stable `run_id`, `process_id`, and `attempt_id` values and rules defining when a run begins or a connection/restart creates a new process.

- **MAJOR — `--resolve=<key>:<provenance>` cannot select a conflicting candidate.** Two conflicting measured or asserted candidates have the same provenance. Resolution must name a stable candidate ID or fact digest and create an auditable resolution record; selecting it must invalidate dependents of the rejected candidate.

- **MAJOR — Concurrent-write safety is underspecified.** Locking a file that is subsequently replaced does not reliably serialize writers, and atomic replacement alone does not prevent lost read-modify-write updates. Lock a stable sidecar lock file across read, merge, validation, temp write, `fsync`, replacement, and directory `fsync`.

- **MAJOR — The history sidecar creates another persistence authority.** Its schema, naming, integrity link, portability, locking, and atomicity are undefined. Either keep history in the document or specify a content-addressed sidecar that is committed under the same lock and whose absence has defined semantics.

- **MINOR — Equal-value deduplication conflicts with idempotence.** Refreshing `at` on every repeated merge changes output each time. Preserve the original observation time or define a separate volatile `last_seen` field and exclude it explicitly from semantic equality.

- **MINOR — `KNOWN_LOSSY` weakens the preservation guarantee.** Forward compatibility promises preservation of unknown fields, while the test permits enumerated silent loss. Restrict the allowlist to explicitly deprecated fields with migration rules; unknown fields must round-trip unchanged.

**REJECT**