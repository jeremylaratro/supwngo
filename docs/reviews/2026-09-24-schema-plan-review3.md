<!-- Preserved verbatim from an ephemeral peer-review output file.
     Original path : /tmp/codex-out/schema-plan-review3.md
     Written       : 2026-09-24 00:29:32 (file mtime)
     sha256[:16]   : fe1052f9226121d5
     Bytes         : 12464
     Subject       : standardized context schema plan, round 3
     Rescued       : 2026-09-24, because /tmp does not survive a reboot and
                     this review was not recorded on any branch. Body is unedited;
                     only this header was added. The reviewing model/effort is
                     whatever the body states -- not asserted here. -->

# Adversarial review

The plan is not safe or internally complete enough to implement as written.

1. **BLOCKING — `asserted` winning over `measured` is unsafe, and the merge table is not a total policy.**

   `asserted` currently means only “a human wrote it”; it does not establish correctness, freshness, target applicability, or an intentional override. A typo or stale assertion would permanently defeat a current measurement. Recording a conflict and printing a warning is insufficient because downstream commands still need one scalar value and noninteractive consumers may never see the warning.

   The table also leaves unresolved `derived`/`derived`, `derived`/`measured`, `measured`/`derived`, `asserted`/`asserted`, `asserted`/`derived`, equal-value collisions, deletion, and merges whose timestamps do not match merge order. “Incoming measured wins” is also arbitrary when two measurement methods disagree.

   **Fix:** separate origin from authority. Keep `provenance: asserted`, but require an explicit `resolution: pinned` or `override: true`, with actor, reason, and scope, before a human value defeats evidence. Store conflicting candidates instead of overwriting them. A fact with unresolved same-scope disagreement must be unavailable to consumers and cause fact-dependent commands to fail clearly. Define and test the complete collision matrix, including equal values, tombstones, confidence, timestamps, and merge order independence.

2. **BLOCKING — Derived facts and sets of jointly valid facts have no dependency or invalidation model.**

   A libc base is not an independent scalar: it is derived from a particular leak, symbol offset, libc build, and process. If the leak or identified libc is superseded, the base must become stale. The same problem applies to PIE bases, resolved gadget addresses, offsets derived from a particular crash, and facts that are valid only as an atomic bundle. `superseded[]` preserves history but does not prevent a stale derived fact from remaining active.

   **Fix:** give every candidate a stable ID/revision and add `depends_on` references to exact candidate IDs, plus artifact/deployment/process scope. Superseding a dependency must transitively mark dependants stale or recompute them. Support observation/assertion bundles so facts such as `{libc digest, leaked symbol, leaked address, computed base}` are activated or invalidated together. Consumers must reject stale or partially satisfied bundles.

3. **BLOCKING — The global SHA-256 refusal guards only one of several required invariants.**

   A byte-for-byte local copy of a remote binary has the same digest and will work. A rebuilt or stripped binary has a different digest; refusing gadget addresses, symbol addresses, and offsets for it is appropriately conservative. The problem is making that decision once for the whole document.

   Some facts are exact-artifact facts, some may survive stripping, some are source-level or architectural, and runtime facts are bound to a deployment, libc, loader, kernel, or individual process—not merely the main binary. Conversely, `--context-mismatch=allow` makes all facts available after the one guard is bypassed, including facts that are plainly unsafe. The plan’s example of an assertion describing a remote binary that differs from the local build also contradicts the declaration that the document describes one exact build.

   **Fix:** identify all relevant subjects—main executable, libc/loader/modules, deployment/endpoint, and process/session—and scope every fact to them. Apply compatibility checks per fact when it is consumed. Preserve incompatible facts as inactive rather than rejecting the entire document. Replace the blanket `allow` switch with explicit target mapping/rebasing or an import-as-untrusted operation; it must not silently activate artifact- or process-specific addresses.

4. **BLOCKING — `ExploitContext`, `facts`, and domain blocks create multiple writable sources of truth.**

   The current model already has two return-offset fields, explicitly described at [core/context.py](/srv/share/dev/supwngo/supwngo/core/context.py:245), as well as `libc.base`, `leaks`, `protections`, and `gadgets`. The plan would additionally represent these in `facts` and blocks such as `protections`, `libc`, and `leaks`. It does not say which representation wins when they disagree or which one a command must update.

   **Fix:** make the resolved fact store the sole canonical state. Blocks should contain immutable/raw analysis evidence and reference the fact candidates they produced; they must not contain independently authoritative copies. `ExploitContext` should be an explicit projection used by existing engines, with a registry mapping each context field to one fact key and conversion rules in both directions. Do not serialize a second complete context blob. Add invariant tests for every mapped field, especially both offset fields, libc base, protections, leaks, and gadgets.

5. **BLOCKING — “Every command” cannot use the proposed single-target envelope.**

   The current CLI has 31 registered commands, not a homogeneous set of binary analyses. `diff` has two binaries; `batch` has a directory and many targets; `source` accepts source files or directories; `kernel` operates on a module plus optional `vmlinux`; `onegadget` operates on libc; `libc-id` has only leaks; and `cyclic`, `cyclic-find`, and `version` have no target at all. A mandatory singular `target` cannot represent these operations.

   **Fix:** define command capabilities before implementation: target-less utility, single artifact, multi-artifact, campaign, source tree, runtime deployment, etc. Either restrict context conformance to commands that meaningfully consume or produce target knowledge, or redesign the envelope around `subjects[]` with typed roles and allow target-less documents. State what “consume” means for each command; merely accepting and ignoring `-c` is not conformance.

6. **BLOCKING — A Click decorator can add flags, but it cannot capture the command’s learned state.**

   Commands currently construct results and contexts in local variables. For example, `exploit` creates its own `ExploitContext` at [cli.py](/srv/share/dev/supwngo/supwngo/cli.py:247), while `autopwn` and `solve` create engines whose contexts are local to their callbacks. Many other commands return nothing and directly print or write bespoke results. A wrapper cannot recover those locals after the callback. Mapping 18 serializers into blocks is therefore per-command integration work, not a small mechanical decorator change.

   **Fix:** introduce a common handler contract such as `CommandResult(context, facts, blocks, artifacts)` or inject a shared result sink that each command and engine explicitly updates. Keep a decorator only for option parsing, initial loading, validation, and final atomic writing. Budget and review a domain adapter for every producing command. The “all up front” milestone should require this refactor rather than assuming the decorator accomplishes it.

7. **MAJOR — The proposed command-registry conformance sweep is not executable as described.**

   Registry enumeration supplies neither required arguments nor fixtures. Some commands need corpora, crash directories, libc, two binaries, external tools, interactive input, or long-running fuzzing. A test that only checks that `--context-out` exists will not prove that commands consume input facts or emit their learned results.

   **Fix:** split testing into:

   - A static registry test for declared context capability and option placement.
   - Adapter unit tests using typed synthetic results.
   - Mocked CLI smoke tests with per-command argument factories.
   - End-to-end tests for a small representative subset.
   - Consumption tests proving a supplied fact changes behavior or avoids remeasurement.

8. **BLOCKING — The byte-identical `doc → ExploitContext → doc` test is not achievable under the stated model.**

   Hand-authored JSON can differ in whitespace and key order, while YAML cannot be byte-identical to canonical JSON. `created`, `updated`, and history may change during conversion. More importantly, `ExploitContext` cannot losslessly hold arbitrary blocks, artifacts, provenance, conflicts, and future extension fields. Its existing values include `Path`, enums, sets, bytes, tuples, `Any` attempt records, and a `Binary` containing runtime parser objects. `default=str` is lossy: it cannot reconstruct the original type and set output is not a canonical ordering.

   **Fix:** introduce a dedicated persistence `ContextDocument` model despite the current “not a new state object” non-goal. Give every supported non-JSON type an explicit reversible codec and canonical ordering; do not use `default=str`. Test:

   - Parse → normalized model → canonical JSON → parse gives semantic equality.
   - Canonical JSON serialization is idempotent.
   - Context projection round-trips only the explicitly mapped facts.
   - Unknown extension fields survive load/write through the document model.

9. **MAJOR — The plan contradicts itself about compatibility with existing JSON output.**

   Dedicated `--context-out` is additive and does not require changing `--json` or existing `-o` files. Yet the plan declares a breaking output-shape change and proposes `--legacy-json`. The listed implementation also says existing `to_dict()` methods remain intact. These are two different migrations.

   **Fix:** keep all current stdout and `-o` schemas unchanged in this work and make only `--context-out` emit the standardized document. Remove `--legacy-json` and the breaking-change claim. If replacing existing JSON is desired, specify it as a separate migration with exact affected commands, deprecation timing, and compatibility tests.

10. **MAJOR — The schema contract is substantially underspecified.**

   The plan names block namespaces but does not define their sub-schemas, cardinality, update behavior, or whether repeated analyses replace or append. It also does not define typed values per fact key, address semantics, null versus unknown, or schema evolution. `target.type: exec|dyn|static` conflates ELF object type with static linkage: an executable can be `ET_EXEC` and statically or dynamically linked, while `ET_DYN` can be PIE or a shared object. The minimal-document test also conflicts with the apparent envelope fields such as `tool_version`, timestamps, history, blocks, and artifacts.

   **Fix:** before adapters are written, specify:

   - A fact-key registry with value schema, units, address space (`VA`, RVA, file offset), width, subject role, and allowed scope.
   - Versioned block schemas with producer, scope, timestamp, and append/replace rules.
   - Required fields and deterministic defaults for hand-authored documents.
   - Separate object format, object type, and linkage fields.
   - Strict version negotiation and v1-to-future migration behavior.
   - `additionalProperties` and extension preservation policy.

   Also add and pin a JSON Schema validator dependency; the repository currently includes PyYAML but not `jsonschema`.

11. **MAJOR — Safe persistence, portability, and sensitive-data handling are omitted.**

   Contexts can contain canaries, captured flags, remote endpoints, command text, crash observations, and exploit attempts. Absolute target and artifact paths undermine portability. Concurrent or interrupted in-place updates can lose data or leave truncated JSON. Artifact digests are recorded but no verification or missing-artifact behavior is defined. YAML and JSON duplicate keys can silently replace values.

   **Fix:** define atomic temp-file-plus-rename writes, optimistic concurrency using the input document digest or a lock, restrictive default permissions, symlink handling, and behavior on command failure. Resolve relative artifact paths against the context file and verify their digest before use. Use safe YAML loading, reject duplicate keys and non-finite numbers, impose size/depth limits, and provide redaction controls for secrets and command history.

12. **MINOR — The target UX contains a nonexistent command.**

   The example uses `fuzz-corpus`, but the current CLI command is `fuzz` and requires `--input-dir`.

   **Fix:** change the example to a valid invocation such as `supwngo -c ctx.json fuzz binary_01 --input-dir corpus`, or explicitly include creation of `fuzz-corpus` in scope.

**REJECT**