# Independent plan review, round 1 — `DetailedProtections.to_dict()`

Verbatim review of the **first draft** of Task 2 in
`2026-09-24-walkthrough-merge-and-protections-to-dict.md`.

- **Date:** 2026-09-24
- **Reviewer:** gpt-5.6-sol, `model_reasoning_effort=xhigh`, `--sandbox read-only`
  (independent same-tier peer; the plan itself was drafted on Opus)
- **Method:** plan plus all consumer sites inlined into the prompt — the
  reviewer read no filesystem, so it could not be misled by stale context
- **Disposition:** six of eight findings accepted and fixed in plan v2; one
  (`MEDIUM`, redundant representations) considered and deliberately not
  adopted; see the plan's "Review record — round 1" for the per-finding
  resolution and for the re-verification of each claim against the code.

---

NOT-APPROVED

1. **HIGH — The reporter argument does not distinguish Option A from Option B.** There is no in-tree path from either `to_dict()` to `BinaryInfo.protections`. On a base `Protections` instance, Option B adds only `rpath` and `runpath`, not ~20 rows. On a `DetailedProtections` instance, both options expose the same detailed fields and create the same truthiness-rendering problem. The reporter is a valid warning about mixed-type protection dictionaries, but not a valid reason to prefer Option A.

2. **HIGH — The field counts and “measured” characterization are wrong.** `DetailedProtections` adds 14 fields, not 20. Including eight inherited fields gives 22 total; the current serializer emits six, so 16 are missing—not “~22.” More importantly, `analyze()` never populates `stack_clash_protection`, `safe_stack`, `cfi`, `shadow_stack`, `rpath`, or `runpath`. Serializing all fields turns unmeasured defaults into apparent findings, especially four `False` values that consumers may interpret as “confirmed disabled.”

3. **MEDIUM — `Binary.checksec()` is not inherently a base-only consumer.** It dynamically calls `self.protections.to_dict()`. If `binary.protections` is ever a `DetailedProtections`, Option A changes `checksec()` and therefore `StaticAnalyzer` output too. The current CLI flow may happen to retain a base instance, but the claimed receiver type and “three CLI sites only” blast radius are not guaranteed by this code.

4. **HIGH — The database and reporter are incorrectly presented as transitive consumers.** The plan explicitly says no in-tree caller feeds either from `to_dict()`. Consequently, claims about Option B changing “whatever the DB column has been storing” or handing fields to the reporter are unsupported. They are potential future/external consumers, not established blast-radius paths.

5. **HIGH — The test assessment needs tightening.**

   - Test 1 will fail unfixed, but it will report 16 missing fields. It also enforces publication of unmeasured and potentially future-internal fields.
   - Test 2 will fail only if it indexes/asserts every declared field. “A distinct value in each field” is impossible for the many boolean fields; setting every default-false boolean to `True` cannot detect boolean fields wired to one another. Use per-field/one-hot cases or an explicit expected mapping.
   - Test 3’s JSON round-trip equality passes unfixed. It fails only because of the additional detailed-key assertion, which merely repeats Test 1. It therefore does not independently prove the persistence path works and does not exercise either the database or CLI.
   - Test 4 is not vacuous: it can catch an accidental Option-B-style base change. It correctly passes unfixed and must not be counted as evidence of the fix.

6. **MEDIUM — The tests do not lock the supposedly explicit wire schema.** Tests 1–3 allow arbitrary extra keys. A typo alias, leaked derived value, or stale compatibility key could be emitted while all tests pass. If an explicit schema is the reason for Option A, assert the exact key set and an explicit expected value mapping. Separately decide whether `rpath` and `runpath` belong in that schema; exposing them only on the subclass is an unexplained change to inherited-field behavior.

7. **MEDIUM — “Strictly additive” does not mean consumer-safe.** The new dictionary mixes booleans, integers, strings, empty strings, and `None`. Any consumer iterating all protection entries—as the reporter already demonstrates—can misrender them. There are also redundant representations that can contradict each other: `relro` versus `full_relro`/`partial_relro`, `pie` versus `pie_type`, and `fortify` versus `fortify_level`. The serializer needs defined consistency and unknown-value semantics.

8. **LOW — Current declared values are JSON-serializable, but runtime types are unchecked.** `None` safely becomes JSON `null`, although downstream consumers may not accept it. More subtly, the saved-file path uses `default=str`, while the stdout JSON path does not. If `rpath`, `runpath`, or a future field contains a `Path` or another non-native value, one CLI output may stringify it while another raises. A round-trip unit test using only declared primitive values will not catch that inconsistency.