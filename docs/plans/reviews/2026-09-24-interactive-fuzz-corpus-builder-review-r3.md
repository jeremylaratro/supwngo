# Independent review — interactive fuzz corpus builder, r3

**Date:** 2026-09-24
**Reviewed:** the r3 revision of
  `docs/plans/2026-09-24-interactive-fuzz-corpus-builder-standard-mode.md`
  (reviewed bytes SHA-256
  `723586f920a6e12eba9162f8fb2befa821bf503225c88374f56ba13bb5ea8a59`; that file
  now holds r4, which answers these findings)
**Reviewer:** independent peer model (Tier 2 peer, `gpt-5.6-sol`,
  `model_reasoning_effort=xhigh`), read-only sandbox, **no filesystem access to
  the repository** — the plan was inlined into the prompt and the reviewer was
  instructed not to read any files, so every finding is about the document's
  internal consistency and engineering merit, not about the tree.
**Disposition:** **NOT APPROVED** (7 High, 6 Medium, 2 Low). Applied in **r4**;
  see the r4 row of the plan's Alignment log for the per-finding mapping.
  H1 forced a **design change to the success gate** (the "better than ASSUMED"
  refusal was unsatisfiable once A4/A5 were corrected); M3/H4.6 caught a
  **self-contradiction** between the escaper rule and its own test; M6 caught an
  unbounded allocation. Two findings are **accepted with a documented
  disagreement** (M2, and the `--allow-non-tty` half of it) — recorded in r4
  rather than silently dropped.

The review is reproduced verbatim below, unedited.

---

## Verdict: NOT APPROVED

### High

**H1 — The standard mode’s success gate is unsound: A4 and A5 assign strong provenance to byte origin while omitting the unsupported claim that those bytes are useful target inputs.**

Fix: Separate provenance of the bytes from evidence of input relevance. “Present in the binary” may be `MEASURED`, but “suitable seed” remains `ASSUMED` or `UNKNOWN` without consumption/reachability evidence. A5 likewise lacks evidence connecting a token to a menu parser. After correcting this, reconsider the “better than ASSUMED” refusal: as designed, standard mode would have no honest path to success on many ordinary targets. Deduplication must also preserve alternative derivations and choose deterministically; first-writer-wins would make the same bytes `MEASURED` or `ASSUMED` depending on strategy order.

**H2 — `measure_replay()` proves only that the target process launched and terminated; it neither proves that the seed was read nor supports the advertised file and socket channels.**

Fix: Define every `ReplayResult` state and its effect on `kept`, discarded reasons, crashes, timeouts, and refusals. Rename `ran` to something like `spawned` unless actual consumption is observed. Disable replay-derived conclusions for file/socket channels until channel-specific drivers exist. The command must not treat an exit-0 program that ignored stdin as evidence that a seed “executed.”

**H3 — The core interactive state machine is not specified sufficiently to implement or test consistently.**

Fix: Specify the exact menu actions, defaults, allowed transitions, candidate and strategy selection rules, measurement-to-retention policy, abort/EOF behavior, cap ordering, duplicate handling, write eligibility, and whether each refusal publishes a diagnostic artifact. In particular, the plan currently never says what happens to successful nonzero exits, crashes, timeouts, or spawn errors.

**H4 — The validation strategy still contains vacuous or materially incomplete checks despite its claim that every absence assertion has a positive counterpart on the same path.**

Fix: Tighten all nine items as follows:

1. Item 1’s nonempty expected seed and discard sets prevent a total writer no-op, but “round-trip `corpus.json`” could accept `{}` or a manifest missing evidence, hashes, observations, tallies, and degradations. Assert an independently constructed golden contract, not merely self-consistency.
2. Item 2 can pass if the session ignores all supplied choices and immediately writes a canned/default manifest. Assert the effects of each requested action, final exit code, and that changing the input sequence changes the resulting state.
3. Item 3’s “for every seed” assertion is vacuous for zero seeds. Assert a nonempty fixture, a valid mixed-confidence positive case, the expected rank relationships, and failures caused by omitted weak evidence—not only a strategy that explicitly lies about its label.
4. Item 4 catches a total strategy no-op, but A2 can emit one constant payload whenever `scanf` is imported and still pass. Assert exact `width`, `width+1`, and `width*2` payloads. Verify the fixture actually imports `__isoc99_scanf`; otherwise normalization can be deleted on toolchains that expose `scanf`. Add a negative target because `fmt-trigger` currently passes if it fires for every binary. Add positive coverage for A4, A5, and C2.
5. Item 5 catches a trivial replay no-op, but dropping `input=seed` still passes because none of the three programs is said to inspect stdin. Add an input-sensitive target, plus nonexistent and unexecutable targets, and assert all `ran`/error/exit/signal fields.
6. Item 6 has positive byte cases, but it cannot prove AFL accepts the output. Also resolve the plan’s own contradiction: the writer says printable `AB` is emitted verbatim, while the test requires `\x41\x42`. Choose one canonical encoding and compare exact serialized bytes with escaped backslashes.
7. Item 7 can pass if every standard invocation unconditionally exits nonzero with a tally or diagnostic manifest. Add successful measured/derived and mixed-corpus cases that require exit 0 and a published `seeds/`.
8. Item 8’s “setup did not create fallback” passes when `setup()` is a complete no-op. Checking only the `-i` pair also permits an argv missing the target, dictionary, or other required arguments. Assert the complete command, including `-x` when the dictionary is nonempty.
9. Item 9’s unchanged hash is satisfied by a no-op consumer, and the warning can be printed unconditionally. Add a canary proving the hash oracle detects mutation and negative assertions for the other `--next-fuzzer` choices. Treat this as an immutability property, not evidence of consumability.

The promised manual “mutate red once” exercise does not cure unspecified assertions; record the exact mutations and expected failing tests.

**H5 — The four method comparisons do not satisfy the standing rule because material alternatives are constrained into strawmen or have invalid flip conditions.**

Fix:

- Fork 1 must compare the flat menu with a guided, backtrackable state machine. A wizard does not become a flat menu merely because it permits review or repetition. Expensive measurement favors caching and confirmation, not inherently a one-way wizard.
- Fork 2 must include persisted private staging or a journal followed by atomic publication. Persisting progress does not require exposing a partial final `seeds/`; the plan itself later acknowledges this hybrid.
- Fork 3’s proposed flip is insufficient: observing a requested read length provides neither input bytes nor the amount actually consumed. Compare against a viable stdin-only dynamic generator and state what demonstrated observation would justify it.
- Fork 4 should compare the layered design with a shared orchestration engine plus separate policy/input adapters, not only an `interactive: bool` threaded through every call. Its flip also contradicts the definition of `--auto`: an unresolved fact should make auto refuse, not prompt.

**H6 — The `--auto` refusal is honestly disclosed, but the claimed “one new file, roughly 60 lines” seam is not credible as specified.**

Fix: Accurately enumerate the future work. A1 and A3 are absent from the current registry, so auto requires changes to `corpus.py`, CLI wiring, and tests, not just `corpus_context.py`. Define every `CorpusEvidence` field and preserve evidence origin/detail rather than only `(value, Confidence)`. Include context/scope in result writes and define the “evidence-backed only” threshold. The refusing flag is acceptable only if help and changelog consistently label it unavailable; it should not be presented as an implemented seam requiring only an adapter.

**H7 — The unsatisfied live AFL gate remains a release blocker because wrapper argv and byte-level unit tests do not establish that AFL accepts either artifact.**

Fix: Implementation may proceed under the disclosed restriction, but merge/release must require an authorized CI job or separate host to start AFL with both `-i seeds/` and `-x dict/tokens.dict` against a tiny instrumented target. Make that an enforceable acceptance gate with an owner, not an open “before trusted at scale” note. A disclaimer in each manifest is not a substitute for validating the feature’s principal consumer.

### Medium

**M1 — The partial-order diagnosis in D1 is correct, but the claimed semantic repair overstates what mapping `ASSERTED` to `ASSUMED` achieves.**

Fix: Document the four-value rank as a local policy rather than an inherent property of the plain enum. The mapping is conservative and disclosed, but lossy: an operator assertion is not a convention-based default. Preserve `source_kind=operator_assertion` separately from confidence so tallies and future resolution do not erase the distinction. Also address the architectural dependency: the cited `facts.py`/`model.py` import is within the same walkthrough package, not precedent for fuzzing importing exploit-layer types; move shared provenance types to a neutral module or explicitly accept that coupling.

**M2 — Deleting the TTY guard solely because the repository lacks precedent discards a real non-interactive safety boundary without weighing it.**

Fix: Define non-TTY behavior explicitly. CI with EOF will fail cleanly, but an inherited pipe that remains open can block indefinitely, and arbitrary numeric input can drive actions and publish output. A small `--allow-non-tty` opt-in would preserve the same `click.prompt` code path and test fidelity without restoring a separate script parser.

**M3 — The dictionary contract contradicts itself about printable bytes.**

Fix: Either emit printable `AB` as `token="AB"` or canonicalize every byte as `token="\x41\x42"`; update the escaper description, exact-byte tests, and live AFL test consistently. The current implementation rule and test cannot both pass.

**M4 — Atomic publication and output-collision behavior are incomplete.**

Fix: State whether an existing output directory is refused, replaced, or versioned. `os.replace()` cannot transparently replace an arbitrary nonempty directory. Test injected write failures, preservation of an existing artifact, temporary-directory cleanup, and the point at which the all-guesses refusal occurs.

**M5 — The plan calls PLT imports “functions flagged in earlier analysis,” although it is recomputing dangerous imported symbols without call-site reachability or user-control evidence.**

Fix: Label them “dangerous imports” in the UI and manifest, and state that reachability and user control are unknown. Do not imply that a target function or vulnerable call site has been selected.

**M6 — Seed generation has count limits but no byte-size or expansion limits.**

Fix: Bound parsed widths, individual seed size, aggregate corpus bytes, dictionary-token size, and menu-sequence expansion. Otherwise a large width literal or binary string can allocate or write an unreasonable amount despite `--max-seeds`.

### Low

**L1 — `--next-fuzzer honggfuzz` is publicly accepted even though the plan says no runnable command can be printed for it.**

Fix: Remove the choice for this pass or define the exact warning-only behavior so selecting it cannot be mistaken for producing an executable next step.

**L2 — The public `--auto` error embeds an ephemeral development branch name.**

Fix: Use a durable capability message such as “context-document support is not available in this build,” and place branch coordination details in developer documentation.