# Independent review — interactive fuzz corpus builder, r1

**Date:** 2026-09-24
**Reviewed:** `docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md` at r1
**Reviewer:** independent peer model (Tier 2, non-cyber peer), read-only
sandbox, no access to the author's reasoning
**Disposition:** all 5 High findings independently re-verified by the plan
author and **accepted**; applied in r2. See the r2 row of the plan's
Alignment log for the per-finding mapping. M1 resulted in a capability being
**deleted** (grammar seeding) rather than fixed.

---

## Verdict: NOT APPROVED

Reviewed corpus-plan SHA-256 `79adc0b5…f8cc8`; companion-plan SHA-256 `21c71da5…97a`. The companion is now v3, while this plan targets rejected v2.

### High

- **H1 — Context integration is incompatible with the current dependency.** The corpus plan emits scalar facts, qualified keys, and `--resolve KEY:PROVENANCE` ([plan:332](/tmp/wt-fuzz-corpus/docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md:332)). The companion is now v3: facts are candidate sets with `applies_to`, stable IDs, and `resolve(key, ctx)`; `--resolve` selects a candidate ID ([schema:167](/srv/share/dev/supwngo/docs/plans/2026-09-24-standardized-context-schema.md:167), [schema:238](/srv/share/dev/supwngo/docs/plans/2026-09-24-standardized-context-schema.md:238)). A1 also consumes `crashes` directly from a block despite the schema forbidding consumers from reading blocks ([plan:427](/tmp/wt-fuzz-corpus/docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md:427), [schema:130](/srv/share/dev/supwngo/docs/plans/2026-09-24-standardized-context-schema.md:130)).  
  **Fix:** redesign Phase 4 for v3 candidate sets, identities, verification classes and candidate-ID resolution. Expose crash inputs through normative facts/artifacts. Keep Phase 4 blocked until the companion contract is approved.

- **H2 — The AFL dictionary is malformed.** `export_afl_dict()` hex-encodes the whole token and prefixes it with one `\x` ([cmplog.py:353](/tmp/wt-fuzz-corpus/supwngo/fuzzing/cmplog.py:353)); `b"AB"` becomes `"\x4142"`, not `"\x41\x42"`. AFL requires `\xNN` per problematic byte. [AFL++ dictionary specification](https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/README.md). The plan explicitly calls this writer “correct” ([plan:460](/tmp/wt-fuzz-corpus/docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md:460)).  
  **Fix:** implement a correct per-byte escaper or emit a dictionary directory. Phase 0 must test `afl-fuzz -x`, not merely `-i`, using an `afl-cc` target or `-Q`; benchmark targets are built with ordinary `gcc` ([build_all.sh:178](/tmp/wt-fuzz-corpus/benchmark/build_all.sh:178)).

- **H3 — Provenance enforcement is label-based theatre.** The proposed test only checks hardcoded strategy labels ([plan:980](/tmp/wt-fuzz-corpus/docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md:980)). Yet:

  - `fgets`/`read` imports do not prove stdin; `read` simultaneously triggers the synthetic `file_io` finding ([static.py:65](/tmp/wt-fuzz-corpus/supwngo/analysis/static.py:65), [static.py:301](/tmp/wt-fuzz-corpus/supwngo/analysis/static.py:301)).
  - A2 admits the format-to-`scanf` association is assumed.
  - A5 labels guessed menu sequences `derived`.
  - A6 emits generic payloads without evidence of user control.

  **Fix:** provenance must be composed from evidence components using the weakest component. Treat input channel as `unknown` or operator-asserted unless dataflow/runtime fd tracing establishes it. Add central manifest validation plus negative tests that reject unsupported `derived`/`measured` claims.

- **H4 — Two default Tier-A capabilities cannot work as specified.** `StringAnalyzer` constructs `FormatSpecifier.width` locally but omits width and precision from its returned `details["specifiers"]` ([strings.py:283](/tmp/wt-fuzz-corpus/supwngo/analysis/strings.py:283), [strings.py:330](/tmp/wt-fuzz-corpus/supwngo/analysis/strings.py:330)); A2 has no usable width through the advertised primitive. Also `%31s` is a maximum field width, not a declared destination-buffer capacity. Separately, A6 requires a format-bearing binary string, but benchmark 05’s vulnerability is `printf(name)` and contains no compiled `%` format literal ([fmtstr_arbread.c:31](/tmp/wt-fuzz-corpus/benchmark/corpus/05_fmtstr_arbread/fmtstr_arbread.c:31)); test 4 therefore cannot produce the asserted `fmt-trigger`.  
  **Fix:** expose width in `StringAnalyzer` results or parse `FORMAT_PATTERN` directly. Reclassify A2’s inference. Remove A6’s literal-format gate or add real call-site/dataflow evidence; otherwise mark it assumed.

- **H5 — The interactive test contradicts the terminal contract.** The command refuses whenever `sys.stdin.isatty()` is false ([plan:850](/tmp/wt-fuzz-corpus/docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md:850)), but the CliRunner test invokes ordinary piped input without `--script` ([plan:910](/tmp/wt-fuzz-corpus/docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md:910)). It must refuse before the first prompt.  
  **Fix:** exercise `--script -` under CliRunner, or inject a terminal/input abstraction. Keep one real-subprocess test for the actual interactive command.

### Medium

- **M1 — B2 grammar generation is non-functional.** Parser-created subrules are never registered in `grammar.rules`; generation expands their names as literals ([grammar.py:121](/tmp/wt-fuzz-corpus/supwngo/fuzzing/grammar.py:121), [grammar.py:287](/tmp/wt-fuzz-corpus/supwngo/fuzzing/grammar.py:287)). Executing the shipped HTTP grammar produced `b'request_0request_1…request_9'`, not HTTP.  
  **Fix:** repair and test nested subrule expansion before exposing `--grammar`, or remove B2 from this feature.

- **M2 — Coverage/degradation reporting is not implementable through the cited APIs.** `StaticAnalyzer` and `get_coverage()` swallow exceptions and return ordinary empty results, so the builder cannot distinguish failure from legitimate emptiness and “promote” the debug error ([static.py:269](/tmp/wt-fuzz-corpus/supwngo/analysis/static.py:269), [dynamic.py:316](/tmp/wt-fuzz-corpus/supwngo/analysis/dynamic.py:316)). `get_coverage()` returns one union for all inputs, not per-seed block sets, so it cannot produce the shown per-seed deltas without rebuilding CFG per seed. Its `timeout` parameter is unused.  
  **Fix:** add structured availability/error results and a cached per-input coverage API with an actual wall-clock guard.

- **M3 — Honggfuzz claims are wrong.** With `--output`, honggfuzz writes new corpus data there; the input directory is not inherently mutated. [Official honggfuzz usage](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md). More seriously, the repository wrapper omits `--stdin_input/-s` ([honggfuzz.py:129](/tmp/wt-fuzz-corpus/supwngo/fuzzing/honggfuzz.py:129)), and the CLI’s Honggfuzz branch only says “support coming soon” ([cli.py:188](/tmp/wt-fuzz-corpus/supwngo/cli.py:188)). LibFuzzer does write discoveries into its first corpus directory, as the plan says. [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html).  
  **Fix:** list honggfuzz as safe when a separate output is supplied, but do not print a runnable Supwngo Honggfuzz next step until `-s` and the CLI branch work.

- **M4 — `_find_callers()` is completely broken, not merely weak.** `binary.symbols` values are `Symbol` objects, but the second loop passes the object itself to `cfg.kb.functions.get()` ([static.py:258](/tmp/wt-fuzz-corpus/supwngo/analysis/static.py:258), [binary.py:120](/tmp/wt-fuzz-corpus/supwngo/core/binary.py:120)); the exception is swallowed. `analyze()` also builds one CFG per dangerous import plus another in `_analyze_functions`, not “one CFGFast.”  
  **Fix:** use `symbol.address` and cache one CFG, or skip call-site analysis entirely for this command.

- **M5 — Failure semantics conflict.** `check_crash()` catches `TimeoutExpired` internally, so an outer caller cannot reliably set `timed_out` by “timing the subprocess itself” while still using that method ([dynamic.py:321](/tmp/wt-fuzz-corpus/supwngo/analysis/dynamic.py:321)). If every seed is `kept:false`, `seeds/` is empty despite the plan saying it must never be empty. The cited `b"A"*8` behavior belongs to `AFLFuzzer.setup()`, not direct `afl-fuzz`.  
  **Fix:** own the subprocess in `measure_replay()`, and abort publication when nothing is runnable rather than writing an empty advertised corpus.

- **M6 — Replay validation does not validate symbolic reachability.** It proves only that the target executes; it does not prove the concretized input reaches the intended sink ([plan:494](/tmp/wt-fuzz-corpus/docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md:494)).  
  **Fix:** verify sink reach with instrumentation/breakpoints, or describe replay only as an execution sanity check.

### Low / citation audit

- **L1:** `cli.py:2689` is another `click.prompt`, not a `click.confirm` precedent ([cli.py:2682](/tmp/wt-fuzz-corpus/supwngo/cli.py:2682)).
- **L2:** `walkthrough/model.py:124-143` cannot be verified: that file is absent from this worktree.
- **L3:** A3’s “schema lines 112-121” citation is stale; current v3’s worked fact is at schema lines 167-199 and uses candidate sets.
- **L4:** C4 says generic magics “go” into the dictionary while the manifest and walkthrough say they are excluded ([plan:583](/tmp/wt-fuzz-corpus/docs/plans/2026-09-24-interactive-fuzz-corpus-builder.md:583)).
- **L5:** The `strings`-missing test has no dependent strategy because A4 explicitly uses `Binary.strings()`.

All other current worktree `file:line` citations matched the cited source.