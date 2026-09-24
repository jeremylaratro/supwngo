# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `supwngo/exploit/pipeline/handoff.py` — a structured, actionable
  hand-off report (`HandoffReport`) built when `CanonicalAutopwnEngine`
  does not reach verified SUCCESS: `attempts_detail` (technique, outcome,
  stage reached, failure reason — projected from the `AttemptRecord`s the
  engine already collected), `blocking_unknowns` (concrete facts like "PIE
  base not leaked"/"libc base not leaked"/"stack canary value unknown",
  derived from `ExploitContext` state that's still unset, gated on a
  technique that actually needed that fact having been attempted this run
  — never a guess independent of what the pipeline tried), `best_partial`
  (the furthest-along artifact: a technique's partial exploit script if
  one exists, else the pipeline's universal fallback template), and
  `suggested_next_steps` (the highest-confidence not-completed strategy's
  `requirements`/`notes`/`steps`, surfaced directly from
  `strategy.py`'s existing `StrategyReport` rather than new prose).
  `CanonicalAutopwnEngine.handoff_report` builds and caches one per run.
  JSON schema is frozen at `schema_version: 1` (additive-only from here);
  intended to double as the shape a future benchmark harness parses for
  PARTIAL/FAILED classification. Phase 4 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.
- `supwngo autopwn`'s non-JSON output now renders the hand-off report with
  `rich` (an attempts table, blocking unknowns, strategy warnings, the
  recommended next strategy, and the best partial artifact) instead of
  dumping the first 50 lines of the universal template — replacing the
  previous sparse fallback. `supwngo autopwn --json` (the flag already
  existed) now includes the same structured hand-off under a `"handoff"`
  key alongside the existing result fields.
- `tests/test_pipeline_handoff.py` — 18 tests covering `HandoffReport`'s
  frozen JSON schema, `derive_blocking_unknowns()`'s grounding in actual
  attempted techniques (not blanket guesses), and `build_handoff_report()`
  assembling `best_partial`/`suggested_next_steps` correctly for both
  successful and non-successful runs.

### Changed
- `supwngo autopwn` (the CLI command) is now driven by
  `CanonicalAutopwnEngine` instead of `EnhancedAutoExploiter`. Previously
  `cli.py` defined **two** `def autopwn` Click commands (one wired to
  `AutoExploiter`, one to `EnhancedAutoExploiter`); Click silently kept
  only the later one, making the first permanently unreachable. There is
  now exactly one `autopwn` command; it gained an `--offset` option
  (previously only on the unreachable command) to skip offset discovery
  when already known. Part of Phase 2 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Added
- `supwngo/exploit/pipeline/` — a new canonical auto-exploitation pipeline
  (`CanonicalAutopwnEngine`) that consolidates the two previously
  overlapping, never-reconciled auto-exploit engines (`AutoExploiter` and
  `EnhancedAutoExploiter`) behind a single, pluggable technique-executor
  architecture: typed `AttemptRecord`/`VerificationReceipt` contracts, an
  `ExecutorRegistry` of 11 technique executors (7 ported from
  `EnhancedAutoExploiter`, plus SROP/scanf-canary-bypass/UAF/double-free
  ported from `AutoExploiter`), and a `PipelineVerifier` that confirms
  success via a unique per-attempt verification-receipt token rather than
  shared-string stdout matching. See
  `docs/architecture/2026-09-23-autopwn-pipeline.md` for the full design,
  the engine-shape decision and justification, and a list of explicit
  follow-up items left for later phases. Phase 2 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Changed
- `supwngo/core/context.py`'s `ExploitContext` gained new fields
  (`gadgets`, `win_function`, `binsh_addr`, `offset`, `captured_flag`,
  `verification_level`, `attempts`, and several `profile_*` fields) to hold
  the state produced by the new canonical autopwn pipeline's static
  analysis and dynamic profiling stages. Pipeline-facing types are imported
  under `TYPE_CHECKING` only, preserving `core/context.py`'s existing
  import-layering rule (no real import of `supwngo.exploit.*` at module
  load time). Part of Phase 2 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`; see
  `docs/architecture/2026-09-23-autopwn-pipeline.md` for the full rationale.
- `supwngo/exploit/verification.py`'s `ExploitVerifier.__init__` now
  accepts optional `marker`/`marker_file` overrides (previously a fixed,
  shared `PWNED_MARKER`/`PWNED_FILE` constant for every caller), so callers
  needing a verification receipt tied to a specific attempt can pass a
  freshly generated unique token per attempt instead of a shared,
  guessable string. Existing callers are unaffected (defaults preserved).
  Part of Phase 2 of `docs/plans/2026-09-23-effectiveness-and-usability.md`.
- `supwngo/exploit/strategy.py`'s `StrategySuggester` gained two new
  `ExploitApproach` strategies — `VARIABLE_OVERWRITE` and
  `NEGATIVE_SIZE_BYPASS` — reconciled in from `EnhancedAutoExploiter`'s
  previously-private, unreconciled `_rank_strategies` inline strategy list.
  Part of Phase 2 of `docs/plans/2026-09-23-effectiveness-and-usability.md`
  (auto-exploit engine consolidation).

### Fixed
- Package failed to `import` at all on Python 3.11 (the advertised `>=3.8` range) due to
  syntax errors in four files. `supwngo/exploit/seccomp.py` and one code path in
  `supwngo/exploit/auto.py` used an f-string containing a backslash inside the expression
  part — legal only under Python 3.12's relaxed f-string grammar (PEP 701) — fixed by
  computing the value in a variable before interpolating. `supwngo/exploit/templates.py`
  and the same `auto.py` code path nested a triple-quoted string inside an f-string using
  the same quote character, which is invalid pre-3.12 — fixed by extracting the nested
  string to a variable defined before the f-string. `supwngo/distributed/coverage_merge.py`
  had a generator expression with two `if` clauses (`... if X if Y else Z`), which is not
  valid Python on any version — fixed by combining into a single boolean condition. All 158
  files under `supwngo/` now parse cleanly on Python 3.11, and `import supwngo.cli`
  succeeds. This was the first prerequisite (Phase 0) of the effectiveness/usability plan;
  see `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Changed
- Declared the previously-undeclared runtime dependencies used by lazily-imported,
  already-guarded optional modules: `anthropic`/`openai` (`supwngo/ai/*`) and `z3-solver`
  (`supwngo/exploit/rop/z3_solver.py`), as new `ai` and `z3` optional-dependency extras in
  `pyproject.toml`. Also added `r2pipe` as an `r2` extra (previously only in
  `requirements.txt`, uncommented as if required).
- Reconciled `pyproject.toml` and `requirements.txt`, which previously listed different,
  non-overlapping dependency sets (`claripy`/`unicorn`/`lief` were only in
  `requirements.txt`; `networkx`/`pyyaml` were only in `pyproject.toml`). `pyproject.toml`'s
  `[project.dependencies]` is now the canonical list; `requirements.txt` mirrors it.
