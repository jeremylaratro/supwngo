# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `supwngo/exploit/verification.py`'s `ExploitVerifier.verify_payload()` only fell back to
  real interactive (pwntools-based) shell verification when the initial `subprocess.run()`
  raised `TimeoutExpired`. A shell spawned via `system()`/`execve()` given piped,
  non-interactive stdin (exactly what `subprocess.run(input=payload)` provides) reads EOF
  and exits immediately rather than hanging — it never times out, so the interactive
  verification path was dead for the single most common case (any technique that lands a
  shell via `system("/bin/sh")`, e.g. ret2win, ret2system). Found via a manual end-to-end
  smoke test against a trivial ret2win target: the exploit payload was independently
  confirmed correct (spawned a real shell when replayed by hand), but `autopwn` reported
  FAILED because `verify_output()`'s passive string-pattern check has nothing to match
  against a piped shell that only ever saw an immediately-closed stdin. Now retries via
  the interactive path whenever the fast passive check didn't already succeed, not only on
  timeout. This was blocking correct verification for what should be the benchmark corpus's
  easiest target and would have silently deflated every ret2win/ret2system-class success
  in Phase 1's benchmark numbers. Found and fixed during integration-branch smoke-testing,
  ahead of Phase 5/6/1-benchmark work.

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
- Added `docs/roadmaps/PARKED.md`, listing speculative-breadth work explicitly out of scope for
  the current effectiveness/usability effort (CFI/CET/MTE/PAC/shadow-stack/COOP bypass, exotic
  heap techniques beyond common UAF/tcache, Windows/macOS/embedded/containers expansion,
  distributed/cloud fuzzing, the enterprise REST/GraphQL API, LLM/RL-based exploit generation),
  corrected per the module-triage audit: `kernel/` is called out as live and NOT parked (wired
  into the CLI via `supwngo kernel <module.ko>`), and `reporting/` is flagged as a future wire-in
  candidate rather than frozen indefinitely. Added a scope-note banner to the top of
  `docs/roadmaps/ROADMAP.md` pointing to it, since most of that document's phases are exactly the
  parked work.
- Added methodology caveats to `docs/roadmaps/ROADMAP.md` (the unsupported "~60%" auto-exploit
  success-rate KPI), `docs/reference/WRITEUP_CAPABILITY_ASSESSMENT.md` (the "45/46 (98%)"/"13/13
  (100%)" figures, which measure hand-fed technique execution, not autonomous exploitation), and
  `docs/reference/TEST_RESULTS.md` (precision/recall/accuracy figures, which measure detection on a
  small local corpus, not exploitation). None of the historical numbers were changed or removed;
  each caveat points to `docs/plans/2026-09-23-effectiveness-and-usability.md` Phase 1 as the
  process that will supersede them with honest, reproducible numbers.
- Flagged the three-way license conflict (`LICENSE`=CC BY-NC-SA 4.0, `README.md`=PolyForm
  Noncommercial 1.0.0, `pyproject.toml`/`setup.py`=MIT) with a prominent note in README.md's
  License section. This is a maintainer/legal decision and is intentionally **not** resolved
  here — see `docs/plans/2026-09-23-effectiveness-and-usability.md` Phase 7.

### Fixed
- README.md's Documentation section linked to `docs/DEVELOPMENT.md` and
  `docs/MANUAL_EXPLOITATION_GUIDE.md`, neither of which exists at those paths after a prior docs
  reorg moved both files to `docs/internal/`. Links now point to `docs/internal/DEVELOPMENT.md`
  and `docs/internal/MANUAL_EXPLOITATION_GUIDE.md`.
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

### Fixed
- `supwngo/exploit/auto_leak.py`'s `AutoLeakFinder`'s puts/GOT leak path (the
  `PUTS_GOT` branch of `auto_leak_libc`) was a bare `pass` stub — it recognized the
  leak opportunity but never built or sent a chain. It now builds and sends a real
  `pop rdi; ret` -> `GOT[sym]` -> `puts@plt` chain (and a 3-register
  `write(1, GOT[sym], 8)` chain for the previously also-silently-ignored `WRITE_GOT`
  case), parses the leaked pointer with a zero-pad-not-truncate fix (`puts()` only
  NULs the trailing/high bytes of a little-endian-packed pointer, so the standard
  technique is to zero-pad up to pointer width rather than treat a short read as a
  parse failure), and resolves the exact libc base via the target's own libc ELF
  symbol table when `context.libc.path` is known (falling back to page-alignment
  otherwise). New helper methods: `_leak_via_got_rop`, `_find_gadget_addr`,
  `_resolve_libc_symbol_offset`, `_parse_leaked_pointer`. Verified end-to-end
  against a real compiled no-PIE/no-canary binary and the host's real libc — the
  resolved base matched `/proc/<pid>/maps` ground truth exactly across multiple
  ASLR-randomized runs. Part of Phase 3 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.
- `supwngo/exploit/rop/z3_solver.py`'s `SolvedChain.build()` appended every gadget
  address first and every popped stack value second as two separate flat blocks —
  wrong for any chain with more than one gadget, since a ROP chain needs each
  gadget's own popped values immediately following its address, not grouped at the
  end. `SolvedChain` gained a `pop_values: List[List[int]]` field (per-gadget
  grouping) that `build()` now interleaves correctly when populated, falling back
  to the old flat layout (only correct for single-gadget chains) for the general
  solver methods not yet repaired (see Changed, below).
- `AutoLeakFinder.identify_leaked_value`'s libc-address range check
  (`0x7f0000000000`-`0x7f7fffffffff`) assumed an older, narrower ASLR entropy
  layout. On modern kernels (observed directly during this repair's benchmark
  spot-check — Ubuntu 22.04's default `mmap_rnd_bits`) a genuine libc leak can
  legitimately come back with an address outside that narrow range, causing a
  correct leak to be silently rejected as "not libc". Widened to the whole
  high-mmap region below the already-checked stack range
  (`0x700000000000`-`0x7ffdffffffff`) — found and fixed as a direct blocker of the
  `_leak_via_got_rop` repair above, not a speculative change.

### Changed
- `supwngo/exploit/rop/z3_solver.py`'s `Z3ROPSolver.solve_call` never actually
  invoked `Solver.check()` against a meaningfully-constrained model — despite the
  name, it was a greedy first-match gadget picker. It is now a real (intentionally
  v1-scoped) constraint search: boolean `use`/integer `order` variables per
  candidate "clean pop-chain" gadget, an explicit "final setter per register"
  choice with ordering constraints so a chosen chain can't have an earlier
  gadget's pop clobber a register a later gadget already set for the same
  purpose, and a chain is only returned when `solver.check() == sat`. Scoped, per
  Phase 3 of the effectiveness/usability plan, to "solve a single function call
  with N register arguments via a real z3 constraint search over available
  gadgets" — the general write-what-where case (`solve_write`/`solve_syscall`/
  `solve_execve`/`solve_mprotect`) is unchanged, still uses the old greedy
  `_find_gadget_to_set_reg`, and remains documented future work. `z3` stays a
  lazy/optional import (`Z3_AVAILABLE` guard), so its absence never blocks import
  of the module or the common (non-solver) exploitation path.
- `supwngo/exploit/tester.py`'s `ExploitTester` accepted generic, easily-spoofed
  output-string matches (`TestConfig.success_indicators` — `"got shell"`,
  `"uid=0"`, etc.) as proof of exploitation success on their own. Tightened via a
  new `ExploitTester._evaluate_output` (shared by `test_local`/`test_docker`) to
  the same receipt-token verification pattern `PipelineVerifier`/
  `verification.ExploitVerifier` already use: `test_local`/`test_docker`/
  `test_remote` now accept an optional `token` parameter, and SUCCESS requires
  either a genuine `flag_pattern` match or that unique per-attempt token being
  echoed back in the output — a loose `success_indicators` match alone now only
  downgrades a FAILED result to PARTIAL, never SUCCESS by itself.
  `TestConfig.success_indicators`'s field/default list is unchanged for backward
  compatibility. `tests/test_new_features_integration.py::test_shell_detection`
  updated to demonstrate the tightened contract (a loose `"uid=0(root)"` match
  alone no longer yields SUCCESS; supplying and echoing back a receipt token
  does). Part of Phase 3 of `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Added
- `supwngo/exploit/pipeline/leak_stage.py`'s `acquire_leaks(context)` extension
  point — previously a documented no-op for `needs_leak` targets — now drives the
  repaired `AutoLeakFinder` (see above) as its real implementation: local-only,
  discovers the buffer offset via the same GDB cyclic-pattern probe every other
  native executor uses when `context.offset` isn't already known, and stores a
  recovered libc base on `context.leaks['libc']`/`context.libc.base`.
- `supwngo/exploit/rop/chain.py`'s `ROPChainBuilder.call_function` gained an
  optional fallback (`_call_function_via_z3`) to the repaired
  `Z3ROPSolver.solve_call` (see above) for when its own simple per-register
  gadget lookup is incomplete — a documented pre-existing bug where a missing
  `pop <reg>; ret` gadget was silently skipped rather than failing the chain,
  leaving that argument register unset. The fallback is lazy/optional (safe when
  `z3` isn't installed) and only engages when the primary lookup was actually
  incomplete; if it also can't find a chain, the original (still-documented-
  incomplete) chain is returned rather than raising, preserving the method's
  existing best-effort contract.
- `supwngo/exploit/pipeline/verifier.py`'s `PipelineVerifier` gained
  `verify_via_tester()`, wiring the now-tightened `ExploitTester` (see above) in
  as an available, **non-default** local/docker/remote verification backend
  alongside `verification.ExploitVerifier` — for callers that already have a full
  generated exploit script and want to test it end-to-end (optionally in Docker
  against a specific libc, or against a real remote target) rather than driving a
  raw payload/tube directly via `verify_payload`/`verify_shell`. No native
  pipeline executor calls it automatically; module docstring updated to reflect
  the new verifier composition. Part of Phase 3 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Fixed
- `supwngo/exploit/auto_leak.py`'s `AutoLeakFinder.identify_leaked_value` and
  `auto_leak_pie_base` referenced a nonexistent `self.binary.base` attribute
  (`core.binary.Binary`'s actual field is `base_address`) — an `AttributeError`
  that crashed `identify_leaked_value`'s final non-PIE fallback branch instead of
  returning `LeakType.UNKNOWN`. Found running the repaired `_leak_via_got_rop`
  path (which calls `identify_leaked_value`) repeatedly against a real compiled
  binary during this Phase 3 repair's benchmark spot-check; fixed both call sites
  to use `base_address`.
