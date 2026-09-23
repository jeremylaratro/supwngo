# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
