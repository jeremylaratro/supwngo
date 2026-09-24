# Parked / Deferred Scope

Status as of 2026-09-23. Source of truth: `docs/plans/2026-09-23-effectiveness-and-usability.md`
("Deprioritized / Parked" section) and `docs/plans/2026-09-23-fix-and-improvement-catalog.md`
Section 6 (module-triage audit), which corrected the original table (`kernel/` removed,
`reporting/` reclassified). This document mirrors those corrections; if the two ever disagree,
the plan document is authoritative.

## Why this exists

The current effort (`docs/plans/2026-09-23-effectiveness-and-usability.md`) is scoped narrowly: get
supwngo to reliably solve Linux ELF **userspace** binaries end-to-end via one honest, autonomous
`solve` command. Most of what `ROADMAP.md` in this same directory describes — AI/LLM integration,
CFI/CET/MTE/PAC bypass, distributed/cloud fuzzing, cross-platform expansion, an enterprise API — is
exactly the kind of speculative-breadth work that effort explicitly does **not** cover right now.
This document lists that work so it's easy to find, not lost, and not mistaken for current scope.

**Rule for reviewers/implementers:** nothing in the table below is deleted — it is frozen and
labeled. Reopen only after the Success Metrics in
`docs/plans/2026-09-23-effectiveness-and-usability.md` are met on the held-out/blind evaluation set.

## Parked (out of scope for the current effort)

| Item | Where it lives today | Why parked |
|---|---|---|
| CFI / CET / shadow-stack / MTE / PAC bypass, COOP gadgets | `ROADMAP.md` Phase 4, `CUTTING_EDGE_ROADMAP.md` | Sketched interfaces, not working code; irrelevant to the high-frequency CTF techniques that move the 75% metric. |
| More House-of-X heap variants, BROP, JOP, seccomp enhancements (beyond the common UAF/tcache case) | `IMPLEMENTATION_PLAN_V2.md` Phase 4 | Exotic breadth; common heap-UAF (Phase 5 of the effectiveness plan) is the only heap work justified now. |
| Windows / macOS / embedded / containers expansion | `windows/`, `macos/`, `embedded/`, `containers/` | Framework is Linux-ELF-focused per its own CLAUDE.md; not wired into the live pipeline; expansion multiplies untested surface. |
| Distributed / cloud fuzzing infrastructure, Kubernetes deployment | `distributed/` | Infrastructure sprawl unrelated to single-binary success or the unified command; also currently contains one of the Phase-0 syntax errors. |
| Enterprise REST/GraphQL API module | `api/` | Not wired in; unauthenticated by default if ever launched, binds `0.0.0.0:8080`, `cors_origins=["*"]` — a real hardening gap if revived, moot while parked. |
| LLM / RL-based exploit generation | `ai/` | Speculative, unproven; also contains two `pickle.load()` sinks worth fixing independently of whether this is ever revived. |

## Explicitly NOT parked

- **`kernel/` is live and out of scope for a different reason — it is not dead weight.**
  ~6,005 LOC, ~1% stub density (1/166 functions), and genuinely wired into the CLI today
  (`supwngo kernel <module.ko>`). It is excluded from the current effort only because that effort
  is scoped to Linux-ELF-**userspace**, not because it's unfinished or unmaintained. Do not list it
  in the table above or treat it as frozen.
- **`reporting/` is a future wire-in candidate, not frozen indefinitely.** ~1,822 LOC of solid
  CVSS calculator / SARIF exporter / multi-format (HTML/MD/JSON/SARIF/PDF/TXT) reporting code,
  currently unwired like the items in the table above — but flagged as a strong candidate to
  surface through the unified `solve` command's success/hand-off output once the core pipeline
  (Phases 0-4 of the effectiveness plan) is proven. Revisit after Phase 4.

## See also

- `docs/plans/2026-09-23-effectiveness-and-usability.md` — the active plan (what's actually being
  worked on, and the Success Metrics that gate reopening anything above).
- `docs/plans/2026-09-23-fix-and-improvement-catalog.md` Section 6 — the module-triage audit this
  table is corrected against.
- `docs/roadmaps/ROADMAP.md` — the aspirational "Next Generation" roadmap most of the table above
  is drawn from.
