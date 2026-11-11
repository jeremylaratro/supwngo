# Outstanding work audit — 11 NOV 2026

What is still open across `docs/plans/`, `docs/roadmaps/` and the 2026-09-29 handoff, taken
after the repo was reconciled to a single `main` (`661b04b`). Plan `Status:` headers are stale
throughout, so every status below comes from the CHANGELOG, git history or the code, not from
the header.

## Repo reconciliation (this session)

- Landed on `main`: the corpus_r2 sprint (`9b3d3d4`, merged `69156c0`), a fix for a stale
  late-block test (`30d38b5`), and the parked dataflow fix (`661b04b`).
- Measured on `9b3d3d4` before merging:
  - `corpus_r2` 15/15 (was 12/15). r2/05, r2/09 and r2/11 are now solved, and the r2/03, r2/10
    and r2/13 guards are unchanged.
  - `corpus_fsop` 3/3. Guards `corpus/11` and `corpus/12` both reach FLAG_CAPTURED.
  - Full suite: 2082 passed, 1 failed, 19 skipped. The failure was
    `test_executor_has_late_stable_name`, which was already failing on `4f36ef4`. `30d38b5`
    fixes it.
- The `test_fsop_executor` live-variant cases are skipped unless `corpus_fsop` is built. Once
  built, 2 of the 3 failed in one run and all 3 passed on an isolated rerun. Treat them as
  intermittent.
- Deleted: 10 merged remote branches, 5 local branches and 5 worktrees.
- The held-out `feat/benchmark-corpus-r{3,4,5}` branches were archived and then deleted, on the
  owner's decision. The archive is `/srv/share/dev/_archive/supwngo-heldout-corpora-11NOV2026/`.
  All three corpora have 15 targets authored and none has been cold-measured.

## Handoff (2026-09-29) "do this next"

| item | state |
|---|---|
| 1. Verify and merge the corpus_r2 sprint | Done (above) |
| 2. Sweep corpus_r2 and corpus_fsop | Done on the merged code (above) |
| 3. Cut release 2.2.0 | Not done: `supwngo/__init__.py:20` and `pyproject.toml:7` still read 2.1.0, and the only tag is `v2.1.0` |
| 4. N3 double fetch, then N2 stack clash | Not started: no executor and no corpus. The N3 prompt in `/tmp/codex-out/` is gone; regenerate it from `docs/plans/2026-09-28-three-new-categories-plan.md` |

Deferred items from the handoff:

- `pie_base_offset()` (`rop_techniques.py:128-149`) has no callers. Its job moved to
  `classify_volunteered_output` and `_rank_pie_leaks`, so delete it rather than harden it.
- Still open: `uaf` PARTIAL-only (G-25); the flag comments in three corpus YAMLs (a history
  rewrite is the owner's call); `subprocess_injection` taking ~72.9 s per menu target; 7 of 9
  round-1 flag oracles never individually controlled.

## Plans that are still open

| plan | state | remaining |
|---|---|---|
| 2026-09-28-three-new-categories | PARTIAL (1/3) | N2 and N3 |
| 2026-09-25-cli-surface-and-reachability | PARTIAL | `serve`/api is not wired; 11 `exploit.heap` modules are not registered as pipeline techniques; `--libc` exists on only 7 commands; no reachability regression test |
| 2026-09-24-pipeline-instrumentation-pass | PARTIAL | I4: `DeliveryResult.timed_out` has no consumer (`delivery.py`) |
| 2026-09-24-interactive-fuzz-corpus-builder-standard-mode | NOT STARTED | Only the plan landed; there is no `fuzz-corpus` command or module |
| 2026-09-24-final-round-r5-unseen-corpus | NOT MEASURED | R5 is authored (15 targets) but now lives only in the archive. The 50%/85% gates are unresolved |
| 2026-09-24-standardized-context-schema | SUPERSEDED | Only unit 1 shipped; units 2 and 3 were never planned |
| 2026-09-23-fix-and-improvement-catalog | PARTIAL | Legacy bugs remain: the UAF detector passes `name=` (`vulns/uaf.py`), FORTIFY `_chk` substring matching, duplicate `sprintf` keys in `static.py`, the libc_db raw-int wire format, and honggfuzz "coming soon" (`cli.py:206`) |
| 2026-09-26-retest-sprint-map | PARTIAL | Sprint 4 (`explain` on PIE) deferred |
| 2026-09-26-m1b-variation-benchmark | PARTIAL | Replay, recipe capture, reducer and control contract were not built |
| 2026-09-26-b3-container-registry | SUPERSEDED | The generic registry was never built; `DeliverySpec.container` is unused |
| 2026-09-26-a1-modularity-assessment | REJECTED | Needs a bigger design or should be dropped |

Everything else in `docs/plans/` is done, superseded or closed. All of `docs/roadmaps/` except
`PARKED.md` is obsolete: those are Dec-2025 plans whose packages were deleted in `8429080` or
replaced by the canonical pipeline.

## Owner decisions outstanding

1. Walkthrough gate shape and budget: `docs/plans/2026-09-24-walkthrough-gate-metric-decision.md`.
2. Whether the 85% gate can be measured at the Tier-3 follower:
   `docs/plans/2026-09-24-walkthrough-follower-tier-decision.md` §5.
3. D-1, the legacy fallback: keep it, remove it, or make it opt-in (it still runs by default).
4. I-45: whether to rewrite history to remove the YAML flag comments.
5. A-1 / M-1b / B-3: fund each one or close it.
6. When to cold-measure R3/R4/R5. `PARKED.md` makes reopening its items conditional on a
   blind-set result.

## Capability gaps with no plan behind them (from the 09-25/09-26 reports; not re-run)

- `heap-analysis` and `integer-analysis` emit invalid JSON on 3 of 7 binaries.
- `leaks` returns nothing and `decompile` fails on 7 of 7.
- `cfg` and `dataflow` time out on static binaries.
- Stripped and tcache misreports.
- `report` finds 0–1 findings per binary.
- The `--libc-path` / loaded-libc check is missing, and the default libc version is "2.31"
  (`utils/config.py:33`).
- No RISC-V or PowerPC support.

## Stale docs

- Plan `Status:` headers, e.g. complete-corpus-r2 still says "not yet handed off".
- The coverage map still marks corpus_r2 rows REFUTED although those targets now solve.
- The work queue's T-1 row still says 4/7.
- The handoff's "exact repo state" table is superseded by this report.
