# Resume queue after the 24 Sep 2026 usage-limit termination

**Date:** 24 Sep 2026
**Cause:** session usage limit (HTTP 429, `rate_limit`), reset 16:50 EDT. **Eight
concurrent agents were terminated mid-flight. None failed on its own work.**
**Purpose:** record what state each branch was left in, and in what order to resume.

## The operational lesson

Eight concurrent agents exhausted the session budget, and one of them had itself
fanned out into six authoring sub-agents — so the real concurrency was ~14. The
termination was indiscriminate: it took the plan reviewer that had done nothing yet
and the consolidation agent that was one command from committing a merge, with equal
prejudice.

**Resume at three concurrent, not eight, and do not let a resumed agent fan out.**
Nothing in the queue below is latency-critical; the only thing that was ever
irrecoverable is a single-use corpus measurement, and none was in flight.

## Fragile state, recorded before anything touches it

Only three worktrees had uncommitted work. Two held untracked files, which are the
only genuinely destructible artifacts — a `reset --hard`, `checkout .`, `clean` or
`merge --abort` would remove them, and they exist nowhere in git.

| worktree / branch | state |
| --- | --- |
| `agent-a5c20160832de222f` — `integration/walkthrough-families-consolidated-20260924` @ `ac3cb9b` | **Unresolved merge. `MERGE_HEAD` present.** 3 conflicts: `CHANGELOG.md`, `walkthrough/families/__init__.py`, `walkthrough/registry.py`. Untracked: `tests/test_walkthrough_route_sweep.py`, `tests/test_walkthrough_scores.py` |
| `agent-aa340ba4df363ee2e` — `feat/context-schema-v4-20260924` @ `62c3859` | Untracked: `docs/plans/2026-09-24-context-schema-v4-review-round3.md` (the round-3 NOT-APPROVED review, 9 HIGH / 5 MEDIUM / 2 LOW) |
| `agent-a4280e6cbeb0a8ec7` — `feat/benchmark-corpus-20260923` @ `2191739` | Untracked `solve_output/` only. Disposable. |

All three untracked files are snapshotted to
`/srv/share/dev/_archive/supwngo-inflight-snapshot-24SEP2026/`. **The worktree copies
remain authoritative**; restore from the snapshot only if a worktree copy is already
gone.

`registry.py` being a merge conflict is the one that needs care rather than speed:
walkthrough family selection **resolves ties on list order**, so a careless
resolution of `_families()` silently changes which family wins on a tie — a defect
that would pass every test and only show up as a wrong walkthrough.

## Resume order

**Resumed immediately (tier 1):**

1. `a5c20160832de222f` — consolidation. First because leaving a repo in a conflicted
   merge is the worst state to leave anything in. Then the six-family score-tie
   sweep, the 15-target regression, the combined suite, and only then heap.
2. `a70d98318defde0a3` — independent review of the instrumentation plan
   (`b022b2d`). It had done no work, so nothing is lost. It blocks all R2 step-3
   implementation; `supwngo/` is untouched since `b3a40b4`.
3. `aa340ba4df363ee2e` — schema v4. Commit the round-3 review verbatim first, then
   fix the 9 HIGH.

**Deferred (tier 2), to start as tier 1 drains:**

4. `a48442d67c54a98ea` — blind-follower scorer. Was mid-run on
   `12_heap_tcache_poison`, both arms in follower phase. Two asks outstanding: the
   retroactive scan for any credited rep resting on a **failed** `execve`, and the
   follower-tier decision given `04`/`08`/`09` all came back UNINFORMATIVE with the
   bare arm at 2/2.
5. `a419d7c10e576f6b6` — R5 corpus generator, at `ad9e6d1` = scaffold plus **2 of 15
   targets**. Its six authoring sub-agents died too. Deliberately last: R5
   *measurement* is gated (see below) and a partially authored held-out corpus is not
   a hazard as long as nobody mistakes 2/15 for complete.
6. `a52935c6c8d84b050` — interactive fuzz corpus builder, test infrastructure green
   (21 passed), waiting on its own library-implementation sub-agent.

## Carried constraints that outlived the termination

- **R5 measurement is gated on I3 covering `variable_overwrite`**, not on the
  `comparison_immediates()` capability fix. Generation and sealing are not gated and
  may proceed. See `2026-09-24-final-round-r5-unseen-corpus.md` §"Precondition".
- **No implementation in `supwngo/` for R2 step 3** until the instrumentation plan
  review returns. Two predecessor revisions were NOT-APPROVED; there is no rev 3.
- The R2 cold figure **4/15** and the R1 baseline **13/13** are unaffected by
  anything in flight. Both were verified uncontaminated by the magic-constant sweep
  (no credited target in either run was solved by `variable_overwrite`), pending the
  reviewer's independent confirmation of that same claim.

changelog: none
