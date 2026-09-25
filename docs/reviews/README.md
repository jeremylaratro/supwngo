# Reviews

Independent plan and code reviews, recorded **verbatim** with a header stating the
reviewer, the artifact revision reviewed, the prompt size, and the assertion that
the output was non-empty before it was read. An `exit 0` with empty output reads
silently as approval, so non-emptiness is asserted rather than assumed.

Each record carries, above the verbatim text:

- the **RECURRENCES / NEW / INTRODUCED** decomposition, reported before any
  revision is made;
- `NEW` classified against the **whole document set**, not only the previous round
  — a class named anywhere in an earlier round or peer review is a RECURRENCE even
  if the current reviewer could not have seen it;
- which of the reviewer's hits were **checked** before being accepted. A sweep
  yields candidates, not findings; reporting an intentional absence as a gap costs
  a round exactly as a skipped sweep does.

## Standardized context schema (v4)

| round | artifact reviewed | verdict | R / N / I | record |
| --- | --- | --- | --- | --- |
| unit 1, round 1 | unit-1 plan rev 1 | NOT-APPROVED | 5 / 0 / 3 | [`../plans/2026-09-24-schema-unit-1-review-round1.md`](../plans/2026-09-24-schema-unit-1-review-round1.md) |
| unit 1, round 2 | unit-1 plan rev 5 | NOT-APPROVED | 4 / 0 / 5 | [`2026-09-24-schema-unit-1-review-round2.md`](2026-09-24-schema-unit-1-review-round2.md) |

Rounds 1–4 of the parent effort, and unit 1's round-1 review, predate this
directory and live in `docs/plans/` beside the plans they review. Round 1's record
is **not** moved, because a verbatim copy of the coordinator's authorization
(`../plans/2026-09-24-schema-unit-1-round1-authorization.md`) references it by
path, and editing a verbatim record to tidy a filename is the wrong trade.

`NEW` has been **0 for three consecutive rounds** on this module. Adversarial
discovery has converged; the findings come from sweeps not run and from
remediation defects, not from undiscovered classes.
