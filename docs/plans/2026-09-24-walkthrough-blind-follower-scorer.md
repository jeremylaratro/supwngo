# Walkthrough scorer: blind-follower measurement with a necessity control

Status: PLAN — written before implementation, per the repo's plan-review contract
Date: 2026-09-24
Owner: benchmark / capability measurement
Implements: Problem 1 and Problem 1a of
`docs/plans/2026-09-24-final-round-r5-unseen-corpus.md`
Related: `docs/plans/2026-09-24-walkthrough-families-fmtstr-heap-integer.md`

## Goal

`benchmark/` contains zero references to walkthroughs. R5 gates the generated
0-to-pwn walkthroughs at >= 85% "followable" and there is currently no way to
measure that at all. Build the measurement instrument, with its negative
control, and prove it can return a negative verdict — before any number is
quoted against it.

Non-goal: passing the gate. This change must not make it easier to pass. If the
instrument says round-1 walkthroughs are not followable, that is the finding.

## What "followable" is defined to mean

A walkthrough is **followable** for a target when a *fresh* agent, given only
that walkthrough and that binary, produces an artifact that captures that
build's secret flag **and** the identical agent given only the binary does not.

Three separable claims are bundled there, and the scorer keeps them separate:

1. *The follower captured the flag* — scored by the existing machinery, never by
   the follower's own report and never by `b"flag" in out`.
2. *The capture was exploitation* — `benchmark/attribution.py`'s behavioural
   witness: the flag must be written by the target process or a descendant.
3. *The walkthrough was necessary* — the bare arm (Problem 1a). Without this the
   number measures the follower, not the artifact.

## Decision 1 — what plays the follower

Three candidates were considered. Two are built; one is rejected.

| candidate | measures | deterministic | cost |
| --- | --- | --- | --- |
| A. deterministic template executor | template *validity* | yes | ~free |
| B. headless agent follower (`claude -p`) | *followability* | no | high |
| C. single-shot LLM completion | neither cleanly | partly | medium |

### Chosen: BOTH A and B, measuring different things, reported separately

The two are not redundant and neither is sufficient:

- **A (`--follower template`)** runs the walkthrough's own embedded pwntools
  template (`python3 <walkthrough>.py`) and scores the result through the
  existing pipeline. This is the *literal execution* the families spec already
  demands as its test strategy — it caught wave-1's real defects (a `NameError`
  on an undeclared constant at the reader's first command; ret2shellcode taught
  on an NX binary). It says nothing about whether the prose teaches anything: a
  reader who cannot read a word of it still passes by typing `python3`.
  Therefore **the template arm may never satisfy the 85% gate.** Its verdicts
  are `TEMPLATE_OK` / `TEMPLATE_BROKEN`, deliberately not `FOLLOWABLE`.

- **B (`--follower agent`)** is the gate metric. A headless `claude -p` session
  in a sealed sandbox containing only a copy of the binary and (walkthrough arm
  only) the walkthrough. It produces `exploit.py`; the scorer then discards
  everything the follower said and scores that artifact exactly as `run_bench.py`
  scores an autopwn artifact.

A `TEMPLATE_BROKEN` result does **not** excuse the target from the agent arm.
It is recorded as a walkthrough defect and counted against the walkthrough in
the strict rate. Excluding it would let a broken artifact shrink the denominator
and flatter the score — the exact VOID-inflation failure mode `run_bench.py`
already guards.

### Rejected: C, the single-shot completion

One completion, no tool loop, no debugging. Cheaper than B and more repeatable,
but its failures are dominated by "no iteration available", not "the walkthrough
was unclear" — it systematically under-measures followability, and a metric that
fails for reasons unrelated to what it names is worse than an expensive one.

**What would flip this:** if the agent arm's cost makes routine R5 measurement
impractical *and* a measured comparison on >= 8 targets showed one-shot outcomes
agreeing with agent outcomes, C becomes the cheap proxy and B the periodic
calibration. That comparison has not been run, so B stays primary.

## Decision 2 — the necessity control (Problem 1a)

Per rep, the identical follower runs a **bare arm**: the same sandbox, the same
prompt scaffolding, the binary and "capture the flag" — and no walkthrough.
Scored through the identical pipeline.

Target verdicts:

| verdict | condition | in the gate denominator? |
| --- | --- | --- |
| `FOLLOWABLE` | walkthrough arm credited, bare arm never credited | yes (numerator) |
| `NOT_FOLLOWABLE` | walkthrough arm never credited, bare arm never credited | yes |
| `UNINFORMATIVE` | bare arm credited in **any** rep | **no** |
| `VOID` | corpus/provisioning/instrument fault (inherited from `run_bench`) | no |

`UNINFORMATIVE` is deliberately **asymmetric and conservative**: one bare
success destroys the claim that the walkthrough contributed anything, whereas
crediting the walkthrough requires its own evidence. The asymmetry always
points away from crediting the walkthrough.

Consequence accepted up front, as the R5 spec requires: a strong follower makes
easy targets uninformative and shrinks the denominator. The report states
`FOLLOWABLE / informative`, `FOLLOWABLE / scored`, and `FOLLOWABLE / total`
side by side, and names every uninformative target. It is never silently
dropped.

## Decision 3 — reps and determinism

`run_bench.py --reps N` reports `solved` (>= 1 rep) and `reliability` (k/N)
because best-of-N without reliability is gaming and a single rep understates.
A nondeterministic follower makes the same split necessary and adds a trap:
best-of-N applied to *both* arms would eventually let a competent bare arm win,
so N must be paired, not per-arm.

- Reps are **paired**: rep *i* runs the walkthrough arm and the bare arm, each
  with its own freshly minted secret flag and its own fresh sandbox. The
  comparison is within-rep.
- Reported per target: `walkthrough_reliability = k/N`,
  `bare_reliability = j/N`, and the verdict above.
- The headline states it is best-of-N, as `write_summary` already does.
- Default `--reps 3` for the agent arm (cost), `5` for the template arm
  (matching `run_bench`'s default, since it is nearly free).

## Decision 4 — follower capability tier, pinned

A stronger follower raises both arms and shifts what `UNINFORMATIVE` means, so
the tier is part of the measurement and is recorded in `report.json`:
`follower_model`, `follower_effort`, `follower_allowed_tools`,
`follower_budget_usd`, `follower_wall_timeout_sec`, `follower_cli_version`.

Default tier: **`sonnet`** — Tier 3 in this repo's model tiering, i.e. a
competent implementer, which is the population a teaching artifact is written
for. Not the frontier tier: a frontier follower maximises both arms, maximises
`UNINFORMATIVE`, and measures less.

The report states plainly that a figure produced at one tier is not comparable
to a figure produced at another.

### Blindness, enforced rather than asserted

- `claude -p` with cwd = a sandbox under `$TMPDIR`, **outside the repo**, so no
  `CLAUDE.md`, plan, or prior-round note is discoverable above it.
- `--disable-slash-commands`, `--strict-mcp-config` with an empty MCP config, no
  `--add-dir`.
- The sandbox contains exactly: the binary (copy), `flag.txt` (copy — required
  so a shell-obtaining exploit can read it, exactly as `run_bench` does), and in
  the walkthrough arm the walkthrough file. No `.c` source, no reference
  exploit, no supwngo tree.
- The follower is never told the flag. It *can* trivially `cat flag.txt`; that
  is by design and gains it nothing, because attribution credits only a write
  from the target's process tree. The pre-existing `script_gamed_the_check`
  channel becomes the per-arm outcome `FOLLOWER_GAMED`, not a credit.
- The walkthrough is passed **byte-for-byte unmodified** (its `BINARY = '<abs
  path>'` constant points at the corpus copy). Both arms' prompts state the
  sandbox binary path identically, so that harness mechanic is not a hint to
  one arm only. Rewriting the artifact was rejected: the follower must see what
  a user receives.
- Every prompt and the full follower transcript are archived per rep for audit.

## Decision 5 — no self-scoring, structurally

The walkthrough engine is never consulted about its own output. The scorer takes
walkthroughs as **files** (`--walkthrough-dir`), or generates them by invoking
the CLI as a subprocess (`--generate`). Scoring is the `run_bench.py` /
`attribution.py` path, unchanged and imported, never reimplemented:
`build_with_secret`, `negative_control`, `inspect_generated_script`,
`independent_verify`, `attribution.witness`, `attribution_verdict`.

One small addition to `attribution.py` is needed: `witness()` hardcodes
`[python, script]`. The agent arm needs to trace an arbitrary argv. Refactor is
surgical — extract `witness_argv(argv, ...)` and have `witness()` delegate, so
`run_bench.py` is untouched and its behaviour is bit-identical.

## Decision 6 — proving the scorer can fail

A validation step that cannot fail is worse than none; this project has found
four. So falsifiability is a committed, runnable artifact, not a claim.

`benchmark/walkthrough/fixtures/` ships hand-written walkthroughs against
`02_ret2plt_system`, and `score.py --selftest` asserts each verdict:

| fixture | defect | required verdict |
| --- | --- | --- |
| `good_reference.py` | none (the verified reference chain) | **CREDITED** |
| `broken_wrong_offset.py` | correct route, offset off by 8 | NOT CREDITED |
| `broken_undeclared_constant.py` | `NameError` at the reader's first command | NOT CREDITED |
| `broken_impossible_route.py` | ret2shellcode taught on an NX binary | NOT CREDITED |

Ordering is the `ablate.py` pattern: the **positive control runs first**. If
`good_reference.py` does not score CREDITED, the harness is broken and the
selftest reports `NOT MEASURABLE` and exits non-zero rather than reporting the
three negatives as passes — a broken scorer would otherwise "fail everything"
and look maximally strict.

Exit codes: `0` all controls behaved; `1` a control gave the wrong verdict
(scorer defect); `2` could not measure (unbuilt corpus, no strace, positive
control failed).

## Files touched

| file | change |
| --- | --- |
| `benchmark/walkthrough/score.py` | new — the scorer, both arms, controls, report |
| `benchmark/walkthrough/followers.py` | new — template + agent follower drivers |
| `benchmark/walkthrough/README.md` | new — how to run, how to read a verdict |
| `benchmark/walkthrough/fixtures/*.py` | new — 1 positive + 3 broken fixtures |
| `benchmark/attribution.py` | extract `witness_argv`; `witness` delegates |
| `CHANGELOG.md` | `[Unreleased] / Added` |

`run_bench.py` is **not** modified. `benchmark/corpus/` is **not** modified.

## Outputs

`benchmark/results_walkthrough/<ts>/` (sibling of `results*`, gitignored):
`report.json`, `summary.txt`, per-target/rep/arm `exploit.py`, prompts,
follower transcripts, strace logs.

## Test strategy

1. `--selftest` — the four fixtures above. Positive control first. This is the
   proof the scorer can return a negative verdict.
2. Template arm over all round-1 targets that have a generated walkthrough.
3. Agent arm end-to-end on a named subset, with both arms, reporting
   `UNINFORMATIVE` counts. The subset size is stated in the result; a
   full-corpus agent run at R5 scale is a separate, budgeted run and is not
   claimed here.
4. `--corpus-root` pointed at this worktree's corpus; `corpus_lock` respected by
   reusing `run_bench.corpus_lock`.

## Risks

- **Cost/time of the agent arm.** N targets x 2 arms x R reps headless sessions.
  Mitigated by `--target`, `--reps`, `--max-budget-usd`, and by the template arm
  being the cheap smoke test.
- **Follower nondeterminism inflating `UNINFORMATIVE`.** Accepted and reported,
  never smoothed. The conservative direction is the honest one.
- **The walkthrough engine is on an unmerged branch**
  (`feat/walkthrough-engine-20260923`). The scorer therefore depends on
  walkthrough *artifacts*, not on the engine, and degrades to a clear error if
  `supwngo explain` is absent. It is family-agnostic by construction: nothing in
  it names `stack_bof`, `rop_chain`, `fmtstr`, `integer` or `heap`.
- **Heap detection-only walkthroughs cannot pass a flag-capture gate** (families
  spec, "Interaction with the R5 walkthrough gate"). Out of scope here: the
  scorer reports per-family counts so that decision can be made on measured
  numbers, but it does not pre-emptively exclude any family. Excluding a family
  is a declared-before-measuring policy call for the maintainer, not a default
  the instrument should bake in.

---

# Independent review and revision (same day)

Reviewed by an independent Tier-2 peer (gpt-5.6-sol, xhigh). Verdict:
**NOT-APPROVED**, 5 blocking + 4 major findings. Full text:
`docs/plans/reviews/2026-09-24-walkthrough-blind-follower-scorer-review-codex.md`.

The review is right about the important things. The plan above is superseded on
the points below; what shipped is this section.

## R1 — Flag laundering defeats attribution (review #3, BLOCKING)

The hole: the follower is handed the real `flag.txt`. It can read the flag and
**send those bytes to the target**, which echoes them back — so the *target*
writes the flag and attribution credits it. `run_bench.py` does not have this
hole because autopwn is a non-adaptive generator that is never handed the flag;
an interactive agent with a shell absolutely does. This would have been a
silent, undetectable false SUCCESS channel.

Two structural defences, both implemented, because neither alone is enough:

1. **Decoy-then-remint.** The follower works against a *decoy* secret (same
   length, so layout is identical). When it finishes, its `exploit.py` is
   **frozen** (copied out and hashed), the sandbox is **wiped** of everything
   except the artifact and the walkthrough, the target is **rebuilt with a
   fresh secret the follower has never seen**, and the frozen artifact is then
   scored against that. This kills hardcoding, generation-time scraping, and
   any decoy-bearing copy of the binary the follower made.
   Re-minting alone does *not* close runtime laundering, which is why:
2. **Behavioural open-audit.** Scoring traces `openat/open` as well as
   `execve/write/clone`, and if a process **outside the target's lineage** opens
   `flag.txt`, the trial is `FOLLOWER_LAUNDERED` and not credited. A shell the
   exploit obtained opening `flag.txt` is legitimate and distinguishable by
   exactly the lineage rule attribution already uses for writes. Opening
   `flag.txt` from the artifact's own process has no legitimate exploit purpose.
   This is behavioural, not a regex, so it is not an arms race.

## R2 — Denominator inflation (review #1 and #9, BLOCKING)

The R5 spec directs `UNINFORMATIVE` out of the walkthrough denominator; the
reviewer is right that this lets a *failing* target be removed by a bare-arm
success and the rate go **up**. Both cannot be satisfied, so the instrument
reports both and declares which is gate-safe:

- `rate_strict = FOLLOWABLE / eligible` — `UNINFORMATIVE` and
  `NOT_MEASURABLE` count as non-passing. **Cannot be inflated by anything
  breaking. This is the gate figure.**
- `rate_informative = FOLLOWABLE / (FOLLOWABLE + NOT_FOLLOWABLE)` — the R5
  spec's figure, printed with its denominator and the excluded slugs named.
- `rate_total = FOLLOWABLE / total`.

`eligible` is the pre-declared non-VOID set, and **VOID is determined before any
follower runs** (review #1), from the existing negative controls. If
`UNINFORMATIVE + NOT_MEASURABLE` exceeds 20% of `eligible`, the informative rate
is **withheld as a gate result** — the denominator has moved too far to be the
same measurement — following `write_summary`'s existing RATE WITHHELD pattern.

A gate verdict is emitted **only** when: follower is `agent`, the full eligible
manifest was run, no target is `NOT_MEASURABLE`, and reps are as declared.
Subset runs report `gate_result: null` with the reason. The spec/reviewer
conflict is surfaced for the maintainer, not silently resolved.

## R3 — Trial validity must gate credit (review #6, MAJOR)

"Bare arm never credited" previously conflated genuine failure with missing
evidence: a CLI crash or a wall timeout in the bare arm could *enable*
`FOLLOWABLE`. Now every scheduled trial in both arms must be **valid** (the
follower ran to completion; a wall timeout with no artifact is invalid, a clean
exit with no artifact is a genuine failure) or the target is `NOT_MEASURABLE`.
`BLINDNESS_SUSPECT` also forces `NOT_MEASURABLE`.

## R4 — Best-of-N tunability (review #7, MAJOR)

- No early stopping: **every scheduled trial runs**, successes included.
- Arm order fixed (`walkthrough` then `bare`) and recorded.
- No retries. Every trial appears in `report.json`, including invalid ones.
- Per-attempt rates are reported next to the best-of-N figure, as
  `run_bench.py` already does for autopwn.

## R5 — Paired accounting instead of an unearned necessity claim (review #2)

The verdict is a conservative **screen**, not a treatment-effect estimate, and
the report says so. At N=3 no confidence bound is meaningful and none is
printed. What is printed is the within-pair contingency table the review
correctly noted was missing: `walkthrough_only`, `both`, `neither`,
`bare_only`, plus each arm's k/N.

## R6 — The metric is artifact-followability, named honestly (review #8, MAJOR)

The reviewer is right that a follower handed a runnable template can copy it, so
the verbatim-artifact metric is **artifact usability**, not prose
comprehension. Two responses, both shipped:

- The metric is renamed in every output: `artifact_followable`. No output claims
  prose was followed.
- `--walkthrough-variant prose` ships a genuine prose-only arm: an auditable
  one-rule redaction (comment lines and the constants block survive; every
  executable statement is stripped), so the follower must reconstruct the
  exploit from the teaching. Default stays `verbatim`; the variant is recorded
  in the report and a figure from one variant is not comparable to the other.

## R7 — Isolation: what is enforced, what is documented (review #4, BLOCKING-as-filed)

Accepted in part. OS-level isolation (container, user namespace, network-denied
image) is the correct answer and is **not built here** — it is a separate piece
of infrastructure. What is enforced instead:

- Sandbox outside the repository; fresh per-sandbox `TMPDIR`.
- The CLI already confines `Read/Write/Edit/Glob/Grep` to cwd; no `--add-dir`.
- No `WebFetch`/`WebSearch` in the tool allowlist, and they are explicitly
  denied.
- `--disable-slash-commands`, `--strict-mcp-config` with an empty MCP config.
- Repo-bearing `PYTHONPATH` entries and all `SUPWNGO_*` variables stripped, so
  `import supwngo` fails.
- The walkthrough is sanitised of repository paths and the run **fails closed**
  if any survive.
- `blindness_audit()` scans transcript and artifact and forces
  `NOT_MEASURABLE` on a hit.

`HOME` is **shared**, because the follower CLI reads its credentials there. That
is the largest residual isolation gap and is recorded as a first-class field
(`isolation: "process-level, not OS-level"`) in every report, in the same spirit
as `attribution.py`'s stated residual gap. A number produced under
process-level isolation must not be quoted as if it were produced under OS-level
isolation.

## R8 — The selftest must test the scorer, not just fixtures (review #5, BLOCKING)

The fixture set alone could be passed by a scorer that special-cases filenames
or merely rejects crashing scripts. Three layers now:

1. **Fixture layer** (positive control first): good reference → CREDITED; wrong
   offset / undeclared constant / impossible route → NOT CREDITED. Fixtures are
   copied to randomised filenames before scoring, so filename special-casing
   cannot pass.
2. **Laundering layer**: `broken_launders_flag_file.py` reads `flag.txt` and
   relays it through the target. Must score `FOLLOWER_LAUNDERED`.
   `broken_stale_secret.py` hardcodes a previous run's flag. Must score
   `NO_FLAG`. These prove R1's two defences actually fire.
3. **Arithmetic layer**: `target_verdict()` and the rate arithmetic are exercised
   as an explicit truth table — every verdict, the inflation case, invalid
   trials, VOID, and the withholding rule — with asserted expected outputs. Plus
   a differential check that `witness()` and `witness_argv()` agree.

## R9 — Provenance hashes (review #10, MINOR)

`sonnet` is a mutable alias and cannot be pinned from here; that is recorded as
a stated limitation. What is pinned: sha256 of every walkthrough artifact, every
frozen follower artifact, and every prompt, in `report.json`.
