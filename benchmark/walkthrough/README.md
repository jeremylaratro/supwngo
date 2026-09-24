# Walkthrough scorer — blind-follower measurement

Measures whether supwngo's generated 0-to-pwn walkthroughs are **followable**.
Before this existed, `benchmark/` contained zero references to walkthroughs, so
the R5 spec's `>= 85% followable` gate was a threshold against a metric that did
not exist. Inventing a lenient one later to clear that gate is the exact failure
this benchmark was built to prevent.

Design: `docs/plans/2026-09-24-walkthrough-blind-follower-scorer.md`
Peer review: `docs/plans/reviews/2026-09-24-walkthrough-blind-follower-scorer-review-codex.md`
Spec: `docs/plans/2026-09-24-final-round-r5-unseen-corpus.md`, Problem 1 / 1a

```
benchmark/walkthrough/
├── score.py       the scorer: both arms, the controls, the report
├── followers.py   who plays the follower; blindness; the prose redaction
├── selftest.py    the falsifiability controls (three layers)
└── fixtures/      one good + six deliberately broken artifacts
```

## Run

```bash
# 1. FIRST. Proves the scorer can return a NEGATIVE verdict. No LLM, no cost.
python3 benchmark/walkthrough/score.py --selftest \
    --corpus-root benchmark/corpus --manifest benchmark/corpus.yaml

# 2. Cheap deterministic arm: does each walkthrough's own template work?
python3 benchmark/walkthrough/score.py --follower template \
    --walkthrough-dir <dir-of-generated-walkthroughs> \
    --corpus-root benchmark/corpus --reps 3

# 3. The gate metric: blind agent follower, both arms.
python3 benchmark/walkthrough/score.py --follower agent \
    --walkthrough-dir <dir> --corpus-root benchmark/corpus \
    --reps 3 --model sonnet --strict-attribution
```

Pass `--corpus-root` pointing at **your** corpus: a run rebuilds every target
with a fresh secret and holds `run_bench.corpus_lock`, so two runs over one
corpus corrupt each other.

## What a walkthrough is credited for

A walkthrough is credited for a target when a **fresh follower**, given only that
walkthrough and that binary, produces an artifact that captures that build's
secret flag — **and the identical follower given only the binary does not**.

Two arms, always:

| arm | what the follower gets |
| --- | --- |
| `walkthrough` | the binary and the walkthrough |
| `bare` | the binary and "capture the flag". Nothing else. |

The follower never receives the flag, is never told the verdict, and everything
it *says* is discarded. Only the file it wrote is scored, through the machinery
`run_bench.py` already uses on an autopwn artifact — fresh per-rep secret,
independent re-execution, negative controls, behavioural attribution. The
walkthrough engine never grades its own output, and `b"flag" in out` is not a
verdict.

## Verdicts

| verdict | meaning | in the strict denominator? |
| --- | --- | --- |
| `FOLLOWABLE` | walkthrough arm captured the flag; bare arm never did | yes — numerator |
| `NOT_FOLLOWABLE` | neither arm captured it | yes |
| `UNINFORMATIVE` | the **bare** arm captured it in **any** rep | yes (as non-passing) |
| `NOT_MEASURABLE` | instrument fault, invalid trial, or a blindness break | yes (as non-passing) |
| `VOID` | corpus/provisioning fault, from `run_bench`'s own controls | **no** |
| `TEMPLATE_OK` / `TEMPLATE_BROKEN` | template follower only — see below | n/a |

`UNINFORMATIVE` is asymmetric on purpose: **one** bare success destroys the claim
that the walkthrough was necessary, whereas crediting the walkthrough needs its
own evidence. The asymmetry always points away from crediting the walkthrough.

`NOT_MEASURABLE` on an invalid trial matters most in the **bare** arm. If a bare
timeout or CLI crash were read as "the bare arm did not solve it", it would
*enable* a `FOLLOWABLE` verdict on missing evidence.

## Three denominators, and which one is the gate

```
rate_strict      FOLLOWABLE / eligible     <- THE GATE FIGURE
rate_informative FOLLOWABLE / (FOLLOWABLE + NOT_FOLLOWABLE)
rate_total       FOLLOWABLE / total
```

The R5 spec directs `UNINFORMATIVE` out of the walkthrough denominator.
Independent review pointed out that this lets a **failing** target be removed by
a bare-arm success and the rate go **up** — breakage reading as improvement,
which `run_bench.write_summary` already refuses to allow. Both cannot be true, so
both are published and the non-inflatable one is named the gate figure. Once
`UNINFORMATIVE + NOT_MEASURABLE` exceeds 20% of `eligible`, `rate_informative`
is **withheld** as a gate result: its denominator has moved too far to be the
same measurement.

A gate verdict is stated **only** for an `agent` run over the full manifest, at
the `verbatim` variant, with no `NOT_MEASURABLE` target. Subset runs report
`gate: null` and why. Eligibility (`VOID`) is decided **before** any follower
runs, so the eligible set is never chosen after seeing results.

Accepted up front, as the spec requires: **a strong follower makes easy targets
uninformative and shrinks the denominator.** Every uninformative slug is named in
the summary. A denominator of 15 must not be assumed.

## The two followers measure different things

| follower | measures | deterministic | can produce a gate figure? |
| --- | --- | --- | --- |
| `template` | template **validity** | yes | **no** |
| `agent` | **followability** | no | yes |

`template` runs the walkthrough's own embedded pwntools template. This is the
*literal execution* the walkthrough-families plan requires as its test strategy —
it is what caught wave 1's real defects. It says nothing about the prose: a reader
who cannot read a word of it still passes by typing `python3`. It has **no bare
arm** (with no walkthrough there is nothing to execute), therefore no necessity
test, therefore it is structurally unable to emit `FOLLOWABLE`. Never quote it
against the 85% gate.

## The metric is named honestly: `artifact_followable`

With `--walkthrough-variant verbatim` (the default) the follower receives the
runnable template and may simply execute it. So the figure measures whether the
**artifact is usable**, not that its prose was read. Nothing in the output claims
otherwise.

`--walkthrough-variant prose` is the teaching-only arm: one auditable rule —
comment lines and `CONSTANT = ...` assignments survive, every executable
statement is stripped — so the follower must reconstruct the exploit from the
explanation. Constants are kept deliberately: they carry the measured facts and
their provenance, which *is* the teaching; stripping the offset too would test
rediscovery, not teaching. **Figures from the two variants are not comparable.**

## Two cheats an agent follower has that autopwn does not

`run_bench.py` faces a non-adaptive generator that is never handed the flag. An
interactive follower with a shell is a different adversary. Both channels are
closed structurally, not by pattern matching.

**1. Hardcoding / generation-time scraping** — the follower can read `flag.txt`
while it works and paste the string in.
Closed by **decoy-then-remint**: the follower works against a decoy secret of
identical length; its artifact is then **frozen** (copied out, hashed), the
sandbox **wiped** of everything but the artifact and the walkthrough, the target
**rebuilt with a fresh secret the follower has never seen**, and the frozen
artifact scored against that. A pasted decoy scores `NO_FLAG`.

**2. Runtime laundering** — re-minting does not stop an artifact that reads
`flag.txt` *at run time* and relays the bytes **through the target**, so the
target performs the flag-bearing write and attribution credits it.
Closed by the **behavioural open-audit**: the trace also records `openat`, and a
process **outside the target's lineage** opening `flag.txt` scores
`FOLLOWER_LAUNDERED`. `cat flag.txt` run by a shell the exploit obtained is the
intended solve path for the shell targets and is distinguished by exactly the
lineage rule attribution already applies to writes.

This is not hypothetical. `fixtures/broken_launders_flag_file.py` uses the *real*
ret2plt chain and then `echo`s a flag it read in Python, and write-attribution on
its own reports:

```
credited: the flag was written by the target's own process tree
          (dash <- dash <- ret2plt_system <- python3) and the target exec'd a shell
```

A clean false SUCCESS. The open-audit is the only thing that refuses it.

## Isolation: enforced vs detected

**Process-level, not OS-level.** Stated plainly because the whole metric rests on
it, and asserting blindness would be worthless.

Enforced:
- Sandbox **outside the repository**, so no `CLAUDE.md`, plan, prior-round note or
  corpus source is discoverable at or above the follower's cwd. `--sandbox-root`
  inside the repo is refused.
- The walkthrough is **sanitised** of repository paths and the run **fails closed**
  if any survive. This matters: a generated walkthrough hardcodes
  `BINARY = '<abs path into benchmark/corpus/NN_slug/>'`, and handing that over
  verbatim hands the follower a pointer to the target's own C source. That one
  line would have voided every walkthrough-arm result.
- `--disable-slash-commands`, `--strict-mcp-config` with an empty MCP config, no
  `--add-dir` (so the CLI confines `Read/Write/Edit/Glob/Grep` to cwd), and
  `WebFetch`/`WebSearch`/`Task` explicitly denied.
- Repo-bearing `PYTHONPATH` entries and all `SUPWNGO_*` variables stripped, so
  `import supwngo` fails — for the follower **and** for its scored artifact.
- Fresh per-sandbox `TMPDIR`.

Detected, **not** prevented:
- **`HOME` is shared**, because the follower CLI reads its credentials there, and
  a follower with a shell can read the filesystem. `blindness_audit()` scans the
  full transcript and the produced artifact for repository paths and corpus source
  filenames, and a hit forces `NOT_MEASURABLE` rather than a credit.

OS-level isolation (container, user namespace, network-denied image) is the
correct answer and is **not built here**. A figure produced under process-level
isolation must not be quoted as if it came from a container; `report.json` records
`isolation` on every run.

## Follower capability tier is part of the measurement

A stronger follower raises **both** arms and makes more targets `UNINFORMATIVE`,
so the tier is pinned and recorded: model, effort, tool allowlist and denylist,
budget, wall timeout, CLI version, plus sha256 of every prompt, walkthrough and
frozen artifact.

Default `sonnet` — a competent implementer, the population a teaching artifact is
written for — and deliberately not the frontier tier, which would solve the easy
targets bare and measure less. **Stated limitation:** `sonnet` is a *mutable
alias* and cannot be resolved to an immutable identifier from here, so two runs
months apart may not be comparable even at the same label.

## Reps

Paired: rep *i* runs both arms, each with its own freshly minted secret and its
own fresh sandbox. **Every scheduled trial runs — there is no early stopping on
success**, arm order is fixed (`walkthrough` then `bare`) and recorded, and there
are no retries. Reported per target: each arm's `k/N` plus the within-rep
contingency table (`walkthrough_only` / `bare_only` / `both` / `neither`).

The verdict is a **conservative screen, not a treatment-effect estimate**. At
`reps=3` no confidence bound is meaningful and none is printed.

## Proving it can fail

`--selftest`, three layers, because any one alone is passable by a broken scorer.

1. **Artifact layer** — one good and six broken artifacts against a real build.
   The **positive control runs first**: if it does not score `CREDITED` the run
   reports `NOT MEASURABLE` (exit 2) rather than reporting the negatives as
   passes. A scorer that credits nothing "fails everything" and looks maximally
   strict while measuring nothing — the `ablate.py` rule. Fixtures are copied to
   **randomised filenames**, so filename special-casing cannot pass.
2. **Arithmetic layer** — `target_verdict()` and `compute_rates()` driven as an
   explicit truth table: every verdict, invalid trials in either arm, the
   denominator-inflation case, the withholding rule, the gate blockers, the prose
   redaction.
3. **Differential layer** — `witness()` and `witness_argv()` must agree, since
   `witness()` was refactored to delegate and `run_bench.py`'s behaviour must be
   bit-identical.

Exit `0` all controls behaved; `1` a control gave the wrong verdict (scorer
defect); `2` could not measure (unbuilt corpus, no `strace`, positive control
failed).

| fixture | defect | required |
| --- | --- | --- |
| `good_reference.py` | none — the verified reference chain | `CREDITED` |
| `broken_wrong_offset.py` | right route, offset off by 8 | `NO_FLAG` |
| `broken_undeclared_constant.py` | `NameError` at the reader's first command | `NO_FLAG` |
| `broken_impossible_route.py` | ret2shellcode taught on an NX binary | `NO_FLAG` |
| `broken_launders_flag_file.py` | real exploit, laundered disclosure | `FOLLOWER_LAUNDERED` |
| `broken_stale_secret.py` | hardcoded flag | `NO_FLAG` |
| `broken_scrape_no_target.py` | `cat flag.txt`, target never run | not credited |

## Family-agnostic by construction

Nothing in `score.py` or `followers.py` names `stack_bof`, `rop_chain`,
`syscall`, `triage`, `fmtstr`, `integer` or `heap`. Walkthroughs are matched to
targets by slug or binary name, never by family, so the families being added
concurrently need no change here.

**Open policy question, not decided by this tool:** a detection-only heap
walkthrough cannot pass a flag-capture gate by construction (see
`docs/plans/2026-09-24-walkthrough-families-fmtstr-heap-integer.md`). The scorer
reports per-target verdicts so that call can be made on measured numbers; it does
not pre-emptively exclude any family, because excluding one is a
declared-before-measuring policy decision for the maintainer, not a default an
instrument should bake in.
