# Walkthrough scorer — blind-follower measurement

Measures whether supwngo's generated 0-to-pwn walkthroughs are **followable**.
Before this existed, `benchmark/` contained zero references to walkthroughs, so
the R5 spec's `>= 85% followable` gate was a threshold against a metric that did
not exist. Inventing a lenient one later to clear that gate is the exact failure
this benchmark was built to prevent.

Design: `docs/plans/2026-09-24-walkthrough-blind-follower-scorer.md`
Plan review: `docs/plans/reviews/2026-09-24-walkthrough-blind-follower-scorer-review-codex.md`
Implementation review: `docs/plans/reviews/2026-09-24-walkthrough-scorer-implementation-review-codex.md`
First measurement: `docs/reports/2026-09-24-walkthrough-scorer-first-measurement.md`
Spec: `docs/plans/2026-09-24-final-round-r5-unseen-corpus.md`, Problem 1 / 1a

```
benchmark/walkthrough/
├── score.py       the scorer: both arms, the controls, the report
├── followers.py   who plays the follower; blindness; the prose redaction
├── selftest.py    the falsifiability controls (four layers)
└── fixtures/      one good + seven deliberately broken artifacts
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
Closed by **decoy-then-remint**, in this order:

1. the follower works against a **decoy** secret of identical length;
2. its artifact and transcript are **frozen** — copied out of the sandbox and
   hashed, so nothing scored afterwards can still be edited;
3. the corpus target is **rebuilt with a freshly minted secret the follower has
   never seen**;
4. the sandbox is **wiped** of everything but the frozen artifact and the
   walkthrough, and the re-minted binary and flag file are re-staged;
5. the frozen artifact is scored against the new secret.

A pasted decoy scores `NO_FLAG`. Each rep also wipes both sandboxes *before* the
follower session, so rep N cannot build on rep N-1's leftovers.

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

### Known residual holes, and why they are open

An independent review of this implementation
(`docs/plans/reviews/2026-09-24-walkthrough-scorer-implementation-review-codex.md`)
found twelve blocking defects. Nine are fixed in code. The rest are listed here
rather than closed, because closing them needs a privilege boundary this harness
does not have — and an undocumented hole is worse than a documented one.

| # | Hole | Why it is still open | What would close it |
| --- | --- | --- | --- |
| 1 | The artifact runs as the **same UID** as the scorer, in a **writable** sandbox: it can overwrite the staged binary, run the substituted image at the target's pathname, and be credited by a lineage rule that trusts the pathname. | Detected, not prevented: `_attest()` pins `st_ino`, `st_ctime_ns`, size and sha256 of the artifact, the target and `flag.txt` across the scoring window, so overwrite-run-restore is caught even though the bytes come back identical (`ctime` cannot be forged without root). `fixtures/broken_overwrites_target.py` demonstrates the attack and asserts the detection. But detection is not prevention. | A separate UID owning a read-only target, plus inode attestation of what was actually `execve`'d. |
| 4, 6, 7 | The flag file is protected **by name**. `link("flag.txt","x")`, a `rename`, an alias created before the re-mint, or `openat2` all evade the open-audit; conversely a successful open of an unrelated `notflag.txt` could falsely accuse an honest artifact. Unfinished/resumed `openat` lines are not reassembled. | Every fix here is another pattern on the same losing side of an arms race. `Stage` now `lstat`s and refuses to follow aliases when wiping and re-staging, which closes the *re-stage-into-an-alias* variant; the read-side evasions remain. | Enforce access at the kernel boundary (mount namespace, or the flag not present on the follower's filesystem at all) instead of matching syscall names. |
| 5 | The artifact is executed **twice** — once plain, once under `strace` — in the same writable directory, so the first run could alter the second. | Mirrors `run_bench.py`'s own verify-then-witness structure, so collapsing it would change the autopwn number for an unrelated reason. Closed in effect by the attestation in row 1: a rewrite between the two runs changes `ctime` and voids the trial. | One traced execution as the single verdict source, with an immutable artifact. |
| 3 (part) | Follower descendants that **double-fork and `setsid()`** escape the process group. | `reap_process_group()` tears down the session's whole process group after every follower run and before the scored secret is minted, so the ordinary case is closed; a deliberate escape is not. | A cgroup or PID namespace per session. |
| 9 | Both arms run in **separate directory trees** (`arm-walkthrough/`, `arm-bare/`) under one sandbox root. The bare follower's `Bash` tool can still walk up and read the other arm. | Same-filesystem confinement cannot be proven from inside the process. `blindness_audit()` scans the transcript and artifact for walkthrough and repository markers and forces `NOT_MEASURABLE` on a hit. | Mutually inaccessible mount namespaces per arm. |
| 12 | `Read`/`Glob`/`Grep` confinement to cwd is **asserted by the CLI**, not provable from here, and `HOME` is shared. | The follower CLI needs its credentials in `HOME`. `--output-format stream-json --verbose` is now requested so tool invocations appear in the transcript the audit reads, which is strictly better than scanning prose — but a transcript can never *establish* blindness. | Container with an isolated `HOME`. |

Every one of these makes the walkthrough arm look **better**, not worse, so the
published figure should be read as an upper bound on `artifact_followable` under
process-level isolation.

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

`--selftest`, four layers, because any one alone is passable by a broken scorer.

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
4. **End-to-end layer** — the first three layers score artifacts and arithmetic
   *directly*, which leaves the machinery that actually protects the measurement
   untested: decoy-then-remint, the per-rep wipe, the pairing and the asymmetric
   validity rule all live in `run_target`. So `run_target` itself is driven with a
   follower **scripted inside `selftest.py`**, installed by replacing
   `score.build_follower` for the duration. There is deliberately **no test hook
   in the product** — "the scorer ran with a stub follower" must not be a
   reachable state of a real measurement.

Exit `0` all controls behaved; `1` a control gave the wrong verdict (scorer
defect); `2` could not measure (unbuilt corpus, no `strace`, or either positive
control failed).

| fixture | defect | required |
| --- | --- | --- |
| `good_reference.py` | none — the verified reference chain | `CREDITED` |
| `broken_wrong_offset.py` | right route, offset off by 8 | `NO_FLAG` |
| `broken_undeclared_constant.py` | `NameError` at the reader's first command | `NO_FLAG` |
| `broken_impossible_route.py` | ret2shellcode taught on an NX binary | `NO_FLAG` |
| `broken_launders_flag_file.py` | real exploit, laundered disclosure | `FOLLOWER_LAUNDERED` |
| `broken_stale_secret.py` | hardcoded flag | `NO_FLAG` |
| `broken_scrape_no_target.py` | `cat flag.txt`, target never run | not credited |
| `broken_overwrites_target.py` | replaces the staged binary with `cat flag.txt`, runs it, restores the bytes | `SCORING_WINDOW_TAMPERED` |

End-to-end cases, each through the real remint cycle:

| case | plan | required |
| --- | --- | --- |
| positive control (runs first) | walkthrough arm solves, bare arm broken | `FOLLOWABLE` |
| necessity | both arms solve | `UNINFORMATIVE` |
| remint | follower hardcodes the flag it was shown | `NOT_FOLLOWABLE`, and the scored secret must differ from the one the follower read |
| validity | the bare trial measured nothing | `NOT_MEASURABLE` |

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
