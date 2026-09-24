# Round 2 cold measurement — generalization check

**Date:** 24 Sep 2026
**Branch:** `bench/round2-cold-and-dev-20260924`
**Plan:** `docs/plans/2026-09-24-benchmark-round2-cold-then-develop.md` (rev 3,
three rounds of independent same-tier review recorded under
`docs/reports/reviews/`)

---

## PART 1 — PRE-REGISTRATION (committed BEFORE the cold run)

Everything in Part 1 was committed before `run_bench.py` was invoked against
`corpus_r2`. The commit that introduced this section contains no results, which is
what makes the denominator and the endpoints un-negotiable after the fact.

### 1.1 Declared denominator: 15 of 15

All 15 R2 targets are sound measurements. Evidence, all gathered before measuring:

| check | result |
|---|---|
| `cflags` ↔ `corpus_r2.yaml` mirror | 15/15 match |
| builds under the **shared** `build_all.sh` (the path `run_bench.py` uses, not R2's own convenience builder) | 15/15 |
| **R8 scrape channel** — `strings <bin> \| grep 'FLAG{'` | **0/15 scrapeable** |
| `flag.txt` present and carrying the secret | 15/15 |
| negative controls: `bare_run_verify_stdin`, `bare_run_filler` (512 × `'A'`), `bare_run_menu_walk` (fresh process per probe) | 15/15 clean, sweep OK |
| reference exploits (positive controls) against a rotated secret | 15/15 pass |
| **necessity ablations** with a same-driver positive control (§1.3) | **15/15 positive controls pass; 51/51 strict ablations BLOCKED; 0 defects; exit 0** |

Nothing joins R1's `11_heap_uaf_leak` / `13_off_by_one` as `VOID`. The
pre-declared adequacy threshold was **≥12 of 15 surviving**; 15 survive, so R2 can
support a cold estimate.

### 1.2 Declared endpoints (fixed; not revised after seeing data)

- **Primary: count of targets at 5/5 reliability** (credited in every rep).
- **Secondary, reported but explicitly exploratory: `solved`** = credited in ≥1 of
  5 reps. An upper bound. Quoting it as the headline rewards luck.
- Both in **both** attribution modes, per target, as `solved` + `reliability` k/N.
- **Never** combined across attribution modes or timeout configurations.
- Configuration: **`--reps 5 --jobs 8 --timeout 20`**, identical to R1's
  authoritative run.
- Exclusions require positive evidence (degenerate / unmeasurable / contaminated).
  A `FAILED` verdict is **never** grounds for exclusion.

### 1.3 Why R2's own ablation suite was not trusted

`benchmark/corpus_r2/README.md` claims "All 15 ablations pass (0/15 produced the
flag)". `benchmark/corpus_r2_reference/ablation.py` cannot support that claim: each
case runs **only the ablated chain** and asserts the flag is absent. There is no
intact-chain leg in the file, `EOFError` is caught into `out = ""`, and `main()`
returns 0 whenever `leaks == 0`. A driver whose `recvuntil(b"shellcode> ")` no
longer matches, a read timeout, or a dead process all yield `no-flag`. **Its clean
result is equally consistent with 15 broken drivers.**

Replaced with `benchmark/ablation/ablate_r2.py`, which ports R1's `ablate.py`
guarantee: one parametrised chain function per target whose **defaults are the
working exploit**, each ablation being the same function with one keyword flipped,
so the positive control and the ablation traverse the *identical* driver path,
delivery and parsing. Outcomes are genuinely three-way — `BLOCKED` (pass),
`NOT BLOCKED` (corpus defect, exit 1), `NOT MEASURABLE` (exit 2) — with the defect
check evaluated first so a defect cannot be masked by a co-occurring setup failure.

> **A validation that asserts absence fails safe in the wrong direction under
> load.** R2's suite asserts flag-*absence*, so a stalled driver reads as a pass and
> contention makes the corpus look *sounder* than it is. R1's asserts presence
> first, so the same stall reads as `NOT MEASURABLE`. Same host condition, opposite
> bias, determined entirely by which way the assertion points.
>
> This is the **fifth** instance of validation-that-cannot-fail found in this
> project, and **all five assert absence.** That is a predictive rule for where to
> look next, not a retrospective tally: audit absence-asserting checks first.

Four ablations were confirmed as **relaxation probes** — documented details that
turn out not to be load-bearing. They are recorded rather than hidden, because the
corpus's difficulty notes should stay honest:

| target | relaxation | what it means |
|---|---|---|
| `04_canary_relay_bypass` | 8 of `buf`'s 64 bytes before the relay still leaks the right canary | the prologue places the canary before any input is read (R1's target 04 showed the identical thing) |
| `11_heap_overflow_tcache_poison` | forged chunk's size field need not be `0x21` | `tcache_get()` never re-validates it — the corpus author's own reference docstring says so |
| `13_off_by_one_retaddr_lsb` | `win_addr+1`'s LSB still reaches `print_flag()` | `win()` begins `f3 0f 1e fa` (`endbr64`); entered one byte late, `0f 1e fa` decodes as a 3-byte NOP that re-syncs to the same prologue. Every other delta tried (−1, ±0x10, ±0x40, +0x80) crashes, so a separate `wrong_lsb` case covers the real ablation |
| `14_oob_read_flag_array` | read range shifted by one index still recovers the flag | the 38-byte flag fits whole inside the misaligned 60-byte window |

### 1.4 The R1 ↔ R2 comparison is NOT like-for-like — on three axes, all compounding

The cold figure will be read against R1's 13/13. **"R1 13/13 versus R2 x/15" is not
a like-for-like comparison on any of three axes**, and all three push R2's figure
*down* relative to R1's. They compound; none offsets another.

| | R1 | R2 |
|---|---|---|
| was the pipeline developed against it | **yes** | no (held out until after R1 closed) |
| flag delivery | compiled in via `-DFLAG` for win()-style targets | **read from `flag.txt` at runtime by every target** |
| `strings \| grep 'FLAG{'` recovers the flag | **9 of 15** | **0 of 15** |
| targets scoring only behind the bypassable script audit | 9 | 0 |
| excluded as `VOID` | **2** (`11_heap_uaf_leak`, `13_off_by_one`) | **0** |
| scoring denominator | **13**, after discarding its 2 weakest members | **15**, nothing discarded |

1. **Overfitting.** R1 is the corpus the pipeline was developed against. This is the
   effect the cold measurement is *designed* to expose, and the only one of the
   three that is about the pipeline.
2. **Scrape surface.** R1 leaks to `strings` on 9 of 15, R2 on 0 of 15, so **part of
   R1's 13/13 was reachable without exploitation**. The confound therefore
   **inflates R1 and deflates R2** relative to true capability.
3. **Denominator composition.** R1 scored **13 sound targets after discarding 2
   unsound ones**; R2 scores **15 sound targets with nothing discarded**. R1 got to
   drop its two weakest members — the two that could be solved without their
   intended vulnerability. **R2 has no weak members to drop.**

**The honest summary: R2 is strictly harder to score on than R1 was, by
construction.** The design improvements responsible — runtime flag reads, and a
corpus whose every member passes its own necessity ablation — are a **feature of R2,
not a deficiency of the pipeline.** A reader who sees only the two fractions will
draw a conclusion the measurement does not support.

#### Instruments, in order of defensibility

A straight percentage comparison is the wrong instrument. Two better ones:

- **Primary: R1-strict vs R2-strict.** `--strict-attribution` is what withholds
  scrape-reachable credit, so this neutralises axis 2. The gap between the
  default-mode pairing and the strict-mode pairing **estimates the size of the
  scrape confound**.
- **Secondary, technique-class-matched: R1-strict on its shell-obtaining six vs
  R2-strict on its shell-obtaining four.** R1: `01`, `02`, `03`, `07`, `08`, `09`.
  R2: `01`, `02`, `03`, `07`. Both sides scrape-clean, both sides sound, both sides
  the same exploitation style. **n = 6 vs n = 4** — very small, so it is a
  tie-breaker, never a headline.

  **Why not the obvious "R1-scrape-clean vs R2-all":** because on R1,
  *scrape-clean* and *shell-obtaining* are **not two properties that happen to
  coincide — they are the same property observed twice.** A target is scrape-clean
  exactly when it obtains a shell and reads `flag.txt` at runtime instead of having
  the flag compiled in. So subsetting on scrape-cleanliness subsets on exploitation
  style **by construction**: R1's scrape-clean six *are* its shell-obtaining
  targets, and the seven excluded (`04`, `05`, `06`, `10`, `12`, `14`, `15`) are
  exactly its arbitrary-read/arbitrary-write primitive targets, which credit via an
  in-target write with a bare process tree and no descendant shell.

  `R1-scrape-clean vs R2-all` would therefore compare a **shell-obtaining-only**
  population against a **mixed** one, and any gap would be partly a difference in
  exploitation style rather than capability — **in an unknown direction**:
  `ret2dlresolve` and SROP are harder in technique terms, while a canary leak or a
  format-string write is a shorter chain with fewer places to fail. That is a
  *systematic selection bias*, not merely reduced statistical power, and it yields
  an instrument that cannot be interpreted. Matching on technique class is what
  fixes it.

> **Lesson, and it applies to R3/R4/R5 as well: on these corpora, flag-delivery
> mechanism is entangled with technique class.** Compiled-in flags go with
> win()-style/primitive targets; runtime `flag.txt` reads go with shell-obtaining
> ones. So **any subsetting by scrape-cleanliness silently subsets by exploitation
> style.** Obvious once stated, invisible otherwise.
>
> **Recommendation for future corpus generators:** vary flag delivery *within*
> technique class — some shell-obtaining targets with a compiled-in flag, some
> primitive targets reading `flag.txt` — so the two factors can be separated
> instead of being confounded by design. R2 improved flag delivery uniformly
> (0/15 scrapeable), which is strictly better for soundness but, precisely because
> it is uniform, removes the within-corpus contrast that would let the two be
> disentangled.

#### Soundness and analysability pulled in opposite directions — and R2's limit is permanent

This is the round's most transferable finding, so it is stated as a tension rather
than as anyone's error:

**R2's uniform 0/15 flag-delivery fix is strictly better for soundness, and
*because* it is uniform it destroys the within-corpus contrast that would let anyone
separate delivery mechanism from technique style.** R2 optimised the first axis
without knowing it cost the second. That is a genuine tension between two desirable
properties, and it was invisible until two corpora existed to compare — not a
mistake to attribute.

**The consequence is a fixed limit, not an open question.** If later rounds carry
varied delivery and R2 is uniform, then **R2 will remain permanently unable to
separate those two axes, no matter what is measured on it later.** No amount of
step-3 development, re-running, or re-analysis can repair it: the contrast was never
built into the corpus, so it cannot be recovered from the corpus. Any future claim
of the form "supwngo does better on shell-obtaining targets than on primitive ones"
**cannot be tested on R2 alone** — on R2 that comparison is identical to comparing
its four runtime-`flag.txt` targets against its eleven runtime-`flag.txt` targets,
which is to say it is not a contrast at all.

The R5 specification is being amended to require varied delivery within technique
class so that R5 is both sound *and* analysable, with the confound separable inside
a single corpus rather than only across corpora. Recording the rationale here as
well as in that spec, because a bare requirement without the reasoning reads as
arbitrary to whoever implements it and would likely be optimised back out — uniform
delivery looks cleaner to anyone who has not seen this analysis.

None of this is offered as a reason to discount the cold number. It is a limit on
what the R1→R2 **delta** can be attributed to.

#### Disclosure: when each instrument was fixed

Pre-registration is worthless if its timing is not itself honest, so:

- The **primary** instrument (R1-strict vs R2-strict) and the confound analysis on
  axes 1–3 were committed **before the cold run started** (`b19db10`, `75454fc`).
- The **secondary** technique-class-matched instrument was revised **while the run
  was in flight**, after `07_static_ret2syscall` had already reported
  `SUCCESS 5/5` — and `07` is one of the four R2 members of that very subset. That
  is disclosed rather than glossed.

Why this is a weak contamination and not a fatal one: the subset's membership is
**mechanically determined by a documented corpus property** — "does this target
obtain a shell and read `flag.txt`", stated in `benchmark/corpus_r2/README.md` and
in R1's `benchmark/README.md` — not chosen by inspecting scores. The revision
*narrowed* the instrument (R2-all → R2 shell-obtaining four) to remove a selection
bias, which cannot flatter the result: it dropped 11 targets including every one
whose verdict was still unknown to me. Had I widened it, or picked members after
seeing which passed, the objection would be fatal.

Nonetheless, because one in-subset data point was visible when it was fixed, this
instrument is **demoted to a tie-breaker and is never quoted as a headline.** The
primary pairing carries the comparison.

**Provenance attestation from the party who originated the criterion** (recorded
because the causal history is held by them, not by the author of this report, and
it is stronger evidence than the timing alone):

> - The technique-class-matching criterion came from the coordinator's message, not
>   from the report author inspecting scores.
> - It was derived entirely from **R1's** structure — that scrape-cleanliness and
>   shell-obtaining are the same property on R1 — with **no R2 target verdicts seen
>   at the time**, not even `07`'s; the report carrying `07` and the message
>   specifying the criterion crossed.
> - The criterion is mechanical ("has no `print_flag`/`flag.txt` path"), so knowing
>   `07` passed cannot change which targets satisfy it.

The causal chain therefore does not run through R2 outcomes at any point. Bias would
require the **criterion** to have been chosen to capture known passers; it was
chosen to fix a selection-bias problem in R1's half of the comparison. This converts
the disclosure from *"weak contamination, argued"* into *"weak contamination, with
provenance documented by the party who caused it."* The demotion to tie-breaker
stands regardless: n = 6 vs n = 4 could not carry a headline however clean its
provenance.

### 1.5 Pre-registered discovery-stall triage

A known live bug (`_probe_echo_sizes`, a single 2.0 s probe with no retry, and
`deliver_parts` collapsing a timeout into `output = b""` with **no `timed_out`
field**) makes a scheduling stall indistinguishable from "this technique does not
apply". It was **deliberately not fixed before this run.**

Detection is mechanical: a rep is a *stub rep* iff its generated script contains
both `Generated by supwngo's canonical autopwn pipeline (no technique verified)`
and `offset = 0  # TODO` — both already in `report.json`, so no re-execution.

| pattern across the 5 reps | classification | effect on the cold figure |
|---|---|---|
| 0 stub reps, 0 credited | capability gap | genuine cold failure |
| 5 stub reps | discovery failure, cause undetermined | cold failure, flagged |
| 1–4 stub reps, ≥1 credited | discovery-stall suspect | `solved` yes; stub reps flagged in the k/N split |
| 1–4 stub reps, 0 credited | stall suspect, unresolved | cold failure, flagged |

A flagged target is re-probed **diagnostically only; the re-probe can never upgrade
a cold verdict.** Both the as-measured figure and a clearly-separated
"stall-failures-excluded" sensitivity figure are published: the first alone
understates the pipeline, the second alone launders a real failure.

### 1.6 Measurement conditions

R1 ablation control, run first as a host-health check under the same conditions:
**49/49 strict ablations blocked, 13/13 positive controls, 0 failures, exit 0** —
reproducing the documented result exactly, including its 3 known relaxation probes.
A false-fail there would have meant the host, not the corpus, was the variable.

**Counting concurrent harnesses is itself a trap, and the first count reported was
wrong.** `pgrep -f run_bench.py` matches any process whose command line contains
the string, including the querying process and any `until ! pgrep -f …` waiter —
which therefore can never exit (three agents in this project have lost waiters this
way; four stale ones were found parked on this host, the oldest ~12 h).
`ps aux | grep "[r]un_bench.py"` fixes only *self*-matching and still counts
unrelated **shells**: it reported **6 "live harnesses" when the true number of
running Python processes was 0**, the rest being 0 %-CPU `zsh` shells (4 stale
waiters in another agent's worktree, plus query shells). Resolved by requiring
`/proc/<pid>/comm` to be a Python interpreter and checking `%CPU` and
`/proc/<pid>/cwd`. `benchmark/sample_load.sh` was corrected to count this way
before the run, because "6 live" and "0 live" support different claims about the
conditions and a later reader cannot tell which was meant.

| | value |
|---|---|
| host | 32 cores, 62 GiB |
| toolchain | gcc 11.4.0, glibc 2.35, Python 3.11.15, pwntools 4.15.0 |
| loadavg at GO | `2.20 2.82 2.81` (~7 %) |
| real harness processes at GO (resolved) | **0** |
| loadavg at start of cold run | *(Part 2)* |
| loadavg at end of cold run | *(Part 2)* |
| continuous load profile | `benchmark/sample_load.sh`, 15 s interval, for the whole run |

**A stale `.run_bench.lock` is expected and means nothing — test acquisition, never
file presence.** `benchmark/corpus_r2/.run_bench.lock` was present at the pre-run
gate. `corpus_lock()` uses `flock`, *deliberately* and with the reasoning in its own
docstring: the kernel releases a `flock` when the holder dies for any reason
including `SIGKILL`, whereas an `O_EXCL` lock file survives a kill and wedges every
later run until a human deletes it. So the inode persists after every run and
carries **no** information about whether the lock is held. It was verified free by
*attempting* `LOCK_EX | LOCK_NB` and releasing. Both wrong inferences are costly and
in opposite directions: treating presence as held waits forever on nothing; treating
absence-of-check as free while it *is* held corrupts a concurrent run's binaries and
`flag.txt` mid-flight, which surfaces as spurious `FAILED`s rather than an obvious
crash. The next person to see this file will have the same question.

---

## PART 2 — THE COLD RESULT

*Pending. This section is written only after the run completes, and the figures in
it are whatever the run produced.*
