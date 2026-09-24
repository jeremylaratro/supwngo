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
| loadavg at start of cold run | `2.89 2.60 2.66` → filled in from §2.6 |
| loadavg at end of cold run | `4.35` falling → filled in from §2.6 |
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

### 2.1 The figure

> ## **4 / 15**
>
> **26.7 %.** Denominator **15**. **VOID list: empty** — no target was excluded, for
> any reason, before or after measurement.
>
> **Primary endpoint (5/5 reliability): 4/15.**
> **Secondary endpoint (`solved`, ≥1/5, exploratory): 4/15.**
> **Strict attribution mode: 4/15** — identical to default, provably so (§2.3).
>
> 0 PARTIAL · 11 FAILED · 0 INTERMITTENT · 0 VOID.

R1 closed at 13/13. R2 cold is 4/15. **This is not a like-for-like comparison and
must not be quoted as "13/13 → 4/15" without the three axes in §1.4 attached** —
R1's 13 is a post-hoc denominator that had already discarded 2 unsound targets,
R2's 15 is a pre-declared denominator with nothing discarded, and R1 is the corpus
the pipeline was developed against while R2 was never seen by it. All three
mechanisms push in the same direction.

What the number is: **the pipeline's cold, single-use generalization score on a
held-out 15-target corpus, at a 20 s per-technique budget.** It is now spent. No
later run on R2 can reproduce it, because from the next commit onward the pipeline
has seen this corpus.

The primary and secondary endpoints coinciding is itself informative: **there were
no intermittent successes at all.** Every target was either credited in all 5 reps
or in none. Best-of-N and per-attempt reliability agree exactly, so on this corpus
the `solved`/`reliability` gap — the usual place gaming hides — is zero, and the
figure needs no hedging in that direction.

### 2.2 Per target

Produced by `benchmark/summarize_cold.py` from the run's `report.json`:

| target | diff | status | solved | k/N | witness | stub reps |
|---|---|---|---|---|---|---|
| `01_stack_shellcode_relay` | easy | FAILED | no | 0/5 | — | **5/5** |
| `02_ret2plt_strcat_system` | easy | FAILED | no | 0/5 | — | 0/5 |
| `03_pie_write_leak_ret2libc` | medium | FAILED | no | 0/5 | — | **5/5** |
| `04_canary_relay_bypass` | medium | FAILED | no | 0/5 | — | **5/5** |
| `05_fmtstr_pie_leak` | medium | FAILED | no | 0/5 | — | **5/5** |
| `06_fmtstr_short_write` | medium | FAILED | no | 0/5 | — | **5/5** |
| `07_static_ret2syscall` | medium | **SUCCESS** | yes | **5/5** | ATTRIBUTED | 0/5 |
| `08_int_mul_overflow` | hard | FAILED | no | 0/5 | — | **5/5** |
| `09_heap_dangling_global` | hard | FAILED | no | 0/5 | — | **5/5** |
| `10_ret2csu_execve` | hard | **SUCCESS** | yes | **5/5** | ATTRIBUTED | 0/5 |
| `11_heap_overflow_tcache_poison` | medium | FAILED | no | 0/5 | — | 0/5 |
| `12_fmtstr_got_overwrite` | hard | FAILED | no | 0/5 | — | **5/5** |
| `13_off_by_one_retaddr_lsb` | easy | **SUCCESS** | yes | **5/5** | ATTRIBUTED | 0/5 |
| `14_oob_read_flag_array` | easy | FAILED | no | 0/5 | — | **5/5** |
| `15_ret2win_arg_gate` | easy | **SUCCESS** | yes | **5/5** | ATTRIBUTED | 0/5 |

By declared difficulty: **easy 2/5, medium 1/6, hard 1/4.** Difficulty does not
order the results — a `hard` ret2csu chain succeeded 5/5 while an `easy`
shellcode-on-a-non-NX-stack target produced a stub in all 5 reps. The corpus's
difficulty labels and this pipeline's actual difficulty gradient are close to
uncorrelated, which is worth knowing before those labels are used to weight
anything.

**Protections do not separate the successes from the failures.** All 4 successes are
no-PIE/no-canary, but so are 7 of the 11 failures (`02`, `06`, `08`, `09`, `11`,
`12`, `14`). The separator is technique class, not protection posture:

| technique class | cold score |
|---|---|
| return-address control → statically known target/chain (`07`, `10`, `13`, `15`) | **4/4** |
| format string (`05`, `06`, `12`) | 0/3 |
| heap (`09`, `11`) | 0/2 |
| ret2plt/`strcat` composition (`02`) | 0/1 |
| PIE defeat via write-then-leak (`03`) | 0/1 |
| canary leak + relay (`04`) | 0/1 |
| shellcode injection, NX off (`01`) | 0/1 |
| integer multiplication overflow (`08`) | 0/1 |
| OOB read of a flag array (`14`) | 0/1 |

**Read as a capability statement: the pipeline reliably solves "get control of the
return address, then jump somewhere whose address is already known," and solves
nothing else on this corpus.** Every one of the four wins is that problem —
`ret2win` with an argument gate, a static `ret2syscall` chain, a `ret2csu` chain,
and a one-byte return-address LSB overwrite. Every failure requires at least one
additional primitive first: a format-string write, heap metadata control, a leak to
defeat PIE, a canary disclosure, an integer-overflow size confusion, or an
out-of-bounds index. That is a sharper and more useful finding than the scalar 4/15,
and it is what §3 development should be aimed at.

### 2.3 Strict attribution equals default attribution — 4/15, derived not re-run

**All 20 credited reps (4 targets × 5) are BEHAVIOURALLY ATTRIBUTED. Zero
UNWITNESSED.** The harness's own evidence block:

```
EVIDENCE FOR THE 4 SUCCESS(es) -- 4 behaviourally witnessed, 0 unwitnessed:
  WITNESSED 07_static_ret2syscall:     flag written by cat <- dash <- python3.11 (target exec'd a shell)
  WITNESSED 10_ret2csu_execve:         flag written by cat <- dash <- dash <- ret2csu_execve <- python3.11 (target exec'd a shell)
  WITNESSED 13_off_by_one_retaddr_lsb: flag written by off_by_one_retaddr_lsb <- python3.11
  WITNESSED 15_ret2win_arg_gate:       flag written by cat <- dash <- dash <- ret2win_arg_gate <- python3.11 (target exec'd a shell)
```

`--strict-attribution` has exactly **one** scoring effect in `run_bench.py` — a
single branch that converts a SUCCESS resting only on a flag string plus the
bypassable pattern audit into `VOID`/`unwitnessed_success`. Verified by enumerating
every use of the flag in the file: of 13 occurrences, 12 are parameter threading and
the report field, and one (`run_bench.py:810`) is the branch. **With zero UNWITNESSED
reps that branch is unreachable, so strict mode is identical to default mode by
construction, not by coincidence.**

This is therefore **derived from the cold run's own transcripts, not measured by a
second execution** — deliberately, and as pre-registered. Re-running under `--strict`
would have confounded the comparison on the known delivery flake (an unsynchronized
send measured 4/96 failures under contention, 0/96 synchronized), so two runs
differing by ~1/96 per rep could not be attributed to the mode rather than to noise.
A derivation from one transcript set has no such problem.

Note the asymmetry with R1: R1 strict degraded `04_canary_leak_bypass` from 5/5 to
4/5, because R1 contained scrapeable targets where the weak-attribution path was
load-bearing. **R2 has 0/15 scrapeable targets (§1.1), so on R2 there is no
weak-attribution credit to withdraw.** R2's 4 is weaker as a score and stronger as
evidence: three of the four are witnessed all the way to a shell the exploit
obtained, and the fourth (`13`) is witnessed as a write by the target process
itself.

### 2.4 Outer truncation is ruled out; inner truncation is not

Every one of the 15 targets reports `wall_timed_out = False` and `returncode = 0`
on **both** autopwn passes — the `--json` probe and the script-generation pass. The
outer wall budget was `max(120, 20×15 + 60) = 360 s` per invocation and nothing came
near it. **No FAILED verdict in this run is an artefact of the harness killing
autopwn.** Total pipeline work was 7 709 s of target time across 75 target-reps
(≈21 min wall at `--jobs 8`).

This is the check R1's uniform 5/5 made unnecessary and an unfamiliar corpus makes
mandatory, and it came back clean. **It does not rule out inner, per-technique
truncation at the 20 s budget** — a technique needing 25 s of gadget search reports
"did not apply" indistinguishably from one that genuinely did not apply. That
remains open and is residual limit 1 in §2.8. Accordingly the figure is
**capability at a 20 s per-technique budget**, never unbounded capability.

### 2.5 Discovery-stall triage, per the §1.5 pre-registered table

**9 of the 11 failures produced a stub script in all 5 reps** — `01`, `03`, `04`,
`05`, `06`, `08`, `09`, `12`, `14`. Per the pre-registered table (`5 stub reps` →
*discovery failure, cause undetermined* → *cold failure, flagged*) all 9 count as
cold failures and are flagged. In these the pipeline never selected a technique at
all: it emitted the `no technique verified` / `offset = 0  # TODO` template.

**The uniformity matters and cuts in a specific direction.** The known bug is a
single 2.0 s `_probe_echo_sizes` probe with no retry, plus `deliver_parts` collapsing
a timeout into `output = b""` with no `timed_out` field. A *flake* of that shape
would produce a mixed k/N split; at `--reps 5` a ~10 %/rep flake shows up in
reliability even when it barely touches `solved`. **Nothing here is mixed: 9 targets
are 5/5 stubs and 0 targets are 1–4/5.** So the flaky reading of that bug is largely
excluded for these 9.

**It does not exonerate the bug, and I will not claim it does.** A single un-retried
2.0 s probe can fail *deterministically* on a target whose echo behaviour never
answers inside 2.0 s — that failure mode is 5/5 by nature, not 1–4/5. So for these 9
the honest verdict is exactly what was pre-registered: **cause undetermined.** The
bug remains a live candidate as a deterministic failure while being largely ruled out
as a flake. Which of the 9 it actually accounts for is a §3 question, answered by
fixing it and re-measuring — and any target it recovers is then *training*
performance on R2, never a revision of this cold figure.

**2 of the 11 failures are not stubs at all** — `02_ret2plt_strcat_system` and
`11_heap_overflow_tcache_poison`. Both generated a real technique, ran it
(`verification.ran = true`, `timed_out = false`), and did not produce the flag; both
pass the script audit clean (no flag literal, no direct `flag.txt` read, no local
flag reader, no binary scraping). These are **genuine capability gaps with a
technique actually attempted**, the cleanest two data points in the failure set, and
the best starting place for §3 precisely because the pipeline's reasoning is visible
rather than absent.

**Pre-registered sensitivity figure, published as required and to be read with
care.** Excluding all 9 flagged stall-suspect targets gives **4/6 (66.7 %)**. This is
an *upper bound on an upper bound* and is almost certainly a large overstatement: it
credits the pipeline for 9 targets on the mere possibility that a known bug rather
than absent capability explains them, when the 5/5 uniformity is evidence against the
flaky version of that hypothesis. It is recorded because §1.5 committed to recording
it, not because it is a defensible figure. **The cold result is 4/15.** The 4/6 is not
an alternative headline and must not be quoted as one.

### 2.6 Measurement conditions, as run

| | value |
|---|---|
| host | 32 cores, 62 GiB |
| toolchain | gcc 11.4.0, glibc 2.35, Python 3.11.15, pwntools 4.15.0 |
| loadavg at GO (coordinator's quiescence signal) | `2.20 2.82 2.81` |
| loadavg at first sample, pre-launch | `2.89 2.60 2.66` |
| **loadavg during the run** (85 samples, 15 s interval) | **min 2.80 · mean 5.54 · max 8.93** (max ≈ 28 % of 32 cores) |
| loadavg after the run | `4.35 …` falling; `5.25 4.57 4.41` at report time |
| concurrent harness processes during the run | **exactly 1 in all 85 in-run samples — never 2** |
| wall clock | 16:36:11Z → ≈16:57:33Z (≈21 min) |
| load profile artefact | `/tmp/r2-cold-loadprofile.tsv`, 115 samples |

The load profile has an auditable shape rather than a flat assertion: sample 1
(pre-launch) reads 0 harnesses, samples 2–86 read exactly 1 for the entire run
window, and samples 87+ read 0 after the run ended. **The counter's transitions line
up with the run's actual start and end**, which is positive evidence that it tracks
reality instead of being stuck on a constant.

**The honest limit on that counter — and it is the same failure shape this project
keeps finding.** It counts only processes whose `/proc/<pid>/comm` is a Python
interpreter. That was the fix for the earlier over-count (the `ps | grep
"[r]un_bench.py"` form reported 6 live harnesses when the true number was 0, the rest
being 0 %-CPU `zsh` shells and 4 stale `pgrep -f` waiters in another agent's
worktree, the oldest ~12 h). But the fix biases the count *downward*: a harness
launched through a wrapper whose `comm` is not `python*` would be missed. So
"never 2" is an **absence assertion by an undercounting detector** — the sixth
instance in this project of a validation that fails safe in the wrong direction, and
consistent with the search rule recorded in §1.4. What actually bounds the risk is
structural rather than observational: `corpus_lock()` serialises any second harness on
the same corpus root, and other agents were passing their own `--corpus-root`. The
load profile's own ceiling of 8.93 on 32 cores is independent corroboration that no
second 8-way run overlapped this one. Recorded as a limit, not closed.

Max in-run load of 8.93 on 32 cores is well inside the regime where the documented
delivery flake was measured at 0/96 (it needed 24-way contention to reach 4/96), so
**contention is not a plausible explanation for any failure here** — and in any case
the direction is wrong for the flake: contention produces *intermittent* failures,
and this run produced **zero** intermittent results.

### 2.7 Provenance

| | |
|---|---|
| pipeline commit measured | `980eabf463b8a5b8dda62e21d35eef36cb5aa853` |
| branch | `bench/round2-cold-and-dev-20260924` (from `b3a40b4`) |
| corpus merged from | `feat/benchmark-corpus-r2-20260923` @ `09bf135`, merged as `f00461f` |
| instrument | `benchmark/run_bench.py` + `benchmark/attribution.py`, **byte-identical to R1's** |
| command | `python3 benchmark/run_bench.py --corpus-root <worktree>/benchmark/corpus_r2 --manifest <worktree>/benchmark/corpus_r2.yaml --reps 5 --jobs 8 --timeout 20` |
| autopwn command line per target-rep | `python3 -m supwngo.cli autopwn <binary> --timeout 20 [--json]`, `cwd` = repo root |
| results directory | `benchmark/results_r2/20260924-163611Z/` (gitignored; carries live secrets) |
| `report.json` sha256 | `66a399f744042c797374031ec8b4de478bc59b94e9e43f279e028f9999912795` |
| committed evidence | `docs/reports/evidence/BENCHMARK-R2-COLD-24SEP2026-report.redacted.json` — 75 secrets (15 targets × 5 reps) replaced; refuses to write if any `FLAG{<32 hex>}` survives |

Per-target binary hashes are deliberately **not** published: each binary is rebuilt
per rep with a fresh secret compiled in via `-DFLAG`, so its hash is a per-run
nonce and reproduces nothing. The stable, checkable inputs are the committed sources
and `cflags`:

| target | source sha256 | `cflags` sha256 |
|---|---|---|
| `01_stack_shellcode_relay` | `e8372923adb6bae7…` | `92bc0f5994930d41…` |
| `02_ret2plt_strcat_system` | `9d3a89add54aa31c…` | `d12aa477baa7a415…` |
| `03_pie_write_leak_ret2libc` | `52f40086298aafe7…` | `fe5c8abd8b432e53…` |
| `04_canary_relay_bypass` | `4822b1021c6d53eb…` | `b026fb68a7707458…` |
| `05_fmtstr_pie_leak` | `475555463cf190ab…` | `fe5c8abd8b432e53…` |
| `06_fmtstr_short_write` | `f45f7bdc4ab169f7…` | `ad25c34e9dce8101…` |
| `07_static_ret2syscall` | `94b90fc3ddb7e4d3…` | `0847fe4ca0144906…` |
| `08_int_mul_overflow` | `428b8f08fa08ffde…` | `d12aa477baa7a415…` |
| `09_heap_dangling_global` | `569029f662a0ae51…` | `d12aa477baa7a415…` |
| `10_ret2csu_execve` | `1a32eb61ac7279a6…` | `d12aa477baa7a415…` |
| `11_heap_overflow_tcache_poison` | `cfc701c969a9ea60…` | `d12aa477baa7a415…` |
| `12_fmtstr_got_overwrite` | `37b694fbf2d7dd91…` | `87a54e88fb28eec1…` |
| `13_off_by_one_retaddr_lsb` | `9533ec9ec3ca2735…` | `d12aa477baa7a415…` |
| `14_oob_read_flag_array` | `b8e3b1de1e7d9057…` | `d12aa477baa7a415…` |
| `15_ret2win_arg_gate` | `cb08f0bf25f87c49…` | `94cf5677d344bfdf…` |

(Full-length digests: `sha256sum benchmark/corpus_r2/*/*.c benchmark/corpus_r2/*/cflags`.)

**Instrument provenance the measurer cannot attest to alone.** The scrape-clean /
technique-class matching criterion used in §1.4 originated with the coordinator, was
derived from R1's structure, and was fixed before either party had seen any R2 result
other than `07`. The messages crossed, and the criterion is mechanical. This is
recorded because a measurer asserting "I did not tune the criterion to the data" is
exactly the claim a measurer cannot make credibly about themselves.

### 2.8 Source-read contamination check — clean on all 15

The benchmark's premise is that the pipeline works from the **binary**. If any code
path on the `autopwn` route read `<target>.c`, the figure would describe a
source-assisted pipeline instead. `supwngo/analysis/source.py` does read `.c` files,
and static audit places it behind the separate `supwngo source` CLI verb only — but
that is an argument about code, so it was checked as behaviour:
`benchmark/contamination_check.sh` replays the cold run's exact autopwn command line
on the same binaries under `strace -f -e trace=openat,open`, all 15 targets.

| observation | result |
|---|---|
| corpus `.c` source files opened, any process | **0 / 15 traces** |
| reference exploits / `corpus_r2_reference` opened | **0 / 15 traces** |
| `flag.txt` opened by the **pipeline** process | **0 / 15 traces** |
| trace coverage positive control (target binary opened by the root Python process) | 4–6 opens per trace, all 15 |

`flag.txt` **is** opened 259 times across the traces, and every one is accounted for:
`14_oob_read_flag_array` 254 (the target loads a flag array at startup, once per
execution — 254 distinct PIDs, one open each), `10` and `15` twice each, `13` once.
**Every opening PID was verified not to be a Python process** (none of them opened a
single `.py` file), i.e. each is the target binary or a shell/`cat` it spawned. That
matches the attribution chains in §2.3 exactly — including `13`, where the target
process itself both opens and writes the flag, and the pipeline never touches it.

The positive control matters as much as the negative result: a trace that recorded
nothing would produce the same "0 source opens" answer as a clean run. Each trace is
2 731–19 966 lines and shows the root Python process opening the target binary, so
the instrument was demonstrably looking at the right thing when it found nothing.

**This is a replay, not an observation of the cold executions themselves** — residual
limit 2 below, stated there and not softened here.

### 2.9 Residual limits — disclosed, not closed

Reproduced verbatim from the plan's §11 so the caveats travel with the number.

> 1. **Inner (per-technique) truncation at the 20 s budget is not ruled out**
>    `[R2-1]`. Transcript analysis catches only an outer kill. A technique needing
>    25 s of gadget search would report "did not apply" indistinguishably from one
>    that genuinely did not apply. No second execution can settle it without
>    confounding on the known delivery flake. Hence the cold figure is defined as
>    *capability at a 20 s per-attempt budget*, never as unbounded capability.
>
> 2. **Source-read contamination is checked on replay, not on the cold executions
>    themselves** `[R2-1 / round-3 #1]`. The reviewer's objection is correct and is
>    recorded rather than argued away: the §6 `strace` run replays the same command
>    line on the same binaries *after* the cold run, and in principle a cold
>    execution's access path could differ.
>
>    *(Executed as §2.8 above: clean on all 15 traces, with a coverage positive
>    control. The replay caveat in this paragraph stands unchanged.)*
>
>    Why I accept this rather than instrument the cold run: observing it from inside
>    would mean an audit hook (via a `sitecustomize.py` on the `PYTHONPATH`
>    `run_bench.py` already sets) running in every measured process, adding per-`open`
>    overhead inside the very 20 s budget that limitation 1 shows is already tight —
>    i.e. trading a real risk to the *primary* measurement for a check on a
>    *secondary*, bounded one. The bound: R2's flags exist only in `flag.txt` at
>    runtime and attribution credits a success only when the target process or a
>    descendant writes the flag, so a source read could yield an informational
>    advantage but **cannot manufacture a flag**. The static audit also establishes
>    that no source-reading code path exists on the autopwn route, and nothing in the
>    pipeline is nondeterministic about *which* files it opens.
>
>    **Structural fix, deferred to R3+**: design the audit hook in from the start of
>    a round, where it is part of the instrument for both the baseline and the
>    measurement, rather than bolted onto an irreplaceable run. Recorded here so the
>    next round can close it properly.
>
> 3. **The host cannot be reserved** `[R2-3]`. Contention is sampled continuously and
>    reported as a load profile; it is not eliminated.
>
> 4. **The committed `report.json` is redacted** `[R2-8]`. Per-rep secrets are
>    replaced with placeholders, so a reader can check structure, statuses, reasons,
>    attribution verdicts and timings against the prose, but not re-derive a verdict
>    from the raw secret. The unredacted original stays on disk with its sha256
>    recorded. This is forced by the corpus contract's no-flag-in-git rule.

Added by this run, not present in the plan:

5. **The concurrent-harness counter undercounts by construction** (§2.6). "Never 2"
   is an absence assertion from a detector biased toward zero. Bounded structurally by
   `corpus_lock()` and corroborated by the load ceiling, not closed.

6. **R2 can never separate flag-delivery mechanism from technique class** (§1.4).
   R2's fix for R1's delivery defect was uniform across all 15 targets, which is
   correct for soundness and destroys the within-corpus contrast needed to
   distinguish "the pipeline is good at this technique" from "the pipeline is good at
   this delivery shape". **No amount of §3 development on R2 repairs this** — it is a
   fixed property of the corpus. The R5 generator spec is being amended to require
   varied delivery *within* technique class; the consequence is that once R5 has
   varied delivery and R2 remains uniform, R2 is permanently the round that cannot
   answer this question.

### 2.10 What happens next, and what this figure is not

The cold measurement is complete and committed. Development (step 3) begins only
after this commit lands, under the §5 generalize-versus-target-specific rules, and
its results go in a **separately titled report labelled training performance on R2**
— `docs/reports/BENCHMARK-R2-POST-DEV-24SEP2026.md`. R1 must still hold 13/13 as a
regression gate. The R3 and R4 corpora (`9326d95`, `9868b75`) remain unmerged and
unseen; code freezes before any access to them.

**4/15 is the generalization number. Any later number on R2 is a training number.**
The two are not comparable and will not be presented as if they were.
