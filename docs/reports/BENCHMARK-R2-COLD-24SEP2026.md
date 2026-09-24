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

### 1.4 The R1 ↔ R2 comparison is NOT like-for-like

The cold figure will be read against R1's 13/13. It must not be read as
like-for-like, and the confound runs in a direction that is easy to get backwards:

| | R1 | R2 |
|---|---|---|
| flag delivery | compiled in via `-DFLAG` for win()-style targets | **read from `flag.txt` at runtime by every target** |
| `strings \| grep 'FLAG{'` recovers the flag | **9 of 15** | **0 of 15** |
| targets scoring only behind the bypassable script audit | 9 | 0 |
| excluded as `VOID` | 2 | **0** |

R1's 9-of-15 scrape surface means **part of its 13/13 was reachable without
exploitation**; R2 closes that route entirely. So the confound **inflates R1 and
deflates R2** relative to true capability — two mechanisms pointing the *same* way
as overfitting, and this measurement cannot separate them.

**R1-strict vs R2-strict is the closest available like-for-like pairing**, because
`--strict-attribution` is what withholds scrape-reachable credit. The gap between
the default-mode pairing and the strict-mode pairing estimates the confound's size.

This is a limit on what the R1→R2 *delta* can be attributed to. It is not offered
as a reason to discount the cold number.

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

---

## PART 2 — THE COLD RESULT

*Pending. This section is written only after the run completes, and the figures in
it are whatever the run produced.*
