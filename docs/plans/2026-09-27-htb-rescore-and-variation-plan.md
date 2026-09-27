# HTB re-score + challenge-variation measurement plan

**Date:** 2026-09-27
**Status:** PLAN — measurement authorised; the recommendation that follows it is
gated on user sign-off.
**Directive (user, 2026-09-27):** "run the tool against all of the htb challenges
plus custom variations. Re-score, then make a recommendation on next steps but do
not start until I sign off." Sign-off scope was clarified by the user to gate
**the recommended next steps**, not the measurement.
**Variation design (user, 2026-09-27):** "Vary the challenge for the rest — same
mechanism but different binaries — size differences, different win functions,
different patterns, etc."

---

## 1. What is being measured, and against what

Two separate measurements with two different harnesses, because one harness
cannot honestly carry both. Reported separately; never summed.

| # | Measurement | Harness | Baseline it compares to |
|---|---|---|---|
| **H** | the 7 HTB challenges, unmodified | `supwngo solve --json` per target | canonical **1/7**, recorded, `docs/plans/2026-09-26-retest-sprint-map.md:73` |
| **V** | authored variation corpora | `benchmark/run_bench.py` | none — first measurement, so it establishes one |

**T-1** is the gate H feeds: *canonical solves ≥3/7 HTB targets without legacy
fallback*. Current recorded state, `measured` but **predating both Sprint 1 and
Sprint 2′**:

| target | legacy | canonical | class |
|---|---|---|---|
| `sick_rop` | ✓ | ✗ | SROP; minimal static, `.text` only, no writable section in headers |
| `rocket_blaster_xxx` | ✓ | ✓ (`ret2libc_leak`) | ret2win-with-args (`fill_ammo`), ships its own glibc |
| `ancient_interface` | ✓ | ✗ | ROP |
| `snow_scan` | ✗ | ✗ | format/parser gate — blocked behind **B-3** |
| `auth-or-out` | ✗ | ✗ | unclassified in the retest report |
| `sabotage` | ✗ | ✗ | `scanf_canary_bypass` (legacy attempted, failed) |
| `bon-nie-appetit` | ✗ | ✗ | unclassified; name suggests heap |

**Erratum, recorded here beside the claim it corrects:** an earlier statement in
the 2026-09-27 session named legacy's three solves as `sick_rop`,
`rocket_blaster_xxx`, `snow_scan`. That is wrong — it misread
`docs/reports/2026-09-26-comprehensive-feature-retest.md:125`, which is about the
`explain` command, not about solving. The legacy solve set is `sick_rop`,
`rocket_blaster_xxx`, `ancient_interface` (same report, lines 74-84).

---

## 2. Measurement H — re-score the 7 HTB challenges

### 2.1 Why not the strong harness (method rejected, with the reason)

The preferred option was to wrap the 7 binaries as a corpus so they would inherit
`run_bench.py`'s reps, negative controls, and behavioural attribution. **It is not
possible without changing the harness**, and the reason is structural, not
cosmetic (`verified by inspection`, `benchmark/run_bench.py`):

- `Corpus.source(slug)` expects `<slug>/<name>.c` and `Corpus.flag_file(slug)`
  expects `<slug>/flag.txt`.
- `corpus_lock`'s docstring states the harness **"rebuilds each target with a
  fresh secret flag mid-run"**. That per-run secret is the whole basis of its
  attribution: a flag that did not exist before the run cannot have been copied
  from anywhere.

HTB binaries have no source and no controllable flag, so the fresh-secret
mechanism has nothing to act on. Wrapping them would mean weakening the harness's
attribution to accommodate the targets — which the standing constraint forbids
outright.

**What would flip this:** building a genuine attribution path for prebuilt
binaries — e.g. scoring HTB solves on `SHELL_ACCESS` confirmed by process-tree
attribution rather than on a flag string. `rocket_blaster_xxx`'s recorded solve
was already `SHELL_ACCESS verified`, so the ingredient exists. That is a sprint,
not a precondition for this measurement, and it is the leading candidate for the
recommendation in §5.

### 2.2 Chosen method

`supwngo solve --json` per target, which is how the recorded 1/7 was produced, so
the comparison is like-for-like. Strengthened where strengthening costs nothing
and does not change the comparison:

- **Reps: 3 per target.** The recorded baseline was single-shot. Reps do not
  change what is measured, only how confidently; a target that solves 1/3 is
  reported as 1/3, not rounded to solved.
- **Verdict per target** is the strongest level reached, from the receipt:
  `SHELL_ACCESS` > `FLAG_CAPTURED` > none. A solve counted toward T-1 requires
  one of the first two, recorded with its technique and provenance.
- **`--libc` is NOT supplied.** T-1 says "without legacy fallback"; the recorded
  1/7 did not pass it either, and `rocket_blaster_xxx`'s shipped-libc detection
  is a Sprint 2′ feature under test. Supplying it would measure the operator, not
  the tool. A target that solves only with `--libc` is reported as a separate,
  clearly-labelled line and does **not** count toward T-1.
- **Timeout: 300s per attempt**, recorded. A timeout is reported as a timeout,
  not as a failure.

### 2.3 Pre-validation of the HTB targets themselves (measured 2026-09-27)

Run before scoring, per the standing "validate the assessment before you trust
it" mandate. It changed the scoring design, which is why it is recorded here
rather than assumed.

| target | linkage | ships `flag.txt` | flag path in binary | achievable success level |
|---|---|---|---|---|
| `ancient_interface` | dynamic, no PIE | **yes** | — | `SHELL_ACCESS` or flag |
| `auth-or-out` | PIE | no | — | `SHELL_ACCESS` only |
| `bon-nie-appetit` | PIE | no | — | `SHELL_ACCESS` only |
| `rocket_blaster_xxx` | dynamic, no PIE | **no** | **`./flag.txt`** | see below |
| `sabotage` | PIE | no | — | `SHELL_ACCESS` only |
| `sick_rop` | **static** | no | — | `SHELL_ACCESS` only |
| `snow_scan` | dynamic, no PIE | **yes** | — | `SHELL_ACCESS` or flag |

Two consequences, neither of which was visible from the recorded baseline:

1. **`FLAG_CAPTURED` is structurally impossible for 5 of 7.** They are
   shell-popping challenges with no local flag file and no flag path compiled in.
   A scoring rule that required a captured flag would score five targets as
   unsolvable by construction and read as a tool failure. Success for these is
   `SHELL_ACCESS`, which is what `rocket_blaster_xxx`'s recorded solve used.
2. **`rocket_blaster_xxx` references `./flag.txt` and does not have one.** Its win
   function `fill_ammo` opens that path, so a genuine `ret2win` solve would
   succeed at redirecting control and then produce nothing to observe — an
   exploited target scored as a failure. The file is absent because HTB serves the
   flag from the remote instance; providing one locally is correct provisioning,
   not a weakened gate.

**Provisioning rule.** Each rep runs in a fresh copy of the challenge directory,
never in `tests/htb-targets/` itself, with a **per-rep random secret** written to
the flag path the binary names. A solve counts only if it reproduces *that*
secret — a value that did not exist before the rep began, so it cannot have come
from anywhere else. Targets that ship a `flag.txt` get theirs replaced by the
per-rep secret in the copy, so a target cannot be credited for echoing a value
that was already on disk.

This recovers, for the ad-hoc harness, the one property that made `run_bench.py`'s
attribution trustworthy — a secret that postdates the run — without touching the
harness or the targets.

### 2.4 Three states, not two

| state | condition |
|---|---|
| SOLVED | ≥2 of 3 reps reach `SHELL_ACCESS` or `FLAG_CAPTURED` |
| INCONCLUSIVE | 1 of 3 reps succeeds, or any rep times out while others fail |
| NOT SOLVED | 0 of 3 reps succeed, no timeouts |

INCONCLUSIVE is not rounded in either direction and does not count toward T-1.

---

## 3. Measurement V — variation corpora

The user's design, applied per the one hard constraint on it:
`FILE_DELIVERY_ALLOWLIST` admits only `variable_overwrite` and `ret2win` on a
non-stdin sink, so ingress can only be varied for those two. Everything else
varies the **challenge** instead.

### 3.1 V-A — ingress variation (allowlist-permitted techniques)

`variable_overwrite` is **done and committed** (`8d76e14`,
`benchmark/corpus_vectors/`, 5/5 transports after I-7). This extends the same
matrix to `ret2win`, minus the combinations that are undeliverable by
construction:

| row | technique | ingress | note |
|---|---|---|---|
| `30` | `ret2win` | stdin | fixed point |
| `31` | `ret2win` | `file-argv`, bare path | |
| `32` | `ret2win` | `file-argv`, `-f FILE` | |
| — | `ret2win` | `argv` | **excluded**: a 64-bit win address packs with NUL bytes, so every payload is unrepresentable in an argv token. This is I-8, not a gap to measure. |

### 3.2 V-B — challenge variation (allowlist-blocked classes)

Same mechanism, different binaries. Per class, the dimensions varied are the ones
that plausibly break a *tuned* implementation while leaving the technique valid:

| class | ingress | varied across binaries |
|---|---|---|
| `ret2win` / win-function discovery | stdin | **win-function name** (in the 21-name list, outside it, and named like a decoy); **arity** (0 args, 1, 3 magic args like `fill_ammo`); buffer size (48/64/200) |
| ROP / `ret2libc_leak` | stdin | leak function (`puts`/`printf`/`write`); buffer size; PIE on/off; shipped-libc vs system libc |
| SROP | stdin | writable section present vs `.text`-only (the `sick_rop` shape); static vs dynamic |
| format string | stdin | offset to the format argument; `%n` available vs write-via-`%hn`; buffer size |
| heap | stdin | chunk sizes straddling tcache bins; allocation order; free order |
| canary bypass | stdin | canary leak via format vs via partial overwrite; buffer size |

**Deliberately held constant within each class:** the vulnerability itself. If
both the mechanism and the geometry move, a failure is unattributable — the same
discipline that made `corpus_vectors` interpretable.

### 3.3 Why this corpus can use the strong harness

Unlike HTB, these are authored from source, so they get per-run secret flags,
reps, negative controls, and behavioural attribution for free — and each class
gets a **paired negative control** on the `90`/`91` pattern that
`corpus_vectors` proved out: a binary with the win path removed must FAIL while
its sibling, differing only by the causal lines, must SUCCEED.

### 3.4 Validation before use (standing user mandate)

No variation target is trusted until, per target: the intended payload wins; a
**wrong-but-present** payload at the same offset does not; and the bare negative
control produces nothing. The `corpus_vectors` build is the precedent — that
4-way check is what caught a gate value (`0x41414141`) that the executor's own
`0x41` filler would have satisfied for free.

---

## 4. PASS / INCONCLUSIVE / FAIL for the whole exercise

This exercise is a **measurement**, not a gate — its deliverable is an honest
number plus a recommendation. It therefore has no PASS condition to satisfy, and
that is deliberate: a measurement with a pass threshold invites the threshold to
be met rather than the number to be reported. The two claims that *will* be
stated, each with provenance:

1. Canonical's HTB solve count, per target, with technique and verification
   level — compared to the recorded 1/7 and to legacy's 3/7.
2. Per class, whether the technique survives challenge variation, or is tuned to
   one shape. A class that solves its fixed point and fails every variant is the
   finding this exercise exists to produce.

**A null result is reportable.** If the re-score comes back 1/7 unchanged, that
is the answer and it gets stated plainly, not reframed.

---

## 5. Risks, and what I will not claim

- **Authoring bias.** I am writing the variation targets and also reporting the
  score. Mitigation: dimensions are fixed in §3.2 *before* any target is built,
  and the 4-way validation in §3.4 is run before any scoring run. It does not
  eliminate the bias and I am not claiming it does.
- **`snow_scan` stays unsolved.** It is blocked behind B-3, which is deferred.
  So the realistic T-1 ceiling from this exercise is 6/7, and the realistic
  outcome is lower.
- **Unclassified targets.** `auth-or-out` and `bon-nie-appetit` have no recorded
  vulnerability class. Classifying them is part of measurement H, and until it is
  done their variation classes in §3.2 are `inferred`.
- **Compute.** V-B is ~6 classes × ~3 variants × reps, plus paired controls.
  Benchmarks are timing-sensitive and must run serially; this is hours, not
  minutes.

---

## 6. Order of work

1. Measurement H — re-score the 7. Cheapest, answers T-1, needs nothing built.
2. Classify `auth-or-out` and `bon-nie-appetit` from the H run's own output.
3. V-A — extend ingress variation to `ret2win` (3 targets).
4. V-B — author and validate the challenge variants, class by class.
5. Report both measurements, then **stop** and present the recommendation.
