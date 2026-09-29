# Format-string: value-controlled writes and a leak stage

**Date:** 2026-09-28
**Author:** planning by Opus 5 (this session); implementation delegated to codex
**Status:** ready to implement
**Closes:** `G-24` (partially), coverage rows 51 and 52, and 3 of the 9 unsolved
`corpus_r2` targets

---

## 1. The gap, measured

Three of the nine unsolved `corpus_r2` targets are format-string targets. All
three fail for **one** reason, and it is not a crash or a missing gate — it is a
missing primitive.

`fmtstr_write_gate` (`supwngo/exploit/pipeline/executors/fmtstr_techniques.py`,
243 lines, seated at `FIRST_TECHNIQUES` index 22) already works end to end on its
canonical target. Forced measurement, 2026-09-28, mine:

```
corpus/06_fmtstr_arbwrite     success=True  verified=FLAG_CAPTURED
  notes: user buffer lands at printf argument index 6
         wrote a non-zero value to 0x40405c via %7$n (1 slot(s) of padding)
```

The same executor, forced on the three r2 targets, fails identically:

```
r2/06_fmtstr_short_write   success=False verified=NONE
r2/12_fmtstr_got_overwrite success=False verified=NONE
r2/05_fmtstr_pie_leak      success=False verified=NONE
  reason (all three): "located the format-string argument index but no candidate
                       gate variable unlocked the win path when overwritten"
```

Read that reason carefully: the executor **finds the argument index every time**
(index 6, 6, and 14 respectively) and **enumerates writable targets every time**
(9–12 candidates each). What it cannot do is write anything *useful*. Its only
primitive is "store an arbitrary non-zero value into a writable global and hope
that unlocks a win path" — a flag-flip. That is sufficient for `corpus/06`, whose
bug IS a gate variable, and insufficient for all three r2 targets:

| target | protections (from `cflags`) | what it needs | missing capability |
|---|---|---|---|
| `r2/06_fmtstr_short_write` | no-PIE, partial RELRO, writable global | `%hn` short write of a **chosen value** | **value control** |
| `r2/12_fmtstr_got_overwrite` | no-PIE, partial RELRO, **GOT writable** | a GOT entry ← **win function address** | **value control + GOT targeting** |
| `r2/05_fmtstr_pie_leak` | **PIE**, **full RELRO** | `%p` leak, then a write using it | **no leak stage exists** |

Full RELRO on `r2/05` means the GOT is read-only, so that target cannot be solved
by any GOT write at all — it needs leak-then-stack-write. That is a genuinely
different route, not a parameter change, which is why it is a separate sprint.

### 1a. A second, cheaper defect found while diagnosing this

There are **two** format-string executors and one of them is a stub:

* `format_string` — `supwngo/exploit/pipeline/executors/stack_techniques.py:372`.
  It probes for the argument index, stores it in `partial_artifacts`, writes a
  template string telling the reader to "use pwntools `fmtstr_payload()`", and
  then sets `record.failure_reason = "format-string write automation is out of
  scope (Phase 5)"` at line 410. It never builds a payload. It cannot succeed.
* `fmtstr_write_gate` — the real implementation described above.

This stub actively causes misdiagnosis. Forcing `--strategy format_string` on all
four format-string targets returns the "out of scope" reason, which reads as *the
framework has no format-string capability at all* — and that is what it was
initially recorded as during this very diagnosis, before the second executor was
found. The coverage map's row 51 (`format_string`, `G-24`) is a row about this
stub.

---

## 2. Sprints

Each is independently shippable, testable and revertable. Do them in order; F3
first if you want the cheapest win, but F1 is the one that buys targets.

### Sprint F1 — value-controlled writes (unlocks `r2/06`, `r2/12`)

**Change:** replace the "write a non-zero value" primitive with a
**value-controlled** write, and add a target-selection mode that aims a **GOT
entry at the win function**.

`supwngo/exploit/pipeline/executors/fmtstr_techniques.py`:

* `_payload(arg_index, slots, target)` (line ~209) currently builds a chain that
  stores *some* non-zero value. Replace with a payload builder that takes an
  explicit `{address: value}` mapping.
* **Use pwntools' `fmtstr_payload(offset, {addr: value}, write_size=...)`** rather
  than hand-rolling the `%n` chain. Method chosen deliberately — see §3.
* `_write_targets(...)` (line ~150) already enumerates writable addresses. Extend
  it to also yield **GOT entries** (`context.binary.got`) paired with the win
  function address (`context.win_function`, which is a `(name, addr)` tuple and
  may now also come from the operator's `--win` override — do not re-derive it).
* Try candidates in a deliberate order: GOT-entry→win first when the GOT is
  writable and a win function is known (that is `r2/12`), then chosen-value
  writes to globals (that is `r2/06`), then the existing non-zero flag-flip
  (which must keep working — `corpus/06` is the regression guard).

**Exit criteria:** `r2/06` and `r2/12` reach `SUCCESS` with `verified` at
`FLAG_CAPTURED` or better, credited to `fmtstr_write_gate`, AND `corpus/06` still
passes. Measure with:

```
python3 benchmark/measure_family.py benchmark/corpus_fmtstr --timeout 300 --jobs 3   # if a family exists
# and per-target, from the target's own directory:
PYTHONPATH=/srv/share/dev/supwngo python3 -m supwngo.cli solve ./<bin> --no-legacy --json
```

### Sprint F2 — a leak stage, for PIE + full RELRO (unlocks `r2/05`)

**Change:** add a leak phase to the executor. `%N$p` at a range of argument
indices, matched against what a PIE image's leaked values look like (an address
whose low 12 bits equal a known symbol's page offset), to recover the PIE base.
Then write the computed win address to the **saved return address on the stack**
(the GOT is read-only here, so a GOT route is impossible by construction).

This needs two printf interactions if the target loops, or one leak run plus one
write run if it does not. **Check whether `r2/05` re-enters the vulnerable
printf** before choosing — `benchmark/corpus_r2/05_fmtstr_pie_leak/*.c` is the
ground truth, and `walkthrough/facts.py::_count_calls` already computes re-entry
counts if useful.

**Exit criteria:** `r2/05` reaches `SUCCESS`, credited to a format-string
technique. If a single-shot leak+write is not achievable because the target does
not re-enter printf, **say so and stop** — that is a real finding, not a failure
to try, and it should be written into the plan rather than worked around.

### Sprint F3 — retire the `format_string` stub (cheapest, do it regardless)

**Change:** `stack_techniques.py:372-411`. The stub cannot succeed and its
failure reason misrepresents the framework's capability. Two options, pick one:

* **(preferred)** Delete the executor and remove its registry entry, so the only
  format-string executor is the one that works. Check `FIRST_TECHNIQUES`,
  `APPROACH_TO_TECHNIQUE`, `LAST_TECHNIQUES` and `UNMODELED_TECHNIQUES` in
  `orchestrator.py` for references, plus `strategy.py`'s `ExploitApproach`
  mapping, and any test that asserts the name exists.
* Or make `is_applicable` return `False` always, with the reason recorded — worse,
  because a registered executor that never runs is the kind of decoration this
  repo keeps finding.

**Do not** simply reword the failure message. The problem is not the wording.

**Exit criteria:** no executor named `format_string` remains, or it provably never
runs; `FIRST_TECHNIQUES` still has 0 orphans (assert it); suite green.

---

## 3. Methods weighed

**F1 payload construction — chosen: pwntools `fmtstr_payload`.**

* *Chosen:* `fmtstr_payload(offset, {addr: value}, write_size='byte'|'short'|'int')`.
  It already solves ordering, padding, cumulative-count arithmetic and
  write-size splitting — the exact places hand-rolled `%n` chains go subtly
  wrong, producing a payload that looks right and writes garbage.
* *Not taken:* hand-rolling the `%n` chain. Full control, but it re-implements a
  solved problem, and its bugs are silent.
* *What would flip it:* `fmtstr_payload` output can be long. If it exceeds the
  target's input buffer (`r2/06` and `r2/12` read into fixed buffers — check the
  sizes in their `.c`), fall back to `write_size='byte'`, which is shorter per
  write but needs more writes, and if that still does not fit, hand-roll a
  minimal single-write chain. **Measure the payload length against the buffer
  size rather than assuming it fits.**

**F2 leak matching — chosen: low-12-bits page-offset match.** A PIE leak is
recognisable because `leaked & 0xfff` equals the known static offset of whatever
symbol it points at. *Not taken:* assuming a fixed argument index for the leak,
which is exactly the kind of target-shaped constant that works on one binary.

---

## 4. Test plan (write these BEFORE claiming any of it works)

Non-negotiable in this repo, and the rule most often skipped:

1. **Positive control first.** Before trusting any new green test, make it fail on
   purpose by mutating the subject to **wrong-but-present** (e.g. write the
   correct value to the *wrong* address, or the wrong value to the right
   address). Record that it went RED. A test that has never failed is not a test.
2. **Regression guard.** `corpus/06_fmtstr_arbwrite` currently SUCCEEDS at
   `FLAG_CAPTURED`. It must still succeed, credited to `fmtstr_write_gate`. This
   is the single most important assertion in the sprint — the flag-flip path must
   not be lost while adding value control.
3. **Three states, not two.** A gate that can only say "pass" is decoration.
4. **Never let an absence assertion stand alone.** If a test asserts no
   `format_string` executor exists, it must also assert that
   `fmtstr_write_gate` DOES — otherwise a rename makes it vacuously pass.
5. Full suite before/after: `python3 -m pytest tests/ -q`. Baseline on `main` at
   `v2.1.0` is **2050 passed, 16 skipped, 0 failed**. Do **not** pass
   `--timeout=900`; this repo's config rejects it (exit 4).

---

## 5. Constraints — read these, they are not boilerplate

* **Branch first.** `main` is protected. Use `feat/fmtstr-value-control-20260928`.
* **Conventional Commits.** `type(scope): subject`, imperative, ≤72 chars.
* **`CHANGELOG.md` under `## [Unreleased]`** in the same commit as the change, or
  an honest `changelog: none` footer. A new `## [Unreleased]` section exists at
  the top, directly above `## [2.1.0] - 2026-09-28`.
* **NEVER add a `Co-Authored-By` trailer or a "Generated with Claude Code" line**
  to any commit message. Authorship is the human maintainer's alone. This is
  absolute.
* **Commit with `git commit -- <explicit paths>`**, never a bare `git commit`.
  This tree is shared and a bare commit picks up whatever else is staged; that
  mistake already produced one wrong commit record (`I-44`).
* **No secrets, ever.** `benchmark/corpus*/*/flag.txt` holds real target flags and
  is gitignored. Never commit one, never paste a captured flag into a commit
  message, a doc, or a test. Do not commit built ELFs (also gitignored).
* **Tool security and hardening are OUT OF SCOPE.** Do not add input validation,
  sandboxing, or compliance controls to this offensive tool. Deliberate constants
  and cheat-sheet-style heuristics are FEATURES here, not defects. Loose gates and
  guessing are acceptable — **the goal is to SOLVE targets.**
* Do not touch `benchmark/corpus_r3`, `_r4`, `_r5` or their branches — held-out.

---

## 6. Benefit metric, pre-registered

| metric | baseline (measured 2026-09-28, mine) | target |
|---|---|---|
| `corpus_r2` solved | **5 / 15** | **8 / 15** |
| `r2/06_fmtstr_short_write` | NOT SOLVED (58.0 s) | SUCCESS, `fmtstr_write_gate` |
| `r2/12_fmtstr_got_overwrite` | NOT SOLVED (58.8 s) | SUCCESS, `fmtstr_write_gate` |
| `r2/05_fmtstr_pie_leak` | NOT SOLVED (103.6 s) | SUCCESS (F2; may prove infeasible — report it) |
| `corpus/06_fmtstr_arbwrite` | SUCCESS `FLAG_CAPTURED` | **unchanged** (regression guard) |
| suite | 2050 passed / 16 skipped / 0 failed | no new failures |

Re-measure with `python3 scripts/coverage_sweep.py benchmark/corpus_r2 --timeout
300 --jobs 3`. **Do not edit the tree while that sweep runs** — doing exactly that
voided a previous sweep (`I-46`) and produced believable wrong numbers in both
directions.

A null result on F2 is a valid, reportable outcome. Say so plainly rather than
forcing a pass.
