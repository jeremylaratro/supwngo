You wrote the supwngo roadmap under review (synthesis + fold). This is a FOLLOW-UP SELF-REVIEW of your own
content. Unlike the earlier passes, **execution and testing of the framework are allowed**: verify claims by
running things, not only by reading them, and investigate further where execution raises new questions.

## Workspace and boundaries

- **Your working directory** is `/tmp/mythos-verify/tree`, a scratch copy of the supwngo repo (no `.git`).
  - Use it for all code imports. Run the framework as `PYTHONPATH=$PWD python3 -m supwngo.cli …`, or run
    `pytest` from this directory.
  - You may write prototype patches here to demonstrate a fix. Label them clearly.
- **Put every scratch script, fixture, log and output** under `/tmp/mythos-verify/work/`, and reference
  those paths in your report.
- **Do not write anywhere else.** In particular, do not modify anything under `/srv/share/dev/`; that is the
  live repo. Do not use git, sudo, or network package installs (pip/apt/npm). Use only tools already
  installed.
- **Target binaries** may be executed only from a copy of their challenge directory under `work/`. The cwd
  must be that copy, because several targets use a relative `./glibc/ld-linux` interpreter.
  - Use a `timeout` (≤ 120 s) on every run.
  - Never leave processes running when you finish.
- **The host is shared and loaded** (32 cores, load often 15–40).
  - Prefix heavy commands with `nice -n 10`.
  - Run at most 4 parallel jobs and at most 2 concurrent Ghidra processes.
  - Record the load average next to any timing you report.
- **Tools available:**
  - Ghidra 12.1.3 at `/opt/ghidra/support/analyzeHeadless`. It has no PyGhidra, so use Java GhidraScripts,
    and pass a `-scriptPath` directory that contains only your script.
  - gcc, `x86_64-w64-mingw32-gcc`, gdb, patchelf, objdump, readelf and pwntools.
  - Prior experiment material is in `_review/experiments/`:
    - `ghidra-frames/scripts/SupwngoFrames.java` — the P-code frame/sink exporter, with its outputs;
    - `pe-fixtures/` — mingw PE32/PE32+ fixtures and their source.

## Read first

`_review/`:
- `BRIEF.md`, `SCORECARD.md`, `SPOTCHECK.md`, `FOLD-NOTES.md`;
- `ROADMAP-FINAL.md` — your folded roadmap, the document under self-review;
- `DBB-REVIEW.md` — the peer review that the fold answered;
- `SP01-PLAN.md` and `SP01-PLAN-DBB-REVIEW.md` — the detailed first-sprint plan and its peer review;
- `ROADMAP-DRAFT.md` and `reviews/D1–D5.md`, as needed.

## What to do

1. **Verify by execution.** Take the load-bearing claims of `ROADMAP-FINAL.md`: baseline numbers, cited
   defects, design premises of SP-01–SP-04, and the decisions DEC-n. Verify each by running something
   wherever that is possible. For each, give a verdict:
   - CONFIRMED-BY-EXECUTION (show the command and an output excerpt);
   - CONFIRMED-BY-READING;
   - WRONG;
   - UNVERIFIABLE.
2. **Run the hypotheses that are cheap to test today.**
   - **HYP-2** — Ghidra cold vs warm (`-process -noanalysis`) on a persisted project.
   - **HYP-4** — engine agreement across `pwn`/`template`/`explain`/`autopwn` on a few binaries.
   - **HYP-5** — rename invariance. For example, `objcopy --redefine-sym` the payoff function of a ret2win
     fixture you build, then compare method and win detection.
   - **HYP-10 and the SROP rax-control question** — sick_rop plus a negative fixture with `syscall; ret`
     and no way to set rax = 15.
   - **HYP-14** — import reachability.
   - **HYP-22** — other stringly-typed comparisons.
   - **The D2-H1 static-offset bet on new fixtures you build**: gcc `-O0`/`-O2`, canary and no canary,
     PIE, a caller buffer with a callee sink, a copy loop, and mingw PE32/PE64. Score the Ghidra P-code
     distance against DWARF truth and, where runnable, a crash/breakpoint measurement.
   - **The B-5 override path** — can `pwn` be made to recommend RET2WIN from a supplied win address, and
     how?
   - **The B-11 deletion consumers.**
   Prefer experiments whose result changes a decision.
3. **Validate the first sprints' test designs.** Write the proposed SP-01 and SP-02 RED tests as scratch
   tests under `work/`. Run them against the current tree and show that they fail, and that they fail for
   the stated reason. Where it is cheap, prototype the fix in the tree copy and show that the test then
   passes. Flag any RED test that is vacuous or that would pass on the broken code.
4. **Record a baseline.** Run the full unit suite once (`nice -n 10 python3 -m pytest -q`; record counts and
   wall time; the expected baseline is about 2230 passed and 18 skipped). Also run the HTB `pwn`,
   `template`, `decompile` and `offset` scorecard from challenge-directory copies. This corrects the
   original scorecard's interpreter defect.
5. **Amend your own roadmap** wherever execution showed it to be wrong, optimistic, mis-sequenced or missing
   something. Be as adversarial with your own content as the peer reviewer was.

## Output (markdown; your final answer is the report)

### 0. Verdict
5–8 bullets. Does the roadmap survive contact with execution?

### 1. Execution log summary
What you ran, wall time, load, and where the artefacts are under `work/`.

### 2. Claim verification
Table: claim, roadmap location, verdict, command/evidence.

### 3. Hypotheses tested
Table: HYP-id, result, evidence, decision impact.

### 4. RED-test validation for SP-01 and SP-02
Table: test, fails on current tree? (Y/N, with reason), vacuous?, prototype fix passes?

### 5. New findings from execution
Bugs and surprises, each with a minimal repro command.

### 6. Roadmap amendments
AMD-n entries, each with the section/sprint changed, the exact change, and the evidence.

### 7. Updated sprint-map rows
Only rows that change, in the same column format as the roadmap.

### 8. Measured baseline
Updated numbers that replace "Today": scorecard from challenge directories, unit suite counts, timings.

### 9. Remaining unknowns
And the cheapest next experiment for each.
