# Implementation review — walkthrough blind-follower scorer (codex, 2026-09-24)

Second independent review for this work item, this one of the **implementation**
rather than the plan. (The plan review is
`2026-09-24-walkthrough-blind-follower-scorer-review-codex.md`.)

- Reviewer: `codex exec -m gpt-5.6-sol -c model_reasoning_effort=xhigh`,
  `--sandbox read-only`, prompt built by `/tmp/codex-out/build-impl-prompt-a48.sh`
  from the working tree at the time: `benchmark/walkthrough/{score,followers,
  selftest}.py`, `benchmark/attribution.py`, the fixtures, and the plan.
- Verdict: **blocking defects exist** — 12 BLOCKING, 5 MAJOR.

The review is recorded verbatim below. Disposition follows it: what was fixed,
and for each hole left open, why, and what would close it. The open ones are
also stated in `benchmark/walkthrough/README.md` so an operator reading the tool
sees them without reading this file.

---

## Review, verbatim

Blocking defects exist.

1. [BLOCKING] `benchmark/walkthrough/score.py — score_artifact`: The staged target is writable by the artifact. It can replace the binary with `#!/bin/sh\ncat flag.txt`, execute the same pathname, and receive `CREDITED`; the open audit considers that shell part of the “target” lineage. Run artifacts under a different UID with the target and flag immutable/read-only, and attest the executed inode/hash rather than only its pathname.

2. [BLOCKING] `benchmark/attribution.py — parse_trace`: `_EXECVE_OK` records failed `execve` calls except `ENOENT`/`EACCES`. An artifact can force `execve(target, huge_argv)` to fail with `E2BIG`, then read and print the flag; subsequent activity is falsely treated as target lineage. Record exec events only when the syscall result is exactly success, including correctly parsing `execveat`.

3. [BLOCKING] `benchmark/walkthrough/score.py — run_target`: The actual order is freeze → re-mint → wipe, contrary to the claimed freeze → wipe → re-mint sequence. Worse, follower descendants are never killed; a daemon can survive the CLI, wait for the new secret, and exfiltrate it after re-staging. Terminate the entire follower cgroup/process namespace, verify it is empty, wipe, then re-mint and stage.

4. [BLOCKING] `benchmark/walkthrough/score.py — Stage.wipe_except/Stage.stage`: `flag.txt` and the binary are preserved by name and overwritten with `shutil.copy2`. A follower can replace `flag.txt` with a symlink or create an external hard link; re-staging then writes the scored secret into the attacker-controlled alias. Remove these paths with `lstat`, reject links/non-regular files, and install fresh files using atomic create-and-rename.

5. [BLOCKING] `benchmark/walkthrough/score.py — score_artifact`: The artifact runs once untraced and then again under audit in the same writable directory. The first execution can scrape the secret, cache it under another name, or rewrite `exploit.py`; the second execution is therefore neither fresh nor the frozen artifact. Use one traced execution as the verdict source, with an immutable artifact and fresh filesystem.

6. [BLOCKING] `benchmark/walkthrough/score.py — flag_file_opened_outside_target`: The audit identifies the flag by the substring `"flag.txt"`, not file identity. `link("flag.txt", "x"); open("x")`, rename, or an alias created before re-mint bypasses it; successful opens of unrelated `notflag.txt` can falsely reject honest artifacts. Prevent alias creation and audit the actual protected inode/file descriptor.

7. [BLOCKING] `benchmark/walkthrough/score.py — flag_file_opened_outside_target`: Open events are reparsed from raw lines, so unfinished/resumed `openat` calls are missed. `openat2` and equivalent mechanisms are not traced at all. Add structured, reassembled open events to `parse_trace`, cover `openat2` and link/rename operations, or enforce access with OS isolation rather than syscall-name matching.

8. [BLOCKING] `benchmark/walkthrough/score.py — score_artifact/gate_result`: `--strict-attribution` defaults off, and a gate can PASS when strace is absent or inconclusive through `CREDITED_UNWITNESSED`. This contradicts the stated requirement that target-lineage attribution is mandatory. Agent runs must treat every unavailable/inconclusive witness as `NOT_MEASURABLE`, and `gate_result` must require strace plus strict attribution.

9. [BLOCKING] `benchmark/walkthrough/score.py — run_target/Stage`: Both arm directories coexist as siblings. The bare follower’s permitted Bash tool can read `../walkthrough/...`, so the necessity control is not binary-only. Run arms in mutually inaccessible mount/process namespaces; merely using separate sibling directories is insufficient.

10. [BLOCKING] `benchmark/walkthrough/followers.py — AgentFollower.run`: A nonzero Claude exit is considered valid whenever any `exploit.py` exists. A bare-arm crash or budget exhaustion leaving a partial file becomes an observed failure and can enable `FOLLOWABLE`. Treat every nonzero/incomplete CLI termination as invalid regardless of artifact presence.

11. [BLOCKING] `benchmark/walkthrough/score.py — compute_rates/gate_result`: `VOID` targets leave the strict denominator, yet do not block the gate. A provisioning or negative-control failure on a previously failing target can therefore increase the reported gate score and produce PASS. Make any runtime-discovered VOID block the gate, or retain it as non-passing in the fixed manifest denominator.

12. [BLOCKING] `benchmark/walkthrough/followers.py — AgentFollower.run/blindness_audit`: `claude -p` output is stored as a “full transcript” without requesting tool-event output; tool invocations and redirected reads need not appear in stdout/stderr. Read/Glob/Grep are also not demonstrably cwd-confined, and shared HOME exposes settings and state. Use a filesystem/container boundary with an isolated HOME; transcript marker scanning cannot establish blindness.

13. [MAJOR] `benchmark/walkthrough/score.py — run_target`: There is no wipe before the next rep’s follower session. Files created by the previous scored artifact, including `.tmp` and deliberately copied helper exploits, survive and can improve later reps. Start every arm/rep in a newly created directory or perform a complete pre-follower wipe.

14. [MAJOR] `benchmark/walkthrough/score.py — gate_result`: The `reps` argument is unused, and the gate accepts arbitrary model, effort, budget, timeout, and one-rep runs. The claimed pinned measurement is only recorded, not enforced. Validate the complete canonical R5 protocol before emitting PASS/FAIL.

15. [MAJOR] `benchmark/walkthrough/score.py — resolve_walkthrough`: Fuzzy globbing silently selects the first of multiple or prefix-matching files, potentially scoring the wrong walkthrough. Require an exact manifest mapping and reject zero or multiple matches.

16. [MAJOR] `benchmark/walkthrough/score.py — main`: Result directories use second-resolution timestamps with `exist_ok=True`; concurrent invocations started in the same second can serialize on the corpus lock and then overwrite the same reports. Use an exclusive UUID/mkdtemp run directory. The corpus lock should cover build-and-copy operations or a private corpus clone, not hours of follower execution.

17. [MAJOR] `benchmark/walkthrough/selftest.py — run`: The self-test bypasses `run_target`, so it does not test the claimed freeze/wipe/re-mint control, process teardown, link aliases, cross-arm isolation, nonzero exits, target replacement, failed exec attribution, or unwitnessed gate behavior. Add end-to-end adversarial controls for those paths; the current negative fixtures cannot validate the critical instrument guarantees.

---

## Disposition

### Fixed

| # | Fix |
| --- | --- |
| 2 | **This one was a live false-credit channel in the pre-existing harness, not just in the new scorer.** `benchmark/attribution.py:parse_trace` recorded an `execve` as successful unless the line mentioned `ENOENT` or `EACCES`, so `E2BIG`, `ENOEXEC`, `EPERM` and `ELOOP` failures all created a fake "the target was exec'd" event — which is the premise the whole lineage rule rests on. Replaced the denylist with an allowlist, `_EXECVE_SUCCEEDED = re.compile(r"\)\s*=\s*0\s*$")`, verified against a real trace (success is `) = 0`, failure is `) = -1 ENOENT (...)`). A strict tightening: it can only ever remove credit, never add it. |
| 3 (order) | The docstring, the README and `summary.txt` now state the real order — freeze → re-mint → wipe → re-stage → score — instead of the order they claimed. |
| 3 (teardown) | New `followers.reap_process_group()`. The follower CLI is now launched with `start_new_session=True` and its entire process group is SIGTERM'd, then SIGKILL'd, after every session and **before the scored secret is minted**, so nothing the follower started can be alive in the sandbox when the new `flag.txt` is staged. Survivors are counted into the trial record. |
| 4 (re-stage half) | `Stage.stage()` now calls `_unlink_alias()` (an `lstat`-then-remove that never follows a link) before every `shutil.copy2`, so re-staging can no longer write the scored secret through a follower-planted symlink. `wipe_except()` no longer descends into symlinked directories. |
| 8 | `gate_result()` gained hard blockers: no `strace`, `--strict-attribution` off, `reps < MIN_GATE_REPS`, and any target that went `VOID` during the run. It is also now **called with those arguments** — the signature had gained them while `main()` still called positionally, so the two new blockers silently defaulted to "satisfied" and could never fire. A gate check that cannot fail is the exact defect this work item exists to prevent. |
| 10 | **Any** nonzero follower exit is now `valid=False`, artifact present or not. Previously a crashed or budget-exhausted session that left a partial `exploit.py` counted as an *observed failure* — and an observed failure in the bare arm is precisely what grants the walkthrough credit, so a crash could manufacture a `FOLLOWABLE`. |
| 11 | Any `VOID` discovered during a run blocks the gate. |
| 12 (partial) | `--output-format stream-json --verbose` is now requested, so tool invocations appear in the transcript the blindness audit reads rather than only the model's prose. The confinement itself is still unprovable from inside the process — see the open list. |
| 13 | Both sandboxes are wiped with the new `Stage.wipe_all()` **before** each rep's follower session, so rep *N* cannot build on rep *N−1*'s leftovers and the k/N figures stay independent. |
| 14 (reps) | `reps` is now used: `reps < 2` blocks the gate. Model/effort/budget are recorded and pinned by default but not *enforced*, which is stated. |
| 15 | `resolve_walkthrough()` raises `AmbiguousWalkthrough` on more than one match instead of returning `hits[0]`. A verdict attached to the wrong artifact is worse than a missing one, because nothing about it looks wrong. |
| 16 | The results directory gets a random suffix and is created **without** `exist_ok`, so a same-second collision fails loudly instead of overwriting a measurement. |
| 17 | New **end-to-end selftest layer** driving `run_target` itself with a follower scripted inside `selftest.py` and installed by replacing `score.build_follower`: positive control (`FOLLOWABLE`), necessity (`UNINFORMATIVE`), a follower that hardcodes the flag it was shown (`NOT_FOLLOWABLE`, plus an assertion that the scored secret differs from the one it read), and an invalid bare trial (`NOT_MEASURABLE`). Deliberately **no test hook in the product**: a stub-follower mode reachable by an operator would be a way to produce a fake measurement. |
| 9 (partial) | Arms moved from sibling directories under one target directory to separate roots (`arm-walkthrough/<slug>`, `arm-bare/<slug>`), so `../walkthrough/` no longer resolves. Filesystem confinement is still not provable — see the open list. |

### Open, with reasons

Documented in `benchmark/walkthrough/README.md` under "Known residual holes".
Summarised: **1** (writable same-UID target — now *detected* by `_attest()`'s
inode + `ctime_ns` + hash attestation across the scoring window, with
`fixtures/broken_overwrites_target.py` demonstrating the attack and asserting the
detection, but detection is not prevention); **4/6/7** (the flag file is protected
by *name*, so `link`/`rename`/`openat2` read-side evasions remain, and unfinished
`openat` lines are not reassembled); **5** (two executions per artifact, kept
because collapsing them would change `run_bench.py`'s autopwn number for an
unrelated reason — covered in effect by the same attestation); **3 (escape)** (a
double-fork + `setsid()` leaves the process group); **9** (same-filesystem
confinement between arms); **12** (tool confinement asserted by the CLI, shared
`HOME`).

Every one of these biases the walkthrough arm **upward**, so the published figure
is an upper bound on `artifact_followable` under process-level isolation. Closing
them needs a privilege boundary — container, user namespace or separate UID —
which is a change of harness class, not a patch.

### Disagreed

- **16, second half** ("the corpus lock should not cover hours of follower
  execution"). Correct in principle and deliberately not done. The lock exists
  because the corpus build directory is shared mutable state and other agents run
  the harness concurrently; releasing it between the decoy build and the re-mint
  would let another run rebuild the target underneath a live measurement. A
  private corpus clone per run is the right fix and is a separate change to
  `run_bench.Corpus`, not to this scorer.
- **15, first half** ("require an exact manifest mapping"). The scorer must stay
  usable against a directory of generated walkthroughs produced by an engine on an
  unmerged branch, which has no manifest to read. Rejecting zero and multiple
  matches gets the safety without inventing a second manifest format.
