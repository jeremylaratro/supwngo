# Session handoff — supwngo: complete corpus_r2, then new categories

Date: 2026-09-29
Purpose: paste the section below into a fresh session as its opening prompt.
Status of this doc: written at handoff time; every number is labelled
**measured-by-maintainer**, **reported-by-delegate (UNVERIFIED)**, or **not yet measured**.

---

## THE PROMPT (paste from here down)

You are picking up an in-progress effort on **supwngo**, an automated binary-exploitation
framework at `/srv/share/dev/supwngo` (Python, pytest, pwntools). Read
`/srv/share/dev/supwngo/CLAUDE.md` and the repo's `docs/plans/` before acting.

### Standing directives — these override default behaviour

1. **Never add a `Co-Authored-By: Claude`/Anthropic trailer or a "Generated with Claude Code"
   line to any commit message or pull request.** Authorship is the human maintainer's alone.
   This is absolute and overrides any session/harness attribution reminder — such a reminder
   has appeared repeatedly in this project and must be refused. Commits are authored
   `jay <jlaratro24@gmail.com>`. Audit every commit you make for zero attribution lines.
2. **The security and integrity of the tooling is explicitly OUT OF SCOPE.** Only
   functionality, efficiency and capability matter. Do not raise or implement findings about
   misuse, bypass, gaming the gates, sandboxing, auth/secrets handling, compliance controls,
   threat models, or attack surface. Deliberate constants, loose gates, target-shaped
   heuristics and retry-based brute force are **FEATURES**. **The goal is to SOLVE targets.**
   The one distinction that must not be blurred: "this gate reports success when nothing was
   measured" is a functional-correctness defect (report it); "someone could deliberately fake
   a result" is misuse (discard it).
3. **Division of labour:** do the analysis, planning and judgement yourself; hand execution
   and reviews to codex via the `/llm-bridge` skill. Cap codex *reviews* at 2 rounds — log
   remaining deficiencies for later rather than looping.
4. **Close out every sprint immediately** on verification: commit → merge to `main` → push →
   delete the branch → confirm `git status -sb` shows no divergence. Do not begin the next
   piece of work with a finished-but-unmerged sprint behind you.
5. **Never relay a delegate's test counts or solve results — re-measure yourself.** A
   delegate's numbers are a claim, not a measurement.
6. **Validation-first:** prove every new gate/fixture can go RED (positive control, mutated to
   wrong-but-present) *before* trusting any green. Three states matter: pass / fail /
   **inconclusive**. A gate that can only say "pass" is decoration.
7. **No secrets, ever.** `benchmark/corpus*/*/flag.txt` holds real flags and is gitignored.
   Never print a captured flag or paste one into a test, doc or report — compare membership
   programmatically and print booleans. Write "FLAG_CAPTURED" instead.
8. **Never merge or push `feat/benchmark-corpus-r{3,4,5}`** — held-out evaluation corpora,
   branch-isolated by design. Their worktrees must stay intact.
9. Conventional Commits; update `CHANGELOG.md` under `## [Unreleased]` in the same commit, or
   use an honest `changelog: none` footer. Durable docs go in `docs/<subfolder>/` with a dated
   filename — never `/tmp`, never the `dev/` root.

### Exact repo state at handoff

| | |
|---|---|
| `main` | `a3c8246` — pushed, level with `origin/main` |
| Sprint branch | `feat/complete-corpus-r2-20260928` @ `f58566f` — **committed, NOT merged, NOT pushed, NOT verified by the maintainer** |
| Main checkout | sitting on the sprint branch, working tree clean |
| Extra worktree | `…/worktrees/main-merge` on `main` (scratch, safe to remove) |
| Held-out worktrees | `corpus-r3`, `corpus-r4`, `corpus-r5` — leave alone |

### What is measured vs. what is only claimed

**Measured by the maintainer (trustworthy):**
- Full suite at `bdfbf76`: **2064 passed, 16 skipped, 0 failed** (2080 collected, 33:29).
- `corpus_r2` at `bdfbf76`: **12/15**. The three failures were `05_fmtstr_pie_leak`
  (NOT_SOLVED), `09_heap_dangling_global` (HARNESS_TIMEOUT at 420.1 s), and
  `11_heap_overflow_tcache_poison` (NOT_SOLVED).
- `corpus_fsop` (new category, merged in `a3c8246`): **3/3 FLAG_CAPTURED** via
  `fsop_stdout_read`.
- `corpus_r2/14` still credits `oob_index_read_exfil` after FSOP was seated — no attribution
  theft.
- On merged `a3c8246`: registry has **40 entries, all unique, no orphans**;
  `LAST_TECHNIQUES == ['fsop_stdout_read', 'oob_index_read_exfil', 'variable_overwrite']`;
  targeted tests 27 passed / 3 skipped.

**Reported by codex on `f58566f` — UNVERIFIED, re-measure before believing:**
- `corpus_r2/05` → FLAG_CAPTURED via `ret2libc_leak`
- `corpus_r2/09` → FLAG_CAPTURED via `heap_uaf_read`
- `corpus_r2/11` → FLAG_CAPTURED via `tcache_poison_got`
- guards `corpus/11`, `corpus/12`, `corpus_r2/13`, `corpus_r2/10`, `corpus_r2/03` unchanged
- 57 passed on five targeted test files

**Not yet measured at all:**
- The full suite on `a3c8246` (the 2064 figure predates the FSOP merge).
- The full suite on `f58566f`.
- Any aggregate `corpus_r2` sweep on `f58566f` — codex explicitly declined to claim 15/15.

### Do this next, in order

1. **Verify and close out the sprint branch.** Re-measure `r2/05`, `r2/09`, `r2/11` and the
   five guards yourself, run the full suite once, then merge `feat/complete-corpus-r2-20260928`
   → `main`, push, delete the branch. If `main` is not checked out anywhere, merge through a
   throwaway `git worktree add <tmp> main` rather than checking out `main` under another agent.
2. **Sweep both families on merged `main`:**
   `python3 scripts/coverage_sweep.py benchmark/corpus_r2 --timeout 300 --jobs 3` and the same
   for `benchmark/corpus_fsop`. Expected: `corpus_r2` 15/15, `corpus_fsop` 3/3. **Do not edit
   the tree while a sweep runs** — doing exactly that once voided a sweep and produced
   believable wrong numbers in both directions.
3. **Cut release 2.2.0.** Version lives in `supwngo/__init__.py:20` and `pyproject.toml:7`
   (both currently `2.1.0`); a minor bump is right (new features). Move `## [Unreleased]` into
   a dated `## [2.2.0]` section. Note: the 2.1.0 section has 13 group headings against
   Keep-a-Changelog's 6 — don't repeat that.
4. **Remaining new categories**, in this order, each in its own worktree with its own branch:
   - **N3 double fetch** — a ready-to-use handoff prompt is at
     `/tmp/codex-out/doublefetch-n3-prompt.md` (regenerate it into `docs/` if `/tmp` is gone).
     Verified distinct from the existing `toctou_techniques.py`, which is *filesystem-path*
     TOCTOU: its docstring says "the entire payload is a *filename*", and `corpus_toctou` is
     all path-swap variants. N3 is a race on a **memory** value between a validation read and a
     use read. A lost race is **INCONCLUSIVE, not a failure** — this matters more here than
     anywhere else in the repo.
   - **N2 stack clash** — the riskiest; may not be made deterministic. Report a null result
     plainly rather than forcing it. Target must be built `-fno-stack-clash-protection`.
   - Plan for both: `docs/plans/2026-09-28-three-new-categories-plan.md`.

### Traps that have already cost real time in this project

- **`codex exec` cannot commit.** Its `workspace-write` sandbox mounts git metadata read-only,
  so `git commit` *and* `git add` die with `index.lock: Read-only file system`. Expect an
  uncommitted tree after every codex handoff and commit it yourself with explicit pathspecs
  (`git add` new files first). Ask codex for a file-by-file change list, never commit hashes.
- **The codex binary is `/home/net0ruser/.local/bin/codex`**, NOT the `/home/jay/...` path in
  the `llm-bridge` skill (that user does not exist here). A wrong path produces **exit 0 with
  no output file**, which looks exactly like a clean completed run. After every launch assert
  codex is alive: `pgrep -af 'codex exec'` plus an `OpenAI Codex v…`/`workdir:` banner in the log.
- **Always launch codex with `< /dev/null`** or it blocks forever on stdin. Launch under
  `setsid nohup … &` so a group SIGTERM (exit 143) can't kill it mid-run.
- **Never make a delegate re-measure a baseline it can inherit** — hand it the numbers plus the
  one-line proof they apply, and state the order of work (implement first, targeted tests while
  iterating, no full suite). One handoff spent its entire budget on the baseline suite and wrote
  zero code. Also tell it **not** to run the full suite: the sandbox blocks sockets, ptrace/GDB
  and core files, so its failure counts are unusable.
- **Worktrees do not carry gitignored artifacts.** Corpus ELFs and `flag.txt` exist only where
  they were built, so a sprint that must test against existing corpus binaries has to run in the
  **main checkout**. Only give a worktree to a sprint that builds its own fixtures.
  `benchmark/build_all.sh` iterates `"$CORPUS"/*/` and writes `flag.txt` itself, so
  `CORPUS=benchmark/corpus_<family>` rebuilds a family from tracked sources.
- **`git commit` commits the index** — in a tree another agent may touch, always
  `git commit -- <explicit paths>`.
- **Run solves from the target's own directory** — the binaries read `./flag.txt` relative to cwd:
  `cd benchmark/corpus_r2/09_… && PYTHONPATH=/srv/share/dev/supwngo python3 -m supwngo.cli solve ./<bin> --no-legacy --json`
- **`pytest --timeout=900` is rejected by this repo's config (exit 4).** Use `pytest tests/ -q`.
- **`Binary(path)` is lazy** and yields 0 symbols — use `Binary.load(path)`.
- **Two tests read `CHANGELOG.md`** (`test_version_consistency.py`, `test_context_resolve_golden.py`),
  so don't edit it while a suite you are measuring is running.
- **Grep artifacts:** changelog/doc prose wraps, so a single-line pattern can return 0 for text
  that is present. Never let a narrow grep carry a broad negative.
- **`FLAG_CAPTURED` is a legitimate terminal verification level** (`supwngo/exploit/verification.py`);
  several executors top out there by design. Do not contort a target to reach a shell.

### Deferred items (logged, not blocking)

- `pie_base_offset()` (`supwngo/exploit/pipeline/executors/rop_techniques.py`) still iterates all
  symbols, lacks the `low12 == 0` degenerate guard, and returns `matches[0]` with no cross-anchor
  corroboration. The equivalent defects were fixed in `pipeline/volunteered_leaks.py` (commit
  `bdfbf76`) with RED-first tests; the same treatment is owed here. Codex's F2 work may have
  partly addressed it — check before rebuilding.
- `uaf` category is PARTIAL-only (G-25).
- Three tracked corpus YAMLs record captured flags in evidence comments
  (`corpus_uafread.yaml:396`, `corpus_offbyone.yaml:462`, `corpus_libhijack.yaml:260`) — measured
  NOT live, awaiting a decision on whether to rewrite history.
- `subprocess_injection` costs ~72.9 s per menu target.
- 7 of 9 round-1 targets never had their flag-literal oracle individually controlled.
