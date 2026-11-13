# SP-01a pre-fix baseline — S0 passcard on `992986e` (2026-11-13)

Checklist item **1a.5** (`docs/plans/2026-11-12-session-goals-checklist.md` §2). This is the reference
that SP-01b's post-fix run (`passcard-s0-post-sp01`) is compared against. It was committed before any
SP-01b code landed.

**Verdict: VALID, ACCEPTED.** Control cell PASS, isolation `bwrap`, time quorum met.

Artefacts (generated, not edited):

| file | sha256 |
|---|---|
| `benchmark/baselines/passcard-s0-pre-sp01.json` | `0707e7b044162a1c7f478b6a8ce84ece56feebcff8b795e88bc5682374a5e356` |
| `benchmark/baselines/passcard-s0-pre-sp01.md` | `70053209c4c8d3d6739aab48a82b8c0ad85a39412f645567568144d46bce37c2` |
| `benchmark/baselines/solve-hyp9-278c0e8.json` | `69f112568f579870e93c2d72993d4bafa807763d3322ef7c64ebc482c1cea44b` |

## 1. Run record

- Code under test: `992986e` (main after PR #34), `git_dirty: false`.
- Command, from the main checkout:
  `SUPWNGO_GHIDRA_TIMEOUT=600 python3 -B benchmark/passcard.py --reps 3 --timeout 1500
  --solve-artifact benchmark/baselines/solve-hyp9-278c0e8.json --solve-commit 278c0e8
  --solve-command "python3 -B scripts/htb_rescore.py --reps 3 --timeout 300"
  --solve-cwd-convention "each rep in a throwaway copy of the challenge directory"
  --out benchmark/baselines/passcard-s0-pre-sp01`, with `ulimit -S -c 0`.
- Isolation: requested `auto`, backend `bwrap`, all four self-check probes true, subreaper on. Observed
  isolation over every cell: `bwrap` only.
- Control cell (V-2): PASS in 23.6 s at load1 24.4; the output hash matches the pinned expectation.
- Host load (1/5/15 min): 24.4/26.1/32.2 at the start, 63.4/52.5/45.9 at the end. The host is shared,
  and three SP-01b lane agents were running targeted test suites in their own worktrees during the run.
- The cell environment passes `SUPWNGO_GHIDRA_TIMEOUT=600` and `JAVA_TOOL_OPTIONS=-Duser.home=/tmp/cell/home`
  through. Both are recorded in the header (`env_passthrough`).
- Solve column (HYP-9): ingested from `solve-hyp9-278c0e8.json`, which is `htb_rescore --reps 3` at
  `278c0e8`. Score 7/7, and every rep is `SHELL_ACCESS` with `shell_proven: true`.

### 1.1 First attempt: INVALID (kept out of tree)

The first attempt, started 10:28 UTC, was **INVALID**: `control_failed: analysis_backend:angr,
code_empty_or_sentinel, anchor_missing:puts`.

- Ghidra on the control fixture hit the 600 s limit (cell wall 636.8 s) and the CLI fell back to angr.
- The next Ghidra cell, `sick_rop-decompile-r1`, also ran to the limit (609 s) at load1 69.9.
- Later decompile cells took 30–140 s.
- Load on the 32-core host peaked at about 70. That was when the lane agents' test runs started.

The control gate did what it is for: it voided a run whose decompile column measured host contention
rather than the product. Its per-target matrix was identical to the accepted run, and only TIME
differed. The INVALID artefacts are kept outside the repository in `/var/tmp/sp01a-solve/invalid-run-1/`.

The accepted re-run started at 11:45 UTC, after the load had fallen to about 24.

## 2. Results

### S0 (7 ELF targets)

| metric | n | PASS | FAIL | ABSTAIN | ERROR | VOID | coverage | exact | selective | net |
|---|---|---|---|---|---|---|---|---|---|---|
| METHOD-R0 | 7 | 2 | 5 | 0 | 0 | 0 | 1.00 | 0.29 | 0.29 | -0.43 |
| METHOD-L | 7 | 3 | 4 | 0 | 0 | 0 | 1.00 | 0.43 | 0.43 | -0.14 |
| TEMPLATE | 7 | 2 | 5 | 0 | 0 | 0 | 1.00 | 0.29 | 0.29 | -0.43 |
| OFF | 8 | 2 | 0 | 2 | 0 | 4 | 0.25 | 0.25 | 1.00 | 0.25 |
| DECOMP | 7 | 2 | 4 | 1 | 0 | 0 | 0.86 | 0.29 | 0.33 | -0.29 |
| ROBUST | 28 | 22 | 6 | 0 | 0 | 0 | 1.00 | 0.79 | 0.79 | 0.57 |

### S0-PE (2 PE fixtures; DECOMP and ROBUST only)

| metric | n | PASS | FAIL | ABSTAIN | ERROR | VOID | coverage | exact | selective | net |
|---|---|---|---|---|---|---|---|---|---|---|
| DECOMP | 2 | 1 | 0 | 1 | 0 | 0 | 0.50 | 0.50 | 1.00 | 0.50 |
| ROBUST | 8 | 5 | 3 | 0 | 0 | 0 | 1.00 | 0.62 | 0.62 | 0.25 |

### TIME

| command | samples | median wall s | max wall s | median load1 |
|---|---|---|---|---|
| pwn | 27/27 | 7.08 | 35.08 | 43.48 |
| template | 27/27 | 2.79 | 17.64 | 42.81 |
| decompile | 27/27 | 32.66 | 148.32 | 40.72 |
| offset | 27/27 | 1.90 | 103.99 | 43.04 |

The per-target matrix and the full cell notes are in `passcard-s0-pre-sp01.md`.

## 3. Reconciliation with earlier numbers

| measure | SCORECARD (`1741b34`) | AMD-1 verify pass | this baseline | why it differs |
|---|---|---|---|---|
| method (top-1) | 2/7 | 2/7 reproduced | METHOD-R0 2/7 | Same. |
| `template -t auto` | constant `ret2system` 7/7 | reproduced | TEMPLATE 2/7 | TEMPLATE scores the method against truth. A constant answer is right only where truth agrees. |
| offset | 0/7, one crash | 2 of 3 valid stack-return cells | OFF 2 PASS, 2 ABSTAIN, 4 VOID | Same as AMD-1. The passcard scores per (target, kind), and the VOIDs are explained below. The SCORECARD crash was a repo-root run artefact (AMD-1). |
| decompile | 3/7 | 5/7 | DECOMP 2/7 | AMD-1 counted real pseudo-C. DECOMP also checks the reported address against truth, and three PIE targets fail only on the address (V-10). |
| ROBUST | — | 28/28 single documents, all exit 0 | 22/28 | The passcard requires a legal (exit code, envelope) pair. The six failures are failure documents that exit 0. |

## 4. Failure classification and owning fix

Every non-PASS cell is listed below with the item that owns it. The SP-01b items are in checklist §3.
Method and template failures are out of SP-01b's scope by design.

### ROBUST — 6 S0 and 3 S0-PE failures; all are SP-01b

- **`offset` failure documents exit 0** (`rc_envelope:0/unrecognised`):
  - S0: snow_scan, ancient_interface, auth-or-out, sabotage and bon-nie-appetit.
  - S0-PE: pe_sym and pe_strip.
  - The pre-fix document has `success: false`, no `error_code`, and exit 0.
  - Owner: **1b.1** (`offset --json` exits 2 with a typed `error_code`). For PE, **1b.5** (`unsupported_format`).
- **`decompile` failure documents exit 0** (`rc_envelope:0/failure`): sick_rop and pe_strip.
  - The pre-fix document is `{"error": "Decompilation failed", "analysis_backend": "angr"}` with exit 0.
  - Owners: **1b.7** (structured Ghidra result, exit 2 on failure) and **1b.4** (default function
    selection when there is no `main`).

### DECOMP — 4 S0 FAIL, 1 S0 ABSTAIN, 1 S0-PE ABSTAIN

- **Address only**, on auth-or-out, sabotage and bon-nie-appetit.
  - All three are PIE.
  - Ghidra returns real pseudo-C, but reports the address at its own image base. For example, `main` on
    auth-or-out is reported at `0x101971`, while truth is file-relative.
  - Owner: **1b.6** (V-10 address normalisation).
- **Ghidra fell back, then the angr sentinel**, on ancient_interface (`empty_or_sentinel`,
  `anchors_missing:read,strcmp`, `min_calls`).
  - Ghidra returned no usable result: every rep finished in about 31–34 s, far below the 600 s limit, so
    this is not a timeout. The pre-fix CLI logs no reason.
  - The angr fallback then returned `// Decompilation failed for main`, with exit 0.
  - Owners: **1b.7** (V-11, so that the Ghidra failure reason becomes visible) and **1b.2** (V-7, angr
    `normalize=True`, so that the fallback returns code).
- **No `main`** gives sick_rop ABSTAIN and pe_strip ABSTAIN.
  - sick_rop is a static binary with no `main` symbol, and pe_strip is a stripped PE.
  - Owner: **1b.4** (V-9: ELF default selection, and the PE order main → `mingw_crt_main_arg` → entry).
  - The pe_strip cut line is recorded in the checklist's Done-when.

### OFF — 2 ABSTAIN and 4 VOID

- **ABSTAIN** on both of ancient_interface's kinds (`buf_to_ret` and `buf_to_canary`).
  - `offset` declines after about 99 s on an interactive target.
  - Owner: **1b.1**. After the fix it is expected to end in a typed `timeout` error with exit 2. The cell
    would then stay ABSTAIN, and its ROBUST cell would pass.
- **VOID `no-truth`** on snow_scan/`indexed_base_ptr` and auth-or-out/`record_to_fnptr`.
  - The S0 truth deliberately pins no integer for these kinds.
  - This is not a product failure.
- **VOID `interp_empty`** on sabotage/`buf_to_var` and bon-nie-appetit/`chunk_to_next_size`.
  - The shipped loader files are 0 bytes, so neither target can run on this host (preflight, §3.5).
  - Owner: none; the VOID is the correct verdict.

### METHOD-R0, METHOD-L and TEMPLATE — not SP-01b

- **`rop_syscall` is ranked first** on rocket_blaster_xxx, auth-or-out, sabotage and bon-nie-appetit.
- **sick_rop** is ranked `stack_pivot` (and `data_only`), not SROP.
- **TEMPLATE** emits `ret2libc` on five targets. TEMPLATE v0 trusts the `technique` field.
- Owners:
  - **SP-02b**: `rax`-control evidence, SROP and `rop_syscall` gating, role tiering, and an honest
    `template`.
  - **SP-04b**, now pulled forward by directive W: name-free payoff selection.

## 5. What SP-01b is expected to move

These follow from the checklist §3 Done-when; they are criteria, not predictions.

- **ROBUST.**
  - All 14 S0 `offset`/`decompile` cells pass.
  - S0-PE reaches 8/8: `pe_sym` and `pe_strip` `offset` refuse with `unsupported_format` and exit 2.
- **DECOMP.** The three address-only FAILs become PASS (V-10). ancient_interface becomes PASS, or an
  honest failure with exit 2 and a named Ghidra reason.
- **`offset --json`** reports `isolation: "bwrap"` under the passcard.
- **Unchanged by design:** METHOD-R0, METHOD-L, TEMPLATE, and the OFF VOIDs.

## 6. Notes

- **Leftover temp directories.** The `container_file_rop` script that the HYP-9 solve run generates
  leaves `supwngo_container_*` directories in the challenge-copy working directory
  (`supwngo/exploit/pipeline/executors/container_file_techniques.py:838`). The `htb_rescore` run at
  `278c0e8` left three in `/var/tmp/sp01a-solve`. The passcard cells are not affected, because they never
  run the generated scripts. This is recorded as a minor follow-up, not an SP-01b item.
- **The Ghidra timeout setting is load-sensitive.** On this shared host, a 600 s budget passed every
  Ghidra cell at load about 24–45 and failed two at load about 27–70. Directive W's dynamic tier
  (W-4) inherits the same exposure. Its budgets (K/T) and cache must be sized against this, not against
  a quiet host.
