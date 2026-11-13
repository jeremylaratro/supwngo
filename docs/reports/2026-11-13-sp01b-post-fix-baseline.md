# SP-01b post-fix baseline — S0 passcard on `11e80b3` (2026-11-13)

Checklist item **1b.10** (`docs/plans/2026-11-12-session-goals-checklist.md` §3). This is the post-fix
run that closes SP-01b, measured against the pre-fix baseline
(`docs/reports/2026-11-13-sp01a-pre-fix-baseline.md`, `992986e`). It was generated on the SP-01b
integration branch `fix/sp01b-honesty` at `11e80b3`.

**Verdict: VALID, ACCEPTED.** Control cell PASS, isolation `bwrap`, time quorum met. Every SP-01b
Done-when item holds.

Artefacts (generated, not edited):

| file | sha256 |
|---|---|
| `benchmark/baselines/passcard-s0-post-sp01.json` | `bef2d97cbfbc086c6f8c1ad3cd3ded2923463fddde7122ffee79d5ef29047fd2` |
| `benchmark/baselines/passcard-s0-post-sp01.md` | `ee314ec57a025176273f9df186e26a8f33571de3875abb33c88e2c30d9f3b804` |

## 1. Run record

- Code under test: `11e80b3` (`fix/sp01b-honesty`), `git_dirty: false`.
- Command, from the main checkout, with `ulimit -S -c 0`:
  `SUPWNGO_GHIDRA_TIMEOUT=600 python3 -B benchmark/passcard.py --reps 3 --timeout 1500
  --solve-artifact benchmark/baselines/solve-hyp9-278c0e8.json --solve-commit 278c0e8
  --solve-command "python3 -B scripts/htb_rescore.py --reps 3 --timeout 300"
  --solve-cwd-convention "each rep in a throwaway copy of the challenge directory"
  --out benchmark/baselines/passcard-s0-post-sp01`.
- Started 17:22 UTC. Toolchain: Ghidra 12.1.3, pwntools 4.15.0, angr 9.2.213.
- Isolation: requested `auto`, backend `bwrap`, self-check available. Observed isolation over every
  cell: `bwrap` only.
- Control cell (V-2): PASS in 19.4 s at load1 2.6; output sha256
  `ad1c6fee…` matches the pinned expectation. The control decompile JSON now carries `selected_by: name`.
- Host load (1/5/15 min): 2.6/3.1/2.4 at the start, 32.7/31.3/20.6 at the end. The host was quiet at
  launch (the end-of-run rise is the solve column's own exploit executors, inside the cells). No other
  heavy job ran during the control or the decompile cells.
- Solve column (HYP-9): ingested from the pinned `solve-hyp9-278c0e8.json` (`278c0e8`), score 7/7, every
  rep `SHELL_ACCESS` with `shell_proven: true`. A fresh live `htb_rescore --reps 3` on `11e80b3`
  independently reproduced 7/7 and 21/21 `shell_proven` (§4, `solve`).

## 2. Results

### S0 (7 ELF targets)

| metric | n | PASS | FAIL | ABSTAIN | ERROR | VOID | coverage | exact | selective | net |
|---|---|---|---|---|---|---|---|---|---|---|
| METHOD-R0 | 7 | 2 | 5 | 0 | 0 | 0 | 1.00 | 0.29 | 0.29 | -0.43 |
| METHOD-L | 7 | 3 | 4 | 0 | 0 | 0 | 1.00 | 0.43 | 0.43 | -0.14 |
| TEMPLATE | 7 | 2 | 5 | 0 | 0 | 0 | 1.00 | 0.29 | 0.29 | -0.43 |
| OFF | 8 | 2 | 0 | 2 | 0 | 4 | 0.25 | 0.25 | 1.00 | 0.25 |
| DECOMP | 7 | 7 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |
| ROBUST | 28 | 28 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |

### S0-PE (2 PE fixtures; DECOMP and ROBUST only)

| metric | n | PASS | FAIL | ABSTAIN | ERROR | VOID | coverage | exact | selective | net |
|---|---|---|---|---|---|---|---|---|---|---|
| DECOMP | 2 | 2 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |
| ROBUST | 8 | 8 | 0 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 |

Both PE fixtures preflight as `unsupported_format` (the `pwn`/`template`/`offset` refusal path), and DECOMP
on each is a PASS (`pe_sym` by symbol, `pe_strip` via the `mingw_crt_main_arg` start-call recovery).

### TIME

| command | samples | median wall s | max wall s | median load1 |
|---|---|---|---|---|
| pwn | 27/27 | 4.78 | 35.26 | 5.10 |
| template | 27/27 | 2.39 | 17.10 | 4.62 |
| decompile | 27/27 | 38.05 | 105.16 | 4.72 |
| offset | 27/27 | 2.25 | 38.48 | 4.44 |

The per-target matrix and the full cell notes are in `passcard-s0-post-sp01.md`.

## 3. Per-metric delta vs the pre-fix baseline (`992986e`)

| metric | pre-fix | post-fix | delta | owner |
|---|---|---|---|---|
| DECOMP (S0) | 2 PASS / 4 FAIL / 1 ABSTAIN, net −0.29 | **7 PASS**, net **1.00** | +5 PASS | 1b.2, 1b.4, 1b.6, 1b.7 |
| ROBUST (S0) | 22 PASS / 6 FAIL, net 0.57 | **28 PASS**, net **1.00** | +6 PASS | 1b.1, 1b.4, 1b.7 |
| DECOMP (S0-PE) | 1 PASS / 1 ABSTAIN, net 0.50 | **2 PASS**, net **1.00** | +1 PASS | 1b.4 |
| ROBUST (S0-PE) | 5 PASS / 3 FAIL, net 0.25 | **8 PASS**, net **1.00** | +3 PASS | 1b.1, 1b.5 |
| OFF | 2 PASS / 2 ABSTAIN / 4 VOID | 2 PASS / 2 ABSTAIN / 4 VOID | unchanged | by design |
| METHOD-R0 / METHOD-L / TEMPLATE | 2/7, 3/7, 2/7 | 2/7, 3/7, 2/7 | unchanged | SP-02b / SP-04b |

What moved, and why:

- **The three PIE address-only DECOMP FAILs** (auth-or-out, sabotage, bon-nie-appetit) are PASS. V-10
  address normalisation (`rva = addr − backend_base`, `address = file_base + rva`) now makes both backends
  report the file-relative address (1b.6).
- **ancient_interface DECOMP** is PASS: `CFGFast(normalize=True)` makes the angr fallback return real code,
  and the structured Ghidra runner surfaces its reason instead of silently discarding the result
  (1b.2, 1b.7).
- **sick_rop and pe_strip DECOMP** are PASS: default-function selection now falls to the entry function
  (ELF, no `main`) and to the `mingw_crt_main_arg` start-call for the stripped PE (1b.4).
- **The six S0 and three S0-PE ROBUST FAILs** are PASS: `offset` and `decompile` failure documents now exit
  2 with a typed `error_code` (and PE refusals carry `unsupported_format`), so every cell is a legal
  (exit code, envelope) pair (1b.1, 1b.5, 1b.7).
- **OFF, METHOD and TEMPLATE are unchanged by design.** The two OFF ABSTAINs (ancient_interface) and four
  VOIDs (two `no-truth`, two `interp_empty`) are the correct verdicts, not product failures. METHOD and
  TEMPLATE are owned by SP-02b and SP-04b.

## 4. Done-when verification (checklist §3, SP-01b)

| criterion | result |
|---|---|
| ROBUST passes on all 14 S0 `offset`/`decompile` cells; no sentinel scores as success | **met** — 28/28 S0 ROBUST |
| `offset --json` isolation is `bwrap`/`outer` under the passcard, `bwrap` direct | **met** — `bwrap` on every cell and direct |
| RELRO: RET2DLRESOLVE on 0 Full-RELRO S0 targets (readelf-counted) | **met** — offered only on ancient_interface (Partial, dynamic) |
| Decompile fixtures pass under `SUPWNGO_REQUIRE_GHIDRA=1` (ELF + PE default-function) | **met** — 180 passed, 1 skipped (angr/PE name case) |
| PE: `pwn`/`template`/`offset` give `unsupported_format` exit 2 on both fixtures | **met** |
| Addresses: both backends report the same normalised address; ELF-PIE, ET_EXEC, PE32+ oracles pass | **met** |
| S0-PE: 8/8 ROBUST, `pe_sym` and `pe_strip` DECOMP PASS | **met** — 2/2 DECOMP, 8/8 ROBUST |
| `solve`: `htb_rescore --reps 3` at 7/7 with 21/21 `shell_proven` | **met** — fresh run on `11e80b3`: 7/7, 21/21 |
| Unit suite: no new genuine failures vs the pre-branch run | **met** — the one lane-interaction failure was the test fake, fixed in `11e80b3` |

The live `htb_rescore --reps 3` on `11e80b3` recorded SHELL_ACCESS on all seven targets for every rep:
ancient_interface (`eintr_accumulator_rop`), auth-or-out (`objptr_hijack`), bon-nie-appetit
(`heap_strlen_ofb1`), rocket_blaster_xxx (`ret2libc_leak`), sabotage (`env_path_hijack`), sick_rop
(`srop_symtab_pivot`), snow_scan (`container_file_rop`).

## 5. Notes

- **Leftover temp directories.** The live `htb_rescore` run left three `supwngo_container_*` directories in
  its scratch area (`/var/tmp/sp01a-solve`), from the snow_scan `container_file_rop` executor
  (`supwngo/exploit/pipeline/executors/container_file_techniques.py`). They are outside the repository, so
  they do not touch git; this is the minor follow-up already recorded in the pre-fix report §6, not an
  SP-01b item. The passcard cells themselves never run the generated scripts and leave nothing behind.
- **Load.** The run launched on a quiet host (load1 2.6) and the control and all Ghidra decompile cells
  completed well under the 600 s budget (decompile max 105 s). This is the valid-window counterpart to the
  pre-fix report's §1.1, where a contended first attempt was correctly voided.
- **One pre-existing flaky unit test (not SP-01b).** The full unit suite on `11e80b3` was 1 failed, 3144
  passed, 37 skipped. The single failure was
  `tests/test_walkthrough_fmtstr.py::test_every_read_step_runs_and_reports_its_own_observation[5]`, the
  walkthrough step that confirms the canary overflow boundary by sending `SMASH_OFFSET` then
  `SMASH_OFFSET + 1` (72 then 73) bytes to a live process and reading back the abort message with
  `recvall(timeout=3)`. It is an intermittent race, not a logic break: it failed pass/fail/fail in three
  isolated re-runs on this tree, and — decisively — it also flakes on `main` (`d8d0c5b`, no SP-01b code):
  pass/pass/pass/fail over four isolated runs. The step-5 code path (the test, the
  `walkthrough/families/fmtstr.py` generator, and the corpus `.c`) is byte-identical between `main` and
  `11e80b3`; the one SP-01b change in the walkthrough module (`walkthrough/facts.py`) touches only RELRO
  derivation and provenance text, and RELRO does not appear in the rendered step-5 smash-probe region.
  The failure is therefore a pre-existing flaky test, independent of SP-01b, and is logged as a minor
  follow-up (harden the abort-message capture, e.g. a longer or retried `recvall`), not an SP-01b item.
  The Done-when "no new genuine failures vs the pre-branch run" holds.
