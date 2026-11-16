# OUTBRIEF — W-3 (success detection) — retire class-C platform patterns

**Date:** 15NOV2026
**Branch:** `feat/w3-success-oracle`
**Directive:** W (retire hardcoded target values), phase W-3
**Host:** wks0 (dev moved off net0srv to spare the shared server)
**Design:** `docs/plans/2026-11-15-w3-success-detection-design.md` (reviewed; all
Codex findings resolved across 4 revisions)

## What W-3 delivers

Product success/flag detection no longer depends on **platform-specific
patterns** (`htb{…}`, `flag{`, `picoctf`, `csaw`, `asis`, …). Every site that
decided "did the exploit succeed?" or "is this a flag?" now routes through a
single **success oracle** with three ordered evidence tiers:

1. **PLANTED** — a fresh ≥128-bit `secrets.token_hex(16)` marker we put in the
   target and look for in the output (never sent to the target). Highest trust.
2. **SHELL-PROVEN** — a response only a real shell produces: `strict_probe`
   (`echo <tok>_STRICT`), `ARITH_PROBE` (`echo SH$((6*7))OK` → `SH42OK`), or a
   `uid=` from `id`.
3. **SHAPE** — a neutral, platform-free flag shape
   (`([A-Za-z0-9_]+)\{[^}\s]{4,}\}`), overridable per-run via `SUPWNGO_FLAG_RE`.

An **anti-echo** rule filters any candidate match that also appears in the bytes
we sent, *before* tier ranking — so echoing our own probe back never counts as
success. The single behaviour change (design §3 R1): an echoed-token-only run
loses its success credit (level `NONE`, `success=False`) while still recording
`shell_confirmed` / `echo_ambiguous` diagnostics.

**Import topology (hard rule, enforced by test):** `success_oracle.py` imports
**only stdlib**; consumers import it, never the reverse.

## Scope closed

- **54 class-C baseline entries → all `migrated` (phase W-3), 0 `allowed`.**
  Final baseline: 54 migrated / 27 allowed (W-2 class-B) / 76 open.
- **Tree-wide platform-token lint** (`scripts/check_platform_tokens.py`) over all
  of `supwngo/` is now a **test gate**: no platform token in any non-comment
  product string (docstrings/comments may still name a platform).

## How it was built — integration of 5 parallel batches + 2 gate steps

Executed as disjoint-file batches in separate worktrees (Fable), integrated by
cherry-pick onto `feat/w3-success-oracle`, ratchet green after each:

| commit | step / batch | surface |
|--------|--------------|---------|
| `e23beb0` | step 1 | pure-stdlib `success_oracle.py` + scanner exemption |
| `c628312` | step 2 | platform-token lint + fixture self-tests |
| `7d9f54e` | batch 1 | `verification.py`, `pipeline/verifier.py`, `tester.py` |
| `7a68ae1` | batch 5 | `analysis/strings.py`, `walkthrough/facts.py` static helpers |
| `d383369` | batch 2 | `auto.py`, `enhanced_auto.py`, `offset_finder.py`, heap/bypass executor (24 sites) |
| `cb8dd15` | batch 3 | canary/fmtstr/heapuafread/input_shape/loop_counter executors + `remote/interaction.py` (8 sites) |
| `eea160f` | batch 4 | oob_read/weak_prng/path_traversal/symlink_write/toctou G-script emitters + `kernel/templates.py` |
| `cf186a4` | step 4 | class-C closure gate + tree-wide lint gate |

**Run-context taxonomy** used to pick the integration per site: **L** (local,
in-process `check()`), **R** (remote/unknown), **S** (static/reporting), **G**
(generated-script text — cannot import the oracle, so it emits a self-contained
snippet via `emit_flag_match_snippet()`, with no literal flag shape by
construction).

**Echo-foolable probes replaced** (credited only on `TIER_SHELL`): W-0018
(`echo PWNED`), W-0153 (`get_shell`), weak_prng — each now uses id/strict/arith
probes.

## New gates, each proven to bite

- `test_w3_inventory_closure` — pins 54 class-C entries all `migrated`/`phase
  W-3`, 0 `open`, 0 `allowed`. **Proven RED** by reopening one entry.
- `test_product_tree_has_no_platform_tokens` — tree-wide lint over `supwngo/`.
  **Proven RED** by planting `flag{planted}` in a product string.
- `test_oracle_imports_no_supwngo_module` — stdlib-only topology (from step 1).
- One lingering platform word in a `heap_strlen_ofb1` generated-script comment
  (`"the HTB shape prints"` → `"the target shape prints"`) was neutralised so the
  tree-wide gate is green; no product behaviour change.

## Gate

- **Integrated W-3 suite** (oracle, lint, inventory ratchet, batch seam tests,
  executor regressions): **162 passed / 60 skipped**. All 23 W-3-touched modules
  import clean (no oracle import cycle).
- **Full ordinary suite** (wks0, no Ghidra env, 12m): **2721 passed / 13 failed /
  784 skipped / 4 errors.**
- **Full gate** (wks0, `GHIDRA_HOME` set + `SUPWNGO_REQUIRE_GHIDRA=1`, 12m):
  **2737 passed / 17 failed / 764 skipped / 4 errors.** The gate un-skips the
  Ghidra tool-tier tests; the +4 vs the ordinary run are the W-2
  `test_ret2win_required_args::test_t12_e2e_win_reached_with_each_param_set`
  variants (arg1/arg3 × stripped/unstripped) failing on the **unbuilt payoff
  corpus** (`FileNotFoundError: benchmark/gen/payoff/build/index.json`) — **the
  identical failure on `main` (67a496c)**.
- **W-3 success path validated on real binaries.** After building the dev corpus
  (`generate.py --set dev --no-pe`, 101 ELF binaries), the full
  `test_ret2win_required_args.py` goes **green under the gate** — the ret2win
  solve reaches verified success through the **new oracle** on real Ghidra-
  analysed, stripped/unstripped binaries. This is the one place W-3 could have
  regressed (Batch 1 rerouted ret2win success); it does not.

**Every one of the 17 failed + 4 errors is pre-existing and environmental, with
an identical node set on `main` (67a496c)** — none is a W-3 assertion:

| category | nodes | cause (verified) |
|----------|-------|------------------|
| payoff corpus not built | `test_ret2win_required_args` e2e ×4 | pass once corpus built |
| `gets()` removed from glibc | `test_solve_command` e2e ×3 | gcc hard-errors on the fixture's `gets()` (host toolchain); same on main |
| hand-curated `benchmark/corpus/*` not built | `test_cli_autopwn_json_wiring` ×3, `test_ret2plt_runtime_string` ×2, `test_binary_load_state`, `test_walkthrough_heap_strlen` | missing fixture binaries |
| corpus not built (setup error) | `test_variable_overwrite_budget` ×4 errors | missing fixture binaries |
| libc-2.41 fsop gate | `test_fsop_executor` ×1 | environmental |
| sandbox under load | `test_sandbox` ×1 | timing/environmental |
| MinGW PE nondeterminism | `test_payoff_corpus::test_same_seed` ×1 | `--no-insert-timestamp` still non-reproducible PE header |

**W-3 introduces no new failures vs main.**

## Shipping

Per the standing instruction (push/PR/merge/delete when done, then continue the
roadmap): once the full gate is confirmed at parity with main, merge
`feat/w3-success-oracle` as a merge commit, delete the branch
(remote/local/worktree), pull main into the primary working copy, then begin
**W-4** (dynamic sandboxed runner / PLANTED universal).
