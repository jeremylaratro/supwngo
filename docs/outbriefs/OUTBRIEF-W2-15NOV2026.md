# OUTBRIEF — W-2 (required-args) ship + payoff-corpus test reconciliation

**Date:** 15NOV2026
**Branch:** `feat/w2-required-args` → PR #41
**Directive:** W (retire hardcoded target values), phase W-2
**Host:** wks0 (dev moved off net0srv to spare the shared server)

## What W-2 delivers

The `ret2win` technique now takes a win function's required arguments from a
Ghidra P-code analysis of the binary (RVA-keyed `required_args` /
`args_status` / `args_reason`, cache envelope v2) instead of a regex scan over a
guessed constant list. The executor abstains before delivery on `unknown`, an
RVA miss, an unsupported register, or a missing pop gadget; the legacy scan is
used only when no authoritative report exists. Class-B inventory: the 27 ABI
class-B entries are closed. (Full detail in `CHANGELOG.md` → Unreleased, and
`docs/plans/2026-11-13-w2-required-args-design.md`.)

## The regression this outbrief records, and its fix

Running the **full** test suite on wks0 surfaced a W-2-introduced regression in
`tests/test_payoff_corpus.py` (6 failing nodes). Root cause: the W-2 payoff
generator deliberately added a **reduced-schema** set of corpus entries, and the
universal invariant tests assumed every entry carried the full standard schema.

Corpus taxonomy (dev set):

| class | marker | count | reduced keys |
|-------|--------|-------|--------------|
| standard (pos/neg + strip/rename twins) | `role` absent | 72 (+8 PE) | — (full schema) |
| falsifiers | `role: "falsifier"` (ids `fal-*`) | 27 | no `decoys` |
| fixtures | `role: "fixture"` (ids `fix-*`) | 3 | no `decoys`, `image_base`, `payoff_rva`, `payoff_vaddr`; fixed seed |

Five invariant tests broke on the reduced entries (KeyError / assertion):
required-keys, symbol-table, function-RVA, decoys-and-references, forbidden-token,
and the same-seed file-count check.

**Fix (test-only — the generator is correct and unchanged):**
- **required-keys:** per-role required set — drop `decoys` for falsifiers; drop
  `decoys`/`image_base`/`payoff_*` for fixtures; allow the fixtures' fixed seed.
- **symbol-table + function-RVA:** skip any role-bearing (special) entry — they
  carry no `functions` answer key.
- **decoys-and-references:** tolerate a missing `symbols_present` via `.get`.
- **forbidden-token:** keep scanning falsifier/fixture generated `names` (the
  security-relevant check) but default `renames` to `{}`.
- **same-seed:** derive the expected source-file count from the corpus structure
  (`len({t["source"] …})`) instead of the hardcoded `40`, so it is robust to the
  falsifier/fixture sources and to `--no-pe`.

Discriminator used: `truth.get("role")` is set for every special entry (both
falsifier base **and** its `falsifier_strip_twin`, and fixtures); standard
entries have no `role`.

Commit: `35156f9 test(w2): reconcile payoff invariants with fal-/fix- reduced schema`.

## Known pre-existing issue (NOT a W-2 regression — out of scope)

`test_same_seed_gives_identical_sources_truth_and_binaries` still fails its
byte-identity check on the **PE** binaries (first diff at byte ~136). This is
MinGW PE build nondeterminism: `x86_64-w64-mingw32-gcc` emits a differing header
field (around the COFF `TimeDateStamp`) on back-to-back builds **even with**
`-Wl,--no-insert-timestamp`, which the generator already passes. Verified
empirically (two identical compiles differ at byte 137) and confirmed the same
failure exists on `main` (5ad294c) when MinGW is installed — so it is
environmental and pre-existing, not introduced by W-2. Left for a separate,
scoped follow-up (e.g. exclude PE from the byte-identity assertion, or build PE
reproducibly); folding it into W-2 would be scope creep on a determinism
guarantee.

## Gate

- `tests/test_payoff_corpus.py`: **22 passed / 1 failed** (the failure is the
  pre-existing PE flake above) — parity with `main`, no new failures.
- Full suite (wks0, `SUPWNGO_REQUIRE_GHIDRA=1`, 48m): **2845 passed / 13 failed
  / 743 skipped / 4 errors** (down from 18 failed / 4 errors pre-fix — the 5
  payoff regressions are closed). The remaining **13 failed + 4 errors are an
  identical node set on `main` (5ad294c)** — re-running exactly those 17 nodes on
  main reproduces the same 13 failed + 4 errors — so they are pre-existing and
  environmental (uncompiled `benchmark/corpus/*` binaries, the libc-2.41 fsop
  gate, sandbox-under-load, and the MinGW PE flake above). **W-2 introduces no
  new failures vs main.**

## Shipping

Per the standing instruction (push/PR/merge/delete when done, then continue the
roadmap): merge PR #41 as a merge commit once the gate is confirmed at parity
with main, delete the branch (remote/local/worktree), pull main into the primary
working copy, then begin W-3 (`feat/w3-success-oracle`; design committed at
`0733d35`, all Codex findings resolved).
