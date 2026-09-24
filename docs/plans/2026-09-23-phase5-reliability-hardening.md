# Phase 5 — reliability hardening of the autopwn pipeline

**Date:** 23 Sep 2026
**Branch:** `feat/phase5-round1-hardening-20260923` (based on `integration/phases-0-4-7-20260923`)
**Owns:** Phase 5 of `docs/plans/2026-09-23-effectiveness-and-usability.md`
**Starting point:** `docs/reports/PHASE1-BASELINE-24SEP2026.md` — **2/15 SUCCESS (13.3%)**
on the `benchmark/` corpus, independently verified.

## Goal

Raise the honest, independently-verified benchmark score by fixing supwngo's
*actual exploitation logic*, with the corpus and `benchmark/run_bench.py`
treated as a fixed measurement instrument. Specifically **not** in scope:
weakening `run_bench.py`'s `classify()`/independent re-execution, editing
`benchmark/corpus/*.c` to make the bugs easier, or relaxing what the reports
claim.

## Root causes found (before writing any fix)

Two defects are *shared* and account for most of the 13 failures; the rest are
missing technique implementations.

### RC1 — single-blob payload delivery (shared, highest leverage)

Every native executor delivered its payload as one write
(`subprocess.run(input=blob)` or a single `sendline`). That is silently wrong
whenever the target mixes buffered stdio input with a raw `read(0, ...)`:
`scanf("%d", &n)` does not read 4 bytes off fd 0, it fills glibc's 4096-byte
stdin `FILE` buffer from whatever is available — so the first `scanf` swallows
the whole exploit and the subsequent `read()` sees EOF. The overflow never
happens and the target looks unexploitable.

Confirmed empirically on `10_int_overflow`: single-blob delivery of
`-1\n` + `A`*88 + `p64(win)` prints `done` (no crash, no flag) for every
offset; the *same bytes* delivered as two parts with a short pause capture the
flag at offset 88.

The same defect starves the second stage of any two-stage exploit (a
ROP-driven second `read()`, a leak-then-overflow round, a menu-driven heap
sequence), i.e. it blocks 03/04/05/07/08/10/11/12 structurally.

**Fix:** a new `supwngo/exploit/pipeline/delivery.py` — multi-part delivery
with an inter-part settle delay, plus a stdio-safe dynamic offset finder
(binary search on "does N filler bytes crash it", avoiding both core dumps
and the GDB batch run, which re-introduces the single-blob problem).

### RC2 — success could only ever be claimed for single-blob payloads

`PipelineVerifier` offered `verify_payload` (one blob) and `verify_shell` (an
already-obtained tube). No multi-stage technique could claim a verified
SUCCESS at all, which is why `ret2libc`/`srop`/`format_string` were
hardcoded to return PARTIAL with prose. Separately, a technique could verify a
payload in-process and emit no script, so the artifact the user is handed was
never itself tested.

**Fix:** `PipelineVerifier.verify_script()` — run the *generated script*
fresh in its own interpreter, with this attempt's unique receipt token piped in
as `echo <token>`. Success signals: the token comes back (only possible through
a real shell) or the target prints a flag. The script's own `log.success()`
lines are explicitly not a signal. Plus `pipeline/script_builder.py`, one
shared script shape for every executor.

### RC3 — attempt ordering spent the budget on the least specific techniques

`StrategySuggester` ranked `VARIABLE_OVERWRITE` at priority 1 for all 15
targets (its applicability test is nearly always true) and `RET2PLT` at 4, so
every target paid ~126 blind magic-value process spawns before the technique it
needed was tried.

**Fix:** explicit `FIRST_TECHNIQUES` / `LAST_TECHNIQUES` layers in
`orchestrator._ordered_technique_names()` — precondition-specific and cheap
first, broad brute-force sweeps last.

### RC4 — leak parsing was label-driven, not syntax-driven

`profile_stage._parse_address_leaks` only recognised a `%p` introduced by one
of a fixed set of English words (`address|leak|stack|heap|libc|ptr`), so it
missed `printf("buf @ %p")` (01) and `printf("chunk[%d] @ %p")` (12). Its
range classifier also tested `0x7f00..` before `0x7ff..`, mislabelling stack
addresses as libc.

**Fix:** `delivery.scan_hex_addresses()` + `delivery.classify_address()`,
matching on `%p`'s actual rendering and testing ranges narrowest-first.

### RC5 — missing technique implementations (per-target)

| target | needed |
|---|---|
| 02 | `ret2plt` — call `system@plt` with no leak (did not exist) |
| 01 | stack shellcode placed *after* the return address, with the stack leak re-read at run time |
| 04, 05 | recover a canary at run time (raw echo / `%N$p` sweep), then ret2win |
| 06 | real `%n` write to a gate variable, with the embedded-NUL ordering fix |
| 03, 07 | ROP `puts(puts@got)` leak → libc base → `system("/bin/sh")`, re-entering the vulnerable function; `ldd`-based local libc resolution |
| 09 | real `SigreturnFrame` SROP (was template-only) |
| 08 | `ret2dlresolve` with a ROP-driven second `read()` to plant the forged relocation |
| 10 | `int_truncation_bypass` (the old `negative_size_bypass` sweep, fixed delivery + real offset) |
| 11 | heap UAF read via the menu (`delete` then `show`) |
| 12 | safe-linking-aware tcache poison → GOT overwrite |
| 14 | negative-index OOB write driven by two numeric `scanf` prompts |

## Approach

One commit per real fix, each validated by re-running the harness for the
target(s) it claims, with a full-corpus run periodically to catch regressions.
No commit lands unless `benchmark/run_bench.py` independently reproduces the
flag for the target it claims.

## Test strategy

`python3 benchmark/run_bench.py --target <slug> --timeout 12` per fix (higher
timeout where a technique is legitimately slow), full corpus between batches.
The harness's own independent re-execution is the only accepted evidence.

## Risks

- **Over-fitting to the corpus.** Mitigated by implementing each technique
  against the *general* shape of its bug class (sweeps over candidate
  offsets/indices/format argument positions, gadget lookup through pwntools,
  `ldd` for libc) rather than hardcoding corpus addresses, and by keeping every
  precondition check in `is_applicable()` honest so a technique skips cleanly
  on targets it does not fit.
- **Runtime growth.** Script verification spawns an interpreter per candidate.
  Mitigated by RC3's ordering and by resolving the offset once (cached on
  `ExploitContext`) instead of per technique.
