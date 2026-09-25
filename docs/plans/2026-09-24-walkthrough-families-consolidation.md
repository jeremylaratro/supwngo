# Consolidating the fmtstr and integer walkthrough families

Date: 2026-09-24
Branch: `integration/walkthrough-families-consolidated-20260924` (from
`integration/phases-0-4-7-20260923` @ `ef40e93`)

A short note rather than a plan: the work is two merges and three verifications,
and the design decisions were all made on the two family branches.

## What was merged

| Branch | Head | Routes |
| --- | --- | --- |
| `feat/walkthrough-integer-family-20260924` | `ddbab5b` | truncation-into-size 0.96, negative index 0.97 |
| `feat/walkthrough-fmtstr-family-20260924` | `e496145` | write gate-flip 0.92, read chain 0.91, GOT redirect 0.82, disclosure-only 0.55 |

Both branch from `cfaa24e`. The integer merge was clean. The fmtstr merge
conflicted at `families/__init__.py`, `registry._families()` and `CHANGELOG.md`,
and every conflict was resolved as a union — neither side's entries dropped.

`_families()` resolved to `[rop_chain, syscall, integer, stack_bof, fmtstr,
triage]`: the union that preserves each side's own relative order, rather than
either side's ordering wholesale. That list is the tie-break for route
selection, so the resolution is load-bearing and not cosmetic.

### The conflict that wasn't

`cli.py`'s `explain --family` help text is the third coordination point the
merge was expected to conflict at. It did not, because **the fmtstr branch never
added itself to it** — so a clean three-way merge produced a tree in which the
one flag that selects the family does not list it. Fixed in the merge commit.

This is worth recording as a class: a coordination point only conflicts if both
sides edited it. A side that *forgot* to edit it merges silently and the gap
survives. The conflict list is therefore a floor on what to check, not a
ceiling.

## The cross-family ordering

Every route in every family, highest first. Enumerated from the family modules
rather than by hand (see below), and **no two nonzero scores are equal**.

| Score | Family | Route | Applicable |
| --- | --- | --- | --- |
| 0.97 | `integer` | negative index (OOB write before the array) | yes |
| 0.96 | `integer` | truncation into a size computation | yes |
| 0.95 | `rop_chain` | ret2plt / ret2system, with a `pop rdi` gadget | yes |
| 0.92 | `fmtstr` | arbitrary write (`%n`), gate-variable flip | yes |
| 0.91 | `fmtstr` | arbitrary read (`%p`/`%s`), canary leak + overflow | yes |
| 0.90 | `stack_bof` | ret2shellcode | yes |
| 0.88 | `syscall` | SROP | yes |
| 0.85 | `rop_chain` | ret2libc via GOT leak, re-entrant input | yes |
| 0.82 | `fmtstr` | arbitrary write, GOT redirect under Partial RELRO | yes |
| 0.80 | `syscall` | ret2syscall execve | yes |
| 0.75 | `stack_bof` | ret2win | yes |
| 0.60 | `rop_chain` | ret2libc via GOT leak, single-shot input | yes |
| 0.55 | `fmtstr` | disclosure only (argument index not measured) | yes |
| 0.45 | `integer` | truncation proven, no control-flow target | yes |
| 0.35 | `rop_chain` | ret2plt with no `pop rdi` gadget | conditional |
| 0.30 | `stack_bof` | ret2win with a `win` symbol but no observed fault | no |
| 0.15 | `triage` | guided triage | yes (always) |
| 0.00 | five families | the non-applicable explanatory routes | no |

### Justification for the ordering

Three bands, and the boundaries are the argument:

1. **0.82 – 0.97, a complete route whose decisive fact was measured on this
   binary.** Within the band, rank by how much is left to the reader. The two
   integer routes top it because their decisive test is an *identity* over the
   input — the exploit either satisfies the arithmetic or it does not, with no
   address to leak and no layout to discover. `ret2plt` at 0.95 follows: one
   known address, no leak. The fmtstr pair sit at 0.92/0.91 because they need a
   measured argument index first, and a write outranks a read because the read
   still has to be spent on something. `ret2shellcode` at 0.90 needs a runtime
   stack address; SROP at 0.88 needs a syscall gadget and a writable frame.
2. **0.45 – 0.80, applicable but partial or contingent.** `integer`'s 0.45
   states this band's principle in its own rationale: *half an exploit should
   lose to a whole one*. It proves the arithmetic and the offset and then hands
   the control-flow half to the code-reuse families. `fmtstr`'s 0.55 is the same
   shape — a disclosure whose argument index was not pinned down, so the `%n`
   route is withheld rather than guessed.
3. **0.15, `triage`.** Deliberately the floor: it always applies, so it must
   lose to anything with something specific to say.

The gap between bands 2 and 3 is where the heap detection family belongs: above
`triage` because it has measured, binary-specific facts about this allocator,
and below `integer`'s 0.45 because it does not demonstrate control of anything.
The values 0.30 and 0.35 inside that gap are taken by non-applicable routes and
must still be avoided, because the uniqueness invariant covers every route
whether or not it currently competes.

### Why ties are a correctness bug, not a style issue

`registry.generate_walkthrough` selects with `max()`, which keeps the **first**
maximum. A tie therefore resolves on position in `_families()` — so two routes
sharing a score means the winner is decided by a list nobody thinks of as a
priority order, and a family added later can capture a target from an existing
one with no code in either family changing.

Both second-wave families hit this during development and both found it by hand:
`integer` raised 0.88/0.90 to 0.96/0.97 (ties with SROP and ret2shellcode), and
`fmtstr` raised its read route off 0.90 (tie with ret2shellcode) and its GOT
route off 0.80 (tie with ret2syscall) — two ties that were invisible on its own
targets. Finding this by hand three times is the argument for a test.

## The three verifications

### 1. No score ties — `tests/test_walkthrough_scores.py` (11 tests)

Scores are read out of the family modules with `ast`, not by calling
`propose()`. That choice matters: it needs no binaries, so it runs in a fresh
clone; it sees every branch of a family's scoring including routes no corpus
target exercises (`rop_chain`'s `0.95 if has_rdi else 0.35` contributes both
arms); and it cannot be satisfied by a family that merely declines to propose
during the test run. A score expression the collector cannot enumerate is an
**error**, not a skip — otherwise a family computing its score arithmetically
would slip past the invariant silently.

`0.0` is the one value allowed to repeat, meaning "not on the table", and a
companion test holds that convention up by failing if any `0.0` route is
applicable.

### 2. The 15-target sweep — `tests/test_walkthrough_route_sweep.py` (30 tests)

All 15 round-1 targets, asserting the winning family, the route within that
family where the family owns more than one, and that the winner is a *strict*
maximum with no runner-up tying it.

Run with `probe=True`, deliberately: that is the default for `supwngo explain`
and the only mode in which the measuring families can speak. Under `--no-probe`
the same corpus routes very differently — 05, 06, 12 and 13 all fall to
`stack_bof`'s ret2win, because nothing has been measured and a `win`-ish symbol
is then the strongest fact available. That is correct by design, but it means a
sweep written against the cheaper mode would assert the wrong thing.

Result — every target keeps the family and route it had before either family
landed:

| Target | Family | Score | Route |
| --- | --- | --- | --- |
| 01_shellcode_stack | `stack_bof` | 0.90 | ret2shellcode |
| 02_ret2plt_system | `rop_chain` | 0.95 | ret2plt / ret2system |
| 03_pie_leak_ret2libc | `rop_chain` | 0.60 | ret2libc via a GOT leak |
| 04_canary_leak_bypass | `triage` | 0.15 | guided triage |
| 05_fmtstr_arbread | `fmtstr` | 0.91 | arbitrary read |
| 06_fmtstr_arbwrite | `fmtstr` | 0.92 | arbitrary write |
| 07_ret2libc_leak | `rop_chain` | 0.60 | ret2libc via a GOT leak |
| 08_ret2dlresolve | `triage` | 0.15 | guided triage |
| 09_srop | `syscall` | 0.88 | SROP |
| 10_int_overflow | `integer` | 0.96 | truncation into a size computation |
| 11_heap_uaf_leak | `triage` | 0.15 | guided triage |
| 12_heap_tcache_poison | `triage` | 0.15 | guided triage |
| 13_off_by_one | `triage` | 0.15 | guided triage |
| 14_negative_index | `integer` | 0.97 | negative index |
| 15_win_function | `stack_bof` | 0.75 | ret2win |

The five `triage` entries are the abstention design working, and they are pinned
precisely because each is a target a family could plausibly capture by accident.

### 3. Full suite

`733 passed, 14 skipped` (341s). The 14 skips are pre-existing and unrelated —
external HTB/challenge binaries not in the repo. Before building the corpus the
same tree reported `620 passed, 86 skipped`: **72 of the two families' own tests
were silently skipping** because `benchmark/corpus/` was not built. Each family
reported passing 40 and 44 tests on its own branch; verifying the combination
required compiling the corpus first, and "green" without it means very little
for these two families.

## Mutation testing

`tests/test_walkthrough_scores.py`, 7 mutations, all **RED**:

| # | Mutation | Verdict |
| --- | --- | --- |
| M1 | `SCORE_WRITE_GOT` 0.82 → 0.80 (ties ret2syscall) | RED |
| M2 | `SCORE_READ_CHAIN` 0.91 → 0.90 (ties ret2shellcode) | RED |
| M3 | `_SCORE_NEGATIVE_INDEX` 0.97 → 0.88 (ties SROP) | RED |
| M4 | `TRIAGE_SCORE` 0.15 → 0.56 (outranks fmtstr disclosure) | RED |
| M5 | `stack_bof` 0.30 route becomes `score=0.0, applicable=True` | RED |
| M6 | a score becomes an arithmetic expression (unenumerable) | RED (error) |
| M7 | `rop_chain`'s `else 0.35` arm → 0.30 (ties stack_bof) | RED |

`tests/test_walkthrough_route_sweep.py`, 6 mutations, 4 RED and **2 green that
are inert rather than uncovered** — checked, not assumed:

| # | Mutation | Verdict |
| --- | --- | --- |
| S1 | `SCORE_WRITE_GATE` 0.92 → 0.99 | green — **inert** |
| S2 | `TRIAGE_SCORE` 0.15 → 0.995 | RED (10 failures) |
| S3 | `_SCORE_NEGATIVE_INDEX` 0.97 → 0.14 | RED |
| S4 | drop `fmtstr` from `_families()` | RED (2 failures) |
| S5 | drop `integer` from `_families()` | RED (2 failures) |
| S6 | `stack_bof` ret2shellcode 0.90 → 0.75 | green — **inert** |

S1 is inert because `fmtstr` **abstains entirely** on 10 and 14 — it proposes no
route at all, so its score cannot affect them. Confirmed by dumping every
proposal on both targets. S6 is inert because `stack_bof` returns exactly one
route per binary: on 01, NX is off so it returns ret2shellcode and never reaches
the ret2win branch, leaving 0.75 still the unique maximum there.

Both mutations do introduce real defects, and both are caught — by the *other*
test. Re-running them against `test_walkthrough_scores.py`: S6 fails
`test_no_two_routes_share_a_score` **and** the recorded-ordering test (it ties
`stack_bof`'s own ret2win), and S1 fails the recorded-ordering test. The two
modules are complementary, and that was verified by execution rather than
assumed from their docstrings.

## What was not done

No benchmark harness run and no parallel sweep: other agents hold gated
measurements on this host. The sweep here collects facts and asks the registry
which route wins — no exploitation, no timing, no scoring. The corpus binaries
were compiled per target via `benchmark/build_all.sh <target>`, which is a
`gcc` wrapper and not the harness.

## Evidence provenance across the `d51f9bc` masking defect

`d51f9bc` fixed a defect that silently collapsed walkthrough families to
`triage` for the rest of any process in which the first `import pwn` happened
inside a `CliRunner`. The review protocol (`f59ec04`) now holds that **any green
result collected while a masking defect was live is uninformative, not
probably-fine.** This section states, for this consolidation's own evidence, what
was collected before that fix and what has been re-run since.

### Test-level results: all re-run after the fix

Everything in this document's "three verifications" section has been re-collected
post-`d51f9bc`:

| Result | When | Outcome |
| --- | --- | --- |
| Full suite | after | **834 passed, 14 skipped**, 0 pwntools load failures |
| `-k walkthrough` | after | **396 passed**, 0 load failures |
| `-k walkthrough`, two concurrent sessions | after | **396 passed each**, rc=0 both, 0 load failures |

The pre-fix "791 passed / 14 skipped" figure is superseded by the 834 above and
should not be cited.

### Mutation tables: collected before the fix, and shown not to be exposed to it

The heap 13-mutation table and the tie-sweep mutation table were both collected
before `d51f9bc`. Re-running every mutant would be the safe default, so the
narrower question was tested first: *can these files be masked at all?*

Each was run one file per process — which is how the mutation tables were
collected — with the masking defect **re-induced** (the `PWNLIB_NOTERM` default
removed from `conftest.py`):

| File | Verdict with the defect live | Poison signatures |
| --- | --- | --- |
| `test_walkthrough_heap.py` | GREEN, 52 passed | 0 |
| `test_walkthrough_scores.py` | GREEN, 20 passed | 0 |
| `test_walkthrough_route_sweep.py` | GREEN, 60 passed | 0 |
| `test_walkthrough_fmtstr.py` | GREEN, 44 passed | 0 |
| `test_walkthrough_model.py` | GREEN, 73 passed | 0 |

None of them can be masked in that configuration, because none imports `pwn`
through a `CliRunner` first — only `test_walkthrough_cli.py` does, and the
poisoning needs it to run *earlier in the same process*. So the mutation evidence
stands on its own terms, and the pre-fix mutation tables above are not withdrawn.

The one result genuinely collected under a live masking defect was the *whole-suite*
figure, and it has been superseded.

### Correction: the `name` tie-break regression was **not** masked

The record should not say it was. An interim version of `common.select_route`
broke score ties on `name`, which silently flipped `fmtstr` to the `%n` write
route in a case whose point is to report the read rejection. It is tempting — and
it was initially reported — that this escaped because the masking defect hid the
two `fmtstr` tests that catch it. That was tested directly rather than assumed:

Reconstructing the exact interim state (conftest without `PWNLIB_NOTERM`, `fmtstr`
ranking its rejections, `select_route` keyed on `name`) and running the minimal
ordering pair that induces the poisoning:

| State | `test_leak_with_no_consumer…` | `test_builds_when_the_cyclic_offset_probe_failed` |
| --- | --- | --- |
| interim code, masking defect **live** | **FAILED** | **FAILED** |
| interim code, masking defect fixed | FAILED | FAILED |
| current code | passed | passed |

Both tests fail with the defect live, so the defect was not hiding them. (The
defect *was* independently live in that run: a third test,
`test_unreachable_write_target_is_marked_rather_than_offered`, failed only in the
first row — that one is a genuine poisoning victim.)

The real reason the regression survived is narrower and more useful: **the
tie-sweep mutation table ran only `test_walkthrough_scores.py` and
`test_walkthrough_route_sweep.py`.** It mutated the selector and ran the
selector's own tests — never `test_walkthrough_fmtstr.py`, where the tests that
encode which route `fmtstr` is *supposed* to pick actually live. The mutants all
died, and the table read as thorough, because every test it ran was a test of the
mechanism rather than of the behaviour the mechanism decides.

This is the same shape as the schema property-test finding: narrowness in a
verification reads exactly like correctness. The rule it yields is not about
masking at all — **a mutation table is only as broad as the test selection it
runs against, so mutating a shared component means running the tests of every
caller whose behaviour it decides, not the component's own tests.** The regression
was caught by the later full `-k walkthrough` run, which is the run that first
included the callers.
