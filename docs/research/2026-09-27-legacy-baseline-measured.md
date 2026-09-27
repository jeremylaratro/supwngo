# The legacy engine's HTB baseline, measured — it is 0/7, not 3/7

**Date:** 2026-09-27
**Sprint:** Sprint −1 (re-baseline), per
[plan v3](../plans/2026-09-27-path-to-5of7-plan-v3.md)
**Status:** complete. This **invalidates the founding premise of the
legacy-to-canonical port effort.**
**Provenance:** all figures in §2 are **measured** (probe executed, both controls
validated). The 3/7 figure discussed in §3 is `recorded` and, as shown there, has
**no surviving artifact**.

---

## 1. The finding

The entire legacy-to-canonical port effort was built on one comparison:

> canonical solves 1/7 HTB targets, **legacy solves 3/7** — so port legacy's
> capability into canonical and the gap closes.

That comparison had never been measured in this session, and one earlier attempt to
state legacy's solve set from memory was wrong. It has now been measured directly.

**Legacy scores 0/7 under attributed crediting, and 1/7 under the loose criterion the
original 3/7 figure itself used.** Canonical at 1/7 is therefore not behind legacy —
it is **equal or ahead on every criterion**.

**There is no legacy capability to port.** Whatever reaches ≥5/7 must be new
capability. This is the fact that reshapes all remaining sprint work.

---

## 2. The measurement

Probe: `/tmp/legacy_probe.py` (ephemeral diagnostic, not a gate — it is not committed
and no gate depends on it). It constructs `EnhancedAutoExploiter(binary,
libc_path=…)` and calls `.run()` directly — the same construction the CLI's fallback
performs at `cli.py:3399` and that `exploit --auto` performs at `cli.py:306`/`:392`.
One target per subprocess, so a hang cannot take the others down. Per-target
isolated workspace (the whole challenge directory copied, so a bundled glibc comes
along), fresh `HTB{<32 hex>}` planted in `flag.txt` per run, 600 s timeout.

### 2.1 The probe was validated in both directions first

Per the standing rule that a custom assessment is proven able to go RED *and* GREEN
before any test trusts it:

| control | expectation | measured |
|---|---|---|
| negative — `/bin/true` | must not solve | `NOT_SOLVED` |
| positive — `benchmark/corpus/15_win_function/win_function` | must solve **and attribute** | `technique=ret2win`, `level=FLAG_CAPTURED`, planted secret reproduced |

The positive control initially failed on `rocket_blaster_xxx`, which canonical *does*
solve. Rather than report that as a negative result, the probe was declared `NOT
MEASURABLE` and fixed: the CLI passes `libc_path=` into the legacy engine and the
probe was withholding it, so it was handicapping the engine relative to the operator
path. With `libc_path` auto-detected (`ws.rglob("libc.so.6")`), `rocket_blaster_xxx`
*still* returned `NOT_SOLVED`, so the positive control was moved to a target with a
known-good route. Only after `15_win_function` came back `FLAG_CAPTURED` was the
rocket result treated as trustworthy.

### 2.2 Results

| target | verdict | technique | level | elapsed |
|---|---|---|---|---|
| `rocket_blaster_xxx` | `NOT_SOLVED` | — | `NONE` | 65.7 s |
| `sick_rop` | `CLAIMED_UNATTRIBUTED` | `variable_overwrite` | `OUTPUT_MATCH` | 6.9 s |
| `ancient_interface` | **`TIMEOUT`** | — | — | 600.1 s |
| `snow_scan` | `NOT_SOLVED` | — | `NONE` | 3.6 s |
| `bon-nie-appetit` | `NOT_SOLVED` | — | `NONE` | 1.6 s |
| `sabotage` | `NOT_SOLVED` | — | `NONE` | 1.7 s |
| `auth-or-out` | **`TIMEOUT`** | — | — | 600.1 s |

**`LEGACY SCORE 0/7 solved=[]`** — where `solved` requires `FLAG_CAPTURED` (the
planted secret reproduced) or `SHELL_ACCESS`.

Crediting ladder used, strongest first: `FLAG_CAPTURED` > `SHELL_ACCESS` >
`CLAIMED_UNATTRIBUTED` > `RAISED` > `NOT_SOLVED`. `sick_rop`'s single positive is
`CLAIMED_UNATTRIBUTED`: the engine set `successful = True` at verification level
`OUTPUT_MATCH`. That is a claim that some expected string appeared in the output. It
is **not a shell and not a reproduced secret**, and under this effort's crediting rule
it is not a solve.

### 2.3 Two timeouts corroborate an independent diagnosis

`ancient_interface` and `auth-or-out` both consumed the full 600 s. For
`ancient_interface` this is **independent confirmation** of the mechanism recorded in
[the ancient_interface spike](2026-09-27-ancient-interface-spike.md) §2: `cmd_read`'s
`read_bytes += read(...)` loop cannot terminate on EOF, because `read()` returns 0 and
`read_bytes != amnt` stays true forever. Two unrelated engines hanging identically on
the same target is the signature of a target-side infinite loop, not of either
engine's search strategy.

This also settles that the hang is **not** a canonical-pipeline property, which the
earlier "canonical search-space exhaustion" framing had implied.

---

## 3. What the 3/7 figure actually was

Source: `docs/reports/2026-09-26-comprehensive-feature-retest.md:84`, "**3/7 solved by
legacy engine**", with the solve set `sick_rop` (`variable_overwrite`),
`rocket_blaster_xxx` (ROP), `ancient_interface` (ROP). Three independent problems make
it unusable as a baseline:

**(a) The crediting criterion was the engine's own self-report.** That report's legend
(`:66`) defines its success mark as `OK+=success` — the `✓` in its legacy table is
`exploiter.successful`, with no attribution requirement. Under *that* criterion this
probe measures **1/7**, not 0/7 — but the figure was never comparable to a
shell-or-flag count, and the 1/7 canonical baseline it was being compared against was
scored on attributed verification. **The two numbers in "1/7 vs 3/7" were never on the
same scale.**

**(b) No artifact survives.** That report states (`:5-9`) that `exploit --auto` was a
**supplemental test** run outside the main harness. Its results directory
`tests/htb-targets/results-20260926-094216/` contains `autopwn.json`, `solve.json`,
and four `exploit-<vuln>.json` files per target — and **no `exploit --auto` output for
any target** (`find … -iname "*auto*"` returns only `autopwn.*`). The 3/7 figure is
therefore unreproducible from the record; only the prose assertion remains.

**(c) Two of the three do not reproduce.** `rocket_blaster_xxx` returned
`NOT_SOLVED` in 65.7 s and `ancient_interface` timed out at 600.1 s, on the same code
path, with a validated probe. Only `sick_rop` reproduced.

**What is *not* claimed here.** I am not asserting the original run was mismeasured.
Its invocation, environment, and timeout are not recoverable from the record, so the
disagreement on those two targets is **unexplained**, and I am not attributing it.
What is asserted is narrower and sufficient: *the current measured value of the legacy
engine on these seven targets is 0/7 attributed / 1/7 self-reported*, and the 3/7
figure cannot be reconstructed to contest it.

---

## 4. What this invalidates

| claim | status now |
|---|---|
| "legacy solves 3/7" | **withdrawn** — measured 0/7 attributed, 1/7 self-reported |
| "canonical (1/7) lags legacy (3/7)" | **withdrawn, and the sign is reversed** — canonical is equal-or-ahead on both criteria |
| "the gap closes by porting legacy capability into canonical" | **withdrawn** — there is no capability surplus in legacy to port |
| "T-1: canonical should reach ≥3/7, *because that is what legacy does*" | the **threshold survives** (it is superseded by the user's ≥5/7 anyway) but its **justification is void**; ≥3/7 was never derived from the difficulty of the targets |

Two consequences worth stating plainly:

1. **Sprint sequencing that assumed a donor implementation is void.** Any sprint framed
   as "lift legacy's heuristic for X" has no source to lift from. Plan v3 already
   derives its sprints from measured per-target root causes rather than from legacy,
   so its structure survives — but the *narrative* of the effort ("port the gap") does
   not, and §5 of this document records what replaces it.
2. **The legacy fallback's value is now an open question, not an assumption.** `--no-legacy`
   (committed `ef3fe80` under I-13) exists so measurement can exclude it. This finding
   says the fallback is not adding solves either; whether it should remain in the
   operator path at all is a separate decision, deliberately **not** taken here.

---

## 5. What this does *not* change

**The user's target is unaffected.** ≥5/7 on HTB **and** ≥5/7 on challenge-alike
variations was set by the user independently of any legacy comparison. It is not
derived from legacy's score and nothing here relaxes it. This finding changes only
*where the capability must come from*, not *how much is required*.

The replacement premise, stated for the record:

> Canonical is the only engine with a measured solve. Every additional seat must come
> from new capability, justified by a per-target root-cause spike with a reproducible
> exploit (gate G-l), and generalizable enough to also hold a variation class (T-2).

That is already how plan v3 §7 is built, so this finding **confirms** v3's method while
deleting the effort's original motivation.

---

## 6. Errata filed beside the originals

Per the standing rule that a correction goes next to the original artifact rather than
only in chat, an erratum pointing here is added to each surviving assertion:

| file | line | assertion |
|---|---|---|
| `docs/reports/2026-09-26-comprehensive-feature-retest.md` | 84, 96, 204 | "3/7 solved by legacy engine" and the two findings built on it |
| `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md` | 13–14 | "Baseline: canonical 1/7, legacy 3/7" |
| `docs/plans/2026-09-26-legacy-to-canonical-port.md` | 63 | T-1 stated as ≥3/7 |
| `docs/plans/2026-09-26-legacy-to-canonical-sprint-plan.md` | 7, 65 | T-1 target and direction |
| `docs/plans/2026-09-27-htb-rescore-and-variation-plan.md` | 26, 217 | "compared … to legacy's 3/7" |
| `docs/process/2026-09-26-standard-work-queue.md` | 277 | T-1 status line "legacy solves 3/7" |
| `CHANGELOG.md` | 89 | "solved 3/7 HTB targets where the canonical pipeline solved 0/7" |

Two other `3/7` matches in `docs/` are **unrelated** and correctly left alone:
`docs/plans/2026-09-24-pipeline-instrumentation-pass.md:862` ("3 of 7 red", a red-proof
count) and `docs/plans/2026-09-24-schema-unit-1-canonicalisation.md:1216` ("three of
the seven false entries").

---

## 7. Next step

Sprint −1's remaining exit criterion: **re-measure the canonical HTB baseline on the
canonical-only path** (`scripts/htb_rescore.py` now passes `--no-legacy`, committed
`ef3fe80`). Until that runs, plan v3 §2's T-1′ ledger still rests on a run in which the
legacy engine was reachable. This finding makes that re-baseline *more* important, not
less: with legacy measured at 0/7, the canonical-only number is the **only** number
either target can be scored against.
