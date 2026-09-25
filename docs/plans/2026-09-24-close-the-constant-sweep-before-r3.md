# Close the folklore-constant sweep before R3

Date: 2026-09-24
Status: **PLAN — needs an independent same-tier review before implementation.**
Blocks: the cold measurement of **R3, R4 and R5** (see
`2026-09-24-final-round-r5-unseen-corpus.md`, "Both preconditions above govern R3 and
R4").

---

## 0. Inventory, and a correction to the R5 spec's preferred remedy

The R5 spec says the preferred fix is to *"source the executor's candidates from
`comparison_immediates()` … instead of the fixed list."* **Measured: that would not close
the exposure.** `comparison_immediates()`
(`supwngo/exploit/pipeline/executors/input_shape_techniques.py:68`) ends with

```python
ordered = sorted(found, key=lambda v: (v.bit_length(), v))[:limit]
for value in FALLBACK_MAGIC_VALUES:
    if value not in ordered:
        ordered.append(value)
return ordered
```

That loop is **outside** the `try/except` and runs unconditionally. Its docstring claims
it "falls back to `FALLBACK_MAGIC_VALUES` when objdump is unavailable or yields nothing
usable" — the code appends them **always**.

Measured on two R1 targets, `PWNLIB_NOTERM=1`, isolated `XDG_CACHE_HOME`:

| target | total returned | recovered from own code | folklore present |
| --- | --- | --- | --- |
| `14_negative_index` | 33 | 24 | **9 of 9** |
| `13_off_by_one` | 9 | 0 | **9 of 9** |

Nine of nine appear even on the target where recovery succeeded and returned 24
constants. So calling the recovery function is not the same as using recovered
constants — *usage is not wiring*, and a plan that stopped at "call
`comparison_immediates()`" would have shipped a fix that changed nothing while reading
as though it closed a measurement precondition.

**Four sites hold the list.** Three are live candidate sources; the fourth is advisory
text and is in scope only so the sweep is complete:

| site | role |
| --- | --- |
| `supwngo/exploit/pipeline/executors/stack_techniques.py:59` `MAGIC_VALUES` | `VariableOverwriteExecutor`'s sweep, 14 sizes × 9 values = 126 unconditional deliveries |
| `supwngo/exploit/pipeline/executors/input_shape_techniques.py:48` `FALLBACK_MAGIC_VALUES` | appended unconditionally by `comparison_immediates()` |
| `supwngo/exploit/enhanced_auto.py:119` `MAGIC_VALUES` | third copy |
| `supwngo/exploit/strategy.py:920` | a suggestion string naming the constants — no sweep, but it will read as stale once the others change |

Paths are given in full deliberately. An earlier revision of this table used bare
basenames, and the repo currently carries 24 agent worktrees under `.claude/worktrees/`,
each with its own `enhanced_auto.py` — a basename is not a resolvable reference here.

### 0.1 The sweep's match identity, and what it therefore cannot see

The table above is the result of matching on **`MAGIC_VALUES *=`**, i.e. *sites that
define the nine-value list*. That identity is narrower than the class. A site that
supplies **one** folklore constant as a gate-value guess, without the other eight, is the
same defect and is invisible to a list-shaped sweep.

So the wider sweep was run too — every tracked `.py` containing **any** of the nine
literals, which is the identity that matches the class rather than the artefact:

```
git ls-files -- '*.py' | xargs grep -inl '0x1337bab3\|0xdeadbeef\|0xcafebabe\|0xbadc0de\
\|0xfeedface\|0xbaadf00d\|0x0d15ea5e\|0x41414141'
```

**28 of 228 tracked `.py` files.** Every one of the 24 beyond the table was inspected and
is **out of scope, not uncovered** — two benign uses account for all of them:

- `0x41414141` / `0x4141414141414141` as a **cyclic or offset marker**, searched for in
  program output or register dumps (`offset_finder.py:358`, `auto_leak.py:283`,
  `advisor.py:392`, `auto.py:1613`, and the test files). Not a value delivered to a gate.
- `0xdeadbeef` as a **placeholder return address in emitted template text**
  (`templates.py:195`, `auto.py:2537` — both inside generated-script string literals).
  Emitted for a human to replace; never compared against by the framework.

Neither is a folklore *guess at a target's comparison constant*, which is the defect. The
wider sweep therefore adds **0 instances** to the four — but the count is stated so the
next reader can audit the disposition instead of inheriting it. Recording this because
the narrow sweep alone would have read as full coverage while resting on an identity no
one had written down.

## 1. Does removing the folklore constants cost real credit?

The decisive question, and it is answerable on R1 without touching held-out material.
Across all 15 R1 targets, exactly **two** use a folklore constant in source:

| target | constant | present as a `cmp` immediate? | consequence |
| --- | --- | --- | --- |
| `14_negative_index` | `0x1337` | **YES** (`cmp $0x1337`) | recovery finds it — no loss |
| `13_off_by_one` | `0xdeadbeef` | **NO** | recovery misses it |

`13_off_by_one` does not weaken the case: its source line is `s.guard = 0xdeadbeef;`, an
**assignment**, and its binary's only `cmp` immediates are `$0x0`, `$0x20` and `$0x0`.
There is no comparison to recover, which means a sweep that hits it is guessing — the
exact credit-validity problem. It is also one of the two documented **VOID** targets, so
it is outside the credited set either way.

Combined with the already-established fact that `variable_overwrite` won **0 of 17**
credited targets across R1 and R2, **removing the folklore source costs zero credited
targets on the evidence available.**

**The limit of that evidence, stated rather than glossed:** I cannot verify losslessness
on R3/R4/R5 without reading held-out sources, which is prohibited. That is not a reason
to skip the fix; it is a reason for the design below to make a miss *observable* instead
of silent.

## 2. Options

### A — Recovered-only, plus an `is_applicable`, plus a declared skip *(recommended)*
Delete the unconditional append; source candidates only from the target's own
`cmp`/`test` stream. Give `VariableOverwriteExecutor` an `is_applicable` — it is the
**only one of 17 executors without one** — returning false with a reason when recovery
yields nothing, so the executor reports *"no gate immediates recovered"* rather than
silently burning 126 deliveries.

- Closes the precondition outright rather than labelling it.
- Removes 126 unconditional `verify_payload` calls, which also matters under the 360 s
  wall: time spent sweeping folklore is time not spent on a route that could work.
- Converts the unverifiable held-out risk into an **observable**: a target whose gate is
  not a comparison shows up as an explicit skip with a reason.

### B — Keep the list, flag and report credit won through it
The R5 spec's option 2. **Not recommended.** It keeps a brute-force channel alive, so
every future round carries the caveat and every report needs the annotation; and a
flagged figure invites "the headline number, ignoring the flagged one" downstream.

### C — Recovered-first, folklore as a declared fallback only when recovery is empty
The behaviour the docstring already claims. **Rejected as the primary fix** — it
preserves the exposure precisely in the case that matters (recovery empty means the
constant is *not* in the binary, so any hit is a guess), while making it look handled.
*What would flip A to C:* a credited target, on any corpus, whose gate constant is
genuinely unavailable from static recovery but reachable by list. R1 offers exactly one
candidate and it is VOID and assignment-only. If R3 produces a real one, C becomes the
honest answer and A's skip-with-reason is what will surface it.

## 3. A coverage limit to fix while in there

`comparison_immediates()` filters to `value >= 0x100`, dismissing smaller constants as
"loop bounds and sizeof-style noise". That is defensible for ranking and wrong as a hard
floor: `off_by_one`'s own comparisons are `cmpl $0x20`, and a gate written
`if (x == 0x41)` is invisible to the recoverer today. Keep the ordering heuristic
(small-and-interesting first), but **rank rather than exclude**, and record the change
as affecting candidate order — not as a new capability claim.

## 4. Verification required

1. **Positive control first.** `14_negative_index` must still yield `0x1337` *from
   recovery*, asserted on provenance rather than on membership. My first attempt at this
   check classified candidates by "is it in `FALLBACK_MAGIC_VALUES`", which cannot
   distinguish *recovered* `0x1337` from *appended* `0x1337` — an instrument ambiguous
   exactly where the question lives. Assert against the objdump stream.
2. **Sweep all four sites** and state the result for each, including the advisory string
   — then **re-run the wider §0.1 sweep after the change** and confirm the 24 out-of-scope
   files are still out of scope. The disposition of §0.1 is a judgement about *current*
   uses; a fix that introduces a single-constant guess somewhere would satisfy the narrow
   sweep and be invisible to it.
3. **Mutation, wrong-but-present:** pin recovery to return a fixed non-empty list and
   require a red. An absence mutation alone passes against a hardwired value.
4. **Re-run R1 and R2 and reproduce 13/13 and 4/15 target-for-target.** Both were
   re-run post-import-fix and reproduced exactly, so the baseline is current and any
   movement is attributable to this change. If either moves, that is the finding and it
   is reported before anything else.
5. **`is_applicable` needs a positive instance on both sides** — one target where it
   returns true, one where it returns false with the reason populated. A predicate no
   corpus exercises is unfalsifiable.

## 5. Method note worth keeping

The at-risk scan in §1 first returned **zero rows**, which read as "no target is at
risk". The shell is **zsh**, where an unquoted `$FOLK` is not word-split, so the loop
tested one long string that matched nothing. Fixed with an array, after which the scan
found the two rows above. An empty result from a loop that never iterated is
indistinguishable from a clean bill of health — the same shape as
[[validation-that-cannot-fail]] instance 12, in the verification of a plan about
absence-collapse. **Print the iteration count.**

**It happened a second time while running the §0.1 sweep**, by a different zsh mechanism:
`grep -rn 'MAGIC_VALUES *=' --include=*.py .` aborted with `no matches found:
--include=*.py`, because zsh tries to glob the unquoted `*.py` in the *flag's* argument
and fails the whole command when nothing matches in the cwd. That one at least failed
loudly. The generalisation across both: **in zsh, a command that enumerates must prove it
enumerated** — print the count, and check the exit status, because the two failure modes
are a silent zero and a hard abort that a `2>/dev/null` would have converted into a silent
zero. Both instances occurred while verifying a document *about* absence collapse.
