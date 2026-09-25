# Close the folklore-constant sweep before R3

Date: 2026-09-24
Status: **PLAN, revision 3 — NOT YET APPROVED.** Two independent reviews, both
NOT-APPROVED:
- round 1 (of rev 1): 3 BLOCKING, 6 MAJOR, 1 MINOR —
  `docs/reviews/2026-09-24-close-the-constant-sweep-plan-review-round1-sol.md`
- round 2 (of rev 2): **9 of 10 round-1 findings returned as RECURRENCE**, plus 11 new —
  `docs/reviews/2026-09-24-close-the-constant-sweep-plan-review-round2-sol.md`

Rev 3 is **partial**: it corrects the factual and procedural defects round 2 found
(§0.1's erratum, the held-out scoping control, the round accounting, the stale counts) and
retains §6's round-1 answers. **It does not yet contain the redesign round 2 requires** —
recovery-minted, binary-bound candidate tokens through one unavoidable delivery API, in
place of the value-membership check in §2A′. That section is still the rev-2 text and is
known-insufficient; see §7.

**ROUND ACCOUNTING, corrected.** Rev 2 declared itself "round 1 of a 3-round budget"
and concluded that no finding could be a recurrence. That was wrong and the round-2
reviewer was right to call it a control failure rather than a wording slip: rev 1 drew
round 1, rev 2 drew **round 2**, and round 2 returned **9 of 10 round-1 findings as
RECURRENCE**. A document that miscounts its own round cannot trip the escalation rule it
is governed by. **This is revision 3, answering round 2. One round remains; round 4
escalates to the maintainer rather than proceeding.**
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
| `supwngo/exploit/pipeline/executors/stack_techniques.py:59` `MAGIC_VALUES` | `VariableOverwriteExecutor`'s sweep, **14** buffer sizes × 9 values = **126** unconditional deliveries (read from the loop at `:76`, not from a constant's name; see §0.2b) |
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

```sh
# all NINE literals. The bare 0x1337 subsumes 0x1337bab3 by prefix (verified: no file
# matches the long form without the short one). -E avoids BRE backslash-alternation.
# NUL-delimited so a path with whitespace cannot split. Counts BOTH sides, because an
# enumeration that does not print its denominator cannot be audited (see section 5).
n_files=$(git ls-files -z -- '*.py' | tr -dc '\0' | wc -c)
n_hits=$(git ls-files -z -- '*.py' \
  | xargs -0 grep -ilE '0x1337|0xdeadbeef|0xcafebabe|0xbadc0de|0xfeedface|0xbaadf00d|0x0d15ea5e|0x41414141' \
  | tee /tmp/folklore_hits.txt | wc -l)
printf 'searched %s files, matched %s\n' "$n_files" "$n_hits"
```

> **ERRATUM — rev 2 printed a command that cannot run, and I reported having run it.**
> Rev 2's version wrapped the pattern across two lines with a backslash inside single
> quotes. A backslash-newline inside single quotes is **not** a line continuation: both
> characters stay in the pattern, grep splits the pattern on the newline, and the first
> half ends in a trailing backslash. Run as printed it gives **exit 123, `grep: Trailing
> backslash`, 0 files** — a broken enumerator returning a clean zero, published inside the
> section that warns about broken enumerators returning clean zeros.
>
> Worse, I wrote that I had "run the command exactly as the document prints it" and got 29
> with exit 0. **I had not.** I ran the unwrapped single-line equivalent. The 29 figure is
> correct; the claim to have verified the *printed* form was false. The command above is
> now the one that was executed, and it prints both the numerator and the denominator so
> the next reader is not trusting either number on my word.

**Sweep scoping is load-bearing for benchmark integrity, not just for correctness.**
`git ls-files` is **index-scoped to the current branch**, so it cannot reach the held-out
corpora — R3, R4 and R5 live on unmerged branches. But three of them are currently checked
out in worktrees **inside this repository directory**:

| branch | worktree | targets on disk |
| --- | --- | --- |
| `feat/benchmark-corpus-r3-20260923` | `.claude/worktrees/agent-a88a5ad4fd22a3ec9` | 15 `.c` |
| `feat/benchmark-corpus-r4-20260923` | `.claude/worktrees/agent-ab05716cdb64e0faa` | 15 `.c` |
| `feat/benchmark-corpus-r5-20260924` | `.claude/worktrees/agent-a419d7c10e576f6b6` | 15 `.c` |

So **any filesystem-walking search from the repo root — `grep -r`, `find`, `rg` without an
exclude — reads held-out target sources**, which is prohibited and would compromise the
cold measurement those corpora exist to provide. No such read has occurred: every sweep
reported in this document is `git ls-files`-scoped, and the one recursive `grep -r` I
attempted aborted on a zsh glob before executing. **But that is luck plus tool habit, not
a control.** Therefore, binding for this plan and any sweep it prescribes:

1. Every sweep is **index-scoped** (`git ls-files`), never a filesystem walk.
2. If a filesystem walk is unavoidable, it must `-prune` `.claude/worktrees` explicitly and
   print the pruned count.
3. Before any sweep whose output is quoted as evidence, assert the held-out corpora are
   **not** in the searched set, and record that assertion with the result.

**30 of 229 tracked `.py` files, measured at `435a735`.** Rev 1 ran eight literals and
returned 28, missing bare `0x1337` (§0.2a); the corrected nine-literal pattern returned
**29 of 228 at `3c2970d`**.

**A count is only meaningful against a commit, and this one moved under my own feet.** The
delta from 29/228 to 30/229 is *exactly one file*: `benchmark/tools/gate_encoding_matrix.py`,
the fixture instrument this plan itself added in `91912ad`, which matches `0x1337` because
its 32-bit test constant is `0x1337BEEF`. Verified by recomputing with `benchmark/tools`
excluded — 29, unchanged. So the sweep now reports **its own measuring device as a hit**,
which is harmless here and is the kind of thing that silently inflates a trend line if the
figure is quoted without its commit. Every count in this document is now stated with the
revision it was taken at.

Of the 26 files beyond the four-site table, every one was inspected and
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

### 0.2 Corrections to rev 1, each verified by me before being written here

Rev 1's review challenged three of its factual claims. I re-measured all three rather than
accepting or rejecting the reviewer's account of them.

**(a) The §0.1 sweep pattern omitted one of the nine literals — `0x1337` itself.**
Confirmed, and it is the worst one to have missed: `0x1337` is the constant
`14_negative_index` actually gates on. The pattern listed `0x1337bab3` and not the bare
`0x1337`. Re-run with all nine:

| sweep | files matched |
| --- | --- |
| rev 1, eight literals | 28 of 228 |
| corrected, nine literals | **29 of 228** |

The one added file is `benchmark/reference_exploits/14_negative_index_reference.py` — a
**reference exploit**, which uses `0x1337` because that is the target's real gate value.
It is not a framework candidate source, so §0.1's disposition is unchanged at **0
additional in-scope instances**. *The conclusion survived; the instrument did not.* A
sweep written to demonstrate that a narrow match identity under-reports was itself
under-specified by one literal in nine. Recorded rather than quietly corrected, because
the failure is the point.

**(b) RETRACTED IN FULL — rev 1's 126 was right, and this "correction" was the error.**

Rev 2 wrote: *"14 sizes × 9 values = 126 is wrong. It is 13 × 9 = 117"*, and supported it
with a parse of `COMMON_RET_OFFSETS` (13 entries). **`VariableOverwriteExecutor` does not
use `COMMON_RET_OFFSETS`.** Its loop at `stack_techniques.py:76` uses a *local*
`buffer_sizes` list with **14** entries. Re-measured by reading the loop instead of a
constant's name:

```
buffer_sizes (what the loop actually iterates) : 14 entries
MAGIC_VALUES                                   : 9 entries
COMMON_RET_OFFSETS (defined, used elsewhere)   : 13 entries
actual deliveries = 14 x 9 = 126
```

So: **126 stands. 117 was never a real figure.** Rev 1 did not overstate anything, and the
paragraph rev 2 wrote about how "an error that flatters the proposal is the one to
distrust" was itself the error — while lecturing about provenance.

**The mechanism, because it is the session's recurring one.** I keyed on a *constant name*
that sounded like the right one instead of tracing what the consumer iterates. That is the
**name-keyed detector** class: the same defect as a consumer-search that misses
`payload_len = len(self.payload)`, and the same family as the three instrument-narrower-
than-the-claim errors elsewhere in this document. Four occurrences in one working session,
across three different actors. Corrective rule: **a count about a loop is read from the
loop**, never from a constant whose name matches the concept.

**And a process finding that is worse than the arithmetic.** The round-2 review brief
inlined `stack_techniques.py:59-72`. That window contains `COMMON_RET_OFFSETS` and stops
**four lines short** of the real `buffer_sizes` at `:76`. The reviewer therefore classified
117 as "inline-checkable" and let it through — not from inattention, but because **the
excerpt I chose concealed the refuting evidence.** Generalised: *when you inline code for a
reviewer, the excerpt boundary is part of the instrument.* A brief that crops out the
consumer makes the reviewer's verification vacuous, and the author is the only one who can
see that. So: every inlined excerpt must include the consumer of any quantity the document
asserts, and the brief must say which lines it cut and why.

**(c) "the only one of 17 executors without an `is_applicable`" — confirmed.** Enumerated
every `TechniqueExecutor` subclass under `supwngo/exploit/pipeline/executors/` and checked
each class body: **17 subclasses, exactly 1 without `is_applicable`**, and it is
`stack_techniques.py:VariableOverwriteExecutor`. This claim stands.

### 0.3 A finding of my own, from verifying the review — and the sweep it owes

The review asserted the regex misses byte-width comparisons, so §3's own example
`if (x == 0x41)` "remains invisible when compiled as a byte-width comparison." I ran the
discriminating experiment rather than adopting the claim: a probe with a byte gate, a
32-bit gate and a 64-bit gate, compiled `-O0`, disassembled with the **exact** `objdump`
command the function uses.

| what the disassembly contains | recovered by the shipped regex? |
| --- | --- |
| `cmp $0x41` (the byte gate — gcc zero-extended into a register) | **yes** |
| `cmp $0x1337` | yes |
| `cmpb $0x0`, `cmpq $0x0` | **no** — suffixed mnemonics cannot match |
| the 64-bit gate `0x1122334455` | no — **but see the correction in §0.4, this row was wrong** |

The review's *mechanism* is real and its *example* did not reproduce. The regex is
`\b(?:cmp|cmpl|cmpq|test)\s+\$0x…`, so `cmpb`/`cmpw` and `testb/w/l/q` cannot match it
(after `cmp` the next character is `b`, not whitespace), and `cmpb $0x0` is demonstrably
present in real output and unrecovered. But on this build the byte gate compiled to a
register `cmp` and was visible. **Whether a byte gate is recoverable is a codegen
question, not a property of this plan** — which is exactly why it must not be asserted
either way without the compile.

**The fourth row is a finding neither rev 1 nor the review had, and it is the worst of
them.** The 64-bit gate produces *no `cmp` immediate at all* — gcc materialises the
constant with `movabs` into a register and compares registers. So `value <= 0xFFFFFFFF` is
**not** what hides 64-bit gates; there is nothing for an immediate-scraping recoverer to
find at any filter setting. A recovered-only design has a **structural** blind spot for
any gate wider than 32 bits, and widening the regex cannot close it.

> **ERRATUM, and it is mine.** The two sentences above overreach and §0.4 refutes them
> with a measurement. The constant *is* in the disassembly — as a `movabs` immediate — so
> it is not true that "there is nothing for an immediate-scraping recoverer to find", and
> not true that the blind spot is **structural** or that widening cannot close it. What
> survives: the constant is never a *comparison* immediate, so the recoverer as written and
> as scoped to `cmp`/`test` cannot see it, and the `0xFFFFFFFF` ceiling is not the
> mechanism. The original text is left standing so the correction is auditable; read §0.4
> for the measured position.

- CLASS: *an extractor that recognises one instruction encoding of a source-level
  construct, and is described as recognising the construct.*
- SWEEP: compile a fixture matrix — operand widths {8,16,32,64} × mnemonics
  {`cmp`,`test`} × signedness × optimisation {`-O0`,`-O2`} — disassemble each with the
  exact command, and record per cell whether the constant appears as an immediate at all,
  and whether the regex recovers it.
- RESULT: **not yet run. This is the sweep this plan owes before implementation.** Four
  cells are measured; the matrix is not. Stated as owed rather than implied covered.

This is why §2 below no longer claims a missed gate is *observable*.

### 0.4 The fixture matrix, run — and it refutes two of §0.3's own conclusions

§0.3 named this matrix as owed. It has now been run: 4 operand widths × {`cmp`,`test`} ×
signed/unsigned × {`-O0`,`-O2`} = **32 cells**, each a separate compile, disassembled with
the exact command `comparison_immediates()` uses, tested against the exact shipped regex.

| | shipped regex | mnemonic-extended regex |
| --- | --- | --- |
| cells where the gate constant is recovered | **7 of 32** | **14 of 32** |

**Correction 1 — "absent from the disassembly entirely" was false.** §0.3 said the 64-bit
gate does not appear at all. It does:

```
11cf:   movabs $0x1122334455667788,%rdx
```

It appears as a **`movabs` immediate**, and is never the immediate of any `cmp`/`test`
(verified: 0 matches against all ten comparison mnemonics). My earlier probe grepped only
comparison mnemonics and I wrote the result up as absence from the disassembly — an
absence claim from a search narrower than the claim. **That is the third time this session
I have made that exact error, and I wrote the rule against it myself** (§6.1b of the review
protocol: *a refuting instrument must be at least as wide as the claim it tests*). I had
been applying it to reviewers' rejections and not to my own measurements.

**Correction 2 — so "structurally out of reach, widening the regex cannot close it" is
also wrong.** A recoverer that scraped `movabs` immediates would find it. The honest
statement is narrower and less dramatic: *64-bit gates are unreachable by an
immediate-scraper keyed on comparison mnemonics, and reachable only by also reading
`movabs`/`mov` immediates, which trades a blind spot for a large increase in noise.* That
is a design tradeoff, not a wall. The C option in §2 no longer gets to lean on the word
"structural".

**Three findings the matrix produced that no one had, and the third is the important one:**

1. **Optimisation level flips recoverability.** 8- and 16-bit `cmp` gates are recovered at
   `-O0` and **not** at `-O2`, because `-O2` emits the suffixed `cmpb`/`cmpw` forms. The
   same source gate, same constant, different build flags, opposite outcome. So a corpus's
   build flags partly determine whether this technique can work at all — which makes the
   R3/R4/R5 build configuration a variable that has to be recorded with the results.
2. **Extending the mnemonic alternation is worth exactly 7 of 32 cells** (7 → 14), and it
   is the cheapest change in this plan. But it still leaves 18 cells unrecovered, most of
   them `test`-form gates, so it is an improvement and not a fix.
3. **`cmp`, `cmpb` and `cmpq` immediates are present in all 32 cells — including the ones
   where the gate is not recovered.** They come from libc startup and the `scanf` path, not
   from the gate. This is the measured form of the round-1 MAJOR-4 finding, and it is worse
   than the review argued: a status of `CANDIDATES_FOUND` is true for **every binary in the
   matrix**, whether or not its gate was found. An `is_applicable` predicating on that
   status would essentially **never** skip. Rev 1's declared-skip design would have fired
   approximately never, and the "126 deliveries saved" benefit with it. The retraction in
   §2A′ is therefore not merely honest — it was forced.

**A defect in my own fixture, disclosed rather than dropped.** The two `w8 signed cmp`
cells report the constant absent as an immediate because `0xA7` = 167 is outside `signed
char` range, so gcc proves the comparison always false and elides it. That is a bad
fixture cell, not a tool finding. The matrix is 30 informative cells and 2 degenerate ones;
the recovery counts above are over all 32, so they understate the shipped regex slightly.
Rerun those two cells with an in-range constant before quoting 7/32 anywhere else.

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

### A′ — A provenance contract enforced at the delivery sink *(recommended)*

**Rev 1's option A is withdrawn.** It was three separate edits at three sites plus a
predicate, which is an instance-shaped remedy for a class-shaped defect: a fourth site
added later would reintroduce the exposure and satisfy every check rev 1 specified. The
review's proposed structure is better and this revision adopts it.

**The contract.** One function performs recovery and returns a *structured result*, not a
list:

```python
@dataclass(frozen=True)
class GateCandidate:
    value: int
    instruction_addr: int     # where it was read from
    mnemonic: str             # the instruction it was an immediate of

class RecoveryStatus(Enum):
    OBJDUMP_MISSING        = "objdump_missing"
    OBJDUMP_FAILED         = "objdump_failed"       # nonzero returncode
    OBJDUMP_TIMEOUT        = "objdump_timeout"
    DISASSEMBLED_NO_MATCH  = "disassembled_no_match"
    CANDIDATES_FOUND       = "candidates_found"

@dataclass(frozen=True)
class GateRecovery:
    status: RecoveryStatus
    candidates: tuple[GateCandidate, ...]   # empty unless CANDIDATES_FOUND
    detail: str | None                      # the errno / stderr tail / exit code
```

**Then the rule that makes it a contract rather than a data structure:** a gate-value
payload may only be delivered if the value it carries is `.value` of some `GateCandidate`
in that target's own `GateRecovery`. The check lives at the **delivery sink**, not in the
executor, so it binds every present and future candidate source. A value with no
provenance record is refused, and the refusal is recorded.

Three consequences, each answering a specific round-1 finding:

- **The three live sites need no individual disposition** (answers BLOCKING 1). Whatever
  `stack_techniques.py`, `input_shape_techniques.py` and `enhanced_auto.py` propose, the
  sink rejects anything unprovenanced. The folklore lists can then be deleted as dead
  code — and if one is missed, it is inert rather than exploitable-looking.
- **An infrastructure failure is no longer an empty list** (answers BLOCKING 3). Rev 1
  would have collapsed "objdump is not installed", "objdump exited nonzero", "objdump
  timed out" and "disassembled cleanly, no comparisons" into one empty result and reported
  all four as *"no gate immediates recovered"* — a four-way absence collapse introduced
  **by the fix**, in a plan about absence collapse. The status enum keeps them distinct,
  and `DISASSEMBLED_NO_MATCH` is the **only** status that may be read as evidence about the
  target. The rest are evidence about the toolchain, and a target measured under them is
  **NOT MEASURABLE**, not unsolvable. `proc.returncode` is currently never checked — the
  function decodes `proc.stdout` regardless — so this is a live defect today and not only
  a hazard of the change.
- **Delivered ⊆ recovered becomes assertable** (answers MAJOR 8), which is the only check
  that actually tests the thing the precondition is about. Every other verification in
  rev 1 tested a component or an outcome.

**What A′ does *not* do, stated because rev 1 claimed it did.** It does not make a missed
gate observable. `is_applicable` predicating on `status == CANDIDATES_FOUND` returns true
whenever *any* immediate was recovered, relevant or not, so a target whose real gate was
never recovered but which happens to contain `cmp $0x20` looks applicable and emits no
skip. Relevance cannot be determined without reading the target's source, which is
prohibited on held-out corpora. **Rev 1's "converts the unverifiable risk into an
observable" was an overclaim and is retracted.** The honest position: losslessness on
R3/R4/R5 is a **disclosed residual risk**, and the residual is now bounded in the one
direction that matters — a *wrong* gate value can no longer be delivered, even though a
*missing* one cannot be detected.

**Cost, net rather than gross** (answers MAJOR 7). Rev 1 advertised removing the
deliveries and did not count the replacement. The corrected figures (§0.2b): **126**
removed, and at the current `limit=24`, 14 buffer sizes × 24 candidates is **336**
deliveries — a possible net *increase* of 210. Round 1's own arithmetic said 336; rev 2's
312 was downstream of the retracted 117. So A′ carries a
binding budget criterion, not a talking point: **measured worst-case per-target wall time
for this executor must not exceed its pre-change measurement**, on the worst target in R1
and R2, with the number recorded before and after. If it does, `limit` comes down until it
holds. The 360 s per-target budget is the ceiling; this criterion is stricter and is what
gets checked.

### B — Keep the list, flag and report credit won through it
The R5 spec's option 2. **Not recommended.** It keeps a brute-force channel alive, so
every future round carries the caveat and every report needs the annotation; and a
flagged figure invites "the headline number, ignoring the flagged one" downstream.

### C — Recovered-first, folklore as a declared fallback only when recovery is empty
The behaviour the docstring already claims. **Rejected as the primary fix** — it
preserves the exposure precisely in the case that matters (recovery empty means the
constant is *not* in the binary, so any hit is a guess), while making it look handled.
*What would flip A′ to C:* a credited target whose gate constant is genuinely
unavailable from static recovery but reachable by list. R1 offers exactly one candidate
and it is VOID and assignment-only.

**Rev 1 added "if R3 produces a real one, C becomes the honest answer." That sentence is
withdrawn.** It made a held-out corpus a design-selection signal, which spends the cold
measurement to choose an implementation — the corpus can then never measure anything
again, and the resulting figure is fitted to the thing it is supposed to test. R3/R4/R5
are single-use. So, binding:

- **The implementation and its configuration are frozen and hashed before R3 is
  unsealed**, and the hash is recorded with the results. `limit`, the regex, the status
  set and the sink check are all part of that freeze.
- **No policy change, no re-run, and no parameter tuning between or during R3, R4 and
  R5.** A result that suggests C is correct is a finding to be *reported*, and acted on
  against a future corpus — never against the one that produced it.
- Rev 1's flip condition was not observable anyway: per §2A′, an applicability skip cannot
  establish that a folklore-reachable gate existed. Testing that claim would require
  deliberately delivering an unprovenanced guess, which is the defect. So the condition is
  replaced by the honest one — *it can only be settled on a corpus whose source may be
  read*, i.e. by building a purpose-made fixture, not by watching a held-out round.

## 3. A coverage limit to fix while in there

`comparison_immediates()` filters to `value >= 0x100`, dismissing smaller constants as
"loop bounds and sizeof-style noise". That is defensible for ranking and wrong as a hard
floor: `off_by_one`'s own comparisons are `cmpl $0x20`, and a small gate constant is
invisible to the recoverer today.

Rev 1 said "rank rather than exclude, and record the change as affecting candidate order —
not as a new capability claim." **Both halves of that were wrong**, and the review was
right on each.

**It is not an order change, it is a set change.** Selection is
`sorted(found, key=lambda v: (v.bit_length(), v))[:limit]`. With the floor removed, `0`,
`1`, loop bounds and `sizeof` constants sort *first* by bit length and consume the 24
slots, so a real higher gate can be **truncated out of the set entirely**. Relaxing a
filter in front of a truncating sort changes what is delivered, what `is_applicable`
returns, and therefore what can be credited. Ranking and truncation have to be redesigned
together or not touched:

- **Partition instead of ranking a single stream.** Keep a per-bucket reservation —
  low-value candidates get a bounded share of the budget and cannot evict high-value ones,
  and every candidate retains its `(addr, mnemonic)` record either way.
- **Acceptance test that would have caught it:** a fixture with **more than 24 distinct low
  loop and size comparisons plus one real higher gate**, asserting the gate survives
  selection. Rev 1 specified no such test, and none of its five checks would have failed.

**And the regex recognises fewer encodings than §3 claims.** Measured in §0.3: `cmpb` and
`cmpw`, and the suffixed `test` forms, cannot match; and a gate wider than 32 bits leaves
no immediate at all. So this section's scope is now explicitly:

| gap | closed here? |
| --- | --- |
| `value >= 0x100` floor discarding small gates | yes — via partitioned selection |
| `cmpb`/`cmpw`/`testb`/`testw`/`testl`/`testq` unmatched | yes — extend the alternation. **Measured gain: 7 of 32 cells** (§0.4) |
| `value <= 0xFFFFFFFF` ceiling | **moot**, but not for the reason rev 2 first gave — see below |
| gates wider than 32 bits | **no** — reachable only by also scraping `movabs`. A tradeoff, not a wall. Disclosed, not fixed. |

The ceiling is moot because a 64-bit constant is materialised by `movabs` and compared
register-to-register, so it is never a *comparison* immediate — raising the ceiling alone
closes nothing, which is the same shape as rev 1's §0 finding about calling
`comparison_immediates()` and changing nothing.

But §0.4 corrects the stronger claim this section made in its first draft: the constant
**is** present in the disassembly, as `movabs $0x…`, so 64-bit gates are *not*
structurally out of reach — they are reachable by widening the scrape to `movabs`/`mov`
immediates, at the cost of a large increase in noise. That is a design tradeoff to take
deliberately later, not a limitation to hide behind now. **The honest argument for keeping
option C on the table is the 18-of-32 unrecovered cells and the `-O2` flip, not an
imaginary wall.**

**Forward consistency with §1**, which the review flagged: §1 argues `13_off_by_one`'s
`0xdeadbeef` is not recoverable, and its only comparisons are `$0x0`, `$0x20`, `$0x0`.
Removing the floor makes `0x0`/`0x20` *recoverable*, so after this change the executor
becomes **applicable** on that target instead of skipping. §1's conclusion is unaffected —
`0xdeadbeef` is still not recoverable, it is still an assignment not a comparison, and the
target is still VOID — but the *mechanism* changes from "skips" to "attempts two
provenanced values and fails honestly", and that is the behaviour to expect in the re-run.
Rev 1 implied a skip there. It would not have skipped.

## 4. Verification required

Rev 1 listed five checks. The review's PASS 1 showed **every one of them could be
satisfied while adding nothing** — the decisive criticism of the revision, and the reason
this section is rewritten around one end-to-end invariant instead of five component
checks.

**4.1 The sink invariant — the only check that tests the precondition itself.**
For every gate-value payload delivered during a run, record the value and require it to
match a `GateCandidate` from that target's own `GateRecovery` by `(value,
instruction_addr, mnemonic)`. Assert **delivered ⊆ recovered** over the whole R1 and R2
corpora, and additionally reconcile every *credited* target's strace against that record.
Rev 1 had no delivery-level oracle at all: its §4.1 asserted `0x1337` appears in the
objdump stream and that the helper returns it, which does not establish that the executor
delivered *that* occurrence. The hollow satisfaction the review named — "show `0x1337` in
objdump and in output without proving the output came from that instruction" — is closed
only by carrying the address through.

**4.2 The status matrix must be red in each cell independently.** Induce each
`RecoveryStatus` and require a distinct, correct outcome: `objdump` absent from `PATH`;
`objdump` present but exiting nonzero; a timeout; a target that disassembles cleanly with
no comparisons; and a normal target. The first three must report **NOT MEASURABLE**, not
"no gate immediates". A single "recovery returned empty" test passes in all five cells
and distinguishes nothing.

**4.3 Mutation, wrong-but-present, at the sink rather than the helper.** The review named
rev 1's version as hollow: a helper-level assertion can fail while the delivery path stays
hardwired. So mutate the **sink**: make the provenance check accept any value, and require
a red from the corpus-wide assertion in 4.1. Then separately mutate recovery to return a
fixed non-empty *provenanced-looking* list with fabricated addresses, and require the
address reconciliation to catch it.

**4.4 The §0.3 fixture matrix, run in full.** Operand widths {8,16,32,64} × {`cmp`,`test`}
× signedness × {`-O0`,`-O2`}. Record per cell whether the constant appears as an immediate
and whether it is recovered. This is the sweep §0.3 owes; the mnemonic alternation may not
be extended until the matrix says which encodings actually occur.

**4.5 The truncation fixture.** More than 24 distinct low loop/size comparisons plus one
real higher gate; assert the gate survives selection. None of rev 1's checks would have
failed on the truncation defect.

**4.6 Budget, measured before and after.** Per-target wall time for this executor on the
worst target in R1 and R2, recorded pre-change and post-change. Post must not exceed pre.
`limit` comes down until it holds. A gross "deliveries removed" count is not evidence
(§2A′).

**4.7 Re-run R1 and R2 and reproduce 13/13 and 4/15 target-for-target** — with the
caveat the review raised and rev 1 missed: **reproducing the solved set can succeed
through a remaining invalid route**, so this check is necessary and not sufficient, and it
only means anything *in conjunction with* 4.1. Both figures were re-run post-import-fix
and reproduced exactly, so the baseline is current and any movement is attributable. If
either moves, that is the finding and it is reported before anything else.

**4.8 Sweeps re-run after the change, with the corrected nine-literal pattern** (§0.2a),
and the §0.1 disposition re-confirmed: all 26 out-of-scope files still out of scope, with
the count stated against its commit. A fix
that introduced a single-constant guess would satisfy the narrow `MAGIC_VALUES *=` sweep
and be invisible to it. Print the iteration count and check the exit status (§5).

**4.9 `is_applicable` needs a positive instance on both sides** — true on one target,
false with a populated reason on another — **and** a case where recovery succeeded but
every recovered value is irrelevant, whose expected result is *applicable, attempts, fails*
(not a skip). That third case is the one that documents the retracted observability claim
in executable form.

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

---

## 6. Answers to the round-1 findings

Verdict answered: **NOT-APPROVED**, 3 BLOCKING / 6 MAJOR / 1 MINOR. Every finding is
accepted except where marked. Two are accepted with a **correction to the reviewer**, and
both corrections were measured, not argued.

```
FINDING  B1 - Option A prescribes no disposition for every live folklore source
INSTANCE enhanced_auto.py had no action; strategy.py only to be "stated"
CLASS    an instance-shaped remedy for a class-shaped defect: N edits at N known
         sites, where site N+1 reintroduces the defect and passes every check
SWEEP    replaced, not enumerated - §2A' moves the check to the delivery sink, so
         the remedy's extent is "every candidate source that exists or will exist"
OTHERS   the three lists become dead code; a missed one is inert, not exploitable
SCOPE    diagnosis was "three sites unaddressed"; remedy is "no site can deliver an
         unprovenanced value". Remedy is WIDER than the diagnosis, deliberately -
         equal extent here would mean three more edits and the same defect class.
RADIUS   §2A withdrawn and rewritten; §4 rewritten around the sink invariant; §3's
         "capability claim" wording corrected; §1's conclusion re-checked, unchanged
```

```
FINDING  B2 - the wider sweep is literal-shaped and omits one of the nine literals
INSTANCE the §0.1 pattern had 0x1337bab3 but not bare 0x1337
CLASS    syntactic occurrence search used as proof of semantic absence
SWEEP    re-ran with all nine literals over all 228 tracked .py
OTHERS   28 -> 29 files. The one addition is
         benchmark/reference_exploits/14_negative_index_reference.py, a reference
         exploit using the target's real gate value - out of scope. 0 additional
         in-scope instances; §0.1's disposition survives, its instrument did not.
SCOPE    ACCEPTED WITH A LIMIT STATED. The reviewer is right that no literal sweep
         proves behavioural absence - decimal forms, computed values, imported
         aliases, packed bytes and non-.py sources are all invisible to it. I am
         not claiming otherwise, and I am not building an AST scan: §2A' makes the
         literal inventory non-load-bearing, because the sink refuses an
         unprovenanced value whatever spelling produced it. The sweep is retained
         as an aid to deleting dead code, not as the proof.
RADIUS   §0.1 count corrected; §0.2a records the omission; §4.8 re-runs corrected
```

```
FINDING  B3 - removing the fallback turns infrastructure failure into "not applicable"
INSTANCE exceptions caught to an empty list; proc.returncode never checked
CLASS    error-as-empty collapse at a measurement boundary - a sentinel that is
         representable as a legal measurement
SWEEP    enumerate every outcome of the recovery step: objdump missing, nonzero
         exit, timeout, clean disassembly with no matches, matches found
OTHERS   five outcomes, rev 1 would have reported four of them identically. The
         nonzero-returncode path is a LIVE defect today, not only a hazard of the
         change: the function decodes proc.stdout without checking the exit code.
SCOPE    diagnosis and remedy are equal in extent - the status enum has exactly one
         member per enumerated outcome, and only DISASSEMBLED_NO_MATCH may be read
         as evidence about the target. The other four yield NOT MEASURABLE.
RADIUS   §2A' bullet 2; §4.2 requires each cell red independently
```

```
FINDING  M4 - is_applicable tests for any immediate, not the relevant gate
INSTANCE 13_off_by_one has 0x0/0x20; §3 makes them recoverable; predicate returns true
CLASS    proxy predicate conflating incidental evidence with the observed event
SWEEP    not applicable - the claim was withdrawn rather than repaired
OTHERS   none; ACCEPTED IN FULL and rev 1's observability claim is RETRACTED
SCOPE    relevance is undecidable without reading held-out source, so the honest
         remedy is to stop claiming the observable and disclose the residual. The
         residual is now bounded in one direction only: a WRONG gate value cannot be
         delivered; a MISSING one cannot be detected. Stated, not glossed.
RADIUS   §2A' "what A' does not do"; §3 forward-consistency note; §4.9 third case
```

```
FINDING  M5 - the regex recognises selected spellings of the instruction class
INSTANCE cmpb/cmpw and testb/w/l/q unmatched; <= 0xFFFFFFFF ceiling
CLASS    an extractor recognising one encoding of a construct, described as
         recognising the construct
SWEEP    compiled a probe with byte/32-bit/64-bit gates, -O0, disassembled with the
         exact objdump command (§0.3)
OTHERS   CORRECTION TO THE REVIEWER, measured. (i) The mechanism is CONFIRMED -
         cmpb $0x0 and cmpq $0x0 are present in real output and unrecovered.
         (ii) The stated example was NOT reproduced - gcc compiled the byte gate
         `c == 0x41` to a register `cmp $0x41`, which the regex matches, so
         recoverability of a byte gate is a codegen question. (iii) The ceiling is
         the WRONG mechanism for 64-bit gates: the constant is materialised by
         movabs and compared register-to-register, so there is no immediate at any
         filter setting. Raising the ceiling would close nothing while looking
         like a fix - the same shape as this plan's own §0 finding.
SCOPE    (iii) is a STRUCTURAL limit of recovered-only and is disclosed, not fixed.
         The mnemonic alternation is not extended until §4.4's matrix says which
         encodings occur - the fixture matrix is owed and is named as owed.
RADIUS   §0.3 new; §3 scope table; §4.4; §2C's C-option argument strengthened
```

```
FINDING  M6 - "rank rather than exclude" keeps a truncating sort that drops the gate
INSTANCE sorted(key=(bit_length, v))[:24] with the floor removed promotes 0/1/bounds
CLASS    filter relaxation without redesigning ranking and truncation together
SWEEP    fixture with >24 distinct low comparisons plus one real higher gate
OTHERS   none beyond this selection site
SCOPE    ACCEPTED IN FULL, including the sharper half: it is a SET change, not an
         order change. Rev 1's "record it as affecting candidate order, not a new
         capability claim" is withdrawn - it changes the delivered set, hence
         applicability, hence what can be credited. Remedy is partitioned
         selection with a bounded low-value share, equal in extent to the defect.
RADIUS   §3 rewritten; §4.5 adds the fixture; §1's 13_off_by_one mechanism updated
         from "skips" to "attempts two provenanced values and fails honestly"
```

```
FINDING  M7 - gross removal counted, net replacement search not
INSTANCE "removes 126 deliveries" with no count of the replacement
CLASS    gross-removal accounting presented as net resource analysis
SWEEP    count both sides by READING THE LOOP, not by parsing a constant's name
OTHERS   rev 2 "corrected" 126 to 117 and was WRONG - see the retraction in §0.2b.
         126 stands (14 buffer sizes x 9). Replacement at limit=24 is 14 x 24 = 336:
         a net INCREASE of 210, which is round 1's original figure.
SCOPE    equal - §4.6 makes measured worst-case wall time a binding acceptance
         criterion with limit as the lever, replacing a talking point with a gate.
RADIUS   §2A' cost paragraph; §0.2b; §4.6. The 126 figure is corrected everywhere
         it appeared.
```

```
FINDING  M8 - verification checks component output and outcomes, not delivery provenance
INSTANCE §4.1 asserted objdump contains 0x1337 and the helper returns it
CLASS    component and outcome tests substituted for an end-to-end causal invariant
SWEEP    ask of each of rev 1's five checks: can it be satisfied while adding
         nothing? The reviewer's PASS 1 answered yes for all five.
OTHERS   all five, which is why §4 is rewritten rather than amended
SCOPE    equal - §4.1 carries (value, instruction_addr, mnemonic) through to the
         sink and asserts delivered subset-of recovered corpus-wide; §4.3 moves the
         mutation to the sink so a hardwired delivery path cannot survive it.
RADIUS   §4 entirely; §2A' consequence 3
```

```
FINDING  M9 - "if R3 produces a real one, C becomes the honest answer" adapts on held-out
INSTANCE §2C's flip condition
CLASS    adaptive development against a corpus reserved for cold measurement
SWEEP    scan this plan and the R5 spec for any other clause conditioning a design
         or parameter choice on a held-out observation
OTHERS   none in this plan. The R5-spec scan is now RUN (it was owed): one match in
         364 lines, and it is the PROHIBITION, not a violation - "if the pipeline is
         then tuned against R5 and re-measured on R5, the result is no longer
         held-out". That spec's Problem 2 already states the single-use policy,
         recommends measure-once, and lists confirmation of it as an open decision
         for the maintainer. So rev 1's flip clause did not merely slip - it
         CONTRADICTED the governing policy in the document it cites as its own
         blocker, which is worse than a local error and is why it was withdrawn
         outright rather than qualified.
         Sweep identity and limit, stated: the scan matched adaptation PHRASINGS
         (if/after/once R3-R5, then tune/adjust/revisit/switch/flip, retune,
         iterate on). It cannot see an adaptation expressed without those verbs.
         It is an aid, not a proof; the binding control is the freeze-and-hash in
         §2C, which does not depend on having found every such sentence.
SCOPE    equal and binding: freeze-and-hash the implementation and configuration
         before R3 is unsealed, record the hash with the results, and prohibit any
         policy change, re-run or tuning between or during R3/R4/R5.
RADIUS   §2C rewritten. The flip condition is replaced by one that can only be
         settled on a fixture whose source may be read.
```

```
FINDING  M10 - load-bearing topology and count claims unverifiable from the brief
INSTANCE "three live sources", "14 sizes x 9 values", "1 of 17 without is_applicable"
CLASS    scope premise asserted without the evidence for independent verification
SWEEP    re-derive each by parsing the source rather than by reading it
OTHERS   of the three: one I wrongly "corrected" and have now retracted (126 was
         right all along, §0.2b), one CONFIRMED (17
         TechniqueExecutor subclasses, exactly 1 without is_applicable, and it is
         VariableOverwriteExecutor, §0.2c), one superseded by §2A' (the count of
         live sources stops being load-bearing once the sink binds all of them).
SCOPE    equal - every count in this revision now states the parse that produced it.
RADIUS   §0.2; §2A'; §0 site table
```

**Not accepted as stated:** none outright. Two accepted with measured corrections (B2's
limit, M5's example and mechanism), and both corrections are recorded above rather than
argued in prose.

**Round-1 recurrence check:** this is round 1, so no class can be a recurrence. The
tripwire for round 2 is any finding whose class appears in §6 — that would mean a sweep
above was skipped.

Of the three sweeps rev 2 first recorded as owed, **two are now run and reported**:

| owed sweep | status |
| --- | --- |
| §0.3 encoding fixture matrix | **RUN** — §0.4. Refuted two of §0.3's own conclusions. |
| M9 scan of the R5 spec | **RUN** — clean, and it reframed M9 as a policy contradiction. |
| §4.8 post-change sweep re-run | **still owed** — cannot run before the change exists. |

The third is owed by construction rather than by omission, and it is named so a round-2
finding there reads as *sequenced*, not as *skipped*.

**One class recurred inside this very revision, and it is mine.** §0.4's Correction 1 is
the third instance this session of *asserting absence from a search narrower than the
claim* — the rule I wrote into §6.1b of the review protocol. Rev 2 caught it only because
the matrix was run. Had the matrix stayed "owed", a false "absent from the disassembly
entirely" would have gone to round 2 as a finished finding. **The lesson for the round
budget: a sweep recorded as owed is not a mitigated risk, it is an unmeasured claim still
standing in the document.**

---

## 7. What rev 3 has NOT done, and the decision that now belongs to the maintainer

Round 2 returned **9 of 10 round-1 findings as RECURRENCE**. Under this project's own
protocol that is not a scorecard, it is a diagnosis: *answers were written at the instance
level for defects that were classes.* I accept it. The single class underneath most of the
nine:

> **A membership test was substituted for a causal one.** §2A′ requires a delivered gate
> value to *equal* some recovered value. It never requires the delivery to have *originated
> from* that recovery. So the folklore list can still choose `0x1337`, and the sink will
> find a genuine `cmp $0x1337` record in `14_negative_index` and bless it — **the exact
> target in this plan's own §1 table.** The contract as written would launder the precise
> case the plan exists to prevent. That is not a gap in the contract; it is the contract
> testing the wrong proposition.

The remedy round 2 names is right and rev 3 does not attempt it in this pass: one
authoritative recovery result mints **tokens bound to the target's binary digest**, exactly
one delivery API accepts them, candidate *selection* is structurally unable to consult
folklore membership, and fault injection proves every real producer and write route rejects
wrong-source, wrong-target and fabricated tokens. That is an implementation design, not a
paragraph — it needs the producer/sink inventory round 2 asked for
(`rg -n -C 12 'comparison_immediates|MAGIC_VALUES|GateCandidate|send(line|after)?\(|process\(|communicate\(|stdin\.write' supwngo/exploit`)
before it can be specified honestly, and that inventory is **not yet run**.

### The round budget is the constraint, and it is nearly spent

One round remains. **Round 4 escalates; it does not proceed.** So spending round 3 on a
design that still has an unrun inventory underneath it risks burning the budget and landing
in escalation anyway. Two ways forward, and the choice is the maintainer's because it trades
scope against the thing being protected:

**Option 1 — spend round 3 on the token redesign.** Run the producer/sink inventory, specify
the contract against it, submit for round 3. If round 3 comes back clean, implement and the
R3/R4/R5 cold measurements are unblocked with the invalid-credit channel genuinely closed.
If it does not, escalation. *Cost:* the three cold measurements stay blocked meanwhile.

**Option 2 — decouple the blocker from the redesign.** Delete `MAGIC_VALUES`,
`FALLBACK_MAGIC_VALUES` and the unconditional append outright, and **give
`VariableOverwriteExecutor` no candidate source at all** pending the redesign. The executor
becomes inert. On the measured evidence this costs **zero credited targets** — it has won 0
of 17 across R1 and R2 — and it closes the invalid-credit channel *completely and
immediately*, because a technique that delivers nothing cannot deliver an unprovenanced
guess. The redesign then becomes a capability project on its own timeline, not a blocker on
three single-use corpora.

**My recommendation is Option 2**, and the reason is the round budget rather than the
engineering: Option 1 asks a nearly-exhausted review budget to ratify a design whose
foundation is unmeasured, to protect credit that has never once been won. Option 2 is
smaller than the plan I have been defending for two rounds, and that is the argument for it.

*What would flip me to Option 1:* evidence that `variable_overwrite` is the only route to
some target family that R3/R4/R5 actually contain — which cannot be checked without reading
held-out sources, so it cannot be established. That asymmetry is itself an argument for
Option 2: the case for keeping the technique is unfalsifiable, and the case against it is
measured.

**Both options still require** the §4 verification set as rewritten, the held-out scoping
control in §0.1, and — for Option 2 — a test that the executor's inertness is *declared*
(an explicit skip with a reason) rather than silently produced, so that a future reader
cannot mistake "no candidates by design" for "no candidates recovered".

---

## 8. The producer/sink inventory, run

Round 2 said the token design could not be specified honestly until every candidate
producer and every delivery route was enumerated, and rev 3's §7 recorded that inventory as
unrun. It is now run — index-scoped per §0.1, non-vacuity 77 tracked `.py` under
`supwngo/exploit/`. It is reported here because it serves **both** options in §7: option A
needs it as a foundation, option B needs it to know the deletion's blast radius.

### Producers — three consumption sites, not three definitions

| site | code | delivers via |
| --- | --- | --- |
| `stack_techniques.py:79` | `for magic in MAGIC_VALUES:` | `verifier.verify_payload()` |
| `enhanced_auto.py:384` | `for magic in self.MAGIC_VALUES:` | `self._test_variable_overwrite()` |
| `input_shape_techniques.py:104` | the unconditional append | returned to its one caller |

### Two facts that change the design, both of which correct earlier sections

**1. `comparison_immediates()` has exactly ONE real caller**, and it is not the executor
this plan has been about. It is `input_shape_techniques.py:240`, inside
`NegativeIndexWriteExecutor` — which already records provenance in its attempt notes
(*"candidate gate values from the binary's own cmp insns"*). So the recovery function is
narrow, single-consumer, and its existing consumer is the honest one.

**`VariableOverwriteExecutor` does not call `comparison_immediates()` at all.** It reads the
raw list. This sharpens §0's finding about the R5 spec's preferred remedy: that remedy was
not "change existing wiring so it uses recovered values", it was **new wiring that does not
exist** — and the unconditional append would have defeated it on arrival. Both halves had
to be wrong for the remedy to fail, and both were.

**2. There are TWO live delivery sinks, in different subsystems.** Round 2's highest-value
change asks for "one named, unavoidable delivery API". Today there are two:
`verifier.verify_payload()` on the pipeline path, and `_test_variable_overwrite()` inside
`enhanced_auto.py`. And `enhanced_auto` is **live, not legacy** — `cli.py:328` and
`cli.py:416` both construct `EnhancedAutoExploiter`, from the `exploit` command (`cli.py:247`).

The benchmark measures the pipeline (`autopwn` → `CanonicalAutopwnEngine`), so
`enhanced_auto` is **off the benchmark path** — which means it cannot corrupt a corpus
figure, and equally means fixing only the pipeline leaves a user-facing command still
guessing from the cheat sheet. That distinction was not drawn anywhere in revisions 1–3, and
it is the difference between "the measurement is sound" and "the tool is sound". Both
matter; only the first blocks R3/R4/R5.

### What this does to the two options in §7

- **Option B (delete, executor inert)** is **7 edits across 4 files**: three list
  definitions, three consumption sites, one advisory string. `comparison_immediates()`
  survives intact for its single legitimate caller once the append is removed, and
  `NegativeIndexWriteExecutor` is unaffected. Blast radius fully enumerated; nothing is
  guessed at.
- **Option A (token contract)** is larger than round 2 assumed, because "one unavoidable
  delivery API" requires either unifying two sinks across two subsystems, or scoping to the
  pipeline and **declaring `enhanced_auto` out of scope in writing** — which is honest but
  leaves the `exploit` command guessing. The recovery side is the easy half: one function,
  one caller.

This inventory does not decide between them. It does make option B's cost fully known and
option A's cost larger than stated, which is information the §7 decision should have.
