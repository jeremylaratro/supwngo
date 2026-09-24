# Walkthrough family: format string (arbitrary read + arbitrary write)

Date: 2026-09-24
Status: REVISED after peer review — see "Peer review and revisions" at the end.
Review: `docs/plans/2026-09-24-walkthrough-family-fmtstr-review.md`
(gpt-5.6-sol, reasoning effort xhigh, read-only; verdict NOT-APPROVED on the
first draft, 10 blocking findings, all addressed below)
Branch: `feat/walkthrough-fmtstr-family-20260924` (based on
`feat/walkthrough-engine-20260923` @ `cfaa24e`)
Implements: the format-string section of
`docs/plans/2026-09-24-walkthrough-families-fmtstr-heap-integer.md`
(highest-priority of the three families in that spec)

## Goal

Add `walkthrough/families/fmtstr.py` with two routes — **arbitrary read**
(`%N$p` / `%N$s`) and **arbitrary write** (`%n` family) — so that format-string
targets get a real 0-to-pwn teaching walkthrough instead of falling through to
guided triage (or, worse, to a stack route that cannot work).

This is a teaching gap, not a capability gap — but the premise needs stating
precisely, because the first draft of this plan got it wrong and the reviewer
caught it.

The "5/5 under strict attribution" round-1 result for 05 and 06 was produced by
`executors/fmtstr_techniques.py` (`FmtStrWriteGateExecutor`), which lives on
`integration/phases-0-4-7-20260923` at commit `6e3de10` and is **not on this
branch**. What this branch has is `FormatStringExecutor` in
`pipeline/executors/stack_techniques.py`, whose own docstring says it "currently
always yields PARTIAL (a template), never SUCCESS", and
`docs/reports/PHASE1-BASELINE-24SEP2026.md` accordingly records 05 and 06 as
FAILED.

So: the *technique* is solved and proven elsewhere in this repo, and this work is
the explanatory layer over it rather than new exploitation research. But on this
branch the walkthrough engine is doing measurement no executor here performs, so
"the pipeline already owns solving, therefore the explainer need not verify" is
**not** a licence to skip verification. Every route below is executed end to end
against the real binaries, and the write route's payload shape is taken from the
integration-branch executor rather than reinvented.

## What the targets actually are (measured, not assumed)

Everything below was measured by hand against the built corpus before writing
this plan. It is recorded here because the design decisions rest on it.

`05_fmtstr_arbread` (canary ON, NX, no PIE, Partial RELRO, dynamic):

| fact | value | how it was measured |
| --- | --- | --- |
| format-argument index | **8** | `AAAAAAAA\|%1$p\|…\|%20$p` — `0x4141414141414141` came back at `%8$p` |
| canary slot | **25** | 3 runs of a windowed `%N$p` sweep: slot 25 differs every run, low byte `00`, not a userspace pointer (`0xbfa7cf26ac46f600`, `0x3fa759731c51ff00`, `0xaf1ccfbe8efdf200`) |
| saved rbp / retaddr slots | 26 / 27 | slot 26 is a `0x7ff…` stack value that changes per run; slot 27 is `0x401361`, constant, inside `.text` (a return into `main`) |
| overflow buffer → canary | **72** | staged padding sweep: `k=72` exits 0, `k=73` aborts with `*** stack smashing detected ***` (rc `-6`) |
| cross-check | 72 | `objdump`: `buf` is at `-0x50(%rbp)`, canary at `-0x8(%rbp)` → `0x50-8 = 72` |
| `%N$s` arbitrary read | works | `%9$s....` + `p64(0x400318)` printed `/lib64/ld-linux-x86-64.so.2` |
| end-to-end | flag | leak slot 25, then `b"A"*72 + canary + b"B"*8 + p64(win)` as the **second** write → `FLAG{…}` |

`06_fmtstr_arbwrite` (canary OFF, NX, no PIE, Partial RELRO, dynamic):

| fact | value | how it was measured |
| --- | --- | --- |
| format-argument index | **6** | same marker probe; marker at `%6$p` |
| gate variable | `unlocked` @ `0x40405c` | the program prints it (`unlocked @ 0x40405c`), it is a program-owned writable global, and `vuln()`'s disassembly does `mov 0x2dc7(%rip),%eax; test; je` then `call 4011b6 <win>` |
| gate flip | works | `b"AAAA%7$n" + p64(0x40405c)` → `FLAG{…}`, rc 0 |
| GOT redirect | `fflush@got` → `win` | `fmtstr_payload(6, {0x404030: 0x4011b6}, write_size="byte")` = 64 B (fits the 127-byte read) → `FLAG{…}`, rc **0** |
| GOT redirect that does *not* work | `puts@got` | `win()` itself calls `puts`, so redirecting `puts` recurses until the stack dies (rc `-11`, no flag). Verified under gdb: execution does reach `win`, then dies. |

That last row is the single most useful thing the measurement turned up: the
"obvious" GOT target is the wrong one, for a reason that is a property of this
binary, and the walkthrough can only know it by looking.

Baseline routing today (`probe=False`): both 05 and 06 select
`stack_bof / ret2win`. For 05 that route cannot work — the canary aborts in
`__stack_chk_fail` long before `ret`. So this family is not taking work away
from a family that was succeeding.

## Approach — two options weighed

### Option A (chosen): probe in the fact layer, family stays pure

A new module `walkthrough/fmtstr_probe.py` owns the dataclass and every probe.
`facts.py` gains ~8 lines: one `TargetFacts` field and one gated call inside
`collect_facts`. `families/fmtstr.py` consumes normalised facts only, so
`propose()` remains side-effect-free (there is an existing test asserting
`propose_routes` is repeatable).

* Matches the stated architecture: `facts.py`'s own docstring calls itself "the
  **single seam** between the walkthrough engine and the rest of supwngo", and
  `probe_offset_with_gdb` already lives at that seam. Dynamic measurement
  belongs there, not in a family.
* Honours `probe=False` uniformly: no fmtstr facts → the family abstains.
* Keeps the bulk of new code in a file no other concurrent agent touches
  (the integer-family agent is also editing `families/__init__.py` and
  `registry.py`), so the merge surface is two one-line registrations plus a
  small, contiguous `facts.py` addition.

Cost: `collect_facts` runs the target a few dozen times on binaries that import
`printf`. Bounded below.

### Option B (not taken): probe inside `families/fmtstr.py::propose()`

Zero edits outside the new module plus the two registrations — the smallest
possible merge surface.

Rejected because it makes `propose()` execute the target. That breaks the
family contract (`propose` is a pure verdict function, and route proposal runs
for *every* family on *every* binary), it would run binaries even when another
family wins, and it puts binary-execution machinery somewhere a reader of
`families/` would never look for it. The merge-surface win is not worth
inverting the layering.

**What would flip the decision:** if `facts.py` turns out to be a genuine
conflict hotspot — i.e. the integer agent rewrites `collect_facts` rather than
appending to it — Option B becomes the pragmatic choice, because the probe is
self-contained enough to move with a ~15-line diff. The dataclass and all probe
functions live in `fmtstr_probe.py` precisely so that move stays cheap.

### Also considered and rejected

* **Brute-forcing the GOT candidate at generation time** (run the binary once
  per writable GOT entry and keep whichever prints something new). It would
  work — that is how the measurement above found `fflush` — but it turns the
  explainer into a solver, and the pipeline already owns solving. Instead the
  candidate is *derived* statically from `objdump` (first PLT call after the
  vulnerable `printf`, minus anything `win()` itself calls) and the reader's
  step *verifies* it dynamically. Derive statically, verify dynamically.
* **Reusing `common.offset_step`** for the read route's overflow. Rejected: the
  cyclic probe needs a SIGSEGV at `ret`, and a canary target aborts in
  `__stack_chk_fail` first, so that step is actively misleading here. The read
  route drops the `OFFSET` constant entirely and introduces
  `SMASH_OFFSET` / `RET_OFFSET`, measured the way a canary target actually
  permits. Explaining *why* the usual offset step does not apply is itself
  worth teaching.

## The format-argument index is the one constant that may never be assumed

It is `MEASURED` or it is `UNKNOWN`. There is no `ASSUMED` path.

Measurement (`probe_format_argument_index`): send an 8-byte marker followed by a
*windowed* `%lo$p|…|%hi$p` chain and look for `4141414141414141` in the output.
Windowed because the vulnerable buffer cannot hold forty specifiers at once —
05's `name[64]` truncated a 20-slot chain mid-way.

Three discriminations the probe must make, because each one is a way to be
confidently wrong:

1. **The marker is the verdict, and it is checked first.** Literal echo is
   *not* grounds for rejection — a program can echo input safely and format it
   unsafely later in the same run — so echo only ever *explains* a negative, it
   never produces one.
2. **Hex in the output is not proof.** 06 prints `unlocked @ 0x40405c` on a
   benign run, so "`0x` appeared" false-positives. The verdict is the marker
   coming back, corroborated by a hex-token *count* differential against a
   benign run (a count, not values — values move with ASLR) and by a paired
   `%%N$p` control probe that a hex dumper cannot distinguish itself from.
3. **Interpreted but marker not found** → the format-string bug is real (the
   read route stays applicable) but the index is `UNKNOWN` with the probe step
   named as its resolver, and the *write* route is withheld: `%n` cannot be
   authored without the index.

Evidence recorded on the fact: the literal probe command, the window that hit,
and the slot table itself.

## Structure

New: `supwngo/exploit/walkthrough/fmtstr_probe.py`

* `FormatStringFacts` — `reachable`, `arg_index`, `slots` (per-slot values
  across N runs), `canary_slot`, `retaddr_slot`, `smash_offset`,
  `overflow_stage`, plus `Confidence`/`Evidence` and `failure_reason`.
* `probe_format_argument_index(path)` — the marker/window sweep above.
* `probe_slot_table(path, runs=3)` — windowed `%N$p` sweep, N runs, so
  per-slot volatility is observable.
* `classify_slots(table, *, path, vuln_function, arg_index)` — **anchored, not
  shape-searched.** Find the return-address slot: value constant across runs
  *and* a member of the return-address set that `objdump` gives for
  `call <vuln>`. From the x86-64 frame layout the canary is then
  `retaddr_slot - 2` and saved `rbp` is `retaddr_slot - 1`; the canary slot is
  *checked* against `_looks_like_canary` (volatile across runs, low byte `00`,
  not a mapped pointer) rather than found by it, and saved `rbp` corroborates.
  A shape search alone is unsound — a decoy slot can satisfy every predicate —
  and the pointer-band exclusion must not assume 48-bit VAs, since LA57 puts
  legitimate pointers above 2^48.
* `probe_smash_offset(path)` — staged padding sweep, tried as write #1 and as
  write #2, recording which framing produced the abort. Only runs when the
  canary is on.
* `derive_write_targets(...)` — printed pointers inside writable sections,
  program-owned writable globals referenced by `vuln()`, and the GOT-redirect
  candidate from `objdump` call order minus `win()`'s callees.

Changed (minimal, additive):

* `facts.py` — one `TargetFacts` field, one gated call in `collect_facts`.
* `families/__init__.py` — add `fmtstr` to the import tuple and `__all__`.
* `registry.py::_families()` — add `fmtstr` to the list.
* `CHANGELOG.md` — `[Unreleased] / Added`.
* `tests/test_walkthrough_fmtstr.py` — new.

## Routes and scoring

`propose()` abstains unless a format-string bug was *observed*. "printf is
imported" is not a reason to speak — that would be the binary-independent
filler the registry docstring exists to forbid.

| condition | route | score |
| --- | --- | --- |
| bug observed, index measured, gate variable guarding a `win` call | arbitrary write | 0.92 |
| bug observed, index measured, no gate but writable GOT + win function | arbitrary write | 0.80 |
| bug observed, canary ON, smash offset measured | arbitrary read | 0.90 |
| bug observed, index measured, nothing to write to | arbitrary read | **non-applicable** — `UNMET_PRECONDITION` + `becomes_viable_if` |
| bug observed, index UNKNOWN | arbitrary read | 0.55, applicable, index resolved by the probe step |

`propose()` constructs *all* candidate routes and returns `max(key=score)`; it
is not a first-match if/elif chain, so no reordering of the conditions can
change the verdict.

Canary-on read outranks the GOT-only write (0.90 > 0.80) because on such a
target the canary leak *is* the unlock; the gate-variable write outranks
everything (0.92) because it is a one-directive exploit. This routes 05 → read
and 06 → write, which is what the two targets are for.

## Steps

Read route (6): `preflight` (shared) · `verify_targets` · `argindex` ·
`stackmap` · `writeoffset` · `fire`.

Write route (6): `preflight` (shared) · `verify_targets` · `argindex` ·
`gateflip` · `writesize` · `fire`.

Every step carries WHY THIS STEP / EXPECT TO SEE / HOW YOU KNOW IT WORKED /
TROUBLESHOOTING (symptom → cause → fix) plus DO IT YOURSELF manual commands,
per the established shape.

Teaching content the spec asks for, and where it lands:

* **Stack-layout dependence** — `argindex` and `stackmap`: slots 1–5 are
  `rsi/rdx/rcx/r8/r9`, 6+ are stack qwords at the call site, which is why the
  index is a property of one compilation and not a number to copy from a
  writeup.
* **Read that leaks a canary vs write that redirects control flow** — the two
  routes state it explicitly, and `writesize` demonstrates it: the gate flip
  changes *data* (a one-directive write), the GOT redirect changes *control
  flow* (a six-byte write into a function pointer).
* **Write-size decomposition** — `writesize`: `%hhn` 1 byte, `%hn` 2, `%n` 4,
  `%lln` 8, and why byte-at-a-time wins: one wide `%n` would require printf to
  emit the *value* as a character count, so writing `0x4011b6` in one directive
  means emitting 4.2 million characters (and `%lln` an unreachable 2^48).
  Byte-at-a-time caps each directive at 255 emitted characters, at the price of
  one address slot per byte written and ascending ordering (a count can only
  grow).

  The reference payload is the real `%182c%11$lln%91c%12$hhn%47c%13$hhn` +
  three addresses verified against 06 — and it is worth reading carefully,
  because it is *not* one address per byte of the value and the earlier draft of
  this plan described it as if it were. `0x4011b6` has three significant bytes
  but the payload uses `%lln` for the first of them, not `%hhn`:

  | directive | running count | writes |
  | --- | --- | --- |
  | `%182c%11$lln` | 182 = `0xb6` | all 8 bytes at `target+0` ← `0x00000000000000b6` |
  | `%91c%12$hhn` | 273 = `0x111` | 1 byte at `target+1` ← `0x11` |
  | `%47c%13$hhn` | 320 = `0x140` | 1 byte at `target+2` ← `0x40` |

  The `%lln` is an *optimization*: writing the low byte with an 8-byte directive
  simultaneously zero-fills bytes 1–7, so the five high bytes of the old pointer
  (`0x00007f…` or a stale PLT stub address) never have to be written
  individually. It saves five directives and five address slots — which is what
  made the payload fit 06's 127-byte read at all.

  Its precondition is the thing to teach: **the 8 bytes at `target` must all be
  yours to zero.** That holds for a GOT slot (exactly 8 bytes, wholly owned) and
  for `unlocked` only if the 7 bytes after it are padding. Where it does not
  hold — a target adjacent to live data, or a value whose high bytes must be
  non-zero — you fall back to `%hhn` per byte and pay for it in payload length.
  Both forms are shown, and the emitted script uses whichever the measured
  `echo_capacity` admits.
* **The two `%n` traps**, both load-bearing and both invisible until you hit
  them: padding must come *before* the directive (a leading `%n` writes 0 and
  flips nothing), and the target address must come *after* it, 8-byte aligned
  (the address's NUL bytes terminate printf's format parsing, but by then the
  write has already happened and the varargs slot still reads the raw stack).

## Test strategy — literal execution, not rendering

Rendering is not verification. The first wave's four real defects were all
invisible to review: a false claim about a leak's leading byte (`vm.mmap_rnd_bits`),
a `NameError` on an undeclared constant at the reader's first command, a route
made unreachable by a `"FUNC"`-vs-`"STT_FUNC"` filter, and protections
defaulting to unprotected when `Binary._elf` was absent.

`tests/test_walkthrough_fmtstr.py`, corpus-gated (skip when unbuilt):

1. **Route selection** — 05 → `fmtstr` / arbitrary read, 06 → `fmtstr` /
   arbitrary write, with `probe=True`.
2. **Every step executes *and observes something*.** For both targets, render to
   a temp file and run `python3 wt.py <n>` for every step. Exit status 0 is
   necessary but not sufficient: `render.py`'s dispatch treats `result is not
   False` as success, so a step returning `None` "passes" and an exit-status
   assertion would accept a no-op. Each step therefore asserts a
   **step-specific observation** — `argindex` prints the measured index and it
   must equal the fact, `stackmap` prints a canary whose low byte is `00`,
   `gateflip` prints the control differential. Exit status alone is what the
   first wave's `NameError` needed; observations are what a silent no-op needs.
3. **The assembled exploit runs and wins, against a same-shape control.**
   `b"flag" in out` is prohibited as a verdict — and so is "differs from a benign
   run", because both targets echo the format string, so *any* payload differs
   from benign whether or not the write landed. The control is a payload of
   identical shape and length with the primitive removed: for 06, `%n` → `%p`;
   for 05, the same overflow with a deliberately wrong canary (which must abort
   where the real one must not). The emitted script uses the same criterion, and
   offers a gdb read of the target as an independent manual confirmation.
4. **The index is MEASURED and carries its command** — assert
   `confidence is MEASURED` and that the emitted comment names the probe
   command. Plus a negative: a hand-built facts object whose probe found no
   marker must render `FMT_INDEX` as `UNKNOWN` naming its resolving step, and
   must *not* offer the write route.
5. **Abstention** — every non-fmtstr corpus target must have the family return
   `None` from `propose`, so no binary-independent filler enters other
   walkthroughs' decision trees.
6. **No canary value is ever a constant** — the canary is a `runtime` fact; a
   `MEASURED` canary *value* in the constants block must fail the test. (The
   first wave's leading-byte defect in this exact shape.)
7. **Verification refuses, not warns** — digest mismatch warns; a write target
   that does not hold the expected bytes makes the step return `False` (exit 1).
   Note the test must target *this family's* `verify_targets` step, not
   `common.preflight_step`: preflight only verifies declared `G_*` gadgets, so
   patching a non-gadget constant would not make it refuse and the test would be
   unfalsifiable.
8. **Unit tests over purpose-compiled fixtures**, for the classification paths
   the corpus does not exercise: a decoy slot satisfying every canary shape
   predicate, a SIGABRT from an unrelated cause, a target where smash stages 1
   and 2 coalesce, a program that echoes safely *and* formats unsafely, and a
   hex dumper that prints pointers without interpreting a format string.

Each new test is run against unfixed code first to confirm it can fail. A test
that cannot fail is worse than no test; this project has found four.

## Risks

| risk | mitigation |
| --- | --- |
| The probe runs the target during fact collection | Gated on `printf` in PLT/symbols *and* `probe=True`; bounded run count; per-run timeout; all runs in a temp cwd |
| A target that hangs waiting for more input | Every probe uses a hard timeout and closes stdin |
| `smash_offset` sweep misattributes a crash | The verdict is specifically `*** stack smashing detected ***` / `SIGABRT`, not "it crashed"; the sharp `k`/`k+1` boundary is asserted, and `objdump` gives an independent cross-check in the manual commands |
| Canary-slot heuristic picks a libc pointer | Userspace-pointer band excluded (this is why slot 13 — `0x72fd7c417600`, low byte `00` — is rejected); requires volatility across runs |
| The GOT candidate is wrong on another build | It is `DERIVED`, labelled as such, and the step that uses it verifies differentially and says what to try next if it fails |
| Merge conflict with the integer family | Edits to `families/__init__.py` and `registry.py` are one line each; everything else is a new file |

## Definition of done

* [ ] Both routes implemented and registered; family abstains elsewhere.
* [ ] Format-argument index `MEASURED` with its command, never `ASSUMED`.
* [ ] Every generated step and the assembled exploit **executed** against 05
      and 06, with real output pasted into the report.
* [ ] New tests verified to fail against unfixed code.
* [ ] `CHANGELOG.md` updated under `[Unreleased]` in the same commit.
* [ ] No corpus vulnerability or verification logic weakened.

## Peer review and revisions

Reviewer: gpt-5.6-sol, `model_reasoning_effort=xhigh`, `--sandbox read-only`,
non-interactive with file handoff. Verdict on the first draft: **NOT-APPROVED**,
12 findings (10 blocking). Full text:
`docs/plans/2026-09-24-walkthrough-family-fmtstr-review.md`.

Two of the findings were factual challenges to claims in the draft. I verified
both against the repo before accepting them; both were correct and both are
corrected above.

### 1. Dangling `OFFSET` constant would fail `Walkthrough.validate()` — ACCEPTED

`common.base_constants()` unconditionally emits `OFFSET`, and when the cyclic
probe fails it emits it as `UNKNOWN` with `resolved_by="offset"`. Neither fmtstr
route has an `offset` step, so `validate()` would reject the walkthrough at
construction — on 05 in particular, where the probe *does* fail because
`__stack_chk_fail` aborts before `ret`.

Fix: both builders filter `OFFSET` out of `base_constants()` explicitly (not by
index, not by truthiness) and substitute their own `SMASH_OFFSET` /
`RET_OFFSET`. Test: construct with `facts.offset.probe_failed = True` and assert
the walkthrough builds.

### 2. `FMT_INDEX` UNKNOWN data flow was circular — ACCEPTED

The draft had the `argindex` step both produce and resolve `FMT_INDEX`, which
`Fact.__post_init__` forbids (`resolved_by` may not name the producing step), and
had later steps `consume` a name that may be UNKNOWN, which
`_validate_consumption` forbids.

Fix: adopt exactly the `common.offset_step` shape — `FMT_INDEX` is the UNKNOWN
constant with `resolved_by="argindex"`; the `argindex` step *produces* a distinct
`runtime=True` fact `FMT_INDEX_MEASURED`; downstream steps declare `consumes`
conditionally on the index being known.

### 3. Canary classification by shape alone is unsound — ACCEPTED (already built)

The reviewer's objection is right and the implementation already answers it: the
shipped `classify_slots()` does not pick the canary by shape. It anchors on the
**return-address slot** (value constant across runs *and* a member of the set of
addresses `objdump` shows being pushed by `call <vuln>`), then takes
`canary_slot = retaddr_slot - 2` from the x86-64 frame layout, and only then
gates that slot on `_looks_like_canary` as a *check* rather than a search. The
saved-`rbp` slot at `retaddr_slot - 1` corroborates. The plan text above
described the abandoned shape-search; it is wrong and this section supersedes it.

Two additions taken from the review: note that the userspace-pointer band
exclusion must not assume 48-bit VAs (LA57 gives 5-level paging and pointers
above 2^48), and add unit fixtures for a **decoy** slot that satisfies every
shape predicate but is not the canary.

### 4. Smash-offset verdict was too loose — ACCEPTED

Three sub-issues, all accepted:

* *Stage mis-attribution.* Already partly fixed by execution before review (see
  "Defects found by execution" below): the sweep now tries `stage=2` before
  `stage=1`, because a single blob spills from `read(0,name,63)` into
  `read(0,buf,200)` and 63+72=135 is a true fact about a framing the exploit
  never uses. Additionally: reject a `stage=1` result when
  `offset >= echo_capacity`, since that is exactly the spillover signature.
* *`rc == -6` is not evidence.* Dropped. The verdict now requires the glibc
  message (`*** stack smashing detected ***` / `*** buffer overflow detected`)
  in the combined output. A SIGABRT from any other cause no longer counts.
* *Boundary sharpness.* The `k`/`k+1` boundary check is repeated, and the
  measured offset is cross-checked against the `lea -0xNN(%rbp)` displacements
  `objdump` reports in `vuln()` — on 05, `0x50 - 8 = 72`, an independent
  derivation of the same number, which is emitted as a manual command.

### 5. Arg-index probe could reject a real bug and accept a fake one — ACCEPTED

* *Do not reject on literal echo.* A program can echo input safely *and* later
  format it. Order inverted: look for the marker first; consult the count
  differential second; use literal echo only to *explain* a negative verdict, not
  to produce one.
* *Hex-dumper false positive.* Added a paired control probe: alongside `%N$p`,
  send `%%N$p` (a literal `%` followed by the text). A program that interprets
  will print `%N$p` for the control and pointers for the probe; a hex dumper or
  echo-with-decoration prints the same shape for both. Disagreement between the
  pair is the signal.
* *Buffer alignment.* If the vulnerable buffer is not 8-byte aligned relative to
  the varargs window, the address-after-directive layout needs pad bytes this
  plan has not tested. Detect it and **withhold the write route** rather than
  ship untested pad arithmetic; the read route survives.

### 6. Option A's justification was inaccurate — ACCEPTED (non-blocking)

The draft argued Option A avoids executing the target before family selection.
It does not: `collect_facts(probe=True)` runs the binary too. The real difference
is *where* the execution lives and how often it happens, not whether it happens.
Option A still wins on that narrower ground (one measurement pass shared by all
families, and `--no-probe` disables it in one place). The draft's "fall back to B
on conflicts" line is removed — it was hedging, not a plan. Added: a hard budget
of process spawns and wall-clock for the whole probe, so a pathological target
cannot stall fact collection.

### 7. Scoring could steal a route from a family that works — ACCEPTED

* The leak-only route at 0.62 is removed as a *score*. When there is nothing to
  write to and no canary to unlock, the route is constructed **non-applicable**
  with an `UNMET_PRECONDITION` rejection and a `becomes_viable_if`, so it cannot
  outrank a working family — it can only speak when nothing else does.
* The unverified GOT-only write drops 0.86 → **0.80**.
* `propose()` builds *all* candidate routes and returns `max(..., key=score)`
  rather than first-match if/elif, so the ordering of the conditions cannot
  change the verdict.

Measured mitigation, so this is not theoretical: with `probe=True` on this
branch, 05 and 06 currently attract only `triage` at 0.15 — `stack_bof`'s
ret2win is non-applicable at 0.30 and `rop_chain` abstains. The new family takes
nothing from a family that works.

### 8. The differential success criterion was self-scoring — ACCEPTED (important)

This is the sharpest finding. Both targets **echo the format string**, so the
exploit's output always differs from a benign run even when the write misses
entirely. "Output differs from benign" would therefore have passed a broken
exploit — precisely the class of defect the brief says review cannot catch.

Fix, in both the emitted script and the test suite: the differential baseline is
a **same-shape control payload**, not a benign run.

* 06: control is the identical payload with `%n`→`%p` (identical length, identical
  echo, no write). The exploit's output must contain what the control's does not.
* 05: control is the identical overflow with a deliberately wrong canary — same
  length, same echo, and it must *abort*; the real one must not.

Plus an independent, non-differential check offered as a manual command: read
`unlocked` out of memory with gdb after the write, so the reader can confirm the
primitive rather than infer it from stdout.

### 9. Tests were not falsifiable — ACCEPTED

`render.py`'s dispatch treats `result is not False` as success, so a step that
returns `None` "passes" and "every step exits 0" accepts a no-op. Revised test
plan:

* Assert **step-specific observations**, not exit status: the `argindex` step must
  print the measured index and it must equal the fact; `stackmap` must print a
  canary whose low byte is `00`; `gateflip` must show the control differential.
* The canary-constant negative asserts on the family's *produced facts*, not on
  rendered text.
* The abstention sweep runs with real probing (`probe=True`), not a stub.
* New unit tests over purpose-compiled fixtures: a decoy canary-shaped slot, a
  SIGABRT from an unrelated cause, a target where stage 1 and stage 2 coalesce,
  a program that echoes safely *and* formats unsafely, and a hex dumper.

Every new test is run against the unfixed code first and must fail there.

### 10. The preflight negative test contradicted the implementation — ACCEPTED

`common.preflight_step` verifies only declared `G_*` gadgets, so patching a
non-gadget constant to a bogus address would not make it refuse. The negative
test instead targets this family's own `verify_targets` step, which must return
`False` (exit 1) when the write target does not hold the expected bytes. Digest
mismatch remains a warning; verification failure is a refusal.

### 11. The plan's premise contradicted this branch — ACCEPTED, premise corrected

Verified: `pipeline/executors/fmtstr_techniques.py` does not exist on
`feat/walkthrough-engine-20260923`. What exists is `FormatStringExecutor` in
`pipeline/executors/stack_techniques.py:288`, whose docstring says it always
yields PARTIAL and never SUCCESS, and `docs/reports/PHASE1-BASELINE-24SEP2026.md`
records 05 and 06 as **FAILED**. The "5/5 under strict attribution" result
belongs to `FmtStrWriteGateExecutor` on `integration/phases-0-4-7-20260923`
(`6e3de10`).

The Goal section above is rewritten accordingly. The consequence for this work:
"the pipeline already solves it, so the explainer inherits correctness" is not
available as an argument on this branch. The payload *shapes* are borrowed from
the integration-branch executor; the *correctness* is established by executing
this family's own output.

### 12. Write-size text contradicted its own reference payload — ACCEPTED

The draft said byte-at-a-time costs "one address slot per byte" and then quoted a
payload using `%lln` + 2×`%hhn` with three addresses. Corrected in the Steps
section above with the per-directive table, the zero-fill explanation, and the
precondition that makes the optimization legal.

### Defects found by execution before this review

Recorded here because they are the evidence for the brief's claim that rendering
is not verification; all four were found by running the probe across all 15
corpus targets, and none were visible in the draft.

1. **False-positive reachability on 01 and 03.** The differential compared hex
   token *values*, and both programs print their own ASLR'd pointer, so a value
   diff always reported something new. Replaced with a token *count* differential,
   which is ASLR-invariant. Both now abstain correctly.
2. **Wrong smash offset on 05** (135/stage 1 instead of 72/stage 2) — the
   spillover framing described in finding 4.
3. **An unreachable GOT target offered on 05.** `fflush@got` was listed although
   the byte-at-a-time payload is 64 bytes and 05's read accepts 63. Added
   `estimate_byte_write_size()`, `WriteTarget.fits_budget`, and a
   `usable_write_targets` filter.
4. **A link-time file offset presented as a runtime address on 03.** The read
   demo picked `0x318`; `%s` on it segfaults. `pick_read_demo_address()` now
   refuses under PIE.

Separately, found with gdb before any code: **`puts@got` is the wrong GOT
redirect on 06.** `win()` calls `puts`, so redirecting `puts` recurses until the
stack dies (rc = -11, no flag). `fflush@got` is correct (called right after the
vulnerable `printf`, not used by `win`): rc = 0, flag printed. This is why
`derive_write_targets` excludes `win()`'s own callees.

## Late revisions (after the integer family landed)

The `integer` family landed while this was in test and reported findings that
apply here. Each was checked against this family rather than assumed:

13. **Score ties are resolved by `registry._families()` list order.**
    `generate_walkthrough` selects with `max()`, and `max()` keeps the *first*
    maximal element, so two families with equal scores are ranked by the position
    of their module in a list whose own docstring calls the order "presentation
    only". Two ties existed and neither was visible on targets 05/06, because on
    both of those the competing route is non-applicable:

    - the read route's 0.90 was exactly `stack_bof`'s ret2shellcode, and
    - the GOT-redirect write route's 0.80 was exactly `syscall`'s ret2syscall.

    Fixed by naming the scores (`SCORE_WRITE_GATE`, `SCORE_WRITE_GOT`,
    `SCORE_READ_CHAIN`, `SCORE_READ_UNMEASURED`) with the whole cross-family
    ordering recorded as a table in the module, and moving the two colliding
    values: read 0.90 → **0.91**, GOT 0.80 → **0.82**. The two placements that
    are judgements rather than bookkeeping are argued in that table — the read
    route sits *above* ret2shellcode because its chain variant only exists on a
    canary-protected frame, where the leak is a prerequisite of the overflow
    rather than a competitor; the GOT redirect stays well below the gate flip
    because *which* GOT entry to hit is derived from call order rather than
    measured, making it the one route here with a non-MEASURED constant.
    Guarded by an AST test that reads every `score=` literal out of every family
    module and asserts disjointness, plus a test that reverses `_families()` and
    requires the winner not to move. Option not taken: raising the GOT route into
    the 0.9 band to match the gate flip. That would have broken the tie too, but
    it would also have let a partly-derived route outrank ret2shellcode and SROP
    on some future binary, which the evidence does not support. What would flip
    it: measuring the GOT-entry choice (e.g. by observing the call order at
    runtime) rather than deriving it.

14. **A guard that no end-to-end test can falsify.** Mutation testing showed the
    stage-1 spillover guard inside `probe_smash_offset` could be deleted with the
    whole suite still green: the stage-2 sweep succeeds first on every corpus
    target, so the branch is never taken. Extracted to `_is_spillover(stage,
    offset, echo_capacity)` with a four-case unit test, plus a separate test that
    patches it to reject everything and requires the sweep to then report no
    offset at all — because a correct predicate nobody calls is the same defect
    in a different place.

15. **Name the disagreement instead of silently overriding it.** `_shared_constants`
    drops `OFFSET` by name (the generic cyclic probe cannot measure it on a canary
    target — `__stack_chk_fail` aborts before `ret`), but the reasoning lived only
    in a source docstring. A reader who re-ran the framework's own probe, got
    nothing, and compared it with `SMASH_OFFSET = 72` had no way to tell which
    number to trust. `_measurement_discrepancies()` now emits an extra
    `ProtectionVerdict` naming both instruments, why the generic one is silent,
    and that the two names mean different quantities (buffer→return address vs
    buffer→canary, two slots apart). Pattern borrowed from the integer family's
    handling of `elf.canary` disagreeing with its function-level verdict.

Also checked and found not to apply: `common.protection_verdicts` is called with
`TargetFacts` (not `ProtectionFacts`); this family corrects no fact, so the
preflight step and the header see the same object; and the column-0 `dedent_code`
trap was already hit and fixed earlier by converting the three multi-line steps
to `splice()`.

Regression sweep over all 15 round-1 targets after the score change: 01 keeps
`stack_bof`/ret2shellcode, 02 keeps `rop_chain`/ret2plt, 03 and 07 keep
`rop_chain`/ret2libc-via-GOT-leak, 09 keeps `syscall`/SROP, 15 keeps
`stack_bof`/ret2win, 04/08/10/11/12/13/14 keep `triage`, and this family abstains
entirely on all 13 non-format-string targets. Only 05 moved, from 0.90 to 0.91.
