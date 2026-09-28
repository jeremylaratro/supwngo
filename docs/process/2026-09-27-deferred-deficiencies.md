# Deferred deficiencies — 2026-09-27

Logged under the standing instruction to keep building and record problems for
later rather than stopping on them. Nothing here blocked a solve; everything here
is a known weakness in what was shipped, or a measurement gap.

Provenance labels: **measured** (I ran it), **recorded** (from an artifact, cited),
**inferred** (reasoned, not observed).

---

## 1. Solve state after this session

| Target | Before | After | Technique | Provenance |
|---|---|---|---|---|
| `rocket_blaster_xxx` | SOLVED | SOLVED | `ret2libc_leak` | recorded (`benchmark/results_htb/rebaseline-nolegacy-20260927.json`) |
| `snow_scan` | NOT_SOLVED | **SOLVED 3/3** | `container_file_rop` | measured (`snowscan-confirm-20260927.json`) |
| `ancient_interface` | TIMEOUT ×3 @300s | **SOLVED 3/3** | `eintr_accumulator_rop` | measured (`ancient-confirm-20260927.json`) |
| `sick_rop` | NOT_SOLVED | **SOLVED** | `srop_symtab_pivot` | measured (single `solve` run + generated-script run) |
| `sabotage` | NOT_SOLVED | NOT_SOLVED | — | recorded |
| `bon-nie-appetit` | NOT_SOLVED | NOT_SOLVED | — | recorded |
| `auth-or-out` | TIMEOUT ×3 @300s | not re-measured | — | recorded |

**1/7 → 4/7.** The ≥5/7 target (T-1′) is **not** met. See §4 for what blocks the
remaining three, with the bug in each already located.

`T-2` (challenge-variations ≥5/7) is **0 and unmeasurable**: the challenge-alike
variation corpus does not exist. See §3.1.

---

## 2. Deficiencies in what was shipped

### 2.1 `container_file_rop`

**Mostly CLOSED on 2026-09-27 (evening) by the generalisation pass — see §6.**
The four bullets marked ✅ below were the target-shaped assumptions; they are
replaced by facts derived from the binary or probed from the target. What remains:

- **Probabilistic, by design.** Success depends on the unknown low byte of the
  buffer base. Unchanged and irreducible — it is stack ASLR. Handled by a `ret`
  sled sized to exactly the deltas the derived geometry allows, plus a sweep of
  the 32 possible 8-aligned bytes. Now stated as a constraint rather than hidden
  in a search: only the low byte is writable, so the shift is
  `(base_low + chosen) mod 256`, and if that sum exceeds `0xff` the pointer moves
  *backward* by ~256 instead of forward.
- **A split parser still routes to the blind sweep.** If the header is validated
  in one function and the fill loop runs in another — which is exactly what the
  measured HTB target (`snow_scan`) does, validating in `loadBitmap` and looping
  in `main` — the parsed fields live in a frame that is already gone by the time
  the loop runs. The analysis declines rather than mixing two frames, and the
  blind sweep handles it (measured: `snow_scan` still solves). This is the largest
  remaining gap and the obvious next increment.
- **The size-field oracle needs the target to echo the field back.** Locating the
  base slot is measured against the printed size value. A target that parses a
  size and never prints it has no anchor, and falls back to the blind sweep.
- **It ignores the resolved delivery sink.** A file path in argv *is* the
  technique, so it writes its own file and spawns the target itself. It is
  allowlisted in `FILE_DELIVERY_ALLOWLIST` on that ground — but that means under
  `--input-vector argv` it will still use file-argv rather than the declared bare
  -argv sink. Honest-but-surprising; worth either a sink-specific gate or a
  louder note in the report. **Still open.**
- ✅ ~~The `size_image` values tried (400, 900, 512) are snow_scan's accept
  rule.~~ The accept window's immediates are now read out of the validator's
  compares and confirmed by probing the target, whose exit status distinguishes
  accepted from refused.
- ✅ ~~Only BMP has a real envelope.~~ The header is synthesised from the
  literals the validator actually demands (`memcmp` magics and inlined byte
  compares) with zero everywhere else — and zero is load-bearing, not filler: it
  satisfies equality-between-fields (a square-dimensions test) and multiplicative
  consistency (`byte_rate == sample_rate * block_align`) without having to
  recognise either. Measured working on BMP, RIFF/WAVE, and a private 16-byte
  header.
- ✅ ~~`base_off` search band is `size_image + 8 .. size_image + 140`.~~ The
  base slot's index is now measured, not swept.
- ✅ ~~Gadget requirements were too strict.~~ The chain demanded a bare
  `pop rdx; ret`, which a statically linked glibc frequently does not contain
  (only `pop rdx; pop rbx; ret`). This aborted the generated script before it
  tried anything — it was the reason the executor scored **0/5** on the variation
  corpus including the anchor, and it would have been invisible without that
  corpus. Register setters now accept the longer forms and pad the chain.

### 2.2 `eintr_accumulator_rop`

- **Assumes same-second timers all deliver.** All 16 timers are armed for the
  same second so the cycle costs ~2s instead of ~18s. Measured 16 armed → 16
  delivered on this host. SIGALRM is a standard signal and does **not** queue, so
  on a slower or more heavily loaded machine two expiries could coalesce and the
  cursor would land short. There is **no fallback** to 1-second-spaced arming,
  and no detection of a short landing — it would simply fail. This is the most
  likely source of future flakiness.
- **Uses the host's libc.** The leak is resolved through `p.libc.path`. A target
  shipping its own loader/glibc under `./glibc/` (as four of the HTB targets do)
  would need that honored instead.
- **Stage 2 re-enters `main`**, which re-runs `setup()` and leaks the previous
  `VARS.kv` allocation. Harmless here; untidy, and it would matter on a target
  where `setup()` had side effects.
- **`_find_prompt` falls back to `b"$ "`.** A target with no prompt-shaped string
  would desynchronise rather than fail cleanly.

### 2.3 `srop_symtab_pivot`

- **Depends on the symbol table surviving.** The pivot is a `.symtab`
  `st_value` field. A fully stripped binary (no `.symtab`) loses every candidate
  and the gate refuses. The technique also depends on `p_filesz` not being
  page-aligned, so the file tail is mapped — true here, not guaranteed.
- **`mprotect`s the whole image RWX and executes shellcode.** Fine for this
  target; it is an NX bypass that assumes `mprotect` on a private file mapping is
  permitted.
- **`_find_count_returning_wrapper` matches only `mov eax,1` (write).** Any other
  count-returning syscall (`recv`, `pread`) would be missed.
- **The offset search band is 8..128 step 8.** Inferred; a larger frame is outside
  it.

### 2.4 Across all three

- **No unit tests.** All three are validated only end-to-end, by the engine
  reaching `SHELL_ACCESS` under the re-score harness's behavioural attribution.
  There is no test that any of them can go **red** for the right reason, which is
  exactly the gap the validation-first rule exists to close. Their gates are
  narrow enough that a silent-pass is unlikely, but that is an argument, not a
  measurement.
- **`verify_script` owns stdin**, so each generated script reads its own stdin and
  bridges it into the obtained shell. That coupling is undocumented in
  `verifier.py`; a future script author will rediscover it the hard way.

---

## 3. Measurement gaps

### 3.1 The challenge-alike variation corpus (T-2) — **CLOSED for one category**

~~`benchmark/corpus_vectors/` varies the **transport** (how the payload arrives),
not the challenge. There is no corpus that holds a challenge's shape and varies
its particulars, so "≥5/7 on challenge variations" cannot be measured at all —
neither passed nor failed.~~

`benchmark/corpus_variants/` now exists for the container-file
metadata-sized-overflow category: an anchor reproducing the measured HTB target,
four variants each changing exactly one particular, and a negative control whose
fill loop is bounded. Manifest at `benchmark/corpus_variants.yaml`; validated as
an oracle before use by `benchmark/reference_exploits/container_variants_reference.py`
(all five positives RED, control not, under a byte-identical attack).

So generalisation is now **measured** for this one category rather than inferred —
see §6. The other two categories (`eintr_accumulator_rop`,
`srop_symtab_pivot`) still have no variation corpus and remain **inferred**.

### 3.2 M-1b's second negative control was never built

`docs/process/2026-09-26-standard-work-queue.md:330` specifies two negative
controls, `90_neg_argv_echo_no_open` and `91_neg_config_flag_stdin_payload`, both
required to FAIL. What exists is `90_ingress_neg_no_open` (a true negative, and it
does FAIL) and `91_ingress_neg_paired_open`, documented at
`benchmark/corpus_vectors.yaml:140` as a *paired positive* control that MUST
solve. So **nothing currently tests whether the engine over-claims when a
declared transport is wrong** — and the near-identical slug makes the absence
invisible at a glance. The M-1b gate reads as met and is not.

### 3.3 Pre-existing test failures (not caused by this work)

`tests/test_i2_attempt_duration.py` — **6 failed, 7 passed**, all
`AttributeError: 'CanonicalAutopwnEngine' object has no attribute '_force_all'`
from tests that call `_attempt_techniques` without going through `__init__`.
Measured identical (6 failed, 7 passed) in a worktree at `40129ab`, i.e. before
any of this session's pipeline changes; `_force_all` was introduced by `1e26373`.
Listed here so it is not silently absorbed into this effort.

### 3.4 `D-1` — the legacy fallback's fate is still undecided

Carried from `docs/process/2026-09-26-standard-work-queue.md`. The measured
legacy baseline is 0/7 attributed, so there is no legacy capability to preserve,
but the fallback has not been removed either.

---

## 4. The three unsolved targets — bug located, chain not built

All three are PIE + Full RELRO + canary heap challenges. In each case the
vulnerability is identified; what is missing is the exploitation chain, and each
is a multi-hour build rather than a missing insight.

### 4.1 `sabotage` — unbounded heap overflow (measured, statically)

`Malloc(n)` allocates `n + 8` and stores `n` at `ptr[-8]`
(`sabotage:0xec5`). `enter_command_control` (`:0x169b`) reads the size with
`scanf("%lu")`, so **`n = -8` makes `Malloc` call `malloc(0)`** — which succeeds
and returns a minimum-size chunk. `readBuffer(ptr, n)` (`:0x1005`) then loops
writing one byte at a time until a NUL or newline *or* `i >= n`, and with
`n = 0xFFFFFFFFFFFFFFF8` that bound never trips: an **unbounded heap overflow**.

Afterwards the function does `setenv("ACCESS", ptr, 1)` and `system("panel")`.

Not converted to a shell because:
- `system("panel")` is a **relative** command name, so it resolves through
  `PATH`. That is only reachable by controlling the target process's
  environment — which the exploit script could trivially do, and which would
  prove nothing about the binary. Rejected deliberately: it would defeat the
  harness's own attribution rather than satisfy it.
- The legitimate route is heap corruption into `setenv`'s allocations (it
  `malloc`s a new `environ` array for a name not already present) under PIE +
  Full RELRO with no leak. Ordering is awkward: the overflow happens *before*
  the array exists, so it has to be a groom, not an overwrite.

### 4.2 `bon-nie-appetit` — `read` bounded by `strlen`, not by the allocation (measured, statically)

`edit_order` (`:0xf36`) ends with
`strlen(order)` → `read(0, order, that_length)` (`:0xfe3`–`:0x100d`). Fill a chunk
completely and `strlen` runs past it into the next chunk's size field, so the
read length exceeds the allocation — a controlled heap overflow over adjacent
metadata.

Not converted: needs the standard overlapping-chunks → libc leak (via
`show_order`'s `%s`) → tcache poisoning chain against the **shipped** glibc under
`challenge/glibc/`. Formulaic but long, and nothing partial is worth anything.

### 4.3 `auth-or-out` — custom allocator, not analysed in depth

Hand-rolled allocator (`ta_alloc`, `ta_free`, `insert_block`, `release_blocks`,
`compact`, `alloc_block`, `count_blocks`) over a `heap` array with
`heap_limit`/`heap_split_thresh`/`heap_alignment`/`heap_max_blocks`. PIE + Full
RELRO + canary. Previously TIMEOUT ×3 @300s. No bug located yet; the timeout
cause was not investigated after `ancient_interface`'s turned out to be a
non-terminating read loop.

---

## 5. Suggested order when this is picked up again

1. **`bon-nie-appetit`** — the bug is the most standard and the chain is the most
   formulaic of the three; best odds of a 5th seat per hour spent.
2. **Red-proofs and unit tests for the three new executors** (§2.4). Currently
   the strongest claim available for each is one end-to-end measurement.
3. **§3.2's missing negative control** — a gate that reads as met and is not is
   worse than a gate known to be absent.
4. **The variation corpus (§3.1)** — until it exists, T-2 has no number.
5. `eintr_accumulator_rop`'s signal-coalescing fallback (§2.2) — the most likely
   future flake.

---

## 6. Generalisation pass: container-file overflow (2026-09-27 evening)

Worked one category end to end — build a variation corpus, validate it as an
oracle, measure, generalise until the variants pass — rather than chasing target
count.

### 6.1 The numbers

| | Before | After | Provenance |
|---|---|---|---|
| Positives in `benchmark/corpus_variants/` | **0 / 5** | **5 / 5** | measured (`variants-baseline-20260927.json`, `variants-derived-20260927.json`, `--reps 2`) |
| Negative control `container_90_neg_bounded` | not solved | **not solved** | measured (both runs) |
| `snow_scan` (the HTB target this category came from) | SOLVED | **SOLVED** | measured (`snowscan-regress-20260927.json`, 2/2, 28.6s / 26.2s) |

Per-target after: all five positives at `SHELL_ACCESS` via `container_file_rop`
in 13–16s (previously the whole pipeline gave up on each in 14–18s).

### 6.2 What the corpus caught that the single target could not

**The executor scored 0/5 — including on the anchor, a target whose shape already
solved.** The cause was a bare `pop rdx; ret` requirement in the generated chain.
A statically linked glibc frequently has only `pop rdx; pop rbx; ret`, so the
script aborted before trying a single candidate. `snow_scan` happens to contain
the bare form, so with one target in the corpus this was invisible; the failure
mode was "technique attempted, no shell", which reads as a capability limit rather
than a bug. This is the concrete argument for variation corpora over target count.

### 6.3 Derived vs. probed vs. searched, after the pass

*Derived statically* (from the parse function's disassembly): header buffer and
`fread` length; the literal bytes the validator demands; each parsed field's
header offset and the immediates it is compared against; which field sizes the
buffer (traced into the VLA allocation); which field feeds `fseek`; and the
frame's relative distances (base slot → index, → `FILE *`, → saved RIP), which
are rbp-relative and therefore exact.

*Probed against the target*: which field values the validator accepts (exit
status is the oracle — every rejection path returns non-zero); and the absolute
payload index of the base slot.

*Searched*: the shift byte only — 32 values, with a `ret` sled sized to exactly
the deltas the derived geometry allows.

### 6.4 Two findings worth keeping

**A crash-based oracle for the base slot does not work, and fails silently.** The
obvious probe — "lengthen the payload until the process dies" — is unusable,
because corrupting the base pointer's low byte shifts the write cursor by
`(chosen - base_low) mod 256`, and when that lands negative the cursor walks
harmlessly *below* the buffer and the process exits perfectly cleanly. Whether a
long payload faults is a coin flip on stack ASLR. Measured: it reported the slot
at index 7824 when the real answer was 752, and the run still "passed" because the
blind fallback then won — i.e. a wrong measurement hidden by a working exploit.
The replacement measures against a value the target *prints* (the parsed size
field, which lives in a slot below the base pointer and so is reached while the
loop is still linear); that is deterministic and ASLR-independent.

**Zero is the right default for unconstrained header fields, not filler.** It
satisfies every equality-between-fields check (a square-dimensions test) and every
multiplicative consistency check (`byte_rate == sample_rate * block_align`)
without the analysis having to recognise either of them. This is what made a
single synthesised-header path work across BMP, RIFF/WAVE and a private 16-byte
format.

### 6.5 Fixture lessons (recorded because they are invisible in the sources)

- **Geometry, not just source shape, decides whether the primitive applies.** The
  anchor first took the `FILE *` as a parameter; gcc spills parameters to the
  *lowest* stack slots, which put the handle **below** the base-pointer slot, so a
  linear overflow destroyed the loop's own file handle before reaching the shift
  point — making the "faithful anchor" strictly harder than the target it was
  meant to reproduce. The measured target does its `fopen` inside the function
  holding the VLA, giving the handle a high slot at `rbp-0x8`. All six fixtures
  were changed to match.
- **The negative control cannot even be measured, which is the correct
  behaviour.** Its bounded loop never reaches the size-field slot, so the
  size-field oracle finds no boundary, the derived path declines, and the blind
  sweep exhausts (measured: 9486 candidates, no shell). It fails for the reason it
  is supposed to.

### 6.6 Still open in this category

- A **split parser** — header validated in one function, fill loop in another —
  routes to the blind sweep. This is exactly `snow_scan`'s shape (`loadBitmap`
  validates, `main` loops), so the real target is still solved by the fallback
  rather than by the derived path. Largest remaining gap; the analysis declines
  rather than mixing two frames, which is honest but not capable.
- The size-field oracle needs the target to **echo the parsed size back**.
- No unit tests for the analysis itself (§2.4 still applies). Its outputs were
  checked against the measured ground truth from the reference exploit on all six
  fixtures, which is a stronger check than a unit test would be, but it is a
  one-off rather than a gate.

### 6.7 Next category

Same cycle for `eintr_accumulator_rop` (signal-interrupted accumulator underflow)
and then `srop_symtab_pivot` (no-writable-segment SROP): build the variation
corpus, prove it can go RED both ways with a deterministic reference exploit,
measure, then generalise until the variants pass.

---

## 7. Five categories added 2026-09-28 — what is deferred

`toctou_path_race`, `uninit_disclosure`, `path_traversal_read`,
`library_path_hijack`, `heap_record_hijack`. All five are measured and merged
(`0d17df1`, `6d41e34`, `1615144`, `344dead`); everything below is a real
deficiency I chose to log rather than fix, per the standing "move forward and
build, log deficiencies for later" directive.

### 7.1 A solve that is not a captured flag

`uninit_disclosure` proves **`SHELL_ACCESS` with `flag=False`** on all five
positives. The disclosure leaks the bytes needed to reach a shell, but no target
in the family plants and reads back a flag, so the stronger oracle is untested
for this category. `toctou_path_race`, `path_traversal_read` and
`library_path_hijack` do reach `FLAG_CAPTURED`; `heap_record_hijack` is also
shell-only.

### 7.2 Two controls decline by wall clock, not by an exhausted ladder

`uninit_disclosure`'s control is "not solved" after **420.1 s of wall time**, and
`path_traversal_read`'s after **318.8 s**. A timeout and a genuinely exhausted
technique ladder are different claims, and only the second is evidence that the
corpus discriminates. `toctou_path_race`'s control does exhaust honestly (316.6
s), as does `heap_record_hijack`'s (146.9 s). The two timeout-based controls
should be given a cheaper shape or a longer budget before their narrowness is
described as proven.

### 7.3 `corpus_libhijack` cannot be provisioned from `cflags` alone

Every other corpus in the tree is reproducible from tracked sources plus a
`cflags` file. This one is not: `install_plugins.sh` has to run **before**
`build_all.sh`, and one target's `lib/` directory is legitimately **empty**,
which git cannot track. A fresh checkout that builds without reading the corpus
README therefore produces a target whose gate **declines** — and it declines for
a provisioning reason that looks exactly like a capability reason. This is the
worst of the five deficiencies, because it degrades silently.

### 7.4 `trav_14` depends on how deep the repository is checked out

Its truncation route needs room in a path buffer: **234 characters available, 95
used** at the current checkout depth. A deeper clone path shrinks that margin
until the route stops working, with no diagnostic that says so.

### 7.5 Both filesystem gates read `-O0` frame slots

`path_traversal_read` and `library_path_hijack` locate their operands at fixed
frame offsets that only hold at `-O0`. Untested at `-O2`, where the slots move or
vanish into registers. The corpora pin `-O0` in `cflags`, so the gates are
consistent with their own fixtures and will simply decline elsewhere rather than
misfire — but the category's reach is narrower than the CWE suggests.

### 7.6 Everything heap is pinned to glibc 2.35

`heap_record_hijack` depends on safe-linking, `tcache_count == 7`, the 0x410
tcache ceiling and the fastbin stash path. Pinned in `cflags` and stated in the
commit; untested on any other glibc. The same is true of the pre-existing
`tcache_poison_got` and `heap_strlen_ofb1`, so this is a framework-wide pin, not
a new one.

### 7.7 Ordering positions cost time to buy correct attribution

`heap_record_hijack` sits in `FIRST_TECHNIQUES` for **attribution, not speed**:
without the entry, `uaf`/`double_free` escalate into its shapes and are credited
with 4 of its 5 positives. The entry costs roughly **80 s per run** of earlier
attempts (100.8 s at that depth vs 20.5–20.9 s reached directly). Accepted
deliberately — a wrong technique label is a reporting defect no pass/fail count
would surface — but it is a real cost and the list will keep accumulating it.

### 7.8 One negative control opens its gate statically, by design

`heap_90_neg_handle_dropped` is the anchor minus one dynamic line, so static
analysis cannot tell them apart and the gate opens on it. Closing it statically
would make the corpus discriminate on a compile-time artifact instead of on the
primitive, so this is intentional — recorded here so a future sweep does not
"fix" it.

### 7.9 Two `FIRST_TECHNIQUES` names have no executor

`off_by_one_guard` and `heap_uaf_read` are ordered but unimplemented. The
orchestrator skips unknown names, so they cost nothing at runtime — but they read
as coverage in the one place a reader would look for it. See
`docs/reference/2026-09-28-vulnerability-category-coverage.md`.

### 7.10 Lessons that are invisible in the sources

- **A sweep that declines on everything looks like a perfectly narrow gate.** The
  sweep that eventually narrowed `heap_record_hijack` was preceded by one
  returning `opened=0` on all 133 images — *including its own positives*. Cause:
  `Binary(path)` instead of `Binary.load(path)`, which leaves the ELF unparsed so
  every image declines with a plausible-sounding reason. It was caught only
  because the script asserts its own positives must open. Any gate sweep without
  that assertion is decoration.
- **A family's own tests can pass while the family crashes.** `objptr_hijack`'s 66
  tests assert `_Analysis.complete is False` on declining targets and never call
  `propose()`, so a `TypeError` in the decline path was invisible to them and was
  caught by a different suite (`9ae5637`). This is the `I-23` class recurring:
  testing the analysis is not testing the thing that renders.
- **A mutation the model rejects proves nothing.** Red-proof mutations have to be
  wrong-but-present *and* structurally valid, or the model's own validation
  swallows them and the proof is vacuous.

### 7.11 Owed measurements

- A **solo re-run of `I-14`** on a quiet host. It fails as a 90-second
  `subprocess.TimeoutExpired`, and the gate that observed it was running
  alongside three compiling agents, so "defect" and "budget too tight under
  load" are currently indistinguishable (run-log row 47).
- A **post-integration whole-tree gate**. The 1588-passed figure was taken while
  the tree was being edited, which makes it a valid pre-integration baseline and
  nothing more.
- ~~A **gate sweep for `heap_record_hijack` run by me**. Its narrowing to 6 of 133
  images is the one number in this cycle I took from an agent without
  re-measuring.~~ **Done 2026-09-28 — see §7.12, and it found something.**

### 7.12 The re-measured heap sweep, and an attribution collision it found

Run by me over the tree as it stands: **159 ELFs swept, gate open on 12, raised
0**, mean 552 ms per image. Its own 6 open, as they must. The other **6 are the
brand-new `benchmark/corpus_allocsize/` family** — the allocation-size integer
overflow category being built the same day, which was told to reuse
`heap_record_hijack`'s destination shape (a function pointer published into a
heap record) rather than invent a new metadata attack.

So the agent's "6 of 133" was right for the tree it measured, and the narrowing
is intact: nothing *pre-existing* is captured. What the wider number exposes is a
**pending attribution collision**, not a gate defect. `heap_record_hijack` sits at
position 22 in `FIRST_TECHNIQUES`; unless `alloc_size_overflow` is ordered ahead
of it, the new category's positives will be credited to a technique that does not
implement wrapping arithmetic. This is the same class as §7.7 and has to be
settled by measuring which name the result is attributed to without `--strategy`,
not by reasoning about the list order.

Two process points worth keeping:

- **A shared destination creates a shared gate.** Telling a new category to reuse
  a proven destination is the right call for getting a solve, and the price is
  paid in attribution, always in the same direction: the older, already-ordered
  family collects the credit. Worth expecting rather than rediscovering.
- **The sweep helper has to match how the gate is reached.**
  `gate_sweep_generic.py` calls a module-level `analyse(path)`; a gate living in
  `Executor.is_applicable(context)` needs `context.binary`, `context.win_function`
  and `context.profile_has_menu`, which exist only after the profile stage. Run
  the wrong helper and it raises on all 159 images and prints `gate OPEN on: 0` —
  §7.10's trap with a different cause. `/tmp/gate_sweep_executor.py` builds the
  real context and asserts its own positives open, exiting 2 when they do not.

---

## 8. Three categories added 2026-09-28 (round 2) — what is deferred

`off_by_one_guard`, `fini_array_write`, `alloc_size_overflow`. Merged as
`576651c` and `2d6331a`. Same rule as §7: everything below is a real deficiency
chosen rather than discovered.

### 8.1 `I-33` — the bare `Binary(path)` constructor is the footgun, not the code it makes look broken

**Reported to me as "supwngo's own protection reporting is wrong", which it is
not.** Re-measured on `obo_10_loop_le_saved_rbp`:

```
Binary.load(path).protections  ->  NX Enabled   RELRO Full RELRO   (correct; agrees with readelf and pwntools)
Binary(path).protections       ->  NX Disabled  RELRO No RELRO     (every field its default)
```

The constructor returns a fully-formed object whose ELF was never parsed, so every
derived property reads as its default and **nothing indicates that**. This has now
produced a confident wrong measurement **twice in one day** by two independent
agents: once as a false framework-defect report, and once as a gate sweep that
printed `opened=0` for all 133 images *including its own positives* and read as a
flawlessly narrow gate (§7.10).

Not fixed here because the fix is a judgement call with reach: make `__init__`
parse, or make it refuse and force `.load()`. Either changes behaviour for every
caller. Logged, and corrected as an erratum beside the original claim in
`benchmark/corpus_offbyone/corpus_offbyone.yaml`.

### 8.2 `I-34` — `probe_prompt_sequence` primes with `creators[0]` and reads sequences short

In `heap_techniques.py` (~line 1591) the prompt probe uses `creators[0]` as its
prologue. On a target whose fill option refuses a record of the wrong kind, the
fill path rejects *before* printing its `data:` prompt, so the probe concludes the
option asks for an index alone. Consequence: `heap_record_hijack` reports
`edit() writes at offset None` and **under-reports its own capability**.

This matters beyond tidiness. `alloc_size_overflow`'s attribution is currently
correct partly *because* of this: `heap_record_hijack`'s gate opens on all six
`corpus_allocsize` targets and its deeper analysis declines them, and part of that
decline's stated reason is this bug. Fix it and that family may see further into
those images. The ordering entry was placed ahead of it precisely so attribution
does not rest on a defect continuing to exist — but the defect is still there.

The generalisable fix is known and was already written once, in
`allocsize_techniques.py`: probe each operating option **once per creator** and
keep the longest sequence observed. Not applied to `heap_techniques.py` because it
would change `heap_record_hijack`'s verdicts on two corpora at once, and that is a
measurement change to make deliberately rather than as a drive-by.

### 8.3 Four of five finaliser positives need a non-default link

`fini_array_write`'s loader-table route requires `-z norelro`. Measured on this
host (gcc 11.4.0, ld 2.38): at gcc's default Partial RELRO, `.fini_array` sits
inside `PT_GNU_RELRO` while its section header still advertises `WA`, and a store
there takes SIGSEGV. So the four loader-table targets are linked `-z norelro`,
pinned per target in `cflags`.

The honest consequence: on ordinary distro binaries the loader-table route is
largely dead, and only the fifth shape — Full RELRO, through a program-owned
shadow-validated table — still applies. **The category's real-world reach is
narrower than CWE-787 suggests**, and the corpus's 5/5 should be read with that in
mind. The `WA`-versus-`PT_GNU_RELRO` distinction is also a trap for any future
gate: a section-flag check would open on every Partial-RELRO image in the tree.

### 8.4 One category is probabilistic and two controls still decline on budget

`off_by_one_guard`'s saved-RBP route cannot be made deterministic:
`arch_align_stack` re-randomises the frame pointer's low byte per exec, and an
already-256-aligned one makes the one-byte write a no-op, capping any single
attempt at **15/16**. Measured per-target rates are recorded in
`corpus_offbyone/corpus_offbyone.yaml`. All three pivot targets land ~6 points
under their derived ceilings by almost the same margin across three different
geometries, which is labelled INFERRED rather than diagnosed — a geometry error
would move one target by a multiple of 1/16, not all three by the same amount.

On controls, the picture improved but is not uniform. `off_by_one_guard`'s control
is the **best in the tree**: it declines statically in 0.00 s naming the
discriminator, which I verified directly through `is_applicable`/`skip_reason`.
`fini_array_write`'s declines at 131.8 s and `alloc_size_overflow`'s at 189.2 s —
both still the ladder exhausting rather than a statement about the family. And
`alloc_size_overflow`'s control is **statically indistinguishable by design**, so
its gate opens on it; that one is deliberate (§7.8's reasoning) and should not be
"fixed".

### 8.5 An ordering seat was credited with a speed-up it could not deliver

Recorded because the mistake is easy to repeat. `alloc_size_overflow` was
recommended for the head of the heap block on the strength of a `--strategy` run
at 17.8 s versus 142.1 s in the tail. Measured, that seat gave 101.4–112.5 s — the
family was still paying `subprocess_injection`'s 72.9 s. Only the seat *ahead* of
`subprocess_injection` delivered 21.0–32.5 s. **`--strategy` bypasses the ladder;
an ordering entry does not.** A projected speed-up from a forced run is an upper
bound on what a seat can buy, not a measurement of it.

### 8.6 Still owed

- `subprocess_injection` burns ~72.9 s on every menu-driven target before
  declining (14 candidate payloads against a `system` import). It now dominates
  the cost of three families. Out of scope for these sprints, but it is the single
  largest latency item in the ladder.
- `benchmark/corpus_r2/08_int_mul_overflow` is solved by nothing in default
  ordering. Pre-existing; `alloc_size_overflow` correctly declines it (no
  allocator in the image) rather than papering over it.
- `heap_uaf_read` remains the last `FIRST_TECHNIQUES` orphan.
- The solo `I-14` re-run on a quiet host, still owed from §7.11.
