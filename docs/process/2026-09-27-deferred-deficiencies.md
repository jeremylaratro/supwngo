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

- **Probabilistic, by design.** Success depends on the unknown low byte of the
  buffer base; the `ret` sled absorbs it for roughly 1 in 4 guesses. Handled by
  retrying across the search space, not by determinism. Measured: shell after 107
  candidate spawns, ~19s.
- **The `size_image` values tried (400, 900, 512) are snow_scan's accept rule**,
  not a general BMP fact. A container whose validator accepts a different range
  will not be hit. Deliberate cheat-sheet data, but undocumented as such outside
  this note.
- **Only BMP has a real envelope.** Every other extension falls back to raw
  bytes, so a target gating on a PNG/WAV *header* will be refused by its own
  validator before the overflow is reached.
- **It ignores the resolved delivery sink.** A file path in argv *is* the
  technique, so it writes its own file and spawns the target itself. It is
  allowlisted in `FILE_DELIVERY_ALLOWLIST` on that ground — but that means under
  `--input-vector argv` it will still use file-argv rather than the declared bare
  -argv sink. Honest-but-surprising; worth either a sink-specific gate or a
  louder note in the report.
- **`base_off` search band is `size_image + 8 .. size_image + 140`.** Inferred
  from one target's frame. A larger frame (more locals below the array) falls
  outside it.

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

### 3.1 The challenge-alike variation corpus (T-2) does not exist

`benchmark/corpus_vectors/` varies the **transport** (how the payload arrives),
not the challenge. There is no corpus that holds a challenge's shape and varies
its particulars, so "≥5/7 on challenge variations" cannot be measured at all —
neither passed nor failed. Any claim about generalisation from the four solved
targets is currently **inferred**.

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
