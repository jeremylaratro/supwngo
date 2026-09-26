# Legacy → Canonical Engine Port: Gap Analysis (26SEP2026)

Phase 1 of the 8-phase development cycle. Inventory of the gaps that keep the
canonical `CanonicalAutopwnEngine` pipeline behind the legacy
`EnhancedAutoExploiter` on the HTB target set.

**Provenance labels** used throughout: `measured` (I ran it this session),
`recorded` (from a prior artifact or log, cited), `inferred` (reasoned, not
observed).

## Target (Phase-8 metric, not a sprint)

**T-1** — Canonical pipeline solves ≥3/7 HTB targets without legacy fallback.
Baseline: canonical 1/7, legacy 3/7 (`recorded`,
`docs/plans/2026-09-26-retest-sprint-map.md` §Results and this session's
forced-strategy matrix).

## Gaps (missing capability)

### G-1 — variable_overwrite cannot recover a gate constant absent from the folklore list
`measured`. `stack_techniques.py:85-86` (pre-change) swept a fixed 9-value
`MAGIC_VALUES` list × 14 buffer sizes. A binary whose gate constant is not one
of those nine is unsolvable by this technique no matter how long it runs.
Proven by `tests/fixtures/i3_candidate_provenance/fixture_b_magic_not_in_list.c`
(gate `0x12345678`): a genuine, winnable overflow that the sweep provably could
not reach — the pre-change test asserted exactly that impossibility.

The constant is in the binary's own `cmp` instructions. `comparison_immediates()`
(`input_shape_techniques.py:68`) already extracted them and was already used by
`IntTruncationBypassExecutor` — the recovery step existed and this executor
simply did not call it. (Phase-4 on-disk search; nothing needed to be built.)

### G-2 — ~~ROP executors cannot drive a menu-driven target~~ **SUPERSEDED — see G-2′**

> **ERRATUM (26SEP2026, after round-1 peer review + protocol sweep).** This item
> was mis-diagnosed. It asserted the blocker was *menu* navigation, inferred from
> the target's name and a prior plan doc — **the binaries were never run**. A
> protocol sweep of all 5 measurable HTB targets found **zero numbered menus**.
> Sprint 2 was built on this error and is inert on every target (see G-2′).
> Retained here, struck through, rather than edited away.

### G-2′ — The pipeline detects a target's input vector, then ignores it and writes to stdin
`measured`. This is the real, general gap. Two halves that do not meet:

**Detection exists.** `analysis/static.py:65` defines `INPUT_SOURCES` mapping
functions to vector classes (`"file"`, `"network"`, `"command line"`,
`"stdin/file"`); `detect_input_sources()` (`static.py:274`) additionally
classifies socket targets (`socket`/`bind`/`listen`/`accept`) and file targets
(`fopen`/`open`/`fread`/`read`). It is surfaced to the user by
`pwn --analyze-only`.

**Delivery does not consume it.** `delivery.py:153` is
`io = process([binary_path], cwd=cwd)` — **argv hardcoded empty, no file
channel, no socket channel**. `PipelineVerifier.verify_payload()`
(`verifier.py:114`) takes bare `payload: bytes` and can only ever pipe them to
stdin. So the pipeline can *say* "this target reads from a file" and then pipe
bytes at a stdin nothing is reading.

**Measured protocol sweep** — match identity: run each target ELF with empty
stdin, capture 2KB, test `profile_stage.py:210`'s substring gate and
`heap_techniques._MENU_ENTRY`:

| target | substr | regex | roles | actual input vector |
|---|---|---|---|---|
| sick_rop | False | False | 0 | raw stdin, no prompt |
| rocket_blaster_xxx | False | False | 0 | stdin after ANSI banner |
| auth-or-out | True | False | 0 | stdin after welcome/auth protocol |
| ancient_interface | False | False | 0 | **command shell**, `strcmp` dispatch table (`{"read", &cmd_read}`, `ancient_interface.c:51,324`) |
| snowscan | False | False | 0 | **argv → `.bmp` file** (`ERROR: No file provided as an argument`, then `Invalid file extension. Only accepting .bmp files.`) |

Consequences, by sub-class:

- **G-2a — argv/file-input targets are unreachable.** `snowscan` needs a
  filename in `argv[1]` and its payload inside that file. No technique can
  solve it, because delivery cannot pass an argument or write a payload file.
  1/5 targets, structurally excluded.
- **G-2b — command-shell protocols are undriveable.** `ancient_interface`
  needs `read <amount> <variable>` command sequencing before the vulnerable
  read is reachable. Not a menu-option selection.
- **G-2c — banner/handshake targets need pre-payload synchronization.**
  `rocket_blaster_xxx`, `auth-or-out` print a banner or auth prompt first.
  (Partly handled today by `deliver_parts()`' settle discipline.)
- **G-2d — network-input targets are unreachable.** Detection classifies them
  (`static.py:292`); delivery has no socket channel at all. No HTB target in
  this set exercises it, so this is `inferred`, not `measured`.

**Menus are one narrow case of G-2, not the shape of it.** Any fix must be an
input-vector abstraction (stdin / argv / file / socket), with menu and
command-shell sequencing as strategies *within* the stdin vector — not the
organizing principle.

### G-3 — SROP three-stage script deadlocks under script verification
`recorded` (this session's forced-strategy matrix; `sick_rop --strategy srop`
reaches PARTIAL). The mprotect→read→execve script is generated but
`verify_script()` never confirms it. Suspected multi-part I/O synchronization
between stages. **Not yet reproduced to root cause — hypothesis, not a
diagnosed bug.**

## Bugs (wrong behavior)

### B-1 — Unbounded recovered-candidate list triples worst-case spawn count
`measured`, **introduced by my own Sprint-1 change**, caught before merge.
`comparison_immediates()` defaults to `limit=24`; combined with the 9 fallback
values that is up to 33 candidates × 14 buffer sizes = 462 process spawns,
versus 126 pre-change. Measured expansion:

| target | candidates | recovered | spawns | pre-change | ratio |
|---|---|---|---|---|---|
| sick_rop | 9 | 0 | 126 | 126 | 1.00x |
| rocket_blaster_xxx | 10 | 1 | 140 | 126 | 1.11x |
| auth-or-out | 10 | 1 | 140 | 126 | 1.11x |
| ancient_interface | 11 | 2 | 154 | 126 | 1.22x |
| snowscan | 33 | 24 | 462 | 126 | **3.67x** |

On a target where `variable_overwrite` is the wrong technique this burns the
wall-clock budget 3.67x harder — the exact failure mode that already prevents
`sick_rop` from reaching `variable_overwrite` under `--all-strategies`.

### B-2 — `detect_input_sources()` cannot discriminate input vectors; it is inverted on the one case that matters
`measured`, **pre-existing**, found while verifying Sprint 2′'s premise *before*
writing code. Sprint 2′ was planned as "thread the existing classification into a
vector-aware delivery path". That premise is false: the classifier cannot feed it.

Measured, `StaticAnalyzer(Binary.load(t)).detect_input_sources()` over the target set:

| target | reported types |
|---|---|
| ancient_interface | `['file input', 'stdin/file']` |
| auth-or-out | `['file input', 'stdin/file']` |
| bon-nie-appetit | `['file input', 'stdin/file']` |
| rocket_blaster_xxx | `['file input', 'stdin/file']` |
| sabotage | `['environment', 'file input', 'stdin/file']` |
| **snowscan** (the only real argv/file target) | **`[]`** |

Three independent defects, each `measured`:

1. **Static binaries are invisible.** The classifier only reads `binary.plt`
   (`static.py:281`, `if func_name in self.binary.plt`). `snowscan` is
   `ELF 64-bit LSB executable, ... statically linked` and `len(binary.plt) == 0`;
   `readelf -r` shows no `fopen`/`read`/`fread` relocation. A PLT-import
   classifier structurally cannot see any input source in it.
2. **The only argv classification is dead code.** `INPUT_SOURCES["argv"] =
   "command line"` (`static.py:76`) is looked up with `"argv" in self.binary.plt`.
   `argv` is never a PLT symbol — it is a `main()` parameter. This entry can
   never fire on any binary, so the codebase's sole "command line" vector label
   is unreachable.
3. **`file input` is non-discriminating.** `has_file_io` ORs over
   `["fopen", "open", "fread", "read"]` (`static.py:303`). `read` is *the* stdin
   primitive, so every stdin-reading target is labeled `file input` — 5/5 above.

**Consequence for Sprint 2′.** Feeding this classifier into a vector-aware
delivery path would be worse than doing nothing: it would leave the file channel
off for `snowscan` (detected `[]`) while switching all 5 currently-working stdin
targets to a file channel (`file input`). That is a plausible 5/5 regression in
exchange for zero gain — the inverse of the intended effect. **The vector signal
must come from somewhere else.**

**Measured alternative signal — the argv-differential probe.** Match identity:
run the target twice under its bundled loader (`glibc/ld-*.so --library-path
glibc`) with stdin at `/dev/null`, once with no argv and once with a single
throwaway path argument, and compare the first 300 bytes of `stdout+stderr`.

| target | output differs with argv? | evidence |
|---|---|---|
| ancient_interface | False | identical `user@host$` shell prompt |
| auth-or-out | False | identical welcome banner |
| rocket_blaster_xxx | False | identical ANSI banner |
| **snowscan** | **True** | `No file provided as an argument.` → `Invalid file extension. Only accepting .bmp files.` |
| bon-nie-appetit | *inconclusive* | bundled `ld-*.so` is not executable (fixture permissions) |
| sabotage | *inconclusive* | same |

4/6 measured: **0 false positives, 1 true positive, 2 inconclusive.** The two
inconclusive rows are a fixture-permission artifact; I did not `chmod` committed
fixtures to improve a number. This signal is behavioral, so it is immune to
defects 1–3 (it needs no symbols and works on static binaries), and it is
target-authored output rather than our inference.

### B-3 — `snowscan` stacks three format gates behind the argv gate
`measured`. Even with a working argv/file channel, `snowscan` is not solvable by
an unstructured payload. Its validation ladder, each stage confirmed by running it:

1. filename must end `.bmp` → `ERROR: Invalid file extension. Only accepting .bmp files.`
2. file must open → `ERROR: Failed to open file.`
3. contents must carry a valid signature → `Invalid file signature.`
4. bitmap must be square, 20x20–30x30 → `ERROR: Invalid bitmap size. The acceptaple resolution range is 20x20 to 30x30.`

All four run with `rc=0`, so **exit status carries no signal at all** — only the
target's stdout discriminates. This means "deliver bytes to a file" and "satisfy a
structured-format parser" are two different capabilities, and only the first is
Sprint 2′. Registered separately rather than smuggled into Sprint 2′'s scope.

## Issues (friction / debt) — pre-existing, NOT caused by this effort

### I-1 — `test_i2_attempt_duration` fails on `main`
`measured`. `AttributeError: 'CanonicalAutopwnEngine' object has no attribute
'_force_all'` at `orchestrator.py:266`. The test constructs an engine by a path
that bypasses `__init__`, so PR #24's new attributes are absent. Verified
failing on `main` at `311ff25` — predates this work.

### I-2 — `test_solve_command::test_guided_fallback_resumes_to_success_with_supplied_offset` times out
`measured`. 90s subprocess timeout, reproduced on `main` at `311ff25` (91.3s)
and on the feature branch (95.2s). Predates this work.

### I-3 — `explain` command probe hangs on interactive binaries
`recorded` (prior session, deferred). Not re-verified this session.

## Phase 2 — Triage

Relevance (1–5) vs complexity (1–5) → derived tier, then at most one hand
adjustment with a stated reason.

| ID | Relevance | Complexity | Derived | Adjustment (reason) | Final | Lane |
|---|---|---|---|---|---|---|
| **B-1** | 5 — a 3.67x spawn regression I am about to ship would make the target *harder* to reach, and it is in the same file as G-1 | 1 — one-line `limit=` argument, covered by existing G-1 tests | P0 | none | **P0** | `now` |
| **G-1** | 5 — directly gates T-1; without it `variable_overwrite` cannot solve a target whose constant is not folklore | 2 — one executor, the recovery helper already existed; provenance semantics need care | P0 | none | **P0** | `now` |
| ~~G-2~~ | — | — | — | **withdrawn**: mis-diagnosed, superseded by G-2′ | — | `closed` |
| **G-2a** (argv/file) | 5 — a whole target class is structurally unreachable; no technique can ever win it | 3 — new delivery+verifier channel, but additive and testable in isolation | P0 | none | **P0** | `now` |
| **B-2** (vector classifier inverted) | 5 — it is the *feeder* for G-2a; using it as-is risks a 5/5 regression for zero gain, so G-2a cannot ship without resolving this | 2 — needs a discriminating signal, and the argv-differential probe is already measured to work (0 FP, 1 TP) | P0 | none | **P0** | `now` (rides in Sprint 2′) |
| **B-3** (format gates) | 3 — it is what stands between a working file channel and `snowscan` actually solving, i.e. between Sprint 2′ and T-1 | 4 — needs a structured-format payload synthesizer (valid BMP header + dimension constraints); unproven | P2 | **push down**: it is strictly downstream of G-2a, and bundling it would make Sprint 2′ untestable in isolation | **P2** | `later` |
| **G-2b** (command shell) | 4 — unblocks `ancient_interface` | 4 — needs per-target protocol inference; approach unproven | P2 | **spike-first**: infer-the-protocol is the unproven part | **P2** | `later` |
| **G-2c** (banner/handshake) | 3 — partly handled by existing settle discipline | 2 — extends `deliver_parts()` | P1 | none | **P1** | `later` |
| **G-2d** (network) | 2 — no target in this set exercises it; `inferred` only | 4 — socket lifecycle, unproven | P3 | none | **P3** | `later` |
| **G-3** | 4 — would add `sick_rop` toward T-1 | 4 — root cause not yet diagnosed; "I don't know if this approach works" is a 4 | P2 | **spike-first push-down**: no sprint until a reproduction isolates the deadlock | **P2** | `later` |
| **I-1** | 2 — pre-existing, no effect on T-1 | 2 — test-construction fix | P2 | none | **P2** | `later` |
| **I-2** | 2 — pre-existing, no effect on T-1 | 3 — 90s timeout, cause unknown | P3 | none | **P3** | `later` |
| **I-3** | 1 — `explain` is not on the T-1 path | 3 — unknown | P3 | none | **P3** | `document-and-move-on` |
| **I-4** (provenance conflation + dead `instruction_address`) | 2 — describes a win, cannot cause one; measured 0/6 corpus reachability | 3 — one contract change, 2 production consumers + 3 test refs + 1 benchmark tool | P2 | none | **P2** | `later` |
| **I-5** (`record.offset` reads as minimal but is first-win-under-ordering) | 1 — sole artifact consumer is a docstring note (`templates.py:141`) | 1 — state the rationale at the loop | P3 | none | **P3** | `document-and-move-on` |

I-4 and I-5 were raised by peer-review round 1 and are answered by class in
`docs/plans/2026-09-26-peer-review-round1-class-answers.md`.

### Phase 3 — Sprint split (by triage band)

- **Sprint 1 (P0): candidate recovery for `variable_overwrite`** — closes
  **G-1** and **B-1**. Both live in `stack_techniques.py`; B-1 is the bound on
  G-1's own cost, so shipping G-1 without B-1 would knowingly regress.
  *Status: implemented (`ae0cd73`) + bound checkpointed (`e39994a`).*
- ~~**Sprint 2 (P0): menu-aware delivery for ROP executors**~~ — **REVERTED.**
  Built on the mis-diagnosed G-2. Measured inert on 5/5 targets (`discover_menu()`
  returns no roles for any of them), so it cannot close anything, and it carries
  a false-positive risk that would convert a solvable target into a
  deterministic failure. **Null result, reverted rather than kept.**
- **Sprint 2′ (P0): input-vector abstraction — argv/file channel** — closes
  **G-2a** and **B-2**. Give `delivery.py`/`PipelineVerifier`/`script_builder.py`
  a vector-aware delivery path (stdin | argv | file), fed by a **behavioral
  argv-differential probe**. Scope held to argv/file: it is the one sub-class with
  a `measured`, structurally-excluded target (`snowscan`).

  > **REVISION (26SEP2026).** As first written this sprint said "fed by the
  > `detect_input_sources()` classification that already exists". Verifying that
  > premise before coding produced **B-2**: the classifier reports `[]` for
  > `snowscan` and `file input` for all 5 stdin targets, so it is inverted on the
  > only discriminating case. B-2 now rides in this sprint and the feeder is the
  > measured argv-differential probe instead. The original wording is corrected
  > here rather than only in chat, per Phase 8.
  >
  > **This sprint does not advance T-1.** `snowscan` stays unsolved because of
  > **B-3** (three stacked format gates behind the argv gate). Stated up front so
  > the Phase-8 claim is about the channel, not about a target count.
- **Sprint 3 (P2, spike first): SROP verification I/O** — **G-3**. Requires a
  reproduction that isolates where the three-stage script blocks *before* any
  fix is planned. Not started, and correctly not started: it was triaged
  P0-by-assumption in the earlier plan doc without a diagnosis.

**Deviation from the earlier plan doc** (`2026-09-26-legacy-to-canonical-port.md`):
that doc listed SROP as a co-equal Sprint 3 with a named fix ("add `recv()`
between stages"). Triage demotes it to P2/spike-first because the root cause is
undiagnosed — the named fix was a guess. Recording the deviation rather than
silently re-scoping.

## Out of scope (declared, and repeated in every delegated prompt)

- **Security/hardening/trustworthiness of supwngo itself.** Deliberate
  constants (magic-value lists, cheat-sheet tables) are FEATURES, not
  weaknesses.
- Never weaken harness verification or corpus vulnerabilities to make a target
  pass. Never self-score.
- Held-out corpora (R3/R4/R5) are not touched and not merged to `main`.
