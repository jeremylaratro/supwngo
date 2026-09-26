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
| **G-2b** (command shell) | 4 — unblocks `ancient_interface` | 4 — needs per-target protocol inference; approach unproven | P2 | **spike-first**: infer-the-protocol is the unproven part | **P2** | `later` |
| **G-2c** (banner/handshake) | 3 — partly handled by existing settle discipline | 2 — extends `deliver_parts()` | P1 | none | **P1** | `later` |
| **G-2d** (network) | 2 — no target in this set exercises it; `inferred` only | 4 — socket lifecycle, unproven | P3 | none | **P3** | `later` |
| **G-3** | 4 — would add `sick_rop` toward T-1 | 4 — root cause not yet diagnosed; "I don't know if this approach works" is a 4 | P2 | **spike-first push-down**: no sprint until a reproduction isolates the deadlock | **P2** | `later` |
| **I-1** | 2 — pre-existing, no effect on T-1 | 2 — test-construction fix | P2 | none | **P2** | `later` |
| **I-2** | 2 — pre-existing, no effect on T-1 | 3 — 90s timeout, cause unknown | P3 | none | **P3** | `later` |
| **I-3** | 1 — `explain` is not on the T-1 path | 3 — unknown | P3 | none | **P3** | `document-and-move-on` |

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
  **G-2a**. Give `delivery.py`/`PipelineVerifier` a vector-aware delivery path
  (stdin | argv | file), fed by the `detect_input_sources()` classification that
  already exists. Scope held to argv/file: it is the one sub-class with a
  `measured`, structurally-excluded target (`snowscan`).
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
