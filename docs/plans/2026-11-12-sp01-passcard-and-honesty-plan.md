# SP-01 — Passcard v0 and the honesty fixes (plan v3, 2026-11-12)

- **Roadmap.** `docs/roadmaps/2026-11-12-mythos-roadmap.md` §5–6 (SP-01). This is the canonical copy of
  `docs/reviews/2026-11-12-mythos-roadmap/roadmap-final-mythos.md`.
- **Supersedes** the S6 detector-depth draft, archived at
  `docs/reviews/2026-11-12-mythos-roadmap/inputs/S6-PLAN-DRAFT-superseded.md`.
- **Review history**, both by Daybreak Blue, recorded beside this file:
  - v1: REJECT, B-1..B-8 (`…-review-daybreak-blue.md`).
  - v2: REJECT, B2-1..B2-4 (`…-review-daybreak-blue-r2.md`).
  - §9 maps every review item to the change it caused.

## 1. Goal

1. Build a falsifiable measurement of the owner's PASS criteria: method, offset, decompile and robustness.
   - It ships with planted mutants that prove each metric can fail.
2. Commit the measured baseline **before** any fix, so that each fix lands as a visible delta.
3. On the scored commands, remove every place where the CLI crashes or reports a failure as success.
4. Run every target execution under an isolation backend that is recorded with the result. This covers both the
   instrument and the product's `offset` (DEC-25).

**Not in scope (SP-02):** the SROP gate, role tiering, overrides on `pwn`/`template`, and template honesty.
`pwn`, `template` and `solve` are measured here, not changed.

**The S0 set (HTB-7) is smoke** (roadmap §1.4): in-sample, never a gate, never tuned on. Nothing in this sprint
claims generalisation.

## 2. Truth schema (`benchmark/truth/s0/<slug>.yaml`)

```yaml
slug: sick_rop
format: elf            # elf | pe
arch: amd64
vuln_family: stack_bof
method_accept: [srop]          # method axis only (§2.2)
method_basis: reviewed         # S0 is reviewed; generated sets use solver_proven | construction
solve_proven: srop_symtab_pivot  # technique id from the HYP-9 artefact (provenance only)
distance:                      # one entry per kind; each (target, kind) is one OFF cell
  - {kind: buf_to_ret, state: known_value, value: 40, provenance: "disasm: sub rsp,0x20 ..."}
decompile:
  vuln_function: {addr: 0x..., provenance: "objdump ..."}
  default_function_any_of: [0x...]   # addresses, never names
  anchors: {calls: [read], min_calls: 1}
stage:                         # allowlist copied into the cell, relative to the challenge dir (§3.3)
  files: [sick_rop]            # the shipped binary; loader/libc closure is added automatically
  placeholders: []             # runtime files synthesized with neutral content, e.g. flag.txt
forbidden_symbols: []          # target-specific identifiers only (e.g. fill_ammo)
```

### 2.1 Truth states and OFF cells (B-1, B2-2)

**One OFF cell per `(target, kind)`.** S0 has eight OFF cells:
- sick_rop: 1;
- rocket: 1;
- ancient_interface: 2 (`buf_to_ret`, `buf_to_canary`);
- the four non-stack-return targets: 1 each.

`distance[].state` is one of four values; `null` is never overloaded.

| State | Meaning | OFF verdict for the cell |
|---|---|---|
| `known_value` | Kind and value known, with provenance | Uses the tool's value for this kind, mapped as in the next list. **PASS** if it equals truth. **FAIL** if it is a different number. **ABSTAIN** if no value for this kind is given, or `offset` returns a failure envelope. **ERROR** if there is no single parseable document. |
| `unknown` | Kind known, value not yet extracted | VOID(`no-truth`), listed in the gaps column |
| `not_applicable` | No distance of this kind | not a cell |
| `known_absent` | Reserved; unused in S0 | not a cell |

**Field mapping from `offset --json`:**
- `buf_to_ret` ← `offset`, when `success` is true and `kind` is `buf_to_ret`. A missing `kind` (pre-fix output)
  is read as `buf_to_ret`, because the pre-fix tool claims a return-address offset.
- `buf_to_canary` ← `canary_offset`, when it is non-null.
- Other kinds have no field until SP-04.

**VOID precedence.** A failed preflight (§3.5) takes precedence over `no-truth`. The reason recorded is the
preflight code.

**Roadmap §1.3.** A saved-RIP number on a non-stack-return target is not scored. It is counted in the
informational column `off_unscored_numbers`.

### 2.2 Families (B-8)

Two axes, defined in `benchmark/passcard_families.py`.

**`method_family`** (15 families, in this order):
`ret2win`, `ret2libc`, `rop_syscall`, `srop`, `ret2dlresolve`, `shellcode`, `stack_pivot`, `one_gadget`,
`fmt_write`, `got_overwrite`, `objptr_hijack`, `heap_metadata`, `fsop`, `data_only`, `env_hijack`.

**`vuln_family`:** `stack_bof`, `heap_overflow`, `uaf`, `double_free`, `integer`, `format_string`,
`off_by_one`, `logic`.

**Mapping.** Every name in the tool's vocabulary maps to exactly one `(axis, family)`, or to `unscored` with a
reason. The vocabulary is:
- all 15 `ExploitApproach` members;
- every `template -t` choice;
- every technique id registered by `build_default_registry()`.

A mapping-coverage test enumerates all three at runtime.

**Scoring rules:**
- METHOD-R0 compares only method-axis families.
- A vuln-axis recommendation scores METHOD-R0 FAIL and appears in an informational VULN column.
- An unmapped name is FAIL with a warning.
- Families are deduplicated after mapping, before METHOD-L precision is computed.

### 2.3 S0 truth

Provenance is recorded in each file. The DEC-7 accept-sets are the write-up method plus the family `solve`
proved `shell_proven`.

| Target | vuln_family | method_accept | solve_proven | OFF cells |
|---|---|---|---|---|
| sick_rop | stack_bof | srop | srop_symtab_pivot | buf_to_ret = 40 |
| rocket_blaster_xxx | stack_bof | ret2win, ret2libc | ret2libc_leak | buf_to_ret = 40 (`forbidden_symbols: [fill_ammo]`) |
| snow_scan | stack_bof | srop, rop_syscall | container_file_rop | indexed_base_ptr: unknown |
| ancient_interface | integer | rop_syscall, ret2libc | eintr_accumulator_rop | buf_to_ret = 4120; buf_to_canary = 4104 |
| auth-or-out | heap_overflow | objptr_hijack | objptr_hijack | record_to_fnptr: unknown |
| sabotage | integer | env_hijack | env_path_hijack | buf_to_var: unknown |
| bon-nie-appetit | off_by_one | heap_metadata | heap_strlen_ofb1 | chunk_to_next_size: unknown |

**ancient_interface.**
- Function `0x40189b`, read loop at `0x401a00-0x401a36`.
- Buffer at `rbp-0x1010`, canary at `rbp-8`, cursor at `rbp-0x1020`.
- The source buffer is at `ancient_interface.c:214`.
- The SPOTCHECK Ghidra P-code run gives local −4120.

**Decompile truth** uses addresses only (`vuln_function`, `default_function_any_of`, call anchors). The
implementer derives it with objdump and records the commands.

**Vuln families** for the heap and integer targets are re-checked against the executor that proved each one.
Any change is recorded.

## 3. SP-01a — passcard v0 and the sandbox (no change to existing product behaviour)

**Commit order:**
1. I-45;
2. `supwngo/core/proc.py` and `supwngo/core/sandbox.py`, additive with no callers yet;
3. the harness, truth, mutants and self-test;
4. the pre-fix baseline.

### 3.1 I-45 (first commit; N-5)

- Redact in place the three captured-flag literals: `corpus_uafread.yaml:395-397`, `corpus_offbyone.yaml:457-463`
  and `corpus_libhijack.yaml:258-261`. Use the existing `FLAG{REDACTED}` convention. No history rewrite.
- Add a test that no YAML under `benchmark/` contains a flag-shaped value (`[A-Za-z0-9_]+\{[^}]{6,}\}`) other
  than the placeholder.

### 3.2 Files

**New, product infrastructure.** Additive in SP-01a and frozen for the baseline pair. If either file changes
before the post-fix run, both baseline headers record their content hashes.
- `supwngo/core/proc.py` (§3.4)
- `supwngo/core/sandbox.py` (§3.3)

**New, instrument:**
- `benchmark/passcard.py`
- `benchmark/passcard_score.py` (pure scoring, no I/O)
- `benchmark/passcard_families.py`
- `benchmark/passcard_preflight.py` (§3.5)
- `benchmark/passcard_stage.py` (§3.3)
- `benchmark/truth/s0/*.yaml` (7 files)
- `benchmark/mutants/*.py`: shim CLIs implementing the `pwn`, `template`, `decompile` and `offset --json` surface.

**New, tests:**
- `tests/test_passcard_score.py`
- `tests/test_passcard_selftest.py`
- `tests/test_passcard_families.py`
- `tests/test_proc.py`
- `tests/test_sandbox.py`

**Baseline:** `benchmark/baselines/passcard-s0-pre-sp01.{json,md}`, immutable. The post-fix run is a separate
file (N-2).

### 3.3 Sandbox and staging (B2-3, B2-4, DEC-25)

**`sandbox.run(argv, *, cwd, rw=[...], hide=[...], net=False, timeout, input=None) -> ProcResult`.** Two
backends:

- **`bwrap`.** The host has bubblewrap 0.6.1, `kernel.apparmor_restrict_unprivileged_userns = 0` and
  `unprivileged_userns_clone = 1`. Flags:
  - mounts: `--ro-bind / /`, `--dev /dev`, `--proc /proc`, `--tmpfs /tmp`;
  - `--bind <p> <p>` for each `rw`, and `--tmpfs <p>` for each `hide`;
  - `--unshare-net` (unless `net=True`), `--unshare-pid`, `--die-with-parent`, `--new-session`, and `--chdir <cwd>`.

  The PID namespace means that killing bwrap on timeout kills every descendant, including gdb inferiors and
  processes that call `setsid()`.
- **`none`.** A plain `proc.run`, used only when the bwrap self-check fails. Every result carries
  `isolation: "none"`.

**Self-check.** `sandbox.available()` runs, once per process and cached:
1. `bwrap … true`;
2. a probe that a hidden path is unreadable;
3. a probe that a socket `connect()` fails.

All three must behave as expected for `isolation: "bwrap"`.

**Staging (passcard; allowlisted, not a directory copy).** `passcard_stage.py` builds each cell in a fresh
scratch directory from:
- the truth file's `stage.files`;
- the loader and library closure: the `PT_INTERP` target if it is relative, and the `DT_RUNPATH`/`DT_RPATH`
  directories that resolve inside the challenge directory;
- `stage.placeholders`, written with neutral content.

Sources, write-ups, `.debug` siblings and everything else stay out. The harness then runs each command through
`sandbox.run` with:
- `cwd` = the cell, and `rw` = the cell plus the cell's private `TMPDIR`/`HOME`/`XDG_CACHE_HOME`;
- `hide` = `benchmark/truth`, `tests/htb-targets`, the scorer's scratch root, and any held-out path;
- `-o`/`--output` forced into the cell (`template` writes into `cwd` by default, `cli.py:1245-1249`).

**Acceptance.**
- A baseline or post-fix result is accepted only with `isolation: "bwrap"`.
- A run on `none` is written as an **unisolated observation**: its header says so, and it never satisfies an exit
  criterion.
- If the self-check fails on this host, SP-01a stops and asks the owner for the dedicated-uid fallback
  (roadmap Q10).

### 3.4 Process runner (`supwngo/core/proc.py`)

**Interface.** `run(argv, *, input=None, cwd, env=None, timeout) -> ProcResult`, where `ProcResult` has:
- `state ∈ {EXITED, SIGNALED, TIMEOUT, SPAWN_ERROR}`;
- `rc`, `signal`, `errno`, `stdout`, `stderr`, `pid` and `wall_s`.

**Mechanics.**
- `Popen(start_new_session=True)`, then `communicate(timeout)`.
- On timeout: `killpg(SIGKILL)`, then `communicate()` to reap.
- Spawn `OSError`s become `SPAWN_ERROR`; they never raise.

**After every passcard cell**, the harness scans `/proc` for survivors in the cell's session. Any survivor is a
ROBUST FAIL and is killed.

### 3.5 Preflight (passcard side; B-3)

Rules, applied with pyelftools against the cell `cwd`:
1. **No `PT_INTERP`.** OK (static, static-PIE).
2. **Absolute interpreter.** Check the host path.
3. **Relative interpreter.** Resolve against the cell `cwd`.
4. **Files.** Target and loader must be regular, non-empty and executable.
5. **Class and machine.** The loader's must match the target's, and the host must support the target's machine.
6. **PE, or any non-native format.** `unsupported_format`.

**Effect.**
- A failure makes only execution-dependent cells VOID: OFF, and `template` measurement.
- `pwn`, `template` (static) and `decompile` are still scored.
- ROBUST is still scored on every cell.

### 3.6 Metrics, verdicts and envelopes

**Verdicts:** `PASS | FAIL | ABSTAIN | ERROR | VOID`.

**Arithmetic, over all cells of a metric** (nothing is dropped):
- coverage = (PASS + FAIL) / all;
- exact = PASS / all;
- selective = PASS / (PASS + FAIL);
- net = (PASS − FAIL − ERROR) / all.

ABSTAIN and VOID score 0. VOID is listed with its reason.

**Semantic metrics judge content; ROBUST judges the envelope.** One output can be OFF ABSTAIN and ROBUST FAIL
at the same time, for example `success: false` with rc 0.

**Failure envelopes (N2-3; command-specific).**

| Command | Success envelope | Failure envelope |
|---|---|---|
| `offset` | rc 0, `success: true`, empty `error` and `error_code` | rc 2, `success: false`, non-empty `error_code` |
| `decompile` | rc 0, a function object with non-empty `code` | rc 2, non-empty top-level `error`, no `code` |
| `pwn`, `template` | rc 0 with the command's document | rc 2 with a non-empty top-level `error` |

A **decline** is a failure envelope judged by content alone (rc ignored). It is what the semantic metrics score
as ABSTAIN. For `offset`, it is `success: false`.

| Metric | PASS | ABSTAIN | FAIL | ERROR |
|---|---|---|---|---|
| METHOD-R0 | `recommended` maps to an accepted method family | decline | any other mapped or unmapped name, or `recommended` null without a decline | no single parseable document |
| METHOD-L | an accepted family in the top 3, ordered by `(-confidence, priority)` with ties broken by list position | decline | otherwise, including an empty list without a decline | as above |
| METHOD-L precision | reported per target: \|families(listed) ∩ accept\| / \|families(listed)\|, over the whole evidence-backed list after dedupe; the macro mean is reported | — | — | — |
| METHOD-SPAM | reported: number of distinct listed families per target | — | — | — |
| TEMPLATE | the emitted technique maps to an accepted method family | decline | otherwise | as above |
| OFF | §2.1, per `(target, kind)` cell | §2.1 | §2.1 | §2.1 |
| DECOMP | returned address ∈ `default_function_any_of`; `code` non-empty after comment stripping and not a sentinel; call-anchor recall 100% on call expressions; ≥ `min_calls` calls. `selected_by` reported, and required from SP-01b. | decline | otherwise | as above |
| ROBUST | per (target, command) cell: exactly one JSON document; no traceback; no timeout; no surviving process; `(rc, envelope)` is that command's success or failure pair | — | anything else | — |
| TIME | wall seconds and the 1-minute load average per cell | — | — | — |

**TIME** is not gated in SP-01. With `--require-time-quorum N`, the harness exits 3 with `time_quorum_failed`
when fewer than N valid samples exist per command. A sample is valid when the load is ≤ `--load-max`.

**v0 limits, stated in the report header (N-4):**
- TEMPLATE trusts the `technique` field.
- OFF trusts the integer, with no RIP proof.
- Anchors are textual after comment stripping.

### 3.7 Mutant self-test (B-1, B2-1)

Each mutant runs end to end through the harness on the seven staged S0 cells, under `bwrap`. The expected
verdict for every `(target, metric[, kind])` is pinned in `tests/test_passcard_selftest.py`.

**S0 cell counts:**
- **28 ROBUST cells:** 7 targets × 4 commands.
- **8 OFF cells:** 4 `known_value` (sick, rocket, ancient ×2) and 4 VOID.
- **7 cells for each other metric.**

| Mutant | Pinned expectation |
|---|---|
| `const`: `ROP_SYSTEM`, template `ret2system`, `offset: 0`, `canary_offset: null` | **METHOD-R0:** PASS rocket and ancient; FAIL sick, snow, auth, sabotage and bon. **TEMPLATE:** same split. **OFF:** FAIL on sick, rocket and ancient `buf_to_ret`; ABSTAIN on ancient `buf_to_canary` (no value given); VOID on 4. |
| `truth_echo` (the test hands it the truth explicitly; it never reads the hidden path) | PASS on every scored cell of METHOD-R0, METHOD-L, TEMPLATE, DECOMP and OFF (4 cells). VOID on exactly the 4 OFF cells listed VOID, each with its pinned reason (preflight code or `no-truth`). ROBUST PASS 28/28. |
| `list_all`: all 15 families, in §2.2 order, with strictly descending confidence | **METHOD-L:** top 3 is `ret2win`, `ret2libc`, `rop_syscall`, so PASS rocket, snow and ancient and FAIL sick, auth, sabotage and bon. **Precision per target:** 1/15 for sick, auth, sabotage and bon; 2/15 for rocket, snow and ancient; macro mean 10/105 = 2/21. **METHOD-SPAM** 15 on every target. |
| `list_none`: empty list, no decline | METHOD-L FAIL 7/7 |
| `abstain_all`: a well-formed decline envelope from every command | **Semantic metrics:** ABSTAIN on every non-VOID cell of METHOD-R0, METHOD-L, TEMPLATE, OFF and DECOMP. Coverage and exact are 0 on each. **ROBUST:** PASS 28/28. |
| `unmapped`: `FOO_BAR` | METHOD-R0 FAIL 7/7, one warning per cell |
| `vuln_axis`: `NEGATIVE_SIZE_BYPASS` | METHOD-R0 FAIL 7/7; VULN column shows `integer` |
| `sentinel`: 32-character `// Decompilation failed for main` | DECOMP FAIL 7/7 |
| `empty_body`: right address, `code` reduced to an empty function body | DECOMP FAIL 7/7 |
| `anchor_in_comment`: anchors only inside comments | DECOMP FAIL 7/7 |
| `wrong_addr`: right code, wrong address | DECOMP FAIL 7/7 |
| `traceback` | ROBUST FAIL 28/28; each semantic metric ERROR |
| `two_docs` | ROBUST FAIL 28/28 |
| `rc0_error`: a failure envelope with rc 0 (today's `decompile`) | ROBUST FAIL on every cell where it is emitted; the semantic metric is ABSTAIN |
| `rc2_success`, `rc127_clean` | ROBUST FAIL on every emitted cell |
| `hang`: sleeps past the budget | ERROR; no process survives |
| `grandchild`: a `setsid()` + fork of a 60 s sleeper, then exits 0 with a valid document | under `bwrap`: the survivor is gone (PID namespace) and ROBUST PASS. A test on the `none` backend alone asserts the survivor is detected (ROBUST FAIL) and killed. |
| `answer_key`: opens by absolute path (1) its truth file, (2) the challenge source file, (3) a `.debug` sibling planted next to the original binary, then emits `truth_echo` output for anything it read | Each open fails inside the sandbox. The mutant scores as `abstain_all`, so no metric can PASS from a leaked key. |
| VOID fixture: a cell whose relative interpreter does not exist | OFF VOID(`interp_missing`); the other metrics are still scored |
| `time_quorum`: run with `--require-time-quorum 1 --load-max 0` | harness exit 3, `time_quorum_failed` |
| `parses_as_json` scorer (D5-F1) | cannot tell `const` from `truth_echo`; the passcard can (asserted) |

### 3.8 Baseline

- Run the passcard on S0 at the SP-01a merge base (product untouched), under `bwrap`.
- Commit `passcard-s0-pre-sp01.{json,md}`. The header records:
  - git SHA and schema version;
  - Python, pwntools, angr and Ghidra versions;
  - host architecture, command line, isolation backend and load averages;
  - hashes of `core/proc.py` and `core/sandbox.py`.
- Ingest the HYP-9 `solve` artefact as a column, with:
  - its commit and command line;
  - the working-directory convention;
  - per-rep technique and wall time.
- If the result differs from the SCORECARD, record and explain it; do not tune it away.

## 4. SP-01b — the honesty fixes (each fix is its own commit with its RED test)

### 4.1 `offset`: runner, sandbox, preflight (B-2, B-3, B2-4)

**New `supwngo/core/exec_preflight.py`.**
- The §3.5 rules for product use, returning `Preflight(ok, code, detail)`.
- It is separate from the harness copy, so the instrument does not share judgement code with what it measures.
  The shared code is `proc` and `sandbox` only, which are mechanism, not judgement.

**Changes in `supwngo/exploit/offset_finder.py`:**

- **Absolute path.** `self.binary_path = Path(binary_path).resolve()`. Today it is kept as given (`:173`).
- **One target-input adapter.** `_run_target(payload, input_method, args, timeout) -> ProcResult`:
  - stdin, argv and file input; file input writes the pattern into a private temporary directory and passes an
    absolute path;
  - `cwd` = the binary's directory;
  - executes through `sandbox.run`, with `rw` = the private temporary directory and `net=False`.
- **Every target execution on the `supwngo offset` path (`OffsetFinder`) goes through the adapter:**
  - gdb (`:280`), run inside the sandbox, so the inferior shares the PID namespace;
  - the core-dump runner (`:402-426`);
  - the bisect probe (`:502-520`);
  - the refine loop (`:541-556`).
- **Narrowed claim.** `InteractiveOffsetFinder` and `QuickExploit` (the pwntools paths at
  `:649, 744, 797, 823, 1199`) have no callers outside this file. They are out of scope and listed for SP-12.
- **Core dumps.**
  - The host `core_pattern` is `core`, written to `cwd`. Under `bwrap`, `cwd` is read-only and bwrap 0.6.1 has
    no overlay, so the core-dump method is skipped with `method_skipped: core (sandboxed)`.
  - With `isolation: none`, only a `core` that did not exist in `cwd` before the run, or `core.<pid>`, is
    analysed, and it is then removed.
  - The scans of `Path(".")` and global `/tmp` (`:432-440`) are deleted.
- **Tri-state bisect.**
  - `test_crash` returns `CRASH`, `NO_CRASH` or `UNKNOWN`; `UNKNOWN` covers `TIMEOUT` and `SPAWN_ERROR`.
  - Any `UNKNOWN` during search or refine aborts with `success=False` and `error_code ∈ {timeout, spawn_error}`.
  - So `:565-569` can no longer fabricate a threshold.
- **Preflight first.** On failure, return `error_code="target_not_executable"`, with the preflight code and the
  interpreter path in `error`.
- **`OffsetResult`.**
  - Add `kind = "buf_to_ret"`, `error_code = ""` and `isolation`. All three are serialised.
  - `confidence` is deferred to SP-04, which has its first consumer. This is recorded as a schema decision in the
    roadmap amendment.
- **CLI.**
  - `offset --json` exits 2 on `success: false`.
  - `--no-sandbox` forces `isolation: none`, for debugging.
  - Human mode is unchanged.

**RED tests (all fail on the SP-01b merge base):**

| Test | RED because |
|---|---|
| Refine timeout: call `_find_with_binary_search` with a patched adapter (crash for length ≥ N, then `TIMEOUT` on the first refine probe) | The exception propagates today. Assert `success=False`, `error_code="timeout"` and no offset value. |
| `TIMEOUT` mid-search | Today it is read as no-crash and a threshold is fabricated. |
| `fork_sleeper` (`setsid` grandchild) through `OffsetFinder` on stdin | It survives today. Assert that no PID survives under `bwrap`. |
| Hidden path: a fixture that tries to open a path passed in `hide` | It is readable today. Assert the open fails. |
| Missing relative interpreter (`-Wl,--dynamic-linker=./nope/ld.so`) | Today: "Could not determine offset with any method". Assert `error_code`, `interp_missing` and the path. |
| Zero-byte relative loader | Assert `interp_empty`. |
| Relative-interpreter positive control: a crashing fixture with a copied host loader reachable only from its directory, run from another `cwd` with a relative `binary_path` | It cannot be exec'd today. Assert the target crashes and the offset equals the source distance. |
| Stale core in `cwd` and `/tmp`, non-crashing fixture, `--no-sandbox` | It may be analysed today. Assert it is ignored. |
| `offset --json` failure (monkeypatched finder) | rc 0 today |
| EOF spin (`eof_spin`) | Assert one document, rc 2 and `error_code="timeout"`. |

### 4.2 angr contract

- **Worker** (`_angr_subprocess.py:239-255`) returns
  `{"status": "ok" | "missing_function" | "decompiler_failed" | "exception", ...}`. Only `ok` carries `code`.
- **Parent** adds `timeout`, validates the union (`decompile.py:510-520`), and returns `None` with the status
  recorded on any non-`ok` status.
- **CLI.** `decompile --json` failure exits 2 (`cli.py:2129-2136`).
- **Existing tests (B-6).** `tests/test_decompile_angr_budget.py:118` and `:160` move to rc 2. `:134` (human mode)
  stays 0.
- **RED.** Five cases give five distinct statuses, `code is None` on the four failures, and `None` from the
  parent. Today the sentinel is returned as code.

### 4.3 RELRO (B-4, N2-1)

**Normaliser.** New `supwngo/core/relro.py`:
- `Relro(Enum): NONE, PARTIAL, FULL`;
- `normalize_relro(value)` accepts the core display strings, pwntools values and lowercase forms, and raises on an
  unknown string.

**Source fix.**
- `core/binary.py:368` passes pwntools' exact level into `_relro_str`, which treats it as a boolean and infers
  from `.got.plt` writability (`:381-391`). Derive from pwntools directly.
- Test against `readelf -lW -d` truth (`GNU_RELRO` plus `BIND_NOW`/`FLAGS_1 NOW`) on three gcc fixtures:
  `-z norelro`, `-z relro -z lazy`, `-z relro -z now`.
- Assert the Full fixture is dynamic and detected FULL before any strategy assertion.
- Prelinked images are out of scope.

**Field.** `Protections.relro_kind: Relro`. `relro` stays the display string, and the legacy JSON is
byte-identical.

**Migrate the core-`Protections` consumers.** Re-run the inventory at implementation time and record each site's
receiver type in the commit message.
- **Broken today:**
  - `strategy.py:454, 976`;
  - `leak_finder.py:329`;
  - `imports.py:398-400, 499`;
  - `pie_bypass.py:191`;
  - `chainer.py:299`.
- **Correct but ad hoc:**
  - `format_string.py:597, 640`;
  - `bypass.py:72, 211`;
  - `fmtstr_techniques.py:198`;
  - `rop_techniques.py:1513, 1536`;
  - `heap_techniques.py:237, 251-252` (the `relro` alias);
  - `heap_strlen_ofb1_techniques.py:1009-1010`.

**Lint (`tests/test_relro_lint.py`, AST): a display-only rule.**
- **Scope.** Outside `supwngo/core/`, a read of an attribute `relro`, or of `getattr(_, "relro", …)`, is allowed
  only in a display position:
  - inside an f-string or a `.format()` argument;
  - as a value in a dict literal passed to JSON emission;
  - as an argument to a logging or `console.print` call.
- **Any other read is flagged.** This covers comparisons, `in`, `.lower()`, `.startswith()`, `str(...) or ""`
  wrappers, and assignment to a local alias.
- **Exceptions** need an exact allowlist entry `(path, enclosing qualname, receiver type, justification)` for
  the non-core models:
  - pwntools `ELF.relro`: `ret2dlresolve.py:365`, `walkthrough/common.py:483`;
  - `GOTAnalysis`: `got_plt.py:105-106, 259, 310`;
  - `ProtectionFacts`: `facts.py:111`, `families/heap.py:860`;
  - `DetailedProtections`: `analysis/protections.py:142-155`;
  - `reporting/cvss.py:453`.
- **Controls.**
  - A stale allowlist entry fails.
  - Positive control: synthetic source with `prots.relro == "full"`,
    `str(getattr(p, "relro", "") or "").lower().startswith("full")` and `r = ctx.protections.relro` is flagged.

**RED.**
- Full-RELRO fixture: `StrategySuggester(bin).analyze()` must not contain RET2DLRESOLVE (it does today).
- One test per enum value, plus a legacy-JSON round trip.
- The lint is red today and green after the migration, because the correct non-core sites are allowlisted by
  type.

### 4.4 `decompile` default selection (B-5, N2-4)

**CLI (`cli.py:2070-2073`).** Stop forcing `main` and send the empty selector. Display the target as `default`;
today it would crash on `hex(None)`.

**Entry from Python.**
- Pass `entry_rva = e_entry − min(PT_LOAD.p_vaddr)` to the Java script.
- The script uses `imageBase + entry_rva`, because Ghidra 12.1.3 `Program` has no `getEntryPoint()` and loads
  ordinary 64-bit ET_DYN at `0x100000`.
- It cross-checks that the loader's `entry`/`_start` label sits there and records any mismatch.
- Prelinked ELF is unsupported and stated as such.
- A hermetic RVA test covers PIE and non-PIE fixtures.

**Java order (`SupwngoDecompile.java:87-96`):**
1. `main` → `symbol`.
2. Input 1 of the entry function's `CALL` P-code op to `__libc_start_main` (thunk or external), when it is a
   constant address → `libc_start_main_arg`.
3. The entry function, when the image has no libc start call → `entry`.
4. A BFS over called functions from the entry, taking the first non-thunk, non-external one with ties broken by
   address → `first_reachable`.

An explicit `-f` gives `name` or `addr`.

**`selected_by` plumbing.** Through the Java JSON (`:119-123`), the parser (`decompile.py:396-418`, which drops
unknown fields today), `DecompiledFunction` (`decompile.py:100-111`) and the CLI JSON.

**angr order.**
1. The `main` symbol.
2. A CFG-recovered `main` (`libc_start_main_arg`).
3. The function at exactly `proj.entry` (`entry`).
4. The first non-PLT, non-SimProcedure function by address (`first_reachable`).

Each step has a deterministic unit test.

**RetDec.** Bypassed for an empty selector, because it fabricates `main` (`decompile.py:468-476`); recorded in
CHANGELOG. Unchanged with `-f`. RetDec is not installed on this host.

**PE default selection** moves to SP-03: `Binary.load` (`cli.py:2051`, `binary.py:175`) is ELF-only.

**Fixtures.**
- `nomain.S`: freestanding `_start`, built with `-nostdlib -static`.
- `nomain_dyn.c`: stripped (`-s`), dynamically linked; its user code is reachable only through the start call.

**RED.**
- Hermetic: the selector passed with no `-f` is `name:main` today.
- Tool tier:
  - `nomain.S` → the entry function, with `selected_by == "entry"`;
  - `nomain_dyn` → the truth function by address, with `selected_by == "libc_start_main_arg"`.
- The tool-tier tests fail instead of skipping under `SUPWNGO_REQUIRE_GHIDRA=1`, which the gate run sets.

**Cut line.** If SP-01b overruns, step 2 is the cut. It then leads SP-02, and its fixture test becomes
`xfail(strict=True)` with the reason.

### 4.5 Answer-key leak and the identifier lint (B-7, N2-2)

- **Remove `"fill_ammo"`** from `offset_finder.py:887`. The rest of that name list is SP-04b's to retire.
- **New `tests/test_no_target_identifiers.py`** (AST plus `tokenize`, over `supwngo/**/*.py`).
- **Forbidden tokens:**
  - the seven slugs, in `-` and `_` spellings, case-insensitive;
  - each truth file's `forbidden_symbols` (v0: `fill_ammo`).
- **Code: zero policy.** No forbidden token in identifiers (names, attributes, def/class names, keyword arguments)
  or in non-docstring string constants.
  - Today exactly two hits exist: `offset_finder.py:887`, which is removed, and the rendered `why=` text spanning
    `walkthrough/families/heap_strlen.py:598-606`, which is reworded to "an HTB smoke target". Both were
    confirmed with the AST by the review.
- **Documentation: exact inventory.** Comments and docstrings are listed in
  `tests/data/target_identifier_inventory.json` as `(path, token, kind ∈ {comment, docstring}, count)`.
  - The file is generated by the test's own `--regen` helper and committed. It is not summarised by hand.
  - Any difference fails.
- **Controls.**
  - Positive: a slug in a string constant, and a forbidden symbol as an identifier, are both flagged.
  - Negative: `main`, `win`, `flag`, `success`, `read`, `system`, `reward` and `vuln` are not flagged.
- **This is hygiene only.** Held-out scoring is the anti-overfitting control (roadmap §1.5).

### 4.6 HO-01 (standalone hygiene commit; N-5)

Delete the dead `pie_base_offset()` at `exploit/pipeline/executors/rop_techniques.py:128`. Re-confirm zero
callers with `git grep` first.

## 5. Exit criteria

### SP-01a

- I-45 is merged, and the flag-shape test is green.
- `sandbox.available()` reports `bwrap` on this host. All three self-check probes behave as expected.
- `passcard-s0-pre-sp01` is committed under `bwrap`, with the §3.8 header.
- Every §3.7 row meets its pinned expectation.
- Mapping coverage is green.
- Preflight results for all 7 S0 cells are reported, with every VOID explained.

### SP-01b

- **ROBUST:** PASS on all 14 `offset` and `decompile` cells. A non-executable target must give its failure
  envelope, which counts as PASS.
- **No sentinel** scores as success anywhere.
- **Processes:** the descendant and hidden-path tests are green, and no surviving process is found after any
  passcard cell.
- **`offset` isolation:** `offset --json` reports `isolation: "bwrap"` on every S0 cell.
- **RELRO:** RET2DLRESOLVE is absent on every Full-RELRO S0 target, counted with `readelf`, and on the Full
  fixture. Both lints are green.
- **Default decompile:** the fixtures pass with `SUPWNGO_REQUIRE_GHIDRA=1`, or the cut line is invoked and
  recorded.
- **Unit suite:** no new failures against a pre-branch run, with counts recorded. The expected count is about
  2230 passed and 18 skipped.
- **`solve`:** `scripts/htb_rescore.py --reps 3` stays at 7/7 with 21/21 `shell_proven`, run once at the end.
- **Baseline:** `passcard-s0-post-sp01.{json,md}` is committed beside the pre-fix file, and the per-metric delta
  is in the PR body.

## 6. Risks

- **Exit-code callers.** `retest_matrix.py` classifies JSON only, `htb_rescore.py` runs only `solve`, and
  `run_bench.py` runs only `autopwn`. The only rc-0 dependants are the two assertions in §4.2. Re-grep before
  the change.
- **`offset` behaviour changes.** Targets now run from their own directory, and under `bwrap`; the core method
  is skipped there. This gets a CHANGELOG `Changed` entry. gdb inside `bwrap` needs ptrace of its own child,
  which Yama scope 1 allows. A test covers it.
- **bwrap on NFS or ext paths.** `/srv/share` is ext2/3 locally, and `--ro-bind / /` is recursive. The `hide`
  tmpfs mounts need existing mount points, which the sandbox asserts.
- **Truth labels are judgement.** Each has provenance and an owner override. S0 never gates.
- **Host contention.** Times are recorded with the load average and are not gated in SP-01.

## 7. Process

- Plan v3 is re-reviewed by Daybreak Blue and recorded beside this file.
- The amendments from the execution-enabled Mythos verify pass are folded into §8 before implementation.
- Implementation is by Sonnet agents, with SP-01a and SP-01b on separate branches.
- The orchestrator reviews each diff and runs the full suite before each PR. CHANGELOG goes under
  `[Unreleased]`, or an honest `changelog: none`.
- Each PR is merged, then its branch is deleted. No worktrees are left behind.

## 8. Amendments from the execution-enabled verify pass

(Filled in after `VERIFY.md`.)

## 9. Review disposition

### Round 1 (v1 → v2)

| Item | Change |
|---|---|
| B-1 scoring contract | Truth states; verdict arithmetic; pinned per-cell expectations, completed in round 2 |
| B-2 runner | `core/proc.py` four states; absolute path; three-way input adapter; unknown is never "no crash"; core attribution; claim narrowed to `OffsetFinder` |
| B-3 preflight | Six rules; VOID applies only to execution-dependent cells; ROBUST denominator defined |
| B-4 RELRO | Typed normaliser; `_relro_str` source fix; typed allowlist; completed in round 2 |
| B-5 decompile | `default` display; `selected_by` end to end; entry RVA; libc-start argument; angr order; RetDec bypass; PE moved to SP-03 |
| B-6 tests | Two rc assertions updated |
| B-7 identifier lint | Zero policy for code; exact inventory for documentation; controls |
| B-8 taxonomy | Method and vuln axes; mapping-coverage test |
| N-1 to N-6 | Roadmap committed; immutable baselines; envelopes; v0 limits listed; standalone hygiene commits; sandbox (round 2) |

### Round 2 (v2 → v3)

| Item | Change |
|---|---|
| B2-1 mutant oracle | Precision formula (whole list, dedupe, macro mean 2/21 for `list_all`); `list_all` ordering pinned; `abstain_all` scoped to semantic metrics with ROBUST PASS 28/28; ABSTAIN defined for every semantic metric; added `empty_body`, `time_quorum` and the three answer-key arms |
| B2-2 multiple distances | One OFF cell per (target, kind), 8 S0 cells; field mapping `offset` → `buf_to_ret` and `canary_offset` → `buf_to_canary`; VOID precedence |
| B2-3 answer key | Allowlisted staging, not a directory copy; `bwrap` required for an accepted baseline; a `none` run is an unisolated observation; leaked keys cannot PASS |
| B2-4 product sandbox | `supwngo/core/sandbox.py` in SP-01a; `offset` executes every target through it in SP-01b; `isolation` field; `--no-sandbox` |
| N2-1 RELRO | Display-only lint catches aliases and wrappers; `heap_techniques.py:251-252` added |
| N2-2 inventory | Generated by the test's `--regen`; hand count removed |
| N2-3 envelopes | Command-specific success and failure pairs |
| N2-4 RVA | Prelinked ELF stated unsupported |
| N2-5 / N-1 | `docs/roadmaps/2026-11-12-mythos-roadmap.md` exists |
| `confidence` deferral | Accepted by the review; recorded as a roadmap amendment |
