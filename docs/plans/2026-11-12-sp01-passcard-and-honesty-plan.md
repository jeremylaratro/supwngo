# SP-01 — Passcard v0 and the honesty fixes (plan v4.3, 2026-11-12)

- **Roadmap.** `docs/roadmaps/2026-11-12-mythos-roadmap.md` §5–6 (SP-01). This is the canonical copy of
  `docs/reviews/2026-11-12-mythos-roadmap/roadmap-final-mythos.md`.
- **Supersedes** the S6 detector-depth draft, archived at
  `docs/reviews/2026-11-12-mythos-roadmap/inputs/S6-PLAN-DRAFT-superseded.md`.
- **Review history**, all by Daybreak Blue, recorded beside this file:
  - v1: REJECT, B-1..B-8 (`…-review-daybreak-blue.md`).
  - v2: REJECT, B2-1..B2-4 (`…-review-daybreak-blue-r2.md`).
  - v3: REJECT, B3-1..B3-5 (`…-review-daybreak-blue-r3.md`). The §3.7 arithmetic was confirmed consistent.
  - v4: **APPROVE WITH CHANGES**, no blocking items (`…-review-daybreak-blue-r4.md`). The four required edits,
    N4-1..N4-4, are applied in v4.1.
  - v4.2 (the §8 verify-pass delta): **APPROVE WITH CHANGES**, no blocking items (`…-review-daybreak-blue-r5.md`).
    N5-1..N5-9 are applied in v4.3.
  - §9 maps every review item to the change it caused.

## 1. Goal

1. Build a falsifiable measurement of the owner's PASS criteria: method, offset, decompile and robustness.
   - It ships with planted mutants that prove each metric can fail.
2. Commit the measured baseline **before** any fix, so that each fix lands as a visible delta.
3. On the scored commands, remove every place where the CLI crashes or reports a failure as success.
4. Run every target execution under an isolation backend that is recorded with the result. This covers both the
   instrument and the product's `offset` (DEC-25).

**Not in scope (SP-02):** the SROP gate, role tiering, overrides on `pwn`/`template`, and template honesty.
`pwn`, `template` and `solve` are measured here, not changed. The one exception is §8 V-8: `pwn` and `template`
refuse non-ELF input (N5-9).

**Owner directive F** (roadmap §14) keeps SP-01 unchanged, because gate F needs this instrument. The three
targets outside the focus strategies (auth-or-out, sabotage, bon-nie-appetit) are measured here and are not
fixed.

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
metrics: all                   # optional; default all. The S0-PE fixtures use [decomp, robust] (§8 V-15, N5-8)
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

**Method basis (N3-3).** Roadmap §1 scores METHOD-R0 only on `solver_proven` or `construction` truth. S0 is
an explicit exception: its `method_basis` is `reviewed`, from the write-up method plus the `solve` family that
was proven. This is acceptable only because S0 is smoke and never gates. From SP-02c on, the gated sets use
generated truth.

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

### 3.3 Sandbox and staging (B2-3, B2-4, B3-1, B3-2, DEC-25)

**`sandbox.run(argv, *, cwd, binds=[(host, inside)], hide=[...], net=False, timeout, input=None) -> ProcResult`.**
Two backends:

- **`bwrap`.** The host has bubblewrap 0.6.1, `kernel.apparmor_restrict_unprivileged_userns = 0` and
  `unprivileged_userns_clone = 1`.
  - **Mount order (B3-1).** bwrap applies mounts in argument order and takes bind sources from the old root, so
    a later hide cannot cut a bind's source off:
    1. `--ro-bind / /`, `--dev /dev`, `--proc /proc`;
    2. `--tmpfs <p>` for each existing `hide` path;
    3. `--tmpfs /tmp`;
    4. last, `--bind <host> <inside>` for each writable bind.
  - **Bind targets.** Every `inside` path is under `/tmp`, so bwrap creates the mount point on the fresh tmpfs.
    Nothing has to be created on the read-only root, and no hide can overmount a writable bind.
  - **Other flags.** `--unshare-net` (unless `net=True`), `--unshare-pid`, `--die-with-parent`, `--new-session`
    and `--chdir <cwd>`. `cwd` must be either an `inside` path or a read-only path that is not hidden.
  - **PID namespace.** Killing bwrap on timeout kills every descendant, including gdb inferiors and processes
    that call `setsid()`.
  - **Hide paths.** A hide path that does not exist is skipped and recorded as `hide_absent: [...]`, because
    bwrap cannot create a mount point on the read-only root.
- **`none`.** A plain `proc.run`, used only when the bwrap self-check fails. Every result carries
  `isolation: "none"`.

**Confidentiality boundary (N3-2).**
- `--ro-bind / /` leaves most host files readable.
- The sandbox contains writes, **IP** networking and processes.
  - `--unshare-net` gives the sandbox its own loopback, which bwrap 0.6.1 brings up. Host listeners are not
    reachable through it.
  - It does **not** block pathname Unix sockets that are visible on the read-only root. The passcard therefore
    also hides `$XDG_RUNTIME_DIR` when it exists.
  - For reads, the sandbox protects only the paths it is told to hide.
- The passcard depends on exactly that. The product `offset` documentation says so, and does not present the
  sandbox as a general host-confidentiality boundary.

**Self-check with controlled positives (B3-1).** `sandbox.available()` runs once per process and caches the
result. Every probe has an unsandboxed positive control:
1. **Bootstrap.** Direct `true` exits 0 (control); `bwrap … true` exits 0.
2. **Hide probe.**
   - The parent creates a temporary directory containing a sentinel file.
   - The sentinel is readable without the sandbox.
   - With that directory in `hide`, `cat <sentinel>` inside the sandbox fails.
3. **Network probe.**
   - The parent listens on `127.0.0.1:<ephemeral>`.
   - An unsandboxed `connect()` succeeds.
   - The same `connect()` inside the sandbox fails. Its isolated loopback is up but has no host listener.
4. **Bind probe.**
   - Control: a direct write-then-read round trip on the host directory succeeds.
   - A file written inside the sandbox to the `inside` path appears at the host path with the same content.

All four must behave as expected for `isolation: "bwrap"`.

**Staging (passcard; allowlisted file by file; B3-2).** `passcard_stage.py` builds each cell in a fresh host
directory, `<scratch>/<run>/<cell>`, from:
- the truth file's `stage.files`;
- **the dependency closure, file by file.** Start with the `PT_INTERP` file, when it is relative. Then add each
  `DT_NEEDED` soname that resolves to a file under the challenge directory, either through a
  `DT_RUNPATH`/`DT_RPATH` entry or relative to `PT_INTERP`. Repeat transitively. Only those resolved files are
  copied, keeping their relative paths. Directories are never copied.
- `stage.placeholders`, written with neutral content.

Sources, write-ups, `.debug` siblings and every unlisted file stay out. A staging test asserts that the cell's
file list equals the computed closure.

**Harness invocation.** The harness runs each command through `sandbox.run` with:
- `binds = [(<host cell>, /tmp/cell)]` and `cwd = /tmp/cell`. The cell's private `TMPDIR`, `HOME` and
  `XDG_CACHE_HOME` are `/tmp/cell/tmp`, `/tmp/cell/home` and `/tmp/cell/cache`. No path may contain a
  dot-component, because Ghidra rejects it (§8 V-1).
- `hide`:
  - `benchmark/truth`;
  - `benchmark/gen` (generator sources and seeds, from SP-02c; recorded as `hide_absent` until it exists);
  - `tests/htb-targets`;
  - the scorer's scratch root;
  - every held-out path;
  - `$XDG_RUNTIME_DIR`, when it exists (pathname Unix sockets);
  - every `--extra-hide` path (used by the self-test).
- `-o`/`--output` forced to `/tmp/cell/...` (`template` writes into `cwd` by default, `cli.py:1245-1249`).

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

**Survivor detection (B3-5).**
- At start, the harness makes itself a child subreaper with `prctl(PR_SET_CHILD_SUBREAPER, 1)`, via ctypes.
- Any descendant orphaned by a cell is then re-parented to the harness. This includes one that called
  `setsid()` or double-forked.
- After every cell, the harness lists `/proc/*/stat` entries whose parent PID is the harness, other than its
  live runner. Any such process is a survivor: ROBUST FAIL, `SIGKILL`, then reap.
- Cleanup repeats until nothing is left: kill every adopted child, reap it, and rescan, because killing an
  intermediate process can orphan more.
- This does not depend on sessions, so it works the same on both backends. Under `bwrap`, the PID namespace
  normally leaves nothing to find.

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
when fewer than N valid samples exist per command. A sample is valid when it completed and its 1-minute load
was strictly below `--load-max`.

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
| `traceback` | ROBUST FAIL 28/28. ERROR on every non-VOID semantic cell. The 4 truthless OFF cells stay VOID with their pinned reasons, because VOID is decided before the output is read (§2.1). |
| `two_docs` | ROBUST FAIL 28/28 |
| `rc0_error`: a failure envelope with rc 0 (today's `decompile`) | ROBUST FAIL on every cell where it is emitted; the semantic metric is ABSTAIN |
| `rc2_success`, `rc127_clean` | ROBUST FAIL on every emitted cell |
| `hang`: sleeps past the budget | ROBUST FAIL 28/28. ERROR on every non-VOID semantic cell; the same 4 OFF cells stay VOID. No process survives. |
| `grandchild`: the parent forks a child, which calls `setsid()` and forks a 60 s sleeper. The sleeper redirects stdin, stdout and stderr to `/dev/null`, then writes its PID to a readiness pipe. The parent waits for that, emits a valid document and exits 0 | Under `bwrap`, the PID namespace removes the survivor, so ROBUST PASS. A separate test forces the `none` backend: the subreaper scan (§3.4) finds the re-parented sleeper (ROBUST FAIL), kills it, and its PID is gone afterwards. |
| `answer_key`: opens by absolute path (1) its truth file, (2) the challenge source file, (3) a `.debug` sibling planted next to the original binary, and (4) a generator-source file containing the truth, planted by the test in a temporary generator root passed as `--extra-hide` (it stands in for `benchmark/gen` until SP-02c creates it). It emits `truth_echo` output for anything it read, and declines otherwise. | Each of the 4 opens fails inside the sandbox, and each path is asserted readable outside it first (positive control). The mutant scores exactly as `abstain_all`, so no metric can PASS from a leaked key. |
| VOID fixture: a cell whose relative interpreter does not exist | OFF VOID(`interp_missing`); the other metrics are still scored |
| `time_quorum`: `--reps 1 --require-time-quorum 2` | Harness exit 3, `time_quorum_failed`. It is deterministic because a quorum larger than the number of reps cannot be met, whatever the load. A sample is valid when it completed and its 1-minute load was strictly below `--load-max`. |
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
- **Private workspace (B3-3).**
  - Each `find_offset` call creates one host directory with `tempfile.mkdtemp(dir="/tmp", prefix="supwngo-offset-")`.
    `dir` is pinned so a caller's `TMPDIR` cannot move it.
  - It is bound at the same path, which is always under the sandbox `/tmp`.
  - The pattern file, the gdb script and any file input go there.
  - Today those files are made with `NamedTemporaryFile` in the host `/tmp` (`:245`, `:275`), which the sandbox
    tmpfs would hide.
  - The workspace is removed afterwards.
- **One target-input adapter.** `_run_target(payload, input_method, args, timeout) -> ProcResult`:
  - stdin, argv and file input; file input passes the workspace file's absolute path;
  - `cwd` = the binary's directory, which is read-only inside the sandbox;
  - executes through `sandbox.run`, with `binds` = the workspace and `net=False`.
- **gdb runner.** `_run_gdb(script, timeout) -> ProcResult` builds `gdb -q -batch -x <workspace>/s.gdb <binary>`
  and runs it through the same `sandbox.run` and workspace. The inferior is a descendant, so it shares the PID
  namespace and dies with it.
- **Every target execution on the `supwngo offset` path (`OffsetFinder`) goes through one of those two:**
  - gdb (`:280`), through `_run_gdb`;
  - the core-dump runner (`:402-426`), the bisect probe (`:502-520`) and the refine loop (`:541-556`), through
    `_run_target`.
- **Nested sandbox.** When the passcard runs `offset`, the product's `sandbox.run` is inside the passcard's own
  bwrap.
  - The product's self-check (§3.3) runs there too. If nested bwrap works, it reports `isolation: "bwrap"`.
  - If nested bwrap does not work, the product reports `isolation: "outer"`, but only when both of these hold:
    - the passcard set `SUPWNGO_OUTER_SANDBOX=1`;
    - the product sees that it is in a separate PID namespace (`/proc/self/ns/pid` differs from the value the
      passcard recorded on the host and passed in).
  - Otherwise it reports `none`.
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
| gdb under bwrap (B3-3): a crashing stack fixture with a known source distance, run directly (not under the passcard) | Assert all four: `isolation == "bwrap"`, `method` starts with `GDB - ` (the existing free-text values at `:305, 319, 331`), the offset equals the source distance, and the gdb script and pattern paths were inside the workspace. A run that falls through to bisect is a FAIL, not a pass. It is RED today: there is no sandbox, and the files are in host `/tmp`. |
| Bisect under bwrap: the same fixture with gdb forced unavailable | Assert `isolation == "bwrap"`, `method` starts with `Binary search` (`:561, 567`), and `success`. The value is recorded, not asserted: bisect is approximate by design, and offset accuracy belongs to SP-04. This test proves the route, not the number. |
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
  - `heap_strlen_ofb1_techniques.py:1009-1010`;
  - `walkthrough/facts.py:376, 388`, the reported-versus-derived cross-check.

The complete classification, including the allowlisted and display reads, is the starting-inventory table
below.

**Lint (`tests/test_relro_lint.py`, AST): a display-only rule (B3-4).**

**Flagged reads.** Outside `supwngo/core/`, the lint looks at every load of an attribute named `relro` and every
`getattr(_, "relro", …)`.

**Display positions.** A read is allowed when its value reaches one of these positions, after stripping `str()`
and `repr()` calls, conditional expressions, and `or <constant>`:
- a `FormattedValue` in an f-string;
- an argument to `.format()`, to a logging method, or to `print`/`console.print`;
- a value in a dict literal.

Every other read is flagged. That covers comparisons, `in`, `.lower()`, `.startswith()`, keyword arguments, tuple
members and assignment to a local alias.

**Allowlist.** An entry is `(path, enclosing qualname, receiver type, justification)` and is keyed by qualname,
not line number. Only receivers that are not the core `Protections` qualify. A stale entry, one that matches no
read, fails the lint.

**Procedure.**
1. The lint has a `--report` mode.
2. The implementer runs it at the SP-01b merge base and pastes the output into the commit message.
3. If it differs from the inventory below, the plan's table is corrected in the same PR. A differing inventory
   is not a blocker; an unclassified read is.

**Starting inventory.** The orchestrator measured 39 reads with an AST scan at `3b7e6b2`.

| Class | Sites | Action |
|---|---|---|
| **Migrate** (core `Protections`, or a mix of core and `DetailedProtections`): 20 reads on 19 lines | **analysis/imports.py** `:398, 499`<br>**exploit/bypass.py** `:72, 211`<br>**exploit/chainer.py** `:299` (×2)<br>**exploit/pie_bypass.py** `:191`<br>**exploit/strategy.py** `:454, 976`<br>**vulns/format_string.py** `:597, 640`<br>**vulns/leak_finder.py** `:329`<br>**executors/fmtstr_techniques.py** `:198`<br>**executors/heap_strlen_ofb1_techniques.py** `:1009`<br>**executors/heap_techniques.py** `:237, 251`<br>**executors/rop_techniques.py** `:1513, 1536`<br>**walkthrough/facts.py** `:376, 388` (`reported = detailed or prot`: compare with `normalize_relro()` on both sides) | Use `relro_kind`, or `normalize_relro()` |
| **Allowlist, by receiver type**: 12 reads | **pwntools `ELF`:** `rop/ret2dlresolve.py:365`, `got_plt.py:105`<br>**`GOTAnalysis`:** `got_plt.py:106, 259, 310`<br>**`DetailedProtections`:** `analysis/protections.py:153, 155`<br>**`ProtectionFacts`:** `walkthrough/facts.py:111`, `walkthrough/common.py:393`, `walkthrough/families/heap.py:860, 864` (one `_weaponisation_step` entry; `:864` is under `_q()`, which the rule does not strip)<br>**`_Image.relro`** (a list of address ranges, not a level): `executors/finiarray_techniques.py:262` | Entry plus justification |
| **Display, passes the rule**: 7 reads | `analysis/protections.py:505`<br>`exploit/bypass.py:430`<br>`exploit/enhanced_auto.py:1281`<br>`pipeline/templates.py:28`<br>`exploit/strategy.py:300`<br>`analysis/imports.py:524`<br>`cli.py:1037` | None |

**Corrections from round 3.**
- `walkthrough/common.py:483` was in the v3 list but is text inside a generated-code string, not an AST read.
- `reporting/cvss.py:453` was in the v3 list but reads a local name.
- `got_plt.py:105` reads pwntools `elf.relro`, not `GOTAnalysis`.
- `cli.py:1037` and `finiarray_techniques.py:262` were in no earlier list.

**Controls.**
- **Positive:** synthetic source containing `prots.relro == "full"`,
  `str(getattr(p, "relro", "") or "").lower().startswith("full")`, `r = ctx.protections.relro` and
  `f(state=x.relro)` is flagged on all four.
- **Negative:** `f"{p.relro}"`, `log.info("%s", p.relro)` and `{"relro": str(p.relro) if p else None}` pass.
- **Stale entry:** a synthetic allowlist entry that matches nothing fails the lint.

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

**PE default selection** moves to SP-03: `Binary.load` (`cli.py:2051`, `binary.py:175`) is ELF-only. *(Superseded by §8 V-9: PE default selection is in SP-01b.)*

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
- `sandbox.available()` reports `bwrap` on this host. All four self-check probes, each with its unsandboxed
  positive control, behave as expected.
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
- **`offset` isolation.**
  - Under the passcard, `offset --json` reports `isolation` of `"bwrap"` (nested) or `"outer"` on every S0
    cell (§4.1).
  - Run directly, it reports `"bwrap"`.
  - The gdb-under-bwrap test is green with `GDB - ` provenance.
- **RELRO:** RET2DLRESOLVE is absent on every Full-RELRO S0 target, counted with `readelf`, and on the Full
  fixture. Both lints are green: every non-core `relro` read is migrated, allowlisted by receiver type, or in a
  display position, and no allowlist entry is stale.
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
- **bwrap mount topology.** `/srv/share` is ext2/3 locally, and `--ro-bind / /` is recursive. Hide mounts need
  existing directories, so absent ones are skipped and recorded. Writable binds live under the sandbox `/tmp`
  tmpfs, after every hide. The bind probe in the self-check catches a regression.
- **Nested bwrap.** The product's sandbox runs inside the passcard's. If the host refuses a nested user
  namespace, the `outer` rule (§4.1) applies. The self-check result is recorded either way, and a direct run
  still has to report `bwrap`.
- **Truth labels are judgement.** Each has provenance and an owner override. S0 never gates.
- **Host contention.** Times are recorded with the load average and are not gated in SP-01.

## 7. Process

- Plan review is complete: v4 was APPROVED WITH CHANGES in round 4, and v4.1 applies those changes.
- The amendments from the execution-enabled Mythos verify pass are folded into §8 before implementation.
- Implementation is by Sonnet agents, with SP-01a and SP-01b on separate branches.
- The orchestrator reviews each diff and runs the full suite before each PR. CHANGELOG goes under
  `[Unreleased]`, or an honest `changelog: none`.
- Each PR is merged, then its branch is deleted. No worktrees are left behind.

## 8. Amendments from the execution-enabled verify pass

**Source.** `docs/reviews/2026-11-12-mythos-roadmap/verify-mythos-execution.md` (Mythos 5-2, single thread,
execution allowed, 72 min). Roadmap-level dispositions are in roadmap §14. Every item below is adopted into
SP-01 and overrides the section it names.

### 8.1 SP-01a

- **V-1, cell paths with no dot-component (AMD-3).**
  - Ghidra rejects any project path with a component starting with `.`. With `TMPDIR=<cell>/.tmp`, decompile went
    from 5/7 to 0/7.
  - The cell layout becomes `/tmp/cell/tmp`, `/tmp/cell/home` and `/tmp/cell/cache`. Staging asserts that no
    scratch or cell path contains a dot-component.
- **V-2, Ghidra control cell (AMD-3, N5-6).**
  - Every passcard run includes a control cell. It catches a broken Ghidra, Java or sandbox environment before
    it reads as product failures.
  - **Fixture.** Source `benchmark/fixtures/ghidra_control/ghidra_control.c`. It defines a non-static
    `ghidra_control()` that calls `puts`, and a `main` that calls it.
  - **Binary.** It is built **non-PIE** (`-no-pie -O0`), so its Ghidra address equals the link-time vaddr both
    before and after V-10. The binary is committed as `ghidra_control.elf`, with its SHA-256 pinned in
    `benchmark/fixtures/ghidra_control/expect.yaml`.
  - **Expectation**, also in `expect.yaml`:
    - selector `-f ghidra_control`;
    - expected address from `nm`;
    - rc 0 and exactly one JSON document;
    - `analysis_backend == "ghidra"`;
    - non-sentinel `code` containing a call to `puts`.
  - **Acceptance precondition.** If the control does not pass, or the binary's SHA-256 differs, the run is
    **invalid**: the header says so, and the run is not accepted.
  - The control is excluded from every semantic and ROBUST denominator.
- **V-3, tests import the checkout (AMD-7).** These three files build their CLI from `shutil.which("supwngo")`,
  which resolves to the editable install under `/usr/bin/python3`:
  - `tests/test_cfg_angr_budget.py:38`
  - `tests/test_decompile_angr_budget.py:43`
  - `tests/test_static_dataflow_strings_angr_budget.py:51`

  They change to `[sys.executable, "-m", "supwngo.cli"]`. A test asserts that no file under `tests/` calls
  `which("supwngo")`. This commit lands before the baseline.
- **V-4, core-dump hygiene.**
  - `core_uses_pid = 1`, and the suite runs crash fixtures from the repo root. That left 42 `core.*` files
    (112 MB), which were deleted on 2026-11-12 after checking each with `file`.
  - The root `conftest.py` already sets `PWNLIB_NOTERM` and `XDG_CACHE_HOME` at import. It now also sets the soft
    `RLIMIT_CORE` to 0 at import. The hard limit is unchanged.
  - No test exercises `_find_with_coredump` (grep, 2026-11-12).
  - **The one core consumer is
    `tests/test_solve_command.py::test_guided_fallback_resumes_to_success_with_supplied_offset` (N5-7).**
    - It reads `p.corefile` from a `python3 -c` child that runs from the repo root, which is the likely source of
      the stray cores.
    - pwntools' `process` already raises its own child's soft limit (`pwnlib/tubes/process.py:439`,
      `setrlimit(RLIMIT_CORE, (-1, -1))`).
    - The fix: run that child with `cwd=tmp_path`, so the core lands in `tmp_path`, and delete the core afterwards.
    - The test must still pass under the new conftest. If pwntools' own raise fails, give the child a
      `preexec_fn` that raises the soft limit to the hard limit.
  - **Focused test.** The pytest process has a soft limit of 0, and a child that opts in gets a non-zero limit.
- **V-5, ROBUST baseline expectation (AMD-1).** These are recorded as measured expectations, not tuned targets:
  - offset 2 of 3 valid stack-return cells, with no crash;
  - decompile 5/7;
  - ROBUST 28/28 single documents, but 28/28 exit 0 including the failures.
- **V-6, loader helper (AMD-2): not moved into SP-01a.**
  - sabotage and bon-nie-appetit ship a 0-byte loader. They stay VOID(`interp_empty`) for execution cells, which
    is the honest result.
  - Both are outside directive F's focus.
  - `run_with_loader` (CG-04) stays in SP-02c, where F-2 needs it for a supplied libc.
- **V-15, S0-PE fixtures and table (N5-8).**
  - **Location.** The two mingw PE64 fixtures from V-9 live in `benchmark/fixtures/s0pe/`, with `pe_vuln.c`:
    - `pe_sym.exe`, built with symbols;
    - `pe_strip.exe`, the same build stripped.
  - **Build.** `x86_64-w64-mingw32-gcc`. The binaries are committed and their SHA-256 values pinned, so the
    pre-fix baseline and the post-fix run score the same bytes.
  - **Placement.** They are built in **SP-01a**, so the pre-fix baseline includes them.
  - **Truth.** Each has a truth file under `benchmark/truth/s0pe/`, with `format: pe` and
    `metrics: [decomp, robust]`.
  - **Separate table.** They are scored in their own **S0-PE** table, with its own denominators:
    - 2 DECOMP cells;
    - 8 ROBUST cells (4 commands × 2).
  - The S0 matrix stays at 7 ELF targets: 28 ROBUST, 8 OFF and 7 cells for each other metric.
  - The §3.7 mutant self-test still runs on that 7-ELF matrix only.

### 8.2 SP-01b

- **V-7, angr CFG (AMD-6).**
  - `_angr_subprocess.py` builds `CFGFast()` without `normalize=True`, so the fallback never produces code on
    this host.
  - The fix goes in the same commit as the tagged union.
  - `test_decompile_angr_happy_path_uses_subprocess_and_returns_function` is rewritten to assert real code: a
    non-sentinel body that names the fixture's call. Today it passes only because the sentinel counts as a
    function.
- **V-8, PE refusal (AMD-10, N5-3, N5-4).**
  - `pwn` on a mingw PE returns SHELLCODE at 0.9 with exit 0 and `arch: ""`, a false success.
  - **Detection.** New `supwngo/core/fileformat.py` defines `detect_format(path) -> elf | pe | unknown`.
    - `elf`: the `\x7fELF` magic and a parseable ELF header.
    - `pe`, only when all of these hold:
      1. the file starts with `MZ`;
      2. `e_lfanew` is readable and in bounds;
      3. `PE\0\0` is at that offset;
      4. the COFF and optional headers are complete;
      5. the optional-header magic is `0x10b` or `0x20b`.
    - Everything else is `unknown`.
  - **Detection tests:**
    - truncated `MZ`;
    - out-of-range `e_lfanew`;
    - missing PE signature;
    - PE32+ and, where `i686-w64-mingw32-gcc` builds it, PE32;
    - a truncated ELF.
  - **Refusal documents.** Detection runs before `Binary.load` and before any template output file is created.
    - `offset --json`: the ordinary `OffsetResult` failure, with `success: false`, a non-empty `error`,
      `error_code: "unsupported_format"` and exit 2.
    - `pwn --json` and `template --json`: exactly
      `{"error": "Unsupported binary format: <pe|unknown>", "error_code": "unsupported_format"}` and exit 2.
    - Human mode: a readable diagnostic on stderr and exit 2, with no JSON.
  - **`decompile` on PE keeps working.** VERIFY measured correct Ghidra pseudo-C with `-f`.
  - This corrects §4.4: `Binary.load` does not block PE decompile; it degrades silently.
- **V-9, PE default function (AMD-10, N5-1).**
  - §4.4 no longer defers PE to SP-03. The PE entry RVA is `AddressOfEntryPoint` from the optional header, parsed
    by `fileformat.py` with `struct`, with no new dependency.
  - That is the CRT start (`mainCRTStartup`), **not** the user's `main`. The PE order is therefore:
    1. `main` symbol → `symbol`.
    2. `mingw_crt_main_arg` → `mingw_crt_main_arg`. Search the CRT start's call tree, to a bounded depth, for the
       function that calls `__getmainargs` (or UCRT `__p___argc`). Take the target of its first direct call after
       that one that receives the argc and argv globals. Proved on `pe_strip.exe`.
    3. `entry` → `entry`, the CRT start itself, labelled as such.
  - `first_reachable` is **not** used for PE: a BFS through CRT initialisation is not a main detector.
  - **Truth.** For both PE fixtures, `default_function_any_of` lists the user `main` address only. An `entry`
    result is therefore an honest DECOMP FAIL, never a pass.
  - **Tests** (tool tier, under `SUPWNGO_REQUIRE_GHIDRA=1`) assert the planted user-function address and a code
    anchor (its `puts` call), not merely non-empty code.
  - **Cut line, as in §4.4.** If step 2 cannot be proved on the fixture inside SP-01b:
    - it moves to SP-03;
    - the `pe_strip` test becomes `xfail(strict=True)` with the reason;
    - S0-PE reports the stripped cell as a FAIL with `selected_by: entry`.
- **V-10, one address convention (finding 9, N5-2).**
  - For PIE, Ghidra reports an address based at `0x100000` and angr one based at `0x400000`, for the same
    function.
  - Both backends' `address` is normalised to the file's link-time virtual address, the objdump convention.
  - **`backend_base` is reported by each backend, never assumed from observed constants.** Hardcoding `0x100000`
    or `0x400000` would corrupt ET_EXEC addresses.
    - Ghidra: `currentProgram.getImageBase().getOffset()`, added to the Java JSON.
    - angr: `proj.loader.main_object.mapped_base`, added to the worker reply.
  - **File base.**
    - ELF: `min(PT_LOAD.p_vaddr)`.
    - PE: `ImageBase` from the optional header, via `fileformat.py`.
  - **Mapping:** `rva = backend_addr − backend_base`, then `address = file_base + rva`.
  - The inverse mapping is applied to an explicit `-f 0x...` selector before it reaches either backend.
  - **Independent-oracle tests.** The expected value comes from `nm`/objdump, or from the PE header and symbol
    table. Cross-backend equality alone does not count, because both can be wrong the same way. The fixtures are:
    - an ELF PIE;
    - an ELF ET_EXEC;
    - PE32+;
    - PE32, when the toolchain builds it.
  - DECOMP truth uses this convention.
- **V-11, Ghidra errors are surfaced (finding 4, N5-5).**
  - The Ghidra runner returns a structured result instead of a Boolean. It carries:
    - its `ProcResult` state;
    - bounded stdout and stderr tails;
    - the first `ERROR` line from stdout.
  - Today stdout is discarded (`decompile.py:291`).
  - The diagnostic survives the RetDec and angr fallbacks. It is included in `error` only if the whole operation
    fails.
  - **Test.** The test exercises the Ghidra seam directly with a dot-component project path, and asserts that the
    structured result's error contains `Path element starting with '.'`.
  - **CLI-level test.** It forces RetDec unavailable and the angr worker into a tagged failure, so a successful
    fallback cannot make it vacuous.
- **V-12, RED-test mechanics (VERIFY §4).**
  - Patches on the target runner match `argv[0]`. A blanket `subprocess.run` patch caught an unrelated `file -b`
    call.
  - `CliRunner(mix_stderr=False)` is used wherever a test parses `--json` stdout.
  - The parent-side sentinel RED feeds the **legacy** worker reply.
- **V-13, exit 2 versus click's usage error (AMD-8).** Exit 2 is kept. Click usage errors print text, not JSON, so
  they fail ROBUST's "exactly one JSON document" check. Every negative-result test asserts the JSON
  `error_code` (offset) or `error` (others) as well as the exit code.
- **V-14, already covered.** These need no change:
  - AMD-13 (RELRO): `got_plt.py` is already allowlisted by receiver type (§4.3).
  - AMD-14 (identifiers): already a zero policy for code plus a generated documentation inventory (§4.5).
  - AMD-11's `core*` glob: already deleted (§4.1).

### 8.3 Exit-criteria additions

**SP-01a:**
- The Ghidra control cell passes in every accepted run.
- The S0-PE fixtures are committed with pinned hashes, and the pre-fix baseline includes the S0-PE table.
- The `which("supwngo")` test is green.

**SP-01b:**
- `pwn`, `template` and `offset` on both PE fixtures return `unsupported_format` with exit 2.
- The angr fallback returns real code on the tiny fixture.
- The PE default-function fixtures pass under `SUPWNGO_REQUIRE_GHIDRA=1`.
- Both backends report the same normalised address on the PIE fixture.
- The **S0-PE table** (V-15) scores 2 DECOMP and 8 ROBUST cells, separately from the 7-ELF S0 matrix:
  - all 8 ROBUST cells PASS;
  - `pe_sym` DECOMP PASSES;
  - `pe_strip` DECOMP PASSES, or is the stated V-9 cut-line FAIL.
- The address-normalisation oracle tests pass for ELF PIE, ELF ET_EXEC and PE32+.

**Unit suite:** VERIFY measured 2229 passed, 2 failed and 18 skipped at load 13–43. Both failures are
wall-budget timeouts that pass alone. The exit criterion compares against a pre-branch run on the same host,
and re-runs any wall-budget failure alone before counting it.

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

### Round 3 (v3 → v4)

| Item | Change |
|---|---|
| B3-1 mount topology | Mount order is hides, then the `/tmp` tmpfs, then writable binds, and every bind target is under the sandbox `/tmp`. Bind sources come from the old root, so a hide cannot cut one off. The cell is at `/tmp/cell`. The self-check has four probes, each with an unsandboxed positive control (sentinel file, parent listener, bind round-trip). |
| B3-2 answer-key arms and staging | `benchmark/gen` is hidden (recorded as `hide_absent` until SP-02c). A fourth arm, generator source, uses an `--extra-hide` temporary generator root, and each arm is first shown readable outside the sandbox. The dependency closure is staged file by file, never by directory, and a test checks the cell's file list. |
| B3-3 gdb under bwrap | A private workspace is bound into the sandbox for the pattern, the gdb script and file input. `_run_gdb` runs gdb through `sandbox.run`. A new test runs gdb under bwrap and asserts `GDB - ` provenance, so falling through to bisect fails it. A separate bisect-route test checks the route only. A nested-sandbox `outer` rule is added. |
| B3-4 RELRO lint | The allowlist is keyed by qualname and receiver type. A `--report` procedure is defined. A measured 39-read starting inventory gives 20 migrate, 11 allowlist and 8 display. The stale v3 entries are removed and the two missing sites added. Display positions are defined after `str()`, conditional and `or` stripping. |
| B3-5 nondeterministic pins | TIME uses a quorum larger than the number of reps, and a valid sample needs load strictly below `--load-max`. Survivors are found by the child-subreaper scan, which is independent of sessions. `traceback` and `hang` give ERROR on non-VOID semantic cells, while the 4 truthless OFF cells stay VOID. |
| N3-1 `confidence` | Recorded as orchestrator roadmap amendment AMD-O1 (roadmap §14) in the follow-up docs PR. |
| N3-2 confidentiality | The sandbox boundary is stated: writes, network and processes are contained; reads are protected only for hidden paths. |
| N3-3 method basis | S0 is stated as an exception to the generic METHOD-R0 basis rule (smoke only; it never gates). |

### Round 4 (v4 → v4.1; APPROVE WITH CHANGES)

| Item | Change |
|---|---|
| N4-1 `heap.py:864` | Moved to the `ProtectionFacts` allowlist entry for `_weaponisation_step`, because `_q()` is not a stripped display wrapper. The inventory is now 20 migrate, 12 allowlist and 7 display. |
| N4-2 network wording | The guarantee is IP-network isolation: loopback is up, isolated, and has no host listener. Pathname Unix sockets are not blocked, so `$XDG_RUNTIME_DIR` is hidden. Probes 1 and 4 have explicit direct controls. |
| N4-3 workspace path | `mkdtemp(dir="/tmp", …)`, bound at the same path under the sandbox `/tmp`. |
| N4-4 survivor fixture | The sleeper closes its standard descriptors and signals readiness before the parent emits. Cleanup kills, reaps and rescans until nothing is left. |
| N3-1 / AMD-O1 | Landed in roadmap §14, with an inline marker at the SP-01 `confidence` line. |

### Round 5 (v4.2 → v4.3; APPROVE WITH CHANGES; §8 delta only)

| Item | Change |
|---|---|
| N5-1 HIGH, stripped mingw default is the CRT start | V-9 order is now `main` → `mingw_crt_main_arg` → `entry`, with no `first_reachable` for PE. Truth accepts only the user `main`, so `entry` is an honest FAIL. Tests assert the planted address and the `puts` anchor. Cut line: if step 2 can't be proved, it moves to SP-03 and becomes a strict xfail. |
| N5-2 HIGH, `backend_base` undefined | Each backend reports its base: Ghidra `getImageBase()`, angr `main_object.mapped_base`. The file base is `min(PT_LOAD.p_vaddr)` for ELF and `ImageBase` for PE. The inverse mapping applies to `-f 0x…`. Independent-oracle tests cover PIE, ET_EXEC, PE32+ and, if buildable, PE32. |
| N5-3 refusal documents | Exact JSON is pinned per command. `offset` keeps `OffsetResult` with `error_code`; `pwn`/`template` emit `{error, error_code}`. Human mode: a stderr diagnostic and exit 2. Detection runs before `Binary.load` and before template output is written. |
| N5-4 PE magic | Strict 5-step PE detection; anything else is `unknown`. Malformed-input tests added. |
| N5-5 V-11 masked by fallback | Structured Ghidra runner result. The diagnostic is preserved through fallbacks. There is a seam-level test, and a CLI test with the fallbacks forced off. |
| N5-6 control oracle | Pinned: source, a committed non-PIE binary with its SHA-256, `-f ghidra_control`, `nm` address, backend `ghidra`, a `puts` anchor, rc 0 and one document. It is a precondition outside every denominator. |
| N5-7 core consumer | Named `test_guided_fallback_resumes_to_success_with_supplied_offset`. Its child runs in `tmp_path` and the core is deleted afterwards. pwntools already raises the child's soft limit. A focused limit test is added. |
| N5-8 PE denominators | New V-15: the S0-PE fixtures and truth (`metrics: [decomp, robust]`), built in SP-01a and scored in a separate S0-PE table (2 DECOMP, 8 ROBUST). The 7-ELF S0 matrix and the mutant self-test are unchanged. |
| N5-9 §1 scope | §1 now names V-8 as the one change to `pwn`/`template`. |
