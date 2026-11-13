## Verdict

- The strategic direction is strong—measurement first, one facts layer, one plan, offline-first LLMs—but the draft is not yet bulletproof or safe to execute as written.
- SP-02 contains two correctness blockers: the SROP gate admits binaries with no `rax=15` mechanism, and the proposed override patch cannot create or recommend RET2WIN.
- SP-04 cannot meet its claimed coverage: it omits interprocedural buffers, optimized stack tracking, copy loops, custom calling conventions, and an exact representation for accumulator overflows.
- The scorecard improves on the old “list everything” metric, but its truth extraction, abstention, metamorphic rules, and isolation still permit selective evaluation or truth leakage.
- The 16-sprint architecture is too large for one maintainer, contains late prerequisites and a hidden deletion migration, and commits to Ghidra before its decisive hypothesis is tested.

## Blocking issues

### B-1 — The roadmap starts from a stale baseline

**Issue.** It says `solve` is unmeasured and schedules HYP-9 for SP-02 (`_review/ROADMAP-DRAFT.md:7,558`), but the ordered input already records a current-tree result: 7/7 targets, 21/21 `shell_proven`, zero hard errors (`_review/SPOTCHECK.md:65-70`). Separately, the original offset/template dynamic results for three targets are VOID because their relative interpreters could not resolve (`_review/SCORECARD.md:87-98`).

**Required change.** Rewrite “Today” before approving the roadmap: preserve 7/7 only as in-sample canonical-pipeline smoke, remove HYP-9 from future work, and mark invalid dynamic cells VOID rather than failures.

Impact: high; effort: S; dependencies: none; risk: low; success: one baseline artifact with correct working directories, `solve`, validity flags, and no contradiction with SPOTCHECK.

### B-2 — Passcard v0 is not isolated enough to be trusted

**Issue.** SP-01 runs commands with `cwd` set to the real challenge directory (`_review/ROADMAP-DRAFT.md:276-280`). Current `template` writes its default output into the current directory (`supwngo/cli.py:1245-1249`), so the benchmark can mutate its corpus. The tool also remains able to read committed truth files and unstripped/debug siblings, allowing accidental or deliberate answer-key coupling.

**Required change.** Run every cell in a disposable challenge-directory copy, always provide an output path outside the corpus, mount source/truth/debug artifacts unreadable to the tool process, and retain them only in the scorer. Preflight relative `PT_INTERP` against the actual target `cwd`.

Impact: critical; effort: M; dependencies: bubblewrap or equivalent isolation; risk: relative-loader breakage; success: a malicious shim trying to read `truth.yaml`, DWARF siblings, or generator source is denied, while all valid challenge loaders still resolve.

### B-3 — The offset timeout fix and its RED proof do not match

**Issue.** The roadmap says to wrap the refine calls “exactly as `test_crash`” and kill the process group (`_review/ROADMAP-DRAFT.md:281`), but `test_crash` uses `subprocess.run` without a new session or group kill (`supwngo/exploit/offset_finder.py:502-520`). The unguarded refine calls are real (`offset_finder.py:541-556`), but an EOF-spinning fixture normally times out during the binary search, is caught, and never reaches refinement.

**Required change.** Introduce one `Popen(start_new_session=True)` target-run helper with group kill/reap. The unit RED must force a crashing bisect result followed by a refine timeout; a second fixture must prove the child and a descendant die. Keep EOF-spin as a robustness/exit-code test, not proof of the escaped-refine bug.

Impact: high; effort: S; dependencies: none; risk: process leaks; success: timeout returns one JSON document with exit 2, and both child and descendant PIDs are gone.

### B-4 — The SROP widening is unsound and its proposed test blesses the false positive

**Issue.** `_has_sigreturn` currently means a `pop rax`/`pop eax` exists (`supwngo/exploit/strategy.py:362-370`). `_has_syscall_ret` only means the chosen gadget text contains `ret` (`strategy.py:360`; `exploit/rop/gadgets.py:312-317`). That does not establish `rax=15`.

The working sick_rop-family executor separately proves a count-returning write wrapper and refuses the target if none exists (`supwngo/exploit/pipeline/executors/srop_nowrite_techniques.py:153-171,219-229`). The proposed test—`syscall; ret`, no pops, expect SROP—would require a false recommendation (`_review/ROADMAP-DRAFT.md:322,345-347`).

**Required change.** Model explicit `RaxControl` evidence: `pop_rax`, exact sigreturn gadget, count-returning syscall wrapper, or another proven data-flow path. Reuse the executor’s static gate or extract its wrapper analysis. Add a negative fixture containing `syscall; ret` but no way to obtain 15.

Impact: critical; effort: M; dependencies: shared static gate; risk: missed exotic SROP routes; success: sick_rop is SROP, while the no-`rax` negative fixture abstains.

### B-5 — The override design cannot make `pwn --win` recommend RET2WIN

**Issue.** RET2WIN is appended only while `StrategySuggester.analyze()` sees `report.has_win_function` (`supwngo/exploit/strategy.py:216-228`). The proposed helper is extracted from a pipeline patch that runs after analysis and changes only report fields/notes (`supwngo/exploit/pipeline/orchestrator.py:1078-1097`). It neither inserts nor re-sorts a RET2WIN strategy. Therefore the stated RED outcome at `_review/ROADMAP-DRAFT.md:347` cannot pass with the stated implementation.

**Required change.** Resolve overrides into a run-scoped `KnownFacts` object before planning. Either inject the resolved payoff into `StrategySuggester` before `analyze()`, or build/insert RET2WIN and recompute the terminal ranking. Apply the same path to `--ret2` when it legally doubles as a destination.

Impact: critical; effort: M; dependencies: target resolver; risk: libc-relative or gadget addresses being treated as functions; success: random-named payoff plus `--win`, `--winfun`, `--ret2`, or `--eip` produces top-1 RET2WIN with operator provenance, while `--ret2 --rop` does not.

### B-6 — SP-02’s template repair still emits incorrect templates

**Issue.** `generate_exploit_script` executes target analysis (`supwngo/exploit/auto.py:283-303,382-415`), drops an explicit zero offset (`auto.py:2761-2762`), and silently falls back to a leak script when requested generation is unsupported (`auto.py:2776-2802`). More importantly, mapping SROP to the legacy generic builder is wrong for sick_rop: that builder expects `pop_rax` and `/bin/sh`, whereas the working executor uses a count-returning wrapper, `mprotect`, and a symbol-table pivot.

The proposed `--offset 0 must appear` RED is also ineffective: broken templates already contain zeros.

**Required change.** In SP-02, `-t auto` may select only a method for which a compatible builder exists; otherwise it must return `no_template_for_method` plus required inputs. Make target execution opt-in immediately. Test zero override by forcing auto-discovery to a nonzero value and asserting operator-provided zero wins in both metadata and the rendered assignment.

Impact: critical; effort: M; dependencies: corrected SROP gate and pre-analysis overrides; risk: more honest exit-2 outcomes initially; success: no selected method is rendered through a different technique, and `template` never executes without `--measure`.

### B-7 — The no-`main` decompile selection is too weak

**Issue.** Today the CLI forces `main` (`supwngo/cli.py:2057-2071`), preventing the Java fallback (`SupwngoDecompile.java:87-96`). Removing that is correct, but `main → entry → first function` merely returns `_start` for many stripped ELF files. The proposed `nomain.S` fixture proves only the easy case where entry itself is useful.

**Required change.** Use `main` → function passed to `__libc_start_main` → meaningful entry function for freestanding images → first non-thunk/non-library entry-reachable function. Add a stripped dynamically linked no-`main` fixture, not only freestanding assembly. Define and serialize `selected_by`.

Impact: high; effort: M; dependencies: callsite export for robust stripped selection; risk: static-libc noise; success: default decompile returns the truth user function on freestanding ELF, stripped dynamic ELF, PE32, and PE64.

### B-8 — Static offset inference does not cover the cases it promises

**Issue.**

- **Canaries:** per-function canary analysis is deferred to SP-08 (`_review/ROADMAP-DRAFT.md:235`), after SP-04 claims `buf_to_canary`/`buf_to_ret`.
- **`-O2`/no frame pointer:** “nearest `lea` feeding the sink” (`ROADMAP-DRAFT.md:429`) is not a def-use slice and does not track stack-pointer deltas, alignment, spills, red-zone use, or phi values.
- **sick_rop/custom ABI:** the measured Ghidra result has unresolved stack-passed arguments (`_review/SPOTCHECK.md:35-37,56`); the proposed fallback assumes a prologue and “buffer at frame bottom” rather than proving the buffer reaches the wrapper.
- **Callee-reached sinks:** there is no summary that composes a callee’s destination parameter back to a caller’s stack object.
- **ancient_interface:** a `reaches` set is not the promised exact distance. It needs an affine result such as `bytes_to_ret = ret_off - base_off - accumulated_count`.
- **snow_scan:** the bug is a copy loop, not a listed sink, and the experiment abstained (`SPOTCHECK.md:58`). This directly contradicts the claimed M1 smoke expectation of 4/4 (`ROADMAP-DRAFT.md:99`).
- **PE:** mingw P-code worked on two fixtures (`SPOTCHECK.md:53-55`), but `/GS`, SEH, indirect imports, and MSVC are deferred to SP-16.
- **Menus:** static inference can avoid dialogue, but the dynamic validation oracle still needs a truth input recipe; that capability is deferred too late.

**Required change.** Expand the design to include interprocedural argument summaries, P-code def-use, instruction-level SP-delta tracking, custom wrapper ABIs, affine indexed destinations, per-function canary slots, and loop-copy recognition. Alternatively reduce M1 honestly to the supported subset.

Impact: critical; effort: L; dependencies: minimal facts exporter, FunctionID, per-function canary analysis; risk: false exact answers; success: per-axis coverage and exactness with no dropped hard cases, including dedicated fixtures for every case above.

### B-9 — The validation oracle and scorecard can still be gamed

**Issue.**

- “Non-computable locations are dropped with a counted reason” (`_review/ROADMAP-DRAFT.md:340-342`) lets the generator remove hard `-O2` cases from the denominator.
- “100% truth extraction or counted abstain” (`ROADMAP-DRAFT.md:229`) has the same loophole.
- Compiler changes must not change distance (`ROADMAP-DRAFT.md:77`) is false: compilers legitimately change stack layout and sometimes method feasibility.
- Method labels derived from a “template × protections table” (`ROADMAP-DRAFT.md:342`) can be self-fulfilling; protections alone do not establish gadget or primitive feasibility.
- Accept sets are expanded “after review” (`ROADMAP-DRAFT.md:58`), so public truth is not human-free.
- METHOD-L excludes `speculative`, allowing an engine to hide broad method spam there.
- The proposed planted mutant covers METHOD/OFF only, not DECOMP, COMP-A/B, ROBUST, TIME, or abstention handling.

**Required change.** Report coverage and selective accuracy separately; cap truth-extraction failures per axis; score every built variant against its own truth; derive generated accept sets from construction plus reference solvers; penalize false listed methods on patched twins; and ship positive, negative, abstain, error, timeout, and answer-key mutants for every metric.

For offset, use three tiers of truth:

1. DWARF location/CFA evaluated at the sink PC.
2. Independent assembly/disassembly derivation.
3. Native ELF breakpoint measurement or RIP proof where executable.

PE without Wine must have tiers 1 and 2 and remain “static-validated,” not dynamically confirmed.

Impact: critical; effort: M; dependencies: generator and scorer isolation; risk: lower headline numbers; success: deleting all hard cases, listing every family, copying truth, or emitting anchor comments each causes a scorer failure.

### B-10 — The architecture commits before its decisive experiment and has late prerequisites

**Issue.** DEC-2 makes Ghidra the system of record before HYP-1 is measured in SP-04 (`_review/ROADMAP-DRAFT.md:145,550`). FunctionID and per-function canary analysis arrive only in SP-08, even though SP-03/04 need them for static binaries. The measured snow_scan export took 427 seconds and was dominated by static libc (`_review/SPOTCHECK.md:60-63`). Sandboxing arrives in SP-07, after untrusted binaries have already been imported into Ghidra.

**Required change.** Add a Ghidra feasibility gate before the architecture commitment. The minimum viable export should contain program metadata, functions, candidate callsites/P-code arguments, requested decompilation, and evidence—not whole-program C. Move minimal FunctionID, per-function canary recognition, and analysis sandboxing into this slice.

Impact: critical; effort: M for the spike, L only after it passes; dependencies: pinned Ghidra configuration; risk: architecture pivot; success: predefined coverage/time gates on at least 20 structurally distinct fixtures before `facts/v1` becomes mandatory.

### B-11 — The deletion schedule is a hidden big-bang migration

**Issue.** SP-12 deletes `auto.py`, `enhanced_auto.py`, and `generator.py` (`_review/ROADMAP-DRAFT.md:220`), but the live `exploit` command imports all three (`supwngo/cli.py:296,370-373,411-437,455-459`). They are also public eager imports in `supwngo/__init__.py:51-52,99-106` and `supwngo/exploit/__init__.py:3,56-65,187-193`. Disabling fallback only in `autopwn`/`solve` does not migrate these consumers.

**Required change.** Inventory and migrate every CLI/API consumer before deletion, publish deprecations for exported names, and delete one subsystem per sprint. Remove the `exploit/ ≤ 70k LoC` gate; compatibility and passcard behavior are the meaningful guards.

Impact: critical; effort: L; dependencies: planner/template replacements; risk: public API breakage; success: import-contract and CLI reachability tests pass before and after each deletion with no forced LoC target.

### B-12 — The LLM trust model contradicts its own hooks and offline requirement

**Issue.**

- The plan says no schema field can contain free-form data, yet it includes a free-text `reasoning` field (`_review/ROADMAP-DRAFT.md:504,511`).
- Hook 4 emits grammars and AFL tokens (`ROADMAP-DRAFT.md:498`), so injection can do more than select a wrong index; it can generate arbitrary target input.
- Hook 1’s “static oracle” is essentially the same open/write/string evidence used by deterministic ranking. That evidence is not independent proof that a function is a payoff.
- “Any oracle record” is too weak: a bad oracle can formally bless a bad value.
- SP-07’s exit includes an agent pilot (`ROADMAP-DRAFT.md:234`) that is specified as using the cloud follower (`ROADMAP-DRAFT.md:528`), so a hard offline deployment cannot meet the gate.

**Required change.** Treat free reasoning as opaque ledger data never parsed by builders; give grammar generation a separate untrusted-artifact type, sandbox, size/complexity limits, and coverage-only promotion. Define assertion-specific independent oracles. Make every sprint gate runnable with `--llm local` or `off`; cloud arms must be optional reports.

Impact: high; effort: M; dependencies: local model inventory and sound deterministic oracles; risk: hooks show no lift; success: zero egress offline, adversarial responses cannot alter facts/builders without a sound oracle, and cloud unavailability cannot block a sprint.

## Non-blocking issues

### N-1 — RELRO normalization needs one canonical field

The mismatch is real: `Protections.relro` emits `"Full RELRO"` (`supwngo/core/binary.py:381-391`), while consumers compare `"full"`, `"Full"`, `"none"`, and `"partial"` (`strategy.py:454,976`; `analysis/imports.py:400,499`; `exploit/chainer.py:299`).

Suggested change: add `relro_kind: Relro`, preserve the display string for compatibility, and prohibit semantic reads of `.relro`. Impact: high; effort: S; dependencies: none; risk: serialization break; success: AST lint plus tests for every enum value and legacy JSON.

### N-2 — The angr failure contract is underspecified

The proposed failure adds `ok: false`, but it does not explicitly require `ok: true` on success. A careless `.get("ok")` check would reject valid results.

Suggested change: make the subprocess response a total tagged union and validate it at the parent boundary. Impact: medium; effort: S; dependencies: none; risk: compatibility; success: success, missing-function, decompiler-failure, exception, and timeout tests are distinct.

### N-3 — Identifier lint is useful but not an anti-overfitting control

Removing `"fill_ammo"` is necessary (`supwngo/exploit/offset_finder.py:881-889`), but a slug/string lint cannot detect target constants, encoded names, or a general-looking executor fitted to one frame.

Suggested change: retain the lint as hygiene, but make held-out performance and rename/compiler variants the enforcement mechanism. Impact: medium; effort: S; dependencies: held-out custody; risk: false confidence; success: a planted structural cheat passes lint but fails held-out, proving the real gate catches it.

### N-4 — Payoff detection needs stronger evidence semantics

An `open → read → write` function can be an ordinary file copier, and extracting “required arguments” from compare constants without parameter data flow is unreliable. The current over-match is confirmed at `supwngo/exploit/offset_finder.py:946-979`.

Suggested change: distinguish candidate, payoff hypothesis, and dynamically proven payoff; slice compare operands back to formal parameters. Impact: high; effort: M; dependencies: facts def-use; risk: lower recall; success: random-name payoffs and decoy file-copy functions are separated on patched twins.

### N-5 — Facts cache identity and operator facts are unsafe as specified

The cache key omits analyzer configuration, loader/language choice, FunctionID database, and tool-manifest version (`_review/ROADMAP-DRAFT.md:369-373`). The architecture also places asserted operator facts inside the per-sha KB (`ROADMAP-DRAFT.md:109-113`), which risks persistent poisoning across runs.

Suggested change: key derived facts by binary hash plus complete analysis manifest; keep operator facts in an immutable run-scoped overlay. Impact: high; effort: M; dependencies: facts schema; risk: larger caches; success: changing any analyzer setting invalidates derived facts, and a bad `--win` never affects a later invocation.

### N-6 — TIME can become an all-VOID metric

High-load cells are simply invalidated (`_review/ROADMAP-DRAFT.md:53`). Without a minimum valid-sample quorum, a noisy host can avoid every performance gate.

Suggested change: require a minimum number of valid cold/warm samples and fail the measurement run if the quorum is not reached. Impact: medium; effort: S; dependencies: quiet window; risk: delayed reports; success: TIME cannot pass or disappear with zero valid samples.

### N-7 — PE acceptance remains ambiguous

M1 claims PE success on mingw while MSVC and `/GS` are deferred to SP-16 (`_review/ROADMAP-DRAFT.md:155-156,243,453`). That may satisfy a narrow fixture goal but not an unqualified “exe works” claim.

Suggested change: label M1 explicitly “mingw PE32/PE32+”; do not claim generic Windows PE until MSVC fixtures pass. Impact: high; effort: S for wording, M for fixtures; dependencies: owner-supplied toolchain/binaries; risk: narrower marketing claim; success: scorecard columns identify compiler and cookie scheme.

### N-8 — Tagging 2.2.0 after SP-02 is premature

At that point templates can still lack a compatible builder, facts do not support PE, and COMP-B golden-fill is deferred to SP-05.

Suggested change: tag a prerelease after SP-02 and reserve 2.2.0 for the first honest stack-template milestone. Impact: medium; effort: S; dependencies: SP-05; risk: delayed release; success: the tagged release passes COMP-B on its documented scope.

## Code-claim spot-checks

| # | Roadmap claim or premise | Verdict | Evidence |
|---:|---|---|---|
| 1 | `pwn` supplies a `GadgetFinder`; `template -t auto` does not and defaults unknown methods to `ret2system`. | CONFIRMED | `supwngo/cli.py:866-870,1220-1231` |
| 2 | The CLI offset path is crash-driven. | CONFIRMED | `supwngo/cli.py:904-935`; `supwngo/exploit/offset_finder.py:210-234` |
| 3 | `TimeoutExpired` can escape the binary-search refine loop. | CONFIRMED | Guarded bisect at `offset_finder.py:502-520`; unguarded refine at `:541-556` |
| 4 | angr reports a decompilation sentinel as successful code. | CONFIRMED | `supwngo/analysis/_angr_subprocess.py:239-255`; accepted at `analysis/decompile.py:510-520` |
| 5 | `decompile --json` can emit an error object with exit 0. | CONFIRMED | Error emitted at `supwngo/cli.py:2129-2134`; `_emit_json` only echoes at `cli.py:23-25` |
| 6 | Full RELRO is normalized inconsistently, allowing RET2DLRESOLVE. | CONFIRMED | Producer: `supwngo/core/binary.py:381-391`; bad gate: `exploit/strategy.py:449-456` |
| 7 | `--win/--ret2/--rop` exist on `autopwn`, `explain`, and `solve`, but not `pwn`, `template`, or `offset`. | CONFIRMED | Definition `supwngo/cli.py:66-109`; attachments `:2840,3238,3449`; missing command decorators `:724-737,904-910,1185-1195` |
| 8 | The CLI’s forced `main` prevents the Java fallback from running. | CONFIRMED | `supwngo/cli.py:2057-2071`; Java fallback `SupwngoDecompile.java:87-96` |
| 9 | Current SROP viability requires a pop-based `rax/eax` setup. | CONFIRMED | `supwngo/exploit/strategy.py:362-370,394-400` |
| 10 | `has_syscall_ret` is adequate evidence for the syscall-return `rax=15` path. | WRONG | It only tests gadget text (`strategy.py:360`; `rop/gadgets.py:312-317`). The actual executor separately requires a count-returning wrapper (`srop_nowrite_techniques.py:153-171,219-229`). |
| 11 | Widening the old SROP gate alone would still leave STACK_PIVOT recommended. | CONFIRMED | SROP 0.6 at `strategy.py:579-583`; pivot 0.65 at `:765-770`; sort at `:278-283` |
| 12 | Extracting the pipeline’s report override patch is sufficient to make `pwn --win` recommend RET2WIN. | WRONG | RET2WIN is created only during analysis (`strategy.py:216-228`); the patch runs afterward and only mutates fields (`pipeline/orchestrator.py:1078-1097`). |
| 13 | `generate_exploit_script` drops explicit zero and silently substitutes leak generation. | CONFIRMED | `supwngo/exploit/auto.py:2761-2762,2776-2802` |
| 14 | `template` currently executes the target while “analyzing.” | CONFIRMED | `auto.py:283-303,382-415`; called by `cli.py:1242-1243` |
| 15 | `htb_rescore.py` gates shell credit on `shell_confirmed`, not `shell_proven`. | CONFIRMED | `scripts/htb_rescore.py:195-207` |
| 16 | Current `Binary.load` is effectively ELF-only. | CONFIRMED | `supwngo/core/binary.py:174-190` calls pwntools ELF and pyelftools only |
| 17 | The current Ghidra `Popen` inherits stdin. | CONFIRMED | No `stdin=` at `supwngo/analysis/decompile.py:280-286` |
| 18 | “Ghidra’s native stack reference is always relative to the return-address slot” is established by repository code. | UNVERIFIABLE | The committed script exports only name/address/type/C (`SupwngoDecompile.java:109-123`); no committed frame exporter defines this invariant. |
| 19 | Static executor gates may depend on target-executed menu facts. | CONFIRMED | Menu fact is set dynamically at `pipeline/profile_stage.py:199-234`; gate sweep documents the dependency at `scripts/gate_sweep.py:20-28` |
| 20 | `auto.py`, `enhanced_auto.py`, and `generator.py` can be deleted after merely disabling `autopwn`/`solve` fallback. | WRONG | The live `exploit` command still imports them at `supwngo/cli.py:296,370,413,436,457`; they are also public imports in `supwngo/__init__.py:51-52`. |

## Sequencing changes you would make

| Sprint ID | Concrete change |
|---|---|
| **SP-01A** | Measurement only: ingest the current 7/7 `solve` result, build isolated passcard execution, validate every scorer with positive/negative/error/abstain/cheat mutants, then commit the untouched baseline. |
| **SP-01B** | Correctness fixes: shared group-killed process runner, interpreter diagnosis, angr sentinel contract, nonzero failure exits, RELRO enum, answer-key removal. Keep each fix separately measurable. |
| **SP-01C** | Decompile selector repair: recovered `main`/entry-reachable user function, `selected_by`, and stripped/no-main ELF plus PE tests. |
| **SP-02A** | Introduce run-scoped `KnownFacts`; add `--winfun`/`--eip` aliases and strict resolution to `pwn` and `template`. Do not add overrides to `offset` until they affect an actual plan. |
| **SP-02B** | Correct SROP classification using explicit `rax` control evidence. Make template generation non-executing and refuse incompatible builders. Retest `template -t auto == pwn top-1 or honest exit 2`. |
| **SP-02C** | Build T0-mini and the gate separately. Require per-axis truth-extraction coverage; do not permit unrestricted dropped cases. Establish the held-out template split before SP-03 tunes against the corpus. |
| **SP-03A** | Ghidra decision spike on ≥20 cases: canary, FPO `-O2`, custom wrapper, caller-buffer/callee-sink, copy loop, stripped/static, PE32/PE64. Make DEC-2 conditional on its gates. |
| **SP-03** | If the spike passes, ship the minimal facts slice: program metadata, functions, library marking, per-function canary, candidate callsites/arguments, on-demand decomp, immutable cache manifest, sandbox. |
| **SP-04** | Static offset only. Add interprocedural summaries, full def-use/SP tracking, affine indexed results, custom ABIs, and loop-copy support. Move the breakpoint oracle’s benchmark implementation from SP-11 here. |
| **SP-04B** | Payoff discovery separately; measure it on renamed payoffs, file-copy decoys, argument-check decoys, and patched twins. |
| **SP-05** | Minimal stack `MethodPlan` for SROP, ret2win, and ROP; render only `pwn`, `template`, and `offset`. Golden-fill and declared-input tests are the exit gate. |
| **SP-06** | Scale corpus/nightly only after the mini generator is sound. Start smaller than 300/150 and grow based on confidence intervals and per-axis variance. Pin the environment before collecting headline numbers. |
| **SP-07/SP-08** | Move minimal FunctionID and per-function canary work earlier; retain SP-08 only for broader static-library coverage. Deliver the full machine contract after the first stable plan schema. |
| **SP-09–SP-11** | Detectors before non-stack plans. Add deterministic menu/file recipes before dynamic confirmation; otherwise SP-11 cannot reach its sink. Do not disable legacy fallback until corpus proof is non-regressive. |
| **SP-12** | Replace with several deletion sprints. Migrate `exploit` and public imports first, deprecate, then remove one engine/module family at a time. |
| **SP-13–SP-15** | Local-only LLM substrate and oracle-soundness test first. Payoff nomination next. Role/vulnerability hooks only after reachability exists. Grammar generation gets a separate sandboxed trust model. Cloud evaluation is optional. |
| **SP-16** | If “PE” means general Windows binaries, move MSVC `/GS` fixtures before any generic PE release claim; otherwise label the release mingw-only. |

## Anything missing that the owner's goals require

- **A hostile-binary analysis threat model.** Ghidra, objdump, decompilers, and parser libraries process attacker-controlled files before SP-07’s sandbox. Add no-network, read-only, CPU/memory/disk-limited analysis from the first facts sprint. Impact: critical; effort: M; dependency: sandbox packaging; risk: tool incompatibility; success: malicious fixtures cannot write outside the workspace or open a socket.

- **A manual escape hatch for static abstentions.** The owner explicitly permits supplied components, but hard offset cases also need `--vuln-func`, `--sink`, `--buffer`, `--canary-offset`, and typed `--known` facts. Impact: high; effort: M; dependency: `KnownFacts`; risk: operator error; success: supplied facts appear verbatim with operator provenance and strict mode rejects unused inputs.

- **A public API migration policy.** The roadmap discusses CLI contracts but not the currently exported Python API. Impact: high; effort: M; dependency: planner facade; risk: downstream breakage; success: one-release deprecation tests and a documented compatibility table.

- **Cache governance.** There is no quota, eviction, corruption recovery, sensitive-data retention, or analysis-manifest policy. Whole-program decompilation and LLM ledgers can grow rapidly and may retain proprietary code. Impact: high; effort: M; dependency: facts/ledger design; risk: lost useful caches; success: bounded storage, deterministic invalidation, redaction/retention controls, and corruption self-repair.

- **Corpus and tool licensing gates.** Several public tiers and vendored tools are proposed with licences still unverified. Impact: medium; effort: S–M; dependency: chosen distribution model; risk: redistribution violation; success: every fetched artifact has source, version, hash, licence, and redistribution status before release.

- **A definition of “decompilation works.”** Anchor strings alone are too easy to satisfy with comments or shallow stubs. Require correct function selection, non-sentinel structured output, call-anchor recall, address consistency, and a minimum body complexity. Impact: high; effort: S; dependency: passcard; risk: backend-specific formatting; success: planted copied-anchor and empty-body mutants fail.

- **Evidence for method recommendations.** The owner asks for the right method, but a family label without the vulnerable function, primitive site, mitigation handling, and missing prerequisites is still misleading. Impact: high; effort: M; dependency: facts/planner; risk: more abstentions; success: every scored recommendation cites a function/site and has no unknown precondition.

- **A comparative release claim.** “Best in existence” needs explicit baselines: deterministic supwngo-off, cwe_checker where applicable, Ghidra alone, and agent-without-toolbox. Impact: medium; effort: M; dependency: stable corpus; risk: external-tool drift; success: each release publishes where supwngo wins, ties, loses, or abstains rather than relying on an absolute slogan.