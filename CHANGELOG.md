# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Walkthrough scorer — blind-follower measurement with a necessity control**
  (`benchmark/walkthrough/`). `benchmark/` previously contained *zero* references to
  walkthroughs, so the R5 spec's `>= 85% followable` gate was a threshold against a
  metric that did not exist — and inventing a lenient one later to clear it is the
  exact failure this benchmark was built to prevent. A walkthrough is now credited
  only when a **fresh blind follower**, given only that walkthrough and that binary,
  produces an artifact whose flag capture is **behaviourally attributed** to the
  target's own process tree, **and** the identical follower given only the binary
  fails. Where both arms succeed the target is `UNINFORMATIVE` — it cannot
  demonstrate the walkthrough contributed anything. This is
  `benchmark/ablation/`'s necessity test applied to documentation instead of to
  exploit steps. Scoring reuses `run_bench.py` and `attribution.py` unchanged
  (fresh per-rep secret, independent re-execution, negative controls, behavioural
  witness); the walkthrough engine never grades its own output and `b"flag" in out`
  is never a verdict. Two followers measure deliberately different things: the
  deterministic `template` follower measures **template validity** and has no bare
  arm, so it is *structurally* unable to emit `FOLLOWABLE` and must never be quoted
  against the gate; the `agent` follower is the gate metric. Family-agnostic by
  construction — nothing in it names a walkthrough family.
- **Walkthrough scorer — falsifiability controls** (`benchmark/walkthrough/selftest.py`,
  `fixtures/`). A validation step that cannot fail is worse than none, and this
  project has found four. `--selftest` proves a negative verdict is reachable across
  four layers: one good and seven deliberately broken artifacts (wrong offset,
  undeclared constant at the reader's first command, ret2shellcode taught on an NX
  binary, flag laundering, hardcoded flag, scrape-without-running-the-target, and
  replacing the staged binary with `cat flag.txt` before running it), with
  the **positive control first** so a broken harness reports NOT MEASURABLE instead
  of reporting the negatives as passes, and fixtures copied to randomised filenames
  so filename special-casing cannot pass; an explicit **truth table** over the
  verdict and denominator arithmetic including the inflation case; a
  `witness()`/`witness_argv()` differential; and an **end-to-end layer** that drives
  `run_target` itself with a follower scripted inside the test — positive control,
  `UNINFORMATIVE`, a follower that hardcodes the flag it was shown, and an invalid
  bare trial — because decoy-then-remint, the per-rep wipe, the pairing and the
  asymmetric validity rule live there and were otherwise untested. There is
  deliberately no test hook in the product: "the scorer ran with a stub follower"
  must not be a reachable state of a real measurement. Measured: positive controls
  credited, 7/7 broken artifacts refused, 4/4 end-to-end cases correct.
- **Walkthrough scorer — two agent-only cheat channels closed structurally.**
  `run_bench.py` faces a non-adaptive generator that is never handed the flag; an
  interactive follower with a shell is a different adversary. (1) *Hardcoding* is
  closed by **decoy-then-remint**: the follower works against a decoy secret, its
  artifact is frozen and hashed, the sandbox wiped, and the target rebuilt with a
  fresh secret it has never seen. (2) *Runtime laundering* — read `flag.txt` and
  relay it **through** the target, so the target performs the flag-bearing write —
  survives re-minting and is closed by a **behavioural open-audit**: a process
  outside the target's lineage opening `flag.txt` scores `FOLLOWER_LAUNDERED`. This
  was a confirmed false-positive channel, not a hypothetical: with the real
  ret2plt chain and an `echo` of a Python-read flag, write-attribution alone reports
  `credited … the target exec'd a shell`.
- **Walkthrough scorer — the gate refuses to state a verdict on a denominator too
  small to support one** (`MIN_INFORMATIVE_TARGETS = 7`). The necessity control's
  cost, accepted up front, is that every target the bare follower solves unaided
  leaves the denominator as `UNINFORMATIVE`. Measured on round-1 this is not a
  trimmed tail: the bare Tier-3 follower captured the flag on both `hard` targets
  (`08_ret2dlresolve`, `09_srop`) in 2/2 reps, while the engine ships a working
  template for only 5 of 15 targets, none harder than the SROP the bare arm beat
  unaided — so `{walkthrough works} ∩ {bare fails}` is plausibly *empty*. An 85%
  threshold over two targets is not a measurement, so the gate now blocks below
  seven informative targets and reports `NOT MEASURABLE`. Seven is derived, not
  chosen: at n=7 one target cannot decide the gate (6/7 = 85.7% still passes), at
  n=6 it can (5/6 = 83.3%). `--selftest` asserts the floor fires at n=2 *and* does
  not fire at n=8, so it cannot degrade into a blocker that always trips. The
  summary now also spells out both denominators side by side, because "85% of the
  targets where a walkthrough could possibly have mattered" and "85% of the 15
  targets" are different claims and a reader must not be able to mistake one for
  the other. Reasoning, the two rejected alternatives (a weaker follower tier; a
  bounded bare arm) and what would flip the decision:
  `docs/plans/2026-09-24-walkthrough-follower-tier-decision.md`.
- `--affordance {shell,read-only}` for the walkthrough follower
  (`benchmark/walkthrough/followers.py`). Bounding the *bare* arm's budget or tools
  to rescue the denominator is the one fix that must not be made: the bare
  allowance would become a dial wired straight to the headline number, and the arms
  would stop being the same follower, which is the only property that licenses
  attributing an outcome difference to the walkthrough. The affordance profile is
  therefore a property of the shared tier object and cannot be applied to one arm —
  `read-only` withdraws `Bash` from **both** arms, removing the test-and-iterate
  loop (the bare `09_srop` transcript ends "Reliable across 3 runs") rather than
  the budget. Default stays `shell`, which is what every recorded figure used;
  `read-only` is committed **unmeasured** so the tier question can be settled by
  measurement instead of argument, and is recorded as such.
- **Phase 5 (reliability hardening) — stdio-safe multi-part payload delivery**
  (`supwngo/exploit/pipeline/delivery.py`). Every native executor previously delivered
  its payload as a *single* write (`subprocess.run(input=blob)` / one `sendline`), which
  is silently wrong for any target that mixes buffered stdio input with a raw
  `read(0, ...)`: `scanf("%d", &n)` fills glibc's 4096-byte stdin `FILE` buffer from
  whatever is available, so a one-blob exploit is swallowed whole by the first `scanf`
  and the following `read()` sees EOF — the overflow never happens and the target looks
  unexploitable. The new module delivers input in parts with a settle delay between them
  (as a human does at a prompt), and adds `find_return_offset()`, a stdio-safe dynamic
  offset finder that binary-searches the smallest filler length that crashes the target
  (no core dumps required — `kernel.core_pattern` is frequently not a plain file — and no
  GDB batch run, which would re-introduce the single-blob problem). Also adds
  `scan_hex_addresses()`/`classify_address()`, which recognise a leaked `%p` by its
  actual rendering instead of requiring one of a fixed set of English labels before it,
  and test address ranges narrowest-first so `0x7ffd…` stack addresses are no longer
  mislabelled as libc.
- **Phase 5 — generated exploit scripts are now the thing that gets verified**
  (`supwngo/exploit/pipeline/script_builder.py`, `PipelineVerifier.verify_script()`).
  `verify_payload()` can only express a single-blob exploit, so no multi-stage technique
  could ever claim a verified SUCCESS (which is why `ret2libc`/`srop`/`format_string`
  were hardcoded to return PARTIAL prose). Executors now build a standalone, runnable
  pwntools script first and the pipeline runs *that script* fresh in its own interpreter,
  with the attempt's unique receipt token piped in as `echo <token>`; SUCCESS requires
  either the token coming back (only possible through a real obtained shell) or the
  target printing a flag. A generated script's own `log.success()` lines are explicitly
  not a success signal. This also closes the gap between "the pipeline says it worked"
  and "the artifact the user is handed works" — they are now literally the same run.
- **Phase 5 — `ret2plt` technique executor**
  (`supwngo/exploit/pipeline/executors/rop_techniques.py`): calls `system("/bin/sh")`
  through the binary's own PLT with **no information leak**, for a non-PIE target that
  imports `system` and already contains a `"/bin/sh"` string. This closes the specific
  gap named in `docs/reports/PHASE1-BASELINE-24SEP2026.md`: the pipeline's only
  `system()` path was gated on "requires a real libc-base leak" even when no libc base
  is needed at all. Tries both stack parities, since glibc's `do_system` executes a
  `movaps` that faults unless RSP is 16-byte aligned at the call.
- **Phase 5 — `int_truncation_bypass` and `negative_index_write` technique executors**
  (`supwngo/exploit/pipeline/executors/input_shape_techniques.py`), for bugs driven by the
  target's numeric input shape. `int_truncation_bypass` replaces what
  `negative_size_bypass` was attempting: it measures the return-address offset against
  *the same* input sequence the exploit uses (a negative length first, then the overflow,
  delivered as separate parts) instead of guessing from five hardcoded offsets, and proves
  the result by re-running the generated script rather than accepting an output substring
  match that also counted the bare word `"win"`. `negative_index_write` handles an array
  index that is only bounds-checked upwards, sweeping both the element distance and the
  gate constant. Both work on statically linked targets: `has_scanf()` checks the symbol
  table as well as the PLT, since a static binary has an empty PLT but still carries
  `__isoc99_scanf`.
- **Phase 5 — gate constants are now read out of the target's own code**
  (`comparison_immediates()`): a "flip this variable to the magic value" bug is only
  exploitable if you know the value, and the executors previously guessed from a
  hardcoded list of nine CTF-folklore constants. The constants are in the binary's own
  `cmp`/`test` instructions, so they are extracted from `objdump` output (most-plausible
  first) with the old list kept only as a fallback.
- **Phase 5 — `canary_leak_ret2win` technique executor**
  (`supwngo/exploit/pipeline/executors/canary_leak_techniques.py`). A canary-protected
  target that *hands you the canary* (an echo that over-reads past the filler, or a
  format-string `%N$p`) is a two-stage exploit: leak, then overflow with the canary
  replaced. Nothing in the pipeline could express that — `scanf_canary_bypass` assumed the
  canary could be skipped over, and the single-blob verifier could not run two stages at
  all. The new executor finds the leak source generically (windowed `%N$p` probing, or
  sweeping echo fill sizes), identifies which leaked stack word is the canary by structure
  rather than by position (glibc's canary always has a zero low byte and otherwise ≥56
  random bits), and locates the canary's frame offset with an *abort-threshold oracle*:
  the smallest filler that provokes `*** stack smashing detected ***` is the first byte of
  the canary, which turns a 25-deep blind offset sweep into two probes.
- **Phase 5 — `fmtstr_write_gate` technique executor**
  (`supwngo/exploit/pipeline/executors/fmtstr_techniques.py`): format-string arbitrary
  write (`%n`) against a gate variable, for the common shape where the target prints a
  writable address and only checks the variable for non-zero. Locates the user buffer's own
  `printf` argument index by probing for a marker, restricts write targets to genuinely
  writable sections, and — the detail that makes `%n` work at all here — emits the `%N$n`
  directive *before* the target address with the padding ahead of it, because a 64-bit
  pointer's embedded NUL bytes terminate `printf`'s format parsing if the address comes
  first.
- **Phase 5 — `stack_shellcode` technique executor**
  (`supwngo/exploit/pipeline/executors/shellcode_techniques.py`): NX-off stack shellcode
  that uses a *leaked* stack address instead of guessing one, re-reading the leak at run
  time so the script works under ASLR. Places the shellcode *after* the overwritten return
  address rather than inside the buffer — shellcode that lands in the buffer is corrupted
  by its own `push` instructions once `rsp` is pointing into it — and sweeps NOP-sled
  sizes, landing mid-sled for slack.
- **Phase 5 — `ret2libc_leak` technique executor**
  (`executors/rop_techniques.py`): the two-stage GOT-leak ret2libc the Phase-1
  baseline's `ret2libc` executor only *described*. Three details keep it general
  rather than target-shaped: the leak target is the output function's own GOT slot
  (calling `puts@plt` with `rdi = &got[puts]` prints puts' real address even under
  lazy binding, because the PLT stub resolves the slot before the callee
  dereferences `rdi`, so no reasoning about which imports are already resolved is
  needed); the re-entry point for stage two is *derived* by `functions_calling()`,
  which finds the function containing the overflowing read from objdump's
  symbol-delimited disassembly; and a PIE image base is recovered by
  `pie_base_offset()`, which identifies which symbol a printed code pointer belongs
  to using the only invariant available — a PIE load base is page-aligned — instead
  of assuming the target leaked any particular function. The same page-alignment
  test then validates the libc leak, which is what makes the leak locatable without
  depending on the target's prompts or on libc landing in a particular range.
- **Phase 5 — `srop`, `ret2dlresolve`, and `tcache_poison_got` technique executors.**
  `srop` (`executors/rop_techniques.py`) replaces a stub that refused to run unless
  another technique had already found the offset and then returned PARTIAL without
  verifying; it now builds a real `rt_sigreturn` frame, places it immediately after
  the syscall address (where `rsp` points when the kernel reads it), and resolves
  `pop rax`/`syscall` through pwntools rather than from a symbol address — which is
  wrong by 4 bytes on a CET-enabled build, where the usable instruction sits behind
  the `endbr64`. `ret2dlresolve` handles a target with *no* leak primitive at all by
  forging an `Elf64_Rela` + symbol + name bytes and letting the linker resolve
  `system` by name; the hard part it automates is composition — ROP-calling the
  binary's own input function to stage those structures, then delivering them as a
  separate input part. `tcache_poison_got`
  (`executors/heap_techniques.py`) escalates a use-after-free write to an arbitrary
  write, with the two glibc invariants read from the locally loaded libc rather than
  assumed: safe-linking's `(chunk_address >> 12) ^ target` mangling (glibc >= 2.32)
  and `malloc`'s 16-byte alignment check on tcache entries, which forces the target
  address to be aligned down and the payload padded onto the GOT slot. It also frees
  *two* chunks before poisoning, because with a single free the first allocation
  empties the bin and the second never consults the poisoned pointer.
- **Phase 5 — menu protocol discovery** (`executors/heap_techniques.py:discover_menu`).
  The pre-existing heap executors could not exploit a menu-driven allocator because
  they sent one blob and grepped the reply; what was missing was the ability to
  *drive the program*. Menu option numbers are now read from the target's own printed
  menu and mapped to roles (create/delete/edit/show), so no option number is
  hardcoded per binary.
- `benchmark/fixtures/positive-controls/` — two supwngo-generated exploit scripts that
  genuinely obtain an interactive shell (`01_shellcode_stack`, `02_ret2plt_system`), checked
  in unmodified as positive controls for changes to `run_bench.py`. Six corpus binaries
  contain no flag at all, so their only route to one is `cat flag.txt` inside a shell the
  exploit obtained; that makes them silently sensitive to what the harness writes to the
  exploit's stdin, and a harness change can turn a working shell into a `FAILED`. These
  fixtures make that regression cheap to detect. See the directory's README.
- `docs/plans/2026-09-23-phase5-reliability-hardening.md` — the Phase 5 plan, recording
  the five root causes found before any fix was written (single-blob delivery,
  payload-only verification, attempt ordering, label-driven leak parsing, missing
  technique implementations) and the per-target work they imply.

### Removed
- **Phase 5 — two superseded stack executors** (`pipeline/executors/stack_techniques.py`).
  `negative_size_bypass` guessed the return-address offset from five hardcoded values and
  delivered its negative length and its overflow as one blob (so the overflow was eaten by
  the target's own `scanf` and never happened); `int_truncation_bypass` measures the offset
  against the real input sequence instead. `stack_shellcode` wrote the shellcode inside the
  overflowed buffer and jumped to a guessed stack address; `stack_shellcode` in
  `shellcode_techniques.py` places it past the return address and uses a leaked one. Both
  replacements verify by re-running the generated script, so neither can report success on
  an output substring match.
- **Phase 5 — the `SROPExecutor` stub** (`pipeline/executors/heap_and_bypass.py`),
  replaced by `rop_techniques.SropExecutor`. It skipped itself unless another
  technique had already populated `context.offset`, took its gadgets from
  `context.gadgets` (which can hold a symbol address rather than a gadget address),
  and returned PARTIAL without verifying, on the grounds that "sigreturn frames are
  timing/alignment sensitive".
- **Phase 5 — the template-only `ret2libc` executor**
  (`pipeline/executors/stack_techniques.py`). It never built a chain: it returned
  PARTIAL with a one-line prose description of the technique and a failure reason
  pointing at an unimplemented leak-acquisition stage. `rop_techniques.
  Ret2LibcLeakExecutor` now performs exactly those steps for real.

### Changed
- **`benchmark/attribution.py` — `witness()` refactored to delegate to a new
  `witness_argv()`**, so the behavioural witness can attribute an arbitrary command
  rather than only `<python> <script>`. The walkthrough scorer needs this and must
  not own a second copy of "who wrote the flag" — the whole point of that module is
  that there is exactly one answer to the question. `witness()`'s behaviour is
  bit-identical (the traced syscall set defaults to what it has always traced, so
  `run_bench.py` is unaffected), and `selftest.py` asserts the two entry points
  agree on the same artifact.
- **Phase 5 — attempt ordering** (`pipeline/orchestrator.py`): `StrategySuggester` ranked
  `VARIABLE_OVERWRITE` at priority 1 for all 15 benchmark targets (its applicability test
  is nearly always true) and `RET2PLT` at 4, so every target paid ~126 blind magic-value
  process spawns before the technique it actually needed was tried. Added explicit
  `FIRST_TECHNIQUES` (precondition-specific and cheap) and `LAST_TECHNIQUES` (broad
  brute-force sweeps) layers around the suggester's own ranking. The brute-force sweeps
  are still attempted — just last.

### Added
- Phase-1 benchmark corpus + measurement harness under `benchmark/`: 15 purposefully
  vulnerable, hand-verified x86-64 Linux ELF targets (`benchmark/corpus/<NN>_<slug>/`)
  spanning stack shellcode, ret2plt/system, PIE-leak ret2libc, canary leak+bypass,
  format-string arbitrary read/write, ret2libc-via-leak, ret2dlresolve, SROP, integer
  truncation, heap UAF read, heap UAF-write/tcache poisoning, off-by-one, negative-index
  OOB write, and a ret2win sanity baseline, with a documented spread of canary/NX/PIE/RELRO/
  linking protection combinations; an idempotent `benchmark/build_all.sh` builder with the
  exact protection flags per target; `benchmark/corpus.yaml`, a manifest recording each
  target's ground-truth (checksec-verified) protections, intended solve path, difficulty,
  and hand-verified status — all 15 targets were hand-verified end-to-end with real
  pwntools exploit scripts, exceeding the plan's 5-6-target minimum; and
  `benchmark/run_bench.py`, a harness that builds the corpus if needed, runs supwngo's live
  `autopwn` CLI per target with a configurable timeout, and determines SUCCESS only by
  genuinely re-executing the generated exploit script fresh and checking for the
  target-specific flag (never by pattern-matching autopwn's own log/success claims),
  writing a timestamped `report.json` + human-readable summary under `benchmark/results/`
  and supporting `--target`/`--timeout` flags. See
  `docs/plans/2026-09-23-effectiveness-and-usability.md` (Phase 1) and `benchmark/README.md`.
- `docs/reports/PHASE1-BASELINE-24SEP2026.md` — the first honest Phase-1 baseline
  measurement of `supwngo autopwn` against the 15-target benchmark corpus, run against the
  fully consolidated pipeline (Phase 0/2/3/4/6 all present): **2/15 SUCCESS (13.3%), 0
  PARTIAL, 13 FAILED** (easy 2/5, medium 0/7, hard 0/3), classified only by independently
  re-executing each generated exploit script and checking for the target-specific flag,
  never by trusting `autopwn`'s own self-reported success. This is the number Phase 5
  (reliability hardening) starts from. See that report for the full per-target breakdown,
  the harness bug found and fixed while producing it (`run_bench.py` mishandled
  `subprocess.TimeoutExpired`'s always-bytes `stdout`/`stderr` even under `text=True`), and
  why four earlier runs were discarded as stale (benchmarked the pre-consolidation
  `EnhancedAutoExploiter` before this branch was rebased onto
  `integration/phases-0-4-7-20260923`).
- `benchmark/reference_exploits/` — hand-written, standalone **pwntools** reference
  exploits establishing ground truth for the benchmark corpus: one verified script per
  in-scope target (01–12, 14, 15 = 14 targets), each self-checking (exits nonzero unless
  the target's real flag appears in the target's own output), each documenting its
  technique, measured protections, exact offsets, required leaks and nondeterminism in a
  module docstring, plus `run_all.sh` for N-rep reliability runs and a README. **None of
  them import or depend on `supwngo`**, so a failure indicates the target or host
  toolchain changed rather than the framework. Result: **14/14 flag capture at 5/5 reps**,
  and **14/14 still capture a freshly randomized `-DFLAG` secret** (rebuilt with per-target
  flags parsed out of `build_all.sh`, which was not modified) — proving the exploits
  genuinely exploit each bug rather than incidentally printing the corpus's
  deterministic committed flag constant.
- `benchmark/ablation/` — an ablation suite proving every step of each round-1 chain is
  **necessary**, not merely that the chain works. Negative controls only establish that a
  target isn't *trivially* solvable (which is how `11_heap_uaf_leak` slipped through: benign
  input doesn't win, and a "working" exploit does, yet the use-after-free was never
  required). For each meaningfully separable step, `ablate.py` runs the whole chain with
  exactly that step removed and requires the flag not to appear. Each target has one
  parametrised chain function whose defaults are the working exploit, so every ablation is
  one flipped keyword on the same code and each target also gets a positive control — a
  `BLOCKED` verdict therefore can't be an artifact of broken harness code. Targets are
  rebuilt with a fresh random secret via `run_bench.build_with_secret()`, all emitted bytes
  are checked, and the run holds `corpus_lock`. CLI mirrors the R4 harness (`--case`,
  `--timeout`, `--list`, `--no-rebuild`, `--corpus-root`; exit 0 = every ablation failed to
  produce the flag, 1 = a step was unnecessary, 2 = setup problem). Result: **49/49 strict
  ablations blocked, 13/13 positive controls passed** — no further round-1 target measures
  less than it claims.
- `docs/reports/CORPUS1-ABLATION-24SEP2026.md` — the ablation audit write-up: per-target
  table of which steps were removed and the result, the method argument for why a `BLOCKED`
  verdict is trustworthy (positive control from the same parametrised chain), the
  clean-checkout portability proof, and three `RELAXATION` findings where a documented
  detail turns out not to be required. One of those corrects an error in the 23 Sep report:
  target 05's `%29$p` is **not** a decoy canary — the canary is per-thread (`%fs:0x28`) and
  stamped identically into every frame (measured byte-identical across runs), so frame
  attribution is not a step a solver must get right and 05's automatability rises to
  MEDIUM-HIGH. The genuine trap is `%13$p`, a libc pointer that also ends in `0x00`, which
  ablation confirms is blocked.
- `docs/reports/CORPUS1-REFERENCE-EXPLOITS-23SEP2026.md` — the per-target ground-truth
  write-up behind those scripts (technique, offsets/addresses, what must be leaked and how
  it is applied, nondeterminism, and an honest automatability read per target), plus
  cross-cutting build facts that break automated exploitation on this corpus (CET/IBT
  shifts every provided `gadget_*` symbol by a 4-byte `endbr64`, so `sym+1` is *not* a bare
  `ret`; every libc call needs a 16-byte stack-alignment `ret`, twice when the chain
  returns into `vuln()`; oversized `read()`s swallow follow-up writes without a delay), and
  **three benchmark-soundness defects**: `13_off_by_one` is VOID (ordinary ≥32-byte input
  alone triggers `win()`) and excluded; `11_heap_uaf_leak` is likewise VOID — `show(0)`
  with no `delete` prints the flag from the *live* chunk, so no use-after-free is required;
  and the flag is recoverable with `strings` from 8 of the 14 binaries (04, 05, 06, 10, 11,
  12, 14, 15), which randomizing `-DFLAG` does **not** fix because the random flag is still
  compiled into `.rodata`. Recommends having `win()` read `flag.txt` at runtime.
- **`benchmark/run_bench.py` now runs N reps per target (`--reps`, default 5) and
  reports BOTH `solved` and `reliability`.** Exploit delivery is not
  deterministic, so a single rep can understate capability for reasons unrelated
  to whether the framework can exploit the target — measured 4/96 delivery
  failures on one probe under 24-way contention against 0/40 unloaded, i.e. the
  flake rate rises with load, which is exactly when a benchmark tends to run.
  `solved` is "credited in at least one rep"; `reliability` is k/N. Neither is
  the score alone — quoting best-of-N without reliability overstates the result,
  quoting one rep understates it — and `summary.txt` says so, calls out
  intermittently-solved targets explicitly, and reports how many targets have no
  reliability figure. `reps` is recorded in `report.json` beside `jobs` and
  `strict_attribution`. Reps run sequentially within a target (each rebuilds the
  binary with a fresh secret, so concurrent reps would race), and a `VOID`
  settles a target immediately rather than being re-rolled, since the controls
  and provisioning checks are deterministic. Each rep gets its own results
  subdirectory so an intermittent target's evidence is not overwritten.

### Fixed
- **`benchmark/attribution.py` recorded FAILED `execve` calls as successful
  target executions** — a live false-credit channel in the existing harness, not
  only in the new scorer. `parse_trace` accepted an exec event unless the trace
  line mentioned `ENOENT` or `EACCES`, so `E2BIG`, `ENOEXEC`, `EPERM` and `ELOOP`
  failures each created a phantom "the target was exec'd" event — which is the
  premise the entire lineage rule rests on. An artifact could force
  `execve(target, huge_argv)` to fail with `E2BIG`, then read and print the flag
  itself, and every subsequent write in that process would be attributed to the
  target. Replaced the errno **denylist with a success allowlist** (the syscall
  result must be exactly `= 0`), verified against a real trace. A strict
  tightening: it can only remove credit, never add it. Found by independent
  review of the walkthrough scorer. **Retroactively cleared against every
  published number** (`docs/reports/2026-09-24-execve-denylist-retrocheck.md`,
  tool `benchmark/soundness_probes/execve_denylist_retrocheck.py`): all 214
  credited reps across R1's three authoritative runs and R2's cold run were
  re-derived under the fixed parser and none rested on a failed `execve`; a wider
  sweep of all 217 archived traces found the same. The *guarantee* was weaker than
  documented for that period; the *measurements* — R1 13/13, R2 cold 4/15 — are
  unaffected. The only `execve` failures these workloads produce are the
  `ENOENT`/`EACCES` of PATH and library-path probing, which the old denylist
  already rejected; the dangerous errnos have to be constructed deliberately.
- **Walkthrough scorer — hardening from independent implementation review**
  (`docs/plans/reviews/2026-09-24-walkthrough-scorer-implementation-review-codex.md`,
  12 BLOCKING findings). Each of these could have manufactured a walkthrough
  credit: a nonzero follower exit that left a partial `exploit.py` counted as an
  *observed failure*, and an observed failure in the bare arm is exactly what
  grants credit — now **any** nonzero exit is invalid; `gate_result` gained
  blockers for missing `strace`, `--strict-attribution` off, `reps < 2` and any
  runtime-discovered `VOID`, **and is now called with those arguments** (the
  signature had gained them while the call site still passed positionally, so two
  blockers silently defaulted to "satisfied" and could never fire); the follower's
  whole process group is now torn down after every session and **before** the
  scored secret is minted, closing a daemon-survives-and-exfiltrates window;
  `resolve_walkthrough` raises on an ambiguous match instead of taking the first,
  because a verdict attached to the wrong artifact is worse than a missing one;
  each rep now wipes both sandboxes **before** the follower runs, so rep *N*
  cannot build on rep *N−1*; the arms moved to separate roots so `../walkthrough/`
  no longer resolves; re-staging `lstat`s and refuses to follow follower-planted
  aliases; results directories are exclusive so a same-second collision fails
  loudly rather than overwriting a measurement; and a new `_attest()` pins inode,
  `st_ctime_ns`, size and hash of the artifact, the target and `flag.txt` across
  the scoring window, so an artifact that overwrites the staged binary with
  `cat flag.txt`, runs it at the target's pathname and restores the bytes is
  caught — `fixtures/broken_overwrites_target.py` performs that attack and the
  selftest asserts the detection. Holes that need a privilege boundary (same-UID
  writable sandbox, name-based flag protection, shared `HOME`) are **not** claimed
  as fixed; they are enumerated in `benchmark/walkthrough/README.md`, and all of
  them bias the walkthrough arm upward, so the figure is an upper bound.
- **`benchmark/soundness_probes/drive.py` never exercised behavioural
  attribution, so the tool that validates the harness could not fail.** It called
  `classify()` without the `attribution=` argument that `run_one()` always
  passes, testing a code path the harness does not use. It reported "no holes"
  while the single most important check was absent — false assurance, which is
  worse than no test. It also still branched on a `WEAK ATTRIBUTION` marker that
  behavioural attribution had superseded, so once that string disappeared the
  driver began reporting a spurious `*** FALSE POSITIVE -- NEW HOLE ***` for
  `pure_python_scrape.py` on `15_win_function`. **The harness itself was never
  affected:** driven through the real path that probe is `VOID`
  /`script_gamed_the_check` with `credited_writers: []` in both default and
  strict mode. The driver now witnesses and classifies exactly as `run_one()`
  does, checks **both** default and strict (rejection only under strict would
  mean a default run is scoreable by a script that never exploited anything),
  prints the attribution chains as the load-bearing evidence, exits non-zero on
  any failure, and refuses to claim anything about false negatives when no
  genuine-exploit probe was run.
- **`benchmark/run_bench.py` recorded only one rep's secret flag, making the
  other reps' verdicts unfalsifiable.** Every rep rebuilds the target with a
  fresh secret, but the rep-aggregated record can carry only one of them, so for
  a 5-rep target the verdicts for reps 2-5 could not be re-derived from their own
  archived `strace.log` — an auditor would not know which string to search for,
  and a wrong verdict in a later rep would have been permanently undetectable.
  Independent re-checkability is the one property this harness exists to provide.
  Found when a cross-check over all 17 archived traces reported reps 2-5 as
  `no_flag` purely because it was matching rep 1's secret against their traces.
  `attempts[]` now records each rep's own `secret_flag`.
- `benchmark/run_bench.py`'s multi-rep records now carry `elapsed_sec_total`.
  A rep-aggregated result inherits `elapsed_sec` from one representative attempt,
  so summing that field across a `--reps 5` report understated the run's real
  cost by about 5x — a 5-rep run appeared to cost the same as a 1-rep run
  (1685s vs 1659s). `elapsed_sec` keeps its old meaning for comparability with
  single-rep reports, and per-rep times were already in `attempts[]`.
- **`benchmark/run_bench.py`'s headline success rate did not admit it was a
  best-of-N figure.** With `--reps 5`, `OVERALL: 2/3 SUCCESS (66.7%)` counted a
  target that succeeded once in five attempts identically to one that succeeded
  five times out of five — and the headline is the number that gets quoted
  downstream, so deferring the disclosure to the `SOLVED vs RELIABILITY` block
  further down the file did not help. Same failure mode as a silently shrunken
  VOID denominator: a true-but-incomplete number that reads as better than
  reality. The headline now states that SUCCESS means credited in at least 1 of N
  reps, and splits the successes into fully-reliable versus intermittent. A
  single-rep run makes no best-of-N claim.
- `benchmark/run_bench.py`'s serial multi-rep progress output did not say which
  target it was reporting on. Suppressing `run_one`'s per-step chatter for
  `--reps > 1` is right — five copies per target buries the result — but it left
  the reps loop printing anonymous `-> SUCCESS: solved=True reliability=1/3`
  lines, so a serial `--reps 5` run (the default rep count) produced verdicts the
  operator could not match to targets. The loop now prints a per-target header, a
  line per rep, and a verdict line that repeats the slug. Parallel runs are
  unchanged and stay silent, which is what keeps 8 workers from splicing their
  output together.
- **A stdin delivery race in `benchmark/soundness_probes/real_exploit_02_explicit.py`
  made a genuine exploit fail under load.** The target does one
  `read(0, buf, 300)`, and `read()` returns as soon as any data is available, so
  an unsynchronised script races it two ways: the payload can be consumed before
  it has fully arrived, or — because `sendline()` is a separate pipe write — the
  same `read()` can swallow the payload *together with* the shell commands,
  spawning a shell whose stdin is already empty. That produces the confusing
  pair `shell_proven=True, flag_found=False`. Measured 4/96 failures under 24-way
  contention and 0/40 unloaded; synchronising on the prompt and letting the
  payload be consumed alone gives 0/96. Raising the `recvall` deadline alone only
  halved it (2/96), so the deadline was a contributing factor and the
  synchronisation is the fix. Worth generalising: any target with a single large
  `read()` will punish a fire-and-forget delivery layer, and it fails in a way
  that looks like a capability limit rather than a race.
- **`benchmark/attribution.py` reached three wrong verdicts about who wrote the
  flag.** The process tree was reconstructed correctly; the reasoning over it
  was wrong. All three fixes make attribution *more* accurate, not more
  permissive, and `tests/test_bench_attribution.py` pins each with a fixture (5
  of its 11 tests fail against the pre-fix module):
  - **False VOID against real exploitation.** The target was identified by its
    *current* image, but `execve` in place replaces a pid's image without ending
    the process — a shellcode or SROP solve execs a shell in the target's own
    pid, so that pid reads `dash` and the target appears never to have run.
    `system()` forks and so kept its name, which is why this hid: it
    systematically under-credited only the hardest techniques.
  - **False accusation of cheating against a working exploit.** A `write`
    record split by strace's `<unfinished ...>`/`<... resumed>` pair matched
    nothing in either half, so the real writer vanished, while pwntools'
    `io.interactive()` relay thread echoed the same bytes in one complete line
    and was reported as the writer — yielding `script_gamed_the_check`. Because
    it depends on whether the kernel interleaves another pid's line mid-write,
    it was non-deterministic: identical code disagreed between runs minutes
    apart. Split records are now rejoined per pid before any matching, and a
    `CLONE_THREAD` writer is resolved to the process it belongs to.
  - **False SUCCESS (pre-existing).** Because the target was identified by its
    latest image, a script that scraped the flag, printed it, and *then* exec'd
    the target was credited — exactly the channel attribution exists to close.
    Credit now requires an ancestor to have exec'd the target *strictly before*
    the write, which is also what keeps the first fix above from turning a false
    VOID into a false SUCCESS.
- `benchmark/run_bench.py`'s `report.json` now records `strict_attribution` and
  `jobs` — the worker count the run *actually used*, clamped to the target count,
  since `run_targets()` goes serial for a single target and a report claiming 8
  workers for a 1-target run would misdescribe its own provenance. Both settings
  change what a verdict *means* — `strict_attribution`
  decides whether an unwitnessed success scores at all, and `jobs` is the
  scheduling shape the run used — so a report omitting them could not be
  compared against another report. Found by exercising `--corpus-root` end to
  end against an alternate corpus; a test now asserts the report carries every
  setting that affects interpretation.
- `benchmark/build_all.sh`'s fail-closed message for a target with no `cflags`
  file cited README rule R8; the rule is R9. The message is what an operator
  reads when a build refuses to guess protections, so the wrong pointer sends
  them to the wrong rule.
- `benchmark/run_bench.py`'s VOID-cause legend said "The four causes" while
  listing seven.

### Security
- **`benchmark/run_bench.py` could report `SUCCESS` without any exploitation
  having occurred, invalidating the `2/15` Phase-1 baseline.** Two
  independent false-positive channels were found and reproduced
  adversarially; full audit and reproductions in
  `docs/reports/HARNESS-SOUNDNESS-AUDIT-23SEP2026.md`.
  - The fixed 48-byte stdin the harness piped into each re-executed exploit
    (to give shell-obtaining exploits a chance to `cat flag.txt`) was itself
    enough input to trigger `13_off_by_one`, whose `read(0, s.buf, 32)`
    returns 32 for *any* input of ≥32 bytes and then writes `s.buf[32]`.
    A "script" whose entire body was `subprocess.run(['./off_by_one'])` —
    no payload, no offset, no address — scored `SUCCESS`. The harness was
    solving the target itself.
  - `build_all.sh` derived the flag by grepping `FLAG{...}` out of the
    target's **git-committed** C source, so the "secret" was a public
    constant, identical on every build and compiled verbatim into the
    `.rodata` of all 9 win()-style targets. A script that printed that
    literal, or ran `strings` over the binary, scored `SUCCESS` on 9 of 15
    targets — including both baseline successes.
  - Fixes: every target is now rebuilt per run with a fresh, unguessable
    `FLAG{<32 hex>}` secret (passed to the builder via
    `SUPWNGO_BENCH_FLAG`, compiled in via `-DFLAG` — no `.c` file changed,
    since every win()-style source already guards its flag with
    `#ifndef FLAG`) and the harness fails closed to `VOID` if the secret
    did not actually land in `flag.txt` and the binary; **three negative
    controls** run each target with no exploit at all (the injected stdin,
    512 bytes of filler, and a benign menu walk) and `VOID` the target if
    the flag appears, which is the structural guarantee that generalises to
    future corpora — each with its own distinct `VOID` cause, since "the
    harness solved it", "the corpus target is trivial" and "the build broke"
    demand opposite responses and pooling them would let an infra regression
    read as a score improvement; the injected stdin is shortened to 27 bytes and its
    marker is now shell arithmetic (`echo $((6*7))`) so a real command
    interpreter can be distinguished from a target echoing its input; and
    the generated script is statically audited, scoring `VOID` if it
    contains the secret literal, reads `flag.txt` itself in Python, or
    shells out to `strings`/`objdump`/`readelf`/`xxd` at runtime (narrow by
    design — `sendline(b'cat flag.txt')` to an obtained shell is the
    legitimate solve path and is not flagged).
  - Corrected baseline: `13_off_by_one` and `11_heap_uaf_leak` become `VOID`
    and `15_win_function` is re-confirmed as a success against a per-run
    secret. **`2/15` (13.3%) becomes `1/13` scorable (7.7%).** Do not cite
    the superseded number.
- **A second unmeasurable target: `11_heap_uaf_leak` never required its
  use-after-free.** `show_note()` gates only on `chunks[idx]` being non-NULL
  and in range, never on liveness, and `main()` pre-populates index 0 with the
  flag — so `printf '3\n0\n' | ./heap_uaf_leak` writes the flag out of a
  **live** chunk with no `free()` ever called. It would have started "passing"
  the moment `autopwn` learned to drive a menu, crediting zero heap reasoning.
  Caught by a new standard negative control (`bare_run_menu_walk`) that walks
  the first few menu options with small integers.
  - The first version of that control fed **one concatenated stream** to a
    single process and reported the target clean, because the stream selects
    the menu's `exit` option before reaching the leaking one. Each probe now
    runs in a **fresh process**, and a regression test forbids the
    single-stream form. A negative control that passes is only evidence once
    you have checked it is capable of failing.
- **Per-build flag randomisation did not close the `strings` channel.** The 9
  win()-style targets necessarily compile a `FLAG` literal into `.rodata`, so
  `strings <bin> | grep FLAG{` still yields the secret with no exploitation —
  and that is routine first-step recon a framework could walk into without
  intending to cheat. The harness now measures the channel **behaviourally**
  (it really runs `strings`) every run as
  `flag_scrapeable_without_exploit`, labels such a `SUCCESS`
  `[WEAK ATTRIBUTION]`, and breaks weak from strong successes out in
  `summary.txt`. The six shell-based targets contain no flag at all, so for
  them a flag in the output can only have come from the running target.
  Durable fix is corpus-side (README R8: have `win()` print the *contents of*
  `flag.txt`); `--strict-attribution` excludes the affected targets meanwhile.
  - **The earlier claim that "every non-exploiting probe is now rejected" was
    overstated and is withdrawn.** An independent review defeated the script
    audit with several two-line scripts
    (`subprocess.run(['cat','flag.txt'])`, `open('flag'+'.txt')`,
    `glob.glob('*.txt')`, `Path('.').iterdir()`,
    `ELF(b).search(b'FLAG{')`). The known forms are closed, but verification
    is not sandboxed and the audit is a **bypassable heuristic, not a proof**.
    `SUCCESS` means "the script produced this run's secret and tripped no known
    cheat pattern". **This is now fixed at the root by behavioural attribution
    (see `benchmark/attribution.py` under Added): a `SUCCESS` requires the flag
    to have been written by the target's own process tree, so the pattern audit
    is no longer the thing standing between a scrape and a score.** The audit
    remains only as a fallback for hosts without `strace`, where results are
    explicitly labelled `UNWITNESSED`.
- A `provisioning_failed` `VOID` now **withholds the success rate entirely**
  (`RATE WITHHELD`, raw counts only) instead of printing a rate under a warning
  banner. Because any `VOID` shrinks the denominator, a build/infra fault would
  otherwise read as a score *improvement*.

### Added
- **`benchmark/attribution.py` — behavioural attribution. A `SUCCESS` now
  requires observing the exploitation event, not inferring it from a string.**
  This is the root fix for the whole class of false positives above: the flag
  string was a *proxy* for exploitation, and every channel found lived in the
  gap between the proxy and the thing. The harness no longer asks whether the
  flag appeared, it asks **who wrote it** — the script is re-executed under
  `strace -f`, the process tree is reconstructed from `execve`/`clone`/`write`,
  and a `SUCCESS` is credited only if the flag was written by the **target
  process or a descendant of it** (the target's own `win()`, or `cat` under a
  shell the exploit obtained). A write by the script, or by a child of the
  script, is not credited.
  - Closes `cat flag.txt`, `open('flag'+'.txt')`, `glob`, `strings` and
    `ELF.search` **in one move**, including variants nobody has enumerated,
    because none of them route the bytes through the target's address space.
    Notably it closes `pure_python_scrape.py`, which no regex can catch and
    which was documented as an open hole in the previous release note.
  - A missing witness is **not** a negative witness: no `strace` or denied
    ptrace yields `inconclusive`, the result falls back to the old string-match
    path, and it is labelled `UNWITNESSED`. `summary.txt` always reports
    witnessed and unwitnessed successes separately and says outright when
    `strace` is absent, so both numbers can be quoted.
  - `--strict-attribution` changed meaning accordingly: it now requires a
    behavioural witness for every `SUCCESS` (`VOID`/`unwitnessed_success`),
    replacing the previous "VOID anything scrapeable". Scrapeability survives
    only as a severity note on the unwitnessed fallback path — it is no longer
    load-bearing, because a scrapeable `.rodata` literal can no longer score.
  - Verified with `benchmark/soundness_probes/attribution_sweep.py` (exits
    non-zero on any discrepancy): all four non-exploiting probes are rejected
    and genuine exploits for **both** target families are credited — the two
    `ret2plt` shapes on `02_ret2plt_system` (with `shell_exec_by_target` as a
    behavioural shell witness, replacing the fakeable `echo $((6*7))` marker)
    and a new `real_exploit_15.py` ret2win on `15_win_function`.
  - Residual gap, stated rather than papered over: a script could deliberately
    write the flag into the target's own output channel. That takes real effort
    rather than a shortcut, but it is not structurally prevented; witnessing the
    target's control flow directly (a breakpoint on `win()`) would close it.
- **`benchmark/run_bench.py --jobs/-j`: targets now run in parallel**, one
  worker per core capped at 8 (`--jobs 1` forces the old serial behaviour).
  A full 15-target run was the rate limiter on the whole project at roughly 28
  minutes serial. Integrity is preserved deliberately over raw speed:
  - Results are reported in **manifest order regardless of completion order**,
    so a parallel run and a serial run produce the same report.
  - Each target is confined to its own directory and gets a private `TMPDIR`;
    `~/.supwngo/libcs` stays shared on purpose (a read-mostly download cache
    keyed by distinct filenames — isolating it would make several targets
    re-fetch libc over the network, trading a real flakiness risk for a
    theoretical one). `autopwn` does not touch the SQLite database that would
    otherwise be shared state.
  - A crash or hang in one target **cannot** alter another's verdict: it becomes
    a `harness_error` `VOID`, which is *fatal* and withholds the whole run's
    rate rather than quietly shrinking the denominator and reading as a score
    improvement.
  - Per-step logging is buffered per target and flushed as one block, so
    interleaved workers cannot splice misleading log lines.
  - Build caching was considered and **rejected**: `gcc` on one small C file is
    milliseconds against ~2 minutes of `autopwn` per target, so it would save
    under 1% while risking the thing that matters — the win()-style targets
    compile the flag in, so a cached binary would carry a stale flag and
    silently break per-run flag rotation.
- `benchmark/run_bench.py` gained `--corpus-root` and `--manifest`, defaulting
  to `benchmark/corpus/` and `benchmark/corpus.yaml`, so later rounds
  following the `benchmark/corpus_r<N>/` + `benchmark/corpus_r<N>.yaml`
  convention reuse the harness unchanged; results are written to a sibling
  `benchmark/results_r<N>/`. `build_all.sh` correspondingly honours
  `SUPWNGO_BENCH_CORPUS` to point at an alternate corpus tree. Because
  per-target protection flags **are** part of the measurement, a target
  directory the builder does not recognise declares them in a `cflags` file
  beside its source (one gcc flag per line, `#` comments allowed); absent that
  file the build **fails closed** naming the missing path, rather than quietly
  building with default protections and measuring a different challenge than
  the manifest claims (README R9). Verified end-to-end on a synthetic
  `corpus_r9` target, both the building and the fail-closed path — the earlier
  `--corpus-root` support was inert for new corpora, since the builder's `case`
  rejected every unknown directory.
- `benchmark/run_bench.py` now reports a fourth status, `VOID`, for targets
  that cannot be measured (negative control leaked the flag, provisioning
  could not establish a real secret, or the generated script gamed the
  check). `VOID` targets are excluded from the success-rate denominator
  rather than silently counted as passes or failures.
- `benchmark/run_bench.py` gained `--strict-attribution`, which `VOID`s any
  target whose flag can be scraped from the binary image with no exploit
  (measured per run). Default off, because that exposure is inherent to
  win()-style targets and excluding them is a corpus decision, not a scoring
  change; the flag exists to measure how much of a score rests on the
  bypassable script audit.
- **Canonical flag/build convention for every benchmark corpus** (rules R1–R9)
  documented in `benchmark/README.md` under "Flag and build convention
  (CANONICAL)", so the `benchmark/corpus_r<N>/` rounds adopt it identically:
  no flag derivable from target name or committed source and no flag literal
  ever committed; fresh `secrets.token_hex(16)` secret per target per run at a
  fixed length (a corpus contract — a target copying its flag into a
  fixed-size buffer bounds it); the exact `#ifndef FLAG` guard plus
  `-DFLAG="\"$flag\""` compile-time injection form; the same secret written to
  `flag.txt` for shell-obtaining targets; the required gitignore entries;
  fail-closed provisioning checks; the requirement that every new target
  **fail** all three of its negative controls (R7); the preference for a `win()`
  that prints the *contents of* `flag.txt` over a compiled-in literal (R8); and
  the `cflags` declaration an alternate corpus needs (R9).
- `benchmark/soundness_probes/negative_control_sweep.py` — sweeps a whole
  corpus for targets that leak their flag to benign input (convention rule
  R7), rebuilding each with a fresh secret. Runs in seconds per target because
  it never invokes `autopwn`, and exits non-zero if any target is unmeasurable
  or mis-provisioned, so it drops into a corpus build script. Supports
  `--corpus-root`/`--manifest`. On the R1 corpus it reports `13_off_by_one` and
  `11_heap_uaf_leak` as unmeasurable and flags the 9 scrapeable targets; the
  other 13 are clean.
- `benchmark/soundness_probes/` — the committed, re-runnable adversarial
  probes behind the audit above (three non-exploiting scripts that must never
  score `SUCCESS`, plus two genuine hand-written ret2plt exploits, in both
  `io.interactive()` and explicit-`sendline` shapes, that must never be lost
  to buffering or the new anti-gaming checks), with a `README.md`.
- `tests/test_bench_harness_soundness.py` — 56 pure-logic regression tests
  over the harness's classification rules, the three negative controls and
  their distinct `VOID` causes, anti-gaming detection, attribution strength,
  secret-flag hygiene, corpus parameterisation, denominator/rate-withholding
  behaviour, and output excerpting.

### Fixed
- **`tcache_poison_got` threw away the evidence of its own success**
  (`supwngo/exploit/pipeline/executors/heap_techniques.py`). The generated
  script triggered the hijacked GOT slot, drained the reply with
  `io.recvrepeat(0.5)` for synchronisation, *discarded the return value*, and
  then called `io.interactive()` — which had nothing left to display, because
  `recvrepeat` consumes what it reads. Every step of the corruption (two
  frees, safe-linking mangle, 16-byte-aligned target, allocation landing on
  the GOT, the overwrite) was working; `win()`'s output was simply never
  printed, so verification saw an empty run and the technique looked broken.
  The trigger's output is now written to stdout.
- **`tcache_poison_got` could pick a self-referential GOT target**
  (same file). Redirecting a slot that `win()` itself calls — e.g. `puts@got`
  for the usual `win() { puts(FLAG); }` — makes `win()` re-enter through the
  slot it was reached by and recurse until the stack is gone, producing no
  output at all and looking identical to a failed primitive. Callees of the
  win function are now read from the binary's disassembly (`callees_of()`) and
  excluded from the candidate list.
- **`ret2dlresolve` never tried the aligned stack parity**
  (`supwngo/exploit/pipeline/executors/rop_techniques.py`). Every other ROP
  executor sweeps both parities, because glibc's `do_system()` executes
  `movaps` and faults unless RSP is 16-byte aligned at the call; the
  dl-resolve path was treated as exempt. It is not — `_dl_fixup` and the
  symbol it resolves execute aligned SSE stores too, so a chain that leaves
  RSP 8-mod-16 faults *inside the dynamic linker*. The resulting
  `SIGSEGV`/`si_code=SI_KERNEL`/`si_addr=NULL` looks nothing like a payload
  problem and is easy to misread as a wrong relocation index, which is how it
  went unnoticed: the forged `Elf64_Rela` was arriving correctly the whole
  time. The executor now sweeps offset candidates × both parities and emits a
  bare `ret` before the staging call when flipping.
- `benchmark/run_bench.py`'s recorded verification output was unauditable:
  `output_tail` kept only `out[-4000:]` of `stdout + stderr` concatenated, so
  the tail was always the *end of stderr* — in practice pwntools/unicorn
  deprecation warnings — and the actual flag/shell evidence never reached
  `report.json`. `stdout` and `stderr` are now recorded separately, each
  keeping head *and* tail with an explicit omission marker.
- `benchmark/run_bench.py` had no guard against a degenerate flag: an empty
  `flag.txt` would make `"" in output` true and score **every** target
  `SUCCESS`. Flags shorter than 16 characters are now a provisioning fault
  (`VOID`).
- `benchmark/run_bench.py` now takes a lock on the corpus root
  (`corpus_lock()`) and fails fast if another run holds it. Because each run
  rebuilds the targets with a fresh secret flag, two concurrent runs over one
  corpus would clobber each other's binaries and `flag.txt` files and produce
  spurious `FAILED`s rather than an obvious crash.
- **Phase 5 — our own timeout-kill was being counted as a target crash**
  (`pipeline/delivery.py`). `deliver_parts()` read the exit status *after*
  `io.close()`, which kills a process that is still running, so every probe against
  a target that loops for more input (`while (1) { vuln(); }`) came back
  `crashed=True` with `rc=-9`. Crash-threshold offset discovery therefore returned
  the smallest length it tried — 8 — on every such target, and the resulting chains
  failed in a way that looks exactly like having picked the wrong technique. The
  status is now read before closing, and only genuine fault signals
  (`SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE`/`SIGABRT`/`SIGTRAP`/`SIGSYS`, not `SIGKILL`)
  count as a crash, with a short reap window so a fault that has not yet been
  reaped is not misread as "still running".
- **Phase 5 — `stack_shellcode` committed to a single measured offset** and so broke
  when crash detection was corrected: the probe measures 80 on
  `01_shellcode_stack` where the return address is at 72, and a wrong offset there is
  indistinguishable from wrong shellcode placement. It now sweeps offset candidates
  like the ROP executors do.
- **Phase 5 — the measured offset is now treated as a candidate, not an answer**
  (`executors/_shared.py:resolve_offsets()`). The crash threshold lands on the first
  byte of whatever follows the buffer, and whether the return address is 8 bytes
  further on depends on details not visible from outside (frame pointer, padding,
  whether the probe's trailing newline overflows). Measured against targets with
  independently known-correct offsets the probe is right most of the time, 8 off
  otherwise, and on some targets not even deterministic between runs. Executors now
  sweep the measurement and its 8-byte neighbours; because each candidate is proven
  by re-running the generated script, a wrong one costs one cheap run instead of
  being misdiagnosed as a wrong technique.
- **Phase 5 — generated exploit scripts are now portable.** The script hardcoded the
  target's absolute path as it was at generation time, so the artifact broke as soon as it
  was copied anywhere (handed to a teammate, checked in as a fixture). It now falls back to
  a binary of the same name sitting next to the script.
- **Phase 5 — a generated script's process factory could be shadowed by the exploit body**
  (`pipeline/script_builder.py`). The factory was named `start()`, and exploit bodies
  routinely bind short local names; a multi-stage body that assigned e.g.
  `start = echoed.find(fill)` between its first and second connection turned the second
  `start()` call into `UnboundLocalError`, so a genuinely working two-stage exploit failed
  at run time *after* the pipeline had verified the technique. Renamed to `open_target()`
  and documented why the name is deliberately not a common local.
- **Phase 5 — the profiling stage silently discarded most leaked pointers**
  (`pipeline/profile_stage.py`). `_parse_address_leaks()` only recognised a printed `%p`
  when it was introduced by one of a fixed set of English words
  (`address|gift|leak|ptr|pointer|stack|heap|libc`, or a bare `at`/`is`/`=`), so the two
  most common real phrasings in the benchmark corpus — `printf("buf @ %p")` and
  `printf("chunk[%d] @ %p")` — were dropped outright, leaving every executor that depends
  on a stack or heap leak with nothing to work from even though the target had handed the
  address over. It now matches a pointer by its actual rendering via
  `delivery.scan_hex_addresses()` and buckets it with `delivery.classify_address()`, which
  also fixes an ordering bug that could label a `0x7ffd…` stack address as libc.
- `CanonicalAutopwnEngine`'s verified-`SUCCESS` path could leave
  `engine.exploit_script` empty: only the template/`PARTIAL`-only executors
  (`srop`, `format_string`, `ret2libc`) ever populated
  `AttemptRecord.partial_artifacts["exploit_script"]`; the native
  stack/shellcode executors (`ret2win`, `direct_shellcode`,
  `variable_overwrite`, `negative_size_bypass`, `stack_shellcode`,
  `scanf_canary_bypass`, `uaf`, `double_free`) verify a raw payload
  in-process and stop, so a fully verified run of any of those techniques
  wrote an *empty* file when `autopwn -o <path>` (or the new `solve`
  command) tried to save the exploit script — directly undermining the
  "one command produces a usable artifact" goal. Added
  `templates.generate_success_script()` (packages an
  already-verified-working payload into a standalone pwntools script — not
  new exploitation logic) as a fallback in `orchestrator.py`'s success
  branch whenever an executor didn't produce its own script. Found while
  building the `solve` command's success-path smoke test.

### Added
- `supwngo solve <binary>` — the unified, one-command entry point from
  Phase 6 of the effectiveness/usability plan. Thin wrapper over the same
  `CanonicalAutopwnEngine` `autopwn` drives (not a second engine — see
  docs/architecture/2026-09-23-autopwn-pipeline.md, "solve vs autopwn"),
  with: a minimal flag surface (`--remote`, `--libc`, `--timeout`,
  `--json`; no `--offset` escape hatch); a working exploit script always
  written to a predictable default path
  (`./solve_output/<binary-name>_exploit.py`) even without `-o`, on both
  success and failure, unlike `autopwn` where `-o` is opt-in; the
  Phase-4 structured hand-off shown on every non-`SUCCESS` result; and a
  `--remote HOST:PORT` flag that templates the written script's
  `REMOTE_HOST`/`REMOTE_PORT` (technique attempts still run locally for
  verification — `CanonicalAutopwnEngine` has no remote-delivery path yet,
  documented honestly in the architecture doc rather than silently
  wired to something that doesn't work). `autopwn` is unchanged and
  remains available for scripting/power users who want its wider flag
  surface and opt-in-only output.
- `solve --interactive` — guided fallback mode (Phase 6, capped at
  "supply one missing fact and resume" per the plan). On a
  partial/failed result, lists the run's `blocking_unknowns` that have a
  known resume mapping (offset, canary value, libc base, PIE base),
  prompts for one and its value, and retries via
  `CanonicalAutopwnEngine.run(known_facts=...)`. A simplified resume (a
  fresh full pipeline run with the one fact pre-seeded), not true
  mid-pipeline resumption — documented as such. Manually verified against
  a real ret2win target whose buffer size pushes the offset past
  `Ret2WinExecutor`'s common-offset fallback list: a plain `solve` run
  FAILs with the offset flagged as blocking; `--interactive`, given the
  real offset, resumes to verified `SUCCESS` (`FULL_CONTROL`).
- `CanonicalAutopwnEngine.run(known_facts=...)` / `_apply_known_facts()` —
  a small resume hook that pre-seeds one user-supplied fact (`offset`,
  `canary_value`, `libc_base`, or `pie_base`) onto `ExploitContext` before
  the technique-attempt loop runs, so an executor that would otherwise do
  a blind search for that fact (e.g. `Ret2WinExecutor`'s GDB/common-offset
  search) can skip it. This is the pipeline-layer foundation for the new
  `solve --interactive` guided-fallback mode (Phase 6) — a simplified
  "re-run with the fact pre-seeded" resume, not true mid-pipeline
  resumption; documented as such in `run()`'s docstring.
  `handoff.BLOCKING_UNKNOWN_FACT_KEYS` maps each `blocking_unknowns`
  description to the matching `known_facts` key.
- `supwngo/exploit/verification.py`'s `ExploitVerifier.verify_payload()` only fell back to
  real interactive (pwntools-based) shell verification when the initial `subprocess.run()`
  raised `TimeoutExpired`. A shell spawned via `system()`/`execve()` given piped,
  non-interactive stdin (exactly what `subprocess.run(input=payload)` provides) reads EOF
  and exits immediately rather than hanging — it never times out, so the interactive
  verification path was dead for the single most common case (any technique that lands a
  shell via `system("/bin/sh")`, e.g. ret2win, ret2system). Found via a manual end-to-end
  smoke test against a trivial ret2win target: the exploit payload was independently
  confirmed correct (spawned a real shell when replayed by hand), but `autopwn` reported
  FAILED because `verify_output()`'s passive string-pattern check has nothing to match
  against a piped shell that only ever saw an immediately-closed stdin. Now retries via
  the interactive path whenever the fast passive check didn't already succeed, not only on
  timeout. This was blocking correct verification for what should be the benchmark corpus's
  easiest target and would have silently deflated every ret2win/ret2system-class success
  in Phase 1's benchmark numbers. Found and fixed during integration-branch smoke-testing,
  ahead of Phase 5/6/1-benchmark work.

### Added
- `supwngo/exploit/pipeline/handoff.py` — a structured, actionable
  hand-off report (`HandoffReport`) built when `CanonicalAutopwnEngine`
  does not reach verified SUCCESS: `attempts_detail` (technique, outcome,
  stage reached, failure reason — projected from the `AttemptRecord`s the
  engine already collected), `blocking_unknowns` (concrete facts like "PIE
  base not leaked"/"libc base not leaked"/"stack canary value unknown",
  derived from `ExploitContext` state that's still unset, gated on a
  technique that actually needed that fact having been attempted this run
  — never a guess independent of what the pipeline tried), `best_partial`
  (the furthest-along artifact: a technique's partial exploit script if
  one exists, else the pipeline's universal fallback template), and
  `suggested_next_steps` (the highest-confidence not-completed strategy's
  `requirements`/`notes`/`steps`, surfaced directly from
  `strategy.py`'s existing `StrategyReport` rather than new prose).
  `CanonicalAutopwnEngine.handoff_report` builds and caches one per run.
  JSON schema is frozen at `schema_version: 1` (additive-only from here);
  intended to double as the shape a future benchmark harness parses for
  PARTIAL/FAILED classification. Phase 4 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.
- `supwngo autopwn`'s non-JSON output now renders the hand-off report with
  `rich` (an attempts table, blocking unknowns, strategy warnings, the
  recommended next strategy, and the best partial artifact) instead of
  dumping the first 50 lines of the universal template — replacing the
  previous sparse fallback. `supwngo autopwn --json` (the flag already
  existed) now includes the same structured hand-off under a `"handoff"`
  key alongside the existing result fields.
- `tests/test_pipeline_handoff.py` — 18 tests covering `HandoffReport`'s
  frozen JSON schema, `derive_blocking_unknowns()`'s grounding in actual
  attempted techniques (not blanket guesses), and `build_handoff_report()`
  assembling `best_partial`/`suggested_next_steps` correctly for both
  successful and non-successful runs.

### Changed
- `supwngo autopwn` (the CLI command) is now driven by
  `CanonicalAutopwnEngine` instead of `EnhancedAutoExploiter`. Previously
  `cli.py` defined **two** `def autopwn` Click commands (one wired to
  `AutoExploiter`, one to `EnhancedAutoExploiter`); Click silently kept
  only the later one, making the first permanently unreachable. There is
  now exactly one `autopwn` command; it gained an `--offset` option
  (previously only on the unreachable command) to skip offset discovery
  when already known. Part of Phase 2 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Added
- `supwngo/exploit/pipeline/` — a new canonical auto-exploitation pipeline
  (`CanonicalAutopwnEngine`) that consolidates the two previously
  overlapping, never-reconciled auto-exploit engines (`AutoExploiter` and
  `EnhancedAutoExploiter`) behind a single, pluggable technique-executor
  architecture: typed `AttemptRecord`/`VerificationReceipt` contracts, an
  `ExecutorRegistry` of 11 technique executors (7 ported from
  `EnhancedAutoExploiter`, plus SROP/scanf-canary-bypass/UAF/double-free
  ported from `AutoExploiter`), and a `PipelineVerifier` that confirms
  success via a unique per-attempt verification-receipt token rather than
  shared-string stdout matching. See
  `docs/architecture/2026-09-23-autopwn-pipeline.md` for the full design,
  the engine-shape decision and justification, and a list of explicit
  follow-up items left for later phases. Phase 2 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Changed
- `supwngo/core/context.py`'s `ExploitContext` gained new fields
  (`gadgets`, `win_function`, `binsh_addr`, `offset`, `captured_flag`,
  `verification_level`, `attempts`, and several `profile_*` fields) to hold
  the state produced by the new canonical autopwn pipeline's static
  analysis and dynamic profiling stages. Pipeline-facing types are imported
  under `TYPE_CHECKING` only, preserving `core/context.py`'s existing
  import-layering rule (no real import of `supwngo.exploit.*` at module
  load time). Part of Phase 2 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`; see
  `docs/architecture/2026-09-23-autopwn-pipeline.md` for the full rationale.
- `supwngo/exploit/verification.py`'s `ExploitVerifier.__init__` now
  accepts optional `marker`/`marker_file` overrides (previously a fixed,
  shared `PWNED_MARKER`/`PWNED_FILE` constant for every caller), so callers
  needing a verification receipt tied to a specific attempt can pass a
  freshly generated unique token per attempt instead of a shared,
  guessable string. Existing callers are unaffected (defaults preserved).
  Part of Phase 2 of `docs/plans/2026-09-23-effectiveness-and-usability.md`.
- `supwngo/exploit/strategy.py`'s `StrategySuggester` gained two new
  `ExploitApproach` strategies — `VARIABLE_OVERWRITE` and
  `NEGATIVE_SIZE_BYPASS` — reconciled in from `EnhancedAutoExploiter`'s
  previously-private, unreconciled `_rank_strategies` inline strategy list.
  Part of Phase 2 of `docs/plans/2026-09-23-effectiveness-and-usability.md`
  (auto-exploit engine consolidation).
- Added `docs/roadmaps/PARKED.md`, listing speculative-breadth work explicitly out of scope for
  the current effectiveness/usability effort (CFI/CET/MTE/PAC/shadow-stack/COOP bypass, exotic
  heap techniques beyond common UAF/tcache, Windows/macOS/embedded/containers expansion,
  distributed/cloud fuzzing, the enterprise REST/GraphQL API, LLM/RL-based exploit generation),
  corrected per the module-triage audit: `kernel/` is called out as live and NOT parked (wired
  into the CLI via `supwngo kernel <module.ko>`), and `reporting/` is flagged as a future wire-in
  candidate rather than frozen indefinitely. Added a scope-note banner to the top of
  `docs/roadmaps/ROADMAP.md` pointing to it, since most of that document's phases are exactly the
  parked work.
- Added methodology caveats to `docs/roadmaps/ROADMAP.md` (the unsupported "~60%" auto-exploit
  success-rate KPI), `docs/reference/WRITEUP_CAPABILITY_ASSESSMENT.md` (the "45/46 (98%)"/"13/13
  (100%)" figures, which measure hand-fed technique execution, not autonomous exploitation), and
  `docs/reference/TEST_RESULTS.md` (precision/recall/accuracy figures, which measure detection on a
  small local corpus, not exploitation). None of the historical numbers were changed or removed;
  each caveat points to `docs/plans/2026-09-23-effectiveness-and-usability.md` Phase 1 as the
  process that will supersede them with honest, reproducible numbers.
- Flagged the three-way license conflict (`LICENSE`=CC BY-NC-SA 4.0, `README.md`=PolyForm
  Noncommercial 1.0.0, `pyproject.toml`/`setup.py`=MIT) with a prominent note in README.md's
  License section. This is a maintainer/legal decision and is intentionally **not** resolved
  here — see `docs/plans/2026-09-23-effectiveness-and-usability.md` Phase 7.

### Fixed
- README.md's Documentation section linked to `docs/DEVELOPMENT.md` and
  `docs/MANUAL_EXPLOITATION_GUIDE.md`, neither of which exists at those paths after a prior docs
  reorg moved both files to `docs/internal/`. Links now point to `docs/internal/DEVELOPMENT.md`
  and `docs/internal/MANUAL_EXPLOITATION_GUIDE.md`.
- Package failed to `import` at all on Python 3.11 (the advertised `>=3.8` range) due to
  syntax errors in four files. `supwngo/exploit/seccomp.py` and one code path in
  `supwngo/exploit/auto.py` used an f-string containing a backslash inside the expression
  part — legal only under Python 3.12's relaxed f-string grammar (PEP 701) — fixed by
  computing the value in a variable before interpolating. `supwngo/exploit/templates.py`
  and the same `auto.py` code path nested a triple-quoted string inside an f-string using
  the same quote character, which is invalid pre-3.12 — fixed by extracting the nested
  string to a variable defined before the f-string. `supwngo/distributed/coverage_merge.py`
  had a generator expression with two `if` clauses (`... if X if Y else Z`), which is not
  valid Python on any version — fixed by combining into a single boolean condition. All 158
  files under `supwngo/` now parse cleanly on Python 3.11, and `import supwngo.cli`
  succeeds. This was the first prerequisite (Phase 0) of the effectiveness/usability plan;
  see `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Changed
- Declared the previously-undeclared runtime dependencies used by lazily-imported,
  already-guarded optional modules: `anthropic`/`openai` (`supwngo/ai/*`) and `z3-solver`
  (`supwngo/exploit/rop/z3_solver.py`), as new `ai` and `z3` optional-dependency extras in
  `pyproject.toml`. Also added `r2pipe` as an `r2` extra (previously only in
  `requirements.txt`, uncommented as if required).
- Reconciled `pyproject.toml` and `requirements.txt`, which previously listed different,
  non-overlapping dependency sets (`claripy`/`unicorn`/`lief` were only in
  `requirements.txt`; `networkx`/`pyyaml` were only in `pyproject.toml`). `pyproject.toml`'s
  `[project.dependencies]` is now the canonical list; `requirements.txt` mirrors it.

### Fixed
- `supwngo/exploit/auto_leak.py`'s `AutoLeakFinder`'s puts/GOT leak path (the
  `PUTS_GOT` branch of `auto_leak_libc`) was a bare `pass` stub — it recognized the
  leak opportunity but never built or sent a chain. It now builds and sends a real
  `pop rdi; ret` -> `GOT[sym]` -> `puts@plt` chain (and a 3-register
  `write(1, GOT[sym], 8)` chain for the previously also-silently-ignored `WRITE_GOT`
  case), parses the leaked pointer with a zero-pad-not-truncate fix (`puts()` only
  NULs the trailing/high bytes of a little-endian-packed pointer, so the standard
  technique is to zero-pad up to pointer width rather than treat a short read as a
  parse failure), and resolves the exact libc base via the target's own libc ELF
  symbol table when `context.libc.path` is known (falling back to page-alignment
  otherwise). New helper methods: `_leak_via_got_rop`, `_find_gadget_addr`,
  `_resolve_libc_symbol_offset`, `_parse_leaked_pointer`. Verified end-to-end
  against a real compiled no-PIE/no-canary binary and the host's real libc — the
  resolved base matched `/proc/<pid>/maps` ground truth exactly across multiple
  ASLR-randomized runs. Part of Phase 3 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.
- `supwngo/exploit/rop/z3_solver.py`'s `SolvedChain.build()` appended every gadget
  address first and every popped stack value second as two separate flat blocks —
  wrong for any chain with more than one gadget, since a ROP chain needs each
  gadget's own popped values immediately following its address, not grouped at the
  end. `SolvedChain` gained a `pop_values: List[List[int]]` field (per-gadget
  grouping) that `build()` now interleaves correctly when populated, falling back
  to the old flat layout (only correct for single-gadget chains) for the general
  solver methods not yet repaired (see Changed, below).
- `AutoLeakFinder.identify_leaked_value`'s libc-address range check
  (`0x7f0000000000`-`0x7f7fffffffff`) assumed an older, narrower ASLR entropy
  layout. On modern kernels (observed directly during this repair's benchmark
  spot-check — Ubuntu 22.04's default `mmap_rnd_bits`) a genuine libc leak can
  legitimately come back with an address outside that narrow range, causing a
  correct leak to be silently rejected as "not libc". Widened to the whole
  high-mmap region below the already-checked stack range
  (`0x700000000000`-`0x7ffdffffffff`) — found and fixed as a direct blocker of the
  `_leak_via_got_rop` repair above, not a speculative change.

### Changed
- `supwngo/exploit/rop/z3_solver.py`'s `Z3ROPSolver.solve_call` never actually
  invoked `Solver.check()` against a meaningfully-constrained model — despite the
  name, it was a greedy first-match gadget picker. It is now a real (intentionally
  v1-scoped) constraint search: boolean `use`/integer `order` variables per
  candidate "clean pop-chain" gadget, an explicit "final setter per register"
  choice with ordering constraints so a chosen chain can't have an earlier
  gadget's pop clobber a register a later gadget already set for the same
  purpose, and a chain is only returned when `solver.check() == sat`. Scoped, per
  Phase 3 of the effectiveness/usability plan, to "solve a single function call
  with N register arguments via a real z3 constraint search over available
  gadgets" — the general write-what-where case (`solve_write`/`solve_syscall`/
  `solve_execve`/`solve_mprotect`) is unchanged, still uses the old greedy
  `_find_gadget_to_set_reg`, and remains documented future work. `z3` stays a
  lazy/optional import (`Z3_AVAILABLE` guard), so its absence never blocks import
  of the module or the common (non-solver) exploitation path.
- `supwngo/exploit/tester.py`'s `ExploitTester` accepted generic, easily-spoofed
  output-string matches (`TestConfig.success_indicators` — `"got shell"`,
  `"uid=0"`, etc.) as proof of exploitation success on their own. Tightened via a
  new `ExploitTester._evaluate_output` (shared by `test_local`/`test_docker`) to
  the same receipt-token verification pattern `PipelineVerifier`/
  `verification.ExploitVerifier` already use: `test_local`/`test_docker`/
  `test_remote` now accept an optional `token` parameter, and SUCCESS requires
  either a genuine `flag_pattern` match or that unique per-attempt token being
  echoed back in the output — a loose `success_indicators` match alone now only
  downgrades a FAILED result to PARTIAL, never SUCCESS by itself.
  `TestConfig.success_indicators`'s field/default list is unchanged for backward
  compatibility. `tests/test_new_features_integration.py::test_shell_detection`
  updated to demonstrate the tightened contract (a loose `"uid=0(root)"` match
  alone no longer yields SUCCESS; supplying and echoing back a receipt token
  does). Part of Phase 3 of `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Added
- `supwngo/exploit/pipeline/leak_stage.py`'s `acquire_leaks(context)` extension
  point — previously a documented no-op for `needs_leak` targets — now drives the
  repaired `AutoLeakFinder` (see above) as its real implementation: local-only,
  discovers the buffer offset via the same GDB cyclic-pattern probe every other
  native executor uses when `context.offset` isn't already known, and stores a
  recovered libc base on `context.leaks['libc']`/`context.libc.base`.
- `supwngo/exploit/rop/chain.py`'s `ROPChainBuilder.call_function` gained an
  optional fallback (`_call_function_via_z3`) to the repaired
  `Z3ROPSolver.solve_call` (see above) for when its own simple per-register
  gadget lookup is incomplete — a documented pre-existing bug where a missing
  `pop <reg>; ret` gadget was silently skipped rather than failing the chain,
  leaving that argument register unset. The fallback is lazy/optional (safe when
  `z3` isn't installed) and only engages when the primary lookup was actually
  incomplete; if it also can't find a chain, the original (still-documented-
  incomplete) chain is returned rather than raising, preserving the method's
  existing best-effort contract.
- `supwngo/exploit/pipeline/verifier.py`'s `PipelineVerifier` gained
  `verify_via_tester()`, wiring the now-tightened `ExploitTester` (see above) in
  as an available, **non-default** local/docker/remote verification backend
  alongside `verification.ExploitVerifier` — for callers that already have a full
  generated exploit script and want to test it end-to-end (optionally in Docker
  against a specific libc, or against a real remote target) rather than driving a
  raw payload/tube directly via `verify_payload`/`verify_shell`. No native
  pipeline executor calls it automatically; module docstring updated to reflect
  the new verifier composition. Part of Phase 3 of
  `docs/plans/2026-09-23-effectiveness-and-usability.md`.

### Fixed
- `supwngo/exploit/auto_leak.py`'s `AutoLeakFinder.identify_leaked_value` and
  `auto_leak_pie_base` referenced a nonexistent `self.binary.base` attribute
  (`core.binary.Binary`'s actual field is `base_address`) — an `AttributeError`
  that crashed `identify_leaked_value`'s final non-PIE fallback branch instead of
  returning `LeakType.UNKNOWN`. Found running the repaired `_leak_via_got_rop`
  path (which calls `identify_leaked_value`) repeatedly against a real compiled
  binary during this Phase 3 repair's benchmark spot-check; fixed both call sites
  to use `base_address`.
