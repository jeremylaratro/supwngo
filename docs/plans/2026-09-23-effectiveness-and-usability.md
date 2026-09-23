# supwngo Effectiveness & Usability Improvement Plan

> Draft for peer review (Opus-authored per repo `CLAUDE.md` "right model for each phase"). Independently reviewed by codex (gpt-5.6-sol, xhigh reasoning) — verdict **APPROVE WITH CHANGES**; see "Peer review record" below for how each blocking issue was addressed. A broader, non-phase-scoped catalog of every issue found across the codebase (8 parallel subsystem audits) lives alongside this plan at `docs/plans/2026-09-23-fix-and-improvement-catalog.md` — read it for the full evidence base; this plan cites only what's load-bearing for the two stated goals.
> Reviewer note: this plan is deliberately explicit about **open questions / unknowns** per phase. Treat every "OPEN QUESTION" as a gate to resolve before that phase's implementation, not as an assumption to build on.

## Executive summary

**The two goals (verbatim from the user):**

1. **Effectiveness** — provide successful end-to-end exploitation strategies for **75% of binaries**, and give **structured guidance (not silence)** for binaries the tool cannot auto-solve.
2. **Usability** — a **single end-to-end command** that runs the whole pipeline, replacing today's need to manually chain ~6+ separate CLI commands and hand-copy values between them.

**Root cause.** supwngo has **several overlapping, partially-wired implementations of the same auto-exploit pipeline**, with **no single canonical path** — and, discovered during peer review, **currently fails to import at all** on its own advertised Python version:

- **The package does not import on Python 3.11** (within the `>=3.8` range `pyproject.toml`/`setup.py` both declare, and the interpreter actually installed in this environment). `supwngo/__init__.py` eagerly imports `exploit/seccomp.py`, which contains an f-string with a backslash in it — legal only under Python 3.12's relaxed f-string grammar (PEP 701). Confirmed directly: `python3 -c "import supwngo.cli"` raises `SyntaxError` immediately. A full-repo AST sweep found 4/158 files that fail to parse on 3.11 (`exploit/seccomp.py`, `exploit/auto.py`, `exploit/templates.py`, `distributed/coverage_merge.py` — the last two are genuine syntax bugs, not version issues, and fail on *any* Python version). **All 31 CLI commands are unreachable until this is fixed.** This supersedes every other finding in priority and is now **Phase 0**.
- Two distinct auto-exploit engines: `AutoExploiter` (`supwngo/exploit/auto.py`, 2,933 LOC) **and** an undocumented `EnhancedAutoExploiter` (`supwngo/exploit/enhanced_auto.py`, 1,432 LOC).
- **Two `@cli.command()` functions both named `autopwn`** in `cli.py` (line 1005 wiring `AutoExploiter`; line 2515 wiring `EnhancedAutoExploiter`). Because Click registers commands by function name and both use `def autopwn`, the **second definition shadows the first** — once Phase 0 makes the CLI importable at all, the `autopwn` a user runs will be the Enhanced variant; the `AutoExploiter` variant is reachable only via the Python API and a third call site (cli.py:~372, canary-bypass cases).
- **At least four overlapping verification implementations**: `supwngo/exploit/verification.py` (`ExploitVerifier`, runtime execution verification — the one wired into the Enhanced engine), `supwngo/exploit/verify.py` (static payload sanity checking — a materially different guarantee, not a duplicate), `supwngo/exploit/tester.py` (`ExploitTester` — script/environment testing, orphaned), and inline verification in `auto.py` (which itself has a duplicate `verify_shell` definition). Closed-loop verification is not absent — it is *present but fragmented and inconsistent in what it actually guarantees*.
- Strategy selection is **forked**: `supwngo/exploit/strategy.py` has a mature `StrategySuggester`/`StrategyReport` (prioritized strategies with confidence, warnings, notes), while `EnhancedAutoExploiter` re-implements its own `ExploitStrategy` dataclass and ranking inline. **Peer review caveat:** `StrategySuggester` is not a drop-in replacement — it returns enum-based approaches that don't map cleanly onto the Enhanced engine's `_try_{name}` dispatch, and it's missing some Enhanced-only strategies (variable overwrite, negative-size bypass). Unifying on it is still the right direction but requires a real mapping/reconciliation step, not a mechanical swap.
- Three capability modules (`AutoLeakFinder`, `Z3ROPSolver`, `ExploitTester`) are exported from `__init__.py` but never called by any engine or CLI command in production — confirmed via grep, their only references are their own definitions plus two isolated test files. **Peer review caveat (important — this changes Phase 3's scope):** these are not simply "orphaned but functional" — `Z3ROPSolver` imports Z3 but its `solve_call`/`solve_write_what_where` never actually invoke a solver (`Optimize()` is configured but `.check()` isn't meaningfully constrained; see catalog); `SolvedChain.build()` appends gadget addresses before popped values in the wrong order. `AutoLeakFinder` stubs out its most important path — the puts/GOT ROP leak — as a bare `pass` at `auto_leak.py:432`. **Wiring these in requires repairing them first, not just adapting their interfaces.**

So the real blocker under both goals is: **the package doesn't currently run at all, and once it does, there is no one pipeline to point the (partially-broken) orphaned capabilities at, to verify, to hand off from, or to expose as a single command.** Every phase below is ordered around fixing that, in dependency order.

**Supporting evidence (verified this session):**
- 173 Python files, ~87,000 LOC. `exploit/` alone is 35,398 LOC — larger than the next 4 modules combined. `core/` (the shared Binary/context/database substrate everything should build on) is only 1,485 LOC. Breadth was prioritized over integration depth — and, per Phase 0, over basic correctness (the package doesn't parse cleanly).
- `supwngo/cli.py` is 2,617 lines with 31 `@cli.command()` entries (30 distinct names after the `autopwn` duplicate is resolved) and no single "do everything" command.
- **Self-reported capability claims don't measure what goal 1 needs.** `docs/reference/WRITEUP_CAPABILITY_ASSESSMENT.md` claims "45/46 tests passed (98%)" / "13/13 (100%)" coverage of 16 CTF writeups, but its own code samples show tests calling technique classes directly with parameters **already known from the human writeup** — this tests "does the primitive execute when a human supplies the right numbers," not autonomous end-to-end exploitation. `docs/reference/TEST_RESULTS.md` is more honest: of 4 trivial single-vuln binaries tested via the real `autopwn`, only 2 reached SUCCESS; ret2libc and heap-UAF only reached PARTIAL. `test_all_binaries.py` (root-level, not even collected by pytest per `testpaths=["tests"]`) measures strategy-suggestion matching, not end-to-end exploitation either.
- **The test corpus doesn't exist in the repo.** `test_all_binaries.py` references a `challenges/` directory that is `.gitignore`d (line 10) and was never committed. No success-rate claim in any existing doc is reproducible from a fresh clone. `ROADMAP.md`'s "~60%" baseline KPI cites no methodology and is inconsistent with `TEST_RESULTS.md`'s own numbers.
- Governance gaps: no `CHANGELOG.md` exists despite the repo's own `CLAUDE.md` mandating one; README links to docs moved by a prior reorg (broken links); **a genuine three-way license conflict** — `LICENSE` is CC BY-NC-SA 4.0, `README.md` says PolyForm Noncommercial 1.0.0, `pyproject.toml`/`setup.py` package metadata say MIT. These are legally distinct terms; this must be resolved (Phase 7) before Phase 1's benchmark-corpus licensing assumptions are relied on.
- git history shows single commits with +15,025 / +20,892 / +7,316 / +6,731 / +5,459 line insertions — consistent with bulk feature dumps landing without an integration/wiring/regression pass per phase.

**Why the phase order serves the goals.** Nothing runs until the package imports — so **Phase 0 fixes that first**, in isolation, before any capability work. You cannot claim "75%" without a reproducible way to measure it — so **Phase 1 builds the benchmark** next. You cannot wire (partially-broken) orphaned modules, verify exploits, or emit a hand-off report into a fragmented multi-engine mess without multiplying the mess — so **Phase 2 consolidates to one canonical pipeline** before anything is wired into it. Phase 3 repairs and wires the dormant capabilities and closes the verification loop; Phase 4 adds structured hand-off; Phase 5 hardens the high-frequency techniques that actually move the success rate (using the fix-and-improvement catalog as its benchmark-failure hit list); Phase 6 adds the single `solve` command (goal 2) as a thin entry point over the now-consolidated pipeline; Phase 7 closes governance gaps (including the license conflict) and formally parks speculative scope so the sprawl pattern doesn't restart.

**Explicit non-goals of this plan.** No new exotic technique breadth (CFI/CET/MTE/PAC/kernel-COOP, BROP/JOP, more House-of-X, distributed cloud fuzzing, Windows/macOS/embedded expansion, enterprise API, LLM/RL exploit generation). No rewrite of the 31 existing CLI commands — the new unified command is **additive**. No repair of the fuzzing/symbolic-execution pipelines (catalog Section 5) — they're broken at the algorithm level, not just unwired, and neither stated goal depends on them; fixing them is out of scope here but should not be marketed as working until it happens. See "Deprioritized / Parked."

---

## Peer review record

Reviewed by codex (gpt-5.6-sol, `model_reasoning_effort=xhigh`, read-only sandbox) against the live repository, fact-checking every falsifiable claim in the original draft. **Verdict: APPROVE WITH CHANGES.** Disposition of each blocking issue it raised:

| Codex blocking issue | Disposition |
|---|---|
| Package doesn't import on the advertised Python range (syntax errors in 4 files) | **Adopted as new Phase 0**, the plan's top priority, ahead of everything else. |
| "75% of binaries" needs a pre-registered target population, not just a 15–25-binary corpus | Adopted into Phase 1 — corpus stratification criteria and scope must be written down and reviewed before targets are built, not implied by the technique-frequency table alone. |
| Benchmark execution should be deterministic/isolated (pinned container image) rather than trusting ambient host state | Adopted into Phase 1's approach. |
| A committed "held-out" set isn't truly held out once developers can see it | Adopted — Phase 1 now distinguishes a committed **development/regression corpus** from a separately-described **blind evaluation** approach (frozen/reviewer-held or parameterized-variant generation), reported separately. |
| `StrategySuggester` is not a drop-in replacement for the Enhanced engine's inline ranking | Adopted — Phase 2's description above now flags this as a reconciliation step, not a mechanical swap. |
| Define pipeline contracts (target/session abstraction, `ExploitContext`, executor registry, typed attempt/failure model, verification-receipt schema) before selecting an engine | Adopted as new Phase 2 step 0 — a blocking prerequisite ahead of the engine choice, not an implementation detail deferred to later. |
| Enhanced's selection as the canonical base isn't yet justified — its format-string/ret2libc paths stop at partial templates | Adopted — folded into Phase 2 step 2's OPEN QUESTION as concrete counter-evidence, alongside the preference for a small pluggable orchestrator over growing Enhanced into another monolith. |
| `AutoLeakFinder`/`Z3ROPSolver`/`ExploitTester` need repair, not just wiring (specific dead paths cited) | Adopted — Phase 3 (below) now explicitly includes repair work, sized accordingly, citing the exact broken paths. |
| Three-way license conflict (LICENSE=CC BY-NC-SA, README=PolyForm, packaging=MIT) undermines the plan's corpus-provenance reasoning, which had assumed PolyForm | Adopted — flagged above and added to Phase 7; Phase 1's corpus approach is now license-agnostic (committed original C sources either way) until this is resolved. |
| Minor: cli.py has 31 `@cli.command()` decorators / 30 distinct names, not 32 | Corrected throughout. |
| Non-blocking: land the unified `solve` command earlier than Phase 6 to get goal-2 feedback sooner | Considered; not adopted as a phase-order change — `solve` genuinely needs Phases 2–4's consolidated pipeline and hand-off contract underneath it to be a thin, correct layer rather than another fork. A minimal internal (non-public) smoke-test of the orchestration shape can happen earlier without shipping the command; left as an implementation-time judgment call rather than a plan restructure. |
| Non-blocking: start `CHANGELOG.md` in Phase 0/1, not Phase 6 | Adopted — Phase 0 starts it. |
| Non-blocking: move the typed hand-off/attempt schema into Phase 1 so failure evidence survives the Phase 2 migration, rather than defining it fresh in Phase 4 | Partially adopted — the verification-receipt/attempt-schema piece is now pulled into Phase 2 step 0 (see above), which covers the "don't lose failure evidence mid-migration" concern; Phase 4 still owns the human-facing hand-off *rendering* built on top of it. |

---

## Phase 0 — Restore an importable, installable baseline

**Goal.** Make `import supwngo` and every one of the 31 CLI commands work at all, on the Python versions the package claims to support. This is a hard prerequisite for every other phase, including Phase 1's benchmark (which needs a working `autopwn` to measure in the first place).

**Approach.**
- Fix the 4 files that fail to parse on Python 3.11 (verified directly via AST sweep of all 158 files under `supwngo/`):
  - `exploit/seccomp.py:342` — f-string containing a backslash (PEP 701, 3.12+ only; codex's independent read pinpointed line 342, correcting this plan's earlier 361). Fix by assigning the escaped string (or its `\x00`/`\n` components) to a variable before interpolating, which works on 3.8+.
  - `exploit/auto.py:2746` — unterminated triple-quoted string literal. Genuine bug; locate the mismatched quote and fix.
  - `exploit/templates.py:269` — f-string brace mismatch from nested quoting. Genuine bug; likely needs the inner conditional expression extracted to a variable rather than nested directly in the f-string.
  - `distributed/coverage_merge.py:718` — `sum(1 for edge in ... if X if Y else Z)`, two `if` clauses in a generator expression with no valid grammar; genuine bug, rewrite as a single boolean condition.
- After fixing, verify `python3 -c "import supwngo.cli"` succeeds on the lowest Python version the project claims to support (3.8) or formally lower the claimed floor to whatever's actually true (3.11, matching this environment) — don't leave the two silently mismatched again.
- Declare the currently-undeclared runtime dependencies discovered during the audit: `z3-solver` (used by the orphaned `Z3ROPSolver`, needed for Phase 3) and `anthropic`/`openai` (used by `ai/llm_analyzer.py`, imported eagerly by some paths) in both `pyproject.toml` and `requirements.txt`, and reconcile the two files' dependency lists (`setup.py` currently reads `requirements.txt`, which has `claripy`/`unicorn`/`lief`/`r2pipe` absent from `pyproject.toml`'s separate hardcoded list, which itself has `networkx`/`pyyaml` absent from `requirements.txt`) — pick one file as the source of truth per modern packaging convention (`pyproject.toml`) and have the other defer to it or be removed.
- Start `CHANGELOG.md` here (Keep a Changelog + SemVer), with this phase's fixes as the first entries, per the repo's own `CLAUDE.md` mandate.

**Files touched.** `supwngo/exploit/seccomp.py`, `supwngo/exploit/auto.py`, `supwngo/exploit/templates.py`, `supwngo/distributed/coverage_merge.py`, `pyproject.toml`, `requirements.txt`, new `CHANGELOG.md`.

**Test strategy.** A CI/pre-commit check that runs `python3 -m py_compile` (or an AST-parse sweep) across every file under `supwngo/` on the minimum supported Python version — this exact class of bug should never land again silently. Add a smoke test that does `pip install -e .` into a clean venv and runs `supwngo --help` plus one real command end-to-end.

**Risks.** Very low — these are mechanical, narrowly-scoped fixes with no behavioral ambiguity. The only judgment call is the Python-version floor (fix for 3.8 compatibility vs. formally raise the floor to 3.11+ and simplify) — recommend fixing for the broadest compatibility since it costs little here, and reserving a floor-raise for if a *future* phase needs a 3.12+-only feature.

**Effort.** Small (this is the highest-value, lowest-effort phase in the entire plan — do it first, unconditionally, before touching anything else).

---

## Phase 1 — Reproducible benchmark corpus + measurement harness

**Goal.** Establish a committed, fresh-clone-reproducible benchmark and a one-command harness that produces an honest baseline success rate. Without this, "75%" is unmeasurable and every current claim (98% "tests passed", 100% "coverage", ~60% "auto-exploit success rate") is unverifiable. Ships **before** any effectiveness change so later phases show honest deltas.

**Approach.**
- **Pre-register the target population before building anything**, per peer review: which architectures (x86-64 first; note whether/when 32-bit and ARM are in scope), interaction styles (stdin, argv, network socket), the technique mix (using the repo's own writeup-frequency data as a starting point, not a final weighting — stack BOF+ROP 94%, heap 35%, info leaks 26%, format string 16%, canary bypass 14%, noting these categories overlap and aren't mutually exclusive sampling buckets), retry policy, and the exact scoring denominator. Write this down and have it reviewed alongside the corpus itself, before the "75%" number is ever quoted.
- Create a versioned corpus of **vulnerable target binaries built from committed C source** (do not vendor third-party CTF binaries — reproducibility and, pending Phase 7's license reconciliation, licensing risk). A build script compiles each source at pinned protection combinations, so a fresh clone rebuilds targets on demand. Commit the **sources + build recipe**, not necessarily the binaries.
- **Run the harness inside a deterministic, pinned environment** (an OCI image digest, not ambient host state) containing a fixed Python, compiler, binutils, GDB, libc/loader, pwntools, and documented ASLR assumptions — per peer review, this is necessary for the numbers to be trustworthy and reproducible run-to-run, not just reproducible-in-principle from source.
- **Distinguish a committed development/regression corpus from a genuinely blind evaluation set**, per peer review's correction to the original "held-out" framing: a corpus committed to the repo is inspectable by anyone iterating against it and will get implicitly tuned to over time, however well-intentioned. Either hold a frozen evaluation corpus outside the repo (reviewer-held, or generated by parameterized variation at evaluation time rather than committed statically) or be explicit that the "held-out" number is a weaker regression signal than a true blind eval, and report both honestly rather than conflating them.
- Build a harness (`benchmark/run_bench.py`, or a `supwngo bench` subcommand — decide in review) that runs the **canonical pipeline** (once Phase 2 exists; until Phase 0/2 land, there is no working baseline to measure at all — this phase's harness can be built and validated against toy fixtures first) fully autonomously per target, captures SUCCESS/PARTIAL/FAILED, and asserts success **only** when a verifier confirms a shell or flag with **zero human input** — via a unique per-run receipt token rather than trusting generic stdout-matching (e.g. `"flag{"` in output, which `exploit/tester.py`'s existing success heuristic does today and which is too loose). Emit a machine-readable report (JSON + summary table) with per-technique breakdown.
- Record the **Phase-1 baseline** in the report and in `docs/` so later phases show honest deltas.

**Files touched.**
- New: `benchmark/` (source `.c` files, build script, `run_bench.py`, `corpus.yaml` manifest, a pinned Dockerfile/image reference, `README.md` including the pre-registered target-population definition).
- New: `docs/benchmark/2026-09-23-baseline.md`.
- Edit: `.gitignore` — ensure `benchmark/` is not caught by the existing `challenges/` ignore; do not un-ignore `challenges/`.

**Test strategy.** The harness is itself the test infrastructure. Smoke test that builds ≥2 corpus targets and runs the harness end-to-end inside the pinned container. Negative control: verify the harness reports FAILED honestly on a deliberately-unsolvable target.

**Risks.**
- Build reproducibility across glibc versions for leak-dependent targets — mitigated by the pinned container.
- Corpus difficulty could be tuned to flatter the tool, consciously or not — mitigated by the blind-eval distinction above and by having the corpus difficulty peer-reviewed.
- Effort risk: building good targets is real work; keep the initial corpus small but honest (15–25 dev-corpus targets) and growable.

**Effort.** Medium (corpus authoring and the pre-registration writeup dominate; the harness mechanics are straightforward).

---

## Phase 2 — Consolidate to one canonical auto-exploit pipeline

**Goal.** Collapse the overlapping engines/verifiers/strategy code into a single, documented, canonical pipeline that everything else builds on. Linchpin phase; skipping it makes every later phase pay the fragmentation tax.

**Approach.**
0. **Define the pipeline contracts before picking or touching an engine** — per peer review, this is a blocking prerequisite, not an implementation detail to backfill later: a target/session abstraction, a persistent `ExploitContext` shape, an executor registry (so techniques are pluggable stages rather than hardcoded `_try_{name}` methods on one class), a typed attempt/failure model, and the verification-receipt schema (pulled forward from Phase 1/3). Write these down first; steps 1-5 below implement against them instead of against whichever engine happens to be chosen.
1. **Resolve the duplicate `autopwn` command** (`cli.py:1005` vs `cli.py:2515`) — remove or repoint the shadowed definition so there is exactly one.
2. **Choose the canonical engine.** Evidence points to `EnhancedAutoExploiter` (already integrates verification, dynamic profiling, iterative offset finding, strategy ranking, template generation), porting in `AutoExploiter`'s unique techniques (SROP, scanf-canary-bypass, explicit UAF/double-free paths — note cli.py's third `AutoExploiter` call site at ~line 372 is specifically for canary-bypass, suggesting the Enhanced engine currently lacks that path). **OPEN QUESTION, not yet settled** — per peer review, Enhanced's selection as the base is not fully justified as-is: its format-string and ret2libc paths currently stop at partial templates rather than verified exploitation. Needs a side-by-side capability diff (including those two paths) before committing; strongly prefer implementing step 0's contracts as a small canonical orchestrator with pluggable technique executors over simply growing `EnhancedAutoExploiter` into the next monolith. Don't delete `auto.py` until its unique techniques are ported and covered by Phase-1 benchmark targets.
3. **Reconcile strategy selection onto `StrategySuggester`** — per the peer-review caveat above, this is a real mapping exercise (enum-based approaches vs. the Enhanced engine's `_try_{name}` dispatch; port over Enhanced-only strategies like variable overwrite and negative-size bypass that `StrategySuggester` currently lacks), not a mechanical import swap.
4. **Pick one verifier**, understanding what each actually guarantees rather than treating them as interchangeable: `verification.py`'s `ExploitVerifier` does runtime execution verification (already wired); `verify.py` does static payload sanity checking (a different, complementary guarantee — likely worth keeping as a pre-flight check rather than deleting); `tester.py`'s `ExploitTester` adds local/docker/remote modes but its current success heuristic (generic string-matching in output) is too loose and needs tightening, not just adoption, before Phase 3 relies on it for a verification receipt. Consolidate on a documented combination rather than assuming one file simply replaces the other three.
5. **Write down the canonical pipeline** as a short architecture note.

**Files touched.**
- `supwngo/cli.py` (remove/rename the shadowed `autopwn`; leave the other 29 commands untouched).
- `supwngo/exploit/enhanced_auto.py` (becomes canonical; reconcile strategy selection).
- `supwngo/exploit/auto.py` (port unique techniques out, then deprecate/remove — sequenced, not abrupt).
- `supwngo/exploit/strategy.py` (extend as needed for the reconciliation in step 3).
- `supwngo/exploit/verify.py`, `supwngo/exploit/tester.py` (clarify roles per step 4; tighten `tester.py`'s success heuristic).
- New: `docs/architecture/2026-09-23-autopwn-pipeline.md`.

**Test strategy.** Run the Phase-1 benchmark before and after consolidation, requiring no regression (this is a refactor, not a capability change). Unit tests pinning: exactly one `autopwn` command registered; the canonical engine calls the chosen verifier(s); ported techniques still fire on their benchmark targets.

**Risks.**
- Porting techniques between engines can silently drop edge cases — mitigate with a dedicated benchmark target per ported technique before `auto.py` is removed.
- Verifier consolidation changes what counts as "success" — lock the success definition in Phase 1 (via the receipt-token approach) and don't let it drift here.

**Effort.** Large (highest-uncertainty phase; engine-diff, strategy reconciliation, and technique porting are the bulk).

---

## Phase 3 — Repair and wire the dormant capabilities, close the verification loop

**Goal.** Turn the three capability modules into live, *working* pipeline stages (not just reachable ones), and make the pipeline verify every candidate exploit before reporting SUCCESS. Serves goal 1(b)/1(c). **This phase's scope grew during peer review** — these modules need repair, not just adapters.

**Approach.**
- **`AutoLeakFinder` (`auto_leak.py`, 587 LOC):** repair the stubbed puts/GOT ROP leak path (`auto_leak.py:432`, currently a bare `pass`) before or as part of wiring it in as the automatic leak-acquisition stage for `needs_leak` strategies. **OPEN QUESTION** — its full input/output contract needs to be read in full at implementation start.
- **`ExploitTester` (`tester.py`, 630 LOC):** tighten its success-detection heuristic (currently accepts generic output strings as proof of success — see Phase 2 step 4) before folding it into the canonical verifier's local/docker/remote modes.
- **`Z3ROPSolver` (`z3_solver.py`, 669 LOC):** currently imports Z3 but its solve methods don't meaningfully constrain/invoke the solver, and `SolvedChain.build()` orders gadget addresses and popped values incorrectly — this needs a real fix, not a wrapper, before it can serve as a ROP-chain-construction fallback. Given the size of this repair, consider scoping it down for v1 (e.g. a narrower, correctly-implemented "solve for a single function call with N register args" case) rather than the full write-what-where solver, and expanding later once the narrow case is proven on the benchmark. Keep it optional/lazily imported (z3 is a heavy dependency) so it never blocks the common path.
- Gate each repaired-and-wired module behind a benchmark delta: it only stays wired if it improves or holds the success rate.

**Files touched.**
- `supwngo/exploit/enhanced_auto.py` (add leak stage, verify stage, z3 fallback hook).
- `supwngo/exploit/auto_leak.py` (repair the stubbed leak path), `supwngo/exploit/tester.py` (tighten success detection), `supwngo/exploit/rop/z3_solver.py` (repair solver invocation and chain-ordering bug).
- `supwngo/exploit/rop/chain.py`/`gadgets.py` (integration point for z3 fallback — confirm the real entry point during implementation).
- `tests/test_new_features.py`, `tests/test_new_features_integration.py` (extend to assert the pipeline path, not just direct class calls with hand-fed parameters).

**Test strategy.** Per-module integration test proving the capability is reached **through** `autopwn`/`solve`, not called directly. Benchmark must show: leak-dependent targets now solve autonomously (expected biggest single win); no SUCCESS without a genuine verification receipt; z3 fallback never on the hot path for simple targets.

**Risks.**
- Repairing `Z3ROPSolver` properly could be a bigger lift than the "wire it up" framing in earlier drafts suggested — budget accordingly, and the scoped-down v1 above is the risk mitigation.
- Closed-loop, tightened verification will likely **lower** the reported success number versus any prior loose measurement. This is correct and honest, not a regression — the Phase-1 baseline should already use the tightened definition so the number is honest from the start.

**Effort.** Medium–Large (revised up from the original "code exists, just wire it up" estimate, per peer review's finding that the code needs real repair).

---

## Phase 4 — Structured hand-off on failure

**Goal.** When full auto fails, emit an **actionable, structured hand-off** instead of silence: what was tried, why each attempt failed, what's still needed, the best partial payload/template, and the suggested next manual step. Serves goal 1(d), and doubles as the fallback for goal 2's guided mode.

**Approach.**
- Extend the canonical report object with structured fields: `attempts_detail` (technique, failure reason, stage reached), `blocking_unknowns` (e.g. libc base, canary, PIE base), `best_partial`, `suggested_next_steps`.
- **Source the guidance from `StrategyReport`, not new prose** — `strategy.py` already produces prioritized strategies, `requirements`, and warnings with per-strategy `steps`. Phase 2 already reconciled the engine onto this, so Phase 4 mostly **surfaces** that existing structured content rather than inventing it.
- Render in the CLI (human-readable) and as JSON. Reuse the Enhanced engine's universal-template generator as the "best partial" artifact.

**Files touched.** `supwngo/exploit/enhanced_auto.py`, the canonical report dataclass, `supwngo/cli.py`, `supwngo/exploit/strategy.py` (read-only reuse).

**Test strategy.** Benchmark targets intentionally not auto-solvable must produce a hand-off report with correct `blocking_unknowns` and a plausible next step — assert on structure. Snapshot-test and version the JSON schema.

**Risks.** Guidance that's confidently wrong is worse than silence — derive `blocking_unknowns` from detected facts, not guesses. Schema churn — freeze early.

**Effort.** Small–Medium.

---

## Phase 5 — Reliability hardening on high-frequency techniques

**Goal.** Raise the *verified* end-to-end success rate toward 75% by hardening the techniques that appear most in real workloads — not by adding exotic breadth. **Use `docs/plans/2026-09-23-fix-and-improvement-catalog.md` as the starting hit list** rather than rediscovering issues from scratch; it already documents specific, file:line-grounded bugs in exactly this territory:

1. **Stack BOF + ROP (94%)** — the foundation is broken in two concrete ways found by audit: `utils/helpers.py`'s `cyclic()` is a non-unique de Bruijn generator (silently wrong offsets), while the *correct* implementation sits unused in `exploit/offset_finder.py`'s `PatternGenerator` (which properly delegates to pwntools). Point `analysis/dynamic.py` at the correct one. Also fix `core/binary.py`'s FORTIFY false-positive (substring match on `_chk`) and RELRO misdetection (Full-RELRO reported as Partial) — both feed wrong protection data into strategy selection for every binary.
2. **Info leaks / ret2libc (26% leaks; currently PARTIAL)** — with `AutoLeakFinder` repaired (Phase 3), fix the two concrete bugs blocking automated libc resolution today: `remote/leak.py`'s leak classifier misidentifies real libc addresses as "stack" (wrong threshold — `format_string.py` has the correct version of this same check elsewhere in the codebase), and `remote/libc_db.py`'s libc.rip query sends the wrong wire format (raw ints where the API expects hex strings — `exploit/libc_auto.py` does this correctly elsewhere). Both are one-line-class fixes with outsized impact. Also fix `offset_finder.py`'s binary-search, which currently reports the crash-length threshold as the RIP offset (not the same number when canaries/partial overwrites are involved) — a silent wrong-payload bug.
3. **Format string (16%)** — fix the non-convergent 64-bit `%n` offset computation in `format_string.py` (estimates slot count once, then grows the string past it without re-checking).
4. **Canary bypass (14%)** — port/keep the scanf-canary-bypass technique from `AutoExploiter` (Phase 2); ensure leak-then-replay works.
5. **Heap UAF (35%, currently PARTIAL)** — the static `UAFDetector` is entirely dead code (constructor `TypeError`s swallowed by a broad `except`, per the catalog) — fix it before expecting the dynamic/crash-driven path to be the only signal. Get the common menu-driven UAF-to-win case to verified SUCCESS.

Each item is still ultimately driven by benchmark failures, in frequency order, stopping when 75% verified is hit — the catalog just tells you where to look first instead of starting blind.

**Files touched.** `supwngo/utils/helpers.py` (retire the broken `cyclic()` in favor of `offset_finder.py`'s), `supwngo/core/binary.py` (FORTIFY/RELRO fixes), `supwngo/remote/leak.py`, `supwngo/remote/libc_db.py`, `supwngo/exploit/offset_finder.py`, `supwngo/exploit/format_string.py`, `supwngo/vulns/uaf.py`, `enhanced_auto.py`. Scope each edit surgically to a failing benchmark case.

**Test strategy.** Benchmark-driven: each hardening lands with the specific corpus target(s) it fixes moving FAILED/PARTIAL → verified SUCCESS, with a regression assertion that previously-passing targets stay green.

**Risks.** Diminishing returns/whack-a-mole — mitigate by fixing failure *classes* (as above) over one-off targets, and by stopping at 75% verified. Over-fitting to the corpus — mitigate with the blind-eval distinction from Phase 1.

**Effort.** Large (this is where the success-rate number is actually earned).

---

## Phase 6 — Unified end-to-end command (`supwngo solve`)

**Goal.** Deliver goal 2: one command running analyze → protection-detect → vuln-detect → strategy-select → leak (if needed) → exploit-attempt → verify → **on success emit a working, verified exploit script; on failure emit the Phase-4 structured hand-off** — with sane defaults, no manual value-copying. Additive; the existing commands stay for power users/scripting.

**Approach.**
- Add a single command (name TBD in review — `solve`; consider aliasing `autopwn` to it). A **thin orchestrator over the Phase-2 canonical pipeline** — must not re-implement pipeline logic.
- Sensible defaults: auto-detect arch/bits, try strategies in `StrategySuggester` priority order, auto-acquire leaks, verify locally, write the exploit script to a predictable path on success.
- Minimal flag surface: `--remote host:port`, `--libc`, `--timeout`, `--json`.
- **Guided fallback mode** (`--interactive` or auto-triggered on partial failure): present the Phase-4 hand-off, let the user supply the one missing fact, resume from that stage. Cap it at "supply one missing fact and resume" — not a new TUI framework.

**Files touched.** `supwngo/cli.py` (one new command + optional alias). Reuses everything from Phases 2–4.

**Test strategy.** Benchmark runs through `solve` (not the internal engine) to prove the single command reproduces the pipeline's success rate. CLI tests for defaults, `--remote`/`--libc` plumbing, guided-mode resume.

**Risks.** Command-name confusion with `autopwn`/`pwn`/`exploit` — resolve explicitly in review. Guided mode is a scope-creep magnet — cap it firmly.

**Effort.** Small–Medium (thin layer if Phases 2–4 did their job).

---

## Phase 7 — Governance & documentation hygiene

**Goal.** Close the evidenced governance gaps — including the license conflict surfaced by peer review — and formally **park** the speculative scope, corrected per the module-triage audit.

**Approach.**
- **Resolve the three-way license conflict** (`LICENSE`=CC BY-NC-SA 4.0, `README.md`=PolyForm Noncommercial 1.0.0, `pyproject.toml`/`setup.py`=MIT) — pick one and correct the other two. This is a maintainer/legal decision, not a technical one; flag it for the repo owner rather than picking on their behalf.
- `CHANGELOG.md` was started in Phase 0 — keep recording user-visible changes in the same commit going forward.
- Fix the broken README links to `docs/DEVELOPMENT.md`/`docs/MANUAL_EXPLOITATION_GUIDE.md` (moved to `docs/internal/` by a prior reorg).
- Once Phase 1's real measurement exists, reconcile or retire the unsupported "~60%" KPI in `ROADMAP.md` and the "98%/100%" claims in `WRITEUP_CAPABILITY_ASSESSMENT.md` — replace with the honest, reproducible baseline.
- Add a **"Parked/Deferred"** section to the roadmap docs listing the speculative items below, **corrected per the module-triage audit**: `kernel/` is removed from the parked list (it's the one module in that set that's genuinely live and wired into the CLI today); `reporting/` is flagged as a good future wire-in candidate (solid, low-maintenance code, currently just as disconnected as the rest, worth surfacing through `solve`'s output once the core loop is proven) rather than a flat exclusion.

**Files touched.** `CHANGELOG.md` (ongoing); `LICENSE`/`README.md`/`pyproject.toml`/`setup.py` (license reconciliation — maintainer decision); `docs/roadmaps/ROADMAP.md`; `docs/reference/WRITEUP_CAPABILITY_ASSESSMENT.md`, `docs/reference/TEST_RESULTS.md`; roadmap "Parked" section.

**Test strategy.** Doc/link check. Verify README links resolve locally. No code tests.

**Risks.** Low, except the license question, which has real legal weight and should not be resolved unilaterally by an implementer — surface it and get an explicit answer.

**Effort.** Small (excluding the license decision, which is a judgment call for the maintainer, not effort).

---

## Deprioritized / Parked (do NOT work on these under this plan)

Corrected per the module-triage audit (`docs/plans/2026-09-23-fix-and-improvement-catalog.md` Section 6) — `kernel/` removed, `reporting/` flagged as an exception:

| Parked item | Where it lives today | Why parked |
|---|---|---|
| CFI / CET / shadow-stack / MTE / PAC bypass, COOP gadgets | `ROADMAP.md` Phase 4, `CUTTING_EDGE_ROADMAP.md` | Sketched interfaces, not working code; irrelevant to the high-frequency CTF techniques that move the 75% metric. |
| More House-of-X heap, BROP, JOP, seccomp enhancements | `IMPLEMENTATION_PLAN_V2.md` Phase 4 | Exotic breadth; common heap-UAF (Phase 5 of this plan) is the only heap work justified now. |
| Windows / macOS / embedded expansion, containers | `windows/`, `macos/`, `embedded/`, `containers/` | Framework is Linux-ELF-focused per its own CLAUDE.md; not wired into the live pipeline; expansion multiplies untested surface. |
| Distributed / cloud fuzzing, Kubernetes deployment | `distributed/` | Infrastructure sprawl unrelated to single-binary success or the unified command; also currently contains one of the Phase-0 syntax errors. |
| Enterprise REST/GraphQL API | `api/` | Not wired in; unauthenticated by default if ever launched (see catalog Section 6) — a real hardening gap if revived, moot while parked. |
| LLM / RL-based exploit generation | `ai/` | Speculative, unproven; also contains two `pickle.load()` sinks worth fixing independently of whether this is ever revived (see catalog Section 8). |
| ~~`kernel/`~~ | — | **Removed from this list.** Confirmed live and wired into the CLI (`supwngo kernel <module.ko>`), ~1% stub density — this is functional, maintained-looking code, not scope creep. Not part of this plan's two goals (which are Linux-ELF-userspace-focused) but should not be treated as dead weight. |
| `reporting/` — noted, not fully parked | `reporting/` | Solid CVSS/SARIF/multi-format reporting code, currently unwired like the rest, but flagged as a **strong candidate to surface through `solve`'s success/hand-off output** once the core loop (Phases 0–4) is proven — revisit after Phase 4, not frozen indefinitely like the rest of this table. |

**Rule for reviewers/implementers:** nothing else in this table is deleted — it is frozen and labeled. Reopen only after the Success Metrics below are met on the held-out/blind evaluation set.

---

## Success metrics (how "75%" is measured, once Phase 1 exists)

1. **Denominator.** The Phase-1 pre-registered, committed development corpus (≥15–25 targets), stratified by technique frequency and difficulty tier, run inside the pinned deterministic environment — **plus** a separately-reported blind evaluation set per the peer-review correction (not simply "the same corpus, unlooked-at").
2. **What counts as SUCCESS.** The single command (`solve`, Phase 6) — run **fully autonomously, zero human input** — produces an exploit script that the canonical, tightened verifier (Phase 2/3) confirms via a **unique per-run receipt token**, not generic output-string matching. Unverified "technique matched" or "template generated" is **PARTIAL**, never SUCCESS.
3. **The 75% target.** `verified_SUCCESS_count / total_corpus ≥ 0.75`, reported overall, per-technique, and **separately for the blind evaluation set** (the blind number is the honest one).
4. **Hand-off quality (goal 1b).** 100% of non-SUCCESS runs produce a structured hand-off with correctly-derived `blocking_unknowns` (never silence).
5. **Usability (goal 2).** A binary previously requiring ≥6 manual commands is solved via **one** `solve` invocation with no hand-copying, verified by running the benchmark exclusively through `solve`.
6. **Honesty gate.** The Phase-1 baseline and every subsequent phase's number come from the same reproducible, pinned harness; `ROADMAP.md`/`WRITEUP_CAPABILITY_ASSESSMENT.md` claims are reconciled to it (Phase 7). No success number is cited anywhere the harness can't reproduce from a fresh clone inside the pinned environment.

---

## Cross-cutting open questions for the reviewer to weigh in on

1. **Canonical engine choice** — adopt `EnhancedAutoExploiter` and port `AutoExploiter`'s unique techniques, or the reverse? Needs the side-by-side technique diff (Phase 2 step 2).
2. **Verifier composition** — Phase 2 step 4's proposed combination (`ExploitVerifier` for runtime confirmation, `verify.py` as a pre-flight static check, `tester.py` for local/docker/remote modes after its success heuristic is tightened) vs. a simpler single-module consolidation. Needs review before implementation.
3. **`AutoLeakFinder`'s real input/output contract** and **`Z3ROPSolver`'s actual repair scope** — both need a full read at Phase 3 start; the latter's scoped-down-v1 proposal needs sign-off.
4. **Command naming** — `solve` vs. reusing/aliasing `autopwn`/`pwn`.
5. **License resolution** (Phase 7) — a maintainer decision, not something this plan should resolve unilaterally.
6. **Python version floor** (Phase 0) — fix for full 3.8+ compatibility (matches current claims) vs. formally raise the floor. Low-stakes either way; flagged so it's a conscious choice, not a default.
