<!-- Preserved verbatim from an ephemeral peer-review output file.
     Original path : /tmp/codex-out/supwngo-plan-review.md
     Written       : 2026-09-23 18:51:43 (file mtime)
     sha256[:16]   : 89e9c8489132272b
     Bytes         : 7292
     Subject       : supwngo phased improvement plan
     Rescued       : 2026-09-24, because /tmp does not survive a reboot and
                     this review was not recorded on any branch. Body is unedited;
                     only this header was added. The reviewing model/effort is
                     whatever the body states -- not asserted here. -->

## (A) Fact-check table

| # | Verdict | Finding |
|---|---|---|
| 1 | **PARTIALLY CONFIRMED** | Two `autopwn` definitions exist at [cli.py:1005](/srv/share/dev/supwngo/supwngo/cli.py:1005) and [cli.py:2515](/srv/share/dev/supwngo/supwngo/cli.py:2515). Click’s second registration replaces the first; isolated registration resolves to the Enhanced command. However, it is not currently “live”: importing `supwngo.cli` on supported Python 3.11 fails on a syntax error in [seccomp.py:342](/srv/share/dev/supwngo/supwngo/exploit/seccomp.py:342). |
| 2 | **CONFIRMED** | [AutoExploiter](/srv/share/dev/supwngo/supwngo/exploit/auto.py:186) and [EnhancedAutoExploiter](/srv/share/dev/supwngo/supwngo/exploit/enhanced_auto.py:92) are independent classes, not an inheritance relationship, and overlap on ret2win, shellcode, format strings, ret2libc, offset discovery, verification, and script generation. Caveat: `auto.py` only parses on Python 3.12 because it uses PEP 701-era f-string syntax despite the project claiming Python ≥3.8. |
| 3 | **PARTIALLY CONFIRMED** | None of `AutoLeakFinder`, `Z3ROPSolver`, or `ExploitTester` is imported or called by either engine or `cli.py`; there are no production consumers. But “only referenced in definitions and two tests” is too strong: they are publicly re-exported by [exploit/__init__.py:112](/srv/share/dev/supwngo/supwngo/exploit/__init__.py:112) and [rop/__init__.py:28](/srv/share/dev/supwngo/supwngo/exploit/rop/__init__.py:28), and appear in roadmap documentation. They are operationally orphaned, not literally unreachable. |
| 4 | **CONFIRMED** | There are four distinct mechanisms: runtime execution verification in [verification.py](/srv/share/dev/supwngo/supwngo/exploit/verification.py:61), static payload sanity checking in [verify.py](/srv/share/dev/supwngo/supwngo/exploit/verify.py:98), script/environment testing in [tester.py](/srv/share/dev/supwngo/supwngo/exploit/tester.py:91), and inline shell verification in [auto.py:42](/srv/share/dev/supwngo/supwngo/exploit/auto.py:42)—including a second `verify_shell` definition at line 96. They overlap but do not all provide equivalent guarantees. |
| 5 | **CONFIRMED** | [strategy.py](/srv/share/dev/supwngo/supwngo/exploit/strategy.py:101) defines `StrategyReport`/`StrategySuggester`; Enhanced imports neither and defines its own `ExploitStrategy` plus `_rank_strategies()` at [enhanced_auto.py:82](/srv/share/dev/supwngo/supwngo/exploit/enhanced_auto.py:82) and [enhanced_auto.py:299](/srv/share/dev/supwngo/supwngo/exploit/enhanced_auto.py:299). |
| 6 | **CONFIRMED** | [test_all_binaries.py:14](/srv/share/dev/supwngo/test_all_binaries.py:14) references nine paths under `challenges/`; [.gitignore:10](/srv/share/dev/supwngo/.gitignore:10) ignores that directory, it is absent locally, and no files beneath it are tracked. The script also measures strategy matching, not end-to-end exploitation. |
| 7 | **CONFIRMED** | No root changelog exists or is tracked. [CLAUDE.md:281](/srv/share/dev/supwngo/CLAUDE.md:281) mandates `CHANGELOG.md` updates for user-visible changes. |

## (B) Blocking issues

- **Add a Phase −1: restore a green, importable baseline.** Under the advertised Python support, syntax errors exist in `auto.py`, `seccomp.py`, `templates.py`, and `distributed/coverage_merge.py`; the last fails even on Python 3.12. The CLI cannot currently import, so Phase 0 cannot benchmark “today’s live autopwn.”

- **Define the target population behind “75%.”** A hand-authored 15–25-binary synthetic corpus can measure regression progress, but cannot substantiate “75% of binaries” generally. Pre-register supported architectures, interaction styles, technique mix, environment, retry policy, and scoring denominator. The listed technique percentages overlap and cannot be treated as mutually exclusive sampling weights.

- **Make benchmark execution deterministic and isolated.** Pin an OCI image digest containing Python, compiler, binutils, GDB, libc/loader, pwntools and kernel/ASLR assumptions. Verify the emitted exploit script from a clean target instance, with a unique receipt token, rather than trusting the in-memory attempt or generic output strings.

- **A committed “held-out” subset is not genuinely held out.** Once developers can inspect its failures, it becomes another tuning set. Use committed sources as the development/regression corpus, plus a frozen blind evaluation corpus held by CI/reviewers or periodically generated parameterized variants. Report the two separately.

- **Define pipeline contracts before selecting an engine.** Phase 1 needs a target/session abstraction, persistent `ExploitContext`, executor registry, typed attempt/failure model, and verification-receipt schema. `StrategySuggester` is not a drop-in replacement: it returns enum approaches that do not map to Enhanced’s `_try_{name}` dispatch and omits Enhanced-only strategies such as variable overwrite and negative-size bypass.

- **Do not treat all three dormant modules as ready-made capabilities.**
  - `AutoLeakFinder` leaves the important puts/GOT ROP leak path as `pass` at [auto_leak.py:432](/srv/share/dev/supwngo/supwngo/exploit/auto_leak.py:432).
  - `Z3ROPSolver` imports Z3 but never invokes a solver; its algorithms are greedy, several constraints are ignored, and [SolvedChain.build()](/srv/share/dev/supwngo/supwngo/exploit/rop/z3_solver.py:94) incorrectly appends all gadget addresses before all popped values.
  - `ExploitTester` accepts generic output indicators as success and builds floating Ubuntu/pip environments. Phase 2 therefore requires qualification/repair, not merely adapters.

- **Resolve repository licensing before establishing corpus provenance.** The plan calls the license PolyForm, but `LICENSE` is CC BY-NC-SA, README says PolyForm, and package metadata says MIT.

## (C) Non-blocking suggestions

- Phase 0 before capability work, and consolidation before wiring and hand-off, are the correct major dependencies.
- Move the typed hand-off/attempt schema into Phase 1 so failure evidence is preserved during migration.
- Add a minimal `solve` command immediately after Phase 1/hand-off contracts and run all later benchmarks through it. Guided resume can remain later. Waiting until Phase 5 delays feedback on the second primary goal.
- Prefer a small canonical orchestrator with technique executors over growing `EnhancedAutoExploiter` into another monolith. Its selection as the base is not yet justified: format-string and ret2libc paths currently stop at partial templates.
- The parked list is broadly sensible. Reconsider only minimal seccomp/ORW support if the defined corpus includes sandboxed flag-reading challenges; that decision should follow corpus evidence.
- Start the changelog in Phase 0, not Phase 6. Phase 6’s remaining documentation work can run in parallel.
- Minor factual correction: `cli.py` contains **31** `@cli.command()` decorators and **30** registered command names after the duplicate replacement, not 32.

## (D) Overall verdict

**APPROVE WITH CHANGES**

The central diagnosis and high-level ordering are sound. Implementation should not begin as written until importability, measurement scope, reproducible execution, pipeline contracts, and the actual maturity of the “dormant” modules are addressed.