<!-- Preserved verbatim from an ephemeral peer-review output file.
     Original path : /tmp/codex-out/wt-plan-review.md
     Written       : 2026-09-23 23:27:58 (file mtime)
     sha256[:16]   : 1524d1ecf736342f
     Bytes         : 15231
     Subject       : walkthrough engine plan
     Rescued       : 2026-09-24, because /tmp does not survive a reboot and
                     this review was not recorded on any branch. Body is unedited;
                     only this header was added. The reviewing model/effort is
                     whatever the body states -- not asserted here. -->

Verdict: I would not approve this plan as written. The model enforces structural completeness, not a usable walkthrough. It can certify polished-looking garbage, and its handling of unknown/runtime facts makes the most important validation target—ret2libc—fundamentally incompatible with the promised per-step execution model.

## High severity

1. **[High — a/e] The model does not prevent thin, generic, or placeholder output.**

The plan’s strongest claim—“the bad artifact cannot be produced”—is false. A known `Fact` only needs a non-`None` value; evidence and description are optional ([model.py:118](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:118)). A `Step` only needs five nonblank strings ([model.py:294](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:294)), and `final_exploit` merely has to be nonblank ([model.py:427](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:427)).

I directly instantiated the model with:

- `Fact(name="offset", value=0, confidence=MEASURED)` and no evidence
- a step whose code was `pass`, with `expect="works"` and `verify="works"`
- `final_exploit="pass"`

It was accepted and rendered `offset = 0  # measured`.

Generic filler can also bypass `Fact` entirely because `Step.code` and `final_exploit` are arbitrary source strings. `kind="raw"` permits arbitrary source as a fact value too ([model.py:166](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:166)). `manual`, `on_failure`, `routes`, `protections`, `success_criteria`, and evidence commands are all optional.

So the model prevents only one narrow representation: an `UNKNOWN` fact without three metadata strings. It does not prevent `offset=0`, TODOs inside code, fabricated “measured” facts, generic prose, or a nonfunctional final exploit.

2. **[High — d/e] `UNKNOWN` facts make the generated module impossible to run, including the step meant to resolve them.**

An unknown renders as a module-level `_unknown(...)` call ([model.py:191](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:191)). Under the plan’s module-level facts layout, `python3 wt.py offset` fails during import before argv dispatch reaches `step_offset`.

The validation is also logically backward:

- It only checks that `resolved_by` names some step ([model.py:447](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:447)).
- It treats every constant, including unknown constants, as “available” to consumers ([model.py:456](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:456)).
- Duplicate fact names are prohibited ([model.py:441](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:441)), so a resolver cannot naturally replace `UNKNOWN offset` with a produced known `offset`.

Worse, the plan turns handoff blocking unknowns into `UNKNOWN` facts ([plan:42](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/docs/plans/2026-09-23-walkthrough-engine.md:42)). Some of those are runtime/session values, not source-code holes. “libc base not leaked” is explicitly one such handoff fact ([handoff.py:200](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/pipeline/handoff.py:200)).

For target 07:

1. `python3 wt.py leak` starts process A and leaks A’s libc base.
2. `python3 wt.py shell` starts process B.
3. ASLR gives B a different libc base.
4. The carried value is invalid.

The leak and final chain must execute on the same tube in one session. The model needs separate static facts and runtime facts, with explicit scope such as `artifact`, `process`, or `connection`. Runtime producers must return values into the same execution context; they cannot be “edit this module constant.”

3. **[High — goal mismatch] The plan does not actually replace the useless fallback.**

The stated goal says replace the failed-autopwn stub ([plan:9](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/docs/plans/2026-09-23-walkthrough-engine.md:9)). But the integration makes walkthrough generation optional via `--walkthrough` ([plan:151](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/docs/plans/2026-09-23-walkthrough-engine.md:151)) and explicitly leaves `templates.py` alone because the walkthrough is “an additional artifact” ([plan:170](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/docs/plans/2026-09-23-walkthrough-engine.md:170)).

Therefore:

- Normal failed `autopwn` still saves `engine.exploit_script or engine.exploit_template` ([cli.py:2557](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/cli.py:2557)).
- Normal failed `solve` does the same ([cli.py:2810](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/cli.py:2810)).
- The template still contains `offset = ... or 0  # TODO` ([templates.py:80](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/pipeline/templates.py:80)).

That misses the user’s “instead” requirement. On failure, the walkthrough should become the default primary artifact, or the existing fallback should embed it. The plan also does not define where the second file goes when `-o` already names the exploit artifact.

4. **[High — b] Rejected routes are not a decision tree.**

`Route` contains a boolean, score, rationale, and free-form requirements ([model.py:313](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:313)). `fallback_routes` simply returns every non-primary route, including routes explicitly marked inapplicable ([model.py:407](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:407)).

That is a candidate inventory, not a decision tree.

A rejected route such as “ret2syscall: no pop rdi/rsi/rdx” is not useful fallback advice after SROP fails—the missing gadgets remain missing. Adding every future heap or format-string family to every stack walkthrough will mostly create irrelevant noise.

A real fallback edge needs:

- The observable trigger that activates it.
- Which facts changed or were disproven.
- Whether missing prerequisites can be established.
- The concrete next step.
- An entry point into that alternative route.

The current route table also omits essential applicability facts. SROP needs enough controllable bytes—the target deliberately documents why 400 bytes are necessary ([srop.c:17](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/benchmark/corpus/09_srop/srop.c:17)). Ret2libc needs a usable leak function, GOT target, re-entry point, exact libc, prompt parsing, and sufficient input capacity. Ret2plt needs stack alignment. Gadget-presence booleans are discriminating for these three curated binaries, but they are not sufficient route preconditions.

5. **[High — c/f] This is secretly a second exploitation engine, despite declaring exploitation mechanisms out of scope.**

The plan says it will not change exploitation mechanisms ([plan:20](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/docs/plans/2026-09-23-walkthrough-engine.md:20)), yet it promises working end-to-end exploits for targets 07 and 09 ([plan:193](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/docs/plans/2026-09-23-walkthrough-engine.md:193)).

Today, the ret2libc executor explicitly stops at a partial template because it does not drive the two-stage leak/call sequence ([stack_techniques.py:340](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/pipeline/executors/stack_techniques.py:340)). The SROP executor likewise produces an unverified partial artifact ([heap_and_bypass.py:69](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/pipeline/executors/heap_and_bypass.py:69)).

For the walkthrough generator to succeed, it must implement missing payload construction, tube synchronization, leak parsing, libc resolution, alignment, and shell verification. That is new exploitation logic, merely placed in a renderer-adjacent package. It will duplicate and eventually drift from the pipeline executors.

This is the biggest underestimated risk.

6. **[High — c] The family abstraction is not compositional and is already too small for target 07.**

`stack_bof`, `rop_chain`, and `syscall` mix different abstraction levels:

- Stack BOF is an input/control primitive.
- ROP is a payload-construction mechanism.
- Syscall/SROP is an execution technique.

All three current targets begin with the same stack-overflow primitive. Future families do not fit as mutually exclusive peers:

- A format string may provide a libc leak used by a later ROP route.
- An integer bug may unlock an OOB write used by a heap route.
- A heap exploit usually requires a stateful allocation/free/leak/poison sequence.
- A format-string offset is not a cyclic return-address offset.

A linear presentation is fine, but execution needs a graph or scoped phases with branches, loops, and shared live sessions. Otherwise future support will bypass the model by stuffing the real logic into `Step.code` and `final_exploit`, making the abstraction ceremonial.

## Medium severity

7. **[Medium — validation] The three targets do not test the claimed failure-mode guarantees.**

All three are local amd64 debug binaries with no PIE, no canary, deterministic input, deliberately inserted gadgets, and offset 72. They validate three payload recipes, but not:

- Core dumps disabled or inaccessible.
- `--no-probe`.
- An unresolved static fact.
- A runtime fact that must remain in one process.
- Wrong or missing libc.
- Remote/local binary or libc mismatch.
- Stripped binaries.
- Menus or multi-prompt synchronization.
- A primary route failing and an alternative actually being taken.

The most important E2E test should be: autopwn fails, cyclic probing also fails, and a fresh process follows the generated artifact without editing hidden assumptions. None of the proposed corpus runs exercises that.

8. **[Medium — d] Several concrete self-containment obligations are missing.**

For target 07, the script must consume the `Input: ` prompt, distinguish the banner from the raw `puts` leak, normalize a short NUL-terminated leak, verify plausible libc alignment, and send stage two on the same connection. The target’s prompt and two-stage behavior are explicit in [ret2libc_leak.c:9](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/benchmark/corpus/07_ret2libc_leak/ret2libc_leak.c:9) and [ret2libc_leak.c:22](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/benchmark/corpus/07_ret2libc_leak/ret2libc_leak.c:22). The model has no transcript, session, or leak-validator concept.

Remote mode only rewrites connection placeholders; the CLI itself warns that analysis and verification remain local ([cli.py:2620](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/cli.py:2620)). Unless the remote binary and libc are proven identical, local addresses and libc offsets are not evidence for the remote target.

The current binaries also advertise SHSTK and IBT in their ELF notes/checksec output, while `ProtectionAnalyzer` defines those fields but never populates them. A fresh operator will see protection output apparently contradicting a ROP walkthrough. The artifact needs to distinguish “advertised in ELF” from “actually enforced for this process.”

Finally, success cannot be `io.interactive()` or “did not crash.” The generated exploit should send a unique command, read the marker, and only then declare shell success.

9. **[Medium — e] There are concrete correctness bugs in `model.py`.**

- Hyphenated step IDs pass validation, but `function_name` leaves the hyphen intact, producing invalid Python such as `step_find-offset` ([model.py:294](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:294)).
- Fact names are regex-checked but not checked against Python keywords.
- `kind` and value type are not validated until rendering.
- No viable route is required, and `family` need not agree with `primary_route`.
- The final exploit has no declared dependencies and may depend on unresolved facts.
- `success_criteria` may be empty.
- `ProtectionVerdict` is arbitrary prose and has no link to the measured fact that supposedly generated it.
- The promised `to_dict()` “round-trip” is impossible: there is no `from_dict()`, values are converted to source-literal strings, and `final_exploit` is omitted entirely ([model.py:470](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:470)).

10. **[Medium — a/e] The handoff is flattened precisely where structure matters.**

`HandoffReport` already preserves technique, outcome, stage reached, failure reason, notes, blocking unknowns, partial artifact, and suggested steps ([handoff.py:113](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/pipeline/handoff.py:113)). `Walkthrough` reduces all of that to one optional `automation_failure: str` ([model.py:361](/srv/share/dev/supwngo/.claude/worktrees/agent-a94bf3ef2466a61db/supwngo/exploit/walkthrough/model.py:361)).

That permits generic “automation failed” filler and loses which payload reached which stage. The attempted routes and partial artifact should remain structured, especially because fallback advice should depend on whether failure occurred during applicability, payload construction, delivery, leak parsing, or shell verification.

## Low severity

- The model records a binary path but not a SHA-256/build ID. A rebuilt binary at the same path can invalidate every “measured” address while retaining apparently strong confidence.
- `Route.score` suggests precision that the design does not supply. Cross-family scores have no calibration or tie policy.
- `Evidence.command` and `ManualCommand.expect` are optional despite the plan advertising pasteable commands with expected observations.

## Minimum changes before approval

At minimum, I would require:

- Failed `solve`/`autopwn` to emit the walkthrough as the default primary artifact.
- Separate static, runtime, and session-scoped facts; no module-level exception that blocks resolver steps.
- A same-process execution context for leak-then-use workflows.
- Evidence required for known facts, final-exploit dependency validation, and a ban on unresolved dependencies in the default exploit path.
- “Ruled out routes” separated from genuine conditional fallback edges.
- E2E tests for the failed-probe/unknown path, wrong libc, remote mismatch, and a fallback transition—not just the three happy-path payload recipes.

The core risk is not prose quality. It is that the plan mistakes a documentation renderer for a reliable exploit synthesizer while quietly implementing a second, less-tested exploitation engine underneath it.