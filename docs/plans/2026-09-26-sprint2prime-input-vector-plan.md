# Sprint 2′ — Input-Vector Abstraction (argv / file channel)

Phase 5 artifact. Closes **G-2a** (argv/file targets structurally unreachable) and
**B-2** (vector classifier inverted). Gap analysis:
`docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md`.

**Provenance labels**: `measured` (I ran it this session), `recorded` (prior
artifact, cited), `inferred` (reasoned, not observed).

**Status: REVISION 2 — round-2 peer review returned NOT-APPROVED with 3 Critical
findings. I independently verified all three against the source and they are
correct; finding 4 is correct and *understated*. No code has been written.
Revision 2 narrows the scope and is re-submitted for round 3 (last of 3).**

> ## Round-2 review disposition (Daybreak Blue, `xhigh`, NOT-APPROVED)
>
> Every finding verified by me directly rather than accepted on report:
>
> | # | Finding | My verification | Disposition |
> |---|---|---|---|
> | 1 (Crit) | Probe proves argc-sensitivity, not a payload sink; false positives do **not** degrade safely | Correct. My "degrades safely" claim was wrong: a false positive *removes* working stdin delivery. My sweep also used a bundled-loader invocation while production launches directly — a real match-identity defect | **ACCEPTED**, probe redesigned (§4) |
> | 2 (Crit) | Spec will be stale: `PipelineVerifier` is built in `__init__` before the prologue | Confirmed: constructed `orchestrator.py:152`, prologue runs `orchestrator.py:237` | **ACCEPTED**, §5 S5 rewritten |
> | 3 (Crit) | S6 impossible: the generated script spawns *before* the body computes the payload | Confirmed: `exploit()` does `io = open_target()` then the body; `open_target()` (`script_builder.py:88-98`) receives no payload. **13** `build_script()` consumers | **ACCEPTED**, §5 S6 rewritten to the reviewer's option 2 |
> | 4 (High) | The "five spawn sites" inventory is materially incomplete | Confirmed and **worse**: enumerating target/artifact launches in `pipeline/` and excluding static tools (`objdump`/`ldd`/`readelf`) gives **~15**, not 5 | **ACCEPTED**, §5.1 per-site disposition table added |
> | 5 (High) | "Unchanged by construction" is asserted, not proven per site; file materialization undefined for multi-part | Correct; `deliver_parts` takes a *sequence* while S3 said "write payload" singular, and `subprocess.run(input=…)` vs `sendline()` differ by a newline | **ACCEPTED**, §6 per-site seam tests |
> | 6 (High) | T3/M-4 can pass while S8 is broken — proves injected plumbing, not canonical integration. M-4 baseline labeled `measured` though the fixture does not exist | Correct, and it is my own provenance rule violated: an unbuilt fixture's result is `inferred` | **ACCEPTED**, M-4 relabeled, T3 rewritten end-to-end |
> | 7 (Med) | Red-proofs weak; a tri-state gate reported inconclusive leaves pytest **green**; regression command does not actually exclude the known failures | Correct on all three | **ACCEPTED** |
> | 8 (Med) | Metric units | Correct. §7's "4/6 probe-negative" was wrong — 4/6 is the *conclusive-row* count; it is 3 negative / 1 positive / 2 inconclusive | **ACCEPTED** |
> | 9 (Med) | Receipt-provenance claim has no implementing sub-component | Correct — `VerificationReceipt` has no delivery field and no sub-component adds one | **ACCEPTED**, claim **withdrawn** rather than grown into scope |
>
> **Nothing rejected.** The review found a second premise-driven failure in the
> making and caught it before code, which is what the gate is for.
>
> **Re-triage forced by finding 4.** G-2a was triaged complexity **3**
> ("additive and testable in isolation"). With ~15 launch sites, a broken feeder,
> and a generated-artifact contract that cannot express pre-spawn payloads, the
> honest complexity is **5**. Since B-3 also means `snowscan` still will not
> solve, full G-2a is a poor P0. **Revision 2 therefore narrows the sprint** to a
> single-shot file-delivery path (§2), leaving the other launch sites explicitly
> and documentedly stdin-only.

---

## 1. Problem restated

The canonical pipeline can only ever write bytes to a target's **stdin**. Five
spawn sites hardcode an empty argv, `measured` by reading each line:

| site | code |
|---|---|
| `pipeline/delivery.py:153` | `io = process([binary_path], cwd=cwd)` |
| `exploit/verification.py:241` | `subprocess.run([self.binary_path], **run_kwargs)` |
| `exploit/verification.py:281` | `p = process([self.binary_path], **proc_kwargs)` |
| `pipeline/script_builder.py:98` | `return process(BINARY, cwd=...)` |
| `pipeline/templates.py:74`, `:176` | `io = process(BINARY)` |

Consequence (`measured`): `snowscan` prints
`ERROR: No file provided as an argument.` and exits, for every payload the
pipeline can construct. No technique can ever win it. 1/6 of the target set is
excluded by plumbing, not by difficulty.

The last two sites matter as much as the first three: `verify_script()` is the
pipeline's primary success oracle, and it runs the **generated artifact**. If the
artifact spawns the target without argv, then fixing delivery alone produces a
pipeline that cannot confirm its own success — and, worse, could report a SUCCESS
the user's script does not reproduce.

**B-2 blocks the obvious feeder.** `detect_input_sources()` reports `[]` for
`snowscan` (statically linked, `len(binary.plt) == 0`) and `file input` for all 5
stdin targets (its `has_file_io` check includes `read`). Using it would turn the
file channel **off** exactly where it is needed and **on** for 5 working targets.

## 2. Narrowed scope (Revision 2)

**In scope — the single-shot file-delivery path only.** A file-vector target is
supported for techniques that have their **whole payload before the target is
spawned**. Concretely three consumers: `deliver_parts()`,
`PipelineVerifier.verify_payload()` (both `verification.py` spawn paths), and the
**raw-payload** success template — the one place the reviewer correctly notes is
tractable, because `PAYLOAD` is a module constant that exists before
`open_target()` is called.

**Explicitly out of scope, and *documented in code* rather than left silent:** the
remaining ~12 launch sites (multi-stage leak acquisition, GDB-driven offset
discovery, heap sequencing, canary leaking). In file mode these techniques must
**refuse with a stated reason**, not attempt a stdin delivery that cannot work.
"Refuse loudly" is the deliverable for those sites; converting them is a later
sprint.

Rationale for the narrowing: finding 4 showed the site count is ~15, and finding 3
showed the generic builder cannot express a pre-spawn payload at all. A sprint
that tried to convert every site would be neither reviewable in one pass nor
revertable in pieces, which violates the Phase-3 rule the earlier Sprint 2 already
broke once.

## 2.1 What this sprint deliberately does NOT do

- **It does not solve `snowscan`, and does not advance T-1.** B-3 (`measured`):
  four stacked gates — `.bmp` extension, open, file signature, square 20x20–30x30
  bitmap — all returning `rc=0`. Satisfying them is a structured-format payload
  synthesizer, which is a separate capability (B-3, triaged P2). Claiming a target
  count here would be an overclaim; the Phase-8 metric is about the channel.
- **No socket/network channel** (G-2d, P3, `inferred` only — no target exercises it).
- **No repair of `detect_input_sources()`'s classification semantics** beyond
  deleting provably-dead code. Rewriting it is its own item; this sprint stops
  using it as a vector oracle and says so in the code.
- **Tool hardening / trustworthiness is out of scope.** Deliberate constants are
  features. This clause is repeated verbatim in every delegated prompt.

## 3. Candidate methods

### Method A — `DeliverySpec` value object threaded through the spawn contracts *(CHOSEN)*

One frozen dataclass describes how to launch a target and where the payload goes:

```python
@dataclass(frozen=True)
class DeliverySpec:
    sink: str = SINK_STDIN          # SINK_STDIN | SINK_FILE
    argv_template: tuple[str, ...] = ()   # "{payload_file}" placeholder
    payload_filename: str = ""      # basename; extension is load-bearing
```

Computed **once** in the prologue, stored on `ExploitContext`, consumed by the
five spawn sites. `SINK_STDIN` with an empty template reproduces today's
behavior byte-for-byte, so every existing path is unchanged by construction.

- **+** The channel is explicit, inspectable and loggable.
  *(Revision 2: the further claim that it is "serializable into the receipt so the
  harness can audit delivery" is **withdrawn** — round-2 finding 9 correctly noted
  that `VerificationReceipt` has no delivery field and no sub-component adds one.
  Growing the sprint to add one would be scope creep, so the advantage is dropped
  instead of implemented.)*
- **+** Testable with no target at all: spec → argv list is a pure function.
- **+** Default-stdin means the regression surface is "did the default change?",
  a single assertion, rather than "did 5 targets still work?".
- **−** Touches five call sites and one context field.

### Method B — polymorphic payload type (`FilePayload(bytes)` vs raw `bytes`)

Keep every signature as `payload: bytes`; dispatch on an `isinstance` check.

- **+** No new parameter anywhere.
- **−** Smuggles the transport into the data. Every one of the five sites needs an
  `isinstance` branch, and any site that forgets one silently falls back to stdin
  — a wrong-but-plausible failure, the hardest kind to notice.
- **−** The filename (extension load-bearing for `snowscan`) has no natural home.
- **−** Cannot express "argv matters but payload still goes to stdin".

### Method C — FIFO / `/dev/stdin` shim, no argv plumbing at all

Pass a named pipe or `/dev/stdin` as the filename so existing stdin machinery is reused.

- **+** Smallest diff by far.
- **−** **Ruled out by measurement.** `snowscan` requires a `.bmp` *extension*, and
  a BMP parser seeks/stats the file; a FIFO is not seekable, so stage 3 (signature)
  and stage 4 (dimensions) cannot be satisfied through a pipe. A real on-disk file
  is required. This is a measured exclusion, not a preference.

**Chosen: A.** **Option not taken: B.** **What would flip it:** a technique that
needs a *different* sink per payload within one attempt (write a file, then also
drive stdin). If that appears, the fix is to give `DeliverySpec` a per-part sink
list — still A, not B; B's `isinstance` dispatch is the part with the silent
failure mode, and that is what disqualifies it regardless of scale.

## 4. Vector detection — the feeder

Because of B-2, the signal is **behavioral**, not import-based. **Revision 2
replaces the single argv-differential test**, which round-2 finding 1 correctly
showed proves only argc-sensitivity — not that the payload belongs in a file.

### `classify_input_vector()` — three stages, each a separate claim

Run the target **directly** (no bundled loader — same construction production
uses; this closes the match-identity defect finding 1 identified) with stdin at
`/dev/null`:

| stage | test | establishes | on failure |
|---|---|---|---|
| **0. determinism** | same condition run twice, outputs compared | output is a function of input, so a later difference is attributable | `INCONCLUSIVE` → stdin |
| **1. argv sensitivity** | no-argv vs a *missing* path | the target reads `argv` | `stdin` |
| **2. causal file open** | a **missing** path vs an **existing, readable** path, *same extension* | the target **opened and read the path** — not merely counted argc | `argv-only` |

Only `determinism ∧ stage1 ∧ stage2` yields `SINK_FILE`. `argv-only`
(stage 1 without stage 2) sets a non-empty `argv_template` while **leaving
`sink=SINK_STDIN`** — which is exactly the "config filename in argv, vulnerable
input on stdin" case finding 1 named, now representable rather than misclassified.

**Measured** (match identity: direct launch, stdin `/dev/null`, first 300 bytes of
`stdout+stderr`, extension auto-discovered from the target's own refusal text):

| target | determ | ext | stage 1 | stage 2 | verdict |
|---|---|---|---|---|---|
| ancient_interface | True | — | False | False | `stdin` ✔ |
| auth-or-out | True | — | False | False | `stdin` ✔ |
| **snowscan** | True | **`.bmp`** | **True** | **True** | **`SINK_FILE`** ✔ |
| bon-nie-appetit | — | — | — | — | `INCONCLUSIVE(launch)` → stdin |
| rocket_blaster_xxx | — | — | — | — | `INCONCLUSIVE(launch)` → stdin |
| sabotage | — | — | — | — | `INCONCLUSIVE(launch)` → stdin |

**3 conclusive negatives / 1 conclusive positive / 3 inconclusive-safe on 6.**
Stated in those units deliberately, per finding 8 — "4/6" previously conflated
*conclusive rows* with *negatives*. The 3 inconclusive rows need a bundled loader
to launch at all; they route to stdin, which is their correct present behavior.

**Extension discovery** is from the target's own refusal text (`.bmp` above was
extracted, not supplied), falling back to `.bin`. The filename is load-bearing —
`snowscan` rejects on extension before opening anything.

### Safety rule, restated correctly

Finding 1 is right that my earlier claim was wrong. The accurate statement:

- **Errors, timeouts, inconclusive results, and false negatives degrade safely** —
  they route to `SINK_STDIN`, i.e. today's behavior.
- **A false positive does NOT degrade safely** — it would remove working stdin
  delivery and could regress a solvable target. This is the one failure mode that
  matters, so it is defended by *three* independent conditions rather than trusted:
  determinism rejects PID/ASLR/timestamp/nonce nondeterminism; stage 2 rejects
  argc-only banner differences; and `argv-only` catches argv-file-plus-stdin
  targets without touching their sink.

**Residual false-positive class, stated not hidden:** a deterministic target whose
output changes when a supplied path becomes readable *but* which still reads the
exploit input from stdin. No such target exists in this corpus (`measured`, 0/6).
Sprint gate T5 carries a purpose-built fixture of exactly this shape to prove the
probe is *not* fooled by it; if it is, the sprint stops.

## 5. Sub-components

| # | Files | Change | Contract affected | Failure mode introduced |
|---|---|---|---|---|
| S1 | `pipeline/contracts.py` | `DeliverySpec` + `SINK_STDIN`/`SINK_FILE`; `build_argv(payload_path)`; `materialize(parts) -> bytes` | new type, additive | a wrong default silently changes every spawn → pinned by per-site seam tests, not by S1 alone |
| S2 | `analysis/vector_probe.py` *(new)* | `classify_input_vector()` — the 3-stage probe of §4, extension discovery | new module | false positive → 3 independent conditions + T5 adversarial fixture |
| S3 | `pipeline/delivery.py:153` | `deliver_parts(..., spec=None)`. In `SINK_FILE`: materialize `b"".join(parts)` to a unique file in `cwd`, pass via argv, and **suppress stdin writes entirely** | `deliver_parts` gains a kwarg | temp file leaks → unique name, `finally` cleanup (T8) |
| S4 | `exploit/verification.py:241`, `:281` | thread spec through **both** paths | `ExploitVerifier.__init__` gains optional `spec` | the two paths differ today (`input=payload` vs `sendline(payload)`, which appends `\n`) → S4 test asserts identical **file bytes** from both |
| S5 | `pipeline/verifier.py` + `core/context.py` + `orchestrator.py` | **Resolve the spec at call time** from `context.delivery_spec`, *not* via the constructor | `PipelineVerifier` reads the context it already holds | **this is finding 2**: a constructor-carried spec is built at `orchestrator.py:152`, before the prologue at `:237`, so it would be permanently stdin. Call-time resolution removes the ordering hazard by construction; T9 asserts the verifier observes the same value stored on the context |
| S6 | `templates.py` raw-payload template only | File mode is supported **only** where the payload is a pre-spawn constant. The generic `build_script()` path and the multi-part template **raise a documented "file delivery unsupported for this technique" error** rather than emitting an artifact that silently sends to stdin | **generated artifact shape**, narrowly | **this is finding 3**: `open_target()` (`script_builder.py:88-98`) is called before the body computes the payload, so it cannot write a payload file. 13 `build_script()` consumers are therefore *not* converted — they refuse | a technique refuses where it could have worked → accepted, and visible in the failure reason rather than silent |
| S7 | `analysis/static.py:76`, `:303` | delete the unreachable `"argv"` entry; comment that `file input` is **not** a vector oracle, citing B-2 | removes dead code | none; behavior-neutral by inspection |
| S8 | `profile_stage.py` prologue | call the probe **once**, store the spec on `ExploitContext` **before** the verifier is first used | one extra probe (≤4 short runs) per invocation | latency → bounded; probe failure routes to stdin |

Ordering: S1 → S2 → S5 (wiring first, so nothing can read a stale spec) →
S3/S4 → S6 → S7/S8.

### 5.1 Per-site disposition — every target launch in the pipeline

Finding 4 is correct that §1's "five spawn sites" was materially incomplete.
Measured inventory (match identity: `grep -rn "process(\|subprocess.run(\|
subprocess.Popen(\|gdb.debug("` across `supwngo/exploit/pipeline/`, then static
tool invocations — `objdump`, `ldd`, `readelf`, `ROPgadget`, `ropper` — removed by
inspection of each line). **Every launch gets an explicit disposition; none is
left unstated.**

| site | what it launches | disposition |
|---|---|---|
| `delivery.py:153` | target | **consumes spec** (S3) |
| `verification.py:241` | target | **consumes spec** (S4) |
| `verification.py:281` | target | **consumes spec** (S4) |
| `templates.py` raw-payload template | generated artifact | **consumes spec** (S6) |
| `profile_stage.py:198` | target | stdin-only, **documented**: profiling reads the target's greeting; no payload involved |
| `leak_stage.py:82` | target | stdin-only, **documented**: multi-round leak, no pre-spawn payload |
| `executors/_shared.py:77` | target under GDB | stdin-only, **documented**: offset discovery via crash, separate contract |
| `executors/_shared.py:250` (`spawn_and_send`) | target | stdin-only, **documented**; file-mode callers refuse via S6 |
| `executors/heap_and_bypass.py:166`, `:280`, `:376` | target | stdin-only, **documented**: heap sequencing is inherently multi-round |
| `executors/stack_techniques.py:352` | target | stdin-only, **documented**: shellcode path is interactive |
| `executors/canary_leak_techniques.py:247` | target | stdin-only, **documented**: leak-then-send, multi-round |
| `templates.py` multi-part template, `script_builder.py:98` | generated artifact | **refuses in file mode** (S6) |
| `input_shape_techniques.py:86`, `heap_techniques.py:100`, `rop_techniques.py:74`, `_shared.py:217`, `verifier.py:183` | `objdump` / `ldd` / the *generated script* | **not target launches** — excluded, listed so the exclusion is auditable |

**Consequence, stated plainly:** after this sprint a file-vector target is solvable
only by single-shot payload techniques. Every other technique reports a clear
refusal on such a target. That is a real limitation and it is the price of a
sprint that can be reviewed and reverted in one piece.

## 6. Test plan — written before execution

New file `tests/test_input_vector_delivery.py`.

**Regression surface (must stay green, same command before and after):**
`pytest tests/ -q`. Known pre-existing failures, excluded **by name**, not
tolerated silently: `test_i2_attempt_duration` (I-1), `test_solve_command::
test_guided_fallback_resumes_to_success_with_supplied_offset` (I-2). Counts are
read off the output by me, never relayed from a delegate.

| gate | asserts | how it is proven able to go RED |
|---|---|---|
| T1 spec→argv contract | `DeliverySpec()` yields exactly `[binary]`; `{payload_file}` substituted at the right index; a spec missing the placeholder **raises** rather than silently dropping | mutate the default `sink`; **and** mutate `build_argv` to ignore `sink` — finding 7 correctly notes the first mutation alone passes if argv ignores the sink |
| **T1b per-site seam tests** *(new, finding 5)* | at each of the 4 consuming sites, capture and pin **argv, exact stdin bytes, cwd, env keys, newline behavior, and whether a file was created**. Default spec must reproduce today's values *at the site*, not in a pure function | replay each pinned tuple against a mutated site; every mutation must fail exactly one seam test |
| **T2 file materialization** *(new, finding 5)* | `SINK_FILE` file contents are exactly `b"".join(parts)`; **no bytes are written to stdin**; `verification.py:241` and `:281` produce **identical file bytes** despite `input=` vs `sendline()` | make `:281` keep its implicit `\n`; T2 must fail |
| **T3 end-to-end capability** *(rewritten, finding 6)* | the argv/file fixture is solved by `CanonicalAutopwnEngine(...).run()` with **no injected spec, no supplied offset, the real probe, real wiring**, and the emitted artifact then executed independently | run the identical fixture on the **pre-change revision** and record the failure. Until that run exists, M-4's baseline is `inferred`, not `measured` |
| T4 probe true positive | `classify_input_vector()` returns `SINK_FILE` on the file fixture | mutate the fixture to ignore `argv` → must return `stdin`; mutate it to read `argv` but never open → must return `argv-only` |
| **T5 adversarial negatives** *(strengthened, finding 7)* | four purpose-built fixtures, each must route to `SINK_STDIN`: (a) nondeterministic stdout (prints its PID), (b) argc-sensitive banner but stdin payload, (c) opens an argv config file but reads the payload from stdin, (d) plain stdin | "return True unconditionally" is too weak a mutation; instead **each fixture is the mutation** — any one misclassified fails T5 |
| T6 artifact reproduces | the generated script for the file fixture, run in a **clean directory with no pre-existing payload file**, captures the flag | strip argv from the emitted script; T6 must fail |
| **T7 stdin paths still function** *(rewritten, finding 7)* | the 3 conclusive stdin fixtures are **solved**, end to end — not merely "the code path is present" | finding 7 is right that a fixture-deletion setup error proves only subject existence; T7 asserts positive solves, so deleting a fixture **errors** and misrouting one **fails** |
| T8 file hygiene | no payload file survives a failed attempt | remove the `finally` cleanup, with the induced failure occurring **after** file creation; T8 must fail |
| **T9 spec propagation** *(new, finding 2)* | the `PipelineVerifier` used during attempts observes exactly the spec stored on `ExploitContext` by the prologue | set the spec to `SINK_FILE` post-construction; a constructor-carried implementation must fail T9 |
| **T10 documented refusal** *(new, finding 3)* | on a file-vector target, a multi-round technique returns a refusal naming file delivery — and **does not** report SUCCESS or silently send to stdin | make it fall through to stdin; T10 must fail |

**Tri-state handling (finding 7).** A gate reported `skip`/`xfail`/inconclusive
leaves pytest green, so: **required capability gates (T3, T4, T5, T7) fail on
inconclusive.** Only T-tests that specifically exercise the tri-state API may
assert an inconclusive *result*. Enforced by a session-level check that no
required-gate node is reported skipped.

**Regression command (finding 7).** The earlier wording named the two known
failures but did not exclude them. Exact form:

```
pytest tests/ -q \
  --deselect tests/test_i2_attempt_duration.py \
  --deselect "tests/test_solve_command.py::test_guided_fallback_resumes_to_success_with_supplied_offset"
```

I read both counts off the output myself; delegate-reported counts are never
relayed.

`snowscan` gets a **progress** assertion only, not a solve, and it must run
**through the new delivery abstraction** — a manual direct run with argv can
already pass today and would not be attributable to this work (finding 8). The
assertion names the **exact** expected stage error (`Invalid file signature.`),
not merely "some later output".

## 7. Benefit metric (Phase 8) — pre-registered

Units and provenance corrected per finding 8. Node IDs are concrete.

| ID | metric (with unit) | harness | baseline (pre-change) | provenance |
|---|---|---|---|---|
| **M-4** | **fixture targets solved: 0/1 → 1/1**, by `CanonicalAutopwnEngine.run()` with no injected spec | `tests/test_input_vector_delivery.py::TestEndToEnd::test_file_vector_fixture_is_solved` | **0/1.** No launch site can pass argv (§5.1). **Relabeled: this is `inferred` until the fixture is built and run on the pre-change revision** — an unbuilt fixture's result cannot be `measured`, which is my own rule | `inferred` → becomes `measured` when the pre-change run is recorded |
| **M-5** | **`snowscan` validation gates passed: 0/4 → 2/4**, measured *through the delivery abstraction*, asserting the exact stage error `Invalid file signature.` | `tests/test_input_vector_delivery.py::TestSnowscanProgress` | **0/4** — never passes `No file provided as an argument.` | `measured` |
| **M-6** | **13/13 eligible corpus targets SUCCESS; each target 5/5 reps** | `benchmark/run_bench.py --jobs 4` | run `20260926-164613Z` on `main` @ `311ff25`; 2 VOID (`11_heap_uaf_leak` = `corpus_missing_liveness_gate`, `13_off_by_one` = `corpus_trivially_solvable`) | `measured` |
| **M-7** | **known stdin targets retaining `SINK_STDIN`: 6/6** (3 conclusive negatives + 3 inconclusive-safe), plus the per-target outcome vector | `classify_input_vector()` over the HTB set + forced-strategy matrix | 6/6 on stdin today, by construction — nothing else is possible | `measured` |

**The 2 VOIDs are corpus faults and must NOT be "fixed" to make numbers move.**
M-6 is compared **per target**, never in aggregate, so a compensating pair of
changes cannot hide as a wash.

**M-4 is the load-bearing claim, and it is weaker than Revision 1 asserted.**
Finding 6 is right: a green T3 with injected plumbing would prove nothing about
canonical integration, and the "structural impossibility" baseline is an
*argument* from reading §5.1, not a run. It is labeled `inferred` until the
pre-change fixture run exists, and that run is now a prerequisite of the sprint
rather than a formality.

**Withdrawn (finding 9):** the Revision-1 claim that the spec is "serializable
into the receipt so the harness can audit delivery". `VerificationReceipt` has no
delivery field and no sub-component adds one. Rather than grow the sprint, the
claim is **removed** — §3's advantages list no longer cites it.

**The 2 VOIDs are corpus faults and must NOT be "fixed" to make numbers move.**
M-6 is compared **per target**, not in aggregate, so a compensating pair of
changes cannot hide as a wash.

**M-4 is the load-bearing claim.** Its baseline is not a low score, it is an
impossibility proof — which is the strongest form of before/after available here
and mirrors how Sprint 1's fixture B was argued.

## 8. Rollback

Single branch `feat/input-vector-delivery`, one revert. S1/S2/S7 are additive
(new type, new module, dead-code deletion). S3–S6 are `spec=None` defaults, so
reverting the prologue call (S8) alone disables the whole feature while leaving
the plumbing inert — a two-stage rollback where stage one is one line.

## 9. Peer-review gate

Not started until an independent Tier-2 model (Daybreak Blue, `xhigh`, cyber)
reviews this plan non-interactively via file handoff. Round 2 of max 3 for this
effort. Findings answered **by class** with a stated sweep match identity and a
count — never instance-by-instance.

Open round-1 classes still owed an answer, carried forward:
provenance conflating origin with necessity; loop-order side effects on the five
winning-result fields; M-2/M-3 metric validity and units.
