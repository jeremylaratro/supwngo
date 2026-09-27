# Sprint 2′ — Input-Vector Abstraction (argv / file channel)

Phase 5 artifact. Closes **G-2a** (argv/file targets structurally unreachable) and
**B-2** (vector classifier inverted). Gap analysis:
`docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md`.

**Provenance labels**: `measured` (I ran it this session), `recorded` (prior
artifact, cited), `inferred` (reasoned, not observed).

**Status: REVISION 3 (current) — see the REVISION 3 section at the end of this
document, which supersedes Revision 2's §4 feeder design. Rounds 2 and 3 both
returned NOT-APPROVED on the same class (the probe's authority), so the 3-round
cap was reached and the outcome is a design change: the probe becomes advisory and
the vector becomes operator-declared. No implementation code has been written.**

*The Revision-2 material below is retained rather than edited away, so the
correction sits beside the original. Where §4 and Revision 3 disagree, Revision 3
governs.*

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

> **VOCABULARY NOTE (added with REVISION 5) — read before implementing from this
> table.** This table is Revision-2 text and predates REVISION 4's four-transport
> model. Wherever it says **`SINK_FILE`**, the shipped code has **two** constants:
> `SINK_FILE_ARGV` (the path is passed in argv) and `SINK_FILE_FIXED` (the target
> opens a path it already knows). Use `is_file_sink(sink)` to cover both. There is
> also `SINK_ARGV`, where the payload *itself* is an argv token and no file exists —
> absent from this table entirely. The four shipped constants live in
> `supwngo/exploit/pipeline/contracts.py`; that module, not this table, is the
> vocabulary of record. Likewise S2's "3-stage probe" shipped as **four** stages.
> Struck rows and stale names are retained deliberately so corrections sit beside
> their originals, but implement against the code.

| # | Files | Change | Contract affected | Failure mode introduced |
|---|---|---|---|---|
| S1 | `pipeline/contracts.py` | `DeliverySpec` + `SINK_STDIN`/`SINK_FILE`; `build_argv(payload_path)`; `materialize(parts) -> bytes` | new type, additive | a wrong default silently changes every spawn → pinned by per-site seam tests, not by S1 alone |
| S2 | `analysis/vector_probe.py` *(new)* | `classify_input_vector()` — the 3-stage probe of §4, extension discovery | new module | false positive → 3 independent conditions + T5 adversarial fixture |
| S3 | `pipeline/delivery.py:153` | `deliver_parts(..., spec=None)`. In `SINK_FILE`: materialize `b"".join(parts)` to a unique file in `cwd`, pass via argv, and **suppress stdin writes entirely** | `deliver_parts` gains a kwarg | temp file leaks → unique name, `finally` cleanup (T8) |
| S4 | `exploit/verification.py:241`, `:281` | thread spec through **both** paths | `ExploitVerifier.__init__` gains optional `spec` | the two paths differ today (`input=payload` vs `sendline(payload)`, which appends `\n`) → S4 test asserts identical **file bytes** from both |
| S5 | `pipeline/verifier.py` + `core/context.py` + `orchestrator.py` | **Resolve the spec at call time** from `context.delivery_spec`, *not* via the constructor | `PipelineVerifier` reads the context it already holds | **this is finding 2**: a constructor-carried spec is built at `orchestrator.py:152`, before the prologue at `:237`, so it would be permanently stdin. Call-time resolution removes the ordering hazard by construction; T9 asserts the verifier observes the same value stored on the context |
| S6 | `templates.py` raw-payload template only | File mode is supported **only** where the payload is a pre-spawn constant. The generic `build_script()` path and the multi-part template **raise a documented "file delivery unsupported for this technique" error** rather than emitting an artifact that silently sends to stdin | **generated artifact shape**, narrowly | **this is finding 3**: `open_target()` (`script_builder.py:88-98`) is called before the body computes the payload, so it cannot write a payload file. 13 `build_script()` consumers are therefore *not* converted — they refuse | a technique refuses where it could have worked → accepted, and visible in the failure reason rather than silent |
| S7 | `analysis/static.py:76`, `:303` | delete the unreachable `"argv"` entry; comment that `file input` is **not** a vector oracle, citing B-2 | removes dead code | none; behavior-neutral by inspection |
| S8 | ~~`profile_stage.py` prologue~~ | ~~call the probe **once**, store the spec on `ExploitContext` **before** the verifier is first used~~ | ~~one extra probe (≤4 short runs) per invocation~~ | ~~latency → bounded; probe failure routes to stdin~~ |

> **ERRATUM on S8 (added with REVISION 5).** The S8 row above is **struck and
> superseded by REVISION 3**, which is the governing revision. It describes the
> probe *deciding* the sink — exactly the authoritative-probe design that rounds 2
> and 3 both returned NOT-APPROVED on, and that measured false positives still
> justify rejecting (a false positive suppresses a target's working stdin delivery).
>
> **S8 as it actually stands:** the vector is **operator-declared** — an
> `--input-vector`/`--input-name` CLI option and the matching engine option. The
> probe may be *logged* as a hint for the operator, but must never select a sink.
> The row is left in place rather than deleted so the correction sits beside the
> original.

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

---

# REVISION 3 — the probe becomes advisory; the vector becomes operator-declared

**Round cap reached (3 of 3).** Per the review protocol, a class recurring after
three rounds is escalated as a *design* change, not patched again. Finding 1
recurred in all three rounds, so the design changes.

## What killed Revision 2, measured by me before the round-3 review returned

I built the four adversarial fixtures Revision 2's T5 promised
(`tests/fixtures/input_vector/`) and ran the 3-stage classifier against them.
Match identity: direct launch, stdin `/dev/null`, first 300 bytes of
`stdout+stderr`, extension auto-discovered from refusal text.

| fixture | expected | 3-stage result | |
|---|---|---|---|
| `file_vector_gate` (payload really is the file) | `SINK_FILE` | `SINK_FILE` | ✔ |
| `neg_nondeterministic` (prints its PID) | inconclusive | `INCONCLUSIVE(nondet)` | ✔ |
| `neg_argc_banner` (argc-dependent banner, stdin payload) | `stdin` | `argv-only` | safe mislabel |
| `neg_argv_config_stdin_payload` (opens an argv config, payload on stdin) | `argv-only` | **`SINK_FILE`** | ✘ **UNSAFE** |

**The unsafe false positive is real and reproducible.** Revision 2 asserted T5
would "prove the probe is not fooled by it"; the probe *is* fooled. Round 3
reached the identical conclusion analytically and noted the sharper form: T5(c)
**cannot** pass under Revision 2's own algorithm, so the plan contained a gate
that contradicted its specification.

I then added a 4th stage — does the file's *content volume* change behavior
(32-byte vs 4096-byte file, comparing output and returncode)? That fixed every
fixture: **0 unsafe false positives, 4/4 as designed.** But it also produced the
finding that ends this line of design:

> **`snowscan` classifies as `argv-only(config)` under the safe 4-stage probe.**
> Its signature check rejects a 32-byte and a 4096-byte file with *identical*
> output, so no content-volume signal escapes. **B-3's format validation masks the
> very signal needed to classify the vector.**

**This inverts the dependency the whole sprint assumed.** Revision 1 and 2 both
treated B-3 (format gates) as strictly *downstream* of the channel. It is not: a
probe cannot safely identify a format-validating target as a payload sink until it
can already satisfy that target's format. The choice is therefore between a probe
that is safe but silent on `snowscan`, and a probe that flags `snowscan` but can
regress a working target. **Neither is acceptable as an automatic decision.**

## Revision 3 design

Both the measurement and round 3's "smallest approvable change" land in the same
place, from different directions:

1. **The probe is advisory, never authoritative.** A positive result yields
   `FILE_CANDIDATE` and is *reported* — it never commits `context.delivery_spec`.
   A heuristic therefore cannot regress a working target, which closes finding 1
   by removing the probe's authority rather than by improving its accuracy.
2. **Only an explicit operator option commits the vector**: engine
   `input_vector="file"` / CLI `--input-vector file --input-name NAME`. The
   capability is "supwngo can exploit file-input targets **when told the vector**",
   which is honest, testable, and cannot misfire.
3. **Refusals are enforced centrally, at the engine, before any executor runs.**
   Round 3 correctly notes a refusal inside `script_builder` is too late: excluded
   techniques launch earlier at `input_shape_techniques.py:158`,
   `stack_techniques.py:308`, `heap_and_bypass.py:249`. One engine-level gate in
   file mode, parameterized over every excluded executor.
4. **Exact-replay fidelity is a gate, not an assumption.** Round 3 found a real
   latent defect: executors verify `payload + b"\n"` but store
   `record.payload = payload` (`stack_techniques.py:125`), and the raw template
   recovers the newline via `sendline()` (`templates.py:178`). A file template
   writing only `PAYLOAD` would **not** reproduce the verified bytes. T6 asserts
   the artifact's file bytes equal the verified bytes exactly.
5. **`DeliverySpec` gains an auxiliary-file slot** so `argv-only` targets (config
   in argv, payload on stdin) are representable rather than coerced.

### Corrections carried in

- **M-7 count corrected again (finding 8, still open in round 3 — reviewer right,
  I was wrong twice).** §4's direct-launch table is **2 conclusive stdin
  negatives + 1 file positive + 3 inconclusive-safe = 6**. Revision 2 said "3
  negatives + 1 positive + 3 inconclusive on 6", which sums to **seven**.
  `rocket_blaster_xxx` was a conclusive negative only in the earlier
  *loader-based* sweep, not the direct-launch one. Correct metric:
  **5/5 non-file targets retain `SINK_STDIN`** (2 conclusive + 3 inconclusive-safe).
- **M-5 restated:** `snowscan` validation gates passed **0/4 → 2/4**, reached via
  the **explicit option**, not via the probe — the probe does not and will not
  flag it while B-3 stands.
- **B-3 re-triaged from P2 to P1** and marked a *prerequisite of reliable
  detection*, not a follow-on. Automatic file-vector detection for
  format-validating targets is blocked until a format synthesizer exists.

### Status

**Not submitted for a 4th round — the cap is reached and the outcome is a design
change, which is the protocol's prescribed terminal action.** Revision 3 is
implementable as specified: its capability claim no longer depends on a heuristic
being right, only on the channel being correct when the operator names it.

---

# REVISION 4 — file input as a general MECHANISM, not a snowscan solution

**Direction from the maintainer:** *"the implementation should not be solely tuned
to the challenge. Different challenges with different types of file inputs need to
work — file input as a mechanism, transport for fuzzing ingress and exploit code
needs to work conceptually."*

Correct, and it exposed two real omissions in Revisions 1–3, one of which I had
specified *wrongly*.

## What was wrong

1. **I modeled one transport and called it "the file channel".** Revisions 1–3
   only expressed "payload in a file whose path is `argv[1]`" — the snowscan
   shape. Three other real transports were absent, and one of my own rules
   actively rejected a legitimate case (I specified `ValueError` when
   `argv_template` lacks `{payload_file}`, which forbids **fixed-path** input).
2. **I was about to duplicate a vocabulary that already exists.** `grep` first, as
   my own rule says: `supwngo/fuzzing/afl.py:389` already documents
   `input_method: How binary receives input (stdin, file, argv)` and generates a
   `fopen(argv[1], "rb")` harness at `:429`; `supwngo/fuzzing/cmplog.py:500`
   already uses AFL's `@@` file placeholder. The exploit path must converge on
   that vocabulary so one transport model serves **both fuzz ingress and exploit
   delivery** — which is precisely the maintainer's point.

## The mechanism taxonomy (implemented now)

| transport | constant | meaning |
|---|---|---|
| stdin | `SINK_STDIN` | bytes to fd 0 (today's only behavior) |
| argv | `SINK_ARGV` | the payload bytes **are** an argv token (`./vuln $(payload)`) |
| file via argv | `SINK_FILE_ARGV` | payload in a file whose **path** is passed in argv — at any position, bare or behind a flag |
| file at a fixed path | `SINK_FILE_FIXED` | payload in a file the target opens **itself**, no argv involved |
| socket | *(reserved)* | G-2d, P3, unimplemented |

`argv_template` accepts `{payload_file}` **and `@@` as an alias**, because `@@` is
AFL's convention and already appears in this repo. Position and flags are
expressible: `("-f", "@@")`, `("--input", "{payload_file}")`, `("mode", "@@")`.
A separate `{payload_arg}` placeholder marks the `SINK_ARGV` token, so the two are
never conflated. `stdin` and `argv` are **orthogonal** — a target may need an
unrelated config argument while its payload still arrives on stdin.

A reserved `container` field is the hook for a **pluggable format envelope**
(wrap payload bytes so a format-validating parser accepts them). It is deliberately
unimplemented here. The general answer to B-3 is a *registry* of format
containers — BMP, PNG, WAV, ZIP, PCAP — with BMP merely the first entry, **not** a
BMP-shaped special case. Same envelope serves fuzz seed generation.

## Measured mechanism matrix

Six fixtures in `tests/fixtures/input_vector/`, each with the gate a struct-pinned
64 bytes from its buffer so `VariableOverwriteExecutor`'s sweep can reach it. Every
row `measured`; each "solves" verified against a wrong-value negative control.

| fixture | mechanism | solves via its transport | probe verdict |
|---|---|---|---|
| `file_vector_gate` | `fopen`/`fread`, bare argv | ✔ | `file-candidate` ✔ |
| `mech_open_read_argv` | raw `open`/`read`, bare argv | ✔ | `file-candidate` ✔ |
| `mech_line_text` | `fgets` line-based **text** file | ✔ | `file-candidate` ✔ |
| `mech_flag_style` | file behind `-f FILE` | ✔ | **`stdin`** ✘ false negative |
| `mech_fixed_path` | fixed `input.dat` in cwd, no argv | ✔ | **`stdin`** ✘ false negative |
| `mech_argv_payload` | payload **is** `argv[1]` | ✔ | `argv-only-not-opened` |

### Two findings that change the design's framing

**The probe detects 3 of 6 mechanisms.** It keys on a bare path in argv, so
flag-style and fixed-path are invisible to it, and argv-payload is not a file at
all. **Every miss routes to `SINK_STDIN`** — today's behavior — so the Revision 3
safety rule holds and nothing regresses. But the conclusion is stronger than
Revision 3 stated: **the operator option is the primary interface for half the
mechanism space, not a fallback for when the heuristic is unsure.** Auto-detection
is a convenience on one shape.

**`SINK_ARGV` must pass raw bytes, never `str`.** Measured: the identical payload
passed as a latin-1-decoded `str` **silently fails** (target prints `nope`) because
the high bytes are re-encoded as multi-byte UTF-8, while the same payload passed as
`bytes` wins. A `str` argv path would produce unreproducible SUCCESSes. This is a
required implementation constraint with its own gate, not a stylistic note.

## Consequences for scope

- §2's narrowed scope is **unchanged in spirit** — single-shot payload techniques
  only, `{variable_overwrite, ret2win}`, everything else refuses centrally — but it
  now covers **four transports** rather than one. The wiring is shared, so the
  incremental cost is the spec plus per-transport gates; the transports were never
  the expensive part.
- **M-4 generalizes** from "fixture targets solved: 0/1 → 1/1" to
  **"input mechanisms solved: 0/6 → 6/6"**, each with its own negative control. That
  is a materially stronger claim than the single-fixture version and it directly
  answers "does this work as a mechanism".
- **B-3 is re-framed** from "write a BMP header" to "add the first entry to a
  container registry". Its sprint must demonstrate the registry with **two**
  formats, not one, or the generality is unproven.
- `detect_input_sources()`'s existing `"file"`/`"stdin/file"`/`"command line"`
  labels stay untouched (B-2 says they are not a vector oracle), but the new
  transport vocabulary deliberately matches `afl.py`'s `stdin|file|argv` so the
  fuzzing and exploit paths can later share one resolver.

---

## REVISION 5 — `stage3_basis`, and a correction to the false-positive bound

Appended 2026-09-26, after the foundation layer (S1/S2/S7) was built and tested.
Two of this document's earlier claims turned out to be measurably wrong. Both
corrections are recorded here rather than by editing the originals.

### Correction 1 — the probe's false-positive class was larger than stated

REVISION 3 argued the 4-stage probe had "0 unsafe false positives", citing the four
adversarial fixtures then in the suite. That is **an artifact of which fixtures were
chosen, not a property of the probe.** A fifth adversarial fixture,
`tests/fixtures/input_vector/neg_slow_config_stdin_payload.c`, was built
specifically to attack stage 3 and produced a false positive on the first try:

| | 32-byte config | 4096-byte config |
|---|---|---|
| wall clock | ~0.43 s | 20.00 s (exceeds the 5 s budget) |
| probe sees | normal exit | `rc: None` (timeout) |

Its payload channel is **stdin**; argv carries only a config file. Stage 3 compares a
small against a large file and treats *any* difference as the content-volume signal,
so a target doing work proportional to its input size is classified
`file-candidate`. `MEASURED`.

This does not change the design, because REVISION 3 already removed the probe's
authority: an advisory verdict cannot commit a `DeliverySpec`, so a wrong advisory
cannot suppress a working stdin delivery. It does change what may be *claimed*. The
honest statement is **"no unsafe false positive can reach the pipeline"** (structural,
holds), not "the probe has no false positives" (empirical, false).

### Correction 2 — `stage3_basis` is not a discriminator

To keep the above diagnosable rather than latent, `classify_input_vector()` now emits
`evidence["stage3_basis"]` ∈ `{none, output, returncode, timeout}`, recording *why*
stage 3 fired. The initial rationale — that a caller could discount a timeout-driven
verdict — **over-claimed, and was caught by its own test.** Measured across every
file-candidate fixture:

| fixture | genuine file sink? | `stage3_basis` |
|---|---|---|
| `file_vector_gate` | yes | `output` |
| `mech_open_read_argv` | yes | `output` |
| `mech_line_text` | **yes** | **`timeout`** |
| `neg_slow_config_stdin_payload` | no | `timeout` |

`mech_line_text` reads its payload from a file and still times out, because it blocks
on a 4096-byte probe file containing no newline. So the weak class holds **both** a
genuine sink and a non-sink, and `timeout` means *"this stage proved nothing"* — never
*"not a file target"*.

Only the converse is usable, and it is the half now asserted:
**a `output`/`returncode` basis implied a genuine file sink in every case measured.**
Pinned by `test_stage3_basis_is_trustworthy_only_in_the_strong_direction`, with a
non-vacuity guard (the strong set must be non-empty) and both weak-class memberships
asserted so the false rule cannot be re-derived later.

### Correction 3 — a foundation gate was green only by omission

`test_exactly_the_true_file_vector_fixtures_are_unsafe_file_candidate` asserted the
probe's file-candidate set was *exactly* the three real sinks. That passed only
because the counterexample was absent from `FIXTURE_NAMES`; adding
`neg_slow_config_stdin_payload` turned it red immediately. The gate now asserts
`TRUE_FILE_CANDIDATES | KNOWN_TIMEOUT_FALSE_POSITIVES`, so a **new** false positive
still fails while the known one is enumerated and labelled. Deleting the gate or
quietly leaving the fixture out were both rejected: the first loses the regression
protection, the second is the defect.

### Effect on the metrics

- **M-7** is restated as **"5/5 non-file HTB targets retain `SINK_STDIN`"** (the
  earlier count conflated conclusive and inconclusive verdicts; see the round-1/2
  class answers). Unchanged by this revision.
- No change to M-4, M-5, or M-6. The probe is not on any metric's critical path —
  the operator-declared vector is, which is the point of REVISION 3.

### Correction 4 — REVISION 5's own Correction 2 was ALSO an over-claim

Appended after the Phase-6 implementation-diff review
(`docs/plans/2026-09-26-foundation-diff-review-daybreak.md`, verdict NOT-APPROVED).

Correction 2 above concluded that although `stage3_basis` is not a discriminator,
**"a `output`/`returncode` basis implied a genuine file sink in every case measured"**
and that this was "the half a caller may rely on". The reviewer challenged the
implication as unsupported by a fixture corpus. I built the counterexamples and
**the challenge is correct.** `MEASURED`:

| target | opens a file? | payload channel | verdict | `stage3_basis` |
|---|---|---|---|---|
| `neg_argv_echo_no_open` | **never** — only `printf`s `argv[1]` | stdin | `file-candidate` | `output` |
| `neg_fast_cfg_stdin_payload` | yes, a config only | stdin | `file-candidate` | `output` |

So a *strong* basis does not imply a file sink either. **`stage3_basis` has no
trustworthy direction in either sense.** It records only *why* stage 3 fired; it is
diagnostic metadata, not evidence. Both counterexamples are promoted to permanent
fixtures, and the test asserting the strong implication is replaced rather than
narrowed.

Note the pattern, because it is the third instance in this sprint: a property was
verified across the fixtures that happened to exist, then stated as a general
implication. The fixtures were the *sample*, not the *domain*. The two earlier
instances were the always-green measurement harness and the
`file-candidate`-set-by-omission gate (Correction 3). The lesson that generalizes:
**a claim of the form "X implies Y" cannot be established by a corpus that was built
to exhibit X** — it needs a deliberate attempt to construct `X ∧ ¬Y`, which is what
finally refuted it here.

### Root cause behind two of these — the pathname confound

The reviewer also identified *why* such false positives are so easy to produce, and it
is a defect rather than an inherent limit. Stages 1-3 used three **different** paths
(`missing_input<ext>`, `existing_small<ext>`, `existing_large<ext>`), so every stage
varied the file's *basename* alongside the variable it meant to isolate. A target that
merely echoes `argv[1]` therefore differs at every stage without ever opening
anything — which is exactly `neg_argv_echo_no_open`. The fix is to probe **one** path
through all three states (absent → 32 bytes → 4096 bytes).

### Also accepted from that review

- **`DeliverySpec.build_argv()` silently accepted undeliverable specs** (HIGH). All
  five reported combinations reproduced. The worst is an unknown/typoed `sink`, which
  falls through every branch and is treated as stdin, **silently dropping the payload** —
  the same silent-failure class for which §3 rejected Method B, re-entering through the
  sink string rather than through `isinstance`. Accepted for loud validation; the
  fix is in progress at the time this section was written, not yet landed.
- **Two test-vacuity gaps** (MEDIUM): `EXPECTED_VERDICTS`'s keys were never asserted
  equal to `FIXTURE_NAMES`, so a fixture added to one list only would silently get no
  verdict test — the same shape as Correction 3. And `TestProbeIsAdvisoryOnly` checked
  a *blocklist* of three parameter names, so adding a `state=None` parameter and
  mutating it would have kept the gate green; it now asserts the parameter set exactly.
- **`OSError` was reported as `"timeout"`** (MEDIUM) and extension discovery was not
  timeout-tolerant (MEDIUM), contradicting the module's documented post-stage-0 rule.
- **Docstring accuracy** (LOW): stages 1 and 2 are documented as comparing output but
  compare `(returncode, output)`; "never opened" and "used only as configuration" are
  stronger than the evidence (a target may open, read, and ignore; `stat`/`access`
  produce the same signature).

`materialize()` was reviewed and found correct.

### New obligation for the wiring layer (S3–S6), created by the `build_argv` hardening

T1 already required that an undeliverable spec **raise** rather than silently drop the
payload, and that is now implemented for five cases (including an unknown `sink`
string). The consequence for the wiring layer is new and must be designed for, not
discovered at runtime:

**A `ValueError` from `build_argv()` must be caught at the central refusal gate in
`_attempt_techniques` and converted into a recorded `failure_reason` for that
technique — never allowed to propagate and abort the whole engine run.** An operator
typo in `--input-vector`/`--input-name` is a user error affecting one technique's
delivery; it must not lose the results of every other technique already attempted.

This pairs with the existing S8 requirement that the CLI validate its own vector
argument up front: the CLI check is the friendly path, and the gate's `try/except` is
the backstop for any spec constructed internally. Both are needed — the CLI cannot
see a spec built by a future caller, and the gate cannot produce a good error message
about a flag it never saw.

Test obligation: add to T10 a case where a deliberately malformed spec reaches the
gate, asserting (a) the run completes, (b) that technique's `failure_reason` names the
delivery problem, and (c) the other techniques still report their own outcomes. Prove
it RED by letting the exception propagate.

---

## Phase 7 / Phase 8 — foundation layer (S1, S2, S7)

### Phase 7(a) — nothing that worked before is broken

`measured`, run `20260926-211443Z`:

| gate | baseline (pre-change, `main` @ `311ff25`, run `20260926-164613Z`) | after | Δ |
|---|---|---|---|
| benchmark, **compared per target** | 13/13 eligible SUCCESS, each 5/5 reps; 2 VOID | 13/13 eligible SUCCESS, each 5/5 reps; 2 VOID | **none** |
| full pytest suite | — | **1174 passed, 14 skipped, 14 deselected, 0 failed** | — |

The 2 VOID targets are unchanged and remain **corpus faults, not tool faults**:
`11_heap_uaf_leak` (`corpus_missing_liveness_gate`) and `13_off_by_one`
(`corpus_trivially_solvable`). They must not be "fixed" into passes.

Two process notes, both recorded because they affected the evidence:

- The earlier regression command's `--deselect` for the known `solve_command`
  failure **silently never matched** — the node ID omitted the `TestSolveEndToEnd::`
  class segment, so only 13 items were deselected and the test ran every time. A
  filter that cannot fail is the same defect class as a test that cannot fail. The
  correct ID is
  `tests/test_solve_command.py::TestSolveEndToEnd::test_guided_fallback_resumes_to_success_with_supplied_offset`;
  14 items are now deselected and the suite is clean.
- That failure was confirmed **pre-existing** by stashing all working changes and
  re-running it at `HEAD` — it fails identically (90 s subprocess timeout in the
  `solve` CLI). It is not caused by this sprint.

### Phase 8 — material benefit, and what is NOT claimed

**No target moved from FAIL to SUCCESS, and none could have.** `measured` — match
identity: `DeliverySpec` and `classify_input_vector|vector_probe` across all `*.py`
excluding `tests/` and each symbol's own defining file → **zero production
consumers**; every non-test hit is a docstring or comment mention. The foundation
layer is unwired by design (S1/S2/S7 only). The pre-registered target metrics M-4
through M-7 belong to the wiring layer and are **not** claimed here.

What is claimed, against the same harness:

| # | metric | baseline | after | provenance |
|---|---|---|---|---|
| F-1 | probe false positives among purpose-built adversarial fixtures | 2 of 3 non-sink fixtures misclassified `file-candidate` | **1 of 4** (`neg_argv_echo_no_open` fixed by the single-path change; `neg_fast_cfg_stdin_payload` and `neg_slow_config_stdin_payload` remain, both pinned) | `measured` |
| F-2 | genuine file sinks still detected | 3/3 | **3/3** — no regression from the fix | `measured` |
| F-3 | `build_argv()` paths that silently drop or corrupt a payload | 5 | **0** (all raise `ValueError`) | `measured` |
| F-4 | gates in the input-vector suites able to pass vacuously | 4 (set-equality-by-omission, expectation/fixture parity, name-blocklist signature gate, tautological pair) | **0** | `measured` |
| F-5 | mislabelled failure causes in probe evidence | 2 (`OSError`→`"timeout"` in stage 3; timeout→`"launch_error"` in stage 0) | **0** | `measured` |

**Honest characterization of that benefit.** F-1 is a capability improvement. F-2 is a
non-regression. F-3, F-4 and F-5 are **correctness and trustworthiness-of-measurement
improvements, not capability improvements** — they are explicitly the non-metric
ground the methodology allows for keeping work that does not move the headline number.
They matter here for a specific reason: this sprint produced three separate
false claims that survived because a gate could not fail, so the value of removing
that possibility is not abstract.

**The claim this sprint must not make** is that the transport model works end to end.
It is a contract plus an advisory probe, both proven in isolation. Whether a
file-vector target can actually be solved is decided by the wiring layer, and remains
unproven until M-4 is measured there.

---

## Wave-1 wiring: measured defect — the declared vector does not reach the spawn

**Status: `measured`, 2026-09-26, before any wave-1 commit.**

Wave 1 of the wiring layer (`--input-vector`/`--input-name`, `context.delivery_spec`,
`PipelineVerifier.resolve_delivery_spec()`, and the central refusal gate) stores and
resolves a `DeliverySpec` correctly, and refuses every non-allowlisted technique under a
file sink. It does **not** make file delivery happen, because the spec never reaches a
spawn site.

**Sweep.** Match identity: `delivery_spec|resolve_delivery_spec|DeliverySpec` over all
`*.py` excluding `tests/` and `contracts.py` (the defining module). Production hits are
confined to four files — `orchestrator.py`, `verifier.py`, `core/context.py`, and
`analysis/vector_probe.py` (comment only). **`exploit/delivery.py`,
`exploit/verification.py`, and `exploit/pipeline/templates.py` have zero hits**, so no
code that actually launches the target consults the spec.

**Behavioral proof (not inference).** `variable_overwrite` — an allowlisted technique —
run against the `file_vector_gate` fixture, whose gate is reachable *only* through the
file, once with no vector declared and once with `input_vector="file-argv"`,
`input_name="payload.bin"`:

| declared vector | outcome | `failure_reason` |
|---|---|---|
| none (stdin) | FAILED | `exhausted 10 candidate values x 14 buffer sizes (1 recovered…` |
| `file-argv` | FAILED | **byte-identical** |

The payload went to stdin in both runs. The fixture is the M-4 baseline gate precisely
because it cannot be solved over stdin, so an identical failure is proof the declaration
changed nothing.

**Why this matters more than a missing feature.** The two allowlisted techniques are
*exactly* the ones that silently deliver to the wrong channel, which inverts the
`--input-vector` help text: it promises `file-argv` "writes the payload to a file whose
path is passed via argv" and that "every other technique refuses cleanly rather than
silently falling back to stdin." Today the *refusing* set is honest and the *allowlisted*
set is the silent fallback. This is the same silent-failure class that got Method B
rejected in §4 and that the `build_argv` hardening (T1) closed five instances of — a
declaration accepted, then quietly ignored.

**Consequence for sequencing.** Wave 1 must not ship on its own with that help text.
Two admissible options:

- **(chosen) Land wave 2 and commit the capability as one change.** `deliver_parts()`
  file mode plus both `verification.py` paths producing identical file bytes, so the
  declaration is honored at the spawn. One coherent commit — "honor an operator-declared
  delivery vector" — and no commit in history in which the tool accepts a file vector and
  delivers over stdin.
- **(not taken) Commit wave 1 first with the gate refusing file sinks outright**, help
  text corrected to match, then lift the refusal in wave 2. Honest at every commit and it
  protects the work sooner, but it adds a refusal plus a test asserting it, both deleted
  within the same `## [Unreleased]` block, and the changelog would state a limitation and
  retract it before release. **What would flip the choice:** wave 2 proving harder than
  scoped (e.g. the two `verification.py` paths not reconcilable to identical bytes) — then
  wave 1 ships behind the outright refusal rather than being held uncommitted.

**Generalizable lesson, third recurrence of the same shape.** A wiring layer that
resolves a value correctly is not a wiring layer that *uses* it. The wave-1 test suite is
green and its 26 tests are sound: they assert storage, call-time resolution, refusal, and
containment — every property except the one a user cares about. No test asked "does the
payload actually arrive through the declared channel," and the reachability sweep that
would have caught it was run *before* wave 1 (finding zero consumers, as expected) and not
re-run *after*. **Re-run the reachability sweep after adding the consumer, not only before.**

### Wave 2 spec — make the declared vector reach the spawn

Scope: the `PipelineVerifier.verify_payload` path only, which is the path both
allowlisted techniques use (`stack_techniques.py:125`, `:214`, `:234` all call
`verifier.verify_payload(self.name, payload + b'\n')`).

**Sub-component 1 — `ExploitVerifier` learns a generic spawn shape, not a sink.**
Two new parameters, deliberately carrying no knowledge of `DeliverySpec`:
`argv: Optional[List[str]] = None` (`None` → `[self.binary_path]`, today) and
`stdin_payload: bool = True` (`False` → stdin receives `b""`). Both spawn paths honor
them. **The layering choice:** `verification.py` sits *below* the pipeline layer that
owns the contract — `pipeline/verifier.py` imports `verification.py`, so importing
`pipeline/contracts.py` back into it would invert the dependency. Passing a prepared
argv + a stdin flag keeps contract knowledge in the layer that already has it. *Option
not taken:* duck-typing a spec object into `verification.py` as `Any` (the precedent
`context.py` set for the same layering reason). Rejected because `verification.py` would
then branch on sinks in two places, and the "identical bytes" invariant would be
asserted twice instead of once. *What would flip it:* a second consumer needing the
spec's own methods deeper down.

**Sub-component 2 — the newline asymmetry is the real hazard.** Path 1 is
`subprocess.run(input=payload)`; path 2 is `p.sendline(payload)`, which **appends
`\n`**. For stdin that asymmetry is long-standing and harmless. For a file sink it would
make the same payload produce two different files, so the fallback path would sometimes
solve and sometimes not, nondeterministically by which path ran. Therefore
`stdin_payload=False` must make path 2 **not call `sendline` at all** rather than send
something adjusted — a flag that merely swaps `sendline` for `send` would still leave two
code paths free to drift. The file is written once, before either path spawns.

**Sub-component 3 — `PipelineVerifier.verify_payload` owns materialization.** Resolve
the spec; non-file sink → `argv=None, stdin_payload=True`, byte-identical to today. File
sink → write `spec.materialize([payload])` to `binary_dir / spec.payload_filename`,
compute `argv = spec.build_argv(binary_path, payload_value=<that path>)`, pass
`stdin_payload=False`. Back up and restore any pre-existing file at that path: a target
may legitimately declare a fixed path that ships with the challenge, and this method runs
once per candidate — tens to hundreds of times per target — so an unrestored overwrite
would corrupt the target directory for every later attempt and for the benchmark corpus.

**Sub-component 4 — `templates.py` is refused, not half-built.** The generic
`build_script()` path calls `open_target()` (`script_builder.py:88-98`), which spawns the
target *before* the body computes the payload; a file sink cannot be expressed without
restructuring that ordering, and it has 13 consumers. Wave 2 documents the refusal. The
consequence is explicit and must be stated in the changelog: a *generated exploit script*
for a file-sink target is not produced by this wave, only a verified in-pipeline solve.

**Test plan.** (a) Regression: same suite command before and after, counts read off the
output directly. (b) New behavior: the end-to-end gate is `file_vector_gate`, whose win
condition is reachable **only** through the file — asserted UNSOLVED with the default
vector and SOLVED with `file-argv`. (c) Red-proofs: the identical-bytes property proven
by mutating `stdin_payload=False` to still call `sendline` and showing the byte-equality
test goes RED; the default-unchanged property proven by mutating the non-file branch to
pass a non-`None` argv and showing an existing test goes RED.

**The falsifiability risk in (b), named up front.** A solve gate can pass for the wrong
reason if the fixture is solvable by any route other than the file. That is why the
negative half of the gate — unsolvable with the default vector — is load-bearing and must
be asserted in the same test, not assumed from an earlier run. Both halves together are
what make the gate a discriminator; either alone is a decoration.

### Wave 2 REVISION 1 — after peer review (Daybreak Blue, `xhigh`), round 1 of 3

Verbatim review: `docs/plans/2026-09-26-wave2-design-review-daybreak.md`. Verdict
**NOT-APPROVED**: 2 Critical, 3 High, 3 Medium. Every finding below was **verified on
disk before being accepted** — the reviewer is not taken at face value.

**ERRATUM to the wave-2 spec above.** Sub-component 4 justified refusing script
generation by citing `build_script()` / `open_target()` (`script_builder.py:88-98`) and
its 13 consumers. That is the wrong function for this path. The allowlisted executors
reach `generate_success_script()` (`orchestrator.py:441`, taken when
`partial_artifacts["exploit_script"]` is empty, which is the normal case for executors
that verify a raw payload in-process), and its template is
`templates.py:172-178`: `io = process(BINARY)` then `io.sendline(PAYLOAD)` — stdin-only,
no argv, no file. The refusal as written therefore pointed at a path these techniques
never take, and would have left the real one untouched. Corrected below.

| # | Finding | Verified how | Disposition |
|---|---|---|---|
| C1 | `argv` sink is neither delivered nor refused | **Independently measured by me before the review landed**: `mech_argv_payload` with `input_vector="argv"` vs default → byte-identical `failure_reason` | ACCEPTED — implement, don't refuse |
| C2 | A verified file solve still emits a stdin-only exploit script and `solve` reports a working artifact saved | Read `orchestrator.py:428-443` and `templates.py:163-182` | ACCEPTED — implement an argv/file-aware template |
| H1 | Both CLI legacy fallbacks drop the vector | `grep -n "EnhancedAutoExploiter("` → **four** sites: 306, 392, **2762**, **3309**; the last two are the post-canonical-failure fallback | ACCEPTED |
| H2 | Target can mutate the payload file between spawn 1 and the fallback spawn | Reasoned from `verify_payload`'s two-path structure; the file is shared | ACCEPTED — re-materialize before each spawn |
| H3 | Restore must include restoring **nonexistence** | A left-behind `input.dat` would make a later default run differ | ACCEPTED — this one can contaminate the benchmark corpus |
| M1 | A typo'd sink is classified non-file and falls through to stdin | This is the latent gap I recorded myself before the review | ACCEPTED — validate the sink before classifying |
| M2 | `subprocess.run(input=b"")` gives EOF; an unsent pwntools stdin stays open | Correct; affects contract wording, not file bytes | ACCEPTED as wording |
| M3 | `--input-name` alone is accepted and discarded | Engine builds a spec only when `input_vector is not None` | ACCEPTED |

**A finding the review did NOT make, and the reason M-4 could not have reached 6/6.**
`mech_flag_style.c` takes its file via `-f FILE`, not bare `argv[1]`. Wave 1 builds the
template itself from a fixed mapping (`SINK_FILE_ARGV` → `("{payload_file}",)`), and
`grep -n "argv_template|payload_arg|input-argv|input_argv" supwngo/cli.py` returns
**nothing** — so there is no way for an operator to express `-f @@` at all. Flag-style
file arguments (`-f`, `-c`, `--input`) are at least as common as bare `argv[1]`, so this
is a transport-generality gap, not a fixture quirk. Wave 2 adds `--input-argv` taking a
template with `{payload_file}`/`@@`/`{payload_arg}` tokens, which `DeliverySpec` already
understands. Found by validating the six M-4 fixtures *before* trusting the gate that
depends on them, per the standing rule that every custom assessment is proven able to
fail first.

**Why the match identity failed twice.** Wave 1's construction-site sweep matched
`CanonicalAutopwnEngine(` and found 3 sites, all threaded. The same defect existed for
`EnhancedAutoExploiter(` and the sweep could not see it, because the identity named *one
class* rather than the property that mattered: **every engine that delivers a payload**.
A sweep is only as general as its match identity, and a narrow identity carrying a broad
negative is the failure this effort has now hit three times.

**Revised scope.** The honest consequence is that "wave 2" is the sprint, not a wave:
(1) `ExploitVerifier` gains keyword-only `argv=None` / `stdin_payload=True` (tested with
`argv is None`, never truthiness) plus a pre-spawn hook so bytes are re-materialized
before *each* spawn; (2) `PipelineVerifier.verify_payload` validates the sink first, then
handles `argv` (latin-1 byte token, loud refusal on embedded NUL — it cannot be
represented in an OS argv) and both file sinks, with backup/restore that restores
nonexistence in a `finally`; (3) the success-script template becomes vector-aware so the
saved artifact actually runs; (4) the two legacy fallbacks refuse loudly under a
non-default vector instead of "succeeding" over stdin; (5) `--input-name`/`--input-argv`
without a compatible vector is rejected at construction; (6) `--input-argv` is added.

**Gate hardening accepted from review answer (d).** The end-to-end gate uses a
**randomized** payload filename held constant across the negative and positive runs,
drives `CanonicalAutopwnEngine` directly, and asserts `technique_used ==
"variable_overwrite"` plus the exact captured flag string — so it cannot pass by keying
off a hardcoded fixture name. Separate tests cover the forced fallback path,
`file-fixed`, cleanup/restoration, and the artifact being runnable.

### Wave 2 REVISION 2 — after round-2 implementation-diff review (round 2 of 3)

Verbatim: `docs/plans/2026-09-26-wave2-impl-review-r2-daybreak.md`. **NOT-APPROVED**:
2 Critical, 2 High, 2 Medium, plus six test defects. Round-1 closure confirmed by the
reviewer for H1/H2/H3/M2/M3; **C1, C2, and M1 are NOT closed.** All verified on disk.

**Answered by CLASS, with the sweep and its match identity.**

**Class 1 — "the central gate only knows about file sinks" (closes C1 + M1).** The gate
tests `is_file_sink(delivery_spec.sink)`, so `SINK_ARGV` passes through to every executor,
including script-based ones that deliver over stdin (`verify_script()` never resolves the
spec; `fmtstr_write_gate` probes stdin directly at `fmtstr_techniques.py:102`). A target
exploitable over stdin would then report SUCCESS under `--input-vector argv` without ever
using argv — and a late-bound typo'd sink takes the same route, which is why M1 is not
closed either: `verify_payload` validates the sink, but script executors never enter that
method. **Sweep** (match identity: `is_file_sink(` across `supwngo/`) → 2 call sites, both
changed to "any sink that is not `SINK_STDIN`". The allowlist and the sink validation both
move into the gate, so the property is "no technique outside `FILE_DELIVERY_ALLOWLIST`
runs under ANY non-stdin vector," not "…under a file vector." M-4 is unaffected because
`variable_overwrite` is allowlisted.

**Class 2 — "the sentinel swap replaces the whole token" (closes H1).** `contracts.py:363`
is `tok.replace("{payload_file}", …)`, i.e. replacement **inside** a token is a supported
form, so `--input={payload_file}` and `--data={payload_arg}` are legal templates. Both the
verifier (`_verify_argv_sink`) and the script generator (`_render_argv_literal`) replace
the entire token when it merely *contains* the sentinel, silently discarding the
`--input=` prefix. For argv that corrupts the launch itself; for files it makes
verification pass and the saved artifact fail. **Sweep** (match identity: `sentinel in tok`
/ any whole-token substitution) → 2 sites, both changed to substitute within the token and
preserve surrounding bytes.

**Class 3 — "non-stdin artifacts are silently inert" (closes C2).** The generated argv
branch connects to `REMOTE_HOST` and never sends `PAYLOAD`; the file branch writes a local
file and then connects remotely without transferring it. Local verification passes and the
saved script sends zero bytes. Remote delivery of a file/argv vector is a genuinely
unsolved problem (it needs a transfer channel), so the honest fix is a **loud refusal in
the generated script's remote branch**, not silence.

**Class 4 — "the contract permits what the code discards" (H2).** `contracts.py:244-247`
states that `SINK_STDIN` may carry a non-empty `argv_template` and that "stdin delivery
and an argv template are orthogonal, not mutually exclusive." The stdin branch ignores
`argv_template` entirely in both the verifier and the generator. Honored rather than
rejected, because the contract already chose: empty template → `argv=None` (the
byte-identical default, unchanged), non-empty → `build_argv()`.

**Class 5 — `delivered_bytes` exists to stop exactly this reconstruction (M2).** The
generator hardcodes `PAYLOAD + b"\n"`. That is correct for the two stock executors today —
the reviewer confirms it — but `AttemptRecord.delivered_bytes` was added precisely so the
artifact would not re-derive delivery bytes by convention. Set it on success and prefer it
in the non-stdin branches. **The stdin branch must keep using `PAYLOAD` + `sendline()`**:
feeding it `delivered_bytes` (which already ends in `\n`) would make `sendline` append a
second newline and break the byte-identical pin.

**Class 6 — six tests that pass while the capability is absent.** This is the
"validation that cannot fail" class again, and it is the most valuable part of the review.
The mechanism test never *executes* the generated artifact, so C2 was completely untested
by a suite that was fully green. The identical-bytes test watches its own callback rather
than the child. Three cleanup tests pass if materialization never happened, because an
untouched original already equals the expected final bytes — an absence assertion whose
subject was never proven to exist. Each is re-specified to assert the child's own
observable effect (its flag, its output), not the harness's.

**One reviewer expectation I am NOT adopting, with the reason.** Round 1's answer (d)
asked that the payload filename be "held constant across the negative and positive runs."
That is unachievable as stated and the reviewer notes the tension itself: the negative run
uses the default vector, and `input_name` without a file vector is now a hard `ValueError`
(M3's own fix), so the name cannot be passed to the negative engine at all. Replacing it
with two controls that ARE achievable: (i) the default-vector negative, which establishes
that stdin cannot reach the gate, and (ii) a same-vector, same-filename negative whose
file carries the wrong gate value (`0xDEADBEEF`), which establishes that the win is
attributable to payload content rather than to the channel merely existing. Together these
bound the claim more tightly than a shared filename would have.

### Class 1 verification — the C1 fix shipped as an UNMEASURED CLAIM, now closed

**Measured, 2026-09-26.** After the Class 1 fix landed and the whole vector suite was
green (154 passed across five files), I red-proofed the gate by reverting only C1's
semantics:

```
-  if delivery_spec.sink != SINK_STDIN:
+  if delivery_spec.sink in (SINK_FILE_ARGV, SINK_FILE_FIXED):
```

Valid Python, every name in scope, nothing else touched — exactly the wrong-but-present
mutation the standing rule requires. **All 37 tests in the delivery file stayed GREEN.**
The C1 fix was present in the code and covered by nothing that could fail.

The reason is structural and worth naming: every one of the six mechanism solves drives
`variable_overwrite`, which is **on** `FILE_DELIVERY_ALLOWLIST`, so the gate is a no-op in
all of them. C1's defect is about techniques that are *not* on the allowlist reaching their
executor under a non-stdin vector — `fmtstr_write_gate` and `stack_shellcode` in
particular, which are script-based, never resolve the delivery spec, and could therefore
report SUCCESS over stdin under a declared argv vector. No test exercised that shape at
all.

Added `TestNonStdinVectorRefusesNonAllowlistedTechniques` (6 tests): the refusal
parametrized over **all three** non-stdin sinks, plus two positive controls — the
allowlisted pair must NOT be refused (a gate that refused everything would satisfy the
refusal assertions while destroying the feature), and a declared `stdin` vector must refuse
nothing (the regression that would matter most, since widening the gate from file-sinks to
all-non-stdin sinks is what could have caught the default path).

**Red-proof of the new gates:** the same mutation now yields **exactly 1 failure — the
`argv` case — with both file cases and both controls green.** Precisely attributable: the
mutation removes only C1's semantics and only the argv gate detects it.

**Two invalid red-proofs I discarded before this one, both mine.** (1) My first mutation
replaced the first regex match without verifying where it landed; 7 tests went red and I
could not attribute the red to the gate. (2) My second substituted `is_file_sink(...)`,
which is **no longer imported** after the Class 1 edit (it survives only in comments), so
the mutation raised `NameError` and reddened all six mechanisms uniformly — a broken
module, not a semantic revert. **A mutation that breaks import or resolution is not a
wrong-but-present mutation, and a red it produces measures nothing.** Verify the mutation
diff and that the module still imports before trusting the red.

**Residual gap, recorded rather than closed.** The embedded-token form (`--input=@@`) is
proven by (a) a unit gate asserting the child's own `cmdline` keeps the `--input=` prefix,
(b) a gate on the generated script text, and (c) my one-off end-to-end run against a
purpose-built `--input=FILE` target, which solved and whose saved artifact replayed and won.
It is **not** covered by a committed compiled fixture, because adding a 13th fixture ripples
into the foundation suite's exhaustive `EXPECTED_VERDICTS == FIXTURE_NAMES` table and would
require measuring its probe verdict. Stated as a gap, not implied to be covered.

---

## Wave 3 — answering round 3 (the last of the 3-round budget)

Review verbatim: `docs/plans/2026-09-26-wave2-impl-review-r3-daybreak.md` (NOT-APPROVED,
0 Critical, 3 High, plus 6 "tests that can pass without the named capability").
Round 3 is the final round; per the standing rule a 4th round escalates the design
rather than patching, so every class below is either **fixed** or **dispositioned with
its sweep** in this wave — nothing is carried as an unmeasured claim.

### Disposition table

| Finding | My verdict after reading the code | Action |
|---|---|---|
| H1 repeated placeholder → silently wrong artifact | **CONFIRMED, blocking** | fix F1 |
| H2 non-stdin verification vs. artifact disagree about fd 0 | **CONFIRMED as a defect, but PRE-EXISTING and family-wide, not introduced by wave 2** | gap G-W3-1 + parity test, not blocking |
| H3 file-materialization failure reported as an exploitation failure | **CONFIRMED, blocking** | fix F3 |
| 6 test-strength items | accepted in full | T1–T6 |
| (found by me, not by the review) remote refusal in the file branch runs AFTER the payload file is written | **CONFIRMED, blocking** — it leaves a winning payload file in the binary's directory, the exact hazard `_verify_file_sink`'s `finally` exists to prevent | fix F4 |
| (found by me) duplicated `# Class 5:` comment block in `templates.py`; stale "materialized later (a later wave's scope)" comment in `orchestrator.py` | cosmetic | fix F5 |

### F1 — repeated placeholders (closes H1)

`measured` — `templates.py:142` reads `prefix, suffix = tok.split(sentinel, 1)`. The
`maxsplit=1` is the whole defect: `DeliverySpec.build_argv()` substitutes with
`str.replace()` (**all** occurrences, `contracts.py:363`) and
`PipelineVerifier._verify_argv_sink` uses `tok.split(sentinel)` with **no** maxsplit
followed by `payload.join(...)` — so for a token containing the placeholder twice the
verifier launches `b"X:X"` while the generated artifact launches
`PAYLOAD + b":<leftover-uuid-hex>"`. The leftover is a *random* sentinel, so the
artifact is not merely different, it is nondeterministic.

Fix: render **every** occurrence, with the same "one definition of where the payload
goes" discipline already used for `_render_argv_literal` — split on all occurrences and
interleave `payload_expr` between the literal pieces. A token equal to the sentinel
still renders as `payload_expr` alone (no wasted `b""`).

### H2 — fd 0, and why it is not blocking

`measured` sweep — **match identity**: for every one of the four sinks, compare (a) what
`ExploitVerifier.verify_payload`'s subprocess path does to the child's stdin, (b) what
`_verify_with_pwntools` does, (c) what the generated artifact does.

- `SINK_STDIN` (**the pre-existing default, unchanged by wave 2**):
  `subprocess.run(input=payload)` → the child sees the payload **and then EOF**; the
  artifact does `io.sendline(PAYLOAD); io.interactive()` → stdin stays **open**.
- the three non-stdin sinks: `subprocess.run(input=b"")` → **immediate EOF**; the
  artifact spawns and goes straight to `io.interactive()` → stdin stays **open**.

The divergence the review names is therefore the *same* divergence the stdin default has
always had — the payload bytes differ, the fd-0 lifecycle does not. It is a pre-existing
class, inherited by the new sinks, not introduced by them. Two further facts decide the
disposition:

1. The stdin script is **pinned byte-identical** to HEAD's generator by
   `TestDefaultUnchanged::EXPECTED_STDIN_SCRIPT`. "Fixing" fd 0 for the non-stdin sinks
   alone would leave the default with the defect and make the sinks disagree with each
   other — trading one drift for another.
2. An unconditional `io.shutdown("send")` in the non-stdin branches would **break the
   canonical pipeline's primary oracle**: `PipelineVerifier.verify_script` feeds
   `echo <receipt-token>` into the artifact's *own* stdin and relies on
   `io.interactive()` forwarding it to a spawned shell to earn `SHELL_ACCESS`. Closing
   the child's stdin starves that signal.

**Option not taken:** select the artifact's fd-0 discipline from the recorded
verification level (`SHELL_ACCESS` ⇒ keep stdin open, `FLAG_CAPTURED` ⇒ shut down send),
which would reproduce whichever spawn path actually won. Rejected for this wave because
it plumbs the verification level into script generation for a defect that is not new, and
because it would still leave the stdin default on the old discipline. **What would flip
it:** a corpus or fixture target that waits for EOF on stdin before opening its declared
input — that turns the latent class into a measured loss and justifies the plumbing.

Recorded instead as **G-W3-1** (gap, not a managed risk: it is measured and named), with
a **parity test** asserting that all four sinks share one fd-0 discipline, so a future
partial fix cannot land silently.

### F3 — delivery failure must be loud (closes H3)

`measured` — `_verify_file_sink` hands `_materialize` to `ExploitVerifier` as
`pre_spawn`; `verify_payload` calls it inside its `try`, and
`except Exception as e: result.notes.append(...); return result` (verification.py:308)
converts an unwritable directory into an ordinary unsuccessful verification. The run then
reports "no combination was confirmed" — i.e. *the payload was wrong* — for a run in
which no payload was ever delivered.

Fix: materialize **once, eagerly, in `_verify_file_sink`, outside the verifier's `try`**,
before constructing `ExploitVerifier`. An `OSError` there propagates as itself. The
`pre_spawn` re-materialization stays (a first execution can truncate or unlink its own
input file, and a fallback spawn must not see the mutated file), but by then the eager
write has already proven the path writable. The `finally` cleanup must now also cover the
eager write, so a failure between the write and the verifier still restores the directory.

### F4 — remote refusal before the file write

The file-sink branch writes `payload_path` and *then* raises the remote refusal. A user
who sets `REMOTE_HOST` gets the exception **and** a winning payload file left in the
binary's directory — which is precisely what makes a later default-vector run win
spuriously. Move both branches' `REMOTE_HOST` refusal to the top of the body.

### T1–T6 — closing the "passes without the capability" set

| id | review item | change |
|---|---|---|
| T1 | C1 enumerates 4 hand-picked names | derive the parametrization from `build_default_registry().names() - FILE_DELIVERY_ALLOWLIST` so the gate cannot be hard-coded to a subset |
| T2 | positive control only exercises `variable_overwrite` | parametrize the control over **both** allowlist members |
| T3 | `delivered_bytes` asserted only for `variable_overwrite` | assert it for both stock allowlisted executors |
| T4 | remote refusals asserted by source text only | **execute** the generated script with `REMOTE_HOST`/`REMOTE_PORT` populated and assert the named `RuntimeError`, so `if REMOTE_HOST and False:` cannot pass |
| T5 | stdin real-spawn test observes only the last writer and accepts either encoding | observe **both** writers and pin the encoding |
| T6 | embedded-placeholder artifacts inspected, not run | **execute** them, including the repeated-placeholder form F1 fixes |

### Red-proof obligation for this wave

Each of F1, F3, F4 gets a mutation that is **wrong-but-present** (the module still
imports and resolves) and must turn its own test RED and nothing else:

- F1: restore `maxsplit=1`.
- F3: move the eager `_materialize()` back inside the verifier's `try`.
- F4: move the `REMOTE_HOST` refusal back below the file write.

A mutation that breaks import or name resolution measures nothing — that lesson is
already recorded above and applies here.

---

## M-1b — the challenge-alike variation benchmark (USER DIRECTIVE, 2026-09-26)

> "Make sure we not only do per target benchmark but the challenge-alike variations"

M-1a (the existing per-target corpus gate: 13/13 eligible SUCCESS at 5/5 reps with the
2 known VOID corpus faults, compared **per target**) proves nothing regressed. It cannot
prove the wave's *capability*, because **every target in `benchmark/corpus/` takes its
payload on stdin** — the input vector was never a corpus dimension. So M-1a is a
regression gate only, and a second gate is required.

### What the harness already gives us (`measured`, read from `benchmark/run_bench.py`)

- `Corpus(root=..., manifest=...)` is already parameterised, and `--corpus-root` /
  `--manifest` are already CLI options (used today by `benchmark/corpus_r2`). A third
  corpus reuses the **same** verdict machinery — same per-run secret flag
  (`mint_secret_flag`), same fail-closed `build_with_secret` provisioning, same
  independent re-execution of the generated artifact as a fresh subprocess, same
  VOID/SUCCESS/PARTIAL/FAILED ladder. That is what makes M-1b comparable to M-1a
  instead of a second, softer harness.
- `build_all.sh` already honours `SUPWNGO_BENCH_CORPUS` and already documents that an
  alternate corpus "needs its own entries" in its per-target flags `case`.

### The one harness gap (`measured`)

`run_supwngo(binary_abs, timeout, extra_args)` takes `extra_args`, but nothing in the
manifest can supply them per target — so a corpus cannot declare
`--input-vector`/`--input-name`/`--input-argv`. M-1b needs an **optional** per-target
`cli_args:` key, defaulting to empty, so `corpus.yaml` and `corpus_r2.yaml` runs stay
byte-identical.

### The matrix — vulnerability held constant, ingress varied

Each variation reuses an existing corpus target's vulnerability verbatim and changes
**only how the payload gets in**, so a per-variant comparison isolates the transport.

| slug | base vuln | ingress mechanism | declared vector |
|---|---|---|---|
| `01_win_stdin_baseline` | ret2win (corpus 15) | stdin | *(none)* — control proving the variation corpus agrees with M-1a |
| `02_win_file_argv_bare` | ret2win | `fopen(argv[1])` + `fread` | `file-argv` |
| `03_win_file_argv_flag` | ret2win | `-f FILE` | `file-argv` + `--input-argv "-f @@"` |
| `04_win_file_argv_embedded` | ret2win | `--input=FILE` | `file-argv` + `--input-argv "--input={payload_file}"` |
| `05_win_file_fixed` | ret2win | `fopen("input.dat")`, no argv | `file-fixed` |
| `06_win_argv_direct` | ret2win | `strcpy(buf, argv[1])` | `argv` |
| `07_win_line_text` | ret2win | `fgets` from the file (stops at `\n`) | `file-argv` |
| `08_varov_file_argv` | variable_overwrite gate | `fread` from `argv[1]` | `file-argv` |
| `09_negidx_file_argv` | negative-index write (corpus 14) | `fread` from `argv[1]` | `file-argv` |

### Negative controls — the matrix must be able to go RED

Per the standing rule that a custom assessment is validated **before** the tests that
trust it, the matrix ships with targets that must **not** score SUCCESS:

| slug | why it must fail | expected |
|---|---|---|
| `90_neg_argv_echo_no_open` | takes a path in `argv[1]` and never opens it — nothing the file sink writes can reach memory | FAILED under `file-argv` |
| `91_neg_config_flag_stdin_payload` | `argv` is an unrelated config flag and the payload is on stdin | SUCCESS on stdin, **FAILED** when `file-argv` is declared |

An all-SUCCESS matrix with these two present is a broken harness, not a win.

### Why M-1b runs AFTER Sprint 2′'s commit, not before

The harness's SUCCESS verdict **re-executes the generated artifact as a fresh
subprocess** and refuses to trust autopwn's self-report. Round-3 H1 (confirmed above) is
precisely a defect in the generated artifact for embedded/repeated placeholders — so
`04_win_file_argv_embedded` would under-report for a cause already known and already
being fixed in Wave 3. Measuring first would produce a number to be thrown away.

Sequence: Wave 3 fixes → red-proofs → targeted suite → full suite → **M-1a** → commit →
then M-1b as its own sprint (its own plan section, its own review round, its own branch),
because it adds a corpus, a manifest key, and builder entries.

**Status: SPECIFIED, NOT MEASURED.** Recorded here so it is a named, scheduled gate
rather than an unmeasured claim.
