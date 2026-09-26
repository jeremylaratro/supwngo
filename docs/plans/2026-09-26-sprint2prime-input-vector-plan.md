# Sprint 2′ — Input-Vector Abstraction (argv / file channel)

Phase 5 artifact. Closes **G-2a** (argv/file targets structurally unreachable) and
**B-2** (vector classifier inverted). Gap analysis:
`docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md`.

**Provenance labels**: `measured` (I ran it this session), `recorded` (prior
artifact, cited), `inferred` (reasoned, not observed).

**Status: PLANNED — not started. No code is written until the peer-review gate
below is green.**

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

## 2. What this sprint deliberately does NOT do

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

- **+** The channel is explicit, inspectable, loggable, and serializable into the
  receipt — so a SUCCESS records *how* it was delivered, which is provenance the
  harness can audit.
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

Because of B-2, the signal is **behavioral**, not import-based.

**`probe_argv_vector(binary_path, *, loader_cmd, timeout)`** — run the target
twice with stdin at `/dev/null`: once with no argv, once with a single throwaway
path. If `stdout+stderr` differs, the target consumes `argv`.

Measured discrimination (match identity: bundled loader
`glibc/ld-*.so --library-path glibc`, stdin `/dev/null`, first 300 bytes compared):

| target | differs? | outcome |
|---|---|---|
| ancient_interface | False | correct negative |
| auth-or-out | False | correct negative |
| rocket_blaster_xxx | False | correct negative |
| **snowscan** | **True** | correct positive |
| bon-nie-appetit | inconclusive | bundled `ld-*.so` lacks `+x` |
| sabotage | inconclusive | same |

**0 false positives / 1 true positive / 2 inconclusive on 6.** The inconclusive
rows are a fixture-permission artifact; committed fixtures are not `chmod`ed to
improve the number.

Two safety properties, both of which must hold and both of which get a test:

1. **Positive evidence only.** The vector flips to file **only** when the probe
   returns True. A probe that errors, times out, or is inconclusive leaves the
   spec at `SINK_STDIN`. A broken probe therefore degrades to today's behavior.
2. **Filename extension is derived from the target's own output**, not guessed —
   the refusal string names the required extension. First cut: scan the no-argv
   and bogus-argv output for a `.<ext>` token and use it; fall back to `.bin`.

**Known limitation, stated not hidden:** a target that reads `argv` but prints
*identical* output either way is a false negative. It degrades to stdin — i.e. to
today's behavior — so it cannot regress anything. Recorded as a limitation, not
a managed risk.

## 5. Sub-components

| # | Files | Change | Contract affected | Failure mode introduced |
|---|---|---|---|---|
| S1 | `pipeline/contracts.py` | `DeliverySpec` + `SINK_STDIN`/`SINK_FILE`; `spec.build_argv(payload_path)` | new type, additive | a wrong default silently changes every spawn → pinned by S1 test |
| S2 | `analysis/vector_probe.py` *(new)* | `probe_argv_vector()`, loader discovery, extension extraction | new module | false positive flips a working target to file → guarded by positive-evidence-only rule + S2 negative-control test |
| S3 | `pipeline/delivery.py` | `deliver_parts(..., spec=None)`; write payload to a temp file inside `cwd` when `SINK_FILE`; build argv | `deliver_parts` gains a kwarg, default preserves behavior | temp file leaks between attempts → unique per-attempt name, cleaned in `finally` |
| S4 | `exploit/verification.py` (`:241`, `:281`) | thread spec through both spawn paths | `ExploitVerifier.__init__` gains optional `spec` | the two paths disagree → S4 test asserts both honor the same spec |
| S5 | `pipeline/verifier.py` | `PipelineVerifier` carries the spec and passes it down | constructor gains optional `spec` | none new (pass-through) |
| S6 | `script_builder.py:98`, `templates.py:74`,`:176` | generated `start()` writes the payload file and passes argv | **generated artifact shape** | artifact diverges from the verified run → S6 test asserts the artifact reproduces it |
| S7 | `analysis/static.py:76` | delete the unreachable `"argv"` entry; comment that `file input` is not a vector oracle (cite B-2) | removes dead code | none; behavior-neutral by inspection |
| S8 | prologue (`profile_stage.py`) | call the probe once, store spec on `ExploitContext` | one extra probe run per pipeline invocation | added latency → bounded by 2 runs × existing timeout |

Ordering: S1 → S2 → S3/S4/S5 → S6 → S7/S8. S6 is **not optional**: without it a
verified SUCCESS would not reproduce in the artifact handed to the user.

## 6. Test plan — written before execution

New file `tests/test_input_vector_delivery.py`.

**Regression surface (must stay green, same command before and after):**
`pytest tests/ -q`. Known pre-existing failures, excluded **by name**, not
tolerated silently: `test_i2_attempt_duration` (I-1), `test_solve_command::
test_guided_fallback_resumes_to_success_with_supplied_offset` (I-2). Counts are
read off the output by me, never relayed from a delegate.

| gate | asserts | how it is proven able to go RED |
|---|---|---|
| T1 default is byte-identical | `DeliverySpec()` → `build_argv()` yields exactly `[binary]` | mutate default `sink` to `SINK_FILE`; T1 must fail |
| T2 spec → argv is correct | `{payload_file}` substituted at the right position | pass a spec with the placeholder absent; assert it raises, not silently drops |
| T3 **new capability** | purpose-built argv/file fixture (reads `argv[1]`, overflows from file contents) goes from FAILED → SUCCESS | run the same fixture with `spec=None`; **must be FAILED**. This is the paired red-proof: it shows the fixture is unsolvable without the change, so T3's green is attributable |
| T4 probe true positive | probe returns True on the argv fixture | mutate fixture to ignore `argv`; probe must return False |
| T5 probe negative control | probe returns False on a stdin-only fixture, and the spec stays `SINK_STDIN` | mutate probe to return True unconditionally; T5 must fail |
| T6 artifact reproduces | generated script for the argv fixture, run as a subprocess, captures the flag | strip the argv from the generated `start()`; T6 must fail |
| T7 no absence-assertion stands alone | where T5 asserts "stdin path unchanged", also assert the stdin fixture **still solves** (subject exists) | delete the stdin fixture; T7 must error, not pass vacuously |
| T8 temp file hygiene | no payload file survives a failed attempt | remove the `finally` cleanup; T8 must fail |

Every gate has **three** states — pass / fail / inconclusive; a probe that cannot
run reports inconclusive and the test says so rather than passing.

`snowscan` gets a **progress** assertion only, not a solve: with the channel in
place it must advance past gate 1 (extension) and gate 2 (open) — i.e. its output
must change from `No file provided as an argument.` to a *later* message in the
B-3 ladder. That is an honest partial, labeled as such.

## 7. Benefit metric (Phase 8) — pre-registered

| ID | metric | harness | baseline (pre-change) | provenance |
|---|---|---|---|---|
| **M-4** | argv/file fixture solved by the canonical pipeline | `tests/test_input_vector_delivery.py::T3` | **0 / 1 — structurally impossible**; no spawn site can pass argv (5 sites read, §1) | `measured` |
| **M-5** | `snowscan` gate depth reached | direct run, output compared to the B-3 ladder | **gate 0** — never passes `No file provided as an argument.` | `measured` |
| **M-6** | no regression on the corpus | `benchmark/run_bench.py --jobs 4` | **13/13 SUCCESS, 5/5 reliable**, run `20260926-164613Z` on `main` @ `311ff25`; 2 VOID (`11_heap_uaf_leak` = `corpus_missing_liveness_gate`, `13_off_by_one` = `corpus_trivially_solvable`) | `measured` |
| **M-7** | HTB stdin targets unchanged | forced-strategy matrix, per target | 4/6 probe-negative → must stay on stdin | `measured` |

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
