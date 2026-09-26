# Class answers — Sprint 2′ foundation-layer diff review

Answers to `docs/plans/2026-09-26-foundation-diff-review-daybreak.md` (verdict
NOT-APPROVED: 1 HIGH, 3 MEDIUM, 1 LOW).

Per the standing rule, each finding is answered as a **class**, with the sweep
actually run, that sweep's **match identity** stated exactly, and the count. A class
answered instance-by-instance comes back in the next round, so where a sweep found
recurrences the review did not name, those were fixed in the same pass.

**Nothing was accepted on the reviewer's word.** Every finding was reproduced first;
the two that turned out to refute my own prior claims are recorded in REVISION 5
Correction 4 of the sprint plan, beside the claims they refute.

---

## Class 1 — Silent acceptance of an undeliverable specification (HIGH)

**Reproduced:** all five reported combinations, verbatim. The decisive one is an
unknown/typoed `sink` string: it fell through every branch and was treated as stdin,
**silently dropping the payload**. `is_file_sink("file-arg")` also returns `False`.
This is the same silent-failure class for which §3 of the plan rejected Method B — it
re-entered through the sink string instead of through `isinstance`.

**Sweep:** every branch of `build_argv()` enumerated against the cross product of
{4 valid sinks + 1 invalid} × {no template, non-placeholder template,
`{payload_file}`, `@@`, `{payload_arg}`, both kinds} × {empty, non-empty
`payload_value`} × {empty, non-empty `payload_filename`}.

**Result:** 5 silent-acceptance paths, all 5 now raise `ValueError` naming the field
and the remedy. Commit `4e65232`.

**Guarded invariant, asserted rather than assumed:** `DeliverySpec()` still returns
exactly `[binary_path]` and never raises — that is what keeps S1 additive, so every
existing spawn site retains byte-identical argv. `@@`/`{payload_file}`
interchangeability and `SINK_STDIN` with an unrelated config flag also still work.

**Consequence recorded, not deferred:** because `build_argv()` can now raise, the
wiring layer must catch `ValueError` at the central refusal gate and record it as that
technique's `failure_reason`. An operator typo in `--input-vector` must cost one
technique, not the whole engine run. Added to the plan with its own T10 case and
red-proof (commit `f982e8f`).

---

## Class 2 — Tests that cannot fail (MEDIUM)

This is the highest-value class in this sprint: three defects of this shape had already
shipped before the review (an unsolvable fixture, an always-green measurement harness,
and a set-equality gate green only because its counterexample was absent).

**Sweep A — absence assertions.** Match identity: `assert .* not in ` OR `assert not `
across `tests/test_input_vector_foundation.py`,
`tests/test_input_vector_fixture_validation.py`,
`tests/test_delivery_spec_validation.py`.

**Result: 8 hits.** 6 have paired positive controls in the same class; 1 is a
fixture-presence check (`assert not missing`) whose subject is the set difference
itself. The 8th was the tautological pair the review named — after
`assert joined == b"ab"`, the following `assert not joined.endswith(b"\n")` cannot
fail independently. **It had not been fixed by the earlier pass**, so it is a
recurrence, and is now replaced with cases the join tests do not subsume: a newline
that is part of the payload must survive byte-exact, and no parts must yield `b""`.

**Sweep B — expectation/fixture parity.** `EXPECTED_VERDICTS`' keys were never asserted
equal to `FIXTURE_NAMES`, so a fixture added to one list alone would silently receive
no verdict test. This is the *same shape* as Correction 3's defect (a gate green by
omission), at a different site. Now asserted equal.

**Sweep C — structural gates built on name blocklists.** `TestProbeIsAdvisoryOnly`
checked that three specific parameter names were absent, so adding a `state=None`
parameter and mutating it would have kept the gate green — the reviewer's stated
bypass. Replaced with an assertion on the **full parameter set**, so any new parameter
fails. Verified by adding `state=None` and watching it fail.

Commits `1b0b8a8`, `140f439`.

---

## Class 3 — Confounded comparison: varying two things at once (MEDIUM)

**Reproduced.** Stages 1–3 used three *different* basenames (`missing_input`,
`existing_small`, `existing_large`), so each stage varied the filename alongside the
variable it meant to isolate. Measured consequence: a target that only
`printf`s `argv[1]` and never opens it differed at every stage and was classified
`file-candidate` with `stage3_basis='output'`.

**Fix:** one path, `probe_input<ext>`, moved through absent → 32 bytes → 4096 bytes.

**Measured effect (my own run, not the delegate's):**

| fixture | before | after |
|---|---|---|
| `neg_argv_echo_no_open` | `file-candidate` / `output` | **`argv-only-not-opened`** |
| `file_vector_gate` (genuine sink) | `file-candidate` / `output` | unchanged |
| `mech_open_read_argv` (genuine sink) | `file-candidate` / `output` | unchanged |
| `mech_line_text` (genuine sink) | `file-candidate` / `timeout` | unchanged |
| `mech_flag_style`, `mech_fixed_path` (documented safe FNs) | `stdin` | unchanged |

So an entire false-positive class is gone with no regression on any genuine sink. That
is the one unambiguous capability improvement in this round.

**The second half of this finding was also correct, and refutes my own claim.** The
reviewer argued that even with the pathname fixed, "a strong basis implies a genuine
file sink" is unsupported by a fixture corpus. I built the counterexample:
`neg_fast_cfg_stdin_payload` opens a config file, prints a size-dependent line, takes
its payload from stdin, and reports `basis='output'`. **The claim is false.**
`stage3_basis` is diagnostic only, with no trustworthy direction. The test asserting
the implication was replaced, not narrowed, and both fixtures are permanent gates.

---

## Class 4 — Overloaded sentinel / mislabelled cause (MEDIUM)

**Reproduced.** `_run_tolerant()` mapped both `TimeoutExpired` and any `OSError` to one
`None` sentinel, so stage 3 reported `stage3_basis="timeout"` for a process that never
started.

**Sweep.** Match identity: `except (` OR `except OSError` OR `except subprocess`
across `supwngo/analysis/*.py`.

**Result: 19 hits.** 18 are unrelated to this sprint (`decompile`, `dynamic`, `source`,
`patch_diff`, `one_gadget`, `dataflow`, `imports` — each catching a timeout for its own
tool invocation, with no cause-dependent label downstream). The 1 that mattered was a
**recurrence the review did not name**: stage 0 caught `OSError` and `TimeoutExpired`
together and filed both under `evidence["launch_error"]`, asserting a process never
started when it may have started and hung.

Fixed by splitting the *audit record* (`stage0_failure_cause`) while deliberately
keeping the *verdict* shared — neither cause allows a later difference to be
attributed, so changing classification would have been scope creep dressed as a fix.

Also fixed: extension discovery used `_run()`, contradicting the module's documented
rule that every stage after the determinism check treats a timeout as behavioral
evidence.

---

## Class 5 — A claim stronger than what the code establishes (LOW)

All three sub-items confirmed by reading the implementation against its docstring:

- Stages 1 and 2 were documented as comparing *output* but compare `(returncode,
  output)`.
- `"argv-only-not-opened"` does not prove the file was never opened — a target may
  open, read, and ignore it.
- `"argv-only-config"` does not prove configuration use — `stat()`, `access()`, or
  open-then-close are indistinguishable, as is any effect invisible in the first
  `TRUNCATE_BYTES` of output.

**Sweep.** Match identity: `proves|guarantees|implies|always|never|every|cannot` in
`vector_probe.py`. 20 hits, reviewed individually; the docstring now states what each
verdict does **not** prove, and names the measured counterexample for
`"file-candidate"`.

This class is the through-line of the whole round. Three of my own claims failed it,
each with the same structure: a property verified across the fixtures that happened to
exist, then stated as a general implication. **The fixtures were the sample, not the
domain.** The generalizable rule, now written into the plan: a claim of the form
"X implies Y" cannot be established by a corpus built to exhibit X — it requires a
deliberate attempt to construct `X ∧ ¬Y`.

---

## Not a finding

`materialize()` was reviewed and found correct (exact byte join). Confirmed.

## Reachability, and what this round does NOT claim

**Measured** — match identity: `DeliverySpec` and `classify_input_vector|vector_probe`
across all `*.py` excluding `tests/` and each symbol's own defining file. **Zero
production consumers**; every non-test hit is a docstring or comment mention.

The foundation layer is therefore still unwired, and this round moves **no target from
FAIL to SUCCESS**. Claiming otherwise would be the overclaim this document's Class 5 is
about. What it delivers is a transport contract that now fails loudly instead of
silently, a probe with one false-positive class eliminated and the rest measured and
pinned, and four gates that can no longer pass vacuously. The target-moving work is the
wiring layer (S3–S6).
