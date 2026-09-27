# Peer review — 2026-09-26-b3-plan-review-r2-daybreak

Model: Daybreak Blue (xhigh). Date: 2026-09-26. Non-interactive file handoff.

## Verbatim review

## Critical

1. **R2.1 remains payload-blind: its gates do not prove that the supplied trailer bytes are present or that those bytes reach unsafe code.**

   **Failure scenario:** For a 1,200-byte payload, an encoder writes the first 400 bytes into pixels, discards the remaining 800 bytes, and appends a constant 8 KB zero trailer. Pillow recovers the expected 400-byte prefix and the target crashes ≥5/20, so every stated proof passes although most of the payload was never encoded.

   **Fix:** Independently extract and compare the complete payload, including the trailer and its length. Separately establish trailer-byte dataflow with instrumentation or a canary visible in target memory/core state. If only trailer length is known to trigger the crash, narrow the claim to “parser-visible carriage plus trailer-triggered reachability,” not “the consumer reads the payload.”

2. **The “unbounded trailer” contract is unsupported by a gate that measures one selected trailer length.**

   **Failure scenario:** A 401-byte payload produces a one-byte trailer under the stated mapping, which behaves like the known non-crashing small trailers. A much larger payload produces a size never tested; non-monotonicity means the selected size’s result cannot be generalized. Both are nevertheless reported as having reachability.

   **Fix:** Define a fixed tested trailer extent, pad shorter tails, publish a maximum supported payload size, and reject or downgrade reachability beyond it. Alternatively, define and independently confirm tested size buckets. Do not call the capacity unbounded; BMP fields and the measured envelope are bounded regardless.

## High

3. **The advertised three-state rule is not mutually exclusive.**

   **Failure scenario:** With test `0/20` and control `1/20`, the table says both `FAIL` because the test is zero and `INCONCLUSIVE` because the control crashed. Different implementations can report different outcomes from identical data.

   **Fix:** Give control contamination precedence: control ≥1/20 → `INCONCLUSIVE`; otherwise test ≥5 → `PASS`, test 1–4 → `INCONCLUSIVE`, and test 0 → `FAIL`.

4. **C0 performs selection, but the plan does not require an independent confirmatory T-C6′ run.**

   **Failure scenario:** One of five ladder points happens to score exactly 5/20 and is selected; the same measurements are cited as T-C6′. The gate passes by construction. Moreover, 5/20 versus 0/20 is only barely significant under an uncorrected two-sided Fisher test, before ladder selection or optional stopping.

   **Fix:** Treat C0 strictly as discovery. Run T-C6′ afterward with fresh repetitions at the fixed selected size, randomized/interleaved arms, defined process resets, and a prespecified statistical comparison or confidence-separation rule. Explicitly prohibit reusing C0 observations.

5. **A run ID and date do not bind a recorded gate to the untracked target or generated inputs.**

   **Failure scenario:** `snowscan` is replaced at the same path, or the BMP/header construction changes, while Phase 8 still cites the old run ID. Nothing establishes which binary and input bytes produced the recorded crashes.

   **Fix:** Record immutable hashes for the binary, every tested envelope, and the runner revision, plus commands, environment, timeout policy, per-repetition signal/exit status, and raw results. The reachability claim should fail closed when that evidence bundle is absent or mismatched.

## Medium

6. **A sparse non-monotonic ladder cannot identify a “threshold” or the true smallest crashing size.**

   **Failure scenario:** A 2,048-byte trailer crashes reliably while the sampled 1,024- and 4,096-byte points do not. C0 reports “no threshold in range,” despite an unsampled working size. A sampled size scoring 4/20 may likewise have a higher true crash probability than the next size scoring 5/20.

   **Fix:** Report only “smallest observed passing ladder point” or “no sampled point passed.” If an actual threshold is required, first justify monotonicity or use a denser/adaptive design with independent confirmation.

7. **The “byte-identical 0-byte-trailer envelope” control is impossible as written and leaves the experimental delta undefined.**

   **Failure scenario:** If `bfSize` is recomputed, the test and control differ in both the header and appended bytes; a crash caused by the declared size is misreported as evidence that trailer bytes were consumed. If `bfSize` is held constant, the control is a truncated envelope with a different validity property.

   **Fix:** Specify the exact byte-level differences, including all BMP size fields, and call the files prefix-identical where appropriate. Use additional matched-length/content controls or instrumentation before attributing the crash to payload-byte consumption.

Demoting target-dependent checks to recorded manual measurements is reasonable, but only with immutable evidence and an explicit acceptance rule preventing a skipped test from supporting a reachability claim. The present two-region construction and gate design still allow a payload-blind implementation to satisfy the plan.

**VERDICT: NOT-APPROVED**