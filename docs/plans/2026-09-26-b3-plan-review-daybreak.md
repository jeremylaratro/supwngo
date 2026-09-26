# Peer review — B-3 container registry plan (Revision 0)

- **Date:** 2026-09-26
- **Reviewer:** Daybreak Blue (`gpt-daybreak-blue-latest`, `model_reasoning_effort=xhigh`, `--sandbox read-only`)
- **Method:** non-interactive `codex exec`, file handoff, polled the output file until stable (0 B for 180 s, then 8510 B)
- **Verdict:** NOT-APPROVED — 2 Critical, 5 High, 3 Medium
- **Disposition:** 8 accepted, 1 refuted by measurement (Critical 1), 1 already corrected elsewhere. See REVISION 1 of the plan.

## Verbatim review

NOT-APPROVED

The BMP path does not currently demonstrate that payload bytes reach the scan loop. Both primary metrics can pass while the actual container capability is absent.

## Critical

1. **C2 places the payload outside the region the scan loop is expected to consume.**

A conventional BMP row loop reads exactly the declared pixel array: `row_stride × height` bytes beginning at the pixel offset. Bytes appended afterward may be accepted by the file parser yet never examined by the row loop. The measured “8 KB ignored” result is evidence for acceptance, not reachability.

**Failure scenario:** The pipeline emits a valid constant 20×20/8bpp BMP followed by 8 KB of payload. `snowscan` prints all 20 PASS lines and exits successfully, so T-C6 and M-5′ pass, but none of the payload influences or is read by the row loop.

The first check should be semantic read tracing:

- Put distinct sentinels in the first pixel row, last pixel row, and trailer.
- Inspect source/disassembly or instrument the scan loop to record the addresses it consumes.
- Do not treat OS-level `read()` coverage as proof: buffered I/O could load the trailer without the scan loop using it.

If only the declared 20×20 pixel array is consumed, embed payload there. For uncompressed 20×20/8bpp BMP, that likely means a capacity of 400 bytes, which must be exposed and enforced. Payloads larger than that must be rejected or use another accepted carrier.

2. **T-C6 does not assert what its description claims.**

The test observes “loop reached with a pipeline-generated payload,” not “payload bytes reached by the loop.” The proposed red-proof only shows that an unwrapped file fails the BMP signature gate.

**Failure scenario:** Replace the actual payload with an unused trailer containing random bytes. The valid BMP prefix still produces `[01]` through `[20]`; T-C6 remains green even though the payload is unreachable.

T-C6 needs a nonempty unique sentinel plus evidence that the loop consumes that sentinel. Otherwise rename the test and M-5′ to “valid BMP reaches scan loop” and do not claim payload landing.

## High

3. **M-8 measures parser acceptance, not payload carriage.**

Pillow opening a BMP and `wave.open()` opening a WAV prove only that enough structure was recognized. They do not establish requirement §2(b): that the format consumer reads the payload.

**Failure scenario:** Both writers emit a valid empty container and append the supplied payload as an ignored trailer. Both independent parsers open the files, so M-8 reports two supported formats, even though neither consumer exposes a payload byte.

Require an independent round trip:

- BMP: recover the payload from decoded pixel indices and compare it byte-for-byte.
- WAV: call `readframes()` and compare the returned sample bytes.
- Target: separately prove the scan loop consumes the designated BMP bytes.

T-C2’s “payload appears at expected offset” is also insufficient when that offset comes from the writer’s own layout assumptions.

4. **`finalize(buf) -> bytes` is sufficient for PNG only under an unstated invariant.**

PNG does not inherently require external per-chunk state. A whole-buffer finalizer can iterate over correctly delimited chunks and recompute each CRC from `chunk_type + chunk_data`. The necessary state is encoded in the buffer.

However, this only works if `wrap()` has already written correct chunk lengths. If `finalize()` is expected to repair placeholder lengths as well, arbitrary bytes do not necessarily reveal the intended chunk boundaries.

**Failure scenario:** `wrap()` leaves an IDAT length of zero before arbitrary payload data. The payload contains bytes resembling another chunk header or `IEND`. From the buffer alone, `finalize()` cannot unambiguously determine where IDAT was intended to end.

Specify this invariant:

> `wrap()` must produce a structurally parseable buffer with correct boundaries and lengths; `finalize()` may update integrity fields derived from those boundaries.

Under that contract, PNG needs no interface change for non-streaming generation. RIFF tests do not prove the invariant, however.

5. **The production API does not guarantee finalization occurs.**

The interface exposes both `wrap()` and `finalize()`, while C4 merely says materialization “wraps” the payload. There is no single public operation guaranteed to perform both stages.

**Failure scenario:** T-C3 tests `finalize(wrap(payload))`, but `materialize()` calls only `wrap(payload)`. Unit tests pass while production WAV files contain stale lengths. T-C5 can also pass if its “wrapped bytes” expectation is the same unfinalized result.

Expose one atomic operation such as `encode(payload) -> finalized bytes`, or make public `wrap()` perform placement and finalization while keeping the stages private.

6. **The WAV red-proof assumes `wave.open()` is a strict length validator.**

It is not safe to assume that stale RIFF or `data` sizes make opening fail. Readers commonly accept understated sizes as shorter chunks, ignore trailers, or defer truncation detection until frames are read.

**Failure scenario:** The stale header declares a zero-length `data` chunk followed by payload bytes. `wave.open()` succeeds and reports zero frames, silently ignoring the payload.

Test exact extracted frames, declared frame count, RIFF length, and data length. Include wrong-but-present smaller and larger length mutations. Also cover odd payload lengths: the `data` size excludes the RIFF pad byte, while the outer RIFF size includes it.

7. **C0 measures a one-dimensional slice while calling it the accepted set.**

The accepted predicate is at least `bit depth × geometry`; the known 20×20/24bpp rejection already proves geometry alone is insufficient.

**Failure scenario:** The recorded data says 20×20 is accepted because the sweep only used 8bpp. A later caller or report generalizes that geometry result to 24bpp and receives the same misleading resolution rejection.

There are two valid choices:

- If this sprint supports only fixed 8bpp BMP, rename C0 to “accepted 8bpp geometry slice,” explicitly lock the implementation to 8bpp, and retain 20×20/24bpp as a negative control.
- If it claims to record the target’s accepted set, sweep a depth-by-geometry matrix.

An 8bpp-only sweep is sufficient to choose a fixed 8bpp template, but not to characterize the accepted set.

## Medium

8. **Non-file transport behavior is incomplete and potentially silent.**

C4 mentions only stdin as a negative case, although direct argv is also not a file sink. It also does not say whether `container=bmp` on an incompatible transport is rejected or silently ignored.

**Failure scenario:** A user selects `--container bmp` with an argv or stdin delivery spec. The option is ignored, raw bytes are delivered, and the target rejects them at the format gate even though the command claimed to request BMP wrapping.

Given the existing `build_argv()` precedent, incompatible container/transport combinations should raise `ValueError`. Test all four transports: both file transports succeed; stdin and direct argv reject the combination.

9. **“The per-row scan loop is the write primitive” is presented as measured fact without supporting evidence.**

One output line per row establishes that a row loop runs. It does not establish that the loop performs the vulnerable write.

**Failure scenario:** The loop safely validates pixels and prints PASS, while the vulnerable copy occurs later or in a different decoder path. The plan reaches the loop and then incorrectly describes that as reaching the write primitive.

Label this as inferred until data flow or instrumentation identifies the vulnerable write.

10. **The plan’s universal red-proof rule is violated by T-C5.**

T-C5 has no red-proof despite the plan requiring one for every gate.

**Failure scenario:** Materialization writes raw payload bytes instead of the container, while the test’s expected value is obtained through the same bypassed path. The test remains green.

Use a wrong-but-present mutation such as bypassing wrapping only in `materialize()` and require T-C5 to fail against independently generated finalized container bytes.

The minimum approval changes are: prove or abandon trailer reachability, embed and independently recover payload bytes from consumer-read regions, make finalization atomic, and rewrite M-5′/M-8 so a valid but payload-blind container cannot satisfy them.