# Sprint B-3 — Container registry (structured-format payload envelopes)

Phase 5 artifact. Closes **B-3** (a target that validates its input's *format*
rejects every payload the pipeline can build, before the vulnerability is reachable).

Gap analysis: `docs/plans/2026-09-26-legacy-to-canonical-gap-analysis.md` (B-3, and
its ADDENDUM).
Research: `docs/research/2026-09-26-snowscan-bmp-format-gate.md` — all format facts
below are `measured` there unless labelled otherwise.
Depends on: Sprint 2′ wiring layer (a file-vector payload must be deliverable before a
*well-formed* file-vector payload is worth building). `DeliverySpec.container` already
exists as a reserved, unused field for exactly this hook.

**Provenance labels**: `measured` (ran it), `recorded` (prior artifact, cited),
`inferred` (reasoned, not observed).

---

## 1. Problem restated

A payload can be delivered to a file-vector target and still never reach the
vulnerability, because the target validates structure first. `snowscan` stacks four
gates (`measured`):

1. `.bmp` extension — checked before the file is opened.
2. The file opens.
3. File signature (`BM`).
4. Bitmap geometry — and the real predicate is **narrower than the advertised one**.

Gate 4 is where the naive assumption fails. The error text advertises
`20x20 to 30x30`, but `30×30/8bpp` is **rejected** and `20×20/24bpp` is **rejected**
with the same *resolution* message. Bit depth is load-bearing and the error text never
mentions it. Only `20×20/8bpp` is confirmed accepted.

**Two facts make this tractable rather than a research project:**

- `20×20/8bpp` is **fully accepted** — `[01] : PASS` … `[20] : PASS`, `rc=0`. So a
  valid envelope exists and is small.
- **8 KB appended after the pixel array is ignored.** The parser does not require the
  file length to match the declared image size, so there is payload room that costs
  nothing structurally.

And one fact bounds the exploit surface: the scan loop emits one line per row, so the
**per-row scan loop is the write primitive**, not the header parse.

## 2. Scope

**In scope.** A pluggable container registry: given payload bytes and a format name,
produce a byte string that (a) satisfies that format's validator and (b) carries the
payload at a position the format's own consumer will read. Two formats implemented, so
the abstraction is exercised rather than asserted. Wired to `DeliverySpec.container`.

**Explicitly out of scope.**
- **Solving `snowscan` is NOT the exit criterion.** Passing the format gates and
  landing bytes in the scan loop is. Whether the overflow is then exploitable by an
  existing technique is a separate question, and claiming the target here would repeat
  this effort's characteristic overclaim.
- Image *content* fidelity. The envelope must be *valid*, not meaningful.
- Formats with compression (JPEG, deflate-compressed PNG scanlines).
- Tool hardening; deliberate constants (format magic numbers, header templates) are
  **features**.

## 3. Method — two candidates weighed

### Method A (chosen): declarative envelope templates + a finalize hook

A registry maps a format name to an object exposing:

```
name            -> "bmp"
extension       -> ".bmp"
wrap(payload)   -> bytes     # build header(s) + place payload
finalize(buf)   -> bytes     # fix up integrity fields AFTER placement
capacity()      -> int|None  # max payload, or None for unbounded
```

`wrap` builds a known-good header from a template and appends/embeds the payload;
`finalize` recomputes any field whose value depends on the payload (chunk lengths,
checksums). The split is the whole point: **it is what makes the interface survive a
format whose validity depends on its own payload.**

*Why chosen:* the `finalize` step is the only part of container handling that is
genuinely format-specific and hard, so isolating it is what proves the abstraction.
Templates keep BMP near-trivial (a fixed 20×20/8bpp header is a constant) while
leaving room for formats that cannot be a constant.

### Method B (rejected): a single parameterized header builder

One function with format flags (`width`, `height`, `bpp`, `magic`). Rejected: it works
only while every format is "fixed header + raw payload region". It has no place to put
a checksum or a length field that depends on the payload, so the first format needing
one forces a rewrite — and the user's requirement that two formats be demonstrated
exists specifically to catch this shape. It is also the shape that would let a
BMP-only abstraction masquerade as general.

**What would flip the decision back to B:** if the second format also turned out to
need no post-placement fixup, `finalize` would be dead weight and A would be
over-built. The second format is therefore chosen to *require* a fixup (§4).

## 4. Format choice — and the option not taken

| format | validity depends on payload? | fixup needed | corpus target |
|---|---|---|---|
| **BMP** (8bpp, square) | no — trailing bytes ignored | none | **`snowscan`** (real) |
| **WAV/RIFF** (chosen 2nd) | **yes** — RIFF size and `data` chunk size must agree with actual length | **length fields** | purpose-built fixture |

WAV is chosen as the second format because BMP alone cannot exercise `finalize` at all
(its trailing bytes are ignored, so nothing is recomputed). RIFF's two nested length
fields force the hook to exist and be correct, and a wrong length is *observable* —
which makes it testable rather than decorative.

**Option not taken: PNG.** PNG would be the stronger generality proof, because its
chunk CRC32s mean an incorrect `finalize` is rejected outright rather than merely
malformed. It is deferred because no target in the corpus needs it, and adding a
checksummed format is a larger change than this sprint can hold while staying
revertable. **What would flip it:** any target requiring a checksummed container, or
`finalize` turning out to need format-specific state that RIFF's length fields do not
reveal. The `finalize(buf) -> bytes` signature is chosen so PNG fits without an
interface change — that is the claim a PNG spike would test, and it is `inferred`,
not measured.

## 5. Sub-components

| # | files | change | failure mode introduced |
|---|---|---|---|
| C0 | *(measurement only)* | **Sweep the accepted set before writing any template.** For 8bpp, sweep square dimensions 18–32 and record accept/reject per case. The research doc explicitly warns against hardcoding `20×20` until this is swept | a template pinned to an unverified dimension → the gate passes in tests and fails on the target |
| C1 | `exploit/pipeline/containers.py` *(new)* | the registry + the interface of §3; `get_container(name)`; a clear error naming valid names | a silently-unknown name falls back to raw bytes → must raise, per the `build_argv` precedent |
| C2 | `containers.py` | BMP envelope: header template from C0's measured accepted geometry, payload appended after the pixel array | payload placed where the parser ignores it *and* the scan loop never reads it → C6 must assert the bytes are reached, not merely accepted |
| C3 | `containers.py` | WAV envelope + `finalize` recomputing both RIFF and `data` lengths | a length field left stale → T-C3 asserts a *parser* accepts it, not just that bytes were written |
| C4 | `contracts.py` | `DeliverySpec.container` stops being reserved: when set, the payload is wrapped before materialization. `materialize()` is the single choke point | wrapping applied twice, or applied to a stdin sink → assert wrapping happens exactly once and only for file sinks |
| C5 | CLI + engine option | `--container bmp|wav|none`, defaulting to `none` | a default other than `none` would change every existing spawn → default asserted |

## 6. Test plan (written before execution)

Every gate below must be proven able to go **RED** by mutating the subject to
**wrong-but-present**, not merely absent — the failure mode this effort has hit
repeatedly.

| id | asserts | red-proof |
|---|---|---|
| T-C0 | the swept accepted-dimension set is recorded as data, and the BMP template's geometry is a member of it | change the template geometry to a swept-rejected value → must fail |
| T-C1 | an unknown container name raises, naming valid choices; **paired control**: a known name does not raise | make the unknown case fall through to raw bytes → must fail |
| T-C2 | the BMP envelope is accepted by a real BMP parser (Pillow, or the measured target behavior), **and** the payload bytes appear at the expected offset | corrupt the signature → parser rejects; move the payload → offset assertion fails |
| T-C3 | the WAV envelope's two length fields equal the actual byte counts, **and** Python's stdlib `wave` module opens it | skip `finalize` → the stale length must make `wave` fail. This is the gate that proves `finalize` is load-bearing rather than decorative |
| T-C4 | `container=""` produces byte-identical output to today; a set container wraps exactly once; a stdin sink never wraps | apply wrapping twice → byte-length assertion fails |
| T-C5 | container payload survives the Sprint 2′ file-delivery path end to end (bytes on disk == wrapped bytes) | — |
| T-C6 | on `snowscan`, the four format gates pass and execution **reaches the per-row scan loop** (observed as `[01] : PASS` …) with a pipeline-generated payload | feed an unwrapped payload → must be rejected at the signature gate |

Regression: the full suite (current baseline **1174 passed, 14 skipped, 14
deselected**) and the benchmark compared **per target** against 13/13 eligible SUCCESS
at 5/5 reps with the 2 known VOID corpus faults.

## 7. Benefit metric (Phase 8), baseline measured now

| metric | baseline | target | provenance of baseline |
|---|---|---|---|
| **M-5′** | `snowscan` format gates passed by a pipeline-generated payload: **0 of 4** | **4 of 4**, reaching the scan loop | `measured` (research doc: every pipeline-constructible payload is rejected at the extension or signature gate) |
| **M-8** | container formats supported: **0** | **2**, each validated by an *independent* parser (Pillow / stdlib `wave`), not by our own writer | `measured` (no registry exists) |
| **M-9** | targets moved FAIL→SUCCESS | — | **explicitly not claimed**; see §2 |

M-8's "independent parser" clause is deliberate: a format writer validated only by its
own reader proves nothing, which is the same defect class as a fixture that cannot
fail.

## 8. Rollback

C1–C3 are a new module; C4/C5 are guarded by a `container` field that defaults to
empty. Reverting is deleting `containers.py` and the two guarded call sites; with
`container=""` the system is byte-identical to Sprint 2′'s end state, which T-C4
asserts directly.

## 9. Review gate

Peer review at the same tier before implementation, per the standing rule, with
tool-hardening and constant-table findings declared out of scope in the prompt. The
specific things to put in front of the reviewer, because they are where this plan is
most likely wrong:

1. Is `finalize` genuinely sufficient for a checksummed format, or does PNG need
   per-chunk state the signature cannot carry? (The §4 claim is `inferred`.)
2. Is appending after the pixel array actually reachable by the scan loop, or is it
   accepted-but-never-read — which would make T-C6 unsatisfiable and the whole BMP
   path useless?
3. Does C0's sweep need bit depths other than 8, given that depth is load-bearing and
   the error text hides it?

---

# REVISION 1 — after peer review (NOT-APPROVED) and a decisive re-measurement

Review: `docs/plans/2026-09-26-b3-plan-review-daybreak.md` (verdict NOT-APPROVED;
2 Critical, 5 High, 3 Medium). Eight findings **accepted**, one **refuted by
measurement**, one already corrected elsewhere. Revision 1 governs where it disagrees
with the text above; the original is retained so corrections sit beside it.

## R1.1 — Critical finding 1 is REFUTED by measurement

The review's headline objection was that BMP trailer bytes may be *accepted but never
read*, making T-C6 unsatisfiable and the whole BMP path pointless; it recommended
embedding inside the 400-byte pixel array instead. **That was the right question and
the wrong answer.** `measured`, 20 reps per case, 20×20/8bpp envelope:

| trailer | crashes | return codes |
|---|---|---|
| 0 bytes | 0 / 20 | `[0]` |
| 64 bytes | 0 / 20 | `[0]` |
| 8192 bytes | **8 / 20** | `[-11, 0]` — **SIGSEGV** |

The trailer is read and **overflows something**. Reachability is proven by crash, which
is stronger evidence than the sentinel tracing the review proposed. The pixel-array
recommendation is therefore not adopted — and separately, pixel *content* was measured
to have **no** effect on output (`0xAA` vs `0x55` fills give byte-identical
transcripts), so the pixel array is the *worse* carrier of the two.

This also overturned a `measured` claim in this effort's own research doc, which said
trailing bytes were ignored. Erratum:
`docs/research/2026-09-26-snowscan-bmp-format-gate.md`. Two mistakes produced it —
judging the run by stdout without ever reading the exit status, and taking one run as
the answer for a nondeterministic crash whose segfault discards buffered output.

**Two hard consequences for every gate in this sprint:**

1. **No single-run observation is admissible.** A single run misses this crash ~60% of
   the time. Every gate touching the target uses repetitions and reports the ratio.
2. **The crash threshold is unmeasured and must not be guessed.** An early 4-rep bisect
   suggested 64 bytes; 20 reps showed 0/20 there. C0 must sweep it properly.

## R1.2 — Accepted findings and what changes

| # | finding | change |
|---|---|---|
| 2 (Crit) | T-C6 asserted "loop reached", not "payload reached" — a random trailer would keep it green | **T-C6 rewritten** (R1.3). Reachability is now evidenced by a *reproducible crash ratio* attributable to the trailer, with a no-trailer negative control, not by the PASS transcript |
| 3 (High) | M-8 measured parser *acceptance*, not payload *carriage*; two writers emitting valid empty containers with ignored trailers would score 2/2 | **M-8 rewritten** to require an independent **round trip**: BMP payload recovered from decoded pixel indices, WAV payload recovered via `readframes()`, each compared byte-for-byte |
| 4 (High) | `finalize(buf)` works for PNG only under an unstated invariant | **Invariant now stated** (R1.4). The reviewer's analysis is adopted verbatim: it holds iff `wrap()` emits correct boundaries and `finalize()` only updates integrity fields derived from them |
| 5 (High) | nothing guaranteed `finalize()` ran in production; unit tests could pass while shipped WAVs carried stale lengths | **Public API is one atomic `encode(payload) -> bytes`**; `wrap`/`finalize` become private stages. This was a real API defect, not a documentation gap |
| 6 (High) | the WAV red-proof assumed `wave.open()` validates lengths strictly — it does not; a zero-length `data` chunk opens fine and reports zero frames | **T-C3 rewritten** to assert exact extracted frames, declared frame count, and both length fields, with wrong-but-present mutations in **both** directions (too small *and* too large), plus an odd-payload-length case since `data` size excludes the RIFF pad byte while the outer size includes it |
| 7 (High) | C0 swept one dimension and called it "the accepted set", though 20×20/24bpp already proves depth matters | **C0 renamed** to *accepted 8bpp geometry slice*, the implementation is **locked to 8bpp**, and 20×20/24bpp is retained as a standing negative control. The two-dimensional characterization is explicitly not claimed |
| 8 (Med) | `container=` on a non-file transport was undefined, and argv — not just stdin — is also not a file sink | **Raise `ValueError`** for a container on `SINK_STDIN` or `SINK_ARGV`, following the `build_argv()` precedent. Tested across all four transports: both file sinks accept, both non-file sinks reject |
| 9 (Med) | "the per-row scan loop is the write primitive" was stated as fact | Already **downgraded to `inferred`** in the research erratum. The trailer evidence now points away from the scan loop, so this sprint makes no claim about where the vulnerable write lives |
| 10 (Med) | T-C5 had no red-proof, violating this plan's own universal rule | **Red-proof added**: bypass wrapping inside `materialize()` only, and require T-C5 to fail against independently generated finalized bytes — not against a value obtained through the same bypassed path |

## R1.3 — Revised reachability gate (replaces T-C6)

| id | asserts | red-proof |
|---|---|---|
| T-C6′ | with a pipeline-generated wrapped payload, the target crashes (`-11`) in **≥1 of N** reps at the trailer size C0 establishes, **and** a byte-identical envelope with a 0-byte trailer crashes in **0 of N** reps | remove the trailer → the crash ratio must fall to 0/N. The paired control is what makes the crash attributable to the payload rather than to the target being generally flaky |
| T-C7 | an **unwrapped** payload is rejected at the signature gate (`rc=255`) and never reaches the scan loop | wrap it → must be accepted, proving the gate discriminates on the envelope |

Note what T-C6′ deliberately does **not** claim: not that the crash is controllable,
not that RIP is reached, and not that the target is exploitable. It claims the payload
reaches memory-unsafe code. Turning that into control is exploitation work downstream
of this sprint.

## R1.4 — The container interface, restated

```
name        -> "bmp"
extension   -> ".bmp"
capacity()  -> int | None
encode(payload) -> bytes        # THE ONLY PUBLIC ENTRY POINT
  _wrap(payload)  -> bytes      # private: emit structurally correct buffer,
                                #          with correct chunk boundaries/lengths
  _finalize(buf)  -> bytes      # private: recompute integrity fields DERIVED
                                #          from those boundaries
```

**Stated invariant (was unstated, finding 4):** `_wrap()` must produce a structurally
parseable buffer whose boundaries and lengths are already correct; `_finalize()` may
only update integrity fields derived from those boundaries. Under this contract PNG
needs no interface change — a whole-buffer finalizer can walk delimited chunks and
recompute each CRC from `chunk_type + chunk_data`. **RIFF does not exercise this
invariant**, so it remains `inferred` and a PNG spike is the only thing that would
confirm it.

## R1.5 — Revised metrics

| metric | baseline | target | provenance |
|---|---|---|---|
| **M-5″** | trailer-attributable crash from a *pipeline-generated* payload: **0** (no pipeline payload passes the format gate at all) | crash in ≥1/N reps with a 0/N no-trailer control | `measured` |
| **M-8′** | container formats whose payload is recovered **byte-for-byte by an independent parser**: **0** | **2** (BMP via decoded pixel indices, WAV via `readframes()`) | `measured` |
| M-9 | targets moved FAIL→SUCCESS | **still not claimed** | — |

M-8′'s round-trip requirement replaces "an independent parser opens the file", which
the reviewer correctly showed a payload-blind writer would satisfy. That is the same
defect class as a fixture that cannot fail, one level up: a metric that cannot
distinguish success from a convincing shell.

## R1.6 — Status

**Not approved for implementation yet.** Revision 1 answers the review on paper; per
the standing rule the revised plan goes back for one more round before code, and the
review budget for this sprint is 3 rounds total.
