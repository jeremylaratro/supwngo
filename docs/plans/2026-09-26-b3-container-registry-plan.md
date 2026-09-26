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
