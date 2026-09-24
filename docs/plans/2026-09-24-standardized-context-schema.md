# Standardized context schema (`supwngo.context/v1`)

**Date:** 2026-09-24
**Status:** v2 DRAFT — v1 was REJECTED by two independent reviews; rewritten, not patched
**Author:** coordinator (Opus 5)

## Revision history

- **v1 — REJECTED** by two independent reviewers who converged on the same
  verdict and the same primary fix.
  - Fatal flaw: `ExploitContext` was to be *the* serialized model, with a
    lossless round-trip, without new import edges. The code permits at
    most one of those three.
  - The merge layer — which v1 itself called "the part most likely to be
    got wrong" — was undefined for its own headline use case (7 of 16
    provenance cells missing, including **every** cell where the incoming
    fact is `asserted`) and failed open on the strongest signal while
    failing closed on the weakest.
  - v1 cited the walkthrough engine's `BINARY_SHA256` preflight as
    precedent for refuse-by-default. That preflight **warns and then
    verifies instructions at claimed addresses** — the opposite of what
    v1 proposed. The precedent argues against v1.
- **v2 — this document.** `facts` is the only normative store; data flows
  one way; `ExploitContext` becomes a projection.

## Goal

One document that every supwngo command can **write** and **read**, so a
fact learned by one command is reusable by another, and so a human can
supply facts supwngo cannot measure.

```bash
supwngo analyze binary_01 --context-out ctx.json
supwngo --context ctx.json pwn binary_01
```

## Non-goals

- Not a replacement for `core/database.py` (per-machine SQLite cache).
- **Not a serialization of `ExploitContext`.** Explicitly abandoned; see
  "One-directional flow".
- Not a wire protocol.

## Why this is not additive

The current state is not "no schema" but **contradictory schemas**:

- `analyze` emits two different shapes for one run — the `--json` stdout
  form flattens `dangerous_functions`/`input_sources`
  (`cli.py:83-90`), the file it writes nests under `analysis`
  (`cli.py:115-126`). It writes that file unconditionally, even in
  `--json` mode.
- **27** `to_dict` methods across 17 modules, no shared envelope
  (`handoff.py` alone has 4 at `:48,:71,:99,:160`).
- `-o` means output *directory* on `analyze`/`fuzz`, output *file* on
  `triage`/`rop`/`exploit`.

### Live bug found during review — fix separately, before this work

`DetailedProtections` (`analysis/protections.py:17-46`) adds ~20 fields
(`static`, `stripped`, `pie_type`, `full_relro`, `cfi`, `shadow_stack`,
`fortify_level`, `stack_protector`, `libc_version`, `uses_tcache`, …) but
**inherits `Protections.to_dict()`, which emits 6 keys**
(`core/binary.py:72-81`). So `analyze --json` already silently discards
most of its own measurement, today, independent of this plan.
`handoff.py:176-179` works around it with
`getattr(binary.protections, "static", False)`.

This is a prerequisite fix, not part of this plan: give
`DetailedProtections` its own `to_dict()` and retype
`ExploitContext.protections` (`core/context.py:201`) accordingly.
Otherwise the `protections` block is lossy on day one.

## Prerequisites (both currently unmerged — this plan is conditional)

1. `feat/walkthrough-engine-20260923` — provides `Confidence`
   (`walkthrough/model.py:124-143`), the address-verification preflight
   (`walkthrough/common.py:384-387`), the flag filter
   (`walkthrough/facts.py:14-20`) and `explain`. The provenance vocabulary
   here must be re-derived from `model.Confidence` **as merged**, not as
   remembered.
2. The `DetailedProtections` fix above.

If (1) does not land, the provenance reconciliation and the
verification-based guard lose their implementation and this plan must be
re-scoped.

## Decisions taken

1. **`--context` is long-form only. No `-c`.** Operator-confirmed intent
   was a dedicated flag; review found the short form unsafe. `exploit`'s
   `-c/--crash` is `type=click.Path(exists=True)` (`cli.py:241`), so
   `supwngo exploit -c ctx.json ./t` — which reads naturally and users
   *will* type — silently accepts the context document **as a crash
   input** (`cli.py:275-277`) and never loads it. `--context-out PATH`
   writes. `-o` is untouched everywhere.
   - Mitigation regardless: `exploit --crash` sniffs for
     `schema_version: supwngo.context/…` and errors out.
2. **All commands classified up front** (operator chose full coverage),
   but as three explicit tiers rather than uniform conformance — see
   "Command tiers". `producer`/`consumer`/`exempt`, with a literal table
   of all 31 registrations and a one-line reason for each exemption.

## Design

### One-directional flow (the central change)

```
command results ──adapters──▶  facts  ◀──hand-authoring── human
                               │  ▲
                   evidence    │  │ projection (read-only)
                      ▼        │  ▼
                   blocks      └─▶ ExploitContext (in-memory, never written back)
```

- **`facts` is the only normative store.** A consumer reads `facts` and
  never a block.
- **`blocks` are non-normative evidence**, append-only, each carrying
  `produces: ["<fact_key>", …]`.
- **`ExploitContext` is a projection.** A loader populates only the fields
  it can. There is no `to_context_doc()`. It is never serialized back over
  facts.

This is forced by the code, not preference:

- `core/context.py:16-28` forbids `core/` importing `supwngo.exploit.*`,
  and types two fields `Any` for exactly that reason
  (`verification_level` at `:256-261`, `attempts` at `:263-267`).
  A `from_context_doc()` must *construct* `AttemptRecord` and
  `VerificationLevel`, i.e. add the forbidden edge. Putting the model in
  `supwngo/schema/context_v1.py` — which may import from `exploit/` —
  removes the conflict.
- **Rehydration mutates what it rehydrates.** `LibcInfo.__post_init__`
  calls `_analyze_libc()` whenever `path` is set (`context.py:83-85`),
  recomputing `system_offset`/`binsh_offset`/hooks from the *local* libc —
  overwriting even a human's `asserted` values. `add_leak()`
  (`context.py:311-318`) re-triggers base derivation. `find_one_gadgets`
  **appends without clearing** (`context.py:130-133`), so each round trip
  lengthens `one_gadgets`. Round-tripping is not merely lossy, it is
  non-idempotent and monotonically corrupting.
- **Existing serializers are destructively lossy by design.**
  `AttemptRecord.to_dict()` reduces `payload: bytes` to
  `payload_len: int` (`contracts.py:104`) and `str()`s non-scalar
  `partial_artifacts` (`:106`). `Vulnerability.to_dict()` drops
  `controllable_input`, `primitives`, `crash`, `details`
  (`detector.py:91-101`). Adapters must read the **live objects**, not
  these `to_dict()`s.
- **Model ambiguity a schema cannot fix:** `ExploitContext.offset`
  (`:250`) and `stack.return_address_offset` (`:154`) are documented as
  deliberately distinct (`:244-249`). Resolve to one field with a stated
  meaning before mapping either to a fact key.

### Facts: provenance, scope, and dependencies

```json
"facts": {
  "stack.return_offset@stdin": {
    "value": 72,
    "provenance": "measured",
    "scope": "build",
    "depends_on": "binary_bytes",
    "derived_from": [],
    "method": "gdb cyclic-pattern probe",
    "evidence": {"rsp": 6748010543161397363, "cyclic_find": 72},
    "conditions": {"input_method": "stdin"},
    "by": "supwngo offset", "at": "<ISO-8601>", "stale": false
  }
}
```

**`provenance`** ∈ `measured | derived | assumed | asserted | unknown`.
`unknown` is load-bearing and carried over from
`walkthrough/model.py:124-143`, where it requires the fact to name a
resolving step; here it requires `resolved_by`. Dropping it (as v1 did)
would make the two models non-interconvertible, defeating the claim that
the walkthrough generator can consume this document.

**`scope`** (validity lifetime) ∈ `build | libc_file | host | boot |
process | attempt`. This is separate from provenance and fixes v1's
category error: an ASLR-dependent `libc.base` is valid for **one process**,
yet v1 described the document as build-portable. `process`/`attempt`-scoped
facts are **refused on reuse in a new run**, regardless of digest.

**`depends_on`** ∈ `binary_bytes | binary_symbols | libc_file | runtime` —
the discriminator the identity gate keys on.

**`conditions`** makes jointly-valid facts explicit. A bare
`stack.return_offset: 72` is ambiguous because `offset --input-method
[stdin|argv|file]` (`cli.py:768`) yields different results per method and
`OffsetResult` (`offset_finder.py:28-42`) does not record which it used.
Keys are qualified (`@stdin`) and `conditions` must match at consume time.

**`derived_from`** lists `"<fact_key>@<fact_digest>"`. On supersede,
dependents are transitively marked `stale: true`, and **consuming a stale
fact is a hard error**. Without this, a corrected `puts` leak leaves
`libc.base` silently wrong and every ret2libc address built from it wrong.

**`confidence` is removed.** v1 carried both `provenance` and
`confidence` as independent trust axes but merged only on provenance, so a
`measured` fact at 0.2 would supersede one at 0.99. Provenance is the
decision variable; where a numeric score genuinely exists
(`Vulnerability.confidence`, `detector.py:75`) it lives in the evidence
block, not in merge logic.

### Merge: complete matrix, and fail closed on contradiction

Rank `asserted > measured > derived > assumed > unknown`, **but rank alone
never resolves a contradiction.**

- Higher rank wins over lower rank; loser recorded in `superseded[]`.
- Equal rank, equal value → deduplicate, refresh `at`, no history entry
  (keeps repeated runs from growing the document without bound).
- Equal rank, different value, **same scope** → the fact becomes
  `unresolved`; the command **aborts** and requires
  `--resolve=<key>:asserted|measured|…`. Safety-critical consumers refuse
  an `unresolved` fact.
- Different scope → both retained; they are not in conflict (this is the
  distinction v1 missed: *"the remote differs from local" is an
  applicability distinction, not provenance precedence*).
- Type mismatch → validation error, never a merge.
- `retracted: true` + `retracted_reason` suppresses a fact without
  asserting a replacement — the verb v1 lacked entirely.

**`asserted` no longer beats `measured` unconditionally.** A contradiction
between a human assertion and a measurement means "the number you are
about to build a payload with is provably not the number this binary
produced." That aborts. Additionally every `asserted` fact records
`asserted_for` (the identity it was written against); if the current
target's identity differs, the assertion is **demoted to `assumed`**
automatically — preserving the legitimate "I know the remote differs" case
while killing copy-paste-from-another-challenge.

**CLI flags are facts.** `autopwn --offset` (`cli.py:2466`), `template
--offset` (`:1010`), `--libc` on several commands, `explain --offset/--libc`
all collide with stored facts. Rule: a CLI flag is an `asserted` fact
scoped to this invocation; it wins in-process, is written back as
`asserted`, and a contradiction with a stored `asserted` fact aborts.

`superseded[]` is capped at 3 entries per fact; older history moves to a
sidecar, so the document stays reviewable and diffable — the property the
design is justified by.

### Identity: verify, don't just hash

v1 refused on `target.sha256` mismatch. Wrong invariant, and the cited
precedent does the opposite.

- Record `sha256` **and `build_id`** (`.note.gnu.build-id`), which survives
  `strip`.
- On read, a digest mismatch **warns**, then supwngo **verifies a sample of
  `binary_bytes` facts against the loaded binary** — does the address still
  hold the claimed instructions? Refuse on **verification failure**, which
  actually predicts wrongness, rather than on a hash difference.
  `walkthrough/common.py:384-387` already implements this check: "Verify
  each claimed gadget address really holds those instructions. This is the
  check that catches a rebuilt binary AND the classic symbol-vs-gadget
  address mistake in one shot."
- Why the hash gate was both over- and under-restrictive:
  **over** — `exploit -r host:port` (`cli.py:242,264-266`) and `solve
  --remote` (`:2720`) load a local *copy*; stripping, a different build-id
  or a `.comment` change alters sha256 while every gadget and offset stays
  correct. **under** — a matching sha256 says nothing about the host's
  libc, yet `libc.base`/`system_offset`/one-gadgets are the facts most
  likely wrong and most catastrophic.
- `--target-identity=sha256|build-id|none` replaces the blanket
  `--context-mismatch=allow`, which disabled all checking at once.
- `Binary.__post_init__` hashes only `if self.path.exists()`
  (`core/binary.py:137-142`), so a doc can carry `sha256: ""`. The doc's
  digest is authoritative and is never overwritten by a locally computed
  value; **refuse to write** a doc with an empty digest.

### Target identity fields (v1 was incorrect)

`exec|dyn|static` conflated two dimensions — PIE is normally `ET_DYN`.
Split into `format`, `elf_type`, `linkage`, `pie`, `os_abi`, `build_id`.
`Binary` has **no `to_dict()`** (the `core/binary.py` producer is
`Protections.to_dict`, `:72`), so `target` needs a new producer.

### Secrets and flags

`ExploitContext.captured_flag` (`:254`) and `VerificationReceipt.flag`
(`contracts.py:133`) must **not** be serialized by default. The
walkthrough engine deliberately filters flag-shaped strings so its
artifact cannot be used to skip the exercise
(`walkthrough/facts.py:14-20,55-62`); writing flags here would reverse
that control. Reuse its `_is_flagish` rather than reinventing it; gate on
`--context-include-flags`.

`method`/`evidence` carry structured fields, not verbatim command lines
(usernames, tokens, remote endpoints). `target.path` and `artifacts[].path`
are **relative to the document**, with `--binary` overriding at read time.
Provenance commands are never executed.

### Encodings (pinned, because "canonical" is meaningless otherwise)

- bytes → base64 with a `b64:` prefix (never `default=str`, which yields
  an irreversible repr; today's habit at `cli.py:126,1601,1761,1765,…`).
- sets → sorted arrays (`profile_bad_bytes`, `context.py:280`).
- addresses → unsigned int; the schema **rejects** hex strings. In-tree is
  currently inconsistent (`hex()` at `detector.py:96`,
  `offset_finder.py:58-59`, `contracts.py:105`; raw ints elsewhere).
- canonical form: `sort_keys=True, separators=(",",":")`, plus a separate
  pretty presentation form that is explicitly **not** the digest input.
- YAML: `safe_load` only, duplicate keys rejected, anchors/aliases
  rejected, size/depth limits. Note YAML 1.1 parses `0x401234` as an int,
  which is why address encoding must be pinned for read parity.

### Persistence

`--context-out` defaults to the `--context` path (in-place accumulate) as
the primary mode. Writes are temp-file + `os.replace()` (atomic), guarded
by `fcntl.flock`. Long-running commands (`fuzz -t 3600`, `cli.py:135`)
checkpoint periodically so a killed campaign still contributes.

### Command tiers

Three tiers, with a literal table of all 31 `@cli.command()`
registrations. Concrete exemptions found in review:

- *No target*: `version` (`:1399`), `cyclic` (`:885`), `cyclic-find`
  (`:896` — it produces an offset with no binary, which would manufacture
  the exact unanchored-fact footgun this plan exists to prevent),
  `libc-id` (`:562`).
- *Target is not the binary*: `onegadget <libc>` (`:822`),
  `source <tree>` (`:1169`), `kernel <module>` (`:1286`).
- *Not one target*: `diff <b1> <b2>` (`:1691`), `batch <dir>` (`:920`).
  These need `targets[]` keyed by ID, or stay exempt.
- *Argument-shape traps*: `triage <crash_dir> <binary>` (`:192`) — the
  binary is the **second** positional, so any decorator assuming "first
  argument is the target" is wrong. The decorator therefore takes an
  explicit **target resolver per command**, never positional inference.

Roughly 25 of 31 commands never build an `ExploitContext` at all — a
further argument for the projection model.

## Files touched

- `supwngo/schema/context_v1.py`, `context-v1.json` (new).
- `supwngo/core/context.py` — projection loader only; **no** `to_context_doc`.
- `supwngo/cli.py` — `--context`, `--context-out`, per-command resolvers.
- New non-lossy adapters for `AttemptRecord`, `Vulnerability`,
  `DetailedProtections`, plus a `target` producer.
- `setup.py` / `pyproject.toml` / `MANIFEST.in` — `jsonschema>=4` in
  install_requires; `schema/*.json` in `package_data` (currently only
  `payloads/templates/*.py` and `data/*.json`, `setup.py:74-79`, so the
  schema would be **absent from an installed wheel** and validation would
  crash for every pip user).
- `tests/test_context_schema.py`, `tests/test_context_conformance.py`.
- `CHANGELOG.md` under `Added` and `Changed`.

## Test strategy

The v1 "byte-identical round trip" assertion is unachievable and is
replaced by three that are:

1. **Fixpoint stability:** `dump(load(dump(load(d)))) == dump(load(d))`.
   Catches non-idempotent rehydration.
2. **Semantic equality modulo a declared volatile set** (`updated`,
   `history[-1].at`, `receipt.verified_at`), the exclusion list living in
   the test so it shows up in diffs.
3. **No-silent-drop:** against a golden maximally-populated document,
   every JSON pointer in the input is present in the output **or** named in
   an explicit `KNOWN_LOSSY` allowlist the test prints on failure.

Plus:

4. **Full 5×5 merge matrix**, both operand directions, plus
   same-value dedup, type mismatch, retraction, idempotence under repeated
   merges, and staleness cascade through `derived_from`.
5. **Contradiction aborts** and `--resolve` selects.
6. **Identity:** digest mismatch warns; instruction-verification failure
   refuses; `process`-scoped facts refused on reuse; `asserted_for`
   mismatch demotes to `assumed`.
7. **Static conformance** over `cli.commands`: every command is either in
   the exemption allowlist **or** accepts both flags. v1's test was
   vacuous — a new command omitting the decorator simply wasn't in the
   parametrization and passed. The allowlist is the artifact a reviewer
   diffs.
8. **Executed conformance** on `tests/` fixtures, marked
   `@pytest.mark.integration`, because a real sweep would need AFL++,
   angr, Ghidra (`cli.py:1771`), external SAST (`:1171-1173`) and
   **network access to libc.rip** (`remote/libc_db.py`).
9. **Flag misplacement:** `supwngo exploit --crash ctx.json ./t` errors
   rather than treating the document as crash bytes.
10. **Secret redaction:** flags absent unless opted in.
11. **YAML/JSON parity** including `0x401234` vs `4198964`.
12. **Atomicity:** interrupted write leaves the prior document intact;
    concurrent writers do not lose updates.
13. **Packaging:** schema loads via `importlib.resources` from an
    installed wheel.

## Risks

- **Prerequisites unmerged.** Named above; if the walkthrough branch
  changes shape, the provenance reconciliation and verification guard must
  be re-derived.
- **`cli.py` is ~2,900 lines with concurrent editors.** Start after the
  walkthrough CLI commit lands.
- **Real unit of work is depth, not breadth** — v1 claimed otherwise.
  `AttemptRecord`, `Vulnerability` and `DetailedProtections` each need a
  *new* non-lossy serializer. Sequence: envelope + `facts` + 3 blocks on
  the core path first, then widen.
- **Breaking consumers** of today's ad-hoc JSON: `--legacy-json` on the
  commands CLAUDE.md documents (`analyze`, `fuzz`, `triage`, `exploit`,
  `rop`, `symbolic`, `libc-id`), byte-identical to today, with a stated
  deprecation horizon.
- **Forward compatibility:** refuse unknown major `schema_version`;
  warn-and-proceed on a newer `tool_version`; preserve unknown fields
  without consuming them.
- **Diagnostics must go to stderr.** 19 commands print JSON to stdout via
  `console.print_json` (`cli.py:88,733,792,850,1116,…`); a warning through
  the same `console` makes stdout unparseable. Conflicts additionally
  appear as a machine-readable `conflicts[]` inside the payload.
