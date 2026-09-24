# Standardized context schema (`supwngo.context/v1`)

**Date:** 2026-09-24
**Status:** v3 DRAFT — v1 and v2 both REJECTED; v3 replaces key→value facts with candidate sets
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
- **v2 — REJECTED.** Two of six blockers fixed (two-authorities,
  round-trip); the merge layer was still wrong, and for one root cause:
  `facts` was an object with **one value per key**, yet the rules said
  "different scope → both retained." The structure could not represent
  what the rules required. Consequently the prose was self-contradictory
  ("higher rank wins" *and* "rank alone never resolves a contradiction"
  *and* "asserted vs measured aborts" *and* "CLI asserted wins"), and
  `--resolve=<key>:<provenance>` could not even name one of two
  conflicting `measured` candidates. Also: demoting provenance to express
  applicability "rewrites what happened"; the verification gate was
  undefined for the majority of facts that are not address claims;
  `derived_from` used `@` as a separator when fact keys already contain
  `@`; libc had no identity of its own; `process`/`attempt` scopes had no
  IDs to be checked against.
- **v3 — this document.** Facts become **candidate sets** with stable IDs.
  One normative resolution function replaces all merge prose.

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

### Facts are candidate sets, not values

A fact key maps to a **list of candidates**, each with a stable ID. This is
the structural change v2 lacked: two facts may be simultaneously true of
different scopes or identities, and the document must be able to hold both
without either silently winning.

```json
"facts": {
  "stack.return_offset": {
    "candidates": [
      {
        "id": "f_7c1a",                       // stable; referenced by derived_from
        "value": 72,
        "provenance": "measured",
        "applies_to": {
          "identity": "t_main@sha256:04aa1a…",
          "scope": "build",
          "conditions": {"input_method": "stdin"}
        },
        "verification": {"class": "static_offset", "state": "unverifiable",
                         "reason": "not an instruction-address claim"},
        "derived_from": [],
        "method": "gdb cyclic-pattern probe",
        "evidence": {"rsp": 6748010543161397363, "cyclic_find": 72},
        "by": "supwngo offset", "at": "<ISO-8601>",
        "state": "active"                     // active|superseded|retracted|unresolved
      }
    ],
    "resolution": {"selected": "f_7c1a", "rule": "most_specific_applicable"}
  }
}
```

A consumer never reads `candidates` directly; it calls `resolve(key, ctx)`
and gets exactly one candidate or an error.

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

### Merge and resolution: two separate operations

v2's merge prose was self-contradictory because it tried to be both at
once. They are split:

**`merge(existing_candidates, incoming)` — never chooses a winner.**
It only ever *adds* a candidate or recognises an exact duplicate:

| condition | outcome |
|---|---|
| no candidate with same `applies_to` **and** same value | append new candidate |
| candidate exists with same `applies_to` and same value | `last_seen` updated on the existing candidate; **no** new candidate, no history entry |
| candidate exists with same `applies_to`, different value, incoming rank **higher** | incoming appended `active`; previous → `superseded`; dependents invalidated |
| candidate exists with same `applies_to`, different value, incoming rank **lower** | incoming appended `state: superseded` immediately (kept as evidence, never selected) |
| candidate exists with same `applies_to`, different value, **equal** rank | both `active`; the key is `unresolved` |
| value fails the key's declared type | validation error; nothing merged |

Rank is `asserted > measured > derived > assumed > unknown`, and it applies
**only within one `applies_to`**. Two candidates with different
`applies_to` are never in conflict and never compared — that is the
applicability-vs-precedence distinction, now enforced structurally rather
than asserted in prose.

**`resolve(key, ctx)` — chooses, or refuses.** Given the current
invocation's identity, run/process IDs and conditions:

1. Discard candidates whose `state` is not `active`.
2. Discard candidates whose `applies_to.identity` does not match the
   current target identity, or whose `scope` has expired (a `process`-scoped
   candidate from a different `process_id`), or whose `conditions`
   contradict the invocation.
3. Of the survivors, select the **most specific**: identity-bound beats
   identity-agnostic, then narrower scope beats broader, then more
   `conditions` matched, then higher rank, then newest `at`.
4. If step 2 leaves nothing → `FactUnavailable`. If step 3 cannot break a
   tie, or the key is `unresolved` → `FactUnresolved`. **Both are errors.**
   Neither is ever silently treated as absent, and no consumer may proceed
   on a guess.

`--resolve <candidate_id>` selects by **candidate ID**, not by provenance
(v2's `--resolve=<key>:measured` could not distinguish two conflicting
`measured` candidates). Doing so writes an auditable
`resolutions[]` record — who resolved it, when, which candidate lost — and
invalidates the dependent closure of the rejected candidate.

**A candidate's provenance is never rewritten.** v2 demoted an
identity-mismatched `asserted` fact to `assumed`, which falsifies the
record of what happened. Instead the candidate simply fails step 2 —
it remains `asserted`, and is *inapplicable* here. Using it against a new
target requires an explicit re-assertion naming that target.

**CLI flags go through the same table.** `autopwn --offset`
(`cli.py:2466`), `template --offset` (`:1010`), `--libc`, `explain
--offset/--libc` become `asserted` candidates bound to this invocation's
identity, merged by the rules above — not a parallel override path.

### Dependencies and staleness

`derived_from` holds **structured** references, `[{"id": "f_7c1a",
"digest": "<sha256 of the candidate's canonical form>"}]` — not strings
(v2 used `@` as a separator when fact keys already contain `@`).

Invalidation closure is recomputed on supersede, retract, transition to
`unresolved`, **and** on any source-candidate digest change. Traversal uses
a visited set, so it terminates. Cycles and dangling references are
rejected **at validation time**, transactionally, so an invalid graph is
never persisted. Consuming a `stale` candidate is a hard error.

### Verification is a registry, and may return "unverifiable"

v2 said "verify a sample of `binary_bytes` facts," which is undefined for
the majority of facts that are not instruction-address claims. Instead
every fact key declares a **verification class**, and each class has a
verifier returning `verified | failed | unverifiable`:

| class | verifier | example keys |
|---|---|---|
| `instruction_at` | disassemble and compare mnemonics | `gadget.pop_rdi`, `plt.system` |
| `symbol_addr` | symbol table lookup | `sym.win` |
| `static_offset` | none available | `stack.return_offset` |
| `libc_offset` | resolve against the bound libc artifact | `libc.system_offset` |
| `runtime` | never verifiable statically | `libc.base`, `leak.puts` |

Rules: **missing tooling yields `unverifiable`, never `verified`.**
`unverifiable` is not a pass — a safety-critical consumer refuses it unless
an explicit, per-key, recorded override exists. `failed` refuses always.
This is what makes the identity gate implementable; it also means the gate
degrades honestly on a machine without a disassembler rather than
pretending to have checked.

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
  `--context-mismatch=allow`. `none` is defined narrowly: it permits
  *selection* of candidates bound to a different identity, and records an
  `identity_override` in `resolutions[]`; it does **not** disable
  verification, and `runtime`-scoped candidates remain refused.
- `Binary.__post_init__` hashes only `if self.path.exists()`
  (`core/binary.py:137-142`), so a doc can carry `sha256: ""`.
  **Refuse to write** a doc with an empty digest.

### Identities are first-class, and there is more than one

v2 had a single `target` and declared its digest authoritative even after a
*different* binary was accepted through verification — so new measurements
from binary B could be stored under binary A's identity. Instead:

```json
"identities": {
  "t_main":  {"role": "target", "sha256": "…", "build_id": "…",
              "format": "elf", "elf_type": "ET_DYN", "linkage": "dynamic",
              "pie": true, "os_abi": "linux", "arch": "amd64", "bits": 64},
  "l_glibc": {"role": "libc", "sha256": "…", "build_id": "…",
              "version": "2.39"},
  "r_prod":  {"role": "remote", "endpoint": "host:1337"}
},
"runs": [{"run_id": "r_01", "at": "…", "process_ids": ["p_01"]}]
```

- Every candidate's `applies_to.identity` names one of these. A fact
  produced while operating on a binary is bound to **the identity actually
  observed**, never to a stale envelope value.
- **libc gets its own identity.** v2 had `libc_file` as a dependency class
  but gave only the main binary a digest, while `libc.system_offset`,
  one-gadgets and every derived base bind to the libc, not the target.
- `process`/`attempt` scopes reference `run_id`/`process_id`/`attempt_id`,
  which is what makes "refused on reuse in a new run" implementable. A new
  `run_id` is minted per CLI invocation; a new `process_id` per spawned or
  reconnected target process. Any candidate scoped to a `process_id` not in
  the current run fails resolution step 2.
- `diff` and `batch` become representable: multiple `target`-role
  identities, with facts bound per identity, rather than being forced
  through a single-target envelope.

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
the primary mode.

Locking `ctx.json` itself does not serialize writers, because the file is
then *replaced* — the lock is held on an inode that no longer backs the
path. So the lock lives on a **stable sidecar**, `ctx.json.lock`, and is
held across the whole read → merge → validate → temp-write → `fsync` →
`os.replace()` → directory `fsync` sequence. That is what prevents lost
read-modify-write updates, which atomic replacement alone does not.

**History stays inside the document.** v2 moved capped `superseded[]`
history to an unspecified sidecar, creating a second persistence authority
with no schema, integrity link, or locking story. Candidates that are
`superseded` or `retracted` simply remain in the candidate list with that
state; a `--context-prune` subcommand compacts them on request, so growth
is bounded by an explicit operator action rather than by a silent cap.

Long-running commands (`fuzz -t 3600`, `cli.py:135`) checkpoint
periodically so a killed campaign still contributes.

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
   `last_seen`, `runs[].at`, `receipt.verified_at`), the exclusion list
   living in the test so it shows up in diffs. `at` is an *observation*
   time and is never refreshed, so it is not volatile — only `last_seen`
   is, which is why repeated identical merges are idempotent.
3. **No-silent-drop:** against a golden maximally-populated document,
   every JSON pointer in the input is present in the output. The
   `KNOWN_LOSSY` allowlist is restricted to fields explicitly deprecated
   with a migration rule; **unknown fields must round-trip unchanged**,
   so the allowlist cannot be used to excuse ordinary loss (v2's version
   contradicted its own forward-compatibility promise).

Plus:

4. **Merge table exhaustively**, both operand directions: every row above,
   plus same-value dedup, type mismatch, retraction, repeated-merge
   idempotence, and that a lower-rank incoming candidate is retained as
   evidence but never selected.
5. **Resolution:** `FactUnavailable` and `FactUnresolved` are raised, not
   swallowed; `--resolve <candidate_id>` selects, records a `resolutions[]`
   entry, and invalidates the rejected candidate's dependent closure.
6. **Dependency graph:** cycles and dangling references rejected at
   validation; closure traversal terminates on a cyclic input that somehow
   reaches it; digest change on a source invalidates dependents.
7. **Verification registry:** each class returns the right state; missing
   tooling yields `unverifiable` and a safety-critical consumer refuses it;
   `failed` always refuses.
8. **Identity:** digest mismatch warns; verification failure refuses;
   `process`-scoped candidates refused in a new run; a candidate bound to
   another identity is not selected; `--target-identity=none` permits
   selection, records the override, and still refuses `runtime` candidates.
9. **Static conformance** over `cli.commands`: every command is either in
   the exemption allowlist **or** accepts both flags. v1's test was
   vacuous — a new command omitting the decorator simply wasn't in the
   parametrization and passed. The allowlist is the artifact a reviewer
   diffs.
10. **Executed conformance** on `tests/` fixtures, marked
   `@pytest.mark.integration`, because a real sweep would need AFL++,
   angr, Ghidra (`cli.py:1771`), external SAST (`:1171-1173`) and
   **network access to libc.rip** (`remote/libc_db.py`).
11. **Flag misplacement:** `supwngo exploit --crash ctx.json ./t` errors
   rather than treating the document as crash bytes.
12. **Secret redaction:** flags absent unless opted in.
13. **YAML/JSON parity** including `0x401234` vs `4198964`.
14. **Atomicity:** interrupted write leaves the prior document intact;
    concurrent writers do not lose updates.
15. **Packaging:** schema loads via `importlib.resources` from an
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
