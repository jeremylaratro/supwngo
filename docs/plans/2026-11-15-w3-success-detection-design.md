# W-3 — success detection without platform patterns (class C) (2026-11-15, Rev 2 DRAFT)

> Directive W, phase W-3. Parent plan: `docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md`.
> Builds on W-2 (`2026-11-13-w2-required-args-design.md`, merged). Plan-review on Opus, execute on Sonnet.
>
> **Rev 2 — reworked after the Codex (third-model) review of Rev 1 returned REWORK (5 BLOCKER / 5 MAJOR /
> 3 MINOR).** The reviewer confirmed the three-tier model is directionally right but flagged: the neutral
> regex is itself a class-C scanner hit (B1); anti-echo contradicts the "keep existing levels" note (B2); the
> retained bare-word list is an undeclared 4th tier that makes "54 migrated" false (B3); `sent_bytes` has no
> end-to-end contract (B4); the commit order leaves the ratchet/lint red for several commits (B5); plus the
> PLANTED lifecycle, result/receipt mapping, exact-ID disposition, lint grammar, and test matrix all needed
> tightening (M1–M5). §10 maps each to its resolution.
>
> **Rev 3 — reworked after the Codex re-review of Rev 2 confirmed B1–B5, M1, M5, N1–N3 RESOLVED and left three
> majors PARTIALLY-RESOLVED (verdict REWORK on those only):** the exact tier→receipt-field mapping and the
> `TestConfig.flag_pattern` decision (M2); the import topology, since `supwngo/__init__.py` eagerly imports the
> exploit package so "import without the exploit initializer" is unachievable and was the wrong target (M3);
> and the still-deferred `HackTheBox` banner decision (M4). All three are closed below (§2.5, §3/§7 R5, §4) with
> concrete decisions, not deferrals.
>
> **Rev 3.1 — the Rev 3 re-review marked M3, M4 RESOLVED and left one M2 nit:** the "echoed token only" row gave
> `shell_confirmed` as prose, not a boolean. Fixed in §2.5 (`shell_confirmed=True`, echo recorded in receipt
> `notes`). With that, every Rev 1 finding is resolved.
> Status: **DRAFT — final nit closed; ready for implementation pending acceptance.**

## 0. Goal (exact, from the parent plan's Done-when)

> **W-3 — Success detection (class C).** Every class-C baseline entry is `migrated`, or `allowed` with a
> justification. Planted-marker oracle: positive control passes; an input-echo decoy fails. No platform token
> appears in any non-comment product string (lint).

Parent §3 principle 4 is the design constraint: where the tool controls the run environment, plant a random
marker and check for it; elsewhere use a platform-neutral flag **shape** the operator can override; a marker
must not be satisfiable by a plain echo of input.

## 1. Scope — the 54 class-C baseline entries

Class C = platform-specific success/flag patterns. The W-0 baseline (`tests/data/target_values_baseline.json`)
holds exactly these 54 IDs (`class == "C"`, all currently `status: open`):

```
W-0001..W-0006, W-0012, W-0013, W-0018, W-0019, W-0020, W-0021, W-0022,
W-0027, W-0028, W-0029, W-0030, W-0031, W-0032, W-0033, W-0046, W-0047,
W-0051, W-0055, W-0069, W-0071, W-0074, W-0075, W-0076, W-0077, W-0078,
W-0079, W-0084, W-0085, W-0090, W-0091, W-0095, W-0106, W-0108, W-0116,
W-0118, W-0124, W-0130, W-0131, W-0132..W-0139, W-0141, W-0153
```

The scanner (`scripts/audit_target_values.py`) recognises three class-C `kind`s: `flag_shape` (a literal
containing `word{`, via `FLAG_SHAPE_RE:326`), `success_words` (a collection drawn from `SUCCESS_WORDS`), and
`success_compare` (a success word tested against an output-like name in `_decide`). One source line can yield
two entries.

### 1.1 Run-context taxonomy (drives the migration target per entry)

- **L — tool-controlled local run.** The tool spawns the target; a **planted random marker** is feasible *only
  when the caller runs it in a private workspace it owns* (see M1 / §2.3). Otherwise L falls back to
  SHELL-PROVEN or SHAPE.
- **R — remote / unknown target.** Only a neutral overridable **shape** or a **shell-proof** challenge.
- **S — static analysis / reporting.** `strings` categorisation and walkthrough redaction. No run.
- **G — generated-script text.** The literal is emitted into a standalone script the operator runs later; the
  script does its own matching (so it cannot import the module — see §2.4).

## 2. The success oracle — one module, ranked evidence, anti-echo everywhere

New module **`supwngo/core/success_oracle.py`** (`core/`, not `exploit/`). It exposes the matcher, the
shell-proof probe set, the planted-marker machinery, and the two static helpers that `strings.py`/`facts.py`
need.

**Import topology (M3, corrected in Rev 3).** The Rev 2 goal "import without loading the `supwngo.exploit`
initializer" is unachievable and was the wrong target: `supwngo/__init__.py` eagerly imports
`supwngo.exploit.auto` (and the rest of the package), so importing *any* `supwngo.*` submodule — including
`supwngo.analysis.strings` itself — already runs the exploit initializer today. W-3 does not change that
(making `__init__` lazy is a separate public-API refactor, out of scope). The real requirement is **no new
circular import and no import-time side effects**, which is met by a hard rule: `success_oracle.py` imports
**only the standard library** at module scope (no `supwngo.exploit.*`, no `supwngo.analysis.*`). The
dependency runs one way — `verification.py`, `verifier.py`, `tester.py`, `strings.py`, `facts.py` import
*from* the oracle; the oracle imports *none* of them. Because the oracle is pure-stdlib, importing it during
`__init__`'s analysis/exploit phase cannot close a cycle. R5's seam test (§7) enforces this: it imports
`supwngo.core.success_oracle` and asserts the oracle module's own top-level imports include no `supwngo.`
module (an AST/`sys.modules`-delta check), which is the property that actually prevents the cycle.

### 2.1 Evidence tiers (preference order, not an impact ranking)

`check()` returns the highest-preference tier whose evidence survives the anti-echo filter, **and the full
filtered evidence set** (N2 — a planted disclosure that also yielded a shell proof keeps both):

1. **PLANTED (strongest attribution; L with a private workspace only).** A fresh ≥128-bit random token
   (`secrets.token_hex(16)`, no platform word) planted in a file inside the run's private workspace; success
   only when that exact token appears in output. Never satisfiable by an echo — the token is never sent.
2. **SHELL-PROVEN (L and R).** The arithmetic + strict-marker probe set (`echo <tok>_STRICT`,
   `echo SH$((6*7))OK`, `uid=`) currently in `pipeline/verifier.py:728-768`, moved here as the canonical
   definition so every caller shares it. An echo of the sent bytes cannot answer `42`/`SH42OK`/`uid=`.
3. **SHAPE (R, and L fallback).** The neutral default shape (§2.2), overridable via `SUPWNGO_FLAG_RE`. Weakest;
   labelled as such in the receipt.

Bare success-word matching (`welcome`, `congratulations`, …) is **removed from success decisions** (B3): it may
be recorded as a `banner` diagnostic but never sets `success` or a tier. This is what lets W-0139 migrate.

### 2.2 The neutral shape and the scanner exemption (B1)

The one sanctioned neutral pattern is `([A-Za-z0-9_]+)\{[^}\s]{4,}\}`. The pinned scanner **does** classify this
literal as `C/flag_shape` (the `)\{` branch of `FLAG_SHAPE_RE` — verified empirically), so dropping it into a
product module would create a current class-C hit with no baseline ID and fail
`test_every_current_hit_has_a_baseline_entry`. The platform-token lint (§4) is **not** a substitute for the
class-C scanner; the default passes the lint but fails the scanner.

Resolution (do **not** regenerate the baseline, do **not** add a W-3 ID):

- Add an **exact-literal exemption** to `scripts/audit_target_values.py` for the single canonical oracle
  constant, pinned the way `UNIVERSAL_NAMES`/`LIBC_ROOTS` are, keyed to the oracle module + symbol so no other
  occurrence of the pattern is exempted. Bump `SCANNER_VERSION` 1 → 2.
- A regression proves the exemption leaves the **frozen entry set, IDs, classes and the W-0 frozen-field hash
  unchanged** (the scanner-version field is not a frozen baseline field).
- A scanner unit test exercises the exemption against the **actual oracle constant imported from the module**,
  not a separately typed copy of the regex.
- The W-3 closure test asserts the **current class-C scan is empty** after migration (§3) — "no `open` class-C
  entry" is vacuous once all 54 are closed.

### 2.3 PLANTED — workspace lifecycle and provenance (M1, N3)

`mint_marker()` returns a `MarkerRecord(value, attempt_id, planted_path, workspace_id)` with ≥128 bits of
entropy and a stable encoding. Rules:

- PLANTED is permitted **only** when the caller supplies a private workspace *and* the oracle has verified the
  marker value is absent from every target-bound input for that attempt (§2.4). Otherwise `check()` falls
  through to SHELL-PROVEN/SHAPE. W-3 does **not** claim every L-site gains PLANTED; the sandboxed dynamic
  runner that makes PLANTED universal is W-4's job. In W-3, PLANTED is wired where a private workspace already
  exists (e.g. `verify_shell_access`'s file-write marker) and proven by the controls below.
- Atomic create + guaranteed cleanup; a fresh marker per attempt; a marker from attempt A must not satisfy
  attempt B (asserted).
- **Positive control:** a real compiled/scripted program that reads the marker from the planted file in a
  temporary private workspace and prints it → PLANTED success. Passing the value via stdin/argv/env would not
  prove the property and is explicitly not the control.
- **Echo decoy:** a program that reflects an input which *contains an otherwise-qualifying shape/probe*; the
  test asserts the reflected subject is present in output **and** that the oracle still returns no success. A
  decoy with no access to the planted value would pass trivially and is not sufficient.

### 2.4 The anti-echo contract across the full transcript (B4)

`check(output, sent_bytes, *, planted=None, workspace=None)`:

- **`sent_bytes` is the lossless concatenation of every byte delivered to the target for that attempt** —
  stdin, argv, and any materialized input files — not just the final payload. Multi-send callers
  (`auto.py:662-684`, `:1283-1293`, the menu-driven executors) must record the whole transcript via the shared
  send helper and hand it to `check()`.
- Anti-echo is applied **per candidate match, before tier ranking**: each individual match that also occurs in
  `sent_bytes` is dropped; a second, non-echoed match at the same or a lower tier may still qualify.
- `str`/`bytes` are normalised losslessly (executors work in `bytes`, `verify_output` in text); the oracle
  defines one internal representation and documents the boundary.
- **Generated scripts (G)** cannot import the product module. The canonical module **emits a self-contained
  oracle snippet** (via `script_builder`) that carries the neutral shape (or `SUPWNGO_FLAG_RE`) *and the same
  per-match anti-echo filter*; the custom generators that currently roll their own regex
  (`oob_read_techniques`, `weak_prng_techniques`, …) are rewired to use that emitted snippet. `weak_prng`'s
  echo-foolable `TOKEN in out` is replaced by the shell-proof probe.

### 2.5 Result and receipt mapping (M2, B2, N1)

`check()` returns a dependency-light `OracleResult(primary_tier, evidence[], matched_value, success,
diagnostics[])`:

- `matched_value` is the **full match** (`group(0)`); operator regexes are never required to expose a capture
  group.
- No-match → `primary_tier=None`, `success=False`, empty `evidence`.
- **Exact tier → receipt-field mapping (M2).** The adapter that builds a `VerificationReceipt` from an
  `OracleResult` sets exactly these fields (B2 — the parent rule wins over "keep existing levels"; an echoed
  token is a diagnostic, never success):

  | `primary_tier` | `VerificationLevel` | `flag` | `shell_confirmed` | `shell_proven` | `matched_requested_token` | `echo_ambiguous` | `success` |
  |---|---|---|---|---|---|---|---|
  | **PLANTED** | `FLAG_CAPTURED` | marker value | from shell evidence if also present, else `False` | from shell evidence | `True` (marker was the requested token) | `False` | `True` |
  | **SHELL-PROVEN** | `SHELL_ACCESS` | `None` | `True` | `True` | `True` if the requested token appeared un-echoed, else `False` | `False` | `True` |
  | **SHAPE** (non-echo capture) | `FLAG_CAPTURED` | matched_value | `False` | `False` | `False` | `False` | `True` |
  | **echoed token only** (no clean tier) | `NONE` | `None` | `True` (the token did appear — echoed) | `False` | `False` | `True` | `False` |
  | **banner word only** (§2.1) | `NONE` | `None` | `False` | `False` | `False` | `False` | `False` |
  | **no match** | `NONE` | `None` | `False` | `False` | `False` | `False` | `False` |

  This reclassifies the current "reflected token ⇒ `shell_confirmed` ⇒ `SHELL_ACCESS` ⇒ success" path
  (`verifier.py:763-785`, `contracts.py:541-554`): `shell_confirmed` (a serialized `bool`,
  `contracts.py:534,564`) is still set `True` when the token appears, but on its own — with
  `echo_ambiguous=True` and no clean tier — it no longer yields a success-bearing level (`success=False`,
  level `NONE`). The echo is recorded in receipt `notes` (e.g. `"token echoed back; no un-echoed proof"`), the
  same channel the existing `echo_ambiguous` note uses. Existing echo-ambiguity tests are updated to assert the
  diagnostic survives serialization while `success` is `False`; historical serialized receipts are not rewritten.
- **`TestConfig.flag_pattern`: preserved, not deprecated (M2 decision).** It stays a supported per-instance
  override (removing a public config field is out of W-3 scope). Precedence is explicit and tested: instance
  `flag_pattern` (when the caller set one) > `SUPWNGO_FLAG_RE` > neutral default.
- `SUPWNGO_FLAG_RE`: compiled-checked; an invalid pattern warns and falls back to the neutral default, and the
  **fallback is visible in `diagnostics`** and tested. The env is read once per `check()` call by exact value
  (deterministic across test/runtime changes).

## 3. Per-entry disposition — exact IDs, all 54 → `migrated` (M3)

The ratchet (W-2 §9, `test_target_value_inventory.py`): entry set + IDs + classes + W-0 frozen-field hash are
frozen; only `status` moves `open → migrated|allowed`, one way. A `migrated` entry's live hit must disappear; an
`allowed` entry keeps its hit with a justification.

**Disposition: 54 migrated, 0 allowed.** The W-3 closure test pins the **exact ID set** from §1, and asserts for
each: `class == "C"`, `status == "migrated"`, `phase == "W-3"`, frozen-field hash unchanged, **and the current
class-C scan is empty**.

Static entries get **dedicated platform-neutral helpers** in the oracle module rather than the runtime
full-match shape, because their semantics differ and must be preserved (M3):

- **`facts.py` (W-0141)** currently redacts on `word{` *and* a prefixless `{abcd}`. A naive swap to the full
  shape (which requires a closing brace + 4 non-space chars) would let a truncated/prefixless flag-like prompt
  escape the fail-safe. The helper preserves prefix-only and prefixless redaction; before/after tests cover
  prefix-only, prefixless braces, `FLAG_...`, and ordinary brace text.
- **`strings.py` (W-0001..0006)** also recognises `FLAG_<alnum>` at `:444` (not one of the six hits but part of
  the function). The classifier helper preserves that behaviour while carrying no platform token; before/after
  tests assert the category labels are unchanged for representative inputs.

The L/R/G runtime entries (the remaining 48) route their success decision through `check()` / the emitted
snippet, deleting their literals. This fixes the echo-foolable `auto.py:1293` and `remote/interaction.py:294`,
and the no-receipt `AttemptOutcome.SUCCESS` in `heap_and_bypass`.

## 4. The lint — "no platform token in any non-comment product string" (M4)

New `scripts/check_platform_tokens.py` + `tests/test_platform_token_lint.py`. AST-walk `supwngo/**/*.py`;
collect `str`/`bytes` constants (including segments inside `JoinedStr` f-strings), **excluding only syntactic
module/class/function docstrings** (AST constants are never comments, so "not on comment lines" is not an
implementation rule — the exclusion is docstrings only). Decode and scan each value. Fail on any platform token:

- Word-bounded tokens `htb`, `hackthebox`, `picoctf`, `csaw`, `asis` (word boundaries so `asis` does **not**
  match `basis`/`OASIS`, verified by test; cf. the benign `"stage3_basis"` at `vector_probe.py:334`).
- Brace shapes `flag{`, `ctf{`, `htb{`, … in both plain (`flag{`) and raw-regex (`flag\{`) forms.

Exemptions, frozen in a table in the test, each with a justification:

- The canonical oracle neutral-shape constant (no platform token by construction — asserted, needs no token
  exemption, only the scanner exemption of §2.2).
- The generated `HackTheBox` banner at `kernel/templates.py:449-460` (`tictacpwn Exploit` /
  `Challenge: HackTheBox tictacpwn`): **decision (M4) — parameterise it, do not exempt.** The banner is
  generated prose, not a success decision, but it carries the `HackTheBox` platform token and would trip the
  lint. W-3 replaces the hardcoded challenge/platform naming with neutral, caller-supplied values (the target
  module name, e.g. `ttp.ko`, and a generic `Generated by supwngo` line); no `HackTheBox`/challenge-platform
  literal remains. The lint then needs **no exemption** for this file. (This is a `kernel/templates.py` edit,
  not a class-C inventory entry — it is swept by the lint, not the ratchet.)
- Comment/docstring HTB references (e.g. `heap_strlen_ofb1_techniques.py` docstrings) are out of scope by the
  docstring/comment exclusion.

Lint tests cover: case variants, raw vs plain brace forms, bytes, f-string segments, docstrings, source
comments, generated-comment strings, `basis`/`OASIS` non-matches, and a deliberately-planted executable
generated-script match (must fail).

## 5. Test matrix (RED-first; no Ghidra needed for these)

**Required** (not "worth adding"):

| Test | Asserts |
|---|---|
| `test_oracle_planted_positive_and_echo_decoy` | the parent Done-when, via the §2.3 controls: real planted-file reader → PLANTED success; reflecting decoy that echoes a qualifying shape → **not** success. |
| `test_oracle_anti_echo_per_match` | a match present in `sent_bytes` is dropped at every tier; a second non-echoed match still qualifies. |
| `test_oracle_tier_precedence` | PLANTED > SHELL-PROVEN > SHAPE when several clean tiers match; a higher match that is echoed yields to a lower clean match. |
| `test_oracle_shell_proof` | arithmetic/strict probes credited; echoing the probe is not (port of `test_shell_proof_markers.py`). |
| `test_oracle_shape_override` | neutral shape matches `X{abcd}`; `SUPWNGO_FLAG_RE` overrides; invalid override warns + falls back, visible in diagnostics; default carries no platform token. |
| `test_oracle_result_and_receipt` | `OracleResult` fields; bytes/text parity; receipt mapping incl. echoed-token → diagnostic with `success=False`, serialization round-trip. |
| `test_oracle_marker_entropy_and_binding` | ≥128-bit, fresh-per-attempt, attempt-A marker fails attempt B, cleanup removes planted state. |
| `test_banner_words_are_not_success` | the `welcome`/`success`/`congratulations` banner false-positive is diagnostic-only, never `success`. |
| `test_w3_inventory_closure` | exact 54-ID set, `class C`, `status migrated`, `phase W-3`, frozen hash unchanged, **empty current class-C scan**. |
| `test_platform_token_lint` | §4 grammar + exemptions; passes on the tree; fails on a planted non-docstring token. |
| `test_scanner_exempts_oracle_constant` | §2.2 exemption against the imported constant; frozen set/hash unchanged; `SCANNER_VERSION == 2`. |
| **Seam tests, one per migration category** | L direct run (multi-send transcript reaches the oracle), L/R pre-screen, G generated script (emitted snippet applies anti-echo), R shell fallback, static classifier (`strings`), redaction filter (`facts`). |

**Gate-can-go-RED proofs:** inject a platform token into a known non-docstring product constant (lint RED), and
break anti-echo against a reflecting process (decoy RED); both in a disposable tree, restored GREEN.

**Regression:** `test_input_vector_delivery`, `test_heapuafread_executor`, `test_fmtstr_write_gate_executor`,
`test_symlink_write_executor`, `test_loop_counter_executor`, `test_receipt_serialises_shell_proof`,
`test_bench_harness_soundness` stay green.

## 6. Execution order — atomic per batch, no knowingly-red commits (B5)

1. Add `core/success_oracle.py` + its focused unit tests (planted, anti-echo, precedence, shell-proof, shape,
   result/receipt, marker). Resolve B1 **in this commit**: scanner exemption + `SCANNER_VERSION=2` +
   `test_scanner_exempts_oracle_constant`. Commit is GREEN.
2. Add `check_platform_tokens.py` + `test_platform_token_lint` with **fixture-level** GREEN/RED self-tests. Do
   **not** yet enable a tree-wide gate that must fail.
3. **Per migration batch** (verification+tester; auto/enhanced_auto/offset_finder/heap_and_bypass; executor
   pre-screens; G script builders; `strings`+`facts`): in **one commit** remove that batch's literals *and* flip
   exactly that batch's baseline rows to `migrated` + `phase: W-3`. Run the existing inventory ratchet after
   every batch (never leaves a removed literal with an `open` row, never leaves an `open` row stale).
4. After the final batch: add `test_w3_inventory_closure` (exact 54, empty class-C scan) and **enable the
   tree-wide platform-token lint gate**; prove each new gate RED with a disposable mutation, restore GREEN.
5. Targeted regressions per batch; the full `SUPWNGO_REQUIRE_GHIDRA=1` gate only once all ordinary gates pass.
6. Docs + CHANGELOG; board W-3 → ✅; PR, merge, cleanup.

## 7. Risks

- **R1 — reclassifying recorded solves.** Preserved *levels* for non-echo evidence; only the echoed-token path
  loses its success credit, as the parent Done-when requires. Flag to reviewer as the one behaviour change.
- **R2 — banner false positives.** Resolved by B3: bare success words are diagnostic-only.
- **R3 — G scripts run outside our process.** They get the emitted neutral-shape snippet + `SUPWNGO_FLAG_RE`
  (the parent "elsewhere … operator can override" branch), with the anti-echo filter baked into the snippet.
- **R4 — static-helper semantics drift.** Mitigated by dedicated neutral helpers + before/after tests for
  prefix-only, prefixless braces, `FLAG_...` (M3).
- **R5 — import topology.** `core/success_oracle.py` imports only the standard library at module scope (the
  dependency runs one way: consumers import the oracle, never the reverse), so no new cycle is possible even
  though `supwngo/__init__.py` eagerly loads the exploit package (§2 "Import topology"). A seam test imports
  `supwngo.core.success_oracle` and asserts the oracle module's own top-level imports include no `supwngo.`
  module.

## 8. Resolved questions

1. Migrate (not `allow`) `strings.py` labels and `facts.py` redaction — with dedicated neutral helpers that
   preserve their distinct semantics, per M3.
2. Canonical shell-proof + marker machinery live in `core/success_oracle.py`; `verifier.py` imports them.
3. `SUPWNGO_FLAG_RE`: compile-checked, warn-and-fallback **visible in diagnostics**, read per call by value.

## 9. — (reserved)

## 10. Finding map (Rev 1 → Rev 2 → Rev 3)

Rev 2 resolved B1–B5, M1, M5, N1–N3 (confirmed by the Rev 2 re-review). Rev 3 closes the three majors the
re-review left PARTIALLY-RESOLVED:

| Finding | Resolution | Re-review status |
|---|---|---|
| **B1** neutral regex is a class-C hit | §2.2 scanner exemption + `SCANNER_VERSION=2` + empty-scan closure assert + import-based scanner test | RESOLVED (Rev 2) |
| **B2** anti-echo vs keep-levels | §2.5 parent rule wins; echoed token → diagnostic, `success=False` | RESOLVED (Rev 2) |
| **B3** retained 4th word-list tier | §2.1 bare success words removed from success decisions → W-0139 migrates | RESOLVED (Rev 2) |
| **B4** no `sent_bytes` contract | §2.4 full-transcript definition, per-match filter, emitted G-script snippet | RESOLVED (Rev 2) |
| **B5** knowingly-red commits | §6 per-batch atomic literal-removal + row-flip; tree-wide lint last | RESOLVED (Rev 2) |
| **M1** PLANTED lifecycle | §2.3 marker record, workspace precondition, real-reader control, qualifying-shape decoy | RESOLVED (Rev 2) |
| **M2** result/receipt underspecified | §2.5 **exact tier→field mapping table** (incl. echoed-token row `shell_confirmed=True`, note in receipt `notes`); `TestConfig.flag_pattern` **preserved** (precedence instance > env > default) | **closed Rev 3.1** |
| **M3** import topology | §2 "Import topology" + §7 R5: oracle is **pure-stdlib, one-way deps**; the "without exploit initializer" goal was unachievable (eager `__init__`) and is dropped for the real no-cycle requirement | **closed Rev 3** |
| **M4** `HackTheBox` banner | §4: **parameterise `kernel/templates.py` banner, no exemption** | **closed Rev 3** |
| **M5** test matrix | §5 controls promoted to required; precedence/parity/override/serialization; gate-RED proofs | RESOLVED (Rev 2) |
| **N1** `SUPWNGO_FLAG_RE` | §2.5 visible fallback, per-call-by-value, full-match value | RESOLVED (Rev 2) |
| **N2** report all evidence | §2.1 primary tier + full filtered evidence set | RESOLVED (Rev 2) |
| **N3** marker entropy/binding | §2.3 ≥128-bit, per-attempt binding, cleanup test | RESOLVED (Rev 2) |
