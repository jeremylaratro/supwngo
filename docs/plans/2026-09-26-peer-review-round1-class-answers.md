# Peer Review Round 1 — Answers by Class (26SEP2026)

Round 1 of max 3 for the legacy→canonical port. Per the review protocol, every
finding is answered **by class, not by instance**: each class gets a sweep over
the whole subject, the sweep's **match identity** is stated, and the count is
reported. An unrun sweep is an unmeasured claim, not a managed risk.

Reviewer: Daybreak Blue (Tier 2, cyber, `xhigh`), non-interactive file handoff.

---

## Class 1 — "Provenance conflates origin with necessity"

**Finding.** `VariableOverwriteExecutor` labels a win `recovered_immediate` when
the value is absent from `FALLBACK_MAGIC_VALUES` and `literal_magic_list`
otherwise. A value that is *both* present in the binary's `cmp` immediates *and*
in the fallback list is therefore labeled fallback-only, understating that it was
observed in the target.

**Sweep — class size.** Match identity: `grep -rn "CandidateProvenance("
--include="*.py" supwngo/`, excluding the definition in `contracts.py`.
**Count: 1 construction site** (`stack_techniques.py:137`). This class is a
singleton, not a distributed pattern.

**Sweep — is it reachable in practice?** Match identity: for each target ELF,
replicate `comparison_immediates()`'s own filter (objdump
`cmp|cmpl|cmpq|test $0x…`, keep `0x100 ≤ v ≤ 0xFFFFFFFF`, dedup) and intersect
the recovered set with `FALLBACK_MAGIC_VALUES`:

| target | recovered immediates | overlap with fallback list |
|---|---|---|
| ancient_interface | 2 | `[]` |
| auth-or-out | 1 | `[]` |
| bon-nie-appetit | 1 | `[]` |
| rocket_blaster_xxx | 1 | `[]` |
| sabotage | 2 | `[]` |
| snowscan | 140 | `[]` |

**Total overlap across the corpus: 0.** `measured`.

**Answer — ACCEPTED as correct, triaged as reporting-fidelity.** The reviewer is
right about the logic. The sweep bounds the impact: on this corpus the ambiguous
case **never occurs** (0/6), so no existing label is wrong today. It remains
latent for a binary whose gate constant happens to be CTF folklore (e.g. a target
genuinely comparing against `0xdeadbeef`), where the label would read
`literal_magic_list` although the value was also observed in the code.

Crucially it **cannot produce a false SUCCESS**: the outcome is receipt-backed by
`verify_payload`, and provenance is a descriptive field that `templates.py` is
tested never to read (`test_i3_candidate_provenance.py:308`). So the defect is
confined to how a genuine win is *described*.

Registered as **I-4**, not folded into a sprint, because the fix is a contract
change with its own blast radius (see Class 2) and it is not on the T-1 path.

## Class 2 — "`instruction_address` is never populated"

**Sweep.** Match identity: `grep -rn "instruction_address" --include="*.py" .`
across the entire repo. **Count: 4 occurrences, all inside
`pipeline/contracts.py`** — the field declaration (`:93`) and its three lines of
`to_dict()` rendering (`:99–101`). **Zero production writers, zero readers.**
`measured`.

**Answer — ACCEPTED. The field is declared-but-dead.** The reviewer's finding is
factually confirmed and its scope is now exact.

**Why it is not a one-line fix.** `comparison_immediates()` is typed
`-> List[int]` (`input_shape_techniques.py:68`) and its regex
`\b(?:cmp|cmpl|cmpq|test)\s+\$0x([0-9a-fA-F]+)` captures only the immediate. The
return type structurally cannot carry an address.

**Is the address even available?** Sweep match identity: re-run the same objdump
pass with the leading address group added
(`^\s*([0-9a-f]+):\s+(?:cmp|cmpl|cmpq|test)\s+\$0x…`). Result: **capturable on
6/6 targets** — objdump prints the address on the same line. `measured`. So the
fix is possible, and the blocker is purely the return type.

**Blast radius, measured.** Production consumers of `comparison_immediates()`:
**2** (`stack_techniques.py:101`, `input_shape_techniques.py:240`), plus 3 test
references and one benchmark tool (`benchmark/tools/gate_encoding_matrix.py`).
Changing `List[int]` → an address-carrying type touches all of them.

Registered as **I-4** together with Class 1, since one contract change resolves
both: returning `(value, address)` pairs simultaneously enables
`instruction_address` and makes "was this observed in the binary?" a fact about
the candidate rather than an inference from list membership. Recommended shape
when it is scheduled: replace the derived `source` string with two independent
facts — `observed_in_binary: bool` and `present_in_fallback: bool` — which
removes the conflation by construction instead of adding a third `both` enum
value that callers could still forget to handle.

## Class 3 — "Loop-order swap affects the winning-result fields"

**Finding.** Sprint 1 swapped the nesting from buffer-outer/magic-inner to
magic-outer/buffer-inner. The first verified win is therefore the smallest buffer
for the *first* candidate rather than the first candidate for the *smallest*
buffer, so a recovered candidate winning at a large buffer can preempt a fallback
candidate winning at a smaller one.

**Sweep — class size.** Match identity: AST walk of every module in
`pipeline/executors/`, selecting methods that contain **both** ≥2 `for` loops
**and** a `verify_payload` call, then testing for actual nesting.
**Count: 1 nested candidate×size sweep in the codebase** —
`VariableOverwriteExecutor.attempt`. (One further method matched on loop count but
is two *sequential* loops, not a product.) `measured`.

**Sweep — which fields does the winning branch set?** Match identity:
`grep -n "record\.\w* *=" stack_techniques.py`, lines 127–137. **6 fields**:
`outcome`, `stage_reached`, `payload`, `offset`, `receipt`,
`candidate_provenance`. (The review said 5; the sixth is `stage_reached`.)

**Sweep — does anything re-derive a payload from the reported offset?** Match
identity: `grep -rn "offset"` across `templates.py` and `script_builder.py`, the
whole artifact-generation path. Result: `record.offset` is consumed at exactly
**one** place, `templates.py:141`
(`offset_note = f"Offset: {record.offset}"`) — a **human-readable docstring
line**. The other hits use `context.offset`, a different field, inside a
TODO-marked generic template. The verified payload itself is carried in
`record.payload` and is what the artifact uses. `measured`.

**Answer — ACCEPTED as a reporting-semantics issue, REJECTED as a correctness
issue.** Both orderings return a win that `verify_payload` confirmed, so neither
is false and no SUCCESS is at risk. What the reviewer correctly identifies is that
`record.offset` is "the buffer size that worked first under the current ordering",
and the ordering makes that **not** the minimal overflow distance. Since its only
artifact consumer is a docstring note, the impact is that a human reading the
generated script may infer minimality that was never claimed.

**Action taken:** registered as **I-5** and the ordering rationale is to be stated
at the loop rather than left implicit. **The swap is kept**, on a stated ground:
it is what makes the recovered-candidate-first ordering meaningful — with
buffer-outer nesting, all 9 folklore values are tried at every buffer size before
any recovered value is reached at any size, which is precisely the behavior G-1
exists to remove. That is a capability justification, not a metric one, and it is
labeled as such.

## Class 4 — "M-2 is too noisy; M-3's units are mislabeled"

**Sweep.** Match identity: read every metric definition in
`2026-09-26-legacy-to-canonical-sprint-plan.md` and check each for (a) a unit
word, (b) rep count, (c) whether the harness is oracle-assisted.

**M-3 — ACCEPTED, already corrected.** The metric said "spawns" while the bound
it enforces counts **candidate payloads**. A failed `verify_payload()` may launch
the target more than once (`verification.py:241` then the pwntools retry at
`:281`), so spawns are a *multiple* of the counted quantity, not equal to it. The
correction is written at the point of use in
`tests/test_variable_overwrite_budget.py:22–25` and the gate asserts candidate
payloads, which is the quantity the cap actually controls.

**M-2 — ACCEPTED, withdrawn as a benefit metric.** It was 7 targets × 1 run with
hand-picked `--strategy` flags. Hand-picking the strategy supplies the technique
choice from outside the tool, so the number measures *oracle-assisted* capability,
not what the pipeline does unaided — it cannot support a claim about the tool. One
run also gives no spread. M-2 is demoted to a diagnostic matrix (useful for
locating which technique is blocked) and is **not** cited in any Phase-8 benefit
claim. Sprint 2′ replaces it with M-4 (a structural impossibility → solved proof),
M-6 (the 13/13 corpus baseline, compared **per target**) and M-7.

---

## New items registered by this round

| ID | Item | Relevance | Complexity | Priority | Lane |
|---|---|---|---|---|---|
| **I-4** | Provenance conflates origin with necessity **and** `instruction_address` is dead. One contract change (`comparison_immediates() -> List[int]` → value+address pairs; `source` → `observed_in_binary`/`present_in_fallback`) resolves both. | 2 — describes a win, cannot cause one; 0/6 corpus reachability | 3 — 2 production consumers + 3 test refs + 1 benchmark tool | **P2** | `later` |
| **I-5** | `record.offset` reads as a minimal overflow distance but is "first win under the current ordering". Sole artifact consumer is a docstring note. | 1 — human-readable note only | 1 — state the rationale at the loop | **P3** | `document-and-move-on` |

Neither is promoted into Sprint 2′: both are reporting-fidelity, and mixing them
into a sprint scoped to the argv/file channel would break the one-triage-band-per-
sprint rule and make the sprint untestable in isolation.
