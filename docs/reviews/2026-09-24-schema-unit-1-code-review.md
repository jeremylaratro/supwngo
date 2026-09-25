# Schema unit 1 — post-implementation CODE review (final round)

**Date:** 2026-09-24
**Reviewer:** codex `gpt-5.6-sol`, `model_reasoning_effort=xhigh`, `--sandbox read-only`
**Subject:** the **implemented code**, not the plan. The plan was reviewed to
convergence (`NEW` 0 for three consecutive rounds, every round-2 `INTRODUCED`
finding a re-created instance of an already-named class), so round 4 escalated to a
change of artifact rather than a fourth prose round. The reviewer was told this
explicitly and told its job was to find where the code and the contract disagree.
**Code under review:** `ad6b8b3..f2eeaab` (9 commits) on
`feat/context-schema-v4-20260924`; docs at `9a04aea`.
**Prompt:** 343906 bytes, every artifact **inlined** with "Do NOT
read any files" — so the reviewer cannot silently review a different tree. It
confirmed compliance in its first line and cited `file:function` plus verbatim
lines rather than inventing line numbers, which is the correct response to an
inlined artifact with no gutter.
**Output:** asserted **non-empty before reading** — `OUTPUT_NONEMPTY bytes=14008`,
`CODEX_RC=0`. Exit 0 with an empty file reads as "approved" and silently skips the
review, which has happened before.

## Verdict as filed

**NOT-APPROVED. RECURRENCES 8 / NEW 0 / INTRODUCED 6.**

`NEW 0` for a **fourth** consecutive round — but note what changed: this round the
zero means something different. The three plan rounds returned `NEW 0` because the
*classes* had converged and the reviewer had nothing left to name. This round
returned `NEW 0` while finding **four confirmed HIGH defects in shipped code**. The
classes were indeed all already named; the instances were not, and no amount of
further prose review would have found them, because they are properties of code
that did not exist yet. That is the evidence that the escalation to a code review
was the right call rather than a way of ending the loop.

## My verification — candidates, not findings

A sweep yields candidates. Four of my own witnesses were withdrawn earlier in this
same session, so the rule is not a formality. Every finding was checked against the
code before being accepted:

| # | finding | severity | my verdict |
| --- | --- | --- | --- |
| F1 | public `canonical()` bypasses the open encoder | HIGH | **CONFIRMED** — `canonical((1,2)) == canonical([1,2]) == "[1,2]"`, and `canonical(Scope.BUILD) == canonical("build") == "\"build\""` |
| F2 | `Observation.digest()` collides via a structural enum at `at` | HIGH | **CONFIRMED** — `Observation(Scope.BUILD) != Observation("build")` yet both digest `{"at":"build","evidence":[]}`, and `_merge_observations` returns **1**, dropping one |
| F3 | C2's refusal table omits type/depth cells | MEDIUM | **CONFIRMED as a test-coverage gap only.** I measured all seven omitted families — plain `Enum`, dataclass, `bytes`/`int`/`str` subclasses, nested dataclass, nested bytes subclass — and the encoder **refuses every one**. So the code is right and the table is narrow. The reviewer drew that distinction itself, which the brief asked for |
| F4 | C3's "generated-domain property" is a fixed list | MEDIUM | **CONFIRMED** — and independently found by me before the review returned; I had already recorded it as an outstanding LOW in §12 |
| F5 | C7 enforced globally by registered type, not per position | HIGH | **CONFIRMED** — a `Candidate` carrying an `Observation` in its `applies_to` field is accepted by public `derive_id`, returning `f_69ef452e4651c390767165f1a97278fc` |
| F6 | C8's identity clause asserted with `==` | MEDIUM | **CONFIRMED as a weak test; production code is correct.** I had separately verified `by_id(c.id) is c` by hand, so the code satisfies clause (b) — but `dataclasses.replace(c) == c` while `is not c`, so the *assertion* would pass against a stale copy |
| F7 | the compatibility break ships under schema v1 | HIGH | **CONFIRMED** — tuple evidence is now refused (`not canonicalisable at an open position: tuple`) while documents still emit `"schema_version":"supwngo.context/v1"`. C9's own text requires the version to move and a migration to ship |
| F8 | C10's test hard-codes five functions instead of deriving `__all__` | LOW | **CONFIRMED** — and independently found by me, which is *why* I enumerated `__all__` myself and discovered `try_resolve`, a consumer this plan names nowhere |

**8 of 8 confirmed. 0 rejected.** Two of the eight (F4, F8) I had already found
independently; the other six I had not, and three of those are HIGH.

### The sharpest finding, and why I missed it

F2 indicts a change I had specifically praised. The enum-first dispatch ordering in
`_jsonable_structural` is load-bearing and correct *for its stated purpose* — it
stops an `IntEnum` being encoded as a bare int. But it applies to **every**
structural position, including `Observation.at`, whose declared type is `str`. So
passing `Scope.BUILD` where a timestamp belongs is silently encoded as `"build"`,
colliding with the genuine string. I read that arm, reasoned about the ordering,
and checked it against the collision it was designed to prevent rather than against
the positions it would now apply to. The reviewer checked the arm against the
schema; I checked it against its own rationale.

F1 and F5 share one root with F2: **a structural position's declared type is
assumed rather than enforced.** F5 is the same defect one level up (a registered
dataclass at the wrong position), F1 the same defect at the root (no declared
position at all, so a caller-supplied tuple takes the structural path). All three
are instances of the class the reviewer named "admission/routing mismatch" — which
is the class I found and fixed once already this session, at the dataclass arm. I
fixed the instance and did not sweep the class across positions.

---

## The review, verbatim

I did not read any files. The pasted source has no numeric gutter, so I use `file:function` plus a unique verbatim line rather than inventing physical line numbers.

### Contract-row audit

| Row | Enforcement in code/tests | Breadth | Reachable counterexample while tests pass? |
|---|---|---|---|
| C1 | `_jsonable_open`: `"if t is bool or t is int or t is str:"`; P21. But `canonical`: `"return json.dumps(_jsonable_structural(obj), sort_keys=True,"` | Wider than declared at the public root: bare values bypass the open encoder. | **Yes:** `canonical((1, 2)) == canonical([1, 2])`. |
| C2 | `_jsonable_open` ends with `"raise SchemaError(f\"not canonicalisable at an open position: {t.__name__}\")"`; validation calls `"_jsonable_open(ev_value)"`. | Correct for validated evidence slots, but not for public root `canonical`; the behavioural table is also incomplete. | **Yes:** bare tuple/enum inputs reach the structural encoder. Some enums with non-JSON values leak incidental `TypeError` from `json.dumps`. |
| C3 | `canonical` has no mutable state; the three golden-file purity tests call `_purity_domain()`. | Runtime code appears pure, but `_purity_domain` is a fixed example list, not a generated recursive domain. | No current impure input established, but the claimed universal enforcement is absent. |
| C4 | `DERIVED_FIELDS`: `"DERIVED_FIELDS: Tuple[str, ...] = (\"observations\", \"state\")"`; P10 checks both derived fields leave both digests unchanged. | Matches C4. | No. |
| C5 | `Observation.digest`: `"return _sha(canonical(self))"`; `_merge_observations` keys on `"o.digest()"`; P31 is the positive control. | Wider than the validated-observation domain because the public constructor and `digest()` perform no structural-field validation. | **Yes:** `Observation(Scope.BUILD)` and `Observation("build")` are unequal but have the same digest. |
| C6 | `_raise_site_inventory`, `_run_instrumented`, and `test_refusal_coverage_census`; output includes `"REFUSAL-SITE CONTROL COVERAGE -- NOT a proof of accepted-domain closure"`. | Matches C6, including declared out-of-scope reporting. | No. |
| C7 | `_STRUCTURAL_DATACLASSES`; exact membership line `"if type(obj) in _STRUCTURAL_DATACLASSES:"`; reserved-field runtime guard; C7 tests. | Exact only globally, not per structural position. The “one type per position” test compares field-name sets instead of annotations/positions. | **Yes:** a public `Candidate` with `Observation` in its `applies_to` field is accepted by public `derive_id`. |
| C8 | `_candidate_id_index`, `FactStore.by_id`, and `_validate_log`. The loop includes `all_candidates()`, raises on duplicates, and stores the original object. | Production code implements (a)–(f). P29 proves mostly duplicate refusal; its successful lookup uses equality rather than identity. | No counterexample in current production code; the required six-clause test gate is incomplete. |
| C9 | Golden vectors cover canonical bytes, IDs, dependency digests, log IDs and a document. | Retained bytes are pinned, but the deliberate compatibility break ships under the unchanged v1 schema identifier. | **Yes:** formerly accepted tuple evidence now raises `SchemaError`, while documents still emit `supwngo.context/v1`. |
| C10 | Current context consumers are `applicable`, `resolve`, `try_resolve`, `conflicts`, and `agreements`; each reaches `validate_context`. P28 calls all five. | Correct today, but P28 hard-codes the set instead of deriving `__all__ ∩ takes-ResolveContext`. | No current counterexample; future additions can evade the promised gate. |

FINDING   HIGH — public `canonical()` bypasses the declared open-domain encoder  
WHERE     `supwngo/schema/resolve.py:canonical`, quoting `"return json.dumps(_jsonable_structural(obj), sort_keys=True,"`  
CONTRACT  C1, C2  
WHY       The public calls `canonical((1, 2))` and `canonical([1, 2])` both succeed and produce the same JSON array. The tuple is neither refused nor sent through `_jsonable_open`. Likewise a bare enum is handled by the structural enum arm. An enum whose `.value` is `bytes` reaches `json.dumps` and raises incidental `TypeError`; that is a crash, not the module’s `SchemaError` refusal.  
TEST      P21 tests refused values only through `canonical(Observation(...evidence...))`, where `_jsonable_evidence_field` does call `_jsonable_open`. Its earlier bare-`canonical` cases contain no tuple, enum, dataclass, set, or builtin subclass, so the public-root path passes every test.  
CLASS     Positional admission/routing mismatch: a caller-controlled value reaches the structural encoder instead of the open encoder.  
SWEEP     Searched every inlined occurrence of `_jsonable_open(`, `_jsonable_structural(`, and `canonical(`. `_jsonable_open` is reached from `_jsonable_evidence_field`, the validation gate, and its own recursion; the public `canonical` entry point unconditionally selects `_jsonable_structural`. The same bypass therefore affects direct users including the purity tests.

FINDING   HIGH — `Observation.digest()` accepts a wrong structural type and collides  
WHERE     `supwngo/schema/resolve.py:_jsonable_structural`, quoting `"if isinstance(obj, enum.Enum):            # FIRST -- see the note above."`  
CONTRACT  C5  
WHY       `Observation(R.Scope.BUILD)` and `Observation("build")` are unequal observations a caller can construct through the exported class. The first `at` value is converted to `Scope.BUILD.value`; the second is already `"build"`. Both digest the same bytes. Neither is refused: both calls succeed.  
TEST      P31 uses the same valid string timestamp and varies only evidence values. P21 also fixes `at="t1"`. Consequently neither exercises a distinguishable structural-field type at `Observation.at`.  
CLASS     A schema-fixed position is assumed rather than enforced at a public digest boundary. This is another instance of the named admission-versus-routing class.  
SWEEP     Searched the inlined source for `Observation(`, `def digest`, `observation.at`, and `_jsonable_structural`. `validate_candidate` does enforce `"if not isinstance(at, str) or not at:"`, but the public `Observation.digest()` path never calls it. Other structural enum-bearing paths have the same global enum arm, but this is the direct C5 witness.

FINDING   MEDIUM — C2’s required refusal table omits several type/depth cells  
WHERE     `tests/test_context_resolve_properties.py:prop_P21_canonicalisation_is_injective`, quoting `"refused_open_values = ["`  
CONTRACT  C2  
WHY       The contract requires plain enum, `IntEnum`, `StrEnum`, tuple, set, dataclass, float, and primitive subclasses, each at the root and nested. The list has `IntEnum`, `StrEnum`, tuple, set/frozenset, float, list subclass and dict subclass, but no plain enum, dataclass, custom int/str/bytes subclass, bytes subclass, or nested forms for most families. An encoder widened only for a nested dataclass or nested bytes subclass would make C2 false while this suite stayed green.  
TEST      P21 exists but is narrower than its contract. The assertion is not vacuous for listed values; the defect is missing table rows. The mutant table mirrors the omission: it restores only tuple, primitive `isinstance`, and list-subclass admissions.  
CLASS     Remedy extent narrower than diagnosis extent in a multi-arm, multi-depth policy.  
SWEEP     Searched the refused-value fixture, all P21 helper classes, and all open-domain mutants for `Enum`, `dataclass`, subclasses of `int`, `str`, `bytes`, `dict`, and `list`, at root and nested positions. Only enum members are tested nested; several required families have no witness at either depth.

FINDING   MEDIUM — C3’s “generated-domain property” is a fixed vector list  
WHERE     `tests/test_context_resolve_golden.py:_purity_domain`, quoting `"return ["`  
CONTRACT  C3  
WHY       `_purity_domain` returns a finite hand-written list. The three purity tests permute, repeat, and interleave only those objects. An implementation carrying call-history state only for an unlisted legal value—such as a deeper legal dict/list nesting—would violate C3 while every purity and golden test passed.  
TEST      `test_purity_repeated_calls_agree`, `test_purity_interleaved_calls_agree`, and `test_purity_independent_of_call_order` can fail, but only on the fixed list. Calling that list a property “over a generated domain” does not supply the domain-quantifying gate named by C3.  
CLASS     Finite examples named as enforcement of a universal property.  
SWEEP     Searched the complete golden file for generators, recursive constructors, Cartesian products, and uses of `_purity_domain`. All three tests consume the same fixed list; `itertools.product` varies call order, not values.

FINDING   HIGH — C7 is enforced globally by registered type, not per structural position  
WHERE     `supwngo/schema/resolve.py:_jsonable_structural`, quoting `"result[f.name] = _jsonable_structural(value)"`  
CONTRACT  C7  
WHY       The recursion carries no expected field annotation or permitted dataclass type. A caller can construct a public `Candidate` whose `applies_to` field is an `Observation` and pass it to public `derive_id`; the dict projection reaches the quoted recursion, and `Observation` is globally registered, so encoding succeeds even though that position permits only `AppliesTo`.  
TEST      `test_c7_one_type_per_structural_position` calls `_check_c7_one_type_per_structural_position`, but that helper only compares dataclass field-name sets. P32 proves subclasses are refused globally; it does not place one registered exact type in another type’s position.  
CLASS     Global admission registry substituted for per-position schema enforcement. This is the named remedy-extent/admission-routing mismatch.  
SWEEP     Searched `_STRUCTURAL_DATACLASSES`, all registry additions, `dataclasses.fields`, `typing.get_type_hints`, and the C7 helpers. `get_type_hints` is used only by the set-annotation check. No check maps a structural field position to its one permitted dataclass type. The reserved-tag half is separately enforced both statically and at runtime.

FINDING   MEDIUM — C8’s identity clause is tested with equality, and four clauses lack direct gates  
WHERE     `tests/test_context_resolve_properties.py:prop_P29_candidate_id_index_is_a_bijection`, quoting `"assert s2.by_id(a.id) == a"`  
CONTRACT  C8  
WHY       Replacing `_candidate_id_index`’s value with `dataclasses.replace(c)` makes `index[c.id] == c` true but `index[c.id] is c` false. The quoted assertion still passes. P29 directly proves duplicate refusal in three readers, but it does not separately assert totality, identity, declared unknown-ID absence, or a successful terminal-candidate lookup.  
TEST      P29 exists, but the quoted equality assertion is vacuous with respect to clause (b): a stale equal copy satisfies it. The duplicate fixture indirectly involves a terminal candidate, but that proves rejection of a duplicate, not clause (f)’s successful terminal bijection.  
CLASS     Testing the contrapositive/duplicate half of a bijection while omitting totality and identity.  
SWEEP     Searched all inlined tests for `_candidate_id_index`, `by_id(`, identity assertions using ` is `, unknown IDs, and terminal lookups. P8 uses identity for resolution witnesses, not the ID index. Other `by_id` tests use equality, non-`None`, or state checks; none asserts `by_id(cid) is stored_candidate`.

FINDING   HIGH — the deliberate compatibility break still emits schema v1  
WHERE     `supwngo/schema/resolve.py:canonical_document`, quoting `"\"schema_version\": \"supwngo.context/v1\","`  
CONTRACT  C9  
WHY       Tuple, enum, dataclass, set, float and subclass evidence accepted by the pre-change implementation are now refused by the module’s own `SchemaError`, which the contract explicitly classifies as a compatibility break requiring a schema-version bump and migration. Yet every valid document still advertises `supwngo.context/v1`.  
TEST      P21 expects the new refusals, while `test_golden_canonical_document_small_store` explicitly expects `'"schema_version":"supwngo.context/v1"'`; therefore the two tests jointly bless the break without the required version change. The golden assertions are not vacuous, but they enforce the wrong combined outcome.  
CLASS     Breaking the accepted domain without changing the published schema identity.  
SWEEP     Searched all inlined occurrences of `schema_version` and `supwngo.context/v1`; the runtime emitter and golden document both retain v1, and no schema-version test ties a domain refusal to a bump. `CHANGELOG.md` was listed in the diffstat but not inlined, so I could not assess the required migration note; I would have searched it for the old accepted types, the new version identifier, and migration instructions.

FINDING   LOW — C10’s test covers today’s five functions but does not enumerate `__all__`  
WHERE     `tests/test_context_resolve_properties.py:prop_P28_every_context_consumer_validates_it`, quoting `"for fn_name, call in ("`  
CONTRACT  C10  
WHY       The tuple hard-codes `applicable`, `resolve`, `try_resolve`, `conflicts`, and `agreements`. Adding another `__all__` function with a `ResolveContext` parameter that omits validation would leave P28 unchanged and green, contrary to the promised whole-set gate.  
TEST      P28 correctly covers every current member, so no current consumer escapes. Its claim to enumerate the exported set is nevertheless unsupported because it never reads `R.__all__` or signatures.  
CLASS     A hand-maintained example list substituted for a mechanically derived public-API census.  
SWEEP     Enumerated the supplied `__all__` and searched the exported function signatures for `ResolveContext`: the current set is exactly the five P28 calls. Searched P28 for `__all__`, `inspect.signature`, and annotation inspection; none occurs.

NOT-APPROVED

RECURRENCES  8  
NEW          0  
INTRODUCED   6
