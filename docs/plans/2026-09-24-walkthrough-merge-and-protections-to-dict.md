# Plan — merge the walkthrough engine, then fix `DetailedProtections.to_dict()`

- **Date:** 2026-09-24
- **Base branch:** `integration/phases-0-4-7-20260923` (`b3a40b4`)
- **Baseline:** `pytest tests/ -q` → **412 passed, 14 skipped** on `b3a40b4`
  (matches the recorded figure at `2ba2698`)

Two independent pieces of work, done in order. Task 1 is a merge and needs
little deliberation. Task 2 changes a serialization contract and gets the
substantive treatment.

---

## Task 1 — merge `feat/walkthrough-engine-20260923`

### Goal

Land the reviewed walkthrough engine (`cfaa24e`) on the integration branch
without disturbing anything already there.

### What is actually being merged

Merge base is `2191739` (`docs(benchmark): record Phase-1 baseline`). Diff of
the walkthrough side against that base:

```
 .gitignore                                        |    1 +
 CHANGELOG.md                                      |   27 +
 docs/plans/2026-09-23-walkthrough-engine.md       |  225 ++
 docs/.../2026-09-23-walkthrough-sample-02-...py   |  782 ++
 supwngo/cli.py                                    |  200 +-
 supwngo/exploit/walkthrough/{__init__,common,
   facts,model,registry,render}.py                 | 3448 ++
 supwngo/exploit/walkthrough/families/{__init__,
   rop_chain,stack_bof,syscall,triage}.py          | 3257 ++
 tests/test_walkthrough_{cli,families,model}.py    | 1703 ++
 19 files changed, 9642 insertions(+), 1 deletion(-)
```

Commits to land: `defc0e8, e99c473, 73263a1, 5b87f7c, f6478b4, c0f73f2,
fc86c27, b523aec, 09bfd38, cfaa24e`.

Note the brief named `09bfd38` as `09bf135` and flagged it as a held-out
corpus branch. `09bf135` is indeed the tip of `feat/benchmark-corpus-r2-20260923`
and is **not** on the walkthrough branch; `09bfd38`
(`fix(walkthrough): stop teaching stack routes with no observed crash`) is a
distinct walkthrough commit that *is* in the lineage and must land. The two
SHAs are only superficially similar. Nothing from
`feat/benchmark-corpus-r2/r3/r4-20260923` enters this merge.

### Method

`git merge --no-ff` (a merge commit, matching how `b3a40b4` itself was
recorded). The alternative — rebasing the walkthrough branch onto the
integration branch — was rejected: the branch is already reviewed at
`cfaa24e`, and rebasing rewrites those ten reviewed commits into ten new
unreviewed SHAs for no benefit. Nothing in this repo requires a linear
history.

### Expected conflict and its resolution

Only `CHANGELOG.md` overlaps (the integration side rewrote 638 lines of it;
the walkthrough side added 27). Both sides append under `## [Unreleased] ###
Added`. Resolution is **additive — keep both sides' entries**, as prior merges
in this repo resolved it. `supwngo/cli.py` is touched only by the walkthrough
side, so it merges clean.

### Verification

- `python3 -c "from supwngo.cli import cli"` and `supwngo --help` /
  `supwngo explain --help` (the new command) resolve.
- `pytest tests/ -q` — expect 412 + the walkthrough branch's own tests, all
  passing, and no regressions in the pre-existing 412.

### Risk

Low. The only shared file is the changelog; a wrong resolution there loses
release notes, not behaviour, and is caught by reading the merged section.

---

## Task 2 — `DetailedProtections.to_dict()` drops 16 of its 22 fields

> **v2.** The first draft of this section was reviewed by an independent
> same-tier peer (gpt-5.6-sol, `model_reasoning_effort=xhigh`) and came back
> **NOT-APPROVED** with eight findings, six of which were factually correct
> and material. The verdict and the resulting changes are recorded at the end
> of this section. Every number below was re-derived by introspecting the
> classes, not carried over from prose.

### The bug

`DetailedProtections` (`supwngo/analysis/protections.py:17-46`) extends
`Protections` with 14 fields and inherits `Protections.to_dict()`
(`supwngo/core/binary.py:72-81`), which hard-codes six keys:

```python
{"canary", "nx", "pie", "relro", "fortify", "aslr"}   # keys only
```

Measured, not asserted:

```
base fields       : 8   canary nx pie relro fortify aslr rpath runpath
subclass-only     : 14  full_relro partial_relro stack_clash_protection
                        safe_stack cfi shadow_stack stack_protector
                        fortify_level pie_type stripped static
                        has_debug_info libc_version uses_tcache
total on subclass : 22
emitted today     : 6
missing           : 16
```

The brief, and the downstream schema plan, both say "roughly 20 fields." The
true figure is **14 added / 22 total / 16 missing**. Corrected here.

`ProtectionAnalyzer.analyze()` (`protections.py:72-108`) assigns exactly
**16** of the 22 — the 6 already emitted plus `full_relro`, `partial_relro`,
`stack_protector`, `fortify_level`, `pie_type`, `stripped`, `static`,
`has_debug_info`, `libc_version`, `uses_tcache`. So ten genuinely measured
facts are computed and then discarded at serialization. `supwngo analyze
--json` does the work and throws it away, and `handoff.py:176-179` already
routes around the dict with `getattr(binary.protections, "static", False)`.

**The six fields `analyze()` never touches** are `stack_clash_protection`,
`safe_stack`, `cfi`, `shadow_stack` (subclass) and `rpath`, `runpath` (base).
Nothing in the tree ever sets them. This matters for the design — see below.

### Consumers of `to_dict()` on these classes (enumerated)

Established in-tree callers:

| Site | Receiver at runtime | Where the dict goes |
| --- | --- | --- |
| `supwngo/cli.py:84` | `DetailedProtections` | `analyze --json` → stdout |
| `supwngo/cli.py:124` | `DetailedProtections` | `analyze` → `<out>/<name>_analysis.json`, written unconditionally, `json.dump(..., default=str)` |
| `supwngo/cli.py:962` | `DetailedProtections` | batch-scan → `--output` JSON file |
| `supwngo/core/binary.py:467` | base `Protections` **today** | `Binary.checksec()` → `supwngo/analysis/static.py:148` → the `"analysis"` block at `cli.py:126` |

On that last row: `checksec()` is `self.protections.to_dict()`, i.e. **dynamic
dispatch**. It takes the base path today only because the sole assignment to
`Binary.protections` (`binary.py:314`) constructs a base `Protections`, and
`ProtectionAnalyzer.analyze()` returns a fresh object instead of mutating the
binary (verified: the only other `.protections =` writes in the package are
`ai/advisor.py:170`, which copies it elsewhere, and
`walkthrough/model.py:599`, an unrelated tuple coercion). That is a property
of the current call sites, **not an invariant** — if anything ever assigns a
`DetailedProtections` to `Binary.protections`, Option A changes `checksec()`
and `StaticAnalyzer` output too.

**Shape-sensitive sinks that nothing currently feeds from `to_dict()`** —
listed because they constrain future work, *not* as established blast radius:

- `supwngo/core/database.py:153,182,211` — `save_binary_analysis(protections:
  Dict[str, Any])` persists a protections dict as a JSON `TEXT` column.
  No in-tree caller passes `to_dict()` output (`tests/test_core.py:128`
  passes a literal).
- `supwngo/reporting/templates.py:40` → `generator.py:250-255` — iterates
  `.items()` and renders every value by bool truthiness as
  `Enabled`/`Disabled`. Nothing populates it from `to_dict()` today. Note
  this renderer is **not** a discriminator between the two options: fed a
  `DetailedProtections` dict, both options misrender it identically.

Checked and genuinely cleared:

- The walkthrough engine just merged in Task 1 reads `binary.protections`
  **attributes** (`walkthrough/facts.py:290-323`, `families/*.py`), never the
  dict. Unaffected either way.
- `PEProtections` / `MacOSProtections` / `ARMProtections` / `MIPSProtections`
  do not inherit from `Protections`.
- No frozen-key-set contract exists for `Protections.to_dict()`. Contrast
  `HandoffReport.to_dict()`, which has a frozen schema, a version constant
  (`handoff.py:32`) and a shape test (`tests/test_pipeline_handoff.py:129`).

### Option A — override `to_dict()` on `DetailedProtections`

Explicit subclass serializer emitting **the 16 fields `analyze()` actually
measures**, with the 6 never-measured fields declared in an explicit
`_UNMEASURED` frozenset and deliberately *not* published.

- Blast radius: the three `cli.py` sites. `Binary.checksec()` → `static.py`
  → the `"analysis"` block keep their exact current shape (subject to the
  dynamic-dispatch caveat above).
- Additive at those three sites: all 6 existing keys keep name, type and
  meaning, so `d["nx"]` readers are untouched.
- The wire shape is written down in one place a reviewer can see in the diff.
- Can express "measured" vs "never measured" — the decisive property.
- Cost: does not structurally prevent a *future* subclass from repeating the
  bug. Mitigated by the partition test below.

### Option B — make the base `to_dict()` introspective

`dataclasses.fields(self)`-driven iteration in the base class, so every
subclass is covered automatically and forever.

- Fixes the class of bug permanently. That is its real attraction, and it is
  a genuine one.
- **But it cannot distinguish measured from never-measured.** It would emit
  `cfi: false`, `shadow_stack: false`, `safe_stack: false`,
  `stack_clash_protection: false` — four hard `false` values that no code
  ever computed. A consumer cannot tell those from `nx: false`, which *was*
  measured. Publishing an unmeasured default as a finding is the same species
  of dishonesty this repo already rejects elsewhere (a check that cannot
  fail, a control that cannot catch anything). This is now the decisive
  objection, and it is one the first draft missed entirely.
- It changes the base-class path too: `checksec()` and therefore `static.py`
  and every saved `_analysis.json` `"analysis"` block gain `rpath` and
  `runpath`. Two keys, not twenty — smaller than the first draft implied, but
  real, verified, and not something Option A does.
- It makes the JSON wire shape an implicit function of the dataclass's field
  list. Adding a derived or private field silently becomes a user-visible
  schema change with no review gate. Wrong direction for a repo that keeps
  one explicit frozen-schema contract and has a standardized-context-schema
  effort in flight.

Arguments **withdrawn** from the first draft as unsound: that the HTML
reporter distinguishes the options (it does not), and that Option B would
change "whatever the DB column has been storing" (nothing feeds it).

### Decision

**Option A**, emitting the 16 measured fields, plus a **partition test** that
recovers Option B's durability without its implicit schema: every
`dataclasses.fields(DetailedProtections)` name must be either emitted by
`to_dict()` **or** listed in the explicit `_UNMEASURED` frozenset. Adding a
field then forces a deliberate choice — publish it, or declare it unmeasured
— and can never silently vanish the way these 16 did.

This also matches what the downstream consumer asked for: the
standardized-context-schema plan
(`docs/plans/2026-09-24-standardized-context-schema.md` on
`docs/context-schema-plan-20260924`) names this as prerequisite (2) and
specifies "give `DetailedProtections` its own `to_dict()`".

**What would flip the decision:** a single generic envelope/serializer
adopted across all 27 `to_dict()` methods by the schema work — then
introspection becomes the consistent mechanism and this override folds into
it. That serializer would still need a measured-vs-unmeasured distinction, so
`_UNMEASURED` (or a provenance wrapper) survives the fold either way.

**Explicitly out of scope** (fix only what demonstrably failed): retyping
`ExploitContext.protections` (`core/context.py:201`); the
two-shapes-for-one-run `analyze` inconsistency; the `generator.py:250-255`
truthiness renderer; and the redundant-representation question raised in
review — `relro` vs `full_relro`/`partial_relro`, `pie` vs `pie_type`,
`fortify` vs `fortify_level` can in principle disagree. `to_dict()` will
**not** reconcile them: a serializer that silently repairs its input hides
analyzer bugs. `analyze()` sets them consistently today; reconciling the
representation belongs to the schema work.

### Files touched

- `supwngo/analysis/protections.py` — `_UNMEASURED` + `DetailedProtections.to_dict()`.
- `tests/test_protections_to_dict.py` — new.
- `CHANGELOG.md` — `### Fixed` under `[Unreleased]`, same commit
  (`analyze --json` output changes, so this is user-visible).

### Test strategy

Five tests. **Three must be demonstrated failing against the unfixed code**
before they count as proof; two are honest regression locks that pass before
the fix and are labelled as such in the file so nobody mistakes them for
evidence.

Fails unfixed (the proof):

1. `test_every_field_is_either_emitted_or_declared_unmeasured` — the
   partition. Pre-fix: fails, 16 fields in neither set.
2. `test_emits_exactly_the_documented_key_set` — `set(to_dict()) ==` the
   explicit expected 16-key set. Pre-fix: fails (6 keys). This is the test
   that locks the schema: it rejects a typo alias, a leaked derived value or
   a stale compatibility key, none of which a "no keys missing" test catches.
3. `test_each_field_reaches_its_own_key` — **one-hot, parametrized per
   field**: for each emitted field, build an instance in which *only* that
   field differs from its default and assert the change shows up at that key
   and at no other. Pre-fix: fails. The obvious alternative — set every
   boolean to `True` and assert every value is `True` — is the defect this
   project has shipped before: it passes even if `"cfi"` is wired to
   `self.static`, because both are `True`. One-hot is what actually detects
   cross-wiring.

Honest locks (pass unfixed, not evidence):

4. `test_values_are_json_native_and_round_trip` — every value is `bool|int|
   str|None` and survives `json.loads(json.dumps(...))` unchanged. Guards the
   `cli.py:124` path, which uses `json.dump(..., default=str)` while the
   `cli.py:84` stdout path does not — a non-native value would stringify in
   one output and raise in the other. Passes pre-fix (the 6 keys are native);
   it is a type-safety guard, not proof of the fix.
5. `test_base_protections_to_dict_is_unchanged` — base `Protections.to_dict()`
   still returns exactly the original 6 keys. Pins the Option-A boundary.

### Risks

- The three `cli.py` JSON sites grow from 6 to 16 protection keys. Additive,
  so any consumer reading known keys is unaffected; a consumer asserting an
  exact key set would break, and none exists in-tree.
- Older `_analysis.json` files stay readable; new ones carry more. No
  migration.
- The 6 unpublished fields stay invisible in JSON. That is intended: they are
  unmeasured. If a detector is ever written for `cfi` or `shadow_stack`, the
  partition test forces moving it out of `_UNMEASURED` in the same change.

### Review record — round 1

Reviewer: gpt-5.6-sol, `model_reasoning_effort=xhigh`, read-only, prompt and
verdict at `/tmp/codex-out/protections-plan-{prompt,review-ab3a}.md`.
Verdict: **NOT-APPROVED**, 8 findings.

Accepted and fixed in v2 (each re-verified against the code first):

- **HIGH, field counts wrong** — "~20 added" was inherited from the brief and
  the downstream plan. Real figures 14/22/16, re-derived by introspection.
- **HIGH, unmeasured fields** — `analyze()` never sets 6 of the 22.
  Serializing them publishes defaults as findings. This inverted the
  Option A/B comparison: Option B *cannot* express the distinction, which is
  now the decisive argument rather than a tiebreak. Drove `_UNMEASURED`.
- **HIGH, the reporter does not distinguish the options** — correct.
  Withdrawn as a reason to prefer A; kept only as a noted hazard.
- **HIGH, DB and reporter overstated as transitive consumers** — correct.
  Demoted to "shape-sensitive sinks nothing currently feeds," and the
  unsupported "whatever the DB column has been storing" claim deleted.
- **HIGH, test weaknesses** — the sharpest finding. "Set every boolean to
  `True`, assert every value is `True`" cannot detect two boolean fields
  wired to each other, exactly the `min(a,b) == expected` defect class this
  repo has been burned by. Replaced with one-hot parametrization. Old test 3
  (JSON round-trip) was also correctly identified as passing unfixed and
  merely re-asserting test 1; it is now a labelled lock, and the schema
  assertion it was smuggling became its own test 2.
- **MEDIUM, tests allowed arbitrary extra keys** — if an explicit schema is
  the justification for Option A, the tests must assert the *exact* key set.
  Now test 2.
- **MEDIUM, `checksec()` is not inherently base-only** — correct; it is
  dynamic dispatch. Reworded to claim only what the current call sites
  guarantee, with the verification that nothing assigns a
  `DetailedProtections` to `Binary.protections`.
- **LOW, `default=str` asymmetry between the two CLI JSON paths** — real.
  Largely defused by not emitting `rpath`/`runpath` (the only plausibly
  non-native fields, and unmeasured anyway); the residue is covered by
  test 4.

Considered and **not** adopted:

- **MEDIUM, redundant representations can contradict** (`relro` vs
  `full_relro`, `pie` vs `pie_type`, `fortify` vs `fortify_level`). Real, but
  reconciling them inside `to_dict()` would make the serializer hide
  analyzer bugs. Documented as out of scope above instead.
