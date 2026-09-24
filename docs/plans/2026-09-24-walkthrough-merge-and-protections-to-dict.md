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

## Task 2 — `DetailedProtections.to_dict()` loses ~20 measured fields

### The bug

`DetailedProtections` (`supwngo/analysis/protections.py:17-46`) extends
`Protections` with 20 fields and inherits `Protections.to_dict()`
(`supwngo/core/binary.py:72-81`), which hard-codes six keys:

```python
return {"canary", "nx", "pie", "relro", "fortify", "aslr"}  # keys only
```

`ProtectionAnalyzer.analyze()` measures and populates `fortify_level`,
`stripped`, `static`, `has_debug_info`, `stack_protector`, `full_relro`,
`partial_relro`, `pie_type`, `libc_version`, `uses_tcache` — every one of
which is dropped on the floor the moment the result is serialized. So
`supwngo analyze --json` performs work it then throws away, and
`handoff.py:176-179` already works around the gap by reaching past the dict
with `getattr(binary.protections, "static", False)`.

### Consumers of `to_dict()` on these classes (enumerated)

Direct callers:

| Site | Receiver type | Where the dict goes |
| --- | --- | --- |
| `supwngo/cli.py:84` | `DetailedProtections` | `analyze --json` → stdout |
| `supwngo/cli.py:124` | `DetailedProtections` | `analyze` → `<out>/<name>_analysis.json`, written unconditionally |
| `supwngo/cli.py:962` | `DetailedProtections` | batch-scan → `--output` JSON file |
| `supwngo/core/binary.py:467` | base `Protections` | `Binary.checksec()` |

Transitive:

- `supwngo/analysis/static.py:148` — `StaticAnalyzer.analyze()["protections"]
  = self.binary.checksec()`, i.e. the **base** class path. Flows on into
  `cli.py:126`'s `"analysis"` block.
- `supwngo/core/database.py:153,182,211` — `save_binary_analysis(protections=
  Dict[str, Any])` persists the dict as a JSON `TEXT` column and
  `get_binary_analysis()` reads it back with `json.loads`. No in-tree caller
  currently feeds it from `to_dict()` (`tests/test_core.py:128` passes a
  literal), but it is a **persistence** path: rows written before a shape
  change and read after it must still parse. Additive key changes are safe
  here; renames and removals are not.
- `supwngo/reporting/templates.py:40` (`protections: Dict[str, Any]`) →
  `supwngo/reporting/generator.py:250-255`, which iterates `.items()` and
  renders *every* value by bool truthiness as `Enabled`/`Disabled`. No
  in-tree code populates it from `to_dict()` today, but this is the consumer
  most hostile to extra keys — see the blast-radius argument below.

Not consumers, checked and cleared:

- The walkthrough engine reads `binary.protections` **attributes**
  (`walkthrough/facts.py:290-323`, `families/*.py`), never the dict, so it is
  unaffected by either option.
- `PEProtections` / `MacOSProtections` / `ARMProtections` / `MIPSProtections`
  are unrelated classes that do not inherit from `Protections`.
- Nothing asserts a frozen key set for `Protections.to_dict()`. Contrast
  `HandoffReport.to_dict()`, which *does* have a frozen schema plus a version
  constant (`handoff.py:32`) and a shape test
  (`tests/test_pipeline_handoff.py:129`). This class has no such contract, so
  the change is not schema-breaking by that repo's own standard.

### Option A — override `to_dict()` on `DetailedProtections`

Give the subclass an explicit `to_dict()` returning the base six keys plus
its own fields (and the two base fields the base method omits, `rpath` /
`runpath`, which are genuinely security-relevant measurements).

- Blast radius: the three `cli.py` sites only. `Binary.checksec()`,
  `static.py`, and therefore the `"analysis"` block, keep their **exact**
  current shape.
- Strictly additive at the three sites: every existing key keeps its name,
  type and meaning; readers of `d["nx"]` are untouched.
- Reviewable — the wire shape is written down in one place and a reviewer can
  see it in the diff.
- Cost: does not fix the *class* of bug. A future `Protections` subclass
  repeats it. Mitigated below.

### Option B — make the base `to_dict()` introspective

Replace the hand-written body with `dataclasses.fields(self)`-driven
iteration, so every subclass is covered automatically and forever.

- Fixes the class of bug permanently, which is its real attraction.
- But it changes output for **every** consumer of `to_dict()`, including the
  base-class path: `Binary.checksec()` and `static.py:148` gain `rpath` and
  `runpath`, so the `"analysis"` block in every saved `_analysis.json`
  changes too, and so does whatever the DB column has been storing.
- It hands the HTML reporter (`generator.py:252`) ~20 extra rows rendered
  with bool truthiness. `stack_protector=""` renders as
  `stack_protector: Disabled`, `fortify_level=0` as `fortify_level: Disabled`,
  and a *detected* `libc_version="2.35"` as `libc_version: Enabled`. Not a
  crash — actively false output. Option A leaves that renderer alone; Option B
  would require fixing it too, widening the change.
- The decisive objection: it makes the JSON wire shape an implicit function
  of the dataclass's internal field list. Adding a private/derived field, or
  renaming one, silently becomes a user-visible, changelog-worthy schema
  change with no review gate. That is the wrong direction for a repo that
  already keeps one explicit frozen-schema contract and has a
  standardized-context-schema effort in flight.

### Decision

**Option A**, plus a coverage guard that buys Option B's durability without
its implicit schema: a test asserting that **every** dataclass field of
`DetailedProtections` appears as a key in `to_dict()`. Adding a field without
extending `to_dict()` then fails the suite instead of silently regressing.

This also matches what the downstream consumer asked for. The
standardized-context-schema plan
(`docs/plans/2026-09-24-standardized-context-schema.md` on
`docs/context-schema-plan-20260924`) names this as prerequisite (2) and
specifies "give `DetailedProtections` its own `to_dict()`".

**What would flip the decision:** if that schema work lands a single generic
envelope/serializer covering all 27 `to_dict()` methods, introspection
becomes the consistent mechanism rather than a one-off, and this override
should be folded into it — together with a fix to `generator.py:250-255` so
it stops rendering non-boolean values as `Enabled`/`Disabled`. Until such a
serializer exists, one explicit override beats changing every consumer.

**Explicitly out of scope** (scope discipline — fix only what demonstrably
failed): retyping `ExploitContext.protections` (`core/context.py:201`), the
two-shapes-for-one-run `analyze` inconsistency, and the
`generator.py` truthiness renderer. All three belong to the schema work.

### Files touched

- `supwngo/analysis/protections.py` — add `DetailedProtections.to_dict()`.
- `tests/test_protections_to_dict.py` — new.
- `CHANGELOG.md` — `### Fixed` under `[Unreleased]`, same commit
  (`analyze --json` output changes, so this is user-visible).

### Test strategy

Four tests; the first three must be demonstrated **failing against the
unfixed code** before they count as proof.

1. `test_to_dict_covers_every_measured_field` — every
   `dataclasses.fields(DetailedProtections)` name is a key in `to_dict()`.
   Pre-fix: fails, ~22 missing.
2. `test_to_dict_preserves_measured_values` — build an instance with a
   distinct, non-default value in each field; assert every value survives
   `to_dict()`. Pre-fix: fails (values absent). This is the test that proves
   *no loss*, as opposed to merely *presence*.
3. `test_to_dict_survives_json_round_trip` — `json.loads(json.dumps(...))`
   equals the dict, and the detailed fields are still there after the trip.
   Pre-fix: fails. Guards the `cli.py:124` / `database.py` persistence paths.
4. `test_base_protections_to_dict_shape_is_unchanged` — base
   `Protections.to_dict()` still returns exactly the six original keys.
   **This test passes before the fix.** It is an honest regression lock on
   the Option-A boundary (base path untouched), *not* evidence the bug was
   fixed, and is labelled as such in the file.

### Risks

- The three `cli.py` JSON sites grow keys. Additive, so any consumer reading
  known keys is unaffected; a consumer asserting an exact key set would
  break, and none exists in-tree.
- `_analysis.json` files written by older runs stay readable; new ones carry
  more. No migration needed.
