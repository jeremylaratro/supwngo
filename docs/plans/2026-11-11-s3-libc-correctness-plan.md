# S3 — libc correctness (CG-01, CG-02) — execution plan (rev 2, post-review)

Sprint S3 of the retest gap-closure effort (master plan:
`docs/plans/2026-11-11-retest-gap-closure-plan.md`). Base = main at `dc22067`
(S2 merged). Branch `fix/retest-s3-libc-correctness`.

Repo contract: author `jay <jlaratro24@gmail.com>`, **no** Claude/Anthropic
trailer, Conventional Commits, CHANGELOG under `## [Unreleased]` same commit,
PRs opt-in (merge locally, push main).

## Research findings (measured this session)

1. **No pipeline executor consumes `DEFAULT_LIBC_VERSION` for offset selection.**
   A full grep of `exploit/pipeline/` confirms none of the version-parameterized
   library classes is reached from an executor with a defaulted version; the
   inline heap/FSOP executors resolve the real version via
   `libc_version(local_libc_path(context))` and skip/`INCONCLUSIVE` when it is
   unresolvable. The independent Tier-2 review (below) re-audited this and agreed.

2. **`DEFAULT_LIBC_VERSION = "2.31"` is a silent hazard on the standalone public
   library API** (`supwngo.exploit.heap`, `supwngo.exploit.fsop`,
   `supwngo.vulns`). Concrete confidently-wrong offset sites:
   - `TcachePerThreadStruct.__post_init__` struct offsets — `minor < 30` →
     `0x40/0x250` else `0x80/0x290` (`tcache.py:52-61`); `_parse_version` falls
     back to `(2,31)` on malformed input (`tcache.py:64-68`).
   - `FSOPExploiter.malloc_hook_attack` / `free_hook_attack`:
     `hook_offsets.get(self.version, 0x3ed8e8)` — unknown version silently uses
     the **2.31** hook offset (`fsop.py:250-257`, `:292-299`).
   - `TcacheExploiter.hook_overwrite_targets` fallback table labelled 2.27
     (`tcache.py:401`).
   Feature/verdict (non-byte) sites that still fabricate a 2.31-derived answer:
   `HeapExploiter.select_technique` (`techniques.py:84-113`), `HouseOfSpirit`
   tcache-vs-fastbin + size validation (`house_of_spirit.py:78,111`),
   `NullByteExploiter` feasibility verdict (`off_by_one.py:505`), `HouseOfStorm`
   feasibility (`large_bin.py:501`).

3. **A correct `--libc`/loaded-libc mismatch detector is entangled with
   loader-threading (CG-04) and is NOT a sprint item.** Per the review: the
   verifier can *strip* `LD_LIBRARY_PATH` when it blocks the interpreter
   (`verifier.py:159`) and generated `open_target()` does not re-thread the
   republished `SUPWNGO_TARGET_*` loader vars (`script_builder.py:88`), so the
   target can load the *host* libc while offsets came from the shipped/`--libc`
   one. `local_libc_path` returns `--libc` **first** (`_shared.py:208`), so it
   cannot by itself mean "the libc actually loaded." A sound detector needs:
   loader-threading, a runtime-libc resolution independent of `local_libc_path`,
   build-ID/content-hash identity (banner `major.minor` equality does not prove
   offset compatibility), operator-vs-autodetect provenance, remote-vs-local
   semantics (`solve --remote --libc` runs local attempts where inequality is
   expected), and enforcement at **every** offset/feature/one-gadget consumer,
   not just `rop_techniques.py:563`.

## Scope decision (best judgement, review-informed)

- **S3 = CG-01a + CG-02-confirm only.** CG-01a directly closes the CG-01 gap as
  worded ("retire hardcoded 2.31; refuse rather than emit confidently-wrong").
- **CG-01b (the `--libc`/loaded mismatch detector) and CG-04 (loader threading)
  are split into a dedicated future sprint** (`S-libc-binding`), because the
  review proves a correct detector requires the CG-04 work + build-ID identity +
  central binding at ~6 sites + provenance + remote semantics. A half-built
  banner-equality detector at one site would emit false MATCH/MISMATCH — worse
  than none. The review is saved as the evidence for this split:
  `docs/plans/reviews/2026-11-11-s3-libc-correctness-review-daybreakblue.md`.
  The master plan's S7 line is updated to carry this deferral.

## CG-01a — retire the silent 2.31 default; make the library API honest

New module `supwngo/utils/libc.py`:
- `LibcVersionUnknown(ValueError)`.
- `parse_libc_version(version) -> Optional[Tuple[int,int]]` — `"2.31"` /
  `"2.31-0ubuntu9"` → `(2,31)`; malformed → `None` (**never** a 2.31 fallback).
- `resolve_libc_version(version=None, libc_path=None) -> Optional[str]` —
  explicit normalized version > glibc release banner read from `libc_path` >
  `None`.
- `require_libc_version(version, *, what) -> Tuple[int,int]` — raise
  `LibcVersionUnknown(f"{what} needs a known libc version; none supplied")` when
  unresolvable. All version comparisons are **tuple** `(major,minor)`, never a
  bare `minor` (so `3.0 > 2.30`).

`utils/config.py`: delete `DEFAULT_LIBC_VERSION`; `ExploitConfig.libc_version:
Optional[str] = None`. Update **every** importer so package import does not break
(`exploit/__init__.py:12` eagerly imports `FSOPExploiter`):
`exploit/fsop.py`, `exploit/heap/tcache.py`, `exploit/heap/techniques.py`,
`exploit/heap/large_bin.py`, `exploit/heap/house_of_spirit.py`,
`vulns/off_by_one.py`, `exploit/tester.py`.

Behavior changes (default `libc_version: Optional[str] = None` = unknown):

- **Offset-byte-critical → refuse on unknown** (never fabricate):
  - `TcachePerThreadStruct`: do not compute offsets eagerly; move the offset
    computation into a method/property that calls `require_libc_version`. Keep
    `size_to_idx` version-independent (static). `TcacheExploiter(None)` must still
    *construct* — instantiate the per-thread layout lazily (only when a
    layout-consuming method runs), so bare construction and version-independent
    helpers (`size_to_idx`) work, while `tcache_perthread_poison` /
    `hook_overwrite_targets` refuse without a version.
  - `FSOPExploiter.malloc_hook_attack` / `free_hook_attack`: `hook_offsets.get`
    with no default; `None` → return an explicit error dict ("libc version
    unknown; cannot place hook offset") rather than the 2.31 offset.
- **Feature/verdict → tri-state (unknown), not a fabricated answer:**
  - `TcacheExploiter` feature flags (`has_tcache`/`has_key`/`has_safe_linking`):
    `None` when version unknown; methods that branch on them report unknown.
  - `HeapExploiter.select_technique`: keep the `List[HeapTechnique]` return; on
    unknown version, emit the conservative set and surface the unknown via a
    separate diagnostic (not a dict key the API doesn't have). `HeapExploitConfig`
    capability flags become tri-state rather than defaulting `has_tcache=True`.
  - `HouseOfSpirit`, `NullByteExploiter`, `HouseOfStorm`: unknown version →
    "unknown" feasibility/branch, never a definite true/false.
- `exploit/tester.py:311`: drop the `or DEFAULT_LIBC_VERSION` tail; unknown →
  explicit default Docker image **with a logged note** (image choice is not
  offset-critical and this path is unreachable from the pipeline).

## CG-02 — `--libc` command-set: confirm + pin (no vacuous flags)

The review corrected the inventory: `onegadget` takes a **required `libc`
positional** (`cli.py:946`); `libc_id` does **not** take a libc positional — it
consumes optional leaked-address flags (`cli.py:644`). The agreed `--libc`
option set is the seven ret2libc/exploit-building commands that already carry it
(`exploit, rop, pwn, template, autopwn, explain, solve`); `onegadget` is covered
by its positional. The analysis commands (`heap_analysis`, etc.) construct
analyzers with **no libc input** (`cli.py:2316` → `AdvancedHeapAnalyzer(bin_obj)`)
and threading a real `--libc` into them is detector-depth work (S6), so S3 does
**not** add a non-functional flag. CG-02 deliverable: a test that enumerates the
CLI and asserts `--libc` presence exactly on the agreed set (and the `onegadget`
positional), pinning the intended surface against drift. If a future sprint
wants `--libc` on `heap_analysis` it must thread it into the analyzer with a
behavioral test — recorded as a note, not done here.

## Test strategy (RED-proof on base `dc22067`, non-vacuous per review)

- `tests/test_libc_version_resolver.py`: `parse_libc_version` (`"2.31"`,
  `"2.35-0ubuntu3"`, malformed→`None`, `3.0` sorts above `2.30`);
  `resolve_libc_version` precedence; `require_libc_version(None)` raises.
- `tests/test_tcache_unknown_version_refuses.py`:
  - `TcacheExploiter()` **constructs** (no raise) — guards MAJOR-5.
  - version-independent `size_to_idx()` works with no version.
  - the offset/layout method refuses (`LibcVersionUnknown`) with no version
    (RED on base: base silently returns 2.31 `0x80/0x290`).
  - explicit `"2.27"` → `0x40/0x250`, `"2.31"` → `0x80/0x290` (explicit callers
    unchanged).
- `tests/test_fsop_unknown_version_refuses.py`: `FSOPExploiter()
  .malloc_hook_attack(...)` / `free_hook_attack(...)` with unknown version return
  an error dict, **not** the 2.31 `0x3ed8e8` offset (RED on base: base emits
  `target = libc_base + 0x3ed8e8`); explicit `"2.23"`/`"2.27"` unchanged.
- `tests/test_heap_feature_flags_tristate.py`: `HeapExploiter` /`HouseOfSpirit`
  /`NullByteExploiter`/`HouseOfStorm` with unknown version report unknown, not a
  fabricated 2.31-derived verdict.
- `tests/test_cli_libc_option_set.py`: enumerate CLI commands; assert `--libc`
  exactly on the agreed set; assert `onegadget` has the required `libc`
  positional and `libc_id` does not.
- Update the existing bare-default callers to the new contract:
  `test_new_modules.py:36,40` (`TcachePerThreadStruct()`, `size_to_idx`),
  `test_heap_modules.py:574,585` (`HeapExploiter(MockBinary())`), and the
  House-of-Spirit / Large-Bin convenience-API tests (`test_heap_modules.py:260,389`).

## Regression + benefit gate

- Full suite vs. the S2-merged baseline
  (`benchmark/results_retest/manifests/s2-merged-junit.xml`: 2137 tot, 1
  known-flaky `test_input_vector_delivery` fail); no new failures; corpus solve
  rates hold (`corpus_r2` 15/15, `corpus_fsop` 3/3).
- Benefit: the public library API no longer fabricates a 2.31 libc. A direct
  `TcacheExploiter()`/`FSOPExploiter()` against an unknown-version target now
  refuses to emit struct/hook offsets instead of silently using 2.31's — the
  exact "confidently-wrong" failure CG-01 names — and feature/feasibility
  verdicts read "unknown" rather than a fabricated answer. `--libc` surface is
  pinned against drift.

## Two commits

1. `fix(exploit): retire silent DEFAULT_LIBC_VERSION; refuse unknown-version libc
   offsets` — CG-01a (resolver + all importers + refuse/tri-state + tests).
2. `test(cli): pin the --libc command-set surface` — CG-02 (pinning test + plan
   inventory fix).

## Peer review dispositions (Daybreak Blue, t2-cyber, xhigh — verdict REWORK)

Full review: `docs/plans/reviews/2026-11-11-s3-libc-correctness-review-daybreakblue.md`.

- **BLOCKER 1 & 3 (loaded≠shipped; detector must cover many sites + loader
  threading):** ACCEPTED → CG-01b/CG-04 split out into a dedicated sprint; S3
  no longer ships a mismatch detector. Removes the unsound half-measure.
- **BLOCKER 2 (Optional[str] can't carry 4 states; major.minor ≠ offset
  identity; provenance; remote):** ACCEPTED → folded into the deferred
  `S-libc-binding` sprint's requirements (typed result, build-ID identity,
  provenance, remote semantics).
- **BLOCKER 4 (FSOPExploiter omitted; deleting the constant breaks import):**
  ACCEPTED → FSOP is now first-class in CG-01a; all importers updated.
- **MAJOR 5 (raise in `__post_init__` breaks construction):** ACCEPTED → lazy
  per-thread layout; construction stays valid; explicit refuse tests added.
- **MAJOR 6 (advisory misclassification; `select_technique` returns a list):**
  ACCEPTED → tri-state verdicts for HouseOfSpirit/NullByte/HouseOfStorm; list
  API kept with a separate diagnostic; config flags tri-state.
- **MAJOR 7 (RED-proof vacuity):** ACCEPTED → offset/error-dict content
  assertions (not mere symbol-absence); explicit-version control cases; bare-
  default caller updates enumerated.
- **MINOR 8 (CLI inventory error):** ACCEPTED → corrected (`libc_id` has no libc
  positional); encoded in the pinning test.
- **MINOR 9 (tuple comparison; malformed refuses):** ACCEPTED → resolver uses
  `(major,minor)`; malformed → `None`/refuse, never 2.31.
