# Canonical autopwn pipeline

Date: 2026-09-23
Status: Implemented (Phase 2 of `docs/plans/2026-09-23-effectiveness-and-usability.md`)
Author: Phase 2 execution (branch `feat/consolidate-autopwn-pipeline-20260923`)

## 1. Problem

Before this change, supwngo had two overlapping, never-reconciled
auto-exploit engines:

- `AutoExploiter` (`supwngo/exploit/auto.py`, ~2,930 LOC)
- `EnhancedAutoExploiter` (`supwngo/exploit/enhanced_auto.py`, ~1,430 LOC)

Both were wired to a duplicate `autopwn` Click command in `cli.py` (Click
silently let the later `def autopwn` win, so `EnhancedAutoExploiter` ran in
production while `AutoExploiter` was reachable only through a third call
site in the `exploit` command, gated on a canary-bypass special case).
Strategy selection was forked (`strategy.py`'s `StrategySuggester` vs.
`EnhancedAutoExploiter`'s inline `_rank_strategies`). Verification was
forked four ways: `verification.py`'s `ExploitVerifier` (real runtime
execution verification, wired into Enhanced), `verify.py`'s
`ExploitVerifier` (a *different* class with the same name - a static
payload sanity checker), `tester.py`'s `ExploitTester` (unwired, loose
string-matching), and ad-hoc inline verification inside `auto.py` (which
has its own duplicate `verify_shell` definition bug - two `def
verify_shell` at module scope in `auto.py`, the second silently shadowing
the first).

Catalogued in detail in `docs/plans/2026-09-23-fix-and-improvement-catalog.md`
(sections 3-4) and `docs/plans/2026-09-23-effectiveness-and-usability.md`
(Phase 2 scope, lines 112-140).

## 2. Decision: a new, smaller canonical orchestrator

Rather than growing either legacy monolith or wrapping one as an adapter
around the other, this phase builds a new, deliberately small
`CanonicalAutopwnEngine` (`supwngo/exploit/pipeline/orchestrator.py`) that:

- owns no technique logic itself - it runs profiling stages, asks
  `StrategySuggester` for an ordering, and walks a pluggable
  `ExecutorRegistry` of independent `TechniqueExecutor` implementations;
- natively reimplements (not thinly wraps) all techniques worth keeping:
  the 7 techniques from `EnhancedAutoExploiter` plus 4 techniques unique to
  `AutoExploiter` (SROP, scanf-canary-bypass, explicit UAF, explicit
  double-free) - 11 executors total;
- is what `supwngo autopwn` (the CLI command, now deduplicated to exactly
  one `def autopwn`) drives.

This was chosen over the alternatives considered:

- **Grow `EnhancedAutoExploiter` in place, port `AutoExploiter`'s unique
  techniques into it.** Rejected: `EnhancedAutoExploiter` hardcodes
  `getattr(self, f"_try_{name}")` dispatch, has no typed attempt/failure
  model, and its `_rank_strategies` duplicates (and disagrees with)
  `strategy.py`'s `StrategySuggester`. Growing it further would cement the
  strategy fork rather than reconcile it, and would not give Phase 3 a
  clean extension point for leak acquisition (`AutoLeakFinder` wiring).
- **Grow `AutoExploiter` in place.** Rejected for the same structural
  reasons, plus it carries ~1,500 more lines of overlapping surface area
  and the known duplicate-`verify_shell` bug.
- **Adapter wrapping a shadow `EnhancedAutoExploiter` instance.** Considered
  as a cheaper option, but it would not give techniques a uniform typed
  `AttemptRecord`/`VerificationReceipt` contract, and would leave the
  `AutoExploiter`-only techniques (SROP, scanf-canary-bypass, UAF,
  double-free) unported. Rejected in favor of full native reimplementation,
  which was tractable within this phase's scope.

**`auto.py` and `enhanced_auto.py` are deliberately NOT deleted.** The
`exploit` CLI command (`cli.py`, unmodified, out of scope for this phase)
still calls both `EnhancedAutoExploiter` and `AutoExploiter` directly, and
per the governing plan, unique techniques must exist elsewhere in the new
pipeline before the old code can be removed - which is now true for all of
`AutoExploiter`'s unique techniques, but full retirement of both legacy
engines and their CLI call site is left to a later phase (see section 8).

## 3. Pipeline contracts

`supwngo/exploit/pipeline/contracts.py` defines the shared typed models,
imported by every stage and executor:

- **`Stage`** (enum): `NOT_STARTED`, `APPLICABILITY_CHECK`, `ANALYSIS`,
  `PAYLOAD_BUILD`, `DELIVERY`, `VERIFICATION`, `SCRIPT_GENERATION`, `DONE`.
- **`AttemptOutcome`** (enum): `SUCCESS`, `PARTIAL`, `FAILED`, `SKIPPED`,
  `ERROR`.
- **`AttemptRecord`** (dataclass): `technique`, `outcome`, `stage_reached`,
  `failure_reason`, `payload`, `offset`, `target_addr`,
  `partial_artifacts` (dict, e.g. `{"exploit_script": ...}`), `notes`,
  `receipt` (`Optional[VerificationReceipt]`), `error`. Has `.to_dict()`
  for JSON output (used by `cli.py`'s `--json` mode).
- **`VerificationReceipt`** (dataclass): `token`, `technique`, `level`,
  `verified_at`, `binary_path`, `flag`, `shell_confirmed`,
  `matched_requested_token`, `notes`, plus a `.success` property. This is
  the "verification receipt" the plan asked for: a unique per-run token
  written then read back, not stdout pattern-matching alone (see section 5).
- **`TechniqueExecutor`** (abstract base class): `name: str`,
  `is_applicable(context) -> bool` (default `True`), abstract
  `attempt(context, verifier) -> AttemptRecord`.

## 4. Target/session and state abstraction

**Target/session abstraction:** reused as-is. `remote/interaction.py`'s
`RemoteInteraction`/`ConnectionConfig` (connect_local/remote/ssh/gdb, tube
ops, `get_shell()`, `leak_via_puts()`, `stage_payload()`) was already
solid and general; this phase does not reinvent it. Executors that spawn
processes locally use pwntools `process()` directly (matching what both
legacy engines already did for local runs) via
`supwngo/exploit/pipeline/executors/_shared.py`'s `spawn_and_send()`
helper; remote/SSH/GDB-attached runs go through `RemoteInteraction`
unchanged. No new target/session type was introduced.

**Persistent pipeline state:** `core/context.py`'s existing
`ExploitContext` dataclass was extended in place, rather than introducing
a separate pipeline-owned state object, for a concrete, discovered reason
(not just taste) - see section 7 (import layering). New fields, all using
only stdlib types (no `supwngo.exploit.*` imports at class-definition
time):

```python
# === Canonical autopwn pipeline state ===
gadgets: Dict[str, int] = field(default_factory=dict)
win_function: Optional[Tuple[str, int]] = None
binsh_addr: Optional[int] = None
offset: Optional[int] = None
captured_flag: Optional[str] = None
verification_level: Optional[Any] = None          # VerificationLevel, typed via TYPE_CHECKING only
attempts: List[Any] = field(default_factory=list)  # List[AttemptRecord], typed via TYPE_CHECKING only
profile_prompts: List[bytes] = field(default_factory=list)
profile_input_count: int = 0
profile_has_menu: bool = False
profile_has_alarm: bool = False
profile_is_shellcode_runner: bool = False
profile_buffer_size: Optional[int] = None
profile_comparison_value: Optional[int] = None
profile_comparison_offset: Optional[int] = None
profile_bad_bytes: Set[int] = field(default_factory=set)
```

The pre-existing `leaks: Dict[str, int]` field (stack/libc/pie address
leaks) is deliberately *reused* rather than duplicated with new
profile-specific fields - both `profile_stage.py`'s dynamic profiling and
the (currently no-op) `leak_stage.py` write into `context.leaks`.

## 5. Executor/registry pattern

`supwngo/exploit/pipeline/registry.py`'s `ExecutorRegistry` (named to
avoid colliding with the pre-existing, unrelated
`supwngo.exploit.chainer.TechniqueRegistry`) holds `TechniqueExecutor`
instances keyed by `.name`: `register()`, `get()`, `names()`, `all()`,
`__contains__`, `__len__`.

`supwngo/exploit/pipeline/executors/__init__.py`'s `build_default_registry()`
registers all 11 built-in executors:

| Executor | `.name` | Source |
|---|---|---|
| `VariableOverwriteExecutor` | `variable_overwrite` | ported from `EnhancedAutoExploiter._try_variable_overwrite` |
| `Ret2WinExecutor` | `ret2win` | ported from `EnhancedAutoExploiter._try_ret2win` |
| `DirectShellcodeExecutor` | `direct_shellcode` | ported from `EnhancedAutoExploiter._try_direct_shellcode` |
| `NegativeSizeBypassExecutor` | `negative_size_bypass` | ported from `EnhancedAutoExploiter._try_negative_size_bypass` |
| `StackShellcodeExecutor` | `stack_shellcode` | ported from `EnhancedAutoExploiter._try_stack_shellcode` |
| `FormatStringExecutor` | `format_string` | ported from `EnhancedAutoExploiter._try_format_string` (template-only) |
| `Ret2LibcExecutor` | `ret2libc` | ported from `EnhancedAutoExploiter._try_ret2libc` (template-only) |
| `SROPExecutor` | `srop` | ported from `AutoExploiter._try_srop` / `_generate_srop_script` |
| `ScanfCanaryBypassExecutor` | `scanf_canary_bypass` | ported from `AutoExploiter._try_scanf_canary_bypass` |
| `UAFExecutor` | `uaf` | ported from `AutoExploiter._try_uaf` / `_execute_uaf_exploit` |
| `DoubleFreeExecutor` | `double_free` | ported from `AutoExploiter._try_double_free` / `_try_double_free_tcache` |

Registration order does not determine attempt order - see section 6.

Instead of hardcoded `getattr(self, f"_try_{name}")` dispatch (both legacy
engines' pattern), the orchestrator loop is:

```python
for name in order:
    executor = self.registry.get(name)
    if not executor.is_applicable(context):
        record SKIPPED
        continue
    record = executor.attempt(context, verifier)  # wrapped in try/except -> ERROR record
    context.attempts.append(record)
```

## 6. Strategy reconciliation

`strategy.py`'s `StrategySuggester`/`ExploitApproach` is now the single
strategy engine; `EnhancedAutoExploiter`'s private, unreconciled
`_rank_strategies`/`ExploitStrategy` dataclass remains only inside
`enhanced_auto.py` itself (still used by that file's own `.run()`, which
the `exploit` CLI command still calls directly - untouched, out of scope).

Two `ExploitApproach` enum members that only existed as inline strategies
inside `EnhancedAutoExploiter._rank_strategies` were ported into
`strategy.py` as real, first-class strategies:

- `ExploitApproach.VARIABLE_OVERWRITE` - `_build_variable_overwrite_strategy()`
- `ExploitApproach.NEGATIVE_SIZE_BYPASS` - `_build_negative_size_bypass_strategy()`,
  gated on `_check_negative_size_bypass_viable()` (read/scanf present)

Both are appended in `StrategySuggester.analyze()` alongside the existing
ret2win/ROP/SROP/format-string/etc. strategies, with the same
priority/confidence/description/requirements/advantages/disadvantages/steps
shape as every other strategy in that file - not a mechanical import swap,
but the same modeling work `strategy.py` already does for its other
strategies.

`orchestrator.py`'s `APPROACH_TO_TECHNIQUE` dict maps `ExploitApproach`
members onto executor names:

```python
APPROACH_TO_TECHNIQUE = {
    ExploitApproach.RET2WIN: "ret2win",
    ExploitApproach.SHELLCODE: "direct_shellcode",
    ExploitApproach.SROP: "srop",
    ExploitApproach.FORMAT_STRING: "format_string",
    ExploitApproach.ROP_SYSTEM: "ret2libc",
    ExploitApproach.VARIABLE_OVERWRITE: "variable_overwrite",
    ExploitApproach.NEGATIVE_SIZE_BYPASS: "negative_size_bypass",
    ExploitApproach.STACK_PIVOT: "stack_shellcode",  # approximation, documented in orchestrator.py
}
```

`StrategySuggester` does not (yet) model heap-UAF, double-free, or the
scanf-canary-skip pattern - those three executors run via
`UNMODELED_TECHNIQUES = ["scanf_canary_bypass", "uaf", "double_free"]`,
tried after the strategy-ordered set, gated purely by their own
`is_applicable()`. Folding these into `StrategySuggester` properly is
Phase 5 territory (heap-UAF hardening is already that phase's scope per
the effectiveness/usability plan), not Phase 2's.

`CanonicalAutopwnEngine._ordered_technique_names()` builds the final
attempt order as: (1) strategy-ordered techniques via
`APPROACH_TO_TECHNIQUE`, sorted by `(priority, -confidence)`, (2)
`UNMODELED_TECHNIQUES`, (3) any remaining registered-but-unreached
executor, in registration order - so no registered executor is ever
silently skipped even if neither the strategy report nor the unmodeled
list reaches it.

`ExploitApproach` members with no executor yet (`ROP_EXECVE`,
`MPROTECT_SHELLCODE`, `RET2DLRESOLVE`, `RET2PLT`, `ONE_GADGET`,
`HEAP_EXPLOIT`, `SECCOMP_BYPASS`) still surface in `strategy_report` for
hand-off purposes (Phase 4 scope) but are not auto-executed.

## 7. Verifier composition

Three verifier-shaped things existed; this phase picked one composition
and documented it rather than leaving the choice implicit
(`supwngo/exploit/pipeline/verifier.py`):

1. **`verification.ExploitVerifier`** (`supwngo/exploit/verification.py`)
   is the **primary receipt implementation**. It does real runtime
   execution confirmation (spawns/attaches, checks for a marker
   file/string, or pwntools-interactive shell confirmation). Extended in
   this phase to accept a per-call `marker`/`marker_file` override (was
   previously a fixed, shared `PWNED_MARKER`/`PWNED_FILE` constant used by
   every caller) so each attempt can be verified against its own unique
   token instead of a shared, guessable string.
2. **`verify.ExploitVerifier`** (`supwngo/exploit/verify.py`) - note this
   is a *different class with the same name* as (1), plus its own
   differently-shaped `VerificationResult` (an enum: PASS/WARN/FAIL,
   colliding in name only with `verification.py`'s dataclass of the same
   name). It performs static payload sanity checks (bad-char/size/
   alignment/one-gadget/address-validity/ROP-chain checks). Used as an
   **optional, non-fatal static pre-flight** before each payload attempt -
   imported with an alias (`from supwngo.exploit.verify import
   ExploitVerifier as StaticPayloadChecker`) specifically to avoid
   confusion with (1) at the call site. A failed pre-flight is logged as a
   note on the eventual `AttemptRecord`, not treated as fatal - a
   heuristic static checker producing a false negative should not block an
   attempt that might actually work.
3. **`tester.ExploitTester`** (`supwngo/exploit/tester.py`) - its
   local/docker/remote modes are a good long-term home for out-of-process
   verification, but its current success heuristic is loose string
   matching and it is presently unwired anywhere. Per the plan's explicit
   permission to punt on tightening it if that would be a large side-quest
   separate from Phase 2, **it remains unwired**. This is a deliberate,
   documented Phase 3+ follow-up, not an oversight.

`PipelineVerifier` (`supwngo/exploit/pipeline/verifier.py`) is the
composition point every executor calls through - not `verification.py` or
`verify.py` directly:

- `run_id = uuid.uuid4().hex[:8]` per engine run; `_new_token(technique)`
  mints `SUPWNGO_{run_id}_{seq}_{TECHNIQUE}` - a fresh, unique marker per
  *attempt*, not a shared constant, so a success claim is tied to the
  specific attempt that produced it.
- `run_static_preflight(payload, notes)` - best-effort call into
  `StaticPayloadChecker`, non-fatal.
- `verify_payload(technique, payload)` / `verify_shell(technique, proc)` -
  delegate to `verification.ExploitVerifier` with the freshly minted
  token, then wrap the result into a `VerificationReceipt` via
  `_to_receipt()`, which sets
  `matched_requested_token = bool(result.shell_confirmed or
  result.pwned_file_created)` - i.e. the receipt honestly distinguishes a
  strong, token-confirmed proof (file/shell-based) from a weaker
  output/flag-string match (`VerificationLevel.OUTPUT_MATCH`, where
  `matched_requested_token` is `False` even though `.success` is `True`).
  This distinction was validated end-to-end in manual smoke testing (see
  section 9).
- `record_receipt(context, receipt)` folds `flag`/`verification_level`
  back onto `ExploitContext` for the orchestrator/CLI/template layers to
  read.

`ExploitVerifier`'s `verify_payload()` uses non-interactive
`subprocess.run(..., capture_output=True)`, so a spawned `/bin/sh` that
immediately receives EOF on its inherited stdin exits instantly without
ever producing shell-access proof for that specific
technique+verification-path+binary-behavior combination. This is a
pre-existing characteristic of `ExploitVerifier.verify_payload` (faithfully
reused, not introduced by this phase - `EnhancedAutoExploiter._test_ret2win`
used the identical call), not a regression.

## 8. Import layering rule (discovered constraint, not stylistic preference)

`core/` is the shared substrate everything else (including `exploit/`)
builds on, and must stay importable on its own. Several `exploit/`
submodules (`generator.py`, `primitives.py`, `bypass.py`, `auto_leak.py`,
`chainer.py`, `signal_handler.py`, `shellcode.py`, `rop/pivot.py`) import
`core.context` at their own module level, and all of those are imported
eagerly by `supwngo/exploit/__init__.py`. If `core/context.py` did a real
(non-`TYPE_CHECKING`) import of anything under `supwngo.exploit.*`,
instantiating that chain would try to import `supwngo.exploit` while
`core.context` was still mid-import, raising `ImportError` on the
not-yet-defined name - the same class of bug Phase 0 fixed elsewhere.

Consequences applied throughout this phase's code:

- `core/context.py` only imports pipeline types (`AttemptRecord`,
  `VerificationLevel`) under `if TYPE_CHECKING:` - for annotations/docs
  only, never executed at runtime.
- New `ExploitContext` fields use only stdlib container types with real,
  import-free `default_factory` callables (`list`, `dict`, `set`) - this is
  *why* pipeline state was folded flat onto `ExploitContext` rather than
  nested inside a separate `RuntimeProfile`-style dataclass owned by
  `supwngo.exploit.pipeline` (a `RuntimeProfile` dataclass was drafted and
  then deleted for exactly this reason).
- `VerificationReceipt.success` (in `contracts.py`) does its
  `from supwngo.exploit.verification import VerificationLevel` import
  lazily, inside the property body, not at module level.

This rule is why `ExploitContext` was extended in place rather than a new
independent pipeline-state object being formalized as the plan's step 0
originally left open as a choice - the import graph made the choice for
us once actually traced.

## 9. End-to-end validation performed

Both legacy engines' code paths and the new pipeline were smoke-tested
against two throwaway, locally compiled C binaries (not committed; built
and removed from a `.scratch/` scratch directory outside `docs/`/`supwngo/`
during development):

- A "shellcode runner" pattern (`read()` into a buffer then call it,
  NX/canary disabled) -> `CanonicalAutopwnEngine` achieved
  `Result: SUCCESS`, `Verification: FULL_CONTROL`, technique
  `direct_shellcode`, with a receipt showing
  `matched_requested_token=True` - a real interactive shell was obtained
  and confirmed via its own unique token.
- A classic ret2win stack buffer overflow (canary/PIE disabled, NX
  enabled) -> `Result: SUCCESS`, `Verification: OUTPUT_MATCH`, technique
  `ret2win`, receipt showing `shell_confirmed=False`,
  `matched_requested_token=False` (correctly, since this was a
  string-match-based success, not a token-confirmed shell) but
  `.success=True` (a "flag captured" string was found in the output) -
  validating that the fallback `COMMON_RET_OFFSETS` search path in
  `Ret2WinExecutor` works and that the receipt schema correctly
  discriminates between weaker (output-match) and stronger
  (token-confirmed-shell) proof kinds, exactly as intended.

Two behaviors observed during this testing were root-caused as
*pre-existing* characteristics of ported logic, not bugs introduced by
this phase:

- GDB-based offset discovery (`_shared.find_offset_via_gdb`, ported from
  `EnhancedAutoExploiter._find_offset_iterative`) can fail to read the
  correct offset from `info registers rip` when a `ret` faults on a
  non-canonical popped address, because x86-64 does not commit RIP to the
  faulting target before delivering the `#GP` - RIP in the signal context
  still points at the `ret` instruction itself. `Ret2WinExecutor`'s
  `COMMON_RET_OFFSETS` fallback list correctly compensates for this in
  practice.
- `ExploitVerifier.verify_payload()`'s non-interactive `subprocess.run`
  cannot confirm a shell that exits immediately on EOF'd stdin (see
  section 7) - a real gap in that verifier's coverage, inherited as-is.

## 10. Remaining work / explicitly punted (not this phase's scope)

- **`tester.ExploitTester` stays unwired.** Its local/docker/remote modes
  are a good long-term home for out-of-process verification, but
  tightening its loose string-matching success heuristic is left as
  explicit follow-up (permitted by the governing plan).
- **`AutoLeakFinder` / `Z3ROPSolver` are not repaired or wired in.**
  `supwngo/exploit/pipeline/leak_stage.py`'s `acquire_leaks(context)` is
  currently a no-op beyond logging already-known leak count, but is the
  explicit, documented extension point for Phase 3 to plug real leak
  acquisition into - `AutoLeakFinder.__init__` already accepts an
  `ExploitContext`, so no further contract changes should be needed there.
- **`auto.py` and `enhanced_auto.py` are not deleted or decomposed.** Both
  remain intact because `cli.py`'s `exploit` command (untouched, out of
  scope for this phase) still calls both directly. Retiring that call site
  and the two legacy modules entirely is a follow-up once Phase 3/4 work
  has had a chance to exercise the new pipeline in production.
- **`format_string`, `ret2libc`, and `srop` executors remain
  template/PARTIAL-only**, matching their legacy behavior - real automated
  two-stage exploitation (leak -> compute -> second-stage payload) needs
  the leak-acquisition extension point above (Phase 3) and, for format
  string, the 64-bit `%n` offset-computation fix noted in the fix catalog
  (Phase 5 scope).
- **`ExploitApproach` members with no live executor**: `ROP_EXECVE`,
  `MPROTECT_SHELLCODE`, `RET2DLRESOLVE`, `RET2PLT`, `ONE_GADGET`,
  `HEAP_EXPLOIT`, `SECCOMP_BYPASS`. These still surface in
  `strategy_report` for hand-off (Phase 4) but are not auto-executed.
- **Known-imperfect leak classification thresholds** in
  `profile_stage.py`'s `_parse_address_leaks()` (stack vs. libc vs. PIE
  heuristics) were ported verbatim from `EnhancedAutoExploiter` rather than
  fixed - matches the fix catalog's note that `remote/leak.py` has the
  same class of bug and `format_string.py` has the correct version.
  Fixing the classifier generally is Phase 5 scope, not Phase 2's.
- **Heap-UAF and double-free strategies are not modeled in
  `StrategySuggester`** (see section 6) - Phase 5 scope.
