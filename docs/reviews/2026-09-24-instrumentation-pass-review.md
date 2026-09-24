# Independent review — `2026-09-24-pipeline-instrumentation-pass.md`

**Reviewed commit:** `b022b2d`
**Code tree reviewed:** `supwngo/` at `b022b2d`, verified byte-identical to `b3a40b4`
and to `55a8db4` (`git diff --stat b3a40b4 b022b2d -- supwngo/` and
`git diff --stat 55a8db4 b022b2d -- supwngo/` both empty), so every claim below is
checked against the same tree the plan was written against.
**Artifacts reviewed:** the plan author's own worktree,
`.claude/worktrees/agent-a4b4d5e56ab5e05c5` (`b022b2d`, `bench/round2-cold-and-dev-20260924`):
`benchmark/results/20260924-172232Z/report.json` (R1, 13 SUCCESS / 2 VOID) and
`benchmark/results_r2/20260924-163611Z/report.json` (R2 cold, 4 SUCCESS / 11 FAILED).
**Method:** every load-bearing claim re-derived from code or artifacts. Nothing accepted
because it looked addressed.

---

## 0. Summary

This is a materially better document than the two it supersedes. The method change is
real, not cosmetic: five of the nine enumerated factual claims are confirmed *exactly*,
including line ranges, and the two hardest ones (the 9 `deliver_parts` call sites with
their timeout distribution, and the 11-of-11 swallowing site) are precisely right. The
core diagnosis — that `variable_overwrite` brute-forces folklore constants while
`comparison_immediates()` sits unused one module away — is correct and is the most
valuable finding in the round.

It is not yet approvable. Three blocking items, all scope/specification defects rather
than reasoning errors:

1. **I4 cannot be built as scoped.** 7 of the 9 `deliver_parts` call sites have no
   `AttemptRecord` in scope, and one of those is called before any `AttemptRecord`
   exists. I4 is a refactor of seven probe helpers, not a recording-only edit.
2. **§1 row 2 has no instrument in the set.** It names a missing duration on
   `autopwn_json_probe`, which is harness-side; §4.1 lists no `benchmark/` file and §9
   forbids harness changes.
3. **§6 step 2 is unexecutable as written** — §2 contains no 13-row per-target map — and
   it prescribes hardening a text parser when a structured field carrying the complete
   map already exists in every `report.json`.

Plus one refuted factual claim (§2's "exactly one generated script"), whose *conclusion*
nonetheless survives by a stronger route. No published figure needs annotation.

---

## 1. The nine assigned claims

| # | claim | verdict |
|---|---|---|
| 1 | 17 executor classes, 16 `is_applicable` predicates | **CONFIRMED** |
| 2 | `timed_out` has zero functional consumers | **CONFIRMED** |
| 3 | 9 `deliver_parts` sites / 6 modules / timeout distribution | **CONFIRMED** (2 wording imprecisions) |
| 4 | the two reason-swallowing sites; 11 of 11 | **CONFIRMED** |
| 5 | complete 13-row R1 map + 4 R2 techniques | **content CONFIRMED, form REFUTED** |
| 6 | `comparison_immediates()` called from one site | **CONFIRMED** |
| 7 | `profile_stage.py:160-165` first-write-wins | **CONFIRMED** |
| 8 | `variable_overwrite` in exactly one generated script | **REFUTED** (conclusion survives) |
| 9 | `--timeout` reaches only capped profiler + verifier | **CONFIRMED** |

### 1.1 Claim 1 — CONFIRMED

`grep -rn "^class .*Executor"` over `supwngo/exploit/pipeline/` returns 19; subtracting
the abstract base `TechniqueExecutor` (`contracts.py:162`) and `ExecutorRegistry`
(`registry.py:18`) gives **17 concrete executors**. `grep -rn "def is_applicable"`
returns 17; subtracting the base definition (`contracts.py:177`) gives **16 predicates**.

The executor without a predicate is `VariableOverwriteExecutor`
(`stack_techniques.py:67`). It inherits `contracts.py:181`'s `return True`. **That is the
mechanism behind the plan's "126 unconditional `verify_payload` calls"** — the plan
asserts the unconditionality without naming its cause. Worth stating, because it is also
the cheapest available R5 mitigation: adding a predicate to that one class bounds the
exposure without deleting the technique class, an option §7's two-row table does not
consider.

### 1.2 Claim 2 — CONFIRMED

Every reference to `timed_out` in `supwngo/`: `delivery.py:97` (`__slots__`), `:104`
(parameter default), `:110` (assignment), `:120` (inside `__repr__`, lines 117-121),
`:181` (construction from `still_running`, itself set at `:172`). No read anywhere else
in the package. Zero functional consumers, as stated.

### 1.3 Claim 3 — CONFIRMED, with two wording imprecisions

Nine executor call sites across exactly six modules, with the stated timeout
distribution:

| site | enclosing function | timeout |
|---|---|---|
| `shellcode_techniques.py:66` | `_probe_stack_leak` | 1.5 |
| `fmtstr_techniques.py:138` | `_find_buffer_arg_index` | 2.0 |
| `fmtstr_techniques.py:175` | `_write_targets` | 2.0 |
| `canary_leak_techniques.py:154` | `_probe_fmtstr_indices` | 2.0 |
| `canary_leak_techniques.py:180` | `_probe_echo_sizes` | 2.0 |
| `fmtstr_techniques.py:102` | `attempt` | 3.0 |
| `input_shape_techniques.py:252` | `attempt` | 3.0 |
| `rop_techniques.py:359` | `_probe_pie_leak` | 3.0 |
| `heap_techniques.py:70` | `discover_menu` | caller-supplied |

1.5 ×1, 2.0 ×4, 3.0 ×3, one caller-supplied — exactly as claimed.

**MINOR (m3):** the caller-supplied site has one in-tree caller,
`heap_techniques.py:213`, which passes no timeout, so it runs at its `3.0` default
(`heap_techniques.py:61-62`). The effective distribution is 1.5 ×1, 2.0 ×4, 3.0 ×4. This
strengthens rather than weakens the plan's operational point ("there is no budget flag to
pass") — the parameter exists and nobody uses it.

**MINOR (m2):** "Every one of them treats a timed-out probe as an ordinary non-match and
`continue`s" — the substantive half is true at all nine sites; the `continue` is literal
at only three (`input_shape:252`, `fmtstr:102`, `canary:180`). Four sites `return
None`/`[]`/`{}`. Two of those are materially *worse* than an ordinary non-match: at
`fmtstr_techniques.py:141-142` and `canary_leak_techniques.py:157-159`, an empty read in
the **first** window makes the executor conclude "not a format-string sink at all" and
abandon the entire sweep. A single timed-out probe therefore disables a whole technique,
not one candidate. The plan understates its own case here.

### 1.4 Claim 4 — CONFIRMED

`stack_techniques.py:95-96`, verbatim:

```python
        record.notes.append("Tried common buffer sizes and magic values; none confirmed")
        return record
```

`failure_reason` is never assigned on this path. Contrast `Ret2WinExecutor`, which does
set it (`stack_techniques.py:145`) — so this is an omission, not a convention.

`heap_and_bypass.py:105-107`, verbatim:

```python
        except Exception as e:
            logger.debug(f"scanf_canary_bypass failed: {e}")
            record.error = str(e)
```

Both swallow paths confirmed: the exception path leaves `failure_reason` empty, and when
`_test_scanf_bypass()` returns `False` at `:100` the record keeps the `PARTIAL` set at
`:95` with no reason recorded at all.

**"11 of 11" — confirmed from artifacts.** In the R2 report, `variable_overwrite`
appears in `autopwn_json_probe.parsed.attempts` with `outcome=FAILED` and
`failure_reason=""` on exactly eleven slugs — `01, 02, 03, 04, 05, 06, 08, 09, 11, 12,
14` — which is precisely the set of eleven `FAILED` targets. Set equality, not just
count equality.

**MINOR (m-loose):** §4 calls this "the recorded cause for 11 of 11 R2 failures". The
site is *hit* on 11 of 11; it is not the reported cause, since on all eleven the last
record is `format_string: PARTIAL`. §1's phrasing ("why `variable_overwrite` failed on
all 11 R2 failures") is the accurate one; §4 should match it.

### 1.5 Claim 5 — content CONFIRMED, form REFUTED

I reconstructed both maps from `autopwn_json_probe.parsed.technique` (see §3 below).

**R2, credited (4):** `07→srop`, `10→ret2libc_leak`, `13→ret2win`, `15→ret2libc_leak`.
§2's list — `srop`, `ret2libc_leak`, `ret2win`, `ret2libc_leak` — matches positionally,
exactly.

**R1, credited (13):**

| slug | intended | winning technique |
|---|---|---|
| `01_shellcode_stack` | `stack_shellcode` | `stack_shellcode` |
| `02_ret2plt_system` | `ret2plt_system` | `ret2plt` |
| `03_pie_leak_ret2libc` | `pie_leak_ret2libc` | `ret2libc_leak` |
| `04_canary_leak_bypass` | `canary_leak_bypass` | `canary_leak_ret2win` |
| `05_fmtstr_arbread` | `fmtstr_arbread` | **`canary_leak_ret2win`** |
| `06_fmtstr_arbwrite` | `fmtstr_arbwrite` | `fmtstr_write_gate` |
| `07_ret2libc_leak` | `ret2libc_leak` | `ret2libc_leak` |
| `08_ret2dlresolve` | `ret2dlresolve` | `ret2dlresolve` |
| `09_srop` | `srop` | `srop` |
| `10_int_overflow` | `integer_overflow` | `int_truncation_bypass` |
| `12_heap_tcache_poison` | `heap_tcache_poison` | `tcache_poison_got` |
| `14_negative_index` | `negative_index_oob_write` | `negative_index_write` |
| `15_win_function` | `ret2win_baseline` | `ret2win` |

(`11_heap_uaf_leak` VOID `corpus_missing_liveness_gate`; `13_off_by_one` VOID
`corpus_trivially_solvable`.)

§2's multiset matches this exactly, including both `×2` counts, and the count is 13. The
rev-2 defect — 12 rows for 13 targets, `15_win_function` missing — **is fixed**. Credit
where due: this is the claim the predecessor died on and it is now right.

**But §2 is not a per-target map.** It is a single table row (`all 13` | a
comma-separated multiset). §6 step 2 instructs the R1 gate to assert "the complete 13-row
per-target technique map in §2". There are no 13 rows in §2 and no target→technique
association anywhere in the document. As written, step 2 cannot be implemented — see
**BLOCKING B3**.

**MAJOR (M2):** the multiset form conceals the single most interesting fact in the table.
`05_fmtstr_arbread` — a format-string target — is credited to `canary_leak_ret2win`, not
to any format-string technique. §8 then reasons about target `05` at length ("`05` gains
nothing (`_find_buffer_arg_index` already sweeps `%N$p`, and `%p` always renders as
hex)") without noting that `05`'s credit does not currently come from the format-string
path at all. That materially affects the phase-1a exposure argument §8 is making. A
count-or-multiset gate also cannot catch a regression that swaps two targets' techniques
while preserving the multiset — exactly the class of drift a per-target gate exists for.

### 1.6 Claim 6 — CONFIRMED

`comparison_immediates()` defined at `input_shape_techniques.py:68`, called at
`:240` and nowhere else. Lines `:47`, `:101` and `:217` are a docstring cross-reference, a
`logger.debug` string, and another docstring cross-reference. No call from `tests/`. The
plan's framing — a working capability the repo already has, used once, inside its own
module — is accurate, and this is the strongest observation in the document.

### 1.7 Claim 7 — CONFIRMED

`profile_stage.py:162-165`:

```python
    for addr in scan_hex_addresses(output):
        bucket = classify_address(addr)
        if bucket and bucket not in context.leaks:
            context.leaks[bucket] = addr
```

`not in` makes it first-write-wins per bucket. §8's correction is right: widening the
scanner is not additive, because an additional earlier-in-scan candidate pre-empts the
bucket and the correct value can then never be written. "Test it; do not assert it" is the
correct instruction.

### 1.8 Claim 8 — REFUTED; conclusion survives

`grep -rl variable_overwrite` over the generated scripts of both runs returns **46
files, not one**:

- R1 (`results/20260924-172232Z/`): **1** — `rep1/11_heap_uaf_leak_generated.py`.
- R2 (`results_r2/20260924-163611Z/`): **45** — nine stub slugs (`01, 03, 04, 05, 06,
  08, 09, 12, 14`) × five reps.

The R2 half of the search was not performed. §2 presents this as verified evidence
("**Confirmed, not assumed. Both halves**"), and it is the same error class the
predecessor was rejected for: a search whose scope is narrower than the sentence
describing it.

**The conclusion is nonetheless correct, by a stronger route.** Every appearance is a
comment line in the failure-template attempt log, e.g.
`#   - variable_overwrite: FAILED`, never a solving technique. Independently confirmed
structurally: across both runs, no target with `status == SUCCESS` has
`autopwn_json_probe.parsed.technique == "variable_overwrite"`. Of the 17 credited
targets, zero. **So 13/13 and 4/15 are genuinely uncontaminated and need no
annotation** — the plan's bottom line stands; only its evidence is wrong. Recommend
§2 cite the structured field instead of a script grep.

**Related, and worth adding to §2:** the same records show the sweep *ran* on 12
target-runs (1 in R1, 11 in R2), each executing 14 × 9 = 126 `verify_payload` calls, over
five reps — on the order of 7,500 verified payload deliveries across the two archived
runs. R2's failing targets average 122-172 s per rep. "Inertness on R1/R2" is true of
*credit* and false of *cost*; the distinction matters for I2's timing story and
strengthens §7.

### 1.9 Claim 9 — CONFIRMED

`orchestrator.py:134` stores `self.timeout`. Two consumers only: `:143`
`PipelineVerifier(..., timeout=timeout, ...)`, and `:187`
`run_dynamic_profile(self.context, timeout=min(self.timeout, 2.0))`. No third reference.
Executor probes use the hardcoded literals in §1.3. `--timeout 20` therefore raises the
verifier budget and leaves every probe at 1.5-3.0 s, as claimed.

---

## 2. Question A — can each §5 negative-report proof actually fail?

| instrument | can it go red? | assessment |
|---|---|---|
| I1 | **Yes** | Strongest design. The proof has a built-in positive control: today the raise path (`orchestrator.py:205-207`, `applicable = False`) and the genuine-non-match path both fall into `:209-213` and produce the identical `"not applicable to this target"`. A broken instrument leaves them identical and the assertion fails. Sound. |
| I2 | **Partially — can pass vacuously** | See m1. |
| I3 | **Yes** | The differential clause ("a different candidate yields a different record") is what makes it non-vacuous. A constant or placeholder provenance fails the second half. Sound. |
| I4 | **Yes, but at 2 of 9 sites only** | The proof as written is falsifiable, but it can only be *written* where an `AttemptRecord` exists. See BLOCKING B1. |
| I5 | **Yes** | Best of the five. Three-way differential — sweep-exhaust, raise, and `_test_scanf_bypass` returning `False` — and the third pair are today indistinguishable, so it is a genuine positive control. Sound. |

**MINOR (m1) — I2's proof can pass vacuously.** "Patch an executor to sleep; assert the
recorded duration reflects it and is not zero/absent" is satisfied by an implementation
that stamps a single whole-run duration onto every `AttemptRecord`. A one-executor test
cannot tell per-attempt from per-run. Fix: assert that two executors in the same run
record *different* durations, and that the sleeping one's exceeds the other's.

**MINOR (m1b) — the prescribed mutation is necessary but not sufficient.** "Revert each
instrument and confirm its test goes red" catches *absence* only. It cannot catch a
*constant-valued* instrument: `duration = 1.0` hardcoded, or `failure_reason = "failed"`,
both survive that mutation while measuring nothing. Given that this project's signature
defect is validation that cannot fail, add the mutation that actually targets it — leave
the instrument in place and make it report a wrong or constant value, then confirm the
test still goes red. Applies specifically to I2 and I5, whose assertions are closest to
mere non-emptiness. I1, I3 and I5's three-way form already resist this.

---

## 3. Question B — is the instrument set sufficient to settle §1's six rows?

| row | instrument | sufficient? |
|---|---|---|
| discovery past 30 s (Fork B) | I2 | **Necessary, not sufficient** (M5) |
| per-target pipeline time vs harness overhead | — | **No instrument exists** (BLOCKING B2) |
| new primitive vs retained legacy fallback | I3 | **Necessary, not sufficient** (M4) |
| why the nine stub targets skipped a technique | I1 | Sufficient, subject to opt-in coverage |
| deterministic probe timeout | I4 | Necessary; infeasible as scoped (B1) |
| why `variable_overwrite` failed on 11/11 | I5 | **Sufficient** — clean |

**"Nine stub targets" — confirmed.** Nine R2 slugs produce the universal/stub template;
9 × 5 reps = the 45 R2 scripts found in §1.8. The count is right.

### 3.1 I2 and the per-technique discovery-time threshold — MAJOR (M5)

Two problems.

**Scope.** §4.2 commits I2 to "wall-clock around `attempt()` only". A "discovery past
30 s" threshold is measured from run start, and `orchestrator.py:186-188` runs
`run_static_analysis`, `run_dynamic_profile` and `acquire_leaks` *before* the first
`attempt()`. Summing per-attempt durations therefore undercounts by the whole profiling
prologue, whose size is unknown and unmeasured. I2 tells you which technique consumed the
time; it does not yield a from-run-start figure. Fix: time those three stages too — three
more wall-clock pairs in the same function, no extra risk.

**Overstated absence.** "`AttemptRecord` has **no timing field**" is literally true
(`contracts.py:79-94`), but the row's implication — that discovery time is unmeasurable
today — is not. `report.json` already carries per-target `elapsed_sec` and
`elapsed_sec_total`, and per-rep `elapsed_sec` in `attempts[]` (R2 `01` reads
`[139.9, 137.1, 136.9, 136.6, 135.9]` — reproducible to ~1 %). `VerificationReceipt`
already carries `verified_at` (`contracts.py:134`), an absolute epoch timestamp on the
winning attempt. A target-level 30 s threshold is measurable *today*; what is missing is
per-technique attribution. That is still worth building, so the conclusion holds — but
rev 1 was rejected for claiming a capability needed adding when it already existed, and
this is a milder instance of the same reflex. State what exists, then state what it
cannot do.

### 3.2 I3 and the regression gate — MAJOR (M4)

I3 supplies the field. It does not supply the gate, and the plan schedules no gate for
it: §6 step 2 requires the R1 gate to assert the technique map only. Provenance recorded
but unasserted distinguishes nothing.

Worse, the vacuity risk is structural. §4 scopes I3 to executors "that search
candidates", i.e. opt-in. An unconverted executor emits no provenance, so a gate phrased
as "if provenance is present it must equal *X*" passes trivially on exactly the executors
that have not been converted — a test that asserts absence, in the precise pattern this
project keeps rediscovering. Fix: pair I3 with an explicit list of techniques for which
provenance is **required**, and have the gate fail when a required provenance is missing,
not only when it mismatches.

### 3.3 BLOCKING B2 — §1 row 2 has no instrument

Row 2's missing instrument is named in the plan itself: "`autopwn_json_probe` carries
**no duration**". Confirmed — that object contains `returncode`, `wall_timed_out` and
`parsed`, and nothing else. But `autopwn_json_probe` is produced by
`benchmark/run_bench.py`, and:

- §4.1's files-touched table lists no `benchmark/` file; and
- §9 states "No change to the harness's verification logic".

So the table that is "the plan's entire justification" contains a row that nothing in the
plan will settle. Either add `benchmark/run_bench.py` to §4.1 and narrow the §9 non-goal
to *verification/classification* logic specifically (adding a duration field is neither),
or strike the row and stop claiming it is addressed. Note the neighbouring
`verification` and `negative_control` objects already carry `timed_out`, so a
`duration_sec` on the probe is consistent with the existing shape and low-risk.

---

## 4. Question C — does "instrumentation only, no capability change" hold?

**Not as written.** I5 holds cleanly; I2 and I3 hold; **I1 and I4 do not**.

### 4.1 I5 — holds, with one meaning change to declare

Nothing in the codebase branches on `failure_reason`. Every consumer is display or
serialisation: `cli.py:2420` (table row), `orchestrator.py:353` (log line),
`handoff.py:53/108/292`, `templates.py:38`, `contracts.py:101` (`to_dict`). Control flow
is untouched. The orchestrator's best-partial selection keys on `outcome` and
`partial_artifacts`, not on reasons. I5 is genuinely behaviour-neutral.

**MINOR (m4):** `handoff.py:292` reads
`failure_reason = record.failure_reason or record.error or None`. For
`scanf_canary_bypass`, today `record.error` is set (`heap_and_bypass.py:107`) and
`failure_reason` is empty, so the handoff reports the exception text. After I5 the new
`failure_reason` wins and the handoff's field changes source. §4.1's "No existing field
changes meaning" is therefore not strictly true. §5's I5 proof already requires the
exception text to reach `failure_reason`, so the two are consistent — but pre-declare it
rather than leave a reviewer to find it.

### 4.2 The script-audit path — checked, and already safe

Worth recording because it is the one plausible mechanism by which "recording only" text
could move a published figure, and the plan does not mention it.

`templates.py:38` interpolates `failure_reason` directly into the generated script:

```python
        f"#   - {a.technique}: {a.outcome.name}" + (f" ({a.failure_reason})" if a.failure_reason else "")
```

and `benchmark/run_bench.py:626-627` audits generated scripts with

```python
_SCRAPES_BINARY_RE = re.compile(
    r"""\b(strings|objdump|readelf|xxd)\b|\.(search|string)\s*\([^\n]{0,40}FLAG""")
```

a bare word match on `objdump`, whose hit routes through `script_cheat_reason`
(`:692-695`) to a cheat verdict. The repo already produces such strings — e.g.
`input_shape_techniques.py:101`, `"comparison_immediates: objdump pass failed"`. So a
reason string mentioning `objdump` reaching an audited script would VOID an honest
target.

**It cannot.** `inspect_generated_script` strips comments and docstrings first
(`run_bench.py:645`, implementation `:657-678`), and its docstring at `:633-636` says
this was done for exactly this reason. Both interpolation paths (`templates.py:38` and
`:145`) emit `#`-prefixed lines inside the module docstring, so both the AST path and the
unparseable fallback (`:664`, `line.split("#")[0]`) remove them. Verified safe. §4.2
should cite this rather than leave the hazard unaddressed — a future instrument that
writes provenance into *executable* code would not be covered.

### 4.3 I1 — MAJOR (M3): the predicate is not side-effect-free

`contracts.py:178-180` states executors "should not do network/process I/O here".
`LeakedStackShellcodeExecutor` violates it:

```
shellcode_techniques.py:62      return self._probe_stack_leak(context) is not None
shellcode_techniques.py:64-66   def _probe_stack_leak(...):
                                    result = deliver_parts(binary_path, [], cwd=binary_dir, timeout=1.5)
```

Its applicability decision *is* a process spawn with a 1.5 s timeout — the shortest
budget of all nine sites, and one that on timeout silently returns `None` and turns the
technique off. A companion reason hook that re-derives the reason will therefore either
re-run the probe (doubling spawns and, because the probe is timing-sensitive, potentially
returning a *different* answer than the decision it is supposed to explain — a reason
that contradicts its own verdict), or it must cache the first result, which means
`is_applicable` has to be restructured to produce decision and reason together. The
latter is the signature change §4 explicitly rejects.

§4's I1 risk note covers "a typo in any predicate silently turns a technique off" but not
"the predicate is not idempotent". This must be resolved before I1 touches
`shellcode_techniques.py`. `ScanfCanaryBypassExecutor.is_applicable`
(`heap_and_bypass.py:50-53`) reads `context.protections.canary` and `binary.plt` only —
cheap and pure, a safe first conversion target.

### 4.4 I4 — BLOCKING (B1): infeasible as scoped

§4 scopes I4 as "9 `deliver_parts` call sites across 6 executor modules", risk
**medium**, mitigated by landing it "as *recording only* — no branch changes". The
enclosing-function mapping refutes the premise:

| site | enclosing function | `AttemptRecord` in scope? |
|---|---|---|
| `input_shape_techniques.py:252` | `attempt()` | **yes** |
| `fmtstr_techniques.py:102` | `attempt()` | **yes** |
| `shellcode_techniques.py:66` | `_probe_stack_leak` | **no — none exists yet** |
| `heap_techniques.py:70` | `discover_menu` (module-level) | no |
| `rop_techniques.py:359` | `_probe_pie_leak` | no |
| `fmtstr_techniques.py:138` | `_find_buffer_arg_index` | no |
| `fmtstr_techniques.py:175` | `_write_targets` | no |
| `canary_leak_techniques.py:154` | `_probe_fmtstr_indices` | no |
| `canary_leak_techniques.py:180` | `_probe_echo_sizes` | no |

Only **2 of 9** can record into the attempt record without a signature change. Six of the
remaining seven return plain values (`Optional[int]`, `List[int]`, `Dict[str, int]`,
`Optional[Tuple[int, str, int]]`) and must change signature or return type to carry a
timeout flag out. The seventh is worse: `_probe_stack_leak` is reached from
`is_applicable` at `shellcode_techniques.py:62`, which runs *before* `attempt()` creates
any `AttemptRecord` (`orchestrator.py:204` precedes `:217`). There is nothing to record
into at that point in the lifecycle.

Concrete failure this causes: implemented as scoped, I4 lands at the two easy sites, its
§5 proof passes there, and the §1 row it exists to settle stays unsettled — because the
sites that actually produce the stub targets are `_find_buffer_arg_index` and
`_probe_fmtstr_indices`, the two that abandon an entire sweep on a first-window timeout
(§1.3, m2), and neither is reachable. The re-run then reports no deterministic timeouts
and the plan concludes none exist. That is a validation that cannot fail, arrived at by
scope rather than by assertion.

Fix: either thread a per-attempt collector (a mutable diagnostics object on
`ExploitContext`, which also solves the `is_applicable` case since the context predates
the record) or have `deliver_parts` callers accumulate into a context-level list. Then
re-rate I4's risk and name the seven helpers individually in §4.1.

### 4.5 "If either published figure moves, that is a defect in the instrumentation" — MAJOR (M7)

Enforceable for R1, not for R2.

R1 is a repeatable gate: same corpus, 13/13, re-runnable, so a movement is attributable.
R2 is not — §6 step 6 concedes that R2 re-runs "are training-set measurements and
**cannot restate the cold figure**, which is spent". So if the instrumented R2 re-run
returns other than 4/15, the sentence provides no way to separate an instrumentation
defect from ordinary post-cold drift, and the rule cannot be applied. As written it reads
as a guarantee and functions as neither a gate nor a diagnostic.

Restate as: R1's 13/13 with the per-target map is the enforcement instrument and any
movement there blocks the pass; the R2 re-run is diagnostic only and no figure claim
attaches to it.

---

## 5. §6 step 2 — parser hardening vs the structured field

**BLOCKING (B3). Use the structured field. It already exists, and I used it to produce
both complete maps in §1.5 in a single pass with no header parsing.**

Every result object in both archived `report.json` files carries:

- `autopwn_json_probe.parsed.technique` — the winning technique name, straight from
  `orchestrator.technique_used` (`orchestrator.py:229`); and
- `autopwn_json_probe.parsed.attempts[]` — the full `AttemptRecord.to_dict()` list, with
  per-technique `outcome`, `failure_reason`, `stage_reached`, `notes`.

This field returned `15_win_function → ret2win` directly — the exact row the rev-2 text
parser dropped, and the reason §2.1 exists. Hardening the
`(technique: X)` / `Technique: X` parser re-creates the failure mode it is meant to fix:
a third header format, or a template change, silently drops a row again and the gate goes
green on 12 of 13. A parser is the wrong instrument for data that is already structured.

Two implementation notes for the gate:

1. Assert a 13-entry **slug → technique** mapping, not a multiset (§1.5, M2), and pin
   `05_fmtstr_arbread → canary_leak_ret2win` explicitly so the off-intent credit is
   visible in the gate rather than buried.
2. Exclude the VOID slugs **by name**. `13_off_by_one` is VOID but still reports
   `parsed.technique == "ret2win"`, so a naive "every slug with a technique" filter
   yields 14 entries, not 13. This is a live off-by-one waiting to happen in precisely
   the place the document is trying to harden.

---

## 6. §7 — sourcing candidates from `comparison_immediates()`

**Reasoning sound; recommendation endorsed; one caveat.**

The asymmetry the plan draws is real and correctly drawn. A buffer offset is a
mechanically derivable quantity that *any* correct value satisfies, so searching for it
measures capability. A gate constant must equal a specific immediate in the target's
instruction stream; a folklore hit measures nothing about the framework's analysis and
generalises to no other binary. Crediting a target because `0xdeadbeef` was in a
nine-element list is not a capability claim. Sourcing candidates from
`comparison_immediates()` (`input_shape_techniques.py:68`, currently one caller) fixes
the actual defect with code already in the repo. Rejecting "leave as is until after R5"
is right: R5 is single-use.

**MINOR (m5) — the caveat.** §7 argues "the buffer-size sweep is legitimate — searching
for an offset is normal, and `find_return_offset()` already exists for it." But
`VariableOverwriteExecutor` does **not** call `find_return_offset()`; it uses its own
hardcoded 14-element list at `stack_techniques.py:76`
(`[32, 40, 48, 56, 60, 64, 72, 80, 96, 100, 104, 112, 120, 128]`). The buffer sweep is
legitimate *in kind* but hardcoded *in fact*, and citing `find_return_offset()`
(`delivery.py:225`) as though it were in use understates the work. The principled version
routes the offset through `find_return_offset()` and the value through
`comparison_immediates()`, leaving no hardcoded list.

**Two points that strengthen §7, both from the artifacts.** First, the sweep is reached
only after everything ordered before it has failed (`orchestrator.py:197`,
`if self.successful: break`) — which is exactly the state a hard R5 target will be in. R5
is where a spurious credit is *most* likely, not least; §7's risk framing should say so.
Second, §7's option table omits the cheapest mitigation: `VariableOverwriteExecutor` is
the one executor of seventeen with no `is_applicable` (§1.1), so adding a predicate
bounds the exposure without deleting a technique class — a third option that dominates
"disable it entirely" on the plan's own reasoning.

---

## 7. CHANGELOG claim — correct

"These change generated-script contents, so user-visible" is right, and verifiable.
`templates.py:38` interpolates `failure_reason` into the generated script's attempt log,
so I5 changes generated-script bytes on every target that reaches either swallowing site
— 12 target-runs across the two archived runs. Today R1 `11_heap_uaf_leak` renders
`#   - variable_overwrite: FAILED`; after I5 it renders a parenthesised reason. That is a
user-visible artifact change. `[Unreleased]` is the right section.

I2/I3/I4, landed as record fields only, are user-visible in `report.json` but not in
scripts. Worth splitting the entry accordingly so the claim stays honest per instrument.

---

## 8. §4.1 files-touched — gaps

**MAJOR (M6) — `AttemptRecord.to_dict()` is not mentioned.** `contracts.py:96-112` is an
explicit dict literal, not a `dataclasses.asdict`. A new field that is not added there
never reaches `autopwn_json_probe.parsed.attempts`, which is the only place §6 step 4
("re-derive the failure table from artifacts") can read it. Concrete failure: I2/I3/I4
land, their in-process tests pass, the re-run completes, and the artifacts are byte-identical
to today's — the instruments exist and measure nothing observable. §4.1 lists
`contracts.py` for "new `AttemptRecord` fields", which a reader may take as covering it;
say `to_dict()` explicitly, and add an artifact-level assertion to §5 (the new keys must
be present in a real `report.json`, not just on an in-memory record).

Also missing or wrong:

- **No `benchmark/` file**, though §6 step 2 needs an R1 gate assertion and §1 row 2
  needs a probe duration. See B2/B3. The §9 non-goal needs narrowing to match.
- **`handoff.py`** will change output via `:292`'s precedence (m4) — not listed.
- **"the 6 executor modules with `deliver_parts` call sites"** is too coarse for I4. Name
  the seven helper functions (§4.4); each needs an individual signature decision, and the
  row as written hides that.
- `templates.py` correctly needs no edit (`:38` already renders `failure_reason`
  conditionally) — no finding, but worth a sentence so a reader does not assume an
  omission.

---

## 9. Sequencing

Two changes to §6's order.

**The gate must precede the first executor conversion.** §6 lists "instruments land, each
with its negative-report proof and the R1 gate green" as step 1 and the complete-map gate
as step 2. Invert them. The per-target map gate is what detects an I1-induced regression;
running I1 conversions against a count-only gate is the configuration that let the rev-2
error through in the first place.

**I1 and I4 should land after the diagnostic re-run, not before.** I2, I3 and I5 are pure
additions with no control-flow surface (§4.1 verified for I5; I2/I3 are write-only
fields). I1 is the one instrument the plan itself concedes can silently lower a score,
and it has the non-idempotent-predicate problem (M3). I4 is a seven-helper refactor
(B1). Landing both before the re-run means any movement in the re-run has two candidate
causes, and §9's "any movement is an instrumentation defect" rule cannot localise which.
Recommended order:

1. R1 per-target map gate, from the structured field (§5).
2. I2 + I3 + I5, with proofs and artifact-level assertions.
3. Instrumented R1/R2 re-run — the diagnostic baseline.
4. I5's re-derived failure table (§6 step 4); this alone settles §1 row 6 and most of
   row 4's motivation.
5. I1, one executor at a time, cheapest predicate first
   (`ScanfCanaryBypassExecutor`), with `LeakedStackShellcodeExecutor` last and only
   after M3 is resolved.
6. I4, rescoped per §4.4.

Nothing else in the pass needs to be held. §7's decision correctly sits outside this
pass, and the R5-access block should stay in force — concur, no finding.

---

## 10. Findings index

**BLOCKING**

- **B1** — I4 infeasible as scoped: 7 of 9 `deliver_parts` sites have no `AttemptRecord`
  in scope, and `shellcode_techniques.py:66` (via `is_applicable` at `:62`) is reached
  before any record exists (`orchestrator.py:204` precedes `:217`). Sites:
  `shellcode_techniques.py:64/66`, `heap_techniques.py:61/70`,
  `rop_techniques.py:354/359`, `fmtstr_techniques.py:132/138`, `:151/175`,
  `canary_leak_techniques.py:147/154`, `:174/180`. Failure: I4 lands at the two easy
  sites, its proof passes, and the sweep-abandoning sites that produce the stub targets
  stay unmeasured — the re-run then reports no deterministic timeouts and the plan
  concludes none exist.
- **B2** — §1 row 2 has no instrument. The named gap is a duration on
  `autopwn_json_probe`, produced in `benchmark/run_bench.py`; §4.1 lists no `benchmark/`
  file and §9 forbids harness changes. Failure: the justification table claims to settle
  a row that nothing in the plan touches.
- **B3** — §6 step 2 unexecutable and mis-specified. §2 contains no 13-row per-target map
  (§1.5), and the prescribed "method that handles both header formats" hardens a text
  parser when `autopwn_json_probe.parsed.technique` already yields the complete map.
  Failure: a third header format drops a row again and the gate greens on 12 of 13.
  Secondary: `13_off_by_one` is VOID yet reports `technique=ret2win`, so a naive filter
  yields 14 rows.

**MAJOR**

- **M1** — §2's "`variable_overwrite` appears in exactly one generated script across both
  runs" is refuted: 1 in R1, 45 in R2, 46 total. R2 was not searched. Conclusion survives
  via `parsed.technique` (0 of 17 credited targets); no figure needs annotation.
- **M2** — §2's multiset conceals `05_fmtstr_arbread → canary_leak_ret2win`, which §8
  reasons about target `05` without noting; and a multiset gate cannot catch a
  technique swap between two targets.
- **M3** — I1 not behaviour-neutral: `shellcode_techniques.py:49-62` performs process I/O
  in `is_applicable`, against `contracts.py:178-180`. A reason hook re-running the 1.5 s
  probe can return a verdict contradicting the decision it explains.
- **M4** — I3 necessary, not sufficient: no gate is scheduled to assert provenance, and
  its opt-in scope makes a presence-conditional gate pass vacuously on exactly the
  unconverted executors.
- **M5** — I2 excludes the profiling prologue (`orchestrator.py:186-188`) so it cannot
  yield a from-run-start threshold; and "no timing field" overstates absence given
  `elapsed_sec` per target and per rep, and `VerificationReceipt.verified_at`
  (`contracts.py:134`).
- **M6** — `AttemptRecord.to_dict()` (`contracts.py:96-112`) is an explicit dict and is
  not mentioned; unlisted fields never reach the artifacts §6 step 4 reads.
- **M7** — "if either published figure moves, that is a defect in the instrumentation" is
  unenforceable for R2, which §6 step 6 concedes cannot be restated.

**MINOR**

- **m1** — I2's proof passes vacuously on per-run-vs-per-attempt mis-attribution; needs a
  two-executor differential.
- **m1b** — "revert each instrument and confirm its test goes red" catches absence only,
  not a constant-valued instrument; add a wrong-value mutation for I2 and I5.
- **m2** — "and `continue`s" literal at 3 of 9 sites; `fmtstr_techniques.py:141-142` and
  `canary_leak_techniques.py:157-159` abandon an entire sweep on a first-window timeout,
  which understates the plan's own case.
- **m3** — the "caller-supplied" timeout has one caller (`heap_techniques.py:213`) that
  passes nothing, so it runs at 3.0.
- **m4** — `handoff.py:292` precedence means I5 changes handoff output for
  `scanf_canary_bypass`; "No existing field changes meaning" is not strictly true.
- **m5** — §7 cites `find_return_offset()` as though in use; `stack_techniques.py:76`
  hardcodes its own 14-element list.
- **m6** — line-range drift: `MAGIC_VALUES` is `:59-62` not `:59-63`; the sweep is
  `:78-93` within a `:73-96` method, not `:76-93`; the orchestrator region is `:203-213`,
  not `:202-206`. Negligible individually; noted because this document's lineage is
  line-accuracy.
- **m7** — §4/§7 omit that `VariableOverwriteExecutor` is the only executor of 17 with no
  `is_applicable` (`contracts.py:181` default). That is *why* the 126 calls are
  unconditional, and adding a predicate is a third §7 option that dominates "disable it".
- **m8** — the script-audit hazard (`templates.py:38` → `run_bench.py:626`'s bare
  `\bobjdump\b`) is already closed by comment/docstring stripping
  (`run_bench.py:645/657-678`); cite it in §4.2 rather than leaving it for a reviewer.

---

## 11. Verdict

The method change is genuine and I want to be explicit about that: the rev-2 table defect
is actually fixed, the multiset matches the artifacts exactly, five of nine claims are
confirmed to the line, and §3's observation about `comparison_immediates()` is the most
useful thing produced in this round. I5 is a model instrument — sufficient for its row,
behaviour-neutral under verification, and with a three-way proof that cannot pass
vacuously. Nothing here is a thinking error of the kind that sank the predecessors.

But the document still carries one refuted artifact claim made in the predecessors' exact
shape (M1: a search narrower than the sentence describing it), and three of its five
instruments are specified in ways that will not deliver what §1's table promises — I4
cannot be built as scoped, row 2 has no instrument at all, and the step-2 gate points at
a table that does not exist while a structured field sits unused in every `report.json`.
Since §1's table is stated to be the plan's entire justification, those are not
refinements.

All of it is fixable in place, and none of it requires a new document — a revision of
§§1, 4.1, 5, 6 and 7 against the findings above should clear it.

**NOT-APPROVED**

---
---

# Round 2 — re-review of revision 2 (`2729940`)

**Reviewed commit:** `2729940` (`docs(plans): revise instrumentation pass against review 31196d2`)
**Prior review:** round 1 above, committed `31196d2`, NOT-APPROVED on B1/B2/B3 + M1-M7.
**Code tree:** `git diff --stat b3a40b4 2729940 -- supwngo/` is **empty** — `supwngo/`
genuinely untouched, so round-1 line citations remain valid without re-derivation.
**Artifacts:** same two `report.json` files as round 1.
**Method:** each of the six new claims re-derived from code; both author push-backs
adjudicated against the source; the three coordinator risks (R1/R2/R3) examined
independently of my own findings. Nothing accepted as "addressed".

## 11. Verdict first, then the work

The three blockers are **genuinely fixed**, and I checked the fixes rather than the
disposition table. B3 in particular is fixed the right way: the header parsing is deleted
rather than taught a second format, the gate reads `parsed.technique`, the §2.1 map matches
my independently extracted table row for row, and both gate traps I flagged are pinned by
name. B1's re-scope is the strongest edit in the revision — §5 now *mandates* the I4 proof
at a sweep-abandoning site with window-1-of-*n* versus *n*-of-*n*, which is precisely the
assertion that makes the old failure impossible to reproduce.

The six new claims are almost all exactly right, including the two most checkable ones
(21 sites; single generic origin). **Both push-backs against me are correct** — I was wrong
that the script-audit hazard was live, and the author's sharpening of M3 is better than my
original. §4.0's "inventory before proposing" rule is a real structural addition, and it
already paid for itself by converting I1 from a new hook into a migration.

Five MAJOR defects remain. None invalidates an instrument's design, none changes the
sequencing, and all five are text or gate-specification fixes. The most consequential —
I1's risk stated in one direction when it is bidirectional — is caught in practice by the
per-target gate landing at step 1 and running after each conversion. **No blocking
findings. Approved, with the five MAJORs binding before their corresponding step lands.**

## 12. The six new claims

| # | claim | verdict |
|---|---|---|
| 1 | I4 collector reaches all 9 sites; per-window recording | **CONFIRMED with one gap** (m9) |
| 2 | 21 specific-skip sites; generic string from one place | **CONFIRMED exactly** |
| 3 | per-target timing already exists; I2's contribution narrowed | **CONFIRMED** |
| 4 | the 13-row map and its two gate traps | **CONFIRMED exactly** |
| 5 | `templates.py:145` renders `record.notes` | **CONFIRMED** |
| 6 | only 1 of 17 executors lacks `is_applicable` | **CONFIRMED** |

### 12.1 Claim 2 — CONFIRMED exactly, and it is the revision's best work

`grep -rn "AttemptOutcome.SKIPPED" supwngo/exploit/pipeline/executors/` returns **exactly
21**. I checked the line after each of the 21 and **all 21 set a specific
`failure_reason`** — e.g. `rop_techniques.py:217` `"no '/bin/sh' string in the binary
image"`, `:227` `"no 'pop rdi; ret' gadget to load system()'s argument"`, `:847`
`"Full RELRO: the GOT is resolved at startup, so there is no lazy resolver to abuse"`,
`shellcode_techniques.py:79` `"target leaks no stack address to aim the return at"`. Not
one is generic or absent.

The generic string originates from **exactly one place** in `supwngo/`:
`orchestrator.py:212`, inside the `:203-213` branch, which also swallows an
`is_applicable` exception into it via `:205-207`. The only other occurrences anywhere are
`tests/test_pipeline_handoff.py:69` (a fixture) and generated artifacts under
`benchmark/results/`. Both claims hold.

This inventory earns its place: it is what turns I1 from "add an optional hook to 17
classes" into "use the idiom 21 sites already use", and that is a genuine reduction in
scope and risk. Minor citation drift only: the plan cites `rop_techniques.py:216` and
`:226` for the quoted strings, which are the `record.outcome` lines; the strings are at
`:217` and `:227`.

### 12.2 Claim 4 — CONFIRMED exactly

§2.1's 13 rows match the table I extracted in round 1 from `parsed.technique` row for row,
including `05_fmtstr_arbread → canary_leak_ret2win`. R2's four match positionally. Both
gate traps are correctly stated and correctly attributed: `13_off_by_one` is VOID
(`corpus_trivially_solvable`) yet still reports `technique == "ret2win"`, so an unfiltered
count yields 14; and `05`'s off-intent credit is pinned. §8 now carries the correction
rather than leaving the old phase-1a argument standing — I checked that specifically,
because a fix landing in §2 while §8 kept the old assumption is exactly the failure mode
I was asked to watch for. It does not happen here.

§6 step 1 also adds the right positive control: "swap two targets' expected techniques and
confirm failure — a multiset gate cannot catch that". That is a gate proven red before it
is trusted.

### 12.3 Claims 3, 5, 6 — CONFIRMED

Claim 3: `elapsed_sec` and `elapsed_sec_total` per target, per-rep `elapsed_sec` in
`attempts[]` (R2 `01` = `[139.9, 137.1, 136.9, 136.6, 135.9]` — the exact values I
measured), `VerificationReceipt.verified_at` at `contracts.py:134`. The narrowed
contribution — per-*technique* attribution — is the correct residue, and §4 I2 now states
the inventory before the proposal rather than asserting absence. M5's framing half is
fixed.

Claim 5: `templates.py:145` is
`notes_block = "\n".join(f"# - {n}" for n in record.notes) if record.notes else ""`,
rendered at `:157`. And `input_shape_techniques.py:241-242` does append
`"candidate gate values from the binary's own cmp insns: ..."` to `notes`, so prose
provenance already reaches generated scripts today. The design constraint the plan draws
from this — provenance must be a structured field, not `notes`, because a gate cannot
assert prose and prose is the half that lands in audited script text — is correct and is
the right conclusion. (The append is at `:241-242`; the plan cites `:240-241`, where `:240`
is the `comparison_immediates(binary)` call.)

Claim 6: confirmed in round 1 §1.1 and unchanged — `VariableOverwriteExecutor`
(`stack_techniques.py:67`) is the only one of 17 with no `is_applicable`, inheriting
`contracts.py:181`'s `return True`.

### 12.4 Claim 1 — CONFIRMED, with one gap and one wrong number

**The collector design is sound.** `ExploitContext` is constructed at
`orchestrator.py:137`, in `__init__` — earlier even than the `:204`/`:217` ordering the
plan cites — so the channel genuinely predates every probe, and `_probe_stack_leak`'s
pre-record case is covered. All 9 sites are in scope, none is declared out of scope, and
per-window recording does distinguish the two cases: at `fmtstr_techniques.py:141-142` and
`canary_leak_techniques.py:157-159` abandonment happens only when `start == 1`, later
windows `continue`, so 1 record versus *n* records is exactly the discriminator needed.
`timed_out` also separates a genuine no-hex target from a stalled probe, which is the
whole point.

**MINOR (m9) — 4 of the 9 sites have no `context` either.** The plan's Design paragraph
argues from "the context predates the `AttemptRecord`", which solves reachability only
where `context` is in scope. It is not, at four sites:

| site | signature | has `context`? |
|---|---|---|
| `heap_techniques.py:70` | `discover_menu(binary_path, cwd, timeout)` — module-level | **no** |
| `fmtstr_techniques.py:138` | `_find_buffer_arg_index(self, binary_path, binary_dir)` | **no** |
| `canary_leak_techniques.py:154` | `_probe_fmtstr_indices(self, binary_path, binary_dir)` | **no** |
| `canary_leak_techniques.py:180` | `_probe_echo_sizes(self, binary_path, binary_dir)` | **no** |

`_probe_stack_leak`, `_probe_pie_leak` and `_write_targets` do take `context`; the two
`attempt()` sites have both. So the collector reaches 5 of 9 without a signature change.
Critically, **the two sites §5 mandates the proof at — `_find_buffer_arg_index` and
`_probe_fmtstr_indices` — are both in the context-less set**, so threading `context` (or a
collector handle) into them is not optional work that can be deferred. The plan's risk
note ("seven helpers each need a signature or return-type decision") does cover this
generically and the risk is honestly re-rated to medium-high, which is why this is MINOR
rather than a repeat of B1 — but the Design paragraph reads as though the context channel
settles reachability, and it does not. `discover_menu` has one caller
(`heap_techniques.py:213`) and no test callers, so its signature change is contained.

**MINOR (m10) — "completes 40 windows" is wrong; it is 8.** `_find_buffer_arg_index`
iterates `range(1, MAX_ARG_INDEX + 1, ARG_WINDOW)` with `MAX_ARG_INDEX = 40` and
`ARG_WINDOW = 5` (`fmtstr_techniques.py:50-51`) — **8 windows**.
`_probe_fmtstr_indices` iterates `range(1, FMTSTR_MAX_INDEX + 1, FMTSTR_WINDOW)` with
`48` and `6` (`canary_leak_techniques.py:48/51`) — also **8 windows**.
`_probe_echo_sizes` iterates `ECHO_FILL_SIZES`, 13 entries
(`canary_leak_techniques.py:45`). 40 is the maximum *argument index*, not the window
count, and no site has 40 windows. The design is unaffected — 1-of-8 versus 8-of-8 is
still the right discriminator — but this is a number asserted about code that the code
contradicts, in text written to fix a blocker, which is the one error class this document
exists to eliminate. Worth fixing precisely because it is small.

## 13. The two push-backs, adjudicated

### 13.1 The `objdump` hazard — **the author is right; I was wrong**

`input_shape_techniques.py:101` is
`logger.debug(f"comparison_immediates: objdump pass failed: {e}")` — a logger call, not a
`failure_reason`. It never reaches `templates.py:38`. My round-1 §4.2 cited it as evidence
that "the repo already produces such strings", which is true of the string and misleading
about the path, and it implied a live hazard.

I checked the stronger form of the author's claim too: scanning every
`failure_reason = ...` string literal in `supwngo/` for `\b(strings|objdump|readelf|xxd)\b`
returns **zero hits**. So no current `failure_reason` contains an audited word and the
hazard is **prospective, not live**. Conceded in full.

The author's use of the correction is better than mine: it matters *because* I5 and I3 are
about to write new reason and provenance strings, and a provenance string naming its
extraction method is exactly the text that would trip it. That reframes m8 from "already
handled, nothing to do" into a live design constraint on I3 — which §4.3 then draws
correctly. This is the revision arguing with the review and improving the result, which is
what a review is for.

### 13.2 The `shellcode_techniques.py:61` short-circuit — **the author is right, and it strengthens M3**

`:60-61` is `if context.leaks.get("stack"): return True`, so the 1.5 s spawn at `:62`→`:66`
happens only when the profiling stage missed the leak's phrasing. The author is right that
this *strengthens* the point: the predicate's cost **and its answer** depend on upstream
pipeline state, so it is not merely impure, it is non-deterministic with respect to
history. A companion reason hook re-running it could legitimately disagree with the
verdict it was explaining. Agreed.

One bound to add in the plan's favour: the short-circuit also means that on every target
where `profile_stage` did recognise the leak, there is **no spawn at all**, so the
migration is fully inert for those targets. The exposure is confined to the fallback path.

**And a correction in the plan's favour that changes I1's cost story.**
`LeakedStackShellcodeExecutor.attempt()` at `:76` is
`leak = context.leaks.get("stack") or self._probe_stack_leak(context)` — it **already
re-checks the same condition** and already returns `SKIPPED` with the specific reason at
`:78-79`. So today, when `leaks["stack"]` is empty and the probe succeeds, the target is
spawned **twice**: once in `is_applicable` (`:62`) and again in `attempt()` (`:76`).
Enumerating the three cases:

| case | today | after deleting `is_applicable` |
|---|---|---|
| `leaks["stack"]` populated | 0 spawns | 0 spawns — identical |
| leaks empty, probe finds an address | **2 spawns** | 1 spawn — **one fewer** |
| leaks empty, probe finds nothing | 1 spawn, generic reason | 1 spawn, specific reason |

So the plan's "it *moves* a process spawn rather than adding one" understates it: for this
executor the migration is a **deletion** of `is_applicable`, and it **removes a duplicate
spawn**. Runtime cannot increase. `context` is never mutated on the skip path — the only
write is `context.offset = offset` at `:109`, reached on SUCCESS only, which already
happens today. The executor the plan fears most and schedules last is in fact its safest
and cheapest conversion, for the leak half of the predicate. (Not for the whole predicate
— see §14.1.)

I also checked whether the removed spawn could perturb attribution. It cannot:
`attribution_witness` traces the *verification* run (`run_bench.py:936-947`), a separate
invocation from the `autopwn_json_probe` at `:916` where these spawns occur. Attribution
input is unaffected.

## 14. The three coordinator risks

### 14.1 R1 — **I1's risk is real and stated in the wrong direction. MAJOR (M8).**

The plan says I1 "is the only instrument that can silently **lower** a score" and that
"for cheap pure predicates this is inert". Both are wrong.

**Inertness has nothing to do with predicate purity.** It depends on whether `attempt()`
already reproduces the predicate's condition. I checked all 16 predicates against their
`attempt()` bodies. 15 of 16 predicates are pure reads — `context.protections`,
`context.win_function`, `binary.plt`, `binary.symbols`, `context.profile_has_menu`,
`context.profile_is_shellcode_runner`, plus pure helpers — confirming the plan's purity
claim. But four executors have **no guard at all** in `attempt()`, because the 21 SKIPPED
sites include no `input_shape_techniques.py` entries and only one `stack_techniques.py`
entry (`:111`, `Ret2WinExecutor`):

- **`IntTruncationBypassExecutor`** — predicate at `input_shape_techniques.py:136-147`
  excludes menu-driven heap targets *deliberately* (`:142-144`: "skip them so they don't
  pay for a sweep that cannot apply"). `attempt()` at `:235-256` goes straight from
  `comparison_immediates()` into the `INDICES × values` delivery sweep with no guard, and
  reaches `verify_script` on a `_looks_like_win` match. **This one can SUCCEED where it
  previously was skipped.**
- **`NegativeIndexWriteExecutor`** — predicate `:227-233`, same shape, no guard.
- **`DirectShellcodeExecutor`** — predicate `stack_techniques.py:155-156` is maximally
  pure (`not context.protections.nx or context.profile_is_shellcode_runner`), yet
  `attempt()` at `:158-183` spawns the target and calls `verifier.verify_shell` with no NX
  check, and can set SUCCESS at `:179`. **The purest predicate has the least inert
  migration** — which is the counter-example to the plan's stated rule.
- **`FormatStringExecutor`** — predicate `stack:198-199`, no guard (PARTIAL-only, so
  lower impact).

Plus `LeakedStackShellcodeExecutor`, which re-checks the leak at `:76` but **not** the
`nx_off or profile_is_shellcode_runner` half at `:53-55`.

So the risk is **bidirectional**: an incomplete migration can credit a technique that was
previously skipped, or change which technique wins, not only turn one off. And for
essentially every executor except `Ret2WinExecutor` (whose `attempt():110-112` reproduces
its predicate exactly), migration requires **adding** guard code, not moving it — a larger
edit than "a migration into an existing idiom" conveys.

**Is this a capability change wearing an instrumentation label?** No — *given* the
sequencing. The per-target §2.1 gate lands at step 1, the diagnostic baseline at step 3
precedes I1 at step 5, and the gate runs after each single-executor conversion, so a
changed winner is both detected and unambiguously attributable. The before-and-after
coverage the coordinator asked about is therefore already satisfied. But an implementer
following the current text would treat 15 of 16 migrations as inert and omit the guards,
and four of those are not inert. Required corrections: state the risk bidirectionally;
replace "for cheap pure predicates this is inert" with the correct invariant — *inert iff
`attempt()` already reproduces the full predicate*; and enumerate which of the 16 are pure
deletions versus which need a new guard.

### 14.2 R2 — **the narrowing is broader than the field it was written for. MAJOR (M9).**

Two questions, two answers.

**Does `duration_sec` touch verification, attribution, classification or scoring? No —
verified.** `classify()` is called at `run_bench.py:950` with
`(supwngo_json, verify, control, script_audit, strict_attribution, attribution)`, where
`supwngo_json = parse_json_result(out1)` (`:917`) — the *parsed* payload. The
`autopwn_json_probe` wrapper that would carry `duration_sec` is assembled separately at
`:963-968`, in the return dict, for reporting only. It is never passed to `classify`. I2b
is genuinely out of all four categories.

**Can the new wording license something it should not? Yes.** "verification, attribution,
classification or scoring logic" omits two cheat-detection subsystems that are *generated*
separately and only *consumed* by `classify`:

- **negative-control generation** — `negative_control()` builds `controls` at
  `run_bench.py:494-530`, including `bare_run_verify_stdin`, `bare_run_filler` and the
  `bare_run_menu_walk` probe set. `classify` reads the *result* at `:755`. Dropping a menu
  probe weakens cheat detection and makes targets pass without touching `classify` at all.
- **script-audit generation** — `inspect_generated_script` at `:630-654` and
  `script_cheat_reason` at `:681-695`. Same structure: weaken the audit, `classify` is
  untouched, targets pass.

Given the standing constraint that the harness's verification logic is never weakened to
make targets pass, a denylist that omits both cheat-detection generators is the wrong
shape. **Recommended fix: invert to an allowlist** — "the only harness changes in this
pass are an additive `duration_sec` on the probe object and the R1 per-target gate
assertion; nothing else under `benchmark/` is touched." An allowlist cannot be read as
licence for anything, which is the property wanted from a clause that will outlive this
pass and govern the per-phase plans that follow.

### 14.3 R3 — sequencing is consistent. No finding.

I checked the dependency the coordinator named. `VariableOverwriteExecutor` is the one
executor with **no** `is_applicable` (§12.3), so I1 never touches it. I3's first conversion
is that executor, at step 2; I1 begins at step 5. So I3 covering `variable_overwrite` — the
§7 precondition for R5 *measurement* — is satisfied three steps before I1 touches any
applicability predicate. Consistent, and the R5 gate does not depend on I1 at all.

The rest of the order also holds: the gate (step 1) precedes every conversion; I2/I2b/I3/I5
are write-only and correctly grouped at step 2; I1 and I4, the only two with control-flow
surface, land at steps 5 and 6 after the step-3 baseline, so any movement has one candidate
cause. Both `benchmark/run_bench.py` edits (gate at step 1, I2b at step 2) are in the same
file with no conflict. This is a correct reordering and it fixes what round 1 objected to.

## 15. Remaining gate and sufficiency defects

### 15.1 I3's required-provenance gate cannot be proven red on any available data. MAJOR (M10).

Two coupled problems with §4 I3 + §5.

**No positive instance exists.** I3 records "the **winning** candidate and its source", so
provenance is populated only when an attempt produces a payload. `variable_overwrite` wins
on **zero** of 17 credited targets across both runs and returns FAILED on all 12
target-runs where it executes. So on R1 and R2 there is no run in which the required
provenance should be present — and §5's proof, "delete provenance from a required executor
and assert the gate goes red on **missing**", has nothing to delete.

**As worded, the gate would red every R1 run.** "Fails when a required provenance is
missing" is unconditional. `variable_overwrite` is on the required list and produces no
provenance on any of the 13 R1 targets, so the gate fails on all of them. The specification
needs the missing-provenance failure conditioned on the attempt having produced a payload
or reached SUCCESS — otherwise the only two available readings are "always red" or "skip
when absent", and the second is the vacuous assertion-of-absence the gate exists to
prevent.

This matters more than its size because §7 gates **R5 measurement** on I3 covering
`variable_overwrite`, and R5 is single-use. The fix the document already contains is
attached to the wrong item: §7's third row specifies "a fixture with an undisclosed
constant" for the `comparison_immediates()` sourcing work, which §7 explicitly makes *not*
a precondition. That fixture — a binary whose gate constant is in `MAGIC_VALUES`, so
`variable_overwrite` genuinely wins — is what I3's gate needs. **Condition: the fixture and
a red-proven gate exist before §7's R5-measurement gate is treated as satisfied.**

### 15.2 One `duration_sec` does not settle row 2. MAJOR (M11).

`elapsed = time.time() - t0` at `run_bench.py:949` spans everything from
`negative_control()` at `:913` through `attribution_witness` at `:937`. Inside that span
the pipeline runs **twice**: `run_supwngo(... ["--json"])` at `:916` (the probe) and
`run_supwngo(... ["-o", script_path])` at `:922` (script generation). Subtracting only the
probe duration from `elapsed_sec` therefore attributes a second complete pipeline
invocation to "harness overhead", overstating it by roughly a full pipeline run — on R1
`01`, within a 35.8 s target budget.

So I2b as specified yields probe-versus-everything-else, not the pipeline-versus-harness
split row 2 names. The fix is one more field: `autopwn_script_generation` at `:969-972` has
the identical wrapper shape, so add `duration_sec` there too. Otherwise row 2 remains
unsettled — the same failure shape as B2, narrower. Cheap to fix; must be fixed, since
row 2 is the reason I2b was added.

### 15.3 Carried-forward A / B / C against the revised text

**A — can the five proofs fail?** Substantially fixed. The two structural upgrades are the
right ones: mutation to *wrong-but-present* across all five, and artifact-level assertions.
I2's new two-executor differential specifically kills the vacuity I found — a whole-run
duration stamped on every record gives both executors the same value and fails the
differential, and so does a constant, so the differential and the new mutation reinforce
each other. I4's proof is now the strongest in the set because it names the site class the
proof must be written at. I1's and I5's were already sound. I2b's is new and falsifiable
(`duration_sec` present, non-zero, and less than `elapsed_sec` — which holds by
construction given `:949`). Residual: I3's, per §15.1.

**B — sufficiency for §1's six rows.** Improved from 1 of 6 to 4 of 6. Row 1 is now
sufficient, because I2 adds the three prologue stages at `orchestrator.py:186-188` that my
M5 identified. Rows 4, 5 and 6 are sufficient (row 5 subject to m9's signature work). Row 2
is insufficient by one field (M11). Row 3 is designed correctly but its gate is
unimplementable as worded (M10).

**C — does "no capability change" hold?** For I2, I2b, I3, I4 and I5, yes, and I verified
the two that could plausibly have failed: nothing in the codebase branches on
`failure_reason` (every consumer at `cli.py:2420`, `orchestrator.py:353`,
`handoff.py:53/108/292`, `templates.py:38`, `contracts.py:101` is display or
serialisation), and the probe wrapper never reaches `classify`. For I1 the non-goal is
honestly *declared* — the plan states the behaviour delta explicitly — but inaccurately
*bounded*, per M8. The `handoff.py:292` meaning change is now pre-declared, which closes
m4.

## 16. Round-2 findings index

**BLOCKING** — none.

**MAJOR**

- **M8** — I1's risk is stated as "can silently lower a score" and "for cheap pure
  predicates this is inert". Both wrong. `IntTruncationBypassExecutor.attempt()`
  (`input_shape_techniques.py:235-256`) and `DirectShellcodeExecutor.attempt()`
  (`stack_techniques.py:158-183`) carry no applicability guard and can reach SUCCESS where
  previously skipped; `NegativeIndexWriteExecutor` and `FormatStringExecutor` are likewise
  unguarded; `LeakedStackShellcodeExecutor` re-checks the leak at `:76` but not
  `:53-55`. `DirectShellcodeExecutor` has the purest predicate and the least inert
  migration, so purity is the wrong test. Failure: an implementer treats the migration as
  inert, omits a guard, and the R1 map changes. Mitigated by the step-1 gate and
  single-executor conversion, so not blocking. Fix: state the risk bidirectionally, adopt
  the invariant *inert iff `attempt()` already reproduces the full predicate*, and
  enumerate deletions versus new guards.
- **M9** — §9's narrowing to "verification, attribution, classification or scoring logic"
  omits negative-control generation (`run_bench.py:494-530`) and script-audit generation
  (`:630-654`, `:681-695`), both cheat-detection that `classify` only consumes. Failure:
  a later plan weakens a control or the audit and passes targets without touching any
  named category. Fix: invert to an allowlist naming the probe `duration_sec` and the R1
  gate as the only harness changes.
- **M10** — I3's required-provenance gate has no positive instance
  (`variable_overwrite` wins 0 of 17) and, as worded, fails unconditionally on missing
  provenance, so it would red all 13 R1 targets. Failure: implemented as "skip when
  absent" it is vacuous, and §7 gates single-use R5 measurement on it. Fix: condition the
  failure on an attempt having produced a payload, and build the `MAGIC_VALUES`-hit
  fixture — §7 already specifies that fixture, but attaches it to the one item it calls
  *not* a precondition.
- **M11** — one `duration_sec` cannot settle row 2: `elapsed_sec` (`run_bench.py:949`)
  spans two full pipeline invocations (`:916` probe, `:922` script generation), so the
  subtraction overstates harness overhead by a whole pipeline run. Fix: add the same field
  to `autopwn_script_generation` (`:969-972`, identical shape).
- **M12** — round-1 M1's lesson is owned in §2.2 but the *practice* is not yet a rule
  anywhere in §5 or §6: nothing in the plan requires that a claim about artifacts be
  derived over **all** archived runs. §4.0's inventory rule covers "does it already
  exist"; it does not cover "did my search cover what my sentence claims". Given that this
  is the specific error that produced both M1 and the rev-2 map defect, add it to §4.0 as
  a second clause. Fix: one sentence.

**MINOR**

- **m9** — 4 of the 9 `deliver_parts` sites have no `context` either (`discover_menu`,
  `_find_buffer_arg_index`, `_probe_fmtstr_indices`, `_probe_echo_sizes`), and the two
  that §5 mandates the I4 proof at are both in that set. The Design paragraph's argument
  from "the context predates the `AttemptRecord`" settles reachability only where
  `context` is in scope. Disclosed generically by the seven-helper risk note, so minor.
- **m10** — "completes 40 windows" is wrong: `_find_buffer_arg_index` and
  `_probe_fmtstr_indices` each run **8** windows (`fmtstr_techniques.py:50-51`;
  `canary_leak_techniques.py:48/51`); `_probe_echo_sizes` runs 13
  (`canary_leak_techniques.py:45`). 40 is `MAX_ARG_INDEX`, not a window count. Design
  unaffected.
- **m11** — citation drift: `rop_techniques.py:216`/`:226` are the `record.outcome` lines,
  the quoted strings are `:217`/`:227`; the `notes` append is
  `input_shape_techniques.py:241-242`, not `:240-241`. Negligible individually.
- **m12** — §4 I1's declared delta, "for `LeakedStackShellcodeExecutor` it *moves* a
  process spawn rather than adding one", is wrong in the plan's favour: `attempt():76`
  already re-probes, so today's fallback path spawns **twice** and the migration is a
  deletion that **removes** a spawn. Worth correcting because it makes the executor
  scheduled last the safest conversion for the leak half of its predicate.

## 17. Round-2 verdict

The three blockers are fixed, and fixed the right way rather than papered over — I checked
§8 specifically for a stale assumption surviving §2.1's rewrite and found none. Both
push-backs against my round-1 review are correct, and one of them (the `objdump` path)
improves the analysis rather than merely correcting it. §4.0's inventory rule is a real
structural addition that already produced the revision's best finding, the 21-site
inventory, which I confirmed exactly. The sequencing is now correct and the gate is proven
red before it is trusted.

Five MAJOR defects remain. None invalidates an instrument, changes the sequencing, or
touches the design; four are text corrections and one (M10) is a gate specification that
needs a fixture. The one with real teeth, M8, is contained by a sequencing decision the
plan has already made correctly. That is not the profile of a document that should be held.

Binding before implementation: **M8** before step 5, **M9** and **M12** before any step,
**M11** before step 2, and **M10** before §7's R5-measurement gate is treated as
satisfied.

**APPROVED**
