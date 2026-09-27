# Sprint M-1b — challenge-alike ingress variation benchmark

Phase 5 artifact. Closes the **M-1b** gate (USER DIRECTIVE, 2026-09-26: *"Make sure we
not only do per target benchmark but the challenge-alike variations"*).

Supersedes the specification section `M-1b` in
`docs/plans/2026-09-26-sprint2prime-input-vector-plan.md`, which is retained as the
original. Where this plan disagrees with it, this plan governs; the four disagreements
are marked **[R]** and each says what was wrong.

**Provenance labels**: `measured` (ran it), `recorded` (prior artifact, cited),
`inferred` (reasoned, not observed).

---

## 1. Problem restated

**M-1a proves nothing regressed. It cannot prove Sprint 2′ built anything**, because
every target in `benchmark/corpus/` takes its payload on **stdin** — the input vector
was never a corpus dimension (`recorded`, Sprint 2′ plan). Sprint 2′'s capability claim
currently rests on a 6/6 mechanism matrix in the unit-test suite, which uses fixtures I
authored and which the benchmark's independent-re-execution machinery never sees.

M-1b closes that gap: the **same** verdict machinery that produced M-1a's 13/13, applied
to a corpus where the *vulnerability is held constant and only the ingress varies*.

## 2. Scope

**In scope.** A third corpus (`benchmark/corpus_vectors/`) plus the one manifest key
needed to declare a per-target input vector, and a measured run of it.

**Explicitly out of scope.**
- Changing `run_bench.py`'s verdict ladder, secret-flag provisioning, VOID detection, or
  independent re-execution. Reusing them unmodified is what makes M-1b comparable to
  M-1a rather than a second, softer harness.
- Tool hardening. Deliberate constants (header templates, technique allowlists) are
  **features**, not weaknesses.
- Never weaken a corpus vulnerability or a harness check to make a variant pass.
- Held-out corpora (R3/R4/R5) are untouched and unmerged.

## 3. Method — two candidates weighed

### Method A (chosen): a separate corpus + an optional per-target `cli_args:` key

A new corpus root and manifest, selected with the **already existing**
`--corpus-root`/`--manifest` options (`measured`: both are current CLI options, used
today by `benchmark/corpus_r2`). One new optional manifest key supplies the per-target
`--input-vector`/`--input-name`/`--input-argv`.

*Why chosen:* the harness is already parameterised for exactly this. The only code
change is threading one optional key into the existing `extra_args` parameter of
`run_supwngo(binary_abs, timeout, extra_args, tmpdir)` (`measured`: `extra_args` exists;
nothing in the manifest can populate it). Everything that makes a benchmark verdict
trustworthy is inherited rather than re-implemented.

### Method B (rejected): add ingress variants into the existing `benchmark/corpus/`

Add `16_win_file_argv`, `17_win_argv_direct`, … to the R1 corpus.

*Rejected:* it changes M-1a's denominator. Every future "13/13" becomes
"13/13 or 22/22 depending on when you ran it", and the recorded `main` @ `311ff25`
baseline stops being comparable per target — which is the one comparison the standing
rule says must never be aggregated away. A separate corpus keeps M-1a's baseline intact
and lets M-1b carry its own.

**What would flip the decision to B:** if the ingress dimension became a permanent
property of every target rather than a variation axis, one corpus would be simpler than
two. Nothing suggests that today.

## 4. Sub-components

| # | files | change | failure mode introduced |
|---|---|---|---|
| V0 | `benchmark/run_bench.py` | `Corpus` accepts an **optional** per-target `cli_args:` list, default `[]`, appended to `extra_args` | a non-empty default, or a key that silently changes existing runs → T-V0 asserts byte-identical behaviour for manifests without the key |
| V1 | `benchmark/corpus_vectors/*/` *(new)* | 9 variation targets + 2 negative controls (§5) | a target solvable without the vulnerability → the harness's own VOID detection catches it; a VOID variant is **not** counted SUCCESS |
| V2 | `benchmark/corpus_vectors.yaml` *(new)* | the manifest, each target carrying its `cli_args:` | a vector declared in the manifest that the target does not actually implement → the variant fails for a reason unrelated to the transport; T-V2 pins each target's ingress by direct inspection |
| V3 | `benchmark/build_all.sh` | `case` entries for the new corpus (`measured`: the script already honours `SUPWNGO_BENCH_CORPUS` and already documents that an alternate corpus needs its own entries) | a variant built with wrong flags (e.g. PIE on where the technique needs it off) → build flags recorded per target in the manifest |

## 5. The matrix — vulnerability constant, ingress varied

| slug | base vuln | ingress mechanism | declared vector / argv template |
|---|---|---|---|
| `01_win_stdin_baseline` | ret2win (corpus 15) | stdin | *(none)* — see the baseline rule below |
| `02_win_file_argv_bare` | ret2win | `fopen(argv[1])` + `fread` | `file-argv` |
| `03_win_file_argv_flag` | ret2win | `-f FILE` | `file-argv`, `--input-argv "-f {payload_file}"` **[R1]** |
| `04_win_file_argv_embedded` | ret2win | `--input=FILE` | `file-argv`, `--input-argv "--input={payload_file}"` |
| `05_win_file_fixed` | ret2win | `fopen("input.dat")`, no argv | `file-fixed` |
| `06_win_argv_direct` | ret2win | `strcpy(buf, argv[1])` | `argv` |
| `07_win_line_text` | ret2win | `fgets` from the file (stops at `\n`) | `file-argv` **[R4]** |
| `08_varov_file_argv` | variable_overwrite gate | `fread` from `argv[1]` | `file-argv` |
| `09_negidx_file_argv` | negative-index write (corpus 14) | `fread` from `argv[1]` | `file-argv` |
| `90_neg_argv_echo_no_open` | *(none — control)* | takes a path in `argv[1]`, **never opens it** | `file-argv` → must **FAIL** |
| `91_neg_config_flag_stdin_payload` | ret2win | `argv` is an unrelated config flag; payload on **stdin** | SUCCESS on stdin, **FAIL** under `file-argv` |

### **[R1]** The placeholder is `{payload_file}`, not `@@`

The superseded spec wrote row 03 as `--input-argv "-f @@"` while row 04 used
`{payload_file}`. Only one can be real: `DeliverySpec`'s argv template substitutes
`{payload_file}` and `{payload_arg}` (`recorded`, `contracts.py:363`). `@@` is AFL
syntax and appears nowhere in the contract. A plan that ships both notations produces a
variant that fails on a typo and gets attributed to the transport.

### **[R2]** The baseline control must separate *my rewrite* from *the transport*

The superseded spec called `01_win_stdin_baseline` a control "proving the variation
corpus agrees with M-1a". As written it proves no such thing: if I rewrite corpus 15's
source into a new corpus, a differing result could come from my rewrite rather than from
the ingress. Fix — the baseline is **byte-identical source** to
`benchmark/corpus/15_win_function`, built with the **same flags**, and the plan records
the `diff` proving it. Any deviation is documented line by line in the manifest.
Otherwise the corpus has no fixed point and every variant's comparison floats.

### **[R4]** `07_win_line_text` may legitimately fail, and that is a finding, not a regression

`fgets` stops at `\n`. A ret2win payload embeds addresses that may contain `0x0a`. If
this variant fails, the finding is about **payload encoding under a line-oriented
reader**, not about the transport. It is kept because that constraint is real in
challenge binaries, and it is called out here so a failure is not silently attributed to
the file sink. It is **excluded from the PASS condition** (§6) and reported separately.

## 6. **[R3]** The PASS condition — stated, because the superseded spec never did

The superseded spec listed a matrix and two controls but never said what M-1b passing
*means*. Without that, any result can be narrated as success.

**M-1b PASSES iff all three hold:**

1. **Capability:** all of `02, 03, 04, 05, 06, 08, 09` score **SUCCESS** (7 of 7).
   `01` is the fixed point, not a capability claim; `07` is reported separately per [R4].
2. **Controls:** `90` scores **FAILED**, and `91` scores **SUCCESS on stdin** and
   **FAILED under `file-argv`**. A matrix that is all-SUCCESS with these present is a
   broken harness, not a win.
3. **Fixed point:** `01` scores SUCCESS at the same reliability as corpus
   `15_win_function` in the same run window.

**Any VOID is a corpus fault of mine**, reported by name with its cause and **not**
counted as SUCCESS — the same treatment M-1a gives `11_heap_uaf_leak` and
`13_off_by_one`. Authoring 11 new targets is authoring 11 new chances to write a
trivially-solvable one; the harness's VOID detection is the check, and I do not "fix"
a VOID by weakening the check.

**INCONCLUSIVE** (three states, not two): if ≥1 variant is VOID or the build fails
fail-closed, M-1b reports inconclusive rather than a ratio over a shifting denominator.

## 7. Test plan (written before execution)

Every gate proven able to go **RED** by mutating the subject to **wrong-but-present**.

| id | asserts | red-proof |
|---|---|---|
| T-V0 | a manifest with **no** `cli_args:` key yields byte-identical `extra_args` to today — asserted on the parsed value, **and** M-1a re-run per target after the change | set the default to a non-empty list → the equality must fail. **[R3]** the superseded "stays byte-identical" claim had no method; a parsed-value assertion plus a per-target M-1a re-run is the method |
| T-V1 | each variant's declared vector matches its actual ingress, by inspecting the target source | swap two variants' `cli_args:` → the mismatch must be detected |
| T-V2 | `cli_args:` reaches `run_supwngo`'s `extra_args` in order, unmodified | drop the last element → must fail |
| T-V3 | the two negative controls score as §6 requires | make `90` open the file → it must start passing, proving the control discriminates |
| T-V4 | `01`'s source is byte-identical to corpus 15 (`diff` empty) | edit one byte → must fail. This is [R2]'s fixed point made mechanical |

Regression: full suite against the current measured baseline **1268 passed, 14 skipped,
14 deselected**, and **M-1a re-run and compared per target** against 13/13 eligible
SUCCESS at 5/5 reps with the 2 known corpus-fault VOIDs — because V0 touches
`run_bench.py`, which M-1a depends on.

## 8. Benefit metric (Phase 8), baseline measured now

| metric | baseline | target | provenance of baseline |
|---|---|---|---|
| **M-1b** | ingress variants solved by the canonical engine: **0 of 7** — no such corpus exists, and every corpus target is stdin | **7 of 7**, with both controls failing | `measured` (corpus inspection, Sprint 2′) |
| **M-1b-ctl** | controls behaving correctly: **n/a** | `90` FAILED, `91` stdin-SUCCESS / file-argv-FAILED | — |
| M-1a | 13/13 eligible SUCCESS 5/5 | **unchanged per target** | `measured` `20260927-021235Z` |

The 0-of-7 baseline is not rhetorical: before Sprint 2′ the engine had no non-stdin
delivery path at all, so the pre-change score on this corpus is structurally zero. That
is what makes M-1b a capability measurement rather than a restatement of M-1a.

## 9. Rollback

V1/V2/V3 are additive — a new directory, a new manifest, new `case` entries; deleting
them restores the prior state exactly. V0 is the only edit to shared code and is guarded
by an empty default, which T-V0 asserts directly. Reverting V0 alone leaves the corpus
present but unusable, which is a clean intermediate state.

## 10. Review gate

Peer review at the same tier before implementation, with tool-hardening and
constant-table findings declared out of scope in the prompt. The three things most
likely wrong:

1. Does holding the vulnerability constant while varying ingress actually isolate the
   transport, or do the rewrites introduce differences that swamp the signal ([R2]'s
   fixed point is the mitigation — is it sufficient)?
2. Is a 7-of-7 PASS condition with 2 controls enough to distinguish a working transport
   from 7 targets I happened to author solvably?
3. Does the optional `cli_args:` key actually leave `corpus.yaml`/`corpus_r2.yaml` runs
   untouched, or does threading it into `extra_args` change ordering in a way T-V0's
   parsed-value assertion would not catch?

---

# REVISION 2 — after round-1 peer review (NOT-APPROVED)

Review: `docs/plans/2026-09-26-m1b-plan-review-r1-sol.md` (Sol 5.6, xhigh; 2 Critical,
3 High, 4 Medium). **All nine findings accepted**; one of them refutes a "fix" Revision 1
introduced. Every Critical and High was independently verified against the code by me
before acceptance — the verifications are cited inline. Revision 2 governs where it
disagrees with the text above.

User decision (2026-09-26): keep a **7-row required matrix**, swapping the unreachable
rows for reachable techniques rather than shrinking the claim or widening the allowlist.

## R2.1 — Two required rows were unreachable by construction (Critical 1)

`measured` by me, reading the code:

| barrier | evidence | consequence |
|---|---|---|
| the argv sink **refuses** any payload containing a NUL | `verifier.py:237` raises `ValueError` on `b"\x00" in payload` | row `06_win_argv_direct` used **ret2win**, whose payload embeds packed addresses full of NULs → could never pass |
| non-stdin delivery is centrally allowlisted | `FILE_DELIVERY_ALLOWLIST = {"variable_overwrite", "ret2win"}` (`orchestrator.py:133`), enforced at `orchestrator.py:428` | row `09_negidx_file_argv` used **negative_index_write**, which is not a member → refused before delivery |

A 7-of-7 PASS condition containing two structurally impossible rows is a gate that
cannot pass, which is the mirror image of a gate that cannot fail. Both are defects.

### The revised matrix — technique × sink, within what the engine actually permits

Only two techniques are permitted on a non-stdin sink today, so the matrix's diversity
axis is **technique × sink**, not "many techniques":

| slug | technique | sink | argv template / name |
|---|---|---|---|
| `01_win_stdin_baseline` | ret2win | stdin | *(fixed point, not a capability claim)* |
| `02_win_file_argv_bare` | ret2win | `file-argv` | `{payload_file}`, `--input-name payload.bin` |
| `03_win_file_argv_flag` | ret2win | `file-argv` | `-f {payload_file}`, `--input-name payload.bin` |
| `04_win_file_argv_embedded` | ret2win | `file-argv` | `--input={payload_file}`, `--input-name payload.bin` |
| `05_win_file_fixed` | ret2win | `file-fixed` | `--input-name input.dat` |
| `06_varov_argv_direct` | **variable_overwrite** | `argv` | *(payload is the token)* |
| `08_varov_file_argv` | variable_overwrite | `file-argv` | `{payload_file}`, `--input-name payload.bin` |
| `09_varov_file_fixed` | **variable_overwrite** | `file-fixed` | `--input-name state.bin` |

`07_win_line_text` remains present and remains **excluded** from the PASS condition
(original [R4]). The required set is `02,03,04,05,06,08,09` — still 7 of 7, now covering
**both** permitted techniques and **all three** non-stdin sinks.

### R2.1a — Row 06 needs a target designed to produce a NUL-free payload

The review suggested variable_overwrite because it is "an argv-compatible no-NUL payload
shape". **That is not automatic** and I am not accepting it as given: a
variable_overwrite payload is `filler + target_value`, and a target value like `1` packed
to 8 bytes is almost entirely NULs. Whether the payload is NUL-free is a property of the
*corpus target I author*, not of the technique.

So `06_varov_argv_direct`'s gate value is chosen NUL-free by construction — the win
condition compares against `0x41414141` ("AAAA") — and:

- **T-V6 (new):** assert the payload the engine generates for row 06 contains **no NUL
  byte** before it is delivered. Red-proof: change the target's gate value to one whose
  encoding contains a NUL → the assertion must fail.

Without T-V6, row 06 could fail for the NUL reason and be silently attributed to the
argv transport — the exact misattribution R2.1 exists to prevent.

## R2.2 — Every file row was missing a mandatory `--input-name` (High 1)

`measured`: both file sinks raise on an empty `payload_filename` (`contracts.py:320` for
`SINK_FILE_FIXED`, `contracts.py:334` for `SINK_FILE_ARGV`), and the engine builds
`payload_filename=""` when `--input-name` is absent (`orchestrator.py:235`). Revision 1's
matrix declared file vectors with no filename, so eight rows would have been skipped as
**invalid configuration** and the matrix would have failed for a typo rather than for
transport behaviour.

Fixed in the R2.1 table: every file row now carries a concrete `--input-name`, and row
05 uses exactly `input.dat` to match its `fopen("input.dat")`.

- **T-V7 (new):** gate the resulting **`DeliverySpec.to_dict()`** per row — not the raw
  forwarded argument string — so a spec that parses but is invalid is caught at the
  manifest, not at run time. Red-proof: blank one row's `--input-name` → must fail.

## R2.3 — The fixed-file rows self-contaminate across reps (High 2)

`recorded` from the review and consistent with what I know of the generator: the
generated script writes the payload file beside the binary and **does not remove it**
(`templates.py:345`; the behaviour is acknowledged in
`tests/test_input_vector_delivery.py:263`). Rep 1 leaves a *winning* `input.dat`. Rep 2
rebuilds the same non-PIE target with a fresh equal-length flag and runs the bare
negative control **before** generating a new script — the stale file is still valid,
still reaches the new flag, and the target is classified **VOID**.

This would have turned rows 05 and 09 (both `file-fixed`) into VOID, and a real success
into a corpus fault — attributed to the corpus rather than to rep hygiene.

**Fix:** every rep gets a **fresh target working directory**. The harness already does
per-target isolation (`private cwd + TMPDIR`, `measured` from its own run banner); this
extends it to per-**rep** for any target declaring a payload path. The narrower
alternative — back up, remove, and restore each declared payload path around the controls
and the verification — is **not** chosen: it is the same backup/restore dance that
`_verify_file_sink` already needed, and duplicating it in the harness is the duplicated-
placement-rule mistake that produced round-3's H1.

- **T-V8 (new):** seed a stale *winning* payload file at the declared fixed path before a
  rep starts; the rep must still classify correctly and must not report VOID. Red-proof:
  disable the per-rep fresh directory → the VOID must reappear.

## R2.4 — Control 91 cannot be one manifest entry (High 3)

`run_bench.py` executes each target under **one** fixed manifest configuration, so a
single entry can measure "stdin SUCCESS" **or** "file-argv FAILED", never both — yet the
PASS condition demanded both. The report could never contain the required pair.

**Fix:** two entries with distinct slugs over **byte-identical source**:

| slug | config | required |
|---|---|---|
| `91a_config_flag_stdin` | `cli_args: []` | **SUCCESS** |
| `91b_config_flag_declared_file` | `file-argv` + `--input-name payload.bin` | **FAILED** |

with a gate asserting the source of 91a and 91b is identical (`diff` empty) — otherwise
the pair proves nothing about the transport. **INCONCLUSIVE if either leg is absent**;
a missing leg must not read as a pass.

## R2.5 — Control 90's red-proof did not work (Medium 1)

Revision 1's red-proof was "make `90` open the payload file → it must start passing".
The review is right that it would not: target 90 has no vulnerability and no
flag-producing path, so exposing payload bytes yields no secret and it stays FAILED. The
mutation proved nothing.

**Fix:** a **paired positive target**, `90p_argv_opens_and_gates`, identical to `90`
except for the causal branch — it reads the file and gates the flag on its contents.
`90` must FAIL and `90p` must SUCCEED. The discriminating difference is one branch, so
the pair isolates "does file content reach a decision" rather than "does something
differ".

## R2.6 — Variants must share a vulnerable core (Medium 2)

Revision 1's fixed point ([R2]) pinned only row 01's source. The review correctly shows
that is not enough: row 02 could use an `fread` length too short to reach the saved
return address, and it would fail for a **changed vulnerability** while row 01 still
matched corpus 15.

**Fix:** all variants are generated from **one shared vulnerable core** (identical buffer
geometry, identical vulnerable read length, identical win path) with **only an ingress
adapter** differing, and the plan records a mechanical comparison of buffer size,
vulnerable length, win symbol, and effective compiler flags across all rows — not just
row 01. T-V4 is widened from "row 01 matches corpus 15" to "every row's core matches the
shared core".

## R2.7 — The baseline is `inferred`, not `measured` (Medium 3)

§8 labelled "0 of 7" as `measured` while §1 says the corpus does not exist. Both cannot
be true, and reporting a measured +7 would assert an observation that never happened.

**Corrected:** the 0-of-7 baseline is **`inferred`** — a counterfactual from the
structural fact that no non-stdin delivery path existed before Sprint 2′. It is stated as
a counterfactual in the Phase-8 table, and the only honest alternative (build the corpus,
check out the pre-Sprint-2′ revision, and run it) is recorded as the option not taken —
**what would flip it:** if the +7 is ever quoted as a headline improvement rather than as
a capability statement, the historical run becomes mandatory.

## R2.8 — `@@` is supported; Revision 1's [R1] was WRONG

Revision 1 claimed `@@` was AFL syntax appearing nowhere in the contract and called row
03's use of it a transport-breaking typo. **I verified this myself and Revision 1 was
wrong.** `contracts.py:128` defines `_normalize_argv_template`, whose docstring states it
exists precisely to normalise AFL's `@@` convention to `{payload_file}` so there is a
single downstream path — and it cites `cmplog.py`'s own `["--", binary, "@@"]` as the
reason.

**Corrected:** `{payload_file}` is the **canonical spelling chosen for this plan's
manifests**, not the only supported one. `@@` is a supported equivalent.

- **T-V9 (new):** an equivalence test — `-f @@` and `-f {payload_file}` must produce
  identical `DeliverySpec.to_dict()` output. Red-proof: break the normalisation → must
  fail. This converts a wrong diagnosis into a real regression gate for a real feature.

## R2.9 — Revised PASS condition

**M-1b PASSES iff:**

1. **Capability:** `02, 03, 04, 05, 06, 08, 09` all SUCCESS (7 of 7).
2. **Controls:** `90` FAILED **and** `90p` SUCCESS; `91a` SUCCESS **and** `91b` FAILED.
3. **Fixed point:** `01` SUCCESS at the same reliability as corpus `15_win_function` in
   the same run window, **and** every row's vulnerable core matches the shared core
   (R2.6).
4. **Hygiene:** no row VOID. Any VOID is my corpus fault, named with its cause, **not**
   counted SUCCESS, and never "fixed" by weakening a harness check.

**INCONCLUSIVE** if any control leg is absent, any build fails fail-closed, or any row is
VOID. Three states, not two.

## R2.10 — Status

Revision 2 goes to round 2. Round budget: 1 spent, **2 remain**.
