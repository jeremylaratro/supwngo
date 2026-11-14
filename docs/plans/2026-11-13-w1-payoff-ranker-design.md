# W-1 — payoff ranker: static evidence, ranking and cache (2026-11-13, Rev 3)

Detailed design for **directive W, phase W-1**. Parent plan:
`docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md` (§4 row W-1, §5 enforcement).
Grounding: claude-mem #65873, #65875, and correction #65876. Branch `feat/w1-payoff-ranker` off `main`
`79383fc` (W-0 merged, PR #38).

**Revision 2** folded in the independent Tier-2 cyber review (Daybreak Blue, round 1, 2026-11-13 — REJECT
of Rev 1: 3 BLOCKER + 6 MAJOR + 1 MINOR) and the corpus refinements R1–R4 (#65875). **Revision 3** folds in
the round-2 re-review (Daybreak Blue, 2026-11-13 — REJECT of Rev 2: 2 BLOCKER + 4 MAJOR + 1 MINOR; it
**confirmed** the architecture, the BLOCKER-1 address fix, and every scope cut as safe, leaving only
contract-level tightenings for which it supplied the exact fix). The §12 revision log maps every finding to
its resolution; all were verified against code. **Status: Rev 3 is the implementation baseline.** Two
independent review rounds converged, the architecture and scope are confirmed, and each round-2 item is a
concrete reviewer-prescribed fix (now applied) whose correctness is proven by the RED tests in §4 — so
implementation proceeds without a third review round.

## Implementation status (2026-11-13 — COMPLETE, gate green)

W-1 is implemented on `feat/w1-payoff-ranker` following the §7 commit order:

| step | commit | contents |
| --- | --- | --- |
| 1 | `0331bf3` | RVA normalization primitive (`to_corpus_rva`) |
| 2 | `b01dacd` | evidence model + scorer |
| 3 | `b4626f6` | versioned `payoff_analysis` cache table + trio |
| 4a | `3127e4b` | additive `env=` seam through `_run_ghidra_headless` |
| 4b | `a1cae7f` | `SupwngoPayoff.java` extractor + `rank_payoffs` driver |
| 5 | `b629ed7` | corpus tests (positives / twins / PE / negatives) |
| 6–7 | `214c4ef` | failure-injection, cache-safety and cache-integration tests |
| 8 | `de07e87` | angr fallback (Ghidra-absent → `DEGRADED`, never authoritative) |
| fix | `d3154c8` | JVM-home gate test forces a fresh pass (order-independent) |

**Gate result (full suite under `SUPWNGO_REQUIRE_GHIDRA=1`, 133 tests, 0 skips,
~27 min):** every Done-when criterion met — corpus top-1 equals truth on
**72/72** (32 positive + 16 rename twin + 16 strip twin + 8 PE), **0/32** decoy
top-1, **8/8** negatives `complete` with an empty candidate list, cache
miss→hit (1 Ghidra spawn then 0), and the per-call JVM `user.home` override
reaching `proc.run` on real Ghidra. The angr-only path is `DEGRADED` end-to-end
and never meets the gate, as designed (§3.2).

## 0. Goal (exact, from the parent plan's Done-when)

Build `supwngo/analysis/payoff.py` (plus one Ghidra script) that, given a binary, returns a **ranked**
list of candidate payoff ("win") functions, each with an **RVA in the corpus-truth convention**
(`rva = address − image_base`, see §2.1) and the static **evidence** behind it, such that:

- On every dev **positive** (32/32), **rename twin** (16/16) and **strip twin** (16/16), **top-1 equals the
  truth `payoff_rva`**, with **status `complete`** and a **non-empty** candidate list (no abstention).
- The three **decoys** are top-1 on **0/32** positives.
- All **8/8 negatives** yield **status `complete` with an empty candidate list** — i.e. a *successful*
  Ghidra pass that found no hypothesis, never a failure masquerading as a negative (BLOCKER 2).
- **PE** top-1 equals truth on **8/8**.
- A **second call** on the same binary spawns **0 Ghidra processes** and returns the cached report; the
  **first** call spawns **exactly one successful** Ghidra process (MAJOR 8).
- The **budget** is recorded as both measured `elapsed_s` and the configured limit (MAJOR 8).

W-1 builds and proves the ranker. Wiring it into the exploit consumers (`facts.py`, class-A/A′ sites) is
**W-5**, not W-1. W-1 adds no product-behavior change outside the new module and a new, additively-created
cache table.

**Explicit W-1 scope cuts (deferred, not dropped):**
- **`ARG_GATE` / argument-constant extraction is deferred to W-2.** It is *not* load-bearing for the W-1
  gate: the arg-gated positives (`arg1`/`arg3`) wrap the *same* constant-target sink, so `FILE_FIXED`/
  `EXEC_CONST` already fire on them (confirmed: the corpus manifest shows every `arg1`/`arg3` unit resolves
  to an `execve`/`system`/`open`/`fopen` sink). Building the CFG-dominance analysis now would be scope we do
  not need to pass the gate; `required_args` provenance is W-2's explicit deliverable. W-1 records the raw
  constant operands it happens to see as opaque diagnostics only.
- **Full taint provenance for disclosure is deferred** (see §2.3, MAJOR 7): W-1 uses a *light* disclosure
  check; the corpus does not exercise the dead-fixed-open-without-disclosure case.

## 1. Why names cannot do this (what the corpus proves)

The payoff corpus v0 is purpose-built so **no surface signal** identifies the payoff. Confirmed from source
and from the built dev corpus (80 units: 32 pos / 16 rename / 16 strip / 8 neg / 8 PE):

| Function | Action | Target of action | Referenced by `main`? |
|---|---|---|---|
| **payoff `exec`** | `system`/`execve(CMD)` | **constant** command literal (arg0/rdi) | **never** |
| **payoff `file`** | `open`/`fopen`→read→stdout | **fixed path literal** (arg0/rdi) | **never** |
| **payoff `arg1/arg3`** | arg gate **then** the exec/file sink | constant (arg0/rdi) | **never** |
| `decoy_filecopy` | `open`/`fopen`→read→stdout (identical body) | **parameter** `const char *path` | yes (called `"/dev/null"`) |
| `decoy_compare` | constant comparisons, bit ops | **no sink**, returns a flag | sometimes |
| `decoy_nop` | nothing | — | sometimes |
| `filler` (arith/slen/table) | generic compute | no sink | sometimes |

Empirical refinements that pin the model (#65875):

- **R1 — the target argument is position-specific.** The payoff/decoy difference is at a *specific* argument:
  `system`/`execve`/`execl*`/`open`/`fopen` → **arg0 (rdi)**; `openat` → **arg1**. The detector must inspect
  *only that argument*. It must **not** treat "any constant argument" as a hit, because `fopen`'s mode arg
  (rsi) is *always* a constant (`"r"`/`"rb"`) — a naive rule false-positives `decoy_filecopy` *and* every
  negative (whose lone `fopen(path,"rb")` has a constant mode). Verified in disasm: the decoy's
  `fopen(%rax=param, $0x402051="r")`.
- **R2 — intra-procedural.** `decoy_filecopy`/negative open their *formal parameter* inside the function even
  though `main` passes a constant (`"/dev/null"`, `"/etc/hosts"`). Classify by the in-function varnode
  (parameter ⇒ `TARGET_IS_PARAM`); never propagate the caller's constant inward.
- **R3 — `UNREFERENCED` is secondary only.** `called=False` is *not* unique to the payoff (`main`, several
  fillers, and `decoy_nop` are uncalled too). The hypothesis gate is fixed-target-sink ∧ ¬param-target;
  `UNREFERENCED` is only a rank tie-breaker.
- **R4 — sink imports survive `strip`.** `strip` removes the payoff's local name but the exec/file imports
  remain as PLT `JUMP_SLOT` relocs (`readelf -r` names `execve@plt`/`fopen@plt`); Ghidra resolves them, so
  rename/strip twins score identically. The **recovered user-function name is never consumed** by ranking.

A **negative** is simply "a binary with the `decoy_filecopy` (param-target sink) + fillers, but no payoff"
→ empty hypothesis tier via the param-target disqualifier.

## 2. Evidence model (the ranker's core)

Per function `f`, collect **evidence atoms** from a complete backend pass; a function is a **hypothesis-tier
candidate iff it carries a sink atom and no param-target disqualifier**.

### 2.1 Address convention (BLOCKER 1 — the single most important fix)

The emitted RVA MUST equal the corpus truth `payoff_rva = address − image_base` (generate.py:49, 408).
`Decompiler._to_file_address()` returns `file_base + (address − backend_base)` = the **VADDR**, which for
non-PIE ELF and PE differs from the truth by `image_base` and would make ≥16/32 positives, 16 twins and 8/8
PE compare unequal (#65876). Therefore:

> **`candidate.rva = backend_addr − backend_base`** (equivalently `_to_file_address(addr) − file_base`),
> where `backend_base` is Ghidra's reported image base / angr's `mapped_base`, and `file_base` comes from
> `core.fileformat` (ELF min PT_LOAD vaddr, PE ImageBase).

If `backend_base`/`file_base` cannot be validated, or normalization of an otherwise-found payoff fails, the
**whole report is `ERROR`/`DEGRADED`** — the candidate is **never** silently dropped into a `COMPLETE`+empty
result (round-2 BLOCKER 1, second path). **Dedicated normalization unit tests for PIE, ET_EXEC and PE run
before any corpus test.**

### 2.2 Target tracer (tri-state) — MAJOR 4 / R1 / R2

The core primitive is a **bounded, cycle-safe def-use trace** of a specific call argument varnode to one of:
- `CONST_STRING(address, value)` — a constant pointer into *defined string data* (validated, not merely a
  constant integer; MAJOR 4);
- `PARAM(position)` — provenance reaches a formal parameter. **Stays `PARAM` even if every current caller
  passes a literal** (intra-procedural; R2);
- `UNKNOWN` — anything else (stack slot of unknown origin, computed, exceeded step budget). **`UNKNOWN` is
  never upgraded to a fixed-target atom.**

The trace handles (at minimum) `COPY`, `CAST`, `PTRSUB(0,const)`, `INT_ZEXT`, `MULTIEQUAL`, `SUBPIECE`,
`LOAD`/`STORE` of a traced stack slot, `INDIRECT`, and parameter varnodes, with a bounded depth and a
visited-set to break cycles. (The existing `SupwngoDecompile.constantAddress` is `private`, only 6 steps,
and does none of the param/stack/string-validation work — W-1's tracer is new, in `SupwngoPayoff.java`.)

### 2.3 Sink atoms (what makes `f` a candidate)

- `EXEC_CONST`: `f` calls an exec-family import (`system`, `execve`, `execl`, `execlp`, `execv`, `popen`)
  and the **command/path argument at the API's path position** (arg0/rdi for all of these) traces to
  `CONST_STRING`.
- `FILE_FIXED`: `f` calls a file-open import (`open`→arg0, `openat`→arg1, `fopen`→arg0) whose **path
  argument** traces to `CONST_STRING`, **and** the function also performs a *light disclosure*: it contains
  a read-family call (`read`/`fread`) and an output to stdout (`write(1,…)`/`fwrite(…,stdout)` /
  `puts`/`fputs(…,stdout)`). W-1's light check requires the *presence* of read+stdout-output in the function,
  not full handle/byte taint (MAJOR 7 residual deferred; the corpus does not expose a fixed-open-without-
  disclosure function, so this is sufficient for the gate and a reasonable wild-robustness floor).

### 2.4 Disqualifier atoms (how decoys/negatives are rejected)

- `TARGET_IS_PARAM`: the sink's path/command argument traces to `PARAM` → the `decoy_filecopy`/negative
  shape. A function with only this (no `CONST_STRING` sink) is **not** a candidate.
- `NO_SINK`: no exec/file sink at all → `decoy_compare`, `decoy_nop`, `filler`.

### 2.5 Confidence atom (rank only)

- `UNREFERENCED`: no call edge from the entry/`main` reachable set targets `f` (interprocedural CFG;
  `reachableFrom`-style). Secondary rank signal only (R3), never a gate.

### 2.6 Scoring and ranking (MINOR 10)

A function is **hypothesis-tier** iff it has `EXEC_CONST` or `FILE_FIXED` (which by construction precludes
`TARGET_IS_PARAM` on the same argument). Candidates are ordered by an explicit **ranking tuple**
`(has_sink, is_unreferenced, has_const_target_quality)` (all bools/ints), ties broken by ascending RVA;
the integer `score` is derived from that tuple (documented weights), not invented. If **no** function is
hypothesis-tier, the candidate list is **empty** — valid *only* when the pass completed (status `complete`;
§3.2). On every positive exactly one function (the payoff) is hypothesis-tier.

## 3. Architecture

```
supwngo/analysis/payoff.py                           # ranker: API, tracer orchestration, scoring, cache
supwngo/analysis/ghidra_scripts/SupwngoPayoff.java   # evidence extractor (self-contained; new tracer)
```

### 3.1 Public API

```python
class PayoffStatus(enum.Enum):
    COMPLETE = "complete"        # a full extractor pass ran; candidates may be empty (true negative)
    NO_BACKEND = "no_backend"    # neither Ghidra nor angr available
    DEGRADED = "degraded"        # ran but provenance incomplete (e.g. angr-only); not authoritative
    TIMEOUT = "timeout"
    ERROR = "error"              # launch/JVM-home/malformed-output/script failure

@dataclass(frozen=True)
class TargetTrace:
    kind: str                    # "const_string" | "param" | "unknown"
    address: int | None          # for const_string
    value: str | None

@dataclass(frozen=True)
class PayoffEvidence:
    atoms: tuple[str, ...]
    sink_api: str | None
    target: TargetTrace | None
    rank_key: tuple                 # explicit ordering tuple
    score: int                      # derived from rank_key

@dataclass(frozen=True)
class PayoffCandidate:
    rva: int                        # corpus-truth convention == backend_addr - backend_base
    name: str | None                # None for Ghidra synthetic FUN_*/SUB_* labels (MINOR 10)
    evidence: PayoffEvidence

@dataclass(frozen=True)
class PayoffReport:
    status: PayoffStatus
    candidates: tuple[PayoffCandidate, ...]   # ranked; [0] is top-1
    backend: str                              # "ghidra" | "angr"
    attempts: tuple[dict, ...]                # per-backend attempt diagnostics (backend, outcome, reason)
    counts: dict                              # {enumerated, analyzed, failed} functions
    elapsed_s: float
    budget_s: float                           # the configured limit (not the measured time)
    from_cache: bool

def rank_payoffs(binary: str | Binary, *, db: "Database | None" = None, use_cache: bool = True,
                 ghidra_timeout: float | None = None) -> PayoffReport: ...
```

`candidates` is authoritative-empty **only** when `status is COMPLETE`. A negative asserts
`status==COMPLETE and candidates==() and backend=="ghidra"` **and** the complete-invariant counts (below).

**`COMPLETE` invariant (round-2 BLOCKER 1).** `status=COMPLETE` is permitted *only* when **all** hold:
the completion marker is present and schema-valid; `counts.failed == 0`; and `counts.analyzed ==
counts.enumerated` (every in-scope function accounted for). If any record is malformed, any function failed
to analyze, the marker is missing, or normalization of a found payoff failed, the report is `ERROR` (hard
failure) or `DEGRADED` (ran but not trustworthy) — **never** `COMPLETE`. An empty candidate list is a
legitimate negative *only* under a valid `COMPLETE`. `ERROR`/`DEGRADED`/`TIMEOUT` reports are **not cached**.

### 3.2 Backends and failure semantics (BLOCKER 2, MAJOR 9)

- **Primary — Ghidra** via the existing harness (`decompile._run_ghidra_headless` → `core.proc.run`,
  process-group reaped; JSON output). The script emits an **output envelope** = an array of per-function
  evidence records **plus a mandatory completion marker** `{enumerated, analyzed, failed, script_version}`.
  `_read_ghidra_output`-style logic distinguishes missing/empty/malformed/non-array (→ `None`) from a
  structurally valid envelope; W-1 then applies the `COMPLETE` invariant (§3.1): a `None` read, a missing/
  malformed marker, `failed>0`, or `analyzed!=enumerated` → `status=ERROR`/`DEGRADED`; a valid envelope with
  `failed==0 and analyzed==enumerated` → `status=COMPLETE` (candidates possibly `()`). This makes "ran,
  analyzed everything, found nothing" provable and distinct from "never ran" **and** from "ran but a
  function failed to analyze".
- **Fallback — angr** only when Ghidra is unavailable. Use **one** static pass via `_op_cfg` (which keeps
  anonymous `sub_*` functions, unlike `_op_static_functions`). **But `_op_cfg` returns no `backend_base`**
  (no `mapped_base`), so angr candidates cannot be normalized to the RVA contract. Therefore in W-1 an
  **angr-only result is always `status=DEGRADED` with an empty candidate list** (never a confident top-1,
  never an authoritative `COMPLETE` negative); it only signals "Ghidra absent, binary was parseable".
  Enabling real angr candidates (plumbing `backend_base` into a one-pass op + provenance) is deferred.
  **The Done-when is proven on the Ghidra path**; corpus tests require Ghidra (skip with a clear reason if
  absent) and never pass on an angr result.

### 3.3 Ghidra `user.home` (BLOCKER 3)

A JVM takes `user.home` from the passwd entry, **not** `$HOME`; without a writable JVM home Ghidra's
launcher fails and `decompile` silently falls back to angr (documented in `benchmark/passcard.py:479-486`,
which already solves it). W-1 **mandates** a per-run writable JVM home via `JAVA_TOOL_OPTIONS="-Duser.home=<tmpdir>"` with any operator
`JAVA_TOOL_OPTIONS` appended **after** ours (later duplicate `-D` wins; matches passcard).

**Threading the env (round-2 BLOCKER 2).** The existing `_run_ghidra_headless(cmd, timeout)` calls
`proc.run(cmd, cwd=…, timeout=…)` with **no** `env=` (decompile.py:424-438). W-1 therefore makes the single,
additive change of extending it to `_run_ghidra_headless(cmd, timeout, *, env=None)`, passing `env` straight
to `proc.run` (which already accepts it, proc.py:80). `env=None` preserves exact current behavior for all
existing callers; the payoff driver passes `{**os.environ, "JAVA_TOOL_OPTIONS": merged}`. This change is
listed in §6 and covered by a test asserting the env reaches `proc.run`. A test with a read-only real home
proves Ghidra actually ran and the result is `COMPLETE`, not a silent angr `DEGRADED`.

### 3.4 Cache (MAJOR 5, BLOCKER 3 cache half)

- **Dedicated table** `payoff_analysis(sha256, script_version, backend_version, report_json, updated_at,
  PRIMARY KEY(sha256, script_version, backend_version))` created additively via the existing
  `_connection()`/`_init_db` plumbing — *not* the shared `binaries.analysis_data` blob (whose
  `INSERT OR REPLACE` overwrites the whole row and whose `clear_cache` deletes gadgets/crashes/exploits/
  symbols/the binary row). The **composite primary/unique key** on `(sha256, script_version,
  backend_version)` is declared in the DDL. This preserves all other data and gives payoff-scoped
  invalidation.
- **Key = (sha256, script_version, backend_version)** per the parent plan §97-102 (not sha256 alone): a
  changed extractor or backend invalidates the entry. **`backend_version` is discovered process-free**
  (round-2 MAJOR 6): the Ghidra version is read from `Ghidra/application.properties` under the install root
  (reuse `benchmark/passcard.ghidra_version()`, which already does this without launching Ghidra), and the
  angr version via in-process `importlib.metadata`. Launching Ghidra just to learn its version would break
  the "0 Ghidra on a cache hit / exactly 1 on first miss" counts.
- **Explicit serialization**: `PayoffReport.to_json()` / `from_json()` with schema+version validation
  (SQLite stores text and returns dicts/lists; dataclasses/tuples do not round-trip implicitly). A
  malformed/stale/wrong-version row is treated as a miss, not trusted.
- **Injectable DB, cache failures non-fatal (round-2 MAJOR 3)**: `rank_payoffs(db=…)`; default constructs
  `Database()` lazily. Any cache init/read/write error (e.g. `~/.supwngo` not writable) is caught and
  **degrades to an uncached analysis attempt**, recorded in `attempts` diagnostics — a broken cache must
  never suppress analysis. Tests inject a temp-path `Database(db_path=tmp)` and **also** cover an unwritable
  DB path proving analysis still runs (so the injected-DB tests do not mask the default-path failure).
- **Cache only `COMPLETE` results** — never `ERROR`/`TIMEOUT`/`DEGRADED`. Check the cache **before**
  constructing or running any backend (so a hit spawns 0 Ghidra). **Digest TOCTOU (round-2 MAJOR 4):** the
  `Binary` sha256 is computed at construction; W-1 rehashes **before analysis and again before cache
  insertion**, and rejects the result (no cache write) if either digest differs from the lookup digest, so
  evidence for mutated bytes is never stored under a stale key.

### 3.5 Import-name canonicalization (MAJOR 6)

Sink APIs are recognized by a **canonical identity** derived from Ghidra external/thunk metadata, not raw
substring match: strip `@plt`, `@GLIBC_*`/version suffixes, `__imp_` (PE), and a single leading `_`, and
resolve thunks to their target. The exact identities Ghidra emits for `system`, `execve`, `open`, `openat`,
`fopen`, `read`, `fread`, `write`, `fwrite` are **tested** across ELF original/rename/strip and PE
unstripped/stripped so the mapping is grounded, not assumed.

## 4. Test strategy (RED, matching the Done-when and the review's anti-vacuity requirements)

New `tests/test_payoff_ranker.py`, corpus built once into a gitignored dir (as W-0 tests do), each assertion
naming its binary id. A temp `Database` is injected per test (MAJOR 8); corpus tests `pytest.skip` if Ghidra
is unavailable and never silently pass on angr.

Load-free unit tests (always run):
- **Address normalization** for PIE / ET_EXEC / PE (BLOCKER 1) — `backend_addr−backend_base` equals truth.
- **Scorer** on synthetic atoms: each atom's effect on the ranking tuple; a `decoy_filecopy` evidence record
  (sink + `TARGET_IS_PARAM`) is **not** hypothesis-tier; `UNKNOWN` target never yields `FILE_FIXED`.
- **Cache envelope** round-trip + rejection of wrong `script_version`/`backend_version`/corrupt JSON; cache
  coexistence (writing payoff does not disturb a `binaries` row).
- **Import canonicalization** mapping unit.

Corpus tests (Ghidra required):
| Test | Denominator | Assertion |
|---|---|---|
| positives top-1 | 32/32 | `status==COMPLETE`, `candidates[0].rva == truth.payoff_rva`, non-empty |
| rename twins top-1 | 16/16 | same vs parent `payoff_rva` |
| strip twins top-1 | 16/16 | same |
| decoys not top-1 | 0/32 | no `truth.decoys` RVA is `candidates[0].rva` |
| **real** param atom | ≥1 | the extractor derives `TARGET_IS_PARAM` for `decoy_filecopy` from a real binary (not hand-fed) |
| negatives | 8/8 | `status==COMPLETE and candidates==() and backend=="ghidra"` **and** `counts.failed==0 and counts.analyzed==counts.enumerated` (a *successful complete* empty pass) |
| PE top-1 | 8/8 | `status==COMPLETE`, `candidates[0].rva == truth.payoff_rva` |
| first call = 1 Ghidra | — | spawn counter: exactly one *successful* Ghidra process, `from_cache==False` |
| second call = 0 Ghidra | — | `from_cache==True`, spawn count unchanged |
| budget | — | `elapsed_s>0` and `budget_s==` the configured limit; `budget_s==` limit on a hit too |
| read-only JVM home | — | with a read-only real home, Ghidra still runs → `COMPLETE` (not a silent angr `DEGRADED`); asserts the merged `JAVA_TOOL_OPTIONS` reaches `proc.run` |
| env threading | — | the payoff driver's `env` (with `JAVA_TOOL_OPTIONS`) is actually passed through `_run_ghidra_headless`→`proc.run` (spy); `env=None` callers unchanged |
| failure injection: marker | — | missing/malformed completion marker → `status!=COMPLETE`, **not** cached |
| failure injection: failed>0 | — | envelope with `failed>0` or `analyzed!=enumerated` → `status!=COMPLETE`, **not** cached, negatives' emptiness not satisfied this way |
| failure injection: output | — | malformed/absent Ghidra output → `status==ERROR`, **not** cached |
| cache unwritable | — | an unwritable default DB path → analysis still runs (uncached), `attempts` records the cache failure; analysis result unaffected |
| digest TOCTOU | — | a file mutated between lookup and insertion → result **not** written under the stale key |

## 5. Risks (residual, after Rev 2)

- **Stack-slot / `MULTIEQUAL` target provenance** is the subtlest tracer case; the corpus `and`/`nest`/
  `early` bodies still end in a constant-target sink, so the gate does not depend on perfect gate tracing,
  but the tracer must not mis-type the decoy's parameter as `CONST_STRING`. Mitigation: default to `UNKNOWN`
  on any unhandled op (fail *closed*: `UNKNOWN` never becomes a candidate), and the real-param corpus test
  catches a regression.
- **angr-only environments** cannot meet the gate; this is accepted and surfaced as `DEGRADED`.
- **Full disclosure taint** deferred (MAJOR 7); documented limitation.

## 6. Files

- **New:** `supwngo/analysis/payoff.py`; `supwngo/analysis/ghidra_scripts/SupwngoPayoff.java`;
  `tests/test_payoff_ranker.py`.
- **Changed (additive / backward-compatible):**
  - `supwngo/core/database.py` — new `payoff_analysis` table in `_init_db` (composite PK); a
    `save_payoff_analysis`/`get_payoff_analysis`/`clear_payoff_analysis(sha256)` trio; injectable path
    already supported. **`clear_cache` gains a `payoff_analysis` deletion in *both* its global and
    sha256-scoped branches** (round-2 MINOR 7) so the existing "clear all cached data" contract still holds;
    `clear_payoff_analysis` remains for payoff-scoped invalidation. No change to existing tables' schemas.
  - `supwngo/analysis/decompile.py` — `_run_ghidra_headless(cmd, timeout, *, env=None)` (additive kwarg;
    `env=None` is byte-for-byte the current behavior), threaded to `proc.run(env=env)` (round-2 BLOCKER 2).
- **Changelog:** `changelog: none` (internal analysis capability; no user-facing behavior until W-5).

## 7. Execution order (each commit RED-first)

1. Address-normalization helper + PIE/ET_EXEC/PE unit tests (no backend).
2. Scorer + evidence/trace dataclasses + `PayoffStatus` + the `COMPLETE`-invariant predicate + synthetic-atom
   and fail-closed unit tests.
3. Cache: `payoff_analysis` table (composite PK) + envelope `to_json`/`from_json` + process-free
   `backend_version` discovery + cache-unavailable→uncached fallback + `clear_cache` payoff deletion +
   version/corruption/coexistence/unwritable-DB tests (injected temp DB).
4. `decompile._run_ghidra_headless(..., env=None)` additive extension (+ env-threading test); then
   `SupwngoPayoff.java`: enumerate functions, canonical import identity, tri-state target tracer, sink/
   disqualifier atoms, reachability, and the output envelope (records + completion marker); Python driver
   with the mandated JVM `user.home` env and `COMPLETE`-invariant enforcement.
5. Corpus tests: positives/twins/PE top-1, decoys-not-top-1, real-param atom.
6. Negative semantics (`COMPLETE`+empty+ghidra + counts) + failure-injection (missing-marker / `failed>0` /
   malformed output → not `COMPLETE`, not cached) + read-only-home + digest-TOCTOU tests.
7. Cache integration: first-call-one-Ghidra / second-call-zero-Ghidra / budget (elapsed + configured limit).
8. angr fallback: one `_op_cfg` pass (keeps anonymous funcs), always `DEGRADED` with empty candidates;
   honest `attempts` recording.

## 8. Review record

- **Rev 1 review (Daybreak Blue, Tier-2 cyber, 2026-11-13):** REJECT — 3 BLOCKER, 6 MAJOR, 1 MINOR. All
  verified against code and resolved in Rev 2 (§12).
  Output: `/tmp/codex-out/codex_w1review_20261113_170411_2419385.md`.
- **Rev 2 re-review (Daybreak Blue, Tier-2 cyber, 2026-11-13):** REJECT — 2 BLOCKER, 4 MAJOR, 1 MINOR;
  architecture + BLOCKER-1 fix + all scope cuts confirmed. All 7 verified against code and resolved in Rev 3
  (§12). Output: `/tmp/codex-out/codex_w1review2_20261113_171918_2502351.md`.
- **Decision:** Rev 3 is the implementation baseline (no round-3 review — see header rationale).

## 12. Revision log — review-finding → resolution

| Finding | Sev | Resolution in Rev 2 |
|---|---|---|
| 1 RVA vs VADDR | BLOCKER | §2.1: emit `backend_addr−backend_base`; PIE/ET_EXEC/PE normalization tests first. #65876. |
| 2 no-hypothesis vs failure | BLOCKER | §3.1 `PayoffStatus`, `attempts`, `counts`, completion marker; negatives assert `COMPLETE`+empty+ghidra; never cache failures. |
| 3 `user.home` | BLOCKER | §3.3: mandate `-Duser.home=<tmpdir>` via `env=` (mirrors passcard.py), operator `-D` wins; read-only-home test. Cache half → §3.4 injectable DB. |
| 4 extractor not designed / private helpers | MAJOR | §2.2 self-contained tri-state tracer in `SupwngoPayoff.java`; param-stays-param; `UNKNOWN`↛fixed. ARG_GATE dominance deferred to W-2 (§0). |
| 5 cache contract | MAJOR | §3.4 dedicated versioned `payoff_analysis` table, explicit (de)serialization+validation, payoff-scoped invalidation, injectable DB, check-before-run, cache only complete. |
| 6 API recognition | MAJOR | §3.5 canonical import identity from thunk/external metadata + cross-twin/PE identity tests; names never consumed by ranking. |
| 7 FILE_FIXED disclosure | MAJOR | §2.3 light disclosure (read + stdout-output presence); full taint deferred + documented (§5). |
| 8 tests prove nothing | MAJOR | §4: real-param atom test, first-call-exactly-one-Ghidra, budget = configured limit, failure-injection, injected temp DB, negative asserts successful complete run. |
| 9 angr fallback | MAJOR | §3.2 one `_op_cfg` pass, keep anonymous funcs, `DEGRADED` (never authoritative negative/top-1); gate proven on Ghidra. |
| 10 score/name ambiguity | MINOR | §2.6 explicit ranking tuple → derived score; §3.1 synthetic `FUN_*`/`SUB_*` mapped to `name=None`. |

**Round 2 (Rev 2 → Rev 3):**

| Finding | Sev | Resolution in Rev 3 |
|---|---|---|
| r2-1 `COMPLETE`+empty can be partial analysis | BLOCKER | §3.1 `COMPLETE` invariant: valid marker ∧ `failed==0` ∧ `analyzed==enumerated`; malformed/analysis/normalization failure → `ERROR`/`DEGRADED`, not cached; §2.1 no silent candidate drop; §4 marker/`failed>0` injection tests + negative asserts counts. |
| r2-2 env not threaded through named runner | BLOCKER | §3.3 + §6: additive `_run_ghidra_headless(cmd, timeout, *, env=None)` → `proc.run(env=…)`; `env=None` unchanged; env-threading test. |
| r2-3 cache unavailability suppresses analysis | MAJOR | §3.4: cache init/read/write errors degrade to uncached attempt + diagnostic; §4 unwritable-DB test (not masked by injected DB). |
| r2-4 digest TOCTOU | MAJOR | §3.4: rehash before analysis and before insert; reject (no write) on any mismatch; §4 TOCTOU test. |
| r2-5 angr `_op_cfg` lacks `backend_base` | MAJOR | §3.2: angr-only result is always `DEGRADED` with empty candidates (no RVA-contract risk); real angr candidates deferred. |
| r2-6 process-free backend-version | MAJOR | §3.4: Ghidra version from `application.properties` (reuse `passcard.ghidra_version()`), angr via `importlib.metadata`; never launch Ghidra for version. |
| r2-7 global `clear_cache` misses payoff | MINOR | §6: `clear_cache` deletes `payoff_analysis` in both branches; `clear_payoff_analysis` kept for scoped. |
