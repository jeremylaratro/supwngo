# Plan — three new vulnerability categories: FSOP, stack clash, double fetch

Date: 2026-09-28
Status: plan, not yet handed off
Sprints: **N1** (FSOP / `_IO_FILE`), **N2** (stack clash via `alloca`/VLA), **N3** (double fetch / thread race)

## Scope exclusion (carry verbatim into every handoff prompt)

The security **and integrity** of this tooling is explicitly out of scope. We
care **solely** about **functionality, efficiency, and capability**. Security
issues, bypasses, and anything involving the tool being **misused** are not a
concern. Do not add or report: input validation framed as security, sandboxing,
privilege/auth/secrets handling, RMF/NIST/compliance or audit controls, threat
models, attack surface, supply chain, tamper-resistance, or "someone could
deliberately game/evade this gate". There is no adversary in the threat model —
this is a lab-only offensive tool run by its author on his own hardware. No
"Security considerations" or "Risks" sections.

**The one distinction that must not be blurred** (same code, different framing):
"this gate reports success when nothing was actually measured" is a
**functional-correctness defect — report it**. "Someone could deliberately bypass
this gate to fake a result" is **misuse — discard it.**

Deliberate constants, loose gates, target-shaped heuristics and retry-based
brute force are **FEATURES** here. **The goal is to SOLVE targets.**

---

## How these three were chosen — verified absent, not assumed absent

Five candidate categories were checked against the tree at `75e6965` before any
was accepted, and **three candidates were rejected because the capability
already exists.** Recording the rejections, because proposing existing work is
this repo's most common waste:

| candidate | verdict | evidence |
|---|---|---|
| CWE-502 deserialisation w/ callback | **REJECTED — duplicate** | `objptr_hijack_techniques.py:1` already covers "a function pointer the program later CALLS is reachable from attacker-controlled bytes". A deserialised record's callback pointer *is* that category. |
| `ret2dlresolve` | **REJECTED — already wired** | present in `exploit/rop/ret2dlresolve.py` **and** reachable from the pipeline via `executors/rop_techniques.py` + `orchestrator.py`. |
| pure-read format-string disclosure | **REJECTED — covered** | `executors/canary_leak_techniques.py` already performs read-only disclosure. |
| unsafe unlink / House of Einherjar | deferred | 0 executor hits, but `exploit/heap/house_of_modern.py` exists; needs a check of the library before it can be called a gap. |
| `mprotect`-based NX bypass | deferred | 2 executor hits; likely already expressible in the ROP chain builder. |

The three accepted below were each confirmed absent **as a pipeline capability**,
by grep over `supwngo/**/*.py` at a fixed commit.

## Where the targets go

The repo's convention is **one corpus directory per category** —
`corpus_allocsize`, `corpus_offbyone`, `corpus_typeconf`, `corpus_uafread`, and
~20 more. New categories therefore get `benchmark/corpus_fsop/`,
`benchmark/corpus_stackclash/`, `benchmark/corpus_doublefetch/`.

**Do NOT add new targets to `benchmark/corpus_r2/`.** Its pre-registered benefit
metric is expressed as `x/15`; appending targets silently changes the denominator
and makes before/after numbers incomparable. This is the same class of error as
re-baselining a harness mid-experiment.

---

## Sprint N1 — FSOP / `_IO_FILE` exploitation (highest value, lowest cost)

**The finding: the technique is already written and the pipeline cannot reach
it.** `supwngo/exploit/fsop.py` and `supwngo/exploit/heap/house_of_modern.py`
both exist, and **no executor in `supwngo/exploit/pipeline/executors/` references
them** — the only executor hits for `_IO_FILE`/`vtable`/`House of Orange` are two
passing word-mentions in `typeconfusion_techniques.py:32` and `:1034`.

This is structurally the same defect as the dead `format_string` stub that
Sprint F3 removes: a capability that exists on disk but is unreachable from the
pipeline, so every run reports "no technique applies" and the diagnosis reads as
"the framework can't do FSOP", which is false.

So N1 is **not** "implement FSOP". It is: read `exploit/fsop.py` and
`house_of_modern.py` first, determine what they already do, and build the
executor + gate + seating that makes them reachable. Grep before building —
specifying work that already exists is the most common waste here. Only write new
technique code for what those two modules genuinely lack.

Target (`benchmark/corpus_fsop/`): the standard shape — a write primitive into
`_IO_2_1_stdout_`'s `_flags` and `_IO_write_base` to turn `puts`/`printf` into an
arbitrary-read that discloses the flag, and/or a vtable redirect. Build at least
**three variants** per the per-category directive, so the executor is proven on
variants and not fitted to one binary.

Gate honestly: FSOP depends on the *locally loaded* glibc's `_IO_FILE` layout and
on vtable-pointer validation (`_IO_vtable_check`, glibc ≥ 2.24), which must be
**checked, not assumed** — `heap_techniques.py` already sets the precedent of
verifying safe-linking against the local libc rather than trusting a version
number. If the local glibc forbids the vtable route, say so and take the
`_IO_write_base` read route instead; report "inconclusive on this libc" rather
than "failed".

Expected ceiling: **`FLAG_CAPTURED`**, not `SHELL_ACCESS` — the read route
discloses the flag without control-flow transfer, and `FLAG_CAPTURED` is a
verification level in its own right (`exploit/verification.py`), with five
executors already topping out there by design.

## Sprint N2 — stack clash via attacker-controlled `alloca`/VLA

Genuinely absent: the only `alloca(`/`stack_clash` hit anywhere in `supwngo/` is
`analysis/protections.py`, i.e. the framework can *detect* the mitigation but has
no technique that exploits its absence. Tracked previously as Stage-4 gap item 6.

Distinct from every existing category: nothing overflows a buffer. An
attacker-controlled size moves `rsp` past the guard page so the new frame
overlaps a *different* mapping, and ordinary in-bounds writes to the new frame
then land in that other region.

Target (`benchmark/corpus_stackclash/`): must be compiled
`-fno-stack-clash-protection` (and record that in the build script comment, since
it is the whole point). Keep the target deterministic — a fixed, attacker-chosen
size that lands the frame on a known global/heap mapping — because a
probabilistic target cannot be regression-tested. Three variants.

This is the riskiest of the three to make *reliably* solve. If it proves
non-deterministic, report a null result plainly and keep N1 and N3 rather than
forcing it.

## Sprint N3 — double fetch / thread race on shared memory

Genuinely absent: 0 executor hits for `double.fetch|thread.race|pthread`. The
existing `toctou_path_race` is **filesystem-path**-specific; this is a race on a
*memory* value between a validation read and a use read.

Target (`benchmark/corpus_doublefetch/`): a validator thread and a worker thread
over a shared struct, where the worker re-reads a length/index the validator
already checked. Make the window generous (an explicit `usleep` between check and
use) so the race is *winnable in bounded attempts* — a target that needs a 1-in-
10⁶ timing win is not a benchmark, it is a coin flip.

Executor: hammer the input in a bounded retry loop and accept the first run whose
output matches the flag pattern. Retry-based brute force is explicitly
acceptable. **Three states matter more here than anywhere else:** a lost race is
**inconclusive**, not a failure, and the gate must be able to say so — otherwise
a flaky red is indistinguishable from a real capability gap.

---

## Test obligations (all three sprints)

* **Positive control first.** Prove each new gate can go RED by mutating the
  subject to wrong-but-present before trusting any green. Record the RED output.
* **Never let an absence assertion stand alone.** A test asserting the new
  executor is registered must also assert the registry is otherwise unchanged
  (no orphans, no duplicates), or a rename passes vacuously.
* **Per-category directive:** make it work on one target, then test on variants,
  adjust until the variants work too, then move to the next category. Three
  variants minimum per category.
* **Regression guard:** each new executor is seated in the orchestrator, which
  changes attribution for every other target. Re-run the full corpus sweep after
  seating, and seat a fast/loose-gated executor **late** — a fast executor with a
  loose gate steals attribution from slower, more specific ones, which has
  already happened once in this repo.

## Benefit metric, pre-registered

| metric | baseline | target |
|---|---|---|
| categories with a working pipeline executor | current count, measured before N1 starts | **+3** |
| `corpus_fsop` | does not exist | ≥2 of 3 variants SUCCESS |
| `corpus_stackclash` | does not exist | ≥2 of 3 variants SUCCESS |
| `corpus_doublefetch` | does not exist | ≥2 of 3 variants SUCCESS |
| `corpus_r2` | unchanged by this plan | **no regression** |
| suite | 2050 passed / 16 skipped / 0 failed (measured, v2.1.0) | no new failures |

Order **N1, N3, N2** — N1 is mostly wiring an existing capability, N3 is a new
but simple executor, N2 is the one that may not be made deterministic. Bank the
cheap certain wins first.
