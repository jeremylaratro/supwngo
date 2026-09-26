# Capability gap analysis — 25SEP2026

Scope: what would make supwngo more capable, more impressive and more useful, given
what is currently missing or lacking depth.

Every number below is labelled **measured** (I ran an instrument and can name it),
**recorded** (read out of an artefact the project already produced) or **inferred**
(reasoned from the above, not directly observed). The distinction matters because the
central finding of this analysis is that one of the project's headline numbers is less
load-bearing than it looks.

---

## 0. The finding that changes priorities

The most decision-relevant gap is **not a missing feature**. It is that the two
numbers a reader would use to judge this tool — "it solves its benchmark" and "it has
198 modules of capability" — are both weaker than they appear:

| Claim | What is actually true |
| --- | --- |
| Solves the benchmark | **13/13 valid targets succeed** (recorded), but on the corpus the tool was *developed against*. The held-out corpora have never been measured cold. |
| ~59k lines of exploit capability | **24% of shipped modules are unreachable from the CLI** (measured), and that 24% is almost entirely untested. |

So the highest-value work is *converting existing code into reachable, measured
capability* — not adding new subsystems. A new subsystem added to this codebase would,
on current evidence, have a 1-in-4 chance of joining the unreachable set.

---

## 1. Measurement and reproducibility gaps

### 1.1 The benchmark number is in-sample

**Recorded** from `benchmark/results/20260924-110437Z/report.json` (15 targets, 5 reps,
`strict_attribution: true`):

- **13 SUCCESS, 2 VOID.** Of the 13, twelve at reliability `1.0`, one
  (`04_canary_leak_bypass`) at `0.8` — 4 of 5 reps credited.
- The 2 VOID targets were voided because **the targets are defective, not the tool**:
  `11_heap_uaf_leak` → `corpus_missing_liveness_gate` ("the read path has no liveness
  or authorization gate, so the flag is reachable without the vulnerability");
  `13_off_by_one` → `corpus_trivially_solvable` ("512 bytes of structure-free filler
  produced the flag with no offset, address or gadget involved").

That the harness caught both is a genuine strength — behavioural attribution by
process tree, with negative controls, is a stronger verification story than most
tools in this space have. **But the effective corpus is 13 single-technique
easy/medium targets that the tool was tuned against**, and the held-out corpora
(R3/R4/R5) have never been run cold. Until one is, "13/13" is a training-set score.

**Gap:** the single most impressive thing this project could publish is a cold
held-out number. It is also the cheapest — the corpora and harness already exist.

### 1.2 No CI at all

**Measured:** no `.github/workflows` directory. 1,100 tests exist and pass locally
(measured, this session), and nothing enforces that on a push. For a tool whose
correctness depends on libc, loader and toolchain versions, an un-enforced suite is a
suite that will drift.

### 1.3 No containerised execution

**Measured:** no `Dockerfile`, and **0 files mention `patchelf`**. Combined with §2.3
this is the reproducibility hole: results depend on the host's libc, and there is no
pinned environment to reproduce them in.

---

## 2. Built but unreachable — 48 of 198 modules (24%)

**Measured** by a static AST import graph (imports at any nesting depth, `from pkg
import name` resolved as `pkg.name`, parent packages included) with BFS from
`supwngo.cli`. Three earlier instruments each produced a confident wrong number and
were discarded after failing their positive controls; see
`docs/plans/2026-09-25-cli-surface-and-reachability.md`.

| Package | Unreachable modules | Lines (measured) | Test references |
| --- | --- | --- | --- |
| `exploit.heap` | 11 | 4,341 | 1 (`tcache`) |
| `ai` | 5 | 2,977 | 0 |
| `distributed` | 5 | 2,690 | 0 |
| `windows` | 5 | 2,205 | 0 |
| `reporting` | 5 | 2,077 | 0 → **fixed this session** |
| `embedded` | 4 | 1,521 | 0 |
| `containers` | 3 | 1,317 | 0 |
| `api` | 3 | 858 | 0 → **built, pending merge** |
| `schema` | 3 | 3,753 | 3 (correctly internal) |
| `macos` | 2 | 568 | 0 |
| `payloads` | 2 | 319 | 0 |

Two properties make this worse than a normal dead-code problem:

1. **It is untested dead code.** Wiring it naked would convert dead code into a
   command that lies. Any wiring PR must carry tests in the same commit.
2. **The README already advertises some of it.** README claims "Heap exploitation
   techniques (tcache poisoning, fastbin dup, House of \*)" under Exploit Generation
   (recorded, `README.md:55`). House-of-\* has **no CLI and no pipeline surface**
   (measured) — `build_default_registry()` registers 17 executors, none of which are
   house-of-force, house-of-einherjar, house-of-spirit, house-of-modern, large-bin or
   unsorted-bin. This is an overclaim in the shipping README.

### 2.1 The heap library is not what I first assumed

**Corrected finding.** `exploit/heap/` (4,341 lines) is a *payload-construction*
library — `HeapExploiter.house_of_force()`, `tcache_poisoning()`,
`SafeLinkingBypass.encrypt/decrypt`, `TcachePerThreadStruct.build_fake_struct`.
`exploit/pipeline/executors/heap_techniques.py` (370 lines) is an *orchestration*
executor that reimplements payload construction inline. They are **complementary, not
duplicates**. So closing this gap is not a wiring switch: it needs **new executors
plus a corpus target per technique** to prove each one. Multi-PR, and gated on
targets.

### 2.2 `ai/` and `distributed/` are the most surprising entries

- **`ai/` — 2,977 lines, 0 TODO/NotImplementedError markers** (measured), containing
  `llm_analyzer.py`, `vuln_predictor.py`, `pattern_learner.py`, `advisor.py`. A
  complete-looking LLM/ML analysis subsystem with no CLI surface and no tests. This is
  the most "impressive-sounding" capability in the tree and it is entirely
  unreachable.
- **`distributed/` — 2,690 lines**: `coordinator.py`, `worker.py`, `seed_sharing.py`,
  `coverage_merge.py`. Distributed fuzzing with corpus sync — again complete-looking,
  unreachable, untested.

**Inferred:** these two are the highest impressiveness-per-line in the repo and the
lowest confidence. Either surface and test them, or move them out of the shipped
package. Shipping them unreachable is the worst of the three options.

---

## 3. CLI surface and option depth

**Measured:** 33 registered commands (`analyze autopwn batch cfg checksec cyclic
cyclic-find dataflow decompile diff explain exploit fuzz heap-analysis imports
integer-analysis kernel leaks libc-id offset onegadget pwn race-analysis report rop
solve source strings-analysis symbolic template triage version`). The command surface
is broad — breadth is not the gap. Depth and consistency are.

### 3.1 Option inconsistency

`--libc` exists on **7 of 32** commands (measured). A user who learns the flag on
`exploit` finds it missing on most neighbours. This is the kind of inconsistency that
makes a capable tool feel unfinished.

### 3.2 No loader threading — the biggest functional gap in the CLI

**Measured absent:** no `patchelf`, no `ld-linux` invocation, no `LD_LIBRARY_PATH`, no
`--library-path` anywhere in the package (the single `ld-linux` hit is a string
literal at `walkthrough/fmtstr_probe.py:1227`).

Consequence: you can give supwngo the remote libc to compute offsets from, but you
cannot make the target *run against* it. Offsets come from one libc, execution uses
another, and nothing detects the mismatch. For a tool whose core value proposition is
ret2libc, this is the gap most likely to produce a confidently wrong exploit.

Compounding it: **hardcoded `libc_version="2.31"`** at `fsop.py:214` and
`off_by_one.py:396` (recorded).

**Inferred:** `--libc-path` threading + an offset-libc-vs-loaded-libc mismatch
detector is the highest-value single feature in this analysis. It converts a silent
wrong answer into either a correct one or a refusal.

---

## 4. Architecture coverage is thinner than the feature list implies

**Measured** file counts mentioning each architecture:

| Arch | Files | Assessment |
| --- | --- | --- |
| amd64 | 32 | primary, well covered |
| arm | 24 | present |
| i386 | 18 | present |
| aarch64 | 6 | thin |
| mips | 3 | thin |
| riscv | **0** | absent |
| powerpc | **0** | absent |

`embedded/arm_exploit.py` and `embedded/mips_exploit.py` exist but are in the
unreachable set. So cross-architecture support is simultaneously *claimed by the
directory structure* and *unavailable from the CLI*.

---

## 5. External tool integration — a genuine strength

**Measured** files referencing each: `gdb` 22, `one_gadget` 20, `angr` 19, `ropper` 7,
`honggfuzz` 6, `ROPgadget` 6, `r2` 5, `afl-fuzz` 4, `ghidra` 2, `seccomp-tools` 2.

This is real breadth and should be stated as such. The gaps here are narrow:
`seccomp-tools` at 2 files means seccomp/sandbox reasoning is shallow, which matters
for modern CTF and for any hardened target.

---

## 6. Recommendations, ordered by value per unit of work

1. **Run one held-out corpus cold and publish the number.** Highest credibility gain
   available; harness and corpora already exist. Must be measure-once — a tuned
   held-out number is worth nothing.
2. **`--libc-path` loader threading + mismatch detector** (§3.2). The only gap here
   that can silently produce a wrong exploit rather than a missing one. Retire the two
   hardcoded `2.31` constants with it.
3. **Add CI** running the 1,100-test suite plus the reachability instrument as a
   regression gate (assert the unreachable set does not grow, with the positive
   control embedded so it cannot pass vacuously).
4. **Decide `ai/` and `distributed/` explicitly** — surface with tests, or remove from
   the shipped package. 5,667 lines currently in limbo.
5. **Correct the README's house-of-\* overclaim now**, and close it properly later via
   new executors plus per-technique corpus targets (§2.1).
6. **Option consistency pass** — `--libc` and friends across all 33 commands.
7. **Containerised, libc-pinned execution** (Dockerfile). Multiplies the value of 1–3
   by making every result reproducible.

### Explicitly out of scope

Per standing project policy, hardening/trustworthiness *of the tool itself* is not in
scope: no provenance, attestation, capability binding, tamper-evidence or audit
trails. Every finding above is about correctness, capability, or measurement validity.
The benchmark's cheat-sheet constants are a feature, not a finding; where the
benchmark is wrong, the fix belongs in the corpus (as the two VOID verdicts correctly
did).
