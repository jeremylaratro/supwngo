# Mythos 5-2 review brief — supwngo re-focus (2026-11-12)

You are reviewing **supwngo**, a Python framework for automated binary analysis, vulnerability
discovery and exploit generation (v2.1.0, PolyForm Strict licence, single maintainer). The directory
you are in is a **history-free export** of the repository at commit `1741b34` (main plus one docs
commit). Target binaries used for evaluation are gitignored and are **not** present.

## 1. The owner's ask (verbatim)

> "run a mythos5.2 review - it should serve as an adversarial review to re-focus the project. How do
> we make the project more scalable, how do we make it better, how do we meet our goals better, what
> tools should we add to the mix, where could we add LLM hooks, and how do we make this the absolute
> best automated binary RE/VR tool in existence?"
>
> "The output of the mythos review should be a bulletproof roadmap + sprint map + plan to make this
> tool the best of the best." (Owner has authorised adding tools/technologies.)

## 2. Owner PASS criteria (set 2026-11-12, verbatim)

> "The tool must output at least the right method, and must at least a) work with a provided
> component if it cant by itself (eg. custom win function provided via --winfun or address to return
> to like --eip, etc. OR b) a template that works with some manual inputs (like manual input of memory
> addresses, win functions, etc. The decompilation must work across elf, exe for now, and we must be
> able to see the offset on all."

Orchestrator's working interpretation (the owner may still redirect; challenge it if wrong):
- "Right method" = the correct technique appears in the tool's output (tracked both as *listed* and as
  *recommended*). A fully autonomous working exploit is **not** required.
- (a) = CLI flags such as `--winfun` / `--eip` (return target) that complete the method when
  auto-detection fails. **No such flags exist today** (only `--offset` on `template`/`autopwn`).
- (b) = an emitted script/template a human completes with addresses etc. `template` exists
  (`-t ret2win|shellcode|ret2system|ret2libc|srop|leak|auto`).
- "exe" = Windows PE, scoped to **decompile + offset** (not Windows exploit generation) "for now".
- "Offset on all" = a stack-overflow offset (input buffer → saved return address, canary-aware) must
  be visible for every target, which implies **static** offset inference: several targets cannot be
  crashed with a plain cyclic pattern (menu-driven, canaried, custom input formats), and PE cannot be
  executed here (no wine).

## 3. Evaluation set

Seven HackTheBox x86-64 ELF challenges (not in this export):

| Target | Protections | Known vuln → expected method |
|---|---|---|
| sick_rop | static, No RELRO, no canary, NX, no PIE, hand-written asm, no `main` | stack BOF → SROP |
| rocket_blaster_xxx | Full RELRO, no canary, NX, no PIE | stack BOF → ret2win (`fill_ammo`) |
| snow_scan | static (877 KB), Partial RELRO, "canary" is a false positive, NX, no PIE | stack BOF (BMP parser) → SROP |
| ancient_interface | Partial RELRO, canary, NX, no PIE, stripped, no `main` | stack BOF via `read` → ROP |
| auth-or-out | Full RELRO, canary, NX, PIE; custom allocator `ta_alloc/ta_calloc/ta_free` | UAF (custom alloc) |
| sabotage | Full RELRO, canary, NX, PIE | integer overflow |
| bon-nie-appetit | Full RELRO, canary, NX, PIE; libc malloc/free | heap off-by-one |

PE: no PE corpus yet; mingw-built x64/x86 fixtures are being added. Seven targets is a tiny,
overfittable set — say how to avoid overfitting to it.

## 4. Measured state (all measured, not assumed)

**History.** `docs/reports/2026-09-26-comprehensive-feature-retest.md` (command matrix, 19 gaps).
Canonical pipeline (`autopwn`/`solve`) solved 0/7; the legacy engine (`exploit --auto`) solved 0/7
under attributed crediting (see the erratum in that report). Gap-closure effort
`docs/plans/2026-11-11-retest-gap-closure-plan.md`: sprints S1–S5 merged (broken commands, reported
facts, libc correctness, angr timeouts, Ghidra decompile); S6 (detector depth) and S7 (cleanup +
2.2.0) pending. Earlier audit: `docs/reports/2026-11-11-outstanding-work-audit.md`.

**Re-measured today (2026-11-12, current tree):**
- `pwn sick_rop`: STACK_PIVOT (recommended) + VARIABLE_OVERWRITE only — **no SROP**. Cause:
  `exploit/strategy.py:394 _check_srop_viable` requires `_has_sigreturn`, set only from a `pop rax`
  gadget; sick_rop sets rax via `read()`'s return value + a `syscall; ret` gadget. Meanwhile the
  canonical pipeline has `exploit/pipeline/executors/srop_nowrite_techniques.py` for exactly this
  binary class — **the engines disagree**.
- `pwn rocket_blaster_xxx`: ROP_EXECVE recommended; **no RET2WIN** (`fill_ammo` is not in the
  hard-coded `WIN_FUNCTIONS` list; `strings-analysis` finds `./flag.txt` but nothing links it to the
  function that opens it).
- `template` with `-t auto` picks **ret2system** for both sick_rop (static, no libc) and
  rocket_blaster_xxx (ret2win) — wrong both times.
- `decompile` (Ghidra via a committed Java GhidraScript; Ghidra 12.1.3 has no PyGhidra): an S5 unit
  run took ~30 s, but in today's CLI flow both sick_rop and rocket_blaster_xxx **hit the 180 s Ghidra
  cap and fell back to angr** (sick_rop: angr failed; rocket: 32 chars of code). CLI defaults to
  function `main`; sick_rop/ancient_interface have no `main`. Root cause under investigation.
- `offset sick_rop`: **crashes** — `exploit/offset_finder.py:545 _find_with_binary_search` lets
  `subprocess.TimeoutExpired` escape (the target loops forever waiting for input). `offset
  rocket_blaster_xxx`: "Could not determine offset with any method". (Sept: offset worked on 1/7.)
- `heap-analysis auth-or-out`: 0 alloc / 0 free / 0 vulns — `vulns/heap_advanced.py` matches only
  libc allocator names **and** only via the import PLT, so in-binary allocators are invisible.
- `report` on sick_rop, auth-or-out, bon-nie-appetit: **0 findings** each.
- A full 7-target × {pwn, template, decompile, offset} scorecard is in `_review/SCORECARD.md` when
  present (complete; see the tally table at its top).

**Codebase shape.** ~143k LoC Python. `supwngo/exploit/` = 102k (71%): `pipeline/` 37k with ~32
technique executors, `walkthrough/` 29k (the `explain` command), 23k of top-level legacy engine files,
`rop/` 5k, `heap/` 5k, `advanced_bypass/` 3k. Then `analysis/` 8k, `vulns/` 7k, `kernel/` 6k,
`schema/` 3.7k, `fuzzing/` 3.5k, `symbolic/` 2.3k, `reporting/` 2k, `core/` 1.7k, `remote/` 1.4k.
`cli.py` is 3.9k lines, ~33 commands (analyze fuzz triage exploit rop symbolic libc_id pwn offset
onegadget checksec cyclic cyclic_find batch template addresses source kernel version cfg dataflow
strings_analysis diff decompile imports leaks heap_analysis integer_analysis race_analysis autopwn
explain solve report). 92 test files (~2,230 tests, local pytest only — **no CI runner**). 141 docs
(see `docs/roadmaps`, `docs/architecture`, `docs/adr`, `docs/plans`).

**Structural facts surfaced during the gap-closure effort.** At least five overlapping "what should I
do with this binary" engines — `pwn` (StrategySuggester), `autopwn`/`solve` (canonical pipeline),
`exploit --auto` (legacy), `explain` (walkthrough), `template` — that disagree with each other. angr
CFG/decompile run in a budgeted, process-group-killed subprocess (S4). Ghidra cannot run Python
scripts here (no PyGhidra), and `-scriptPath` directories must be near-empty or Ghidra hangs scanning
them. A pre-existing `solve` timeout (I-2) and a load-sensitive test flake exist.

## 5. Available infrastructure and tools

- **Installed:** Ghidra 12.1.3 headless (no PyGhidra), angr, angrop, pwntools, ropper, capstone,
  keystone, lief, pyelftools, gdb, ltrace, strace, gcc, mingw-w64 (x64 + x86). **Absent:** wine,
  RetDec, IDA, Binary Ninja. The owner authorises installing tools.
- **LLMs:** a local fleet of four NVIDIA DGX Spark (GB10) nodes serving open-weight models through
  vLLM OpenAI-compatible endpoints; an in-house agentic CLI the team owns and can extend; cloud models
  through the Claude and Codex CLIs. **Offline / air-gapped operation is a hard requirement** of the
  owner's wider vulnerability-research platform, which already runs LLM-driven agents that call
  command-line tools (they mostly drive tools through a shell, rarely through MCP). The `ai` extra in
  `pyproject.toml` lists `anthropic` and `openai`.
- **Process constraints:** Conventional Commits, branch + PR per sprint, a written and peer-reviewed
  plan for non-trivial work, CHANGELOG discipline, local tests only.

## 6. Review rules

- **Be adversarial.** Challenge the owner's goals, the PASS criteria, this brief and the
  orchestrator's interpretations. Say where the project is wasting effort or fooling itself.
- **Evidence over opinion.** Cite `path:line` from this tree. Mark anything you could not verify as
  UNVERIFIED. Do not invent file names, APIs or results.
- **Read-only.** Stay inside this directory. Do not execute anything.
- Every recommendation needs: impact, effort (S / M / L), dependencies, risk, and a **falsifiable**
  success measure.
- Also propose **new hypotheses / experiments**, each with an explicit falsifier.

## 7. Corrections after the first review wave (orchestrator, verified against the tree)

- **Override flags exist on some engines.** `--win SYM|ADDR`, `--ret2 SYM|ADDR` and `--rop` are defined by
  `target_override_options` (`supwngo/cli.py:66-109`) and attached to `autopwn` (`cli.py:2840`), `explain`
  (`cli.py:3238`) and `solve` (`cli.py:3449`), resolved by `supwngo/exploit/pipeline/target_overrides.py`.
  They are **missing from `pwn`, `template` and `offset`**. §2's "No such flags exist today" is wrong;
  PASS (a) is a coverage/aliasing job plus the flow into method selection and templates.
- **A CI workflow file exists** (`.github/workflows/ci.yml`, added in commit e8a250d), but the owner's
  standing policy is local-only testing; no runner executes it. Treat it as dead configuration.
- **Host architecture.** The analysis host (where targets run) is x86-64. The DGX Spark nodes are ARM64
  (GB10) and serve models only; they cannot run x86-64 targets natively.
- **Ghidra 180 s cap, diagnosed.** The identical headless command re-run alone took 34 s. Ghidra's
  `application.log` showed every phase uniformly 5–20× slower during the capped runs (JVM start, project
  create, import, analysis) while the host had 15-minute load ~26 on 32 cores with 12 users. That is
  host contention plus per-call full re-analysis (no project reuse), not a script hang.
- **Target-name leak confirmed.** `supwngo/exploit/offset_finder.py:887` hard-codes `"fill_ammo"` (the
  rocket_blaster_xxx answer) in `WIN_NAMES`.
