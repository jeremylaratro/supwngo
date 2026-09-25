# Plan: walkthrough engine — zero-to-pwn strategy walkthroughs

Date: 2026-09-23
Branch: `feat/walkthrough-engine-20260923` (based on `integration/phases-0-4-7-20260923`)
Status: **awaiting coordinator review**

## Goal

Replace thin findings output and the near-useless failed-`autopwn` stub
(`offset = 0  # TODO: confirm/find correct offset`,
`supwngo/exploit/pipeline/templates.py:84`) with an **in-depth, step-by-step
strategy walkthrough embedded in a runnable pwntools template** that takes a
reader from zero to a shell on the specific binary in front of it.

The artifact is a teaching document that happens to execute. Its real bar: a
**fresh agent with no context** can follow it blind, step by step, and land a
shell. That means self-containment is the acceptance criterion, not prose
quality.

### Non-goals (this pass)

- Format-string, heap, and integer/data-only families. The abstraction must
  admit them cleanly; building them now would be framework-for-absent-content.
- Any change to exploitation *mechanisms*. The Phase-5 agent owns those.

## What "good" means here (the design bar, restated as testable properties)

Each of these maps to an enforced invariant or a validation step, not a wish:

| Property | How it is enforced |
| --- | --- |
| Every step runnable on its own | Renderer emits one function per step + `argv` dispatch, so `python3 wt.py offset` runs exactly that step. Validated by running each step of each generated walkthrough. |
| Every step states expected observation + how to tell it worked | `Step.expect` and `Step.verify` are non-empty-checked in `Step.__post_init__`. |
| Failure guidance | `Step.on_failure: tuple[Fallback]`, keyed by **observable symptom** (what the reader actually has in hand), not by cause. |
| Steps chain statefully | `Step.produces: tuple[Fact]` / `Step.consumes: tuple[str]`. `Walkthrough.validate()` rejects a step consuming a fact no earlier step or constant provides — a forward reference means the walkthrough cannot be followed in order. Renderer prints "carried in from step N". |
| Binary-specific and evidence-backed | Every value is a `Fact` carrying `Evidence(method, command, detail)` — including a pasteable command to re-derive it — and a `Confidence` of `MEASURED`/`DERIVED`/`ASSUMED`/`UNKNOWN`. |
| No `offset = 0 # TODO` | `Fact.__post_init__` **raises** unless an `UNKNOWN` fact states `unknown_reason`, `plausible`, and `resolved_by` (a step id that must exist). Unknowns render as a loud `_unknown(...)` raise, never a fake value. Expressing the bad artifact is structurally impossible. |
| Explains WHY, tied to observed protections | `ProtectionVerdict(name, state, implication, rules_out, forces)` — generated from *measured* protection state, so the reasoning cannot drift from the facts. |
| Includes manual/interactive tooling | `Step.manual: tuple[ManualCommand]` — real `checksec`, `gdb`, `ROPgadget`/`ropper` invocations with expected output. |
| Ends in a complete working exploit | `Walkthrough.validate()` requires a non-empty `final_exploit`. |
| Decision tree / fallbacks | Families declare their own applicability as a `Route`. The selected route is the best-scoring one; **the rejected routes are the decision tree**, each carrying why it was rejected. A new family therefore appears in every other family's fallback tree for free — no duplicated fallback prose. |
| Excellent when automation FAILED | The Phase-4 `HandoffReport` is an *input*. `automation_failure` records what the robot already tried, and its `blocking_unknowns` become named `UNKNOWN` facts pointed at the step that resolves each one. |

## Approach

### Data model (`model.py`) — already drafted

Three load-bearing types, described above: `Fact` (value + evidence +
confidence, with the unknown-must-be-actionable invariant), `Step` (runnable,
with `produces`/`consumes` dataflow), `Route` (self-declared applicability that
doubles as the decision tree). Plus `Evidence`, `Confidence`,
`ProtectionVerdict`, `ManualCommand`, `Fallback`, and `Walkthrough` with a
`validate()` that enforces the invariants at construction time.

`Walkthrough.to_dict()` gives a machine-readable view for tests and `--json`.

### Module layout

```
supwngo/exploit/walkthrough/
├── __init__.py        public API: generate_walkthrough(), render_script()
├── model.py           the data model above (no supwngo imports — pure)
├── facts.py           TargetFacts: the ONLY adapter onto supwngo internals
├── common.py          shared step builders (recon, crash, cyclic offset,
│                      gadget hunt, shell confirmation)
├── families/
│   ├── __init__.py
│   ├── stack_bof.py   overflow control + shellcode where NX permits
│   ├── rop_chain.py   ret2plt/ret2system, ret2libc leak-then-resolve
│   └── syscall.py     ret2syscall execve, SROP
├── registry.py        family registration, route selection, decision tree
└── render.py          Walkthrough -> runnable annotated pwntools script
```

**Coupling control.** `facts.py` is the single seam onto the rest of supwngo.
Everything above it consumes normalised `TargetFacts`. When the Phase-5
hardening work lands, only `facts.py` can need adjustment — that is the
property that makes the rebase painless. `model.py` imports nothing from
supwngo at all, so it is trivially testable.

### `TargetFacts` — the adapter

Reads *stable* interfaces only, and memoises the expensive ones
(`ProtectionAnalyzer.analyze()` and every `GadgetFinder.find_*` are uncached
and shell out / rescan the whole file per call):

- `Binary.load(path)` — note `symbols[name]` is a `Symbol` object (`.address`)
  while `plt`/`got` are plain ints; `protections.relro` is a **string**.
- `ProtectionAnalyzer(binary).analyze()` → `DetailedProtections`, called once.
- `GadgetFinder` for real gadget addresses. Important: the *symbol* address is
  not the gadget address — `gadget_pop_rdi_ret` is at `0x4011f6` but the actual
  `pop rdi; ret` is at `0x4011fa`, four bytes past an `endbr64`. The walkthrough
  must teach this, and must emit the gadget address, not the symbol.
- `supwngo/vulns/stack_bof.py` `Vulnerability` — `.details` (not `.metadata`),
  and note the static path never sets `offset`.
- `supwngo/exploit/pipeline/handoff.py` `HandoffReport` via
  `engine.handoff_report` (cached) — consumed, never rebuilt.

**Offset is measured, not guessed.** `facts.py` runs its own small, contained
cyclic probe (send `cyclic(n)`, read the faulting value from the corefile,
`cyclic_find`) to get a `MEASURED` offset. This is the difference between an
evidence-backed artifact and filler. If the probe fails, the offset becomes an
`UNKNOWN` fact naming a plausible range derived from the buffer size
(`buf + saved_rbp`) and pointing at the offset step — the "inconclusive between
72 and 88, resolve via step 2" shape, which is useful, rather than a
placeholder, which is not. `--offset N` and `--no-probe` control this.

### Route selection is driven by measured facts

Verified on the real corpus binaries — the signals are fully discriminating:

| target | `system@plt` | `/bin/sh` in binary | `pop rdi` | `pop rax` | `syscall` | route |
| --- | --- | --- | --- | --- | --- | --- |
| `02_ret2plt_system` | yes | yes `0x402008` | `0x4011fa` | no | no | ret2plt/system |
| `07_ret2libc_leak` | no | no | `0x4011ba` | no | no | ret2libc via leak |
| `09_srop` | no | yes `0x402008` | no | `0x4011ba` | `0x4011c3` | SROP |

So the three chosen validation targets exercise three different routes through
the engine, and the selection logic is grounded in facts rather than filenames.

### Rendered script shape

```
#!/usr/bin/env python3
"""header: target, measured protections + what each one forces,
   strategy narrative, decision tree, what automation already tried"""
from pwn import *
# --- facts (each annotated with confidence + how it was obtained) ---
OFFSET = 72          # measured - cyclic_find on corefile RSP
POP_RDI = 0x4011fa   # measured - pwntools ROP; note: symbol+4, past endbr64
# --- steps ---
def step_offset():   # WHY / EXPECT / VERIFY / TROUBLESHOOTING / MANUAL gdb
    ...
def exploit(): ...   # complete, assembled from the steps
if __name__ == "__main__":  # no args -> exploit; "steps" -> list; <id>|<n> -> one step
```

Per-step `argv` dispatch is what makes "every step is runnable right now"
objectively checkable rather than aspirational.

## CLI surface (small, surgical edits to `cli.py`)

Following the existing conventions exactly (`@cli.command()`, binary as first
`click.argument`, `--json`/`json_output` rename, `@click.pass_context` last,
function-local heavy imports, `rich` console output):

1. **`supwngo explain BINARY`** — new command, the dedicated surface. Options:
   `-o/--output` (default `./walkthrough_output/<name>_walkthrough.py`),
   `--offset N`, `--no-probe`, `--libc PATH`, `--family {auto,stack_bof,rop_chain,syscall}`,
   `--json`, `--remote HOST:PORT` (reusing `_fill_remote_placeholders`).
2. **`--walkthrough` flag on `solve` and `autopwn`** — on completion (especially
   failure) also write the walkthrough, consuming `engine.handoff_report`. This
   is the "most important case": a failed run hands back an actionable plan.

Reuses the existing `_render_handoff_report` rather than re-rendering.

## Files touched

New (all mine):
- `supwngo/exploit/walkthrough/{__init__,model,facts,common,registry,render}.py`
- `supwngo/exploit/walkthrough/families/{__init__,stack_bof,rop_chain,syscall}.py`
- `tests/test_walkthrough_model.py`, `tests/test_walkthrough_families.py`,
  `tests/test_walkthrough_cli.py`
- `docs/plans/2026-09-23-walkthrough-engine.md` (this file)

Shared, surgical only:
- `supwngo/cli.py` — one new command + one flag on each of two commands
- `CHANGELOG.md` — `[Unreleased] / Added`

**Not touched** (owned by other agents): `supwngo/exploit/pipeline/executors/*`,
`delivery.py`, `orchestrator.py`, `script_builder.py`, `verifier.py`,
`profile_stage.py`, `benchmark/run_bench.py`, `benchmark/build_all.sh`,
`benchmark/corpus/*.c`. `templates.py` is left alone too: the walkthrough is an
additional artifact, not a replacement of the orchestrator's template call.

## Test strategy

Repo conventions: class-based, bare `assert`, `SimpleNamespace` fakes, no
`conftest.py`, `tmp_path` for filesystem. `CliRunner` for flag/validation only —
anything that runs pwntools must be a real `subprocess` (`CliRunner` replaces
stdio with objects lacking `fileno()`).

1. **Model invariants** (pure, no binary): an `UNKNOWN` fact missing
   `plausible`/`resolved_by` raises; a step consuming an unprovided fact raises;
   duplicate step ids / fact names raise; an empty `final_exploit` raises;
   `to_dict()` round-trips. These tests *are* the guarantee that the bad artifact
   cannot be produced.
2. **Render**: generated script is syntactically valid (`compile()`), exposes one
   function per step, and its `argv` dispatch lists every step.
3. **Family selection**: with `SimpleNamespace` fact bundles matching the three
   corpus shapes, assert the expected route wins and that rejected routes carry
   a non-empty `rationale`.
4. **End-to-end against the corpus** (`gcc`-gated, `subprocess`): generate for
   `02`, `07`, `09`; assert the script compiles, each step runs, and the full
   exploit yields a shell.
5. **The real validation, done by hand**: follow each generated walkthrough
   *literally, step by step, as written, without shortcuts*, and confirm a
   shell. Any step needing knowledge not in the document is a **defect in the
   walkthrough** to be fixed there — not papered over with my own expertise.
   Ground truth already established by hand: offset 72 on all three;
   02 needs an alignment `ret` at `0x40101a` before `system` (glibc `do_system`
   uses `movaps`); 07 leaks `puts@got` then returns into `vuln` (called 3x from
   `main`); 09 needs `pop rax`=15 → `syscall` → a 248-byte `SigreturnFrame`
   (payload 344 bytes, fits the 400-byte read).

## Risks

| Risk | Mitigation |
| --- | --- |
| **Generated content is generic filler** — the main failure mode | Every value is a `Fact` with evidence; the hand-follow validation catches vagueness that tests cannot. |
| Rebase pain when Phase-5 lands | All supwngo coupling isolated in `facts.py`; `model.py` imports nothing from supwngo. |
| Cyclic probe unreliable (core dumps disabled, `core_pattern`) | Probe is best-effort with a GDB fallback; failure degrades to a *specific* `UNKNOWN`, and the walkthrough teaches both the corefile and the GDB route so the reader is never blocked. |
| Over-abstraction | Three real families first; `registry.py` stays a dict + scoring until a fourth family justifies more. |
| Fragile environment values (libc path/version) | Marked `ASSUMED` with a command to re-derive, never `MEASURED`. |
| `GadgetFinder`/`ProtectionAnalyzer` slowness (subprocesses, full-file scans per call) | Memoised once in `facts.py`. |
| Independent plan review | `scripts/codex-review.sh` does **not** exist in this repo; using the `codexrev` skill instead, per CLAUDE.md's "where present" wording. |

## Sequencing

1. `model.py` + its tests (lowest risk, authorised to start during review).
2. `facts.py` + `render.py` + `registry.py`.
3. `families/rop_chain.py` (covers 02 and 07), then `syscall.py` (09), then
   `stack_bof.py`.
4. CLI + `CHANGELOG.md`.
5. Hand-follow validation on 02, 07, 09; fix walkthrough defects found.
