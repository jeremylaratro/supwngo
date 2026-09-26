# CLI surface and code reachability — plan

**Date:** 2026-09-25
**Status:** in progress
**Baseline:** `main` @ `6c89ae1` (v2.0.0)

## Problem

24% of the shipped package cannot be reached by any CLI invocation, and the
unreachable part is also the untested part. Both numbers are measured below.

### How reachability was measured (and three instruments that were wrong first)

The final instrument builds a static import graph over all 198 shipped modules
with `ast`, recording imports **at any nesting depth** (including inside
function bodies) plus `from pkg import name` resolved as `pkg.name`, then does a
BFS from `supwngo.cli`, adding parent packages because importing a submodule
executes its parents' `__init__`.

Three earlier instruments were discarded for being narrower than the claim they
carried:

1. **grep for `import <module_name>`** — reported 0 importers for 25 techniques.
   Its positive control failed: 4 of 5 techniques that *are* registered in
   `build_default_registry()` also reported 0, because the registry keys are
   technique *slugs*, not module names. Wrong axis; discarded.
2. **`sys.modules` after `import supwngo.cli`** — reported 103 modules "never
   loaded". But the CLI defers imports into command bodies, so `kernel` and
   `symbolic` (both real commands) were misclassified. Load-time ≠ reachable.
3. **Transitive closure over targets named in `cli.py`** — reported 62
   unreachable, including `exploit.walkthrough.render`. Wrong: `render` is
   imported inside `explain_binary()`, a function body one level below the CLI,
   which an import-only closure never executes.

The accepted instrument's positive control asserts that
`exploit.walkthrough.render`, `exploit.walkthrough.registry`,
`exploit.pipeline.executors`, `kernel.slab` and `core.binary` all come out
reachable. It passes. **A reachability claim in this document without that
control behind it should not be trusted** — the first three instruments each
produced a confident, wrong number.

### Measured result

| | count |
| --- | --- |
| modules shipped | 198 |
| reachable from `supwngo.cli` | 150 |
| **unreachable** | **48 (24%)** |

Unreachable, by package: `exploit.heap` 11, `ai` 5, `distributed` 5,
`reporting` 5, `windows` 5, `embedded` 4, `api` 3, `containers` 3, `schema` 3,
`macos` 2, `payloads` 2.

### The compounding fact

The unreachable modules are also almost entirely untested. Test files
referencing each:

```
exploit.heap.tcache           1        api.server               0
schema.resolve                3        distributed.coordinator  0
exploit.heap.house_of_force   0        ai.advisor               0
exploit.heap.techniques       0        containers.escapes       0
exploit.heap.layout           0        windows.pe_binary        0
payloads.loader               0        macos.mach_binary        0
reporting.generator           0        embedded.firmware        0
```

So this is **not** tested library code waiting for a surface. Wiring a module to
the CLI as-is would ship an unverified feature and convert "dead code" into
"a command that lies". Every wiring in this plan therefore lands **with tests in
the same PR**, or it does not land.

## Non-goals

- Tool hardening (provenance, audit trails, trust boundaries) — out of scope by
  standing project rule.
- Wiring all 48 modules. Platform modules (`windows`, `macos`, `embedded`,
  `containers`) cannot be honestly verified on this host; they are deliberately
  deferred rather than surfaced untested.
- `schema.*` stays internal. It is the normative context-document resolver and
  is test-facing by design (3 test files); it is correctly not a CLI command.

## Approach

Ordered by value per unit of risk. One PR per numbered item, merged before the
next begins, each green.

1. **`supwngo report`** — surface `reporting/` (5 modules, 1,822 lines: SARIF
   exporter, CVSS v3.1 calculator, HTML/Markdown generator). Highest usefulness:
   SARIF is consumable by CI and code scanning, so this turns analysis output
   into an artifact other tools ingest. Real work is the adapter from the
   `Vulnerability` dataclass the analyzers emit to `VulnerabilityFinding`; the
   click wrapper is the easy half.
2. **`supwngo serve`** — surface `api/` (`create_app()`, `run_server()` at
   `api/server.py:135,531`). Self-contained; FastAPI is already an optional
   import with a graceful failure path. Must fail loudly with an install hint
   when FastAPI is absent rather than traceback.
3. **Heap technique dispatch** — the 11 `exploit.heap` modules (house-of-force /
   einherjar / spirit / modern, large_bin, unsorted_bin, safe_linking, tcache,
   techniques, layout) are exploitation capability, not surface. Wiring them
   means registering executors in `build_default_registry()` so `autopwn` can
   select them, which requires corpus targets that exercise each. Largest
   capability gain, largest risk, and the only item here that needs benchmark
   targets before it can be claimed to work.
4. **Option consistency audit** — `--libc` exists on 7 of 32 commands. Normalize
   the shared option set across commands that analyze a binary.
5. **`--libc-path` loader threading** (previously deferred) — let a target
   execute against a specified glibc, and detect offset-libc ≠ loaded-libc
   mismatch. Verified absent today: no `patchelf`, `ld-linux`, `LD_LIBRARY_PATH`
   or `--library-path` anywhere in the package (the one `ld-linux` string hit is
   a literal in `walkthrough/fmtstr_probe.py:1227`), so targets always run
   against host glibc while offsets may come from a different one.

## Tradeoffs, and the option not taken

**Taken: surface-then-verify, one small PR at a time.** Each PR adds one command
plus its tests, so a regression is attributable to one merge.

**Not taken: a single "wire everything up" PR.** It would show 12 new commands
at once and look far more impressive in a changelog. Rejected because the
unreachable code is untested code — a bulk PR would ship ~10 unverified
commands whose failures could not be attributed, and the first user to run
`supwngo windows` on a host with no PE to analyze would get a traceback that
looks like a broken tool. What would flip this: if the platform modules already
had passing tests, bulk wiring would be cheap and safe.

**Not taken: deleting the unreachable code instead.** Defensible for
`windows`/`macos`/`embedded` (~11 modules, no tests, no surface, no corpus). Not
chosen yet because deletion is irreversible in effect and the maintainer has not
asked for it; it stays on the table as a follow-up decision once the valuable
items above are surfaced. Deleting `exploit.heap` would be wrong — that is
genuine technique code the pipeline should be using.

## Test strategy

- One test module per new command, asserting the **real invocation** via
  `CliRunner` (not the underlying function), because the wiring is the thing
  being added.
- Each new command asserts its failure path: missing optional dependency, and
  missing/unreadable binary, exit non-zero with a message naming the cause.
- A reachability regression test: re-run the accepted AST-graph instrument in
  CI and assert the unreachable set does not grow. It carries its own positive
  control, so it cannot silently pass by measuring nothing.

## Risks

- **Surfacing untested code.** Mitigated by the tests-in-same-PR rule.
- **The reachability test becoming a rubber stamp.** Mitigated by embedding the
  positive control in the test itself; if the control stops firing, the test
  fails rather than passing vacuously.
- **Item 3 cannot be honestly completed without corpus work.** It will be
  reported as partial rather than claimed done if targets are not available.
