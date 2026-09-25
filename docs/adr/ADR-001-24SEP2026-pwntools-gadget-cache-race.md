# ADR-001 — Do not patch pwntools' ROP gadget cache; isolate it instead

- **Date:** 2026-09-24
- **Status:** Accepted
- **Supersedes / superseded by:** none
- **Related:** `conftest.py`, commit `d51f9bc`; review protocol `f59ec04`

## Context

pwntools keys its ROP gadget cache by the analysed ELF's sha256 and stores it
under `$XDG_CACHE_HOME/.pwntools-cache-<pyver>/rop-cache/`. Two details make that
shared file hazardous when more than one process analyses the same binary:

- `ROP.__cache_save()` is `open(filename, 'w+').write(repr(data))` — truncate in
  place, unlocked, non-atomic. A large gadget dictionary spans several `write()`
  calls, so the file is observably incomplete for a window on every save.
- `ROP.__cache_load()` is an unguarded `eval(open(filename).read())`. A reader
  arriving mid-write raises `SyntaxError` *out of `ROP()` construction*.

In supwngo that exception is caught by `GadgetFinder`, which then reports no
gadgets. `rop_chain` abstains, and any target needing a ROP technique reports
`triage` instead of its real route. The failure therefore does not look like a
crash; it looks like a **plausible, actionable, wrong answer**, and it is
non-deterministic, so a suite result obtained under concurrency is untrustworthy
in both directions.

Several agents run test suites and gated measurements concurrently on this host,
so the preconditions are routinely met.

## The race is real — positive control

This was measured, not inferred. A harness drove four processes through 40
save+load cycles each against one shared cache path, with a payload large enough
that a single save spans multiple `write()` calls:

- **Unpatched pwntools: torn reads occurred** (`READ FAILED: SyntaxError …`).
  This was asserted as `failures > 0`, deliberately, so that the patched result
  could not pass merely because the race fails to reproduce on this machine.
- With an atomic-publish patch in place: zero torn reads.

So the hazard exists and is reproducible here. That is the part worth keeping.

## It was **not** the cause of the six spurious signatures

The cache race was the leading hypothesis for six recurring failure signatures
(`pwnlib has no attribute 'context'`, families collapsing to `triage`), and
`XDG_CACHE_HOME` isolation was proposed as the fix on the strength of a clean
sample plus confirmation that `context.cache_dir` resolved to the isolated path.

That confirmed the redirect was *installed*; it never tested whether the redirect
*explained* the symptom. The discriminating experiment — re-induce the failure
with the intervention live — gave:

- `pytest tests/ -k walkthrough` alone: **10 failed, 6 pwntools load failures, in
  a single process.** Not concurrency.
- The minimal two-file repro under a fresh, verified-isolated `XDG_CACHE_HOME`:
  **2 failed, 105 passed.** Isolation live, symptom unchanged.

The actual cause was unrelated: `pwnlib/term/text.py` calls `curses.setupterm()`
at module scope guarded only by `except curses.error`, which does not catch the
`io.UnsupportedOperation: fileno` raised when `sys.stdout` has no file descriptor
(as under `click.testing.CliRunner`). The aborted import evicts the half-built
`pwnlib` from `sys.modules` while leaving its finished submodules cached, so every
later `import pwn` in that process gets a fresh empty `pwnlib` whose submodules
are never rebound, and `from pwnlib import *` fails on `context` from then on.
Fixed in `d51f9bc` by setting `PWNLIB_NOTERM` at conftest import time.

**Both things are true at once**, and conflating them is what cost the time: the
cache race is real, and it explained none of the observed failures.

## Decision

1. **Isolate, do not patch.** The root `conftest.py` gives each test session its
   own `XDG_CACHE_HOME`, so concurrent sessions do not share a cache file at all.
   No locking semantics, nothing to deadlock, no pwntools internals touched.
2. **Reject the atomic-publish patch.** A working implementation existed
   (`supwngo/utils/pwnlib_cache.py` plus 8 passing tests including the positive
   control above) and was deliberately dropped, not lost.

## Why the patch was rejected

The patch monkeypatched pwntools' **name-mangled private methods** —
`_ROP__cache_save`, `_ROP__cache_load`, `_ROP__get_cachefile_name` — and, to make
atomic publishing work, **reimplemented one line of upstream logic**: the
transform that stores gadget keys relative to the ELF's link address
(`k + elf.load_addr - elf.address`) so a cache survives being loaded at a
different base.

That trade is bad in the specific direction this project cares about most:

- **It swaps a detectable failure for a silent one.** A torn read raises
  `SyntaxError` — loud, and already surfaced by the tests. A drifted address
  transform returns *gadget addresses that are wrong but still look like
  addresses*. Every downstream consumer accepts them; the exploit simply does not
  work, for reasons that point anywhere but here.
- **The fragility is silent on upgrade.** Private name-mangled attributes carry no
  compatibility promise. A pwntools bump can change the transform or rename the
  method, and the patch degrades quietly rather than failing to apply.
- **The cheaper fix covers the demonstrated hazard.** Every failure actually
  observed was in a test process, and per-session `XDG_CACHE_HOME` removes the
  sharing outright rather than making sharing safe.

Guarding the reimplemented transform with a round-trip test (which the dropped
suite did, including a shifted load address for PIE) reduces but does not remove
this: the test proves the transform matches *today's* upstream, and only if
someone runs it after the bump.

## Consequences

- Concurrent **test sessions** are safe, and this is enforced by test
  (`tests/test_pwnlib_import_isolation.py` asserts the resolved `cache_dir` is
  session-specific, and a mutant that drops the pid from the path is killed).
- **Non-test processes are not covered.** Anything invoking supwngo outside pytest
  — notably `benchmark/run_bench.py` under concurrency — still shares the default
  cache and can still take a torn read. The same three-line environment default
  closes it; that residual is assigned to the owner of that file and is
  deliberately **not** addressed here.
- Each session leaves a `/tmp/supwngo-test-cache-<pid>/` directory behind. Cheap,
  and preferred over a `tmp_path_factory` fixture, which cannot run early enough:
  the value must be set before collection imports anything.
- The rejected implementation is not in the tree. It is set aside at
  `/tmp/wt-cache-setaside/` for this session only; this ADR, not that directory,
  is the durable record.

## What would reopen this

Either of:

1. **A measured torn read outside a test process** — e.g. a benchmark or CLI run
   that takes a `SyntaxError` out of `ROP()`, or produces a gadget-cache-derived
   wrong answer, where per-process `XDG_CACHE_HOME` is not an option. Environment
   isolation is preferred even then; a patch is justified only if isolation is
   genuinely unavailable.
2. **pwntools exposing a supported cache hook** — a documented lock, an atomic
   write, a pluggable cache backend, or a public override for the cache path. At
   that point the fix stops being a monkeypatch of private internals and the
   silent-wrongness objection above disappears.

Absent one of those, the next person to rediscover this race should read this
document and stop, rather than rebuild the patch.
