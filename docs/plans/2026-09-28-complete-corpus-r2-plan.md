# Plan — complete `corpus_r2`: UAF allocator-reuse, fmtstr leak, overflow-driven tcache poison

Date: 2026-09-28
Status: plan, not yet handed off
Sprints: **F7** (`r2/09`), **F2** (`r2/05`), **F8** (`r2/11`)

Sprints F1+F3 (`r2/06`, `r2/12`) and F4+F5+F6 (`r2/01`–`r2/04`, `r2/14`) are in
flight in separate trees. If both land, `corpus_r2` is **12/15** and the only
targets left are the three below. This plan buys all three, closing the corpus.

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
**functional-correctness defect — report it**, and it is the highest-value
finding class in this repo. "Someone could deliberately bypass this gate to fake
a result" is **misuse — discard it.** A finding whose remedy is a *control*
rather than a *fix* is out of scope.

Deliberate constants, loose gates, target-shaped heuristics and retry-based
brute force are **FEATURES** here. **The goal is to SOLVE targets.**

---

## Sprint F7 — the allocator-reuse UAF shape (buys `r2/09`)

### What the target actually needs — MEASURED

`benchmark/corpus_r2/09_heap_dangling_global`. `main` performs **no startup
allocation** (measured: read the source; the loop is the whole program, despite a
header comment claiming the note is "populated once at startup"). The complete
exploit is a fixed sequence of five menu selections with **no addresses, no
leak, no ROP, and no heap grooming**:

```
1   alloc_note      note_ptr = malloc(80), memset 'A'      (inert placeholder)
2   free_note       free(note_ptr); note_ptr NOT cleared   -> dangling global
4   check_license   malloc(80) returns the SAME chunk      (tcache LIFO)
                    read_flag_into(tok+16, 63)             -> flag lands at +16
3   show_note       puts(note_ptr + 16)                    -> FLAG
5   exit
```

**Measured by me, by hand, on the built binary** — `printf '1\n2\n4\n3\n5\n'`
into the target yields the flag in its stdout. Controls, all four measured in one
run, flag-membership tested programmatically (never printed):

| sequence | meaning | flag in output |
|---|---|---|
| `1,3,5` | alloc → show, no free, no reuse | **no** |
| `1,2,3,5` | alloc → free → show, no reuse | **no** |
| `1,4,3,5` | alloc → license → show, no free | **no** |
| `1,2,4,3,5` | the full UAF chain | **FLAG** |

Three negatives and one positive, so the target is honest: only the genuine
release → reuse-for-something-else → read-through-stale-pointer chain exposes
the secret. The `+16` offset is deliberate — tcache writes `next`/`key` over the
first 16 bytes, so reading at `+16` after free-but-before-reuse shows only the
placeholder.

### The gap — one missing recipe

`supwngo/exploit/pipeline/executors/heapuafread_techniques.py:458`
`build_ladder()` enumerates five shapes:

| # | recipe | step order |
|---|---|---|
| 1 | `release_then_read(free)` | free → read |
| 2 | `rebuild_short_then_read(other)` | other → read |
| 3 | `alias_then_release(other, free)` | **other → free** → read |
| 4 | `occupy_then_release(create, free)` | create → free → read |
| 5 | `release_twice(free)` | free → free → read |

**None is `free → other → read`.** Shape 3 is the closest and has the order
reversed. That is the entire gap, and it is the canonical allocator-reuse UAF
shape — the most realistic one in the family.

### Change

Add one recipe family to `build_ladder()`:

```
release_then_rebuild_then_read(free, other):
    [Step(free, idx=SECRET_IDX), Step(other, idx=SECRET_IDX)] + reads_sweep
```

i.e. release the privileged object, then drive **each** unclassified command
(which may re-allocate the same size class and write its own data into the
just-freed chunk), then sweep every read path. Cost is `len(frees) × len(others)`
— the same order as existing shape 3.

`r2/09` has **no index at all**, so the recipe must tolerate an option with no
index prompt. The driver already probes each option's prompt sequence both bare
and with arguments (`probe_prompt_sequence`, ~line 776), so verify this works
rather than assuming it does — and verify it rather than building new probing.

### The ordering defect — worth more than the recipe

`build_ladder`'s docstring (line 463) states the ladder is ordered **by cost,
not by likelihood**, justified by: *"the oracle is exact: the first recipe whose
output contains a flag pattern is the answer and the rest are never run."*

That justification holds only if the ladder always runs to completion. It does
not: `r2/09`'s prior run was a **420.1 s harness timeout** (recorded, from the
earlier sweep — inconclusive, not a decline). Under truncation, cost-ordering
silently degrades into likelihood-ordering-by-accident, and a cheap-but-unlikely
shape sitting ahead of the canonical one loses the target with no diagnostic
saying so.

So: seat the new recipe **immediately after shape 1**, not appended at the end.
Appending it would leave `r2/09` failing exactly as it does today while the test
suite goes green, which is the repo's signature defect class — a check that
cannot fail in a way that looks like failure.

Also amend that docstring: the cost ordering is contingent on completing the
ladder, and it does not always complete.

### Tests

* **Positive control first.** Assert the new recipe is present in the ladder
  **and** that it sits ahead of the shapes it must precede. Mutate the order to
  wrong-but-present (move it back to the end) and confirm the ordering test goes
  RED. Record the RED output.
* Never let the absence assertion stand alone: a test asserting shape 3 is not
  the only `other`-using shape must also assert shape 3 still exists, or
  deleting it passes vacuously.
* **Regression guard:** the round-1 UAF-read target that `heapuafread` already
  solves must still solve, same technique credited. Identify it by name from the
  corpus rather than assuming which one it is.
* Three states: pass / fail / **inconclusive**. A timeout is inconclusive and
  must be reported as such, not as a failure.

---

## Sprint F2 — format-string leak stage (buys `r2/05`)

`benchmark/corpus_r2/05_fmtstr_pie_leak` is **Full RELRO** — confirmed by
`cflags` and by pwntools. **Its own source comment claims `partial` and is
wrong; trust the ELF.** This matters: "partial" would imply a GOT route, and
there is none. So no write-based path exists and the target must be leaked.

Leak primitive: a spilled `void (*self)(void) = vuln;` on the stack. Read it via
a positional `%p` directive, recover the PIE base from it, then `read(0, buf,
300)` with the saved return address at `buf+232` gives a write in the **same
process** — no printf re-entry needed, so this is a single-shot leak-then-write.

### VERIFIED end to end by hand — and it corrected this plan twice

Driven by hand with pwntools; **flag captured**. Two corrections to what this
plan originally said, both found by testing the rule instead of asserting it.

**Correction 1 — the low-12-bits discriminator as first written is NOT
sufficient, and picks the wrong answer on this very target.** Measured from one
`printf` of 41 `%p`:

* 37 values parsed. A **bare range check would have accepted 12 of them** — so
  the discriminator does real work and must stay.
* But matching low 12 bits against *any* symbol produced a **false positive
  first**: `_end` (a **data** symbol at `+0x4020`) collided on low 12 bits `0x20`
  with an unrelated leaked value at position 4. The resulting base was even
  **page-aligned**, so that sanity check does not discriminate either. Using it
  failed.
* `low12 == 0` is a **degenerate class** — every page-aligned value matches every
  page-aligned symbol (`data_start`, `_IO_stdin_used`, `_init`, …). It must be
  excluded outright.

The corrected rule, measured working:

1. Anchor **only on function symbols** in executable sections. That alone removes
   `_end`/`data_start`.
2. **Drop the `low12 == 0` class.**
3. Treat the match as a **ranking, and enumerate candidates** — try each and keep
   the first that works. It is not a single decision.
4. **The real validity signal is two independent anchors agreeing on one base.**
   Here `vuln` (position 32) and `main` (position 39) both yielded
   `0x5733c47b9000`, which **equals the kernel's true load base** from
   `/proc/<pid>/maps`. Cross-check anchors against each other; a lone match is
   weak, two agreeing is strong.

Note the scan depth: `self` sits at **position 32**, so a 30-slot scan misses it.
Use 41 `%p.` (123 bytes), which fits the 127-byte read.

Frame layout, read from `objdump` rather than trusted from the comment
(`sub rsp,0xe0`; `self` at `rbp-0x10`; `name` at `rbp-0xa0`; `buf` at `rbp-0xe0`):
saved `rbp` at **`buf+224`**, return address at **`buf+232`**. The source comment's
232 is correct — unlike its RELRO claim.

**Correction 2 — the cross-cutting one. See the section below; it is why the
first attempt failed with the base already correct.**

---

## Sprint F8 — overflow-driven tcache poison (buys `r2/11`)

`benchmark/corpus_r2/11_heap_overflow_tcache_poison`. Distinct from round-1's
`12_heap_tcache_poison`, which corrupted a freed chunk's `next` via a **UAF
write** with no size overflow. Here `delete_note()` correctly clears its slot —
there is no dangling pointer. The bug is a genuine heap overflow (CWE-122):
`fill_note()` checks the attacker length only against a fixed `0x400` ceiling,
never against the note's own allocated size.

Facts measured from the source:

* `dispatch_table` is a **named symbol**, `__attribute__((aligned(16)))`, so a
  poisoned pointer landing there passes glibc's `aligned_OK()` with no offset
  fudge. `win` is a named symbol. Non-PIE, partial RELRO.
* `create_note()` **prints the chunk address**: `printf("chunk[%d] @ %p\n", ...)`
  — the heap address needed for safe-linking is *volunteered*, exactly the
  harvest capability Sprint F4 builds. Reuse it.
* Safe-linking: the stored `next` is `(chunk_addr >> 12) ^ target`.

### The chain is VERIFIED, not a sketch — measured end to end by hand

I drove this target by hand with pwntools and **recovered the flag on the first
attempt**. So this sprint is implementing a known-good recipe, not discovering
one. Measured constants (local glibc **2.35**, so safe-linking is active):

| item | value |
|---|---|
| `win` | `0x401358` |
| `dispatch_table` | `0x404090` — 16-byte aligned, as its `__attribute__` intends |
| `noop` | `0x40133e` |
| PIE | off |
| chunk stride for `sz=0x50` | **`0x60`**, measured uniform across three chunks |

The overflow payload from `chunks[0]`, total length **`0x68`**:

```
0x00 .. 0x4f   b"A" * 0x50          chunk0 data
0x50 .. 0x57   p64(0)              chunk1 prev_size
0x58 .. 0x5f   p64(0x61)           chunk1 size  <- REPAIR; the write crosses it
0x60 .. 0x67   p64((a1 >> 12) ^ dispatch_table)   chunk1 tcache next
```

`PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`, where `pos` is the freed chunk's own
data address — which `create_note()` volunteers via its `%p`.

**Built-in oracle:** the second re-allocation prints `dispatch_table` as its own
chunk address. So the implementation can confirm the poison landed by parsing the
target's own output, before ever attempting the hijack. Use it — it separates "the
poison failed" from "the hijack failed", which are different bugs.

Controls, all measured, each necessary step proven necessary by removing it alone:

| flag | poison landed | case |
|---|---|---|
| no | n/a | no poison at all, just `call(0)` |
| no | **YES** | poison lands but `win` never written |
| no | **NO** | **one free only** (tcache count == 1) |
| **FLAG** | YES | full chain, two frees (positive control) |

The third row is the one to keep: it converts the count-of-2 requirement from an
inference into a measurement. With a single free the count reaches 0 after the
first re-allocation, the next `malloc` never consults tcache at all, and the
poison silently does nothing — `dispatch_table` is never returned.

Sequence, ~9 menu interactions, deterministic once the addresses are harvested:

1. `create` 0, 1, 2 at one size class (chunk stride `0x60` for `sz=0x50`).
2. `delete` 2, then `delete` 1 → tcache holds `chunk1 -> chunk2`, **count = 2**.
3. `fill` 0 with `len` reaching `chunk1`'s body: pad to the stride, **repair
   `chunk1`'s size field** (`0x61`, i.e. size | PREV_INUSE) since the write
   crosses it, then write `(addr1 >> 12) ^ dispatch_table`.
4. `create` → returns `chunk1`; the bin head becomes `dispatch_table`, count 1.
5. `create` → count > 0, so `tcache_get` returns **`dispatch_table`**.
6. `fill` that index with `p64(win)` → `dispatch_table[0] = win`.
7. `call` 0 → `win()` → flag.

**The count-of-2 step is load-bearing and is the usual reason this fails:** with
only one chunk freed, the count drops to 0 after step 4 and the next `malloc`
never consults tcache at all, so step 5 silently returns ordinary heap memory
and the poison appears not to work. Free two.

Cost: still the most *machinery* of the three — overflow delivery, size-field
repair, safe-linking — but the **uncertainty is gone**, since the chain above is
measured working. Extend the existing `tcache_poison_got` executor with an
overflow-based write primitive rather than rewriting it: it already implements
safe-linking against the *locally loaded* libc rather than trusting a version
number, and it **refuses PIE targets outright** (`heap_techniques.py:174`), which
is no obstacle here because `r2/11` is non-PIE. Grep before building.

---

---

## Cross-cutting finding — harden `pie_base_offset()`, don't rebuild alignment

### First, a retraction: the alignment retry is NOT missing

I hit a stack-alignment trap by hand and initially wrote this section up as a
missing framework capability. **Grepping the tree before handing that off showed
most of it already exists**, so the claim is withdrawn — recorded here because the
underlying mechanism still matters.

* `rop_techniques.py:14-17` already documents the `movaps`/`do_system` fault.
* `Ret2PltSystemExecutor` (`:253`) and `Ret2LibcLeakExecutor` (`:456`) already try
  **both** stack parities — `for use_align in (True, False)`. Strictly better than
  the single fix I found by hand.
* `Ret2WinExecutor` (`stack_techniques.py:229`, `:259`) already prepends the
  aligning `ret` whenever a `ret` gadget is known — exactly what `r2/05` needs, so
  the framework would not have hit my trap at all.

The mechanism, kept for the record — **and corrected, because my first
explanation was wrong.** Measured on `r2/05` with the base already proven correct
against `/proc/<pid>/maps`: `p64(win)` → **SIGSEGV, exit -11, zero output**;
`p64(ret) + p64(win)` → **exit 0, FLAG_CAPTURED**.

I first attributed that to lazy binding — `fopen`/`fgets`/`fputs` are called
nowhere earlier, so the first call would enter `_dl_runtime_resolve`, which saves
XMM state with `movaps`. **That is not what happens here.** `readelf -d` shows
`FLAGS BIND_NOW` and `FLAGS_1: NOW PIE`, and pwntools reports RELRO **Full**, so
every `R_X86_64_JUMP_SLOT` (including `fopen`, `fgets`, `fputs`) is resolved
**eagerly at startup** and `_dl_runtime_resolve` is never involved.

The real cause is simpler and has a **broader** trigger: glibc's own SSE code
inside `fopen` executes `movaps` against the stack and faults when `rsp` is not
16-byte aligned — precisely the case `rop_techniques.py:14-17` already documents
for `do_system`. So the condition is **"the win path calls into glibc"**, not
"the target uses lazy binding". Full-RELRO targets need the alignment retry just
as much as partial-RELRO ones; anyone implementing this must not gate it on RELRO.

The failure is indistinguishable from a wrong address — SIGSEGV, zero output, not
even `flag.txt missing` — which is what made it costly to diagnose.

**Two traps recorded from that dead end**, both of which cost me probes:

* Take the `ret` from an **executable** region. `ELF.search(b"\xc3")` scans the
  whole file including non-executable sections; using its result jumped to a
  non-executable byte, crashed, and made me wrongly conclude alignment was not the
  problem.
* `win` and `print_flag` build their own frames (`push rbp; mov rbp,rsp`), so a
  clobbered saved `rbp` is **irrelevant** to them. Supplying a "valid rbp" changes
  nothing.

The one alignment gap that **is** real, and it is narrow: `Ret2WinExecutor` adds
the aligning `ret` **unconditionally** instead of trying both parities, so a target
needing the unaligned form fails with no diagnostic — the mirror image of the bug I
hit. Two-line change to match what the two ROP executors already do.

### The finding that stands: `pie_base_offset()` can confidently return a wrong base

`rop_techniques.py:119` already implements the low-12-bits discriminator, phrased
equivalently as "`leaked - offset` is only a possible load base when it is
page-aligned". Sound idea. Measured against `r2/05`, three weaknesses remain:

1. **It iterates every symbol, data included** (`:130`). On `r2/05` this admits
   `_end` (`+0x4020`) as an anchor for an unrelated leaked value whose low 12 bits
   happen to be `0x20`. Its sort at `:139`,
   `key=lambda item: (item[0].startswith("_"), len(item[0]))`, *accidentally*
   defends against `_end` specifically by deprioritising underscore names.
2. **No guard for the degenerate `low12 == 0` class** — the live hole the sort does
   *not* cover. Any page-aligned leaked value matches every page-aligned symbol. On
   `r2/05` that class holds `data_start`, `__data_start`, `_IO_stdin_used` and
   `_init`, and **`data_start` does not start with `_`**, so the existing sort would
   select it and return a confidently wrong base. Exclude `low12 == 0` outright.
3. **It returns `matches[0]` — one decision, no enumeration.** Measured: the strong
   validity signal is **two independent anchors agreeing on one base**. On `r2/05`,
   `vuln` (scan position 32) and `main` (position 39) both produced
   `0x5733c47b9000`, equal to the kernel's true load base. Return ranked candidates
   and let the caller try each; corroborate across anchors when several pointers
   were leaked.

Scale of the risk, measured from one `printf` of 41 `%p`: 37 values parsed, of
which **a bare range check would accept 12**. The discriminator is doing real work
and must stay — these are refinements to a sound idea, not a replacement.

**This is the change F4's classifier and F2 should both consume** rather than each
writing its own. If codex's in-flight F4 classifier lands without these three
refinements, log it as a deficiency and fix it here.
## Benefit metric, pre-registered

| metric | baseline | target |
|---|---|---|
| `corpus_r2` solved | **5/15** measured at v2.1.0; **12/15** expected entering this plan if F1+F3 and F4–F6 land | **15/15** |
| `r2/09` | prior run 420.1 s harness **timeout (inconclusive)** | SUCCESS, `FLAG_CAPTURED` |
| `r2/05` | NOT SOLVED (103.6 s, recorded) | SUCCESS |
| `r2/11` | NOT SOLVED | SUCCESS |
| suite | 2050 passed / 16 skipped / 0 failed (measured, v2.1.0) | no new failures |

Re-measure with `python3 scripts/coverage_sweep.py benchmark/corpus_r2 --timeout
300 --jobs 3`. **Do not edit the tree while that sweep runs** — doing exactly
that voided a previous sweep and produced believable wrong numbers in both
directions.

**All three chains are now measured working end to end by hand**, so every sprint
here is wiring a known-good recipe rather than discovering one. Order:

1. **The alignment retry** (cross-cutting section above) — first, because it is a
   few lines, it is shared, and it may convert targets this plan never mentions.
   Re-run the full corpus sweep straight after it, before anything else lands, so
   its effect is attributable.
2. **F7** — one recipe plus a reseat.
3. **F8** — most machinery, but zero remaining uncertainty.
4. **F2** — depends on the alignment retry and on F4's classifier, with the
   function-only/non-degenerate/enumerate corrections applied.

A null result on any of them reported honestly is worth more than a forced pass.
