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

**The discriminator is load-bearing:** accept a leaked value as a code pointer
only when its **low 12 bits** match the page offset of a known symbol. ASLR
relocates by whole pages, so the low 12 bits are invariant. A bare range check
accepts garbage and propagates a confident wrong base into every later stage.
If Sprint F4 lands first, reuse its classifier rather than writing a second one.

Prove the classifier can REJECT: feed it a plausible-range value whose low 12
bits match no symbol offset and assert it is **not** classified as a code
pointer.

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

Sketch, ~9 menu interactions, deterministic once the addresses are harvested:

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

Cost: this is the most expensive of the three sprints — it needs the overflow
delivery, the size-field repair, and safe-linking. Do it last. If the existing
`tcache_poison_got` executor can be extended with an overflow-based write
primitive rather than rewritten, prefer that; grep before building.

---

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

Order the sprints **F7, F2, F8** — cheapest and most certain first. F7 is one
recipe plus a reseat; F8 is a genuine new primitive. A null result on any of them
reported honestly is worth more than a forced pass.
