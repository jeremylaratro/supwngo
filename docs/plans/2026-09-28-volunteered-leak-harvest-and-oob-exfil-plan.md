# Volunteered-leak harvest, and data-only OOB-read exfiltration

**Date:** 2026-09-28
**Author:** planning by Opus 5 (this session); implementation delegated to codex
**Status:** ready to implement — F1/F3 (format string) are in flight separately
**Buys:** 4 of the 9 unsolved `corpus_r2` targets (01, 03, 04, 14) from **two**
capabilities

---

## 1. The gap, measured

I read all nine unsolved `corpus_r2` sources (2026-09-28, mine) rather than
guessing from directory names — a habit this repo has already been burned by
twice (`r2/10` solves via `ret2libc_leak`, not the `ret2csu` its name advertises;
`r2/07` via `srop`). Four of the nine share a shape that no current executor
exploits, and it is not a missing exploitation *technique*. It is a missing
*input* path.

**Three targets hand us the leak for free, before any payload is sent, and the
framework throws it away.**

| target | protections | what the target volunteers | where |
|---|---|---|---|
| `r2/01_stack_shellcode_relay` | canary OFF, **NX OFF**, no-PIE | `printf("buf @ %p\n", buf)` — the stack buffer's own address, as text | before the read |
| `r2/03_pie_write_leak_ret2libc` | canary OFF, NX ON, **PIE**, full RELRO | `write(1, &self, 8)` where `self = vuln` — a **raw 8-byte code pointer**, defeating PIE | before the read |
| `r2/04_canary_relay_bypass` | **canary ON**, NX ON, no-PIE | `write(1, relay_buf, 8)` where `relay_buf = buf+72` — i.e. **the canary itself**, 8 raw bytes | between the two reads |

None of these needs a format string, a ROP-based leak, or a brute force. Each
prints the exact value that defeats its own protection, unprompted, every run.
`r2/04` does not even require the first write to contain anything: `read(0, buf,
64)` cannot reach `buf+72`, so the 8 bytes `memcpy`'d from `buf+72` are the live
canary regardless of what we send.

That is **one capability serving three targets**: harvest what the target
volunteers, classify it, and register it as a leak.

**The fourth target needs no control flow hijack at all.**

`r2/14_oob_read_flag_array` — `canary OFF, NX ON, no-PIE, partial RELRO`:

```c
struct data_s { int arr[8]; char secret[64]; };   /* file-scope static `d` */
...
if (idx < 0) { puts("bad"); return 1; }           /* lower bound only */
printf("arr[%d] = %d\n", idx, d.arr[idx]);        /* no upper bound at all */
```

`init()` populates `d.secret` from `flag.txt` at runtime (so no `.rodata`
literal exists to find statically). `idx = 8..23` is 16 ints = 64 bytes = the
entire flag, printed as decimals. `main` loops `while (vuln())` until stdin is
exhausted, so **one stdin blob** (`8\n9\n…\n23\n`) recovers everything in a
single process. There is no shell, no ROP, and no address leak in the solution.

This is an exploitation *class* the framework does not model: **data-only
information disclosure, where reading the flag IS the win.** Every existing
executor is built around redirecting control flow.

---

## 2. Sprints

### Sprint F4 — volunteered-leak harvest (buys `r2/01`, `r2/03`, `r2/04`)

**Change:** add a harvest stage to the interaction layer that reads whatever the
target emits before and between payload writes, extracts candidate leaked
values, **classifies** each one, and registers it in `ExploitContext` so the
existing executors can consume it.

Extraction — run all of these over every chunk of target output, they are cheap:

* **Text pointers:** `0x[0-9a-fA-F]{6,16}` (this is `r2/01`'s `%p`).
* **Raw little-endian pointers:** any 8-byte window whose value is in a
  plausible mapping range. For amd64: `0x400000–0x500000` (no-PIE image),
  `0x550000000000–0x5a0000000000` (PIE image), `0x7f0000000000–0x800000000000`
  (libc/stack). This is `r2/03`'s `write(1, &self, 8)`.
* **Canary candidates:** an 8-byte window whose **low byte is 0x00** and whose
  upper 7 bytes are not all equal and not ASCII. That is `r2/04`.

Classification — what each one unlocks:

| signature | classify as | register as |
|---|---|---|
| in no-PIE image range, and `value & 0xfff` equals a known symbol's page offset | code pointer | PIE/image base = `value − symbol_offset` |
| in PIE image range, same low-12-bit match | code pointer | PIE base |
| in libc range | libc pointer | libc base candidate (needs a symbol guess; may stay unresolved) |
| low byte `0x00`, high entropy | **stack canary** | `context.canary` |
| in stack range (`0x7ff…`, low 12 bits unconstrained) | stack address | `context.stack_leak` — this is `r2/01`'s shellcode jump target |

**The low-12-bits page-offset match is the discriminator** and it is what keeps
this honest: a genuine code pointer's low 12 bits equal the static offset of the
symbol it points at, because ASLR relocates by pages. Do not accept a value as a
code pointer without that match — otherwise the harvester "finds" a leak in any
random output and every downstream executor gets a confident wrong base.

Then let the existing executors use it: `stack_shellcode` should prefer a
harvested stack address over its current guess (`r2/01`, NX is OFF so the payload
is `shellcode + padding + p64(stack_leak)`); the canary-aware overflow path should
prefer a harvested canary over brute force (`r2/04`); the PIE-aware ROP path
should prefer a harvested image base (`r2/03`).

**`r2/03` needs one more thing after the PIE base:** it is full RELRO with NX, so
it still needs libc. Its `read(0, buf, 500)` into `buf[72]` leaves "room for a
multi-round ROP chain" (the source says so) — so `puts@plt(puts@got)` to leak
libc, return into `vuln` again, then `system("/bin/sh")` on the second round.
`ret2libc_leak` already does two-round chains (it solved `r2/10`); the only thing
it lacked here was the PIE base. If the multi-round return proves not to work,
**say so** — `r2/03` is then a partial result and F4 still buys 01 and 04.

### Sprint F5 — data-only OOB-read exfiltration (buys `r2/14`)

**Change:** a new executor, suggested name `oob_index_read_exfil`, for the class
"the target reads an index and echoes a value derived from it".

* **Gate (deliberately loose — looseness is the point):** the target prompts for
  something numeric, and echoing a numeric value back. A missing upper-bound
  check is nice to confirm from the disassembly but must **not** be required —
  the gate should open on "reads an int, prints an int".
* **Exploit:** sweep `idx` over a range (0 up to ~512, and also a negative sweep
  down to −64 for the mirror-image bug that round 1's `14_negative_index` has),
  feeding them as one newline-separated stdin blob since these targets loop until
  EOF. Parse every integer out of the output.
* **Reassembly:** take the harvested values in index order and reinterpret them
  as bytes in **several widths** — 4-byte little-endian (that is `r2/14`), 8-byte
  little-endian, and 1-byte — then scan each reassembly for the flag pattern.
  Try all widths; do not try to infer the right one.
* **Verification:** `FLAG_CAPTURED` directly. There is no shell here, and this is
  **already supported — checked, not assumed** (2026-09-28, mine). The ladder in
  `supwngo/exploit/verification.py:34` makes `FLAG_CAPTURED` a level in its own
  right, and at least five executors already top out there with no shell:
  `heapuafread_techniques.py:10` says outright that "the ceiling for this whole
  category is `FLAG_CAPTURED` and never `SHELL_ACCESS`", and
  `path_traversal_techniques.py`, `loop_counter_techniques.py`,
  `library_hijack_techniques.py` and `toctou_techniques.py` do the same. So F5 is
  **not gated** — follow the `heapuafread` executor as the shape to copy, since it
  is the closest existing analogue (read a secret out of live memory, print it,
  credit the flag).

**Seating:** this executor is fast and its gate is loose, which is exactly the
combination that steals attribution from narrower executors. Measure before
seating it early — the repo has three precedents (two seats granted, one denied
on measurement, `I-42`). Default to seating it **late** unless measurement says
otherwise.

### Sprint F6 — ret2plt with a runtime-built command string (buys `r2/02`)

**The whole gap is one failed string search.** `r2/02_ret2plt_strcat_system`
(`canary OFF, NX ON, no-PIE, partial RELRO`) needs no leak at all. Measured
2026-09-28, mine:

| piece | where | note |
|---|---|---|
| `system@plt` | `0x4010e4` | present in the PLT; referenced via a never-taken `getenv()` branch purely so the import is emitted |
| `sh_buf` | `0x404080` | **a named symbol**, `static char sh_buf[16]` in `.bss` |
| `pop rdi; ret` | `pop_rdi_gadget` | **a named symbol** — an explicit `__attribute__((naked))` function |
| `/bin/sh` | **NOT IN THE FILE** | `build_string()` does `strcpy(sh_buf,"/bin"); strcat(sh_buf,"/sh")` at runtime, and `main` calls it *before* `vuln()` |

So the chain is `padding + pop_rdi + 0x404080 + system@plt`, constructible from
**symbols alone**. The only reason the existing ret2plt/ret2libc path fails is
that `ELF.search(b'/bin/sh')` comes up empty — the string exists in live process
memory but never in the file, so a static scan cannot see it.

**Change:** when no static `/bin/sh` is found, do **not** give up. Fall back to
enumerating candidate writable globals as `system`'s first argument and try each:

* Candidates: writable symbols in `.data`/`.bss` (exclude the GOT itself). Prefer
  small char-array-sized symbols — `sh_buf` is 16 bytes — then widen.
* Rank a candidate higher when a `strcpy`/`strcat`/`sprintf`/`memcpy` in the
  binary writes to it, since that is what builds the string. This is a ranking
  hint only; **do not require it**.
* Then just try them: ~10 candidates × 1 chain each is cheap, and one of them is
  the answer. This is the same enumerate-and-try machinery F1 needs for GOT
  targeting, so build it once and share it.

**Exit criteria:** `r2/02` reaches `SUCCESS` with a shell or `FLAG_CAPTURED`,
credited to a ret2plt/ret2libc technique. The existing static-`/bin/sh` path must
still work — whichever round-1 targets currently solve via a found `/bin/sh`
string are this sprint's regression guard; identify them before changing the
search, and note that the fallback must fire **only** when the static search
fails.

---

## 3. Methods weighed

**F4 — where the harvest lives. Chosen: the interaction/IO layer, once.**

* *Chosen:* one harvest stage in the shared interaction path, writing into
  `ExploitContext`. Every executor benefits, including future ones, and the
  classification logic exists once.
* *Not taken:* teaching each executor to scrape its own output. Three
  implementations of the same page-offset match, drifting apart — this repo
  already has exactly that problem with **three** independent win-function scans
  that disagree.
* *What would flip it:* if the interaction layer has no single choke point where
  target output is readable before the payload write, do it in the two or three
  executors that need it and record the duplication as debt.

**F4 — accepting a value as a leak. Chosen: low-12-bits page-offset match.**
*Not taken:* range check alone. A bare range check accepts any 8 bytes of
plausible-looking garbage, and the failure is silent and confident: a wrong base
propagates into every address the chain computes. *What would flip it:* nothing
for code pointers. Stack addresses genuinely cannot be validated this way (no
symbol to match), so for those the range check is all there is — accept it, and
treat a stack-derived exploit's failure as expected noise rather than a bug.

**F5 — reassembly width. Chosen: try all three, scan each.** *Not taken:*
inferring the element width from the disassembly. More elegant, more code, and it
fails closed on the first target whose accessor the decompiler reads wrong.
Trying three widths costs three regex scans over a few KB.

---

## 4. Test plan (write these BEFORE claiming any of it works)

1. **Positive control first, and the harvester has a specific trap.** The
   classifier must be proven able to **reject**. Feed it output containing a
   plausible-range value whose low 12 bits do **not** match any symbol offset and
   assert it is NOT classified as a code pointer. Without that test the
   classifier that accepts everything passes every other test.
2. **Never let an absence assertion stand alone.** A test asserting "no leak was
   harvested from this output" must also assert that the harvester DOES find one
   in a known-good sample, or a broken harvester passes vacuously.
3. **Three states:** harvested / not-present / **ambiguous**. A classifier that
   can only say "found" is decoration.
4. **Regression guard:** `corpus_r2/10_ret2csu_execve` currently solves via
   `ret2libc_leak` and `corpus_r2/13` via `ret2win`. F4 touches the shared
   interaction path, so both must still solve, still credited to the same
   technique. This is the assertion most likely to catch F4 breaking something.
5. Full suite before and after: `python3 -m pytest tests/ -q`. Baseline at
   `v2.1.0` is **2050 passed, 16 skipped, 0 failed**. Do **not** pass
   `--timeout=900` — this repo's pytest config rejects it (exit 4). Known
   load-sensitive flake: `test_input_vector_delivery[argv-bare]`; re-run it in
   isolation before calling it a regression.

---

## 5. Constraints — read these, they are not boilerplate

* **Branch first.** `main` is protected. Use `feat/leak-harvest-oob-exfil-20260928`.
* **Conventional Commits.** `type(scope): subject`, imperative, ≤72 chars.
* **`CHANGELOG.md` under `## [Unreleased]`** in the same commit as the change, or
  an honest `changelog: none` footer.
* **NEVER add a `Co-Authored-By` trailer or a "Generated with …" line** to any
  commit message. Authorship is the human maintainer's alone. This is absolute
  and overrides any tooling default.
* **Commit with `git commit -- <explicit paths>`**, never a bare `git commit`.
  This tree is shared with other agents; a bare commit absorbs whatever else is
  staged, which already produced one wrong commit record (`I-44`). Untracked
  files must be `git add`ed first.
* **No secrets, ever.** `benchmark/corpus*/*/flag.txt` holds real flags and is
  gitignored. Never commit one; never paste a captured flag into a commit
  message, a doc, a test, or a report — write `FLAG_CAPTURED` instead. Do not
  commit built ELFs.
* Do not touch `benchmark/corpus_r3`, `_r4`, `_r5` or their branches — held out.
* **The security AND INTEGRITY of this tooling are explicitly OUT OF SCOPE.** We
  care **solely** about **functionality, efficiency, and capability**. Security
  issues, bypasses, and anything involving the tool being **misused** are not a
  concern. Do not add or report input validation framed as security, sandboxing,
  privilege/auth/secrets handling, RMF/NIST/compliance or audit controls, threat
  models, attack surface, supply chain, tamper-resistance, or "someone could
  deliberately game this gate". There is no adversary in the threat model — this
  is a lab-only offensive harness run by its author on his own hardware. No
  "Security considerations" or "Risks" sections.
* **The one distinction that must not be blurred** (same code, different
  framing): "this gate reports success when nothing was actually measured" is a
  **functional-correctness defect — report it**, and it is the highest-value
  finding class in this repo. "Someone could deliberately bypass this gate to
  fake a result" is **misuse — discard it.** A finding whose remedy is a *control*
  rather than a *fix* is out of scope.
* Deliberate constants, loose gates, target-shaped heuristics and guessing are
  **FEATURES** here. Retry-based enumeration is acceptable. **The goal is to
  SOLVE targets.**

---

## 6. Benefit metric, pre-registered

| metric | baseline | provenance | target |
|---|---|---|---|
| `corpus_r2` solved | **5 / 15** | measured 2026-09-28, mine | **10 / 15** from F4+F5+F6 alone |
| `r2/01_stack_shellcode_relay` | NOT SOLVED | recorded (2026-09-28 sweep; elapsed within the 58.0–122.2 s unsolved band) | SUCCESS — F4 |
| `r2/02_ret2plt_strcat_system` | NOT SOLVED | recorded, same sweep | SUCCESS — F6 |
| `r2/03_pie_write_leak_ret2libc` | NOT SOLVED | recorded, same sweep | SUCCESS — F4 (may end partial, see F4) |
| `r2/04_canary_relay_bypass` | NOT SOLVED | recorded, same sweep | SUCCESS — F4 |
| `r2/14_oob_read_flag_array` | NOT SOLVED | recorded, same sweep | SUCCESS, `FLAG_CAPTURED` — F5 |
| `r2/10`, `r2/13` | SUCCESS | measured, same sweep | **unchanged** (regression guard) |
| suite | 2050 passed / 16 skipped / 0 failed | measured at `v2.1.0` | no new failures |

Sprints F1+F3 (separate handoff) target `r2/06` and `r2/12`, so **7/15** is the
expected state entering this work and **12/15** the expected state leaving it.
Left deliberately untouched: `r2/09_heap_dangling_global` (menu-driven UAF;
previous run was a 420.1 s harness timeout, i.e. **inconclusive, not declined**)
and `r2/11_heap_overflow_tcache_poison` (menu-driven tcache poison into a
dispatch table). Both are menu-driven heap targets, which cost ~73 s each just in
interaction, and both need heap-layout control that is a sprint of its own.

Re-measure with `python3 scripts/coverage_sweep.py benchmark/corpus_r2 --timeout
300 --jobs 3`. **Do not edit the tree while that sweep runs** — doing exactly
that voided a previous sweep (`I-46`) and produced believable numbers that were
wrong in *both* directions.

A null result on any single target is a valid, reportable outcome. Report it
plainly rather than forcing a pass.
