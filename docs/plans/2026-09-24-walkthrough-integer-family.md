# Walkthrough family: integer (full 0-to-pwn)

Status: PLAN — written before implementation, per the repo's plan-review rule
Date: 2026-09-24
Branch: `feat/walkthrough-integer-family-20260924`, based on
`feat/walkthrough-engine-20260923` (`cfaa24e`)
Implements: `docs/plans/2026-09-24-walkthrough-families-fmtstr-heap-integer.md`
(the "Integer (full, normal priority)" section)

## Goal

Add `supwngo/exploit/walkthrough/families/integer.py` with two routes —
**overflow/truncation into a size computation** and **negative indexing** — so
integer-bug targets stop falling through to guided triage, and so the emitted
walkthrough teaches the *arithmetic identity* rather than a crash recipe.

Measured starting state on this branch (`collect_facts` + `propose_routes`,
corpus rebuilt from source):

| target | winning route today | score |
| --- | --- | --- |
| `10_int_overflow` | `guided triage` | 0.15 |
| `14_negative_index` | `guided triage` | 0.15 |

Both fall to triage for the same measured reason: `_resolve_offset`'s GDB cyclic
probe writes `cyclic(400)` straight into the target, both targets read a
**decimal number** with `scanf("%d")` first, the pattern fails that `scanf`, the
program returns without overflowing, and `MeasuredOffset.probe_failed` comes back
`True`. `stack_bof` then correctly *refuses* to teach ret2win (score 0.3, not
applicable) because it has no evidence the return address is reachable. Nothing
is wrong with that logic — it is the family that understands the arithmetic that
is missing.

## Ground truth established before writing any code

Everything below was measured on this machine against the freshly built corpus,
not inferred. These are the values the family must reproduce and the walkthrough
must teach.

### `10_int_overflow` — truncation into a size

`vuln()` at `0x401210`, `objdump -d --disassemble=vuln -M intel`:

```
401264: mov    eax,DWORD PTR [rbp-0x54]   ; len_in, the scanf("%d") destination
401267: cmp    eax,0x40                   ; guard: bound = 64
40126a: jle    40127d                     ; SIGNED branch -> upper bound only
40127d: mov    eax,DWORD PTR [rbp-0x54]
401280: mov    BYTE PTR [rbp-0x1],al      ; the cast: 32 bits -> 8, sign discarded
4012a6: movzx  edx,BYTE PTR [rbp-0x1]     ; the truncated byte becomes the count
4012aa: lea    rax,[rbp-0x50]             ; destination buffer
4012b6: call   4010c0 <read@plt>          ; read(0, rbp-0x50, edx)
```

Instruction-level demonstration of the wrap (GDB breakpoints at `0x401267`,
`0x401280`, `0x4012b6`, input fed through a FIFO so stdio cannot slurp it):

| `len_in` | guard `eax` | `al` after the cast | `rdx` at `call read` |
| --- | --- | --- | --- |
| 8 | 8 | 8 | 8 |
| 65 | 65 | — guard rejected it — | — |
| -1 | -1 (`0xffffffff`) | 255 | **255** |
| -191 | -191 (`0xffffff41`) | 65 | **65** |
| -256 | -256 (`0xffffff00`) | 0 | 0 |

So the **identity** the walkthrough teaches, stated exactly:

> an input `n` is exploitable iff `n <= 64` (it passes the signed guard) **and**
> `(n & 0xFF) > 64` (the truncated byte still overruns the 64-byte buffer).

`-256` shows the second clause is not automatic; `-191` is the boundary case
(`0xffffff41 & 0xFF == 65`); `-1` maximises the count at 255. Reaching the saved
return address needs `(n & 0xFF) >= 96`, i.e. `n` in `[-160, -1]`.

`OFFSET = 88`, and it is **derivable statically**: `read()`'s destination is
`rbp-0x50`, the prologue is the textbook `push rbp; mov rbp,rsp`, so the saved
return address is at `rbp+8` and the distance is `0x50 + 8 = 88`. Confirmed
independently by a shaped cyclic probe: faulted value `0x6161617861616177`,
`cyclic_find(...) == 88`.

`win()` is at `0x4011f6`. Verified end to end:
`-1\n`, wait for `Data: `, then `b"A"*88 + p64(0x4011f6)` → the win path runs.

### The stdio trap, which only literal execution finds

This target cannot be exploited with a single write, and the two failure modes
are *different* and both silent:

- `gdb ... -ex 'run < payload_file'` → the process **exits 0 and prints `done`**.
  `scanf` fills glibc's stdin buffer from the file, the file hits EOF, and the
  raw `read(0, buf, 255)` returns 0. No overflow, no crash, no diagnostic.
- `process(...).send(b"-1\n" + payload)` in one call → the process **hangs** at
  `Data: `. `scanf`'s buffered read consumed the whole 99 bytes off the pipe, so
  the raw `read` has nothing left and blocks.

Only `send(b"-1\n")` → `recvuntil(b"Data: ")` → `send(payload)` works, because
then the payload is still in the pipe when the raw `read` runs. Consequences for
this family:

1. every step that drives the target must be **two-phase and prompt-synchronised**;
2. the offset probe cannot use `run < file`; it uses GDB with stdin on a **FIFO**
   written in two phases (verified: `OFFSET 88`);
3. this is a TROUBLESHOOTING entry with two distinct symptoms, not one.

### `14_negative_index` — negative indexing

`vuln()` at `0x401b2f`:

```
401bed: mov    eax,DWORD PTR [rbp-0x54]        ; idx, the scanf("%d") destination
401bf0: cmp    eax,0x7                          ; guard: bound = 7
401bf3: jg     401c0f                           ; SIGNED -> no lower bound at all
401bfc: cdqe                                    ; sign-extend eax -> rax
401bfe: mov    QWORD PTR [rbp+rax*8-0x48],rdx   ; arr base rbp-0x48, scale 8
401c03: mov    eax,DWORD PTR [rbp-0x50]         ; the guard variable
401c06: cmp    eax,0x1337
401c20: call   401b15 <win>
```

`arr` base displacement `-0x48`, guard slot `-0x50` ⇒ the index that lands on the
guard slot is `(-0x50 - -0x48) / 8 = -1`, and the value it must carry is
`0x1337`. Both **derived from the disassembly**, not guessed.

GDB at the store (`0x401bfe`), addresses compared to each other rather than
asserted absolutely (the first wave's leaked-byte lesson — these are ASLR'd):

| `idx` | `rax` at the store | effective target | vs `arr` base | vs guard slot |
| --- | --- | --- | --- | --- |
| 0 | 0 | `arr+0` | equal | +8 |
| -1 | `0xffffffffffffffff` | `arr-8` | -8 | **equal** |
| -3 | `0xfffffffffffffffd` | `arr-24` | -24 | -16 |
| 8 | — guard rejected it — | | | |

`idx=8` being rejected is worth teaching in its own right: the *upper* bound is
enforced, so the saved return address — which would need
`(rbp+8 - (rbp-0x48))/8 = 10` — is unreachable. This route is a single
attacker-chosen qword written before the array, and nothing more. Verified end to
end: `idx=-1, val=0x1337` → win path; `idx=0, val=0x1337` → `flag=0, try again`.

## Approach — two options weighed

### Option 1 (CHOSEN): detect the arithmetic in the family, from `objdump`

`families/integer.py` owns a small disassembly analyser, `_analyse(path,
function)`, that runs `objdump -d --disassemble=<vuln> -M intel` once (cached by
`(path, mtime, function)`) and returns an `IntegerAnalysis` with, for each site:
the attacker-controlled stack slot, the guard instruction + its bound + whether
its branch is signed, the truncating cast or the `cdqe`, the sink, the buffer
displacement, and the prompt string addresses — each with its **address and
literal instruction text**, so every constant the family emits is `MEASURED`
against a real instruction and carries the `objdump` command that shows it.

Taint link that keeps this specific: a site only counts when the guarded value is
loaded from a stack slot that was passed as the destination of a `scanf`-family
call. That is what separates target 14's real bug from its `for (i=0;i<8;i++)`
initialisation loop, which matches every other part of the pattern (`cdqe`, same
scaled store, a signed compare against 7) and whose counter is never a `scanf`
destination.

- **For:** `facts.py` — the single, shared seam, and the file the concurrent
  fmtstr family is most likely to also touch — stays untouched, so the merge is
  confined to two trivially-additive lines. No subprocess added to
  `collect_facts`, so every other target pays nothing. The analysis degrades to
  "no sites → `propose` returns `None`" on a non-ELF, which is exactly what the
  existing hand-built test fixtures are, so no existing test changes behaviour.
- **Against:** `objdump` runs in `propose()`, i.e. for every binary even when the
  family will abstain (~50 ms, cached); and a second family that wanted the same
  facts would have to import them from here rather than from `facts.py`.

### Option 2 (NOT TAKEN): collect integer facts in `facts.py`

Add `TargetFacts.integer_sites`, populated in `collect_facts`, matching how
`gadgets`/`win_functions`/`frame_size` are collected today.

- **For:** architecturally the stated convention — `facts.py` is documented as
  the single seam to the rest of supwngo, and families are supposed to read
  normalised facts rather than shell out themselves. Cheaper if a second family
  ever needs the same data.
- **Against:** it puts ~250 lines of integer-specific x86 pattern matching into
  the file every other family and both concurrent agents depend on, for one
  consumer; and it is the highest-conflict file in the tree right now.

**What would flip the decision:** a second family needing the same arithmetic
facts (a heap family reasoning about a wrapped `malloc` size is the obvious
candidate), or the analyser needing a value `objdump` cannot give — a real taint
result, or anything requiring the `Binary`/pwntools object. Either of those makes
Option 2 correct, and the move is mechanical: `_analyse` becomes
`_collect_integer_sites(binary, ...)` in `facts.py` and the dataclasses move with
it. I am choosing the low-merge-risk placement for one consumer now and naming
the trigger to revisit it.

## Routes, scores, and abstention

| route | score | why that number |
| --- | --- | --- |
| `integer truncation into a size computation` | **0.96** | above `ret2plt` (0.95) and tying nothing. On a target of this shape the generic offset probe feeds `cyclic` bytes to `scanf("%d")`, which rejects them, so a code-reuse walkthrough opens by **measuring nothing** — the arithmetic bypass is the precondition for the overflow existing at all. Raised from a first-draft 0.88 after review: 0.88 tied SROP, and ties resolve on `_families()` order, which is not a justification. |
| `integer truncation`, overflow proven but no return target | 0.45 | PIE on, or no fixed-address win function. Teaches the arithmetic, the offset and control of the return address with a marker, then hands the control-flow half to the code-reuse routes. Below every complete route on purpose: half an exploit should lose to a whole one. |
| `negative index (out-of-bounds write before the array)` | **0.97** | a single deterministic qword write whose landing site and required value are both derived from the disassembly; no offset, no gadgets, no leak, nothing to align, and the program's own branch is the oracle. Raised from 0.90, which tied `ret2shellcode`. |
| `negative index`, landing site not characterised | **not applicable** (0.0) | the primitive is real and measured, but nothing was found that reads the slot it reaches, so the route cannot claim an outcome. Shipped as a `Rejection.UNMET_PRECONDITION` with `becomes_viable_if` naming the manual frame-characterisation workflow — **not** as an applicable low-scoring route, because a selected walkthrough must contain a complete final exploit and this one has none. First-draft 0.55 withdrawn after review. |
| `integer truncation`, count cannot reach the return address | **not applicable** (0.0) | `STRUCTURAL`: real out-of-bounds write, just not that far. |
| `integer truncation`, canary in the vulnerable function | **not applicable** (0.0) | `STRUCTURAL`: the write crosses the canary on the way. Judged from the function's own instructions, not the image-wide verdict. |
| either route, no frame-pointer prologue | **not applicable** (0.0) | `UNMET_PRECONDITION`: rbp-relative displacements are measured from a moving anchor, so no offset is derivable and claiming one would be guessing. |

`propose` returns `None` — abstains — whenever no site is found, which includes
every non-ELF fixture, every target with no `scanf`-fed signed guard, and 32-bit
binaries. Per the registry docstring, a family with nothing specific to say says
nothing; "no integer overflow detected" is binary-independent filler.

## Files touched

| file | change |
| --- | --- |
| `supwngo/exploit/walkthrough/families/integer.py` | new: the analyser, `propose`, `build`, both routes |
| `supwngo/exploit/walkthrough/families/__init__.py` | +1 import, +1 `__all__` entry (kept additive for the concurrent fmtstr merge) |
| `supwngo/exploit/walkthrough/registry.py` | `_families()`: +1 import, +1 list entry |
| `supwngo/cli.py` | one line: the `--family` help string's list of families |
| `tests/test_walkthrough_integer.py` | new: unit + literal-execution tests |
| `CHANGELOG.md` | `[Unreleased] / Added` |
| `docs/plans/2026-09-24-walkthrough-integer-family.md` | this plan |

Nothing in `facts.py`, `common.py`, `model.py` or `render.py` changes. The
`OFFSET` constant is fed by handing `common.base_constants` a
`dataclasses.replace(facts, offset=...)` copy — a derived `MeasuredOffset` for the
truncation route, `None` for the negative-index route (which needs no offset, and
whose walkthrough must therefore not emit an `UNKNOWN OFFSET` fact whose
`resolved_by` step it does not contain).

## Step plan

Truncation route: `preflight` (shared) → `arithmetic` → `wrap` → `offset` →
`fire`. Negative-index route: `preflight` → `arithmetic` → `landing` → `fire`.

- `arithmetic` is static and always runnable: it re-disassembles the claimed
  guard/cast/store addresses with `disasm(elf.read(addr, n), vma=addr)` to prove
  the instructions are really there, then enumerates the exploitable input set in
  Python and prints the identity. No process, so it works even when the target
  cannot be run. The re-disassembly lives in a **helper** (`verify_instructions`,
  driven by a generated `CLAIMS` list) rather than inside the step, and the helper
  is also the first statement of `final_exploit`: `render.py` runs `exploit()`
  directly for a complete run and executes no steps at all, so a check only the
  diagnostic path performs is a check the real run skips. It compares mnemonics
  only, because capstone prints `cmp eax, 0x40` where objdump prints
  `cmp eax,0x40` and an exact text match would fail on a perfectly good binary.
- `wrap` / `landing` is the concrete demonstration: GDB, breakpoints at the
  measured addresses, input through a FIFO, printing the value *before* and
  *after* the cast (or `rax` and the effective address at the store), run twice —
  once benign, once with the wrap value — so the reader sees the same instruction
  produce two different numbers.
- `offset` (truncation route only) is the two-phase FIFO cyclic probe, compared
  against the statically derived 88.
- `fire` is the two-phase prompt-synchronised exploit.

`landing` compares addresses to each other and never asserts an absolute stack
address; that is the direct lesson of the first wave's false leading-byte claim.

## Test strategy

Rendering is not verification. The three first-wave defects this has to be
immune to were a `NameError` on an undeclared constant at the reader's first
command, a route made unreachable by a wrong symbol-type filter, and a false
claim about an observed value — none visible in review.

1. **Literal execution, both targets.** Generate the walkthrough, write it to a
   temp file, and run `python3 wt.py steps`, then every step by number, then the
   full exploit — as subprocesses, asserting exit status per step. This is the
   test that would have caught all three.
   Every subprocess carries a hard `timeout=`: the defect this suite most needs to
   catch (a collapsed two-phase send) fails by *hanging*, so a test without a
   timeout would not report it, it would become it.
2. **No self-scoring.** `b"flag" in out` is not a verdict anywhere, and an AST
   check asserts no *executable* string literal in either generated script even
   mentions one. Each fire step is judged by a differential against **two**
   controls, not one — a benign input and one the target's own bounds check
   refuses:
   - target 14: benign `idx=0` prints `flag=0, try again`; `idx=8` prints
     `out of range`, which the benign run never prints, so a single-control
     comparison would score the bounds check *working correctly* as a successful
     exploit. Only output absent from the union of both controls counts. All three
     runs send the same value and differ only in the index.
   - target 10: benign (`len=8`) ends in `done`; `len=65` prints `too long`. The
     exploit run must produce a line neither control produced. Control transfer is
     proven by output the normal path cannot produce, without asserting anything
     about content.
   The test for this checks the **call sites** by AST (every `differential(...)`
   is passed a list of ≥ 2 controls), not the presence of the helper: the first
   draft of the test only asserted `"differential([" in text`, which passed
   against a deliberately single-control mutation. That is a fifth
   test-that-cannot-fail, found and fixed before commit.
3. **Tests that can fail.** Every new test is run against deliberately broken
   code before being committed and the failure is recorded in the report: the
   accept-edge inverted, the derived index off by one, the `scanf`-taint check
   removed, the two-phase send collapsed into one, the recommended input pushed
   past the bound, the differential reduced to one control, `GUARD_MAX` described
   as a buffer size, and the canary verdict taken from the image instead of the
   function. A test that passes both ways is deleted or sharpened.
4. **Preflight semantics unchanged:** digest mismatch warns, a failed instruction
   verification refuses. Note what shared `common.preflight_step` does and does
   not do: it verifies only the declared `G_*` gadget constants, **not** every
   instruction this family quotes. That is why the integer verifier is its own
   helper (see the step plan) rather than an assumed property of preflight.
5. **Regression guards:** the loop counter in target 14 must not be reported as a
   site (the `scanf`-taint discriminator); `propose` must abstain on every
   existing hand-built fixture; `propose_routes` stays side-effect-free with the
   analyser's cache in play.

## Risks

- **`objdump` absent.** The analyser returns no sites and the family abstains, so
  the target falls back to today's behaviour (triage). Degradation, not breakage.
- **A different compiler changes the instruction sequence.** The analyser matches
  the *shape* (signed guard on a `scanf` slot, then a narrowing store or `cdqe`
  plus a scaled store), not fixed addresses, and everything it emits is checked
  again by `preflight` and re-disassembled by `arithmetic` on the reader's
  machine. If the shape is not found, the family abstains.
- **`-O2` inlining.** `vuln()` may not survive as a symbol; the family abstains.
  The corpus is built at the documented flags, so this is a future concern.
- **Scoring change reroutes another target.** The new routes only exist when a
  site is found, so no target that has none can be affected. A test asserts the
  five already-validated corpus targets keep their current family and route.

## Out of scope

Heap (a separate module, detection-floor scope) and format string (another agent,
in progress). No changes to the benchmark corpus, its sources, or the harness.

## Independent review — NOT-APPROVED, and what changed

Reviewed at the same tier by `gpt-5.6-sol` (`model_reasoning_effort=xhigh`,
read-only sandbox). Verdict **NOT-APPROVED**: 8 blocking, 2 non-blocking. Every
blocking issue is resolved below before any code was kept.

| # | Blocking issue | Resolution |
| --- | --- | --- |
| 1 | The detector proved signedness but not *control flow or dataflow*: which edge reaches the sink, whether the truncated value reaches `read`'s count argument, whether the *stored value* is attacker-controlled, whether the landing slot is the one later compared, whether the satisfying branch reaches `win`. | `_SIGNED_BRANCHES` now carries `accepts_on_taken`, and `Guard.accept_at` is the accepting edge's address; `_find_truncation` / `_find_negative_index` scan **only from there**. `_find_size_use` requires the narrowed slot to be loaded into *that sink's own* count register (`_SIZE_SINKS` is a sink→register map: `read`→RDX, `malloc`→RDI) and the destination to be a negative rbp slot. `_find_negative_index` traces the stored value back to a `scanf` slot or reports `value_slot=None`. `_find_landing` requires a **negative** index, the compared immediate, and `_reaches_call` following the *equal* edge through unconditional jumps to the win call. Truncation additionally requires `count >= OFFSET + 8`. |
| 2 | `buf[64]` cannot be established from `objdump`; the guard immediate 64 is not the object's capacity. | The constant is renamed `GUARD_BOUND`→**`GUARD_MAX`**, its evidence states in so many words that it is the bound the *check* enforces and not a claim about the destination's size, and every exploitability threshold uses the **derived** `OFFSET + 8` instead. A test asserts `GUARD_MAX` is never described as a buffer size. |
| 3 | Missing full-exploit preconditions: PIE, canary, a usable control target, a count large enough. | Canary in the function → non-applicable `STRUCTURAL`. `count < OFFSET + 8` → non-applicable `STRUCTURAL`. PIE on or no win function → the 0.45 control route, which proves control of the return address with a marker and hardcodes no address. All GDB breakpoints are `break *(vuln+N)`, symbol-relative, so they are correct under PIE; a test asserts no absolute `break *0x...` survives. |
| 4 | 0.88 tied SROP, 0.90 tied `ret2shellcode`, both lost to `ret2plt` (0.95) — and ties resolve on `_families()` order, while `ret2plt` checks ingredients rather than deliverability. | 0.96 and 0.97, tying nothing, with the measured justification recorded in a module comment: the generic probe feeds `cyclic` bytes to `scanf("%d")` and measures nothing on these targets. `integer` is inserted into `_families()` before `stack_bof`. |
| 5 | The 0.55 "landing site not characterised" route would win against triage and then leave `build` with no honest exploit. | Made non-applicable (score 0.0, `Rejection.UNMET_PRECONDITION`, `becomes_viable_if` naming the manual workflow). The untested build variant and its probe step were **deleted rather than shipped**. |
| 6 | The plan's claim that shared preflight rechecks every emitted instruction was false (`common.preflight_step` verifies only declared `G_*` gadgets), and a complete run bypasses steps entirely (`render.py:552`). | `verify_instructions(CLAIMS)` is a generated helper, invoked by the `arithmetic` step **and** as the first statement of `final_exploit`. The plan text above is corrected. |
| 7 | Target 14's oracle had a false-pass path: `idx >= 8` prints `out of range`, absent from the benign run. And the literal subprocesses had no hard timeout, though the plan itself identifies the collapsed-send mutation as a *hang*. | `differential(controls, exploited)` takes a **list**; every fire step and both `final_exploit`s run a benign *and* a refused control and require output absent from their union. `gdb_probe` is deadline-bounded and every test subprocess carries `timeout=`. |
| 8 | Target 14's normalized facts are wrong and the plan left them alone: `_derive_canary` reports a canary because `__stack_chk_fail` is linked into the static image, and `_Unwind_*` matches the substring win-function detector. | Corrected **locally, in this family, without touching `facts.py`**: `_CANARY_RE` checks the vulnerable function's own instructions and `_corrected_protections` turns the canary claim off — only ever off, only on function-local evidence — with the reason recorded in `provenance`. `_NOT_WIN` plus a leading-underscore filter excludes `_Unwind_*` from `_pick_win`, and the negative-index route additionally requires its win function to be *called from the satisfying edge inside `vuln()`*, which excludes them structurally. |
| 9 (non-blocking) | Assert directly that the negative-index walkthrough has no `OFFSET` fact or executable reference. | Done, as a test over the rendered script's code lines. |
| 10 (non-blocking) | Provenance overlabelling: addresses and immediates are `MEASURED`, but index `-1`, offset `88` and arithmetic ranges are `DERIVED`. | Already correct in the implementation; now pinned by a test that checks the confidence of each named constant. |

Issue 8's correction produced a visible contradiction the review did not
anticipate: the *generated* preflight prints `Canary True` because it calls
pwntools' `elf.canary` at runtime, which is image-wide. Rather than disagree
silently with a line the walkthrough itself prints, the family emits an extra
protection verdict naming the discrepancy and the reason — and the reader gets a
better lesson than the corrected flag alone: a canary is emitted per function,
and a tool's image-wide answer is the union of every function's.

## Defects found by literal execution that review did not

1. **The generated script for target 14 did not parse.** `_retaddr_note` returned
   a two-line string interpolated into an f-string that then went through
   `dedent_code`, so the second line arrived at column zero:
   `IndentationError: unindent does not match any outer indentation level at line
   748`. Caught by `render.py`'s own compile check on the first generation, not by
   review of the same code. Fixed by making the helper return exactly one
   statement, with a docstring saying why.
2. **Preflight was handed the uncorrected facts** in both builders, so the
   corrected canary verdict reached the walkthrough header while the step that
   prints protections still used the raw ones.
3. **`common.protection_verdicts` takes `TargetFacts`, not `ProtectionFacts`** —
   an `AttributeError` at generation time, invisible until run.
4. **The differential test could not fail.** `assert "differential([" in text`
   passed against a mutation that reduced both call sites to a single control.
   Rewritten to check the call sites by AST. Found by running the mutation, which
   is the only reason it was found at all.
No weakening of any verification path.
