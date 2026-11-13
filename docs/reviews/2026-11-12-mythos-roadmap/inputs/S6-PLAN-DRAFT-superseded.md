# S6 — Detector depth (RT-08, RT-09, RT-10)

**Date:** 2026-11-12
**Sprint:** S6 of the 2026-09-26 retest gap-closure effort
**Parent plan:** `docs/plans/2026-11-11-retest-gap-closure-plan.md`
**Band:** P2 (detector depth)

## Goal / exit criterion (from the tracker)

> report flags the known vuln on ≥2 of the 3 zero-finding targets; pwn lists SROP
> for sick_rop; heap-analysis sees ta_alloc

Three independent detector-depth gaps, each with its own revert surface:

| Item | Symptom (reproduced 2026-11-12, current tree) | Exit |
|------|-----------------------------------------------|------|
| RT-08 | `pwn sick_rop` lists STACK_PIVOT + VARIABLE_OVERWRITE only; **no SROP** | SROP appears among viable strategies for sick_rop |
| RT-09 | `heap-analysis auth-or-out` → `Allocation sites: 0, Free sites: 0, Vulnerabilities: 0` | ≥1 alloc site (`ta_alloc`) detected on auth-or-out |
| RT-10 | `report` → `Findings : 0` on sick_rop, auth-or-out, bon-nie-appetit (each has a known vuln) | report surfaces a real finding on ≥2 of the 3 |

## Baselines (reproduced against the real HTB binaries this session)

Captured to `/tmp/s6-baseline/` (raw CLI dumps, scratch — not committed):

- **RT-08** `pwn tests/htb-targets/organized/sick_rop`: recommended STACK_PIVOT (65%),
  plus VARIABLE_OVERWRITE (50%). Key-gadget table shows `syscall` @ 0x401014
  (`syscall; ret`), `leave; ret`, `ret`; **`pop rax/rdi/rsi/rdx` all NOT FOUND**.
  SROP not listed.
- **RT-09** `heap-analysis tests/htb-targets/organized/auth-or-out`: `Allocation sites: 0`,
  `Free sites: 0`, `Vulnerabilities: 0`. Binary defines `ta_alloc` (T@0x105d),
  `ta_calloc` (T@0x1108), `ta_free` (T@0xc71), `alloc_block` (t@0xd79),
  `ta_num_free` — all in-binary `.text`; PLT imports have **no** malloc/calloc/free.
- **RT-10** `report` on all three: `Findings : 0` each.

## RT-08 — SROP gate too narrow

### Root cause (verified against disassembly)
`supwngo/exploit/strategy.py:394` `_check_srop_viable`:
```python
def _check_srop_viable(self) -> bool:
    if not self._gadgets_analyzed:
        return self._is_static
    return self._has_sigreturn and self._has_syscall
```
`_has_sigreturn` is set **only** from the presence of a `pop rax` (x64) / `pop eax`
(x86) gadget (`strategy.py:367/370`). sick_rop has no `pop rax`, so
`_has_sigreturn = False` → SROP is gated out even though it is *the* canonical
technique (the challenge is literally "sick ROP").

sick_rop's disassembly confirms the real rax-control mechanism: `read` @ 0x401000
(`mov $0x0,%eax; … syscall`) and `write` @ 0x401017 (`mov $0x1,%eax`), with a
`syscall; ret` gadget @ 0x401014 and no writable `.data`/`.bss` in headers. The
classic SROP-via-sigreturn on this binary sets `rax = 15` (`SYS_rt_sigreturn`) by
controlling how many bytes `read()` returns (its return value lands in rax), then
chains `syscall; ret`. That mechanism is a `syscall; ret` gadget, not a `pop rax`.

### Design (minimal, low-risk)
Widen the gate to accept the syscall-return-value path, which is exactly what
`_has_syscall_ret` already captures (`strategy.py:360`):
```python
def _check_srop_viable(self) -> bool:
    if not self._gadgets_analyzed:
        return self._is_static
    if not self._has_syscall:
        return False
    # rax=15 can be set by a pop-rax/pop-eax gadget (_has_sigreturn) OR, as in the
    # canonical sick_rop solution, by chaining a `syscall; ret` gadget so a read()'s
    # return value (bytes read) lands in rax.
    return self._has_sigreturn or self._has_syscall_ret
```
`_build_srop_strategy` (`strategy.py:579`) already degrades confidence to 0.6 when
`_has_sigreturn` is false and its steps already say "Set rax = 15" — so no
confidence/priority change is needed. Enrich only the `notes`/`steps` to name the
rax-via-syscall-return method when `_has_sigreturn is False and _has_syscall_ret is True`,
so the suggestion stays honest and actionable.

### Why this does not over-trigger
SROP requires a syscall + a way to set rax=15 + ~248 bytes of controlled stack.
The widened gate still requires `_has_syscall`; it only additionally accepts a
`syscall; ret` gadget as the rax path. A binary with `syscall; ret` but no overflow
simply gets SROP listed at 0.6 confidence (never recommended over a stronger
strategy), which is an acceptable *suggestion* for a suggestion engine. All flags
(`_has_syscall`, `_has_syscall_ret`, `_has_sigreturn`, `_is_static`,
`_gadgets_analyzed`) are initialized in `__init__` (`strategy.py:191-202`), so the
gate is safe before gadget analysis.

### Files touched
- `supwngo/exploit/strategy.py` — `_check_srop_viable` (+ `_build_srop_strategy` notes).

### Tests
- **Hermetic (RED-proof):** construct a `StrategySuggester` over a stub binary
  (static, 64-bit), set `_gadgets_analyzed=True`, `_has_syscall=True`,
  `_has_syscall_ret=True`, `_has_sigreturn=False`, `_is_static=True`; assert
  `_check_srop_viable()` is True (fails on old tree → non-vacuous). A paired case
  with `_has_syscall=False` asserts False (no over-trigger). A case with
  `_has_syscall_ret=False, _has_sigreturn=False` asserts False.
- **Opt-in real-binary:** gated on sick_rop presence — build the full strategy list
  and assert `ExploitApproach.SROP` is among `report.strategies`.

## RT-09 — heap-analysis blind to custom allocators

### Root cause (from subagent trace, verified against the binary)
`heap-analysis` → `supwngo/vulns/heap_advanced.py::AdvancedHeapAnalyzer`. Two fatal
filters in the site finders:
1. **Name-list-only** — `_find_allocation_sites` (`heap_advanced.py:149-157`) matches
   only `{malloc, calloc, realloc, aligned_alloc, memalign, pvalloc, valloc}`;
   `_find_free_sites` matches literally `'free'` (`:220/236`).
2. **Import/PLT-only** — each match is gated on `if alloc_func in self.binary.plt`
   (`:184`) / `if 'free' not in self.binary.plt: return` (`:220`). `self.binary.plt`
   is import stubs only (`core/binary.py:215`); in-binary `.text` allocators never
   appear. auth-or-out's PLT has no malloc/calloc/free, so both finders no-op.

The symbol inventory is **not** the problem: `self.binary.symbols['ta_alloc']` exists
with `.type == 'STT_FUNC'` and `.address` = the `.text` VA (`binary.py:330-342`). The
finders already disassemble every symbol body with capstone and detect `call`
instructions (`heap_advanced.py:171-186`, `225-236`). Only the callee-resolution
step excludes defined functions.

### Design (second target source; existing PLT path untouched)
In both `_find_allocation_sites` and `_find_free_sites`, before the disasm loop,
build a `target_addr -> (callee_name, kind)` map from two sources:
- **existing:** PLT entries whose name is in the libc set (alloc) / `== 'free'`
  (free) → target = `self.binary.plt[name]` (current behavior, byte-for-byte).
- **new:** **defined** function symbols (`sym.type == 'STT_FUNC'`, `sym.address`
  truthy) whose name matches a custom-allocator regex → target = `sym.address`.

In the `call` handler, keep the existing substring test
(`hex(target) in insn.op_str or str(target) in insn.op_str`) — it already resolves
direct calls to defined functions (`call 0x105d` → op_str `"0x105d"` =
`ta_alloc.address`). Classify alloc vs free by which regex matched; populate the
existing `AllocationSite` (callee name into `alloc_func`) / `FreeSite` dataclasses
unchanged (`heap_advanced.py:50-69`).

**Over-match guards (the real risk):**
- alloc regex: `re.compile(r'(?:^|_)(?:x?m?alloc|calloc|realloc|aligned_alloc|memalign|_new)\b|alloc(?:_block|ate)?$', re.I)` —
  tuned to catch `ta_alloc`, `ta_calloc`, `alloc_block` but avoid matching arbitrary
  words containing "alloc". (Final regex to be fixed during implementation against
  the symbol set; keep it a module constant for tunability.)
- free regex: `re.compile(r'(?:^|_)free\b|_free$|^free', re.I)` with an **explicit
  exclusion** of counter/metadata names (`num_free`, `free_count`, `free_list`,
  `n_free`) so `ta_num_free` is not miscounted as a deallocator.
- Only **defined** (`STT_FUNC`, non-zero address) symbols are considered, so a normal
  dynamically-linked binary (allocators are imports, already handled by the PLT path)
  sees no behavior change.
- Default the custom-alloc `size_arg_idx` to arg-0 (`rdi` on x64) since wrapper arg
  order is unknown; size inference (`_find_arg_value`) and null-after-free
  (`_check_ptr_nulled`) remain reusable unchanged.

### Files touched
- `supwngo/vulns/heap_advanced.py` — site-finder callee resolution + two module-level
  regex/exclusion constants.

### Tests
- **Hermetic (RED-proof):** a fake binary exposing `symbols` with STT_FUNC
  `ta_alloc`/`ta_calloc`/`ta_free`/`ta_num_free` + a `read()` seam returning bytes
  whose disasm contains a direct `call` to those addresses, empty `plt`. Assert
  `_find_allocation_sites` yields ≥1 site naming `ta_alloc` and `_find_free_sites`
  yields `ta_free` but **not** `ta_num_free` (fails on old tree; pins the
  over-match guard). *If a fully-hermetic capstone fixture proves brittle, fall back
  to the opt-in real-binary test as the RED-proof and keep a pure-unit test of the
  name-classification helper.*
- **Opt-in real-binary:** gated on auth-or-out presence — `AdvancedHeapAnalyzer(bin).analyze()`
  then assert `len(analyzer.alloc_sites) >= 1` and some site `.alloc_func` starts `ta_`.
- **JSON regression:** once auth-or-out yields non-zero sites, add it to the
  `_CONTAMINATING` set in `tests/test_cli_json_mode_pwnlib_redirect.py` so the
  `heap-analysis --json` single-document invariant stays pinned on it.

## RT-10 — report finds 0 vulns despite known bugs

*(Filled after the report/detector subagent trace returns — pending.)*

Known-vuln shapes to surface:
- **sick_rop:** static, no-canary stack BOF — `vuln()` `read()`s into a stack buffer.
- **auth-or-out:** custom-heap (`ta_*`) — depends on RT-09 feeding the heap detector,
  or a direct custom-allocator misuse finding.
- **bon-nie-appetit:** libc heap-note challenge (malloc/free/read + `edit_order`) —
  heap overflow.
Target the 2 easiest-and-safest (likely sick_rop stack-BOF + bon-nie-appetit heap)
to meet the ≥2-of-3 bar without false positives on clean binaries.

## Out of scope (S6)
- RT-12 (`pwn` sort-by-priority-not-confidence, retest #12) — separate item, not in S6.
- The ret2win `WIN_FUNCTIONS` breadth (retest #3) — separate.
- Full exploit *generation* for these targets — S6 is detector/suggester depth only.

## Risks
- **False positives on clean binaries** — the central risk for RT-09/RT-10. Mitigated
  by: defined-symbol-only + tight regex + explicit exclusions (RT-09); and for RT-10,
  gating findings on concrete structural evidence (not mere import presence).
- **Hermetic capstone fixtures brittle** — fallback to opt-in real-binary RED-proofs.
- **Regression surface** — full `pytest tests/` before commit; known load flake
  (`test_input_vector_delivery … argv-repeated-across-tokens`) passes in isolation.

## Peer review (Daybreak Blue)
*(To be recorded in `docs/plans/2026-11-12-s6-detector-depth-review-daybreak-blue.md`
and resolved here before implementation.)*
