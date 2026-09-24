# Round-1 corpus — ablation audit (necessity, not just reachability)

**Date:** 2026-09-24
**Branch:** `docs/reference-exploits-corpus1-20260923`
**Suite:** `benchmark/ablation/ablate.py` (+ `benchmark/ablation/README.md`)
**Scope:** the 13 valid round-1 targets — 01–10, 12, 14, 15
**Companion:** `docs/reports/CORPUS1-REFERENCE-EXPLOITS-23SEP2026.md` (the chains being ablated)

---

## 1. Headline

| | |
|---|---|
| Strict ablations run | **49** |
| Strict ablations that **blocked** the flag (required result) | **49 / 49** |
| Ablations where the flag still appeared | **0** |
| Positive controls passed | **13 / 13** |
| Exit status | **0** (= every ablation failed to produce the flag) |
| New VOID targets found | **none** |
| Corpus C sources modified | **0** |

**No further round-1 target is measuring less than it claims.** Nothing joins
`11_heap_uaf_leak` and `13_off_by_one` as VOID. For all 13 valid targets, every
step I could meaningfully separate out is load-bearing: delete it and the flag
stops appearing.

Three cases are deliberate **RELAXATION** probes — documented details that turn
out *not* to be required (§4). They are not defects, but one of them corrects an
error in my own earlier write-up and makes target 05 easier than I reported.

## 2. Why this layer was needed

Benign-input controls answer *"is this target trivially solvable?"*. That is
necessary but not sufficient, and the gap is exactly how one of the two round-1
void targets survived:

* `13_off_by_one` — ordinary ≥32-byte input trips `win()`. A negative control
  **does** catch this.
* `11_heap_uaf_leak` — `show(0)` prints the flag from the **live** chunk, so the
  use-after-free was never required. **No negative control catches this**: benign
  input does not get the flag, and a "working" exploit does. Reachability was
  tested; necessity never was.

Ablation closes that gap. The rule it enforces:

> "The exploit works" is not evidence a target is sound.
> **"Nothing less than the exploit works"** is.

## 3. Method — and why a `BLOCKED` verdict can be trusted

The obvious failure mode of an ablation suite is that *all* cases report BLOCKED
because the suite itself is broken. Four properties rule that out:

1. **One parametrised chain per target.** The positive control is that function
   with every step intact; each ablation is the **same function with one keyword
   flipped**. There is no separate "ablated" reimplementation that could be
   wrong on its own.
2. **A positive control runs first, per target.** If the intact chain does not
   produce the flag, the target is reported `NOT MEASURABLE` and its ablations
   are explicitly *not* interpreted, rather than passing silently. All 13 passed.
3. **Fresh random secret per target**, rebuilt through the harness's own
   `run_bench.build_with_secret()`. No verdict can rest on a stale or
   predictable flag constant. (`--no-rebuild` opts out for quick re-runs.)
4. **Every emitted byte is checked.** A `Rec` tube wrapper accumulates everything
   the target prints, so the flag cannot be missed because it scrolled past in an
   earlier read. (This mattered in practice: it broke target 06's index
   discovery during development, because the banner was now part of the captured
   output.)

The sweep holds `corpus_lock`, so it cannot race `run_bench.py` while rotating
binaries and flags.

**Portability proof** (matching the standard R4 set): exported the committed tree
with `git archive` — a clean checkout holds only `<slug>.c` per target — built it
with `benchmark/build_all.sh` inside that clone, and ran the suite **from `/` by
absolute path** and **from `/tmp`**: 49/49 blocked, exit 0, resolving the clone's
own corpus. Every reporting branch in the committed file has been executed,
including the two failure paths (forced on a throwaway copy, then deleted):
flag-still-appears → exit 1, and relaxation-unexpectedly-blocked → exit 1.

## 4. Relaxations — documented details that are NOT required

Reported because the corpus's difficulty notes should be honest about what each
target actually pins down.

### 4.1 `05` — main's canary is not a decoy (**corrects my 23 Sep report**)

My earlier write-up said `-fstack-protector-all` gives `main()` a *decoy* canary
at `%29$p`, and used that to argue verification-by-use was essential. **That was
wrong.** The canary is per-**thread**, read from `%fs:0x28` and stamped
identically into every frame. Measured:

```
run 0  %25$p=0xad4b3e14486b8a00  %29$p=0xad4b3e14486b8a00  %13$p=0x7bc6c2e17600
run 1  %25$p=0xcb4b4ebffa762c00  %29$p=0xcb4b4ebffa762c00  %13$p=0x7ee4b3e17600
run 2  %25$p=0xab5877505867f700  %29$p=0xab5877505867f700  %13$p=0x76e496c17600
```

`%25$p` and `%29$p` are byte-identical every run — the same 8 bytes, so either
works, and the ablation using `%29$p` correctly still produces the flag.

The genuine trap is the *other* candidate: `%13$p` is a **libc pointer** that
merely also ends in `0x00`, and ablation confirms it is blocked. So the step a
solver must get right is **canary-shaped vs pointer-shaped**, not frame
attribution. That is a materially easier discrimination (e.g. "high entropy in
the upper bytes, not `0x7f`-prefixed"), and it **raises 05's automatability** from
my earlier MEDIUM toward MEDIUM-HIGH: a sweep with a shape filter suffices, and
verification-by-use is a cheap safety net rather than a necessity.

The canary **leak itself remains necessary** — `canary_not_leaked` (a
canary-shaped guess) is blocked, as is `leak_only`.

### 4.2 `04` — the stage-1 write length is not load-bearing

The chain fills `buf` exactly (72 bytes) before the `write(1, buf, sizeof+8)`
echo. Sending **8** bytes instead also discloses the canary, because the
over-read is a fixed `sizeof(buf)+8` regardless of how much of `buf` was filled.
So "send exactly 72 bytes" is presentation, not a step. The **leak** is still
required (`canary_not_leaked` blocked) and so is the second overflow
(`leak_only` blocked).

### 4.3 `09` — the `+4` endbr64 skip is not required *here*

Using `gadget_syscall_ret` itself rather than `+4` still works: `endbr64` is a
NOP when IBT is not enforced. Worth keeping in the notes anyway, because the
related trap is real and asymmetric — for this target `sym+1` also works (it
decodes as a multi-byte NOP then `syscall`), whereas for target 02's `pop rdi`
gadget `sym+1` is **not** a bare `ret` and silently eats a chain entry. Only an
offset that lands past the `syscall` (`+6`, the bare `ret`) blocks it.

## 5. Per-target results

Every row below is "run the whole verified chain with exactly this removed". All
49 strict rows blocked the flag.

### 01_shellcode_stack — 4/4 blocked
| ablation | result |
|---|---|
| `no_shellcode` — return address set, nothing written to jump to | blocked |
| `no_rip_overwrite` — shellcode in `buf`, saved RIP untouched | blocked |
| `no_stack_leak` — same payload shape, guessed stack address | blocked |
| `shellcode_in_buffer` — shellcode before the saved RIP instead of after | blocked |

Confirms both halves of the corpus's own claim: the free stack leak is mandatory
(ASLR), *and* post-RIP placement is mandatory (in-buffer placement is
self-clobbering).

### 02_ret2plt_system — 4/4 blocked
| ablation | result |
|---|---|
| `no_alignment_ret` — drop the 16-byte alignment `ret` | blocked (SIGSEGV in `do_system`'s `movaps`) |
| `no_rdi_setup` — call `system()` without loading rdi | blocked |
| `no_system_call` — load rdi, never call `system()` | blocked |
| `wrong_rdi_string` — call `system()` with a non-shell string pointer | blocked |

The alignment `ret` being load-bearing is the notable one: it is an easy step to
omit and its failure looks like a wrong-technique crash.

### 03_pie_leak_ret2libc — 5/5 blocked
| ablation | result |
|---|---|
| `pie_leak_not_applied` — take the `%p` leak, never rebase on it | blocked |
| `libc_leak_not_applied` — leak `puts@got`, compute `system()` without the base | blocked |
| `no_reentry_ret` — drop the parity `ret` before returning into `vuln()` | blocked |
| `no_alignment_ret` — drop the final-round alignment `ret` | blocked |
| `leaks_only` — do both leaks, never call `system()` | blocked |

Both leaks are necessary *and* must actually be applied — the distinction that
matters for a tool that "finds a leak" but doesn't rebase on it.

### 04_canary_leak_bypass — 3/3 blocked (+1 relaxation, §4.2)
| ablation | result |
|---|---|
| `canary_not_leaked` — overflow with a canary-shaped guess | blocked (`*** stack smashing detected ***`) |
| `leak_only` — leak the canary, never overflow | blocked |
| `wrong_return_target` — restore the canary, return elsewhere | blocked |

### 05_fmtstr_arbread — 3/3 blocked (+1 relaxation, §4.1)
| ablation | result |
|---|---|
| `canary_not_leaked` — canary-shaped guess, no format-string read | blocked |
| `wrong_index_decoy_ptr` — read `%13$p`, a libc pointer ending in `0x00` | blocked |
| `leak_only` — leak the canary, never overflow | blocked |

### 06_fmtstr_arbwrite — 4/4 blocked
| ablation | result |
|---|---|
| `no_format_write` — ordinary text, no `%n` | blocked (`locked.`) |
| `no_padding_before_n` — `%n` first, padding after → writes 0 | blocked |
| `address_before_directive` — address first; its NULs stop printf parsing | blocked |
| `wrong_target_address` — `%n` writes to `&unlocked+8` | blocked |

Both format-string ordering rules are genuinely load-bearing, which is the
argument for encoding them explicitly (pwntools' stock `fmtstr_payload` applies
neither).

### 07_ret2libc_leak — 4/4 blocked
| ablation | result |
|---|---|
| `leak_not_applied` — leak `puts@got`, ignore the base | blocked |
| `no_reentry_ret` — drop the parity `ret` before re-entering `vuln()` | blocked |
| `no_alignment_ret` — drop the round-2 alignment `ret` | blocked |
| `leak_only` — leak the libc base, never call `system()` | blocked |

### 08_ret2dlresolve — 4/4 blocked
| ablation | result |
|---|---|
| `forgery_not_written` — write junk of the same length instead of the forged `Elf64_Rela`/`Elf64_Sym` | blocked |
| `no_dlresolve_call` — write the forgery, never enter PLT0 with the index | blocked |
| `wrong_reloc_index` — resolve with `reloc_index + 1` | blocked |
| `no_alignment_ret` — drop the alignment `ret` | blocked |

`forgery_not_written` is the important one: it proves the second, ROP-driven
`read()` must land the *real* structures, i.e. the target genuinely measures
ret2dlresolve and not just "a long ROP chain".

### 09_srop — 3/3 blocked (+1 relaxation, §4.3)
| ablation | result |
|---|---|
| `no_sigreturn_trigger` — `syscall` without `rax=15` | blocked |
| `no_frame` — trigger sigreturn with no `SigreturnFrame` on the stack | blocked |
| `frame_rax_not_execve` — `frame.rax=0` (read) instead of 59 | blocked |

### 10_int_overflow — 4/4 blocked
| ablation | result |
|---|---|
| `legal_length` — ask for 64 → read capped, no overflow | blocked |
| `honest_oversize_length` — ask for 200 → the signed check rejects it | blocked |
| `no_rip_overwrite` — truncation applied, stop before the saved RIP | blocked |
| `wrong_return_target` — overflow to a non-`win()` address | blocked |

`legal_length` and `honest_oversize_length` together are the key pair: the
truncation *is* the vulnerability, and there is no honest length that wins.

### 12_heap_tcache_poison — 5/5 blocked
| ablation | result |
|---|---|
| `no_safe_linking_mangle` — store the raw target, not `PROTECT_PTR(pos, target)` | blocked |
| `unaligned_target` — aim the freelist at `free@got` directly (8-aligned) | blocked (`aligned_OK` assertion) |
| `poison_non_head_chunk` — corrupt chunk A's `next` instead of head B's | blocked |
| `no_got_write` — win the allocation, never write `win()` over `free@got` | blocked |
| `no_free_trigger` — write `free@got`, never call `free()` again | blocked |

All three glibc-version-specific invariants from the write-up are confirmed
independently necessary. This target really does measure what its label claims,
and its LOW automatability rating stands.

### 14_negative_index — 3/3 blocked
| ablation | result |
|---|---|
| `in_bounds_index` — write `arr[0]` | blocked (`flag=0, try again`) |
| `wrong_negative_index` — write `arr[-2]` | blocked |
| `wrong_value` — write `arr[-1] = 1` instead of `0x1337` | blocked |

### 15_win_function — 3/3 blocked
| ablation | result |
|---|---|
| `no_win_address` — padding only | blocked |
| `offset_too_short` — `&win` 8 bytes early | blocked |
| `offset_too_long` — `&win` 8 bytes late | blocked |

Even the ret2win baseline requires the exact offset, so it is a real (if easy)
measurement rather than a freebie.

### Excluded
* **`11_heap_uaf_leak`** — VOID. `show(0)` with no `delete` prints the flag from
  the live chunk, so there is no chain whose steps could be ablated.
* **`13_off_by_one`** — VOID, dropped from the corpus.

## 6. What this changes

* **The 13 valid targets are sound on necessity.** A genuine pass on any of them
  evidences the technique on its label. That was previously an assumption.
* **One automatability rating moves up: `05` → MEDIUM-HIGH** (§4.1). The canary
  index sweep needs a canary-vs-pointer shape filter, not frame attribution.
* **Two ratings are reinforced.** `12` stays LOW — all three allocator
  invariants are independently required. `08` stays LOW-MEDIUM — the forged
  structures must really be written by a synthesised write primitive.
* **Stack parity is confirmed as a genuine cross-cutting requirement**, not an
  artifact of my scripts: four separate `no_alignment_ret` / `no_reentry_ret`
  ablations (02, 03 ×2, 07 ×2, 08) all block. The recommendation to have the
  framework try both parities automatically is load-bearing advice.
* **Ablation should gate every future round before it is scored.** It is the only
  layer that catches the `11` defect class, it costs a few minutes, and the
  template is now in-tree.

## 7. Reproducing

```bash
benchmark/build_all.sh
python3 benchmark/ablation/ablate.py          # expect: 49/49 blocked, exit 0
python3 benchmark/ablation/ablate.py --list   # the case list, runs nothing
```

Verified environment: Ubuntu 22.04.5, kernel 6.8.0, gcc 11.4.0, glibc 2.35,
pwntools 4.15.0, x86-64, ASLR on. Also verified from a clean `git archive`
checkout, built in place, run from `/` and `/tmp` by absolute path.

Reference exploits re-confirmed on the same tree after merging the corrected
harness: **14/14 at 2/2 reps** (`benchmark/reference_exploits/run_all.sh 2`).
