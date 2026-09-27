# Spike — `ancient_interface`: root cause, timeout mechanism, and exploitation path

**Date:** 2026-09-27
**Sprint:** Sprint 2 (root-cause spikes), per
[plan v3](../plans/2026-09-27-path-to-5of7-plan-v3.md)
**Status:** four-fact record complete; **GO pending a reference exploit** (a GO requires
a reproducible exploit per v3 §7.1 / gate G-l — this document does not yet contain one)
**Provenance:** all facts below are **measured** — source read plus `objdump` of the
shipped binary. Nothing here is inferred from protection flags.

---

## 1. Why this target was spiked first

It is the cheapest of the five undetermined routes: it is **non-PIE** (so no image-base
leak is needed at all) and it is the **only HTB target that ships its C source**
(`tests/htb-targets/a12c7393-…/challenge/ancient_interface.c`, 337 lines). It was also
one of the two targets that consumed the entire harness timeout, making it the largest
single unknown in the ledger.

**Anti-fitting boundary (v3 §7.4).** The source is used here as *ground truth to
validate a diagnosis*. It is not engine input, and no capability may be justified by it
— the engine must derive the mechanism from the binary. The same applies to the official
writeup PDFs bundled in `tests/htb-targets/`.

---

## 2. The timeout was the target, not the search

**This corrects a diagnosis I had already withdrawn once and can now replace with a
mechanism.** `cmd_read` (source `:250-254`):

```c
read_bytes = 0;
do {
    read_bytes += read(0, buf + read_bytes, amnt - read_bytes);
} while (read_bytes != amnt);
```

On **EOF, `read()` returns 0**, so `read_bytes` never changes and `read_bytes != amnt`
is never satisfied: the target **spins in an infinite loop**. Any engine that sends a
`read N var` command and then closes or exhausts stdin hangs the target forever.

This matches the measurement exactly: `ancient_interface` was observed at **64.7–70% CPU
with live child target processes** at timeout, and it timed out at 1100s as readily as at
300s. The earlier framing — "canonical search-space exhaustion" — was wrong, and raising
any budget would never have fixed it. **I-13's re-baseline will not move this target
either**; the fix is that the harness and the engine must both tolerate a target that
never exits.

---

## 3. The vulnerability

Three facts combine, and all three are required:

| # | fact | cite |
|---|---|---|
| a | `read_bytes` is **`int32_t`**, so a negative `read()` return walks the destination *backwards* and *grows* the length | source `:219`, `:253` |
| b | the SIGALRM handler is installed with **`sa.sa_flags = 0`** — **no `SA_RESTART`** — so a signal delivered during a blocking `read()` makes it return **-1/`EINTR`** | source `:79-81` |
| c | `cmd_alarm` calls **`timer_create` on every invocation** (into a `static timer_t tmid`), so repeated `alarm` commands arm **multiple** timers and can deliver many signals | source `:151`, `:166` |

### The chain

1. `alarm N` (one or more times) arms SIGALRM timer(s).
2. `read M var` enters the blocking `read(0, buf, M)`.
3. A timer fires; `alarm_handler` runs `write(1, ALARM_HIT, …)`; because of (b) the
   interrupted `read` returns **-1**.
4. `read_bytes += -1` → `read_bytes == -1`.
5. Next iteration: `read(0, buf - 1, amnt + 1)`.
6. After *k* interruptions: `read(0, buf - k, amnt + k)` — a **stack underflow write**.

Note the write *end* stays fixed at `buf + amnt`; only the start moves down. So this is
an underflow, not an overflow — which is why the next fact is the load-bearing one.

---

## 4. Measured stack layout — why the underflow becomes arbitrary write

From `objdump -d -M intel ancient_interface`, the `cmd_read` frame (function at
`0x4018a3`, `read@plt` call at `0x401a15`; the binary is stripped, so it was located by
its 0x1000-byte frame and `read@plt` callsite):

| variable | slot | derivation |
|---|---|---|
| `buf[4096]` | `[rbp-0x1010]` … `[rbp-0x11]` | `lea rdx,[rbp-0x1010]` at `0x401a00` |
| `p` | `[rbp-0x1018]` | `mov rax,QWORD PTR [rbp-0x1018]` at `0x401a3d` |
| `amnt` | `[rbp-0x101c]` | `cmp DWORD PTR [rbp-0x101c],0xfff` at `0x4019ba` |
| `read_bytes` | `[rbp-0x1020]` | `add eax,edx; mov DWORD PTR [rbp-0x1020],eax` at `0x401a22-0x401a24` |

**`read_bytes` and `amnt` both sit BELOW `buf`.** Therefore:

- `k = 12` puts the write destination on **`amnt`** (`buf-12 == rbp-0x101c`)
- `k = 16` puts it on **`read_bytes`** itself (`buf-16 == rbp-0x1020`)

Once the attacker's bytes land on `read_bytes`, the loop's own index is attacker
controlled. The next iteration computes `buf + read_bytes` with a **chosen** value, so
the write destination becomes arbitrary *relative to the frame* — including **upward**,
which the underflow alone could never reach. `amnt - read_bytes` supplies a matching
controlled length.

---

## 5. The four facts (v3 §7.2)

| # | fact | value |
|---|---|---|
| 1 | disclosure primitive | **`N/A`, justified** — binary is non-PIE, no ASLR-dependent address is required |
| 2 | derived base | **`N/A`, justified** — same reason |
| 3 | corruption primitive | **ESTABLISHED** — SIGALRM/`EINTR` underflow → controlled `read_bytes`/`amnt` at `[rbp-0x1020]`/`[rbp-0x101c]` → arbitrary-offset stack write of controlled length |
| 4 | terminal control target + trigger | **IDENTIFIED, not yet demonstrated** — `cmd_read`'s saved return address at `[rbp+0x8]` (== `buf + 0x1018`); trigger is `cmd_read` returning normally |

### 5.1 The canary is not an obstacle — corrected

My first pass recorded "the canary must be accounted for, because the write is
contiguous from `buf-k` upward." **That was wrong**, and correcting it materially
strengthens the route.

Once `read_bytes` is attacker-controlled, the write's **start** is arbitrary — it does
not have to run contiguously from `buf-k`. Setting `read_bytes = 0x1018` makes the
destination `buf + 0x1018`, and since `buf` is at `rbp-0x1010`, that is exactly
**`rbp+0x8`: the saved return address**. The canary lives at `rbp-0x8`, *below* that, so
the write **begins above the canary and never touches it.**

The length term cooperates as well: `amnt - read_bytes` is computed in `uint32_t`, and
with `amnt <= 4095 < 0x1018` it **wraps to a very large value**, so the length is not a
constraint on the payload either.

So the terminal step needs no canary leak and no canary preservation. What remains is
purely payload construction: **non-PIE, NX on, partial RELRO, dynamically linked**, so a
ROP chain (ret2libc via a leak, or ret2plt).

### 5.2 Honest status of this route

Per gate G-l, "identified but not demonstrated" is **`undetermined`, not GO and not
NO-GO** — a GO requires a reproducible exploit and an attributed result, and this
document does not contain one. But the remaining work is now ordinary ROP construction
against a target with an arbitrary stack write, no canary problem, and no ASLR problem.
**Of the five undetermined routes this is much the furthest along, and it is the
strongest candidate for seat 3.**

---

## 6. What capability the engine would need

This is the part that matters for **T-2**, since a fix that only solves this binary
counts for nothing:

| capability | generality |
|---|---|
| **Converse with a line-oriented command protocol** — issue `alarm N`, then `read M var`, in sequence, maintaining state | broad; this is the dialogue/action-schema capability, and it is a precondition for the heap routes too |
| **Induce and exploit an async event mid-read** (timing a signal against a blocking read) | narrow as stated; the generalizable form is "the engine can drive a target whose state changes without further input" |
| **Recognize a signed accumulator in a read loop** as an underflow primitive | moderately general — this is a real bug class (`int` accumulator + `read` return) |
| **Reason about locals below a buffer** as the underflow's targets | general, and it is the same reasoning the existing `variable_overwrite` disassembly guidance already does for locals *above* a buffer |
| **Tolerate a target that never exits** | general and currently absent — see §2; this is an engine/harness robustness gap, not an exploitation capability |

The last row is the cheapest and highest-value item in this table: it is a bug in *our*
tooling, it is why this target reported nothing at all for 1100s, and it blocks
diagnosis of `auth-or-out` too.

---

## 7. Next steps for this route

1. Determine the canary handling (leak via `echo $var`, or write around the slot).
2. Build the reference exploit and capture the attributed flag — `ancient_interface`
   **does** ship a `flag.txt`, so `FLAG_CAPTURED` attribution is achievable here (only
   2 of 7 targets allow it).
3. Only then record this route **GO** and derive the engine work from the working chain,
   per v3's rule that infrastructure follows demonstrated evidence.
