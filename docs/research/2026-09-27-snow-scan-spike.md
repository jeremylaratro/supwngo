# Spike — `snow_scan`: the engine never delivered a byte, and the bug is reachable

**Date:** 2026-09-27
**Sprint:** Sprint 2 (root-cause spikes), per
[plan v3](../plans/2026-09-27-path-to-5of7-plan-v3.md)
**Status:** **`undetermined`** per gate G-l — a reachable memory-safety fault is
**confirmed**, but it is an out-of-bounds **read**; a controlled **write** is plausible
and **not demonstrated**. "Not found" is not NO-GO.
**Provenance:** all facts **measured** — binary executed, `objdump`, and `gdb`.

---

## 1. The headline: this target was never given an input

`snow_scan` ships a `server.py` that reveals the real ingress:

```python
SCANNER = './snowscan'
MAX_FILE_SIZE = 3*1024                      # 3 kb limit
filename = re.sub(r'[^a-zA-Z0-9_.-]', '', file.filename)
file_path = os.path.join(UPLOAD_DIR, filename)
output = subprocess.run([SCANNER, file_path], capture_output=True, text=True, timeout=1).stdout
```

The target takes **a file path as `argv[1]`**. Measured behaviour:

| invocation | result |
|---|---|
| no arguments (what stdin delivery looks like) | `ERROR: No file provided as an argument.` — exit 255 |
| `./snowscan foo.txt` | `ERROR: Invalid file extension. Only accepting .bmp files.` — exit 255 |
| `./snowscan valid.bmp` | scans, printing `[01] : PASS …` per row |

**`scripts/htb_rescore.py` passes no `--input-vector`, so every rep delivered to
stdin.** The target therefore printed "No file provided as an argument" and exited
before a single payload byte was considered. The recorded `NOT_SOLVED` at 19.4s is
**not a statement about the engine's exploitation ability at all** — it never got a
chance to try.

Two framework features that already exist are exactly what this needs:

- `--input-vector file-argv` — writes the payload to a file and passes its path via argv
- `--input-name <name>.bmp` — the extension is **load-bearing** here, which is precisely
  what that flag's help text describes ("some targets gate on it before ever opening the
  file")

So the first question for this route is not "what capability is missing" but **"why is
the manifest not declaring the transport the target requires."** That is a
configuration/manifest gap, and it is cheap.

> **Caveat that keeps this honest.** `FILE_DELIVERY_ALLOWLIST = {"variable_overwrite",
> "ret2win"}` (`orchestrator.py:133`) means that even with the right vector declared,
> every *other* technique hard-SKIPs on a file sink. So declaring the transport is
> necessary but almost certainly not sufficient — whatever technique this target needs
> must either be in that allowlist or be made able to build its payload before the
> target is spawned.

---

## 2. Protections — unusually favourable

Static, non-PIE (measured previously via `readelf` + `Binary.load()`, agreeing):

| PIE | canary | NX | RELRO | link |
|---|---|---|---|---|
| no | yes | yes | partial | **static** |

Statically linked and non-PIE is close to the best case for exploitation: no ASLR on the
binary, no libc leak required, syscall instructions present, and a very large gadget set.
The canary is the only protection in the way.

---

## 3. A reachable memory-safety fault — confirmed

The advertised validation is **not enforced as advertised**. With the pixel payload held
at 512 bytes and the header's width/height varied:

| declared `w = h` | result |
|---|---|
| 20, 25, 30 | scans, exit 0 |
| **31, 64** | scans, exit 0 — **the "30x30" upper bound is not enforced** |
| **256, 4096, 16384, 0x7fffffff** | **SIGSEGV** |

Under `gdb`, the fault (declared 256×256, 566-byte file):

```
Program received signal SIGSEGV
0x0000000000433630 in __memcmp_sse4_1 ()
=> 0x433630 <__memcmp_sse4_1+3696>:  mov -0xf(%rdi),%rax
rdi  0x7ffffffff008        rsi  0x4c10ff        rdx  0xf
#0  __memcmp_sse4_1
#1  0x4022be in sequenceDetected ()
#2  0x402333 in scan ()
#3  0x402543 in main ()
```

`rdi` is a **stack** address running off the end of the buffer. So this is an
out-of-bounds **read** in `memcmp`, reached via `sequenceDetected` ← `scan`. The scan
loop iterates using the **unvalidated header dimensions** while the buffer was sized
from something else.

This is the condition B-3 set as its exit criterion — "reaching the parser's
memory-unsafe path" — and it was reached here by hand in a few minutes with a
hand-built BMP.

---

## 4. Why a controlled write is plausible — and why I am not claiming it

In `main`, the buffer is a **stack VLA**, not a fixed array. The classic
variable-size-stack-allocation probe sequence:

```
4024a4:  cmp  rsp,rdx
4024a9:  sub  rsp,0x1000
4024c4:  sub  rsp,rdx          <- size derived from parsed metadata
```

and it is then filled by a **`getc`-until-EOF loop**:

```
402500:  mov  eax,DWORD PTR [rbp-0x34]     ; index++
402503:  lea  edx,[rax+0x1]
40251e:  call 41b580 <_IO_getc>
402523:  mov  DWORD PTR [rbp-0x64],eax
402526:  cmp  DWORD PTR [rbp-0x64],0xffffffff   ; loop while != EOF
```

**The buffer's size comes from parsed metadata; the amount written comes from the actual
file length.** Any input that passes validation while carrying more bytes than the VLA
was sized for is a stack overflow with fully attacker-controlled content.

**I could not construct that input.** Every attempt to desynchronise declared size from
actual size was rejected by `ERROR: Invalid bitmap size. The acceptaple resolution range
is 20x20 to 30x30.` — and my model of that check is demonstrably wrong, because
31×31 and 256×256 headers both *pass* it while 4×4 and 20×20-with-1254-bytes are
*rejected*. The check is not a simple bound on the header dimensions, and I did not
finish reversing it. `loadBitmap` (`0x402020`) is only the header parser — it `malloc`s
0x38 bytes and `fread`s the fields — so the validation lives elsewhere.

**Honest status:** OOB read confirmed; write asymmetry identified structurally but not
triggered. Per G-l this is **`undetermined`**, and calling it NO-GO on an incomplete
search would be exactly the failure that gate exists to prevent.

---

## 5. Next steps, in order

1. **Reverse the size validation** (the guard reached before `main:0x4023e8`) to learn
   what is actually compared. This is the single fact blocking the route.
2. If the VLA can be overflowed: canary handling. Static + non-PIE means a ROP chain is
   otherwise straightforward, and a static binary offers `syscall` gadgets directly.
3. If it cannot: the OOB read is still an **oracle** — `PASS`/non-`PASS` per row is
   observable output derived from a `memcmp` against out-of-bounds memory, which is a
   byte-at-a-time disclosure primitive. That could leak the canary, which would reopen
   the write path if a write is found elsewhere.
4. **Independently of exploitation:** fix the manifest so this target is delivered
   `file-argv` with a `.bmp` name. Until that happens no measurement of this target
   means anything, and that is true regardless of which primitive wins.

---

## 6. Capability implications for T-2

| capability | generality | status |
|---|---|---|
| declare/derive a **file-argv** transport with a load-bearing extension | broad — already built and proven by the ingress corpus (rows 20–23) | **exists**; not wired into the HTB manifest |
| let techniques other than `variable_overwrite`/`ret2win` use a file sink | broad — currently a hard allowlist (`orchestrator.py:133`) | **missing**, and likely required here |
| parse/emit a **structured container format** (BMP header) as the payload envelope | moderate — a real class of challenge; the engine must place payload bytes inside a format that passes validation | **missing** |
| recognise a **VLA sized from metadata, filled to EOF** as an overflow primitive | moderate — a genuine bug class | **missing** |

Row 3 is the interesting one for generalization: the payload had to be wrapped in a
valid BMP before any byte of it mattered. That is the "format envelope" capability, and
it is the same shape as the `file-argv` work already done — transport solved, *envelope*
not.
