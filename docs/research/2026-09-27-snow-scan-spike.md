# Spike — `snow_scan`: the engine never delivered a byte, and the bug is reachable

**Date:** 2026-09-27
**Sprint:** Sprint 2 (root-cause spikes), per
[plan v3](../plans/2026-09-27-path-to-5of7-plan-v3.md)
**Status:** **`undetermined`** per gate G-l — a reachable memory-safety fault is
**confirmed**, but it is an out-of-bounds **read**; a controlled **write** is plausible
and **not demonstrated**. "Not found" is not NO-GO.

> **UPDATE, 2026-09-27 (later the same day) — §4's blocker is resolved.** The size
> validator has been reversed and the write asymmetry is now **measured, exact, and
> computed**, not merely structural: the validated field is `biSizeImage`, the
> dimensions are checked only against *each other*, the VLA is sized from
> `biSizeImage ∈ [400,900]`, and the fill loop has **no bound but EOF**. See **§7**.
> `main` also has **no canary**. Status remains `undetermined` only because gate G-l
> requires a *reproducible exploit*, which is the single remaining step. §4's "I could
> not construct that input" is superseded — the reason it failed is identified there.

**Provenance:** all facts **measured** — binary executed, `objdump`, and `gdb`. The one
exception is the offset arithmetic in §7.6, which is explicitly labelled a **prediction**
and is not yet verified by execution.

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

> **ERRATUM, 2026-09-27 — the last sentence is wrong, and the profile is even better than
> this table suggests.** The `canary=yes` in the table is a **true reading of the image
> and a false reading of the target**: `main`, which holds the overflow, contains zero
> `fs:0x28` references, while the statically-linked libc inside the same image contains
> 302 — and a static link is exactly what makes a whole-image canary check report yes.
> Measured in §7.5. **There is no protection in the way at all** on the path that
> matters. (This independently confirms, from the binary, the note in
> `docs/reports/2026-09-26-comprehensive-feature-retest.md:18` that the canary is a false
> positive — which had been carried on the authority of the HTB writeup.)
>
> Worth generalising: for a **statically linked** target, a whole-image canary/protection
> reading says little about the vulnerable function. That is a measurement caveat for the
> engine's own profiling, not just for this spike.

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

1. ~~**Reverse the size validation**~~ **— DONE, 2026-09-27, see §7.2.** The rule is
   `400 <= biSizeImage <= 900` and `biWidth == biHeight`; the dimensions are not bounded.
2. ~~If the VLA can be overflowed: canary handling.~~ **Superseded — there is no canary
   in `main` (§7.5), so there is nothing to handle.** Static + non-PIE means the ROP
   chain is straightforward and `syscall` gadgets are present in-image.
3. ~~If it cannot: the OOB read is still an **oracle** …~~ **No longer on the critical
   path.** The write is now established (§7.4), so the disclosure primitive is not needed.
   It is retained here only as a fallback if §7.6's offset prediction fails in a way that
   blocks the direct route — and since there is no canary, its original purpose (leaking
   one) has gone away.
   **New item 3:** verify §7.6's predicted 536-byte offset by execution, then build the
   reference exploit. This is now the only thing between this route and **GO** under G-l.
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

---

## 7. The size validator, reversed — and why §4's attempts all failed

**Provenance: measured**, by static disassembly only (`objdump -d -M intel`); no
execution, so nothing here could perturb the re-baseline running at the time.

### 7.1 The header struct is a byte-for-byte BMP mirror

`loadBitmap` (`0x402020`) `malloc`s `0x38` and `fread`s fifteen fields. Mapping the
`lea rdi,[rax+N]` offsets against the read sizes and BMP's on-disk layout:

| struct | size | BMP field | file offset |
|---|---|---|---|
| `+0x00` | 2 | `bfType` (`"BM"`) | 0 |
| `+0x04` | 4 | `bfSize` | 2 |
| `+0x08` | 4 | `bfReserved` | 6 |
| `+0x0c` | 4 | **`bfOffBits`** | 10 |
| `+0x10` | 4 | `biSize` | 14 |
| `+0x14` | 4 | **`biWidth`** | 18 |
| `+0x18` | 4 | **`biHeight`** | 22 |
| `+0x1c` | 2 | `biPlanes` | 26 |
| `+0x1e` | 2 | `biBitCount` | 28 |
| `+0x20` | 4 | `biCompression` | 30 |
| `+0x24` | 4 | **`biSizeImage`** | 34 |
| `+0x28`…`+0x34` | 4 ea. | `biXPelsPerMeter`, `biYPelsPerMeter`, `biClrUsed`, `biClrImportant` | 38–50 |

### 7.2 What the validator actually checks — `loadBitmap:0x402235`

```
mov  eax,[rax+0x24]        ; biSizeImage
cmp  eax,0x18f             ; 399
jbe  402251                ;   <= 399  -> error "Invalid bitmap size ... 20x20 to 30x30"
cmp  eax,0x384             ; 900
jbe  40225d                ;   <= 900  -> ACCEPT
                           ;   > 900   -> same error

mov  edx,[rax+0x14]        ; biWidth
mov  eax,[rax+0x18]        ; biHeight
cmp  edx,eax
jne  40226f                ; not equal -> error (different string, 0x4960b8)
```

So the accepted set is exactly:

> **`400 <= biSizeImage <= 900`** *and* **`biWidth == biHeight`**

`400 = 20×20` and `900 = 30×30`, which is where the error message's "20x20 to 30x30"
comes from — **but the range is enforced on a *size* field, and the dimensions
themselves are never bounded at all, only checked for equality.**

### 7.3 This explains every previously-inexplicable observation

§4 recorded that "my model of that check is demonstrably wrong" because 31×31 and
256×256 passed while 4×4 and 20×20-with-1254-bytes were rejected. Under the measured
rule all four are consistent, and the earlier model was wrong in a specific way — **I
was varying the dimensions, which are not range-checked, while the field that *is*
range-checked was moving as a side effect of the payload size I happened to pick:**

| attempt (§3/§4) | `biSizeImage` | `biWidth==biHeight` | measured | consistent? |
|---|---|---|---|---|
| 20, 25, 30 @ 512 B | in range | yes | accepted | ✅ |
| **31, 64** @ 512 B | in range | yes | accepted — dimensions are *not* bounded | ✅ |
| **256, 4096, 16384, 0x7fffffff** | in range | yes | accepted, then **SIGSEGV** in `scan` | ✅ |
| 4×4 | **< 400** | yes | rejected | ✅ |
| 20×20 with 1254 B | **> 900** | yes | rejected | ✅ |

The §3 SIGSEGV is now fully attributed too: an accepted header with a huge `biWidth`
makes `main` call `scan(vla_base, biWidth)` (`0x40252c-0x40253e`), so the scan walks
`biWidth` rows out of a VLA sized from `biSizeImage` — hence the out-of-bounds **read**
in `__memcmp_sse4_1` reached via `sequenceDetected` ← `scan`.

### 7.4 The controlled write — exact, and it needs no dimension games at all

`main`:

```
40244b:  mov eax,[rax+0x24]     ; biSizeImage  ...
402452-4024c4:                  ; ... sizes the stack VLA (align-16, page-probe, sub rsp)
4024e5:  mov rax,rsp
4024ec:  mov [rbp-0x60],rax     ; VLA base

402500:  mov eax,[rbp-0x34]     ; index
402503:  lea edx,[rax+0x1]
402506:  mov [rbp-0x34],edx     ; index++   <-- NO BOUND
40250e:  mov rdx,[rbp-0x60]     ; VLA base
402514:  mov [rdx+rax*1],cl     ; store the byte
40251e:  call _IO_getc
402526:  cmp [rbp-0x64],0xffffffff
40252a:  jne 402500             ; loop while != EOF   <-- the ONLY terminator
```

Before the loop, `0x402446` does `fseek(f, bfOffBits, SEEK_SET)`. Therefore:

| quantity | source | attacker-controlled? | bounded? |
|---|---|---|---|
| VLA size | `biSizeImage` | yes | **yes — [400,900]** |
| bytes written | `filesize − bfOffBits` | yes | **no — EOF is the only stop** |

**The two are never compared.** No dimension needs to be abnormal: `biSizeImage = 400`,
`biWidth = biHeight = 20` (a header the validator likes), `bfOffBits = 54`, and a file
longer than `54 + 400` bytes overflows the VLA with fully attacker-chosen bytes. The
deployment's own `MAX_FILE_SIZE = 3*1024` (§1) permits ~2.6 KB past the buffer — far
more than a ROP chain needs. This is why §4's framing ("*any* input that passes
validation while carrying more bytes than the VLA was sized for") was right in
principle but unreachable in practice: the desync is between `biSizeImage` and the
**file length**, not between the declared dimensions and anything.

### 7.5 The canary is a false positive — now measured, not cited

`main` contains **zero** `fs:0x28` references (`grep -c` over its disassembly = 0),
while the image as a whole contains 302 — all in statically linked libc code. That is
precisely why `checksec` and `Binary.load()` both report `canary=yes` for this target.
The retest report noted "snow_scan canary is a false positive per HTB writeup"; it is
now established from the binary, and it applies to **the function that holds the
overflow**, which is the only place it matters.

### 7.6 Predicted offset to the saved return address

From the prologue — `push rbp; mov rbp,rsp`, five register pushes (`r15 r14 r13 r12
rbx` = `0x28`), `sub rsp,0x58` — and the VLA allocation subtracting `align16(biSizeImage)`:

```
vla_base  ~= rbp - 0x80 - align16(biSizeImage)
saved RIP  = [rbp+0x8]
distance   = 0x88 + align16(biSizeImage)
```

With `biSizeImage = 400 (0x190)`: distance = `0x88 + 0x190` = **`0x218` = 536 bytes**
from the VLA base, so a file of `54 + 536 + 8 = 598` bytes places 8 controlled bytes on
the saved return address.

**This is a prediction, labelled as such, and it is not yet verified** — verifying it
means running the target, which was deliberately deferred so as not to perturb the
concurrent HTB re-baseline. Epilogue caveat to check when verifying: `main` restores via
`mov rsp,rbx` then `lea rsp,[rbp-0x28]` (`0x402554`), then pops `rbx r12 r13 r14 r15`,
so those five saved registers sit between the VLA and the return address and are
overwritten on the way — they must be filled with values the epilogue tolerates.

### 7.7 Status, and what changes for the ledger

Still **`undetermined`**, because G-l requires a reproducible exploit and §7.6 is a
computed prediction rather than a demonstrated one. But the blocker named in §5 item 1
— "reverse the size validation … this is the single fact blocking the route" — is
**closed**, and what remains is ordinary ROP construction against the most favourable
protection profile in the whole set: **static, non-PIE, no canary in the vulnerable
function, no ASLR dependency, syscall gadgets present in-image, and ~2.6 KB of
controlled overflow.**

Alongside `ancient_interface`, this is now a leading candidate for a seat. The
capability table in §6 is unchanged in substance — the engine still needs the **format
envelope** (a payload wrapped in a header that passes validation) and the **file-argv
transport** — but row 4 should be re-read: the primitive to recognise is not "VLA sized
from metadata" in the abstract, it is **"a buffer sized from one parsed field and filled
from an independent length"**, which is a broader and more common bug class.
