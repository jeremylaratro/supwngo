# snowscan BMP format gate — measured entry conditions (26SEP2026)

Phase-4 research for **B-3** (structured-format payload gate), the sprint queued
after Sprint 2′. All rows below are `measured` — each is a run of the target ELF
at `tests/htb-targets/a12c736f-06d6-4b36-a0f1-9bb76498a4f2/challenge/snowscan`
with the file passed as `argv[1]` and stdin at `/dev/null`.

## Headline

**A synthetic BMP that snowscan fully accepts exists and is trivial to build:
20×20, 8 bits per pixel, standard 54-byte header.** It passes every validation
stage and the target proceeds into its per-row scan loop, printing
`[01] : PASS` … `[20] : PASS` and exiting `rc=0`.

This **re-triages B-3 downward.** The gap analysis scored it complexity **4**
("needs a structured-format payload synthesizer … unproven"). The synthesizer is
~15 lines of `struct.pack` and is now proven against the real target, so the
honest complexity is **2**. B-3 was already raised P2 → P1 in Sprint 2′
Revision 3; this measurement is why it is now the cheapest remaining step toward
T-1 rather than the most expensive.

## Measured matrix

Header construction: `BM` + `BITMAPFILEHEADER` (14 B) + `BITMAPINFOHEADER`
(40 B, `biSize=40`, `biPlanes=1`, `biCompression=0`), pixel data at offset 54,
rows padded to a 4-byte multiple.

| case | rc | target output |
|---|---|---|
| **20×20, 8bpp** | **0** | `[01] : PASS` … `[20] : PASS` — **fully accepted** |
| ~~20×20, 8bpp, 8 KB appended *after* the pixel array~~ | ~~0~~ | ~~identical full PASS run — trailing bytes ignored~~ **← WRONG, see ERRATUM below** |
| 20×20, 24bpp | 255 | `Invalid bitmap size. The acceptaple resolution range is 20x20 to 30x30.` |
| 25×25, 24bpp | 255 | same |
| 30×30, 24bpp | 255 | same |
| **30×30, 8bpp** | 255 | same — **rejected despite being inside the advertised range** |
| 19×19 / 31×31, 24bpp | 255 | same |
| 20×25 (non-square), 24bpp | 255 | same |
| height `-20` (bottom-up), 8bpp | 255 | `Invalid bitmap resolution. Only square bitmaps are processed.` |
| 20×20, pixel array inflated to 8 KB | 255 | `Invalid bitmap size …` |
| 20×20, `biSizeImage` declared `0xFFFFFF` | 255 | `Invalid bitmap size …` |
| 20×20, 64 KB pixel array | 255 | `Invalid bitmap size …` |

## Findings that matter for the B-3 sprint

1. **Bit depth is load-bearing and undocumented by the error text.** Every 24bpp
   variant is rejected with a *resolution* message. The message is misleading:
   `20×20/8bpp` passes while `20×20/24bpp` does not, so the rejection is keyed on
   the pixel-array size (or `biSizeImage`), not on width/height alone.
2. **The advertised 20×20–30×30 range is not the accepted set.** `30×30/8bpp` is
   rejected. Only `20×20/8bpp` is confirmed accepted so far. The real predicate is
   probably an exact size equality rather than a range — worth one more sweep at
   the start of the B-3 sprint before the synthesizer hardcodes anything.
3. **Oversized pixel arrays are validated, trailing bytes are not.** Inflating the
   declared array fails, but 8 KB appended *after* it is silently ignored. So a
   naive "append the payload" overflow is closed at this layer; the exploit surface
   is inside the per-row scan, not the file tail.
4. **The scan loop is the exploit surface.** One `[NN] : PASS` line per row (20
   rows for a 20×20). Locating the overflow inside that loop is the actual B-3
   exploitation work; reaching it is now solved.
5. **`rc` is informative here, unlike the earlier gate ladder.** The four
   validation refusals exit `255`, and acceptance exits `0`. The earlier B-3 note
   recorded `rc=0` for the *pre-open* refusals (missing argument, bad extension);
   both statements are correct about different stages. Noting it so the two are not
   read as contradictory.

## Consequence for Sprint 2′ metric M-5

M-5 was registered as "`snowscan` validation gates passed: 0/4 → 2/4". This
measurement shows **4/4 is reachable** once a format synthesizer exists. M-5 is
left at its pre-registered 2/4 target for Sprint 2′ — the channel sprint is not
allowed to claim credit for a synthesizer it does not build — and 4/4 becomes the
B-3 sprint's own metric. Recording the distinction so the later claim cannot be
retrofitted onto this sprint's baseline.

## Not yet established

- Where in the scan loop the memory-safety bug is (no crash observed in any case
  above; every accepted input completed normally).
- Whether the accepted dimension set is exactly `{20×20}` or a larger set at
  8bpp. **Do not hardcode `20×20` in the synthesizer until this is swept.**

---

## ERRATUM (2026-09-26, same day) — "trailing bytes ignored" is FALSE

The struck row above, and conclusion 3's claim that *"the naive 'append the payload'
overflow is closed at this layer; the exploit surface is inside the per-row scan, not
the file tail"*, are **both wrong**. They were produced by observing **stdout only**
and never checking the process's own exit status.

**Re-measured** with the target's `returncode` captured directly (not a pipeline's
status), 20 repetitions per case, 20×20/8bpp envelope:

| trailer after the pixel array | crashes | distinct return codes |
|---|---|---|
| 0 bytes | **0 / 20** | `[0]` |
| 64 bytes | 0 / 20 | `[0]` |
| **8192 bytes** | **8 / 20** | `[-11, 0]` — **SIGSEGV** |

**The trailer is read, and it overflows something.** A `-11`/`139` never occurs
without a trailer and occurs in 40% of runs with an 8 KB one, so the trailer is
reachable and memory-unsafe — the opposite of "ignored". The file tail is therefore a
**live exploit surface**, not a closed one.

### Why the original measurement said otherwise

Two compounding mistakes, both worth naming because they are reusable failure modes:

1. **Exit status was never observed.** The run was judged by its printed output, and a
   crash *after* the last `PASS` line looks identical to a clean finish on stdout.
2. **The crash is nondeterministic, and a single run was taken as the answer.** With
   stdio buffering, a segfault usually discards the buffered output entirely, so the
   same input yields either the full 239-byte PASS transcript or **nothing at all**
   depending on the run. A one-shot observation of this target can produce three
   different-looking results from one input.

### Consequences

- **B-3's BMP path is more viable than planned, not less.** Payload belongs in the
  trailer, whose reachability is now proven by crash. An earlier peer review argued
  the trailer might be "accepted but never read" and recommended embedding inside the
  400-byte pixel array instead; that recommendation is **superseded by measurement** —
  and separately, pixel *content* was measured NOT to affect output at all
  (`0xAA`-filled and `0x55`-filled 20×20 images produce byte-identical transcripts).
- **Any B-3 gate must use repetitions, never a single run.** A single run has a ~60%
  chance of missing this crash entirely.
- **The crash threshold is NOT established.** An early 4-rep bisect appeared to show
  crashes from 64 bytes upward; that did not reproduce at 20 reps (0/20 at 64 bytes).
  The threshold and the offset of the overwritten object remain **unmeasured**, and no
  number should be relied on until they are swept with adequate reps.
- **Conclusion 4's "the scan loop is the exploit surface" is downgraded from
  `measured` to `inferred`.** One `PASS` line per row proves a row loop runs; it does
  not prove that loop performs the vulnerable write, and the trailer evidence now
  points elsewhere.
