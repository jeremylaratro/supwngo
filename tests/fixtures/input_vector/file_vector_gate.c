/*
 * Sprint 2' file-vector fixture: the payload MUST arrive via a file named in
 * argv[1]. Nothing is ever read from fd 0, so a stdin-only pipeline cannot
 * solve this target at all -- that impossibility is metric M-4's baseline.
 *
 * Plan: docs/plans/2026-09-26-sprint2prime-input-vector-plan.md (REVISION 3)
 *
 * All of the following is MEASURED against the compiled fixture, not assumed:
 *
 *   - Exactly ONE winning offset: 64. It is in VariableOverwriteExecutor's
 *     buffer sweep [32,40,48,56,60,64,72,80,96,100,104,112,120,128], so the
 *     technique can actually reach it.
 *   - Negative control: 0xDEADBEEF written at offset 64 does NOT win, so a
 *     win is attributable to the value and not merely to reaching the offset.
 *   - Positive control: 0x5AFEF11E at offset 64 does win.
 *   - Run with no argv it prints "ERROR: no file argument" -- structurally
 *     unsolvable without an argv/file delivery channel.
 *   - classify_input_vector() rates it "file-candidate": a 32-byte file
 *     prints "nope" (rc=0) while a 4096-byte file crashes (rc=-11), which is
 *     the content-volume signal stage 3 looks for.
 *   - 0x5AFEF11E is NOT in FALLBACK_MAGIC_VALUES, and comparison_immediates()
 *     recovers it at rank 0 of 10 -- so the win requires the Sprint-1
 *     recovery path, not the folklore list.
 *
 * WHY A STRUCT rather than two adjacent locals: it pins the
 * adjacent-overwrite distance to exactly sizeof(buf) == 64 regardless of
 * frame layout or padding. Written first as two locals (`char buf[64]` then
 * `unsigned int gate`), which gcc -O0 placed at rbp-0x50 and rbp-0x4 -- a
 * distance of 76, NOT in the sweep, so the fixture was unsolvable by the
 * technique and the gate would have been vacuous. The struct removes that
 * dependence on compiler layout choices.
 *
 * Build (the test does this automatically):
 *   gcc -m64 -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -w \
 *       -o file_vector_gate file_vector_gate.c
 */
#include <stdio.h>

int main(int argc, char **argv) {
    struct { char buf[64]; unsigned int gate; } s;
    FILE *f;

    s.gate = 0;
    if (argc < 2) { puts("ERROR: no file argument"); return 1; }
    f = fopen(argv[1], "rb");
    if (!f) { puts("ERROR: cannot open file"); return 1; }
    fread(s.buf, 1, 256, f);   /* overflow: 256 into a 64-byte buffer */
    fclose(f);

    if (s.gate == 0x5AFEF11E) { puts("FLAG{file_vector_reached}"); }
    else puts("nope");
    return 0;
}
