/*
 * M-1b ingress-variation corpus. The VULNERABILITY IS HELD CONSTANT across
 * every target here -- a struct pinning an overwrite gate at exactly offset
 * 64 with winning value 0x5AFEF11E -- and ONLY THE INGRESS MECHANISM varies.
 * A per-target difference in result is therefore attributable to how the
 * payload got in, which is the whole point of this corpus.
 *
 * Provenance: adapted from the MEASURED mechanism fixtures at
 * tests/fixtures/input_vector/, whose docstrings record why offset 64 and
 * 0x5AFEF11E specifically: 64 is in VariableOverwriteExecutor's buffer sweep,
 * and 0x5AFEF11E is recovered by Sprint 1's comparison-immediate path rather
 * than from the folklore magic-value list. It is also NUL-free and shares no
 * byte with the executor's 0x41 filler, so it survives an argv token and
 * cannot be forged by filler alone.
 *
 * WHY A STRUCT, not two adjacent locals: it pins the overwrite distance to
 * exactly sizeof(buf) == 64 regardless of frame layout. As two locals, gcc
 * -O0 placed them 76 bytes apart -- not in the sweep -- making the target
 * unsolvable by the technique and the gate vacuous.
 *
 * The flag is compiled in via -DFLAG by build_all.sh (a per-run secret), so
 * the #ifndef default below is only for manual builds.
 */
#include <stdio.h>
#include <string.h>
#ifndef FLAG
#define FLAG "FLAG{supwngo_ingress_22_file_argv_flag}"
#endif
/* INGRESS: the path arrives behind a "-f FILE" flag, so the argv TEMPLATE
   (not just the path) has to be honoured. */
int main(int argc, char **argv) {
    struct { char buf[64]; unsigned int gate; } s;
    FILE *f; int i; const char *p = 0;
    s.gate = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 1; i + 1 < argc; i++) if (!strcmp(argv[i], "-f")) p = argv[i+1];
    if (!p) { puts("usage: prog -f FILE"); return 1; }
    f = fopen(p, "rb");
    if (!f) { puts("ERROR: cannot open file"); return 1; }
    fread(s.buf, 1, 256, f);
    fclose(f);
    if (s.gate == 0x5AFEF11E) puts(FLAG); else puts("nope");
    return 0;
}
