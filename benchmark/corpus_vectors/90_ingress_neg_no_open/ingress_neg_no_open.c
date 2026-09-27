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
#ifndef FLAG
#define FLAG "FLAG{supwngo_ingress_90_never_printed}"
#endif
/* NEGATIVE CONTROL -- must score FAILED.
   Accepts a path in argv[1] and NEVER OPENS IT. Nothing the file sink writes
   can reach memory, so no payload can win. Paired with 91, which is this
   file plus the single causal branch that reads and gates -- so the pair
   isolates "does file CONTENT reach a decision" rather than "does something
   differ". If 90 ever SUCCEEDS the harness is crediting something other
   than exploitation. */
int main(int argc, char **argv) {
    struct { char buf[64]; unsigned int gate; } s;
    s.gate = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { puts("ERROR: no file argument"); return 1; }
    printf("received path: %s\n", argv[1]);
    if (s.gate == 0x5AFEF11E) puts(FLAG); else puts("nope");
    return 0;
}
