/*
 * Positive control for scripts/htb_rescore.py.
 *
 * The harness must be shown able to report SOLVED / FLAG_CAPTURED before any
 * NOT_SOLVED it produces means anything. No HTB target serves as this control:
 * the 5 that canonical might solve are shell-popping challenges with no flag
 * path, and the corpus targets compile their flag in with -DFLAG rather than
 * reading it from disk, so they cannot exercise the "reproduced THIS rep's
 * planted secret" check that the harness's attribution depends on.
 *
 * So this target is deliberately shaped to exercise exactly that path:
 *
 *   - vulnerable in a way canonical reliably solves -- the same struct-pinned
 *     variable_overwrite shape proven by benchmark/corpus_vectors, gate at
 *     offset 64, winning value 0x5AFEF11E (NUL-free, shares no byte with the
 *     executor's 0x41 filler, so a filler-only payload cannot win by accident)
 *   - on win it READS ./flag.txt at runtime and prints it, rather than printing
 *     a compiled-in constant
 *
 * A harness run against this binary that does NOT report FLAG_CAPTURED with the
 * planted secret is a broken harness, not a broken tool.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    struct { char buf[64]; unsigned int gate; } s;
    char flag[256];
    FILE *f;

    s.gate = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("name?");
    gets(s.buf);                 /* deliberate: the overflow under test */

    if (s.gate == 0x5AFEF11E) {
        f = fopen("./flag.txt", "r");
        if (!f) {
            /* Distinguish "not exploited" from "exploited but nothing to
             * read" -- the exact confusion that makes rocket_blaster_xxx's
             * missing flag.txt score an exploited target as a miss. */
            puts("WIN_BUT_NO_FLAG_FILE");
            return 1;
        }
        if (fgets(flag, sizeof(flag), f)) fputs(flag, stdout);
        fclose(f);
        return 0;
    }
    puts("nope");
    return 0;
}
