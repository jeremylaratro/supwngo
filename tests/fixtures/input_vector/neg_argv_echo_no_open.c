/*
 * Sprint 2' REVISION 4 adversarial fixture (D1 pathname-confound regression
 * gate). Source copied from the peer-review counterexample at
 * /tmp/probe_cx/echo_argv_only.c.
 *
 * WHAT THIS IS: a target that never opens argv[1] at all -- it only prints
 * it -- and otherwise reads its real payload from stdin. It is the
 * textbook non-file-vector target: argv is inspected (for a banner), but
 * no file I/O ever happens on that path.
 *
 * WHAT IT MEASURES: whether classify_input_vector()'s stage 1/2/3 file
 * probes use three DIFFERENT basenames (missing_input<ext>,
 * existing_small<ext>, existing_large<ext> -- the pre-REVISION-4 D1 defect)
 * or ONE reused basename (probe_input<ext> -- the REVISION 4 fix). Under
 * the three-basename design, this target's printf("target=%s\n", argv[1])
 * echoes a different STRING each stage purely because the basename differs
 * in length/content, which stage 3 then misreads as a content-volume
 * signal -- even though the target never opens the file at all.
 *
 * MEASURED VERDICT, BEFORE the D1 fix (three different basenames):
 *     file-candidate, stage3_basis='output'   -- FALSE POSITIVE.
 *
 * MEASURED VERDICT, AFTER the D1 fix (one reused probe_input<ext> path):
 *     argv-only-not-opened, stage3_basis=None (stage 3 never reached)
 *     -- CORRECT: with only existence/content varying and the basename
 *     held constant, stage 2 (missing vs. existing-32-byte) shows no
 *     difference, because the target's printed argv[1] string is now
 *     identical across stage 1/2/3 runs -- the probe halts at
 *     "argv-only-not-opened" instead of reaching stage 3 at all.
 *
 * This fixture is kept as a PERMANENT regression gate for D1: if the
 * pathname confound is ever reintroduced, this target will misclassify as
 * file-candidate again.
 *
 * Build (the test does this automatically):
 *   gcc -m64 -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -w \
 *       -o neg_argv_echo_no_open neg_argv_echo_no_open.c
 */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char b[64];
    if (argc > 1) printf("target=%s\n", argv[1]);
    if (fgets(b, sizeof b, stdin)) printf("got %zu\n", strlen(b));
    return 0;
}
