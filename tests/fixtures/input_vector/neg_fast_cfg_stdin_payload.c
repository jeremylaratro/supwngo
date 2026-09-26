/*
 * Sprint 2' REVISION 4 adversarial fixture (measured, GENUINE stage-3
 * false positive -- distinct from neg_argv_echo_no_open, which the D1 fix
 * resolves). Source copied from the peer-review counterexample at
 * /tmp/probe_cx/fast_cfg_stdin.c.
 *
 * WHAT THIS IS: a target that genuinely opens the argv[1] path as a
 * config file, prints a message whose content depends on the config's
 * SIZE (quickly -- no timeout involved either way), and then reads its
 * real payload from stdin. Unlike neg_slow_config_stdin_payload (the
 * existing timeout-based false positive), this one produces a real
 * *output* difference between the 32-byte and 4096-byte probe files, so
 * it is not explained away by the "timeout is ambiguous" caveat already
 * documented for stage3_basis == "timeout".
 *
 * WHAT IT MEASURES: that a target which opens and reads argv[1] (so it
 * legitimately passes stage 2, "causal file open") but uses the file only
 * as size-gated CONFIGURATION -- not as the exploitable payload sink --
 * can still flip stage 3 on genuine `output` evidence. This is orthogonal
 * to D1 (the pathname confound): here the SAME basename is used at every
 * stage (this fixture predates and is unaffected by the D1 path-reuse
 * fix), and the false positive survives regardless, because the target's
 * own behavior is content-size-sensitive by design, just not on the
 * payload channel.
 *
 * MEASURED VERDICT, BEFORE the D1 fix (three different basenames):
 *     file-candidate, stage3_basis='output'   -- FALSE POSITIVE.
 *
 * MEASURED VERDICT, AFTER the D1 fix (one reused probe_input<ext> path):
 *     file-candidate, stage3_basis='output'   -- STILL a FALSE POSITIVE,
 *     unchanged by D1. This is the expected/measured result, not a
 *     regression: the false positive here is not caused by the pathname
 *     confound, it is caused by the target genuinely reading file content
 *     and behaving differently based on its size -- which is exactly what
 *     stage 3 is designed to detect, and exactly the documented residual
 *     gap (a config-consuming target that is content-volume sensitive but
 *     not payload-bearing). Harmless because the probe is advisory-only
 *     and can never commit a DeliverySpec.
 *
 * Kept as a permanent, measured counterexample so nobody claims stage 3's
 * "output"/"returncode" basis implies a genuine file sink -- it does not;
 * see the corrected claim in test_input_vector_foundation.py.
 *
 * Build (the test does this automatically):
 *   gcc -m64 -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -w \
 *       -o neg_fast_cfg_stdin_payload neg_fast_cfg_stdin_payload.c
 */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char b[64];
    long n = 0;
    FILE *f;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            n = ftell(f);
            fclose(f);
            puts(n > 1024 ? "large config profile" : "small config profile");
        } else {
            puts("cfg missing");
        }
    }
    if (fgets(b, sizeof b, stdin)) printf("payload %zu\n", strlen(b));
    return 0;
}
