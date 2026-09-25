/*
 * I5 induced fixture -- a canary + scanf target that genuinely reaches
 * ScanfCanaryBypassExecutor.attempt() (supwngo/exploit/pipeline/executors/
 * heap_and_bypass.py).
 *
 * See docs/plans/2026-09-24-pipeline-instrumentation-pass.md §4 I5, §4.4
 * Class 1: `scanf_canary_bypass` is SKIPPED on all 12 occurrences across
 * both benchmark runs and never executes, so neither of its two swallowing
 * sites (the `except Exception` path, and `_test_scanf_bypass() -> False`)
 * has any naturally-occurring subject. This fixture exists purely to give
 * both legs a genuine subject: a real, compiled, canary-protected binary
 * that reads with `scanf("%lf", ...)` in a loop (the exact pattern
 * CanaryBypassDetector._detect_scanf_bypass looks for -- a raw `%lf` byte
 * pattern in the image plus a scanf variant in .plt) and a `win` function
 * (one of profile_stage.WIN_FUNCTIONS, so run_static_analysis() populates
 * ExploitContext.win_function for real, exactly as a live pipeline run
 * would, rather than the test hand-wiring that field).
 *
 * This target deliberately does NOT implement the "add grades" menu
 * protocol _test_scanf_bypass()'s probe assumes (a '>' prompt, then a ':'
 * count prompt, then one '[' prompt per element) -- it just loops reading
 * doubles. That is what makes the probe leg (leg 3) a genuine negative: the
 * probe's fixed protocol assumption doesn't match this binary's real I/O,
 * so it fails for real, not by construction.
 *
 * Build (also done automatically by the test):
 *   gcc -m64 -O0 -fstack-protector-all -D_FORTIFY_SOURCE=0 -g \
 *       -o scanf_canary_target scanf_canary_target.c
 */
#include <stdio.h>

void win(void) {
    puts("you win");
}

int main(void) {
    double arr[40];
    int i;

    puts("enter values:");
    for (i = 0; i < 40; i++) {
        scanf("%lf", &arr[i]);
    }
    puts("done");
    return 0;
}
