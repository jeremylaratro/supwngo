/*
 * I3 candidate-provenance Fixture B (negative control for the sweep).
 *
 * See docs/plans/2026-09-24-pipeline-instrumentation-pass.md §4 I3 / M10.
 *
 * Structurally identical to fixture_a_magic_in_list.c -- same genuine stack
 * buffer overflow (CWE-121/CWE-787), same 60-byte adjacent-overwrite
 * distance -- but GATE_VALUE (0x12345678) is deliberately NOT one of the
 * nine MAGIC_VALUES constants in
 * supwngo/exploit/pipeline/executors/stack_techniques.py.
 *
 * The vulnerability is real (sending the correct 0x12345678 at the correct
 * offset does win it -- verified empirically, see
 * tests/test_i3_candidate_provenance.py), but VariableOverwriteExecutor's
 * fixed 14x9 sweep can never produce this value, so the sweep exhausts and
 * the attempt genuinely FAILs with no candidate to attribute. This is what
 * makes "swept" a provable claim rather than a label attached regardless of
 * what actually happened: a target the sweep truly cannot win.
 *
 * Build (also done automatically by the test):
 *   gcc -m64 -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -g \
 *       -o fixture_b fixture_b_magic_not_in_list.c
 */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[60];
    unsigned int gate = 0;
    read(0, buf, 256);
    if (gate == 0x12345678) {
        printf("you win\n");
    } else {
        printf("nope\n");
    }
    return 0;
}
