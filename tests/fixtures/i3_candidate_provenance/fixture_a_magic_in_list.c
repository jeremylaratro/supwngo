/*
 * I3 candidate-provenance Fixture A (positive control).
 *
 * See docs/plans/2026-09-24-pipeline-instrumentation-pass.md §4 I3 / M10.
 *
 * A genuine stack buffer overflow (CWE-121/CWE-787): `buf` is 60 bytes but
 * `read()` is told it may write up to 256, so writing past `buf`'s declared
 * bound corrupts the adjacent local `gate`. No bounds check exists on the
 * read path -- this is a real vulnerability, not a simulated one, compiled
 * with no stack protector so the overflow reaches `gate` unobstructed.
 *
 * GATE_VALUE (0xcafebabe) is deliberately one of the nine constants in
 * supwngo/exploit/pipeline/executors/stack_techniques.py's MAGIC_VALUES, so
 * VariableOverwriteExecutor's blind 14-buffer-size x 9-magic sweep can
 * genuinely win this target -- this is I3's positive control: a real
 * SUCCESS whose provenance must read "literal_magic_list".
 *
 * The offset (60 bytes of 'A' then the 4-byte magic) and the fact that only
 * this one (buffer_size, magic) pair among all 126 the executor tries
 * triggers the win was verified empirically against the compiled binary,
 * not assumed -- see tests/test_i3_candidate_provenance.py.
 *
 * Build (also done automatically by the test):
 *   gcc -m64 -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -g \
 *       -o fixture_a fixture_a_magic_in_list.c
 */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[60];
    unsigned int gate = 0;
    read(0, buf, 256);
    if (gate == 0xcafebabe) {
        printf("you win\n");
    } else {
        printf("nope\n");
    }
    return 0;
}
