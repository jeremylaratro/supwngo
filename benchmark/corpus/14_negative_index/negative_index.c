/*
 * Target 14: negative-index out-of-bounds array write (CWE-129/CWE-787).
 * Technique: `idx` is checked against the upper bound only (`idx < 8`),
 * never against a lower bound, so a negative index is accepted and used
 * directly to index `arr`. `flag` is declared immediately before `arr` in
 * a struct (guaranteeing ascending-address layout with `arr` starting
 * exactly 8 bytes after the struct base, i.e. right after `flag` plus its
 * alignment padding), so `arr[-1]` lands exactly on `flag`.
 *
 * win() is called directly once flag has the expected value -- no address
 * leak or ROP is needed, so this target is statically linked purely for
 * corpus protection-variety; it has no effect on solvability.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, STATIC.
 */
#include <stdio.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_14_negative_index}"
#endif

void win(void) {
    puts(FLAG);
}

void vuln(void) {
    struct {
        int flag;
        long arr[8];
    } s;
    s.flag = 0;
    for (int i = 0; i < 8; i++) s.arr[i] = 0;

    int idx;
    long val;

    printf("index: ");
    fflush(stdout);
    if (scanf("%d", &idx) != 1) return;
    printf("value: ");
    fflush(stdout);
    if (scanf("%ld", &val) != 1) return;

    /* BUG: upper bound checked, lower bound is not -> negative idx
     * reaches memory before arr[0], i.e. s.flag. */
    if (idx < 8) {
        s.arr[idx] = val;
    } else {
        puts("out of range");
        return;
    }

    if (s.flag == 0x1337) {
        win();
    } else {
        printf("flag=%d, try again\n", s.flag);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 14 negative-index OOB write ===");
    vuln();
    puts("done");
    return 0;
}
