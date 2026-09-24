/*
 * Target 13: off-by-one single-byte overflow.
 * Technique: `buf[n] = 0;` is called with n possibly equal to
 * sizeof(buf) (32), writing one byte past the end of buf -- directly into
 * the low byte of the adjacent `guard` field. The two fields are grouped
 * in a struct specifically so their relative layout (buf immediately
 * followed by guard, no compiler reordering) is guaranteed by the C
 * standard rather than left to whatever order the compiler happens to
 * pick for separate locals.
 *
 * win() is called directly by this function once the guard's low byte has
 * been zeroed -- no address leak or ROP is needed, so PIE is turned on
 * here purely for corpus protection-variety; it has no effect on
 * solvability.
 *
 * Protections: canary=OFF, NX=ON, PIE=ON, RELRO=partial, dynamic.
 */
#include <stdio.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_13_off_by_one}"
#endif

void win(void) {
    puts(FLAG);
}

void vuln(void) {
    struct {
        char buf[32];
        int guard;
    } s;
    s.guard = 0xdeadbeef;

    printf("Input: ");
    fflush(stdout);
    int n = (int)read(0, s.buf, 32);
    if (n < 0) n = 0;
    if (n > 32) n = 32;
    s.buf[n] = 0; /* BUG: off-by-one -- n==32 writes s.buf[32], the first
                   * byte of s.guard, one past the end of buf. */

    printf("You said: %s\n", s.buf);

    if ((s.guard & 0xff) == 0) {
        win();
    } else {
        puts("access denied");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 13 off-by-one single-byte overwrite ===");
    vuln();
    puts("done");
    return 0;
}
