/*
 * Round-2 Target 14: array-indexing bug -- missing UPPER bound check
 * allows a positive out-of-bounds READ that leaks an adjacent secret
 * buffer, printed directly (no shell, no leak of any address needed).
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * Deliberately the mirror-image indexing bug from round-1's
 * 14_negative_index (a missing LOWER bound allowing a negative index
 * that WRITES into an adjacent field). Here `idx` is checked only against
 * a lower bound (`idx < 0`); no upper bound exists at all, so any
 * idx >= 8 reads past `d.arr` into `d.secret`, which the C standard
 * guarantees sits immediately after `arr` in ascending declaration order
 * inside the same global struct. Reading idx = 8..23 (16 ints = 64 bytes)
 * recovers the entire flag, 4 bytes at a time, from the printed decimal
 * values alone.
 */
#include <stdio.h>
#include <string.h>

struct data_s {
    int arr[8];
    char secret[64];
};

static struct data_s d;

/* The flag is intentionally NOT compiled into this binary (no literal in
 * .rodata that `strings`/ELF.search() could find with zero exploitation).
 * It is generated fresh per build by build_all_r2.sh and written to
 * flag.txt alongside the binary; d.secret is populated from it at runtime
 * only, so the OOB read still has to reach genuinely-live process memory
 * rather than a compiled-in constant. */
static void read_flag_into(char *dst, size_t cap) {
    memset(dst, 0, cap);
    FILE *f = fopen("flag.txt", "r");
    if (!f) return;
    fgets(dst, (int)cap, f);
    dst[strcspn(dst, "\n")] = '\0';
    fclose(f);
}

static void init(void) {
    for (int i = 0; i < 8; i++) d.arr[i] = i;
    read_flag_into(d.secret, sizeof(d.secret));
}

static int vuln(void) {
    printf("index: ");
    fflush(stdout);
    int idx;
    if (scanf("%d", &idx) != 1) return 0; /* EOF or bad input: stop */

    /* BUG: only the lower bound is checked -- no upper bound at all. */
    if (idx < 0) {
        puts("bad");
        return 1;
    }
    printf("arr[%d] = %d\n", idx, d.arr[idx]);
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-14 oob-read-flag-array (positive indexing bug) ===");
    init();
    while (vuln()) {
        /* keep serving index queries until stdin is exhausted */
    }
    puts("done");
    return 0;
}
