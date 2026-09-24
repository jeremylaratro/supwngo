/*
 * Round-2 Target 13: single-byte off-by-one overflow used for a PARTIAL
 * (low-byte-only) function-pointer overwrite, redirecting a call from
 * safe_path() to win() -- both functions' addresses share every byte
 * except the lowest one (verified at build time; see corpus_r2/README.md).
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * Deliberately a different off-by-one mechanic from round-1's
 * 13_off_by_one (which zeroed a separate 4-byte struct "guard" field via
 * `s.buf[n] = 0` with n possibly == sizeof(buf)). Here the off-by-one is
 * a classic fencepost loop bound (`n < sizeof(s.buf) + 1` lets n reach
 * sizeof(s.buf), one past the array), and the byte it clobbers is not a
 * guard flag but the low-order byte of a same-struct function pointer
 * (`s.cb`, declared immediately after `s.buf` -- struct layout in
 * ascending declaration order is guaranteed by the C standard), which the
 * program then calls unconditionally.
 */
#include <stdio.h>
#include <unistd.h>

typedef void (*cb_t)(void);

void safe_path(void) {
    puts("safe path taken");
}

/* The flag is intentionally NOT compiled into this binary (no literal in
 * .rodata that `strings`/ELF.search() could find with zero exploitation).
 * It is generated fresh per build by build_all_r2.sh and written to
 * flag.txt alongside the binary; win() reads it at runtime only after the
 * real bug has actually been exploited. */
static void print_flag(void) {
    FILE *f = fopen("flag.txt", "r");
    if (!f) {
        puts("flag.txt missing");
        return;
    }
    char flag[256];
    if (fgets(flag, sizeof(flag), f)) {
        fputs(flag, stdout);
    }
    fclose(f);
}

void win(void) {
    print_flag();
}

struct frame_s {
    char buf[64];
    cb_t cb;
};

void vuln(void) {
    struct frame_s s;
    s.cb = safe_path;

    printf("data (no newline): ");
    fflush(stdout);

    int n = 0;
    char c;
    /* BUG: fencepost error -- n can reach sizeof(s.buf) (64), one past the
     * array's last valid index (0..63), writing into s.cb's low byte. */
    while (n < (int)sizeof(s.buf) + 1 && read(0, &c, 1) == 1 && c != '\n') {
        s.buf[n] = c;
        n++;
    }

    putchar('\n');
    fflush(stdout);
    s.cb();
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-13 off-by-one partial function-pointer overwrite ===");
    vuln();
    puts("done");
    return 0;
}
