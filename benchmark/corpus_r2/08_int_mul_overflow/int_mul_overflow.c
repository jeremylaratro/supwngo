/*
 * Round-2 Target 08: integer/size-arithmetic bug -- an 8-bit
 * multiplication overflow in a size calculation used to gate a
 * record-count loop, distinct from round-1's 10_int_overflow (which
 * truncated a raw length value with no multiplication involved at all).
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * The program accepts a record count (0-255, `unsigned char`), each
 * record being a fixed 8 bytes, into a 64-byte `buf` (max 8 legitimate
 * records). The size check computes `len * 8` and truncates the product
 * back to `unsigned char` (classic CWE-190 pattern: size = count *
 * elem_size, computed/checked in a type too narrow for the real result)
 * *before* comparing it against `sizeof(buf)` -- so len=32 makes
 * `(unsigned char)(32*8)` wrap to 0, passing the "total_bytes <= 64"
 * check, while the actual copy loop below still runs the full,
 * untruncated `len` (32) iterations of 8-byte reads (256 bytes total)
 * into the 64-byte buffer: a clean, controlled stack overflow gated by
 * an integer-overflowed bounds check.
 *
 * The record count is parsed via a raw read() + manual digit parse
 * rather than scanf(): glibc's buffered stdio performs its own readahead
 * on the underlying fd, which can silently steal bytes intended for the
 * later raw read() calls in the copy loop when they share fd 0 -- a real
 * bug hit while building this target (scanf's internal buffer grabbed
 * part of the attacker's payload before the loop ever saw it). Avoiding
 * stdio for the count keeps the raw read() loop's byte accounting exact
 * and deterministic, matching the read()-only idiom used elsewhere in
 * this corpus.
 */
#include <stdio.h>
#include <unistd.h>

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
        fputs(flag, stdout); /* flag.txt already ends in '\n' */
    }
    fclose(f);
}

void win(void) {
    print_flag();
}

static unsigned char read_count(void) {
    char c = 0;
    unsigned char val = 0;
    while (read(0, &c, 1) == 1 && c != '\n') {
        if (c >= '0' && c <= '9') {
            val = (unsigned char)(val * 10 + (c - '0'));
        }
    }
    return val;
}

void vuln(void) {
    char buf[64];
    unsigned char len;
    int i;

    printf("records (0-8, 8 bytes each): ");
    fflush(stdout);
    len = read_count();

    /* BUG: the size check is computed and compared in 8-bit arithmetic,
     * so it wraps for len values well past the intended 0-8 range. */
    unsigned char total_bytes = (unsigned char)(len * 8);
    if (total_bytes > sizeof(buf)) {
        puts("too many records");
        return;
    }

    printf("loading %u records...\n", (unsigned)len);
    fflush(stdout);
    for (i = 0; i < (int)len; i++) {
        read(0, buf + i * 8, 8); /* untruncated len drives real byte count */
    }
    puts("loaded");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-08 int-mul-overflow ===");
    vuln();
    puts("done");
    return 0;
}
