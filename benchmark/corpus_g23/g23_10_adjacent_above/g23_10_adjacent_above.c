/*
 * G-23 loop_counter_overflow, variant 10: the reference shape.
 *
 * This is deliberately the closest possible relative of
 * benchmark/corpus_r2/08_int_mul_overflow/int_mul_overflow.c -- G-23 exists
 * BECAUSE that target is solved by nothing in the ladder (see
 * docs/plans/2026-09-28-g23-loop-counter-overflow-plan.md), and the first
 * positive in this family has to be the shape that motivated the category:
 * an 8-bit multiplication overflow gates a record-count loop whose OWN
 * induction variable and reloaded bound live inside the region the overflow
 * reaches.
 *
 * `unsigned char total = (unsigned char)(count * 8)` wraps for count=32
 * (32*8=256, truncated to 0), passing `total <= sizeof(buf)` while the
 * un-truncated `count` still drives 32 iterations of an 8-byte read() into a
 * 64-byte buffer. The loop reloads `count` from its own stack slot every
 * iteration (`for (i = 0; i < (int)count; i++)`), and both `count` and `i`
 * sit ABOVE `buf` in the frame -- closer to `rbp` than `buf`'s own base --
 * which is what makes the induction variable and the loop bound themselves
 * part of the overflow's reach rather than bystanders to it.
 */
#include <stdio.h>
#include <unistd.h>

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
    unsigned char count;
    int i;

    printf("records (0-8, 8 bytes each): ");
    fflush(stdout);
    count = read_count();

    unsigned char total = (unsigned char)(count * 8);
    if (total > sizeof(buf)) {
        puts("too many records");
        return;
    }

    printf("loading %u records...\n", (unsigned)count);
    fflush(stdout);
    for (i = 0; i < (int)count; i++) {
        read(0, buf + i * 8, 8);
    }
    puts("loaded");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== g23-10 adjacent-above ===");
    vuln();
    puts("done");
    return 0;
}
