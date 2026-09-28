/*
 * G-23 loop_counter_overflow, variant 13: a 16-byte record stride.
 *
 * Every other variant in this family reads 8-byte records; this one reads
 * 16-byte records, so the control record has room for the induction
 * variable AND the reloaded bound with more slack, and the derivation's
 * `stride = 1 << K` must come out as 16 rather than 8. The wrap arithmetic
 * itself is unchanged: `(unsigned char)(count * 16)` truncates to 0 at
 * count=16 (16*16=256).
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

    printf("records (0-4, 16 bytes each): ");
    fflush(stdout);
    count = read_count();

    unsigned char total = (unsigned char)(count * 16);
    if (total > sizeof(buf)) {
        puts("too many records");
        return;
    }

    printf("loading %u records...\n", (unsigned)count);
    fflush(stdout);
    for (i = 0; i < (int)count; i++) {
        read(0, buf + i * 16, 16);
    }
    puts("loaded");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== g23-13 stride16 ===");
    vuln();
    puts("done");
    return 0;
}
