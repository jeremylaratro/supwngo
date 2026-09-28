/*
 * G-23 loop_counter_overflow, variant 11: locals declared in the opposite
 * order from g23_10, so the induction variable and the reloaded bound land
 * at DIFFERENT relative offsets in the frame -- proving the gate derives
 * `BUF`, `I` and `L` from the instructions actually emitted rather than
 * assuming g23_10's specific -0x4/-0x5 layout. Buffer size and stride also
 * differ (96 bytes, still an 8-byte record) so this is not byte-identical
 * machine code to g23_10 by any measure.
 *
 * Same defect: `unsigned char total = (unsigned char)(count * 8)` wraps to
 * zero at count=32 for THIS buffer too (32*8=256 truncates to 0, well under
 * 96), so the same magic count applies.
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
    int i;
    unsigned char count;
    char buf[96];

    printf("records (0-12, 8 bytes each): ");
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
    puts("=== g23-11 swapped-order ===");
    vuln();
    puts("done");
    return 0;
}
