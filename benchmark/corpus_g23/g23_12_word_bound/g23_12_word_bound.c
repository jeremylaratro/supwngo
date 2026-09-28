/*
 * G-23 loop_counter_overflow, variant 12: a 16-bit reloaded bound.
 *
 * Same 8-bit truncation on the SIZE CHECK as g23_10 (`(unsigned char)(count *
 * 8)` still wraps to 0 at count=32), but `count` itself -- the field the loop
 * re-reads every iteration to decide whether to keep going -- is now a
 * 16-bit `unsigned short`, not a byte. That is the fact this variant
 * exercises: the loop's reloaded bound (`movzx eax, WORD PTR [rbp-L]`) is a
 * WORD load here, not a BYTE load, so a gate keyed to one specific load width
 * would miss this target even though the wrap arithmetic is identical to
 * g23_10's.
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

static unsigned short read_count(void) {
    char c = 0;
    unsigned int val = 0;
    while (read(0, &c, 1) == 1 && c != '\n') {
        if (c >= '0' && c <= '9') {
            val = val * 10 + (unsigned int)(c - '0');
        }
    }
    return (unsigned short)val;
}

void vuln(void) {
    char buf[64];
    unsigned short count;
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
    puts("=== g23-12 word-bound ===");
    vuln();
    puts("done");
    return 0;
}
