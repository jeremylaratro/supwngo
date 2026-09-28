/*
 * G-23 loop_counter_overflow, variant 14: the loop recomputes its limit from
 * a SECOND narrow local rather than reloading the original count directly.
 *
 * `count` is read once and used for the wrap check; `limit` is a separate
 * byte copied from `count` right before the loop, and it is `limit` -- not
 * `count` -- that the loop reloads from memory every iteration
 * (`for (i = 0; i < (int)limit; i++)`). A gate that assumes the reloaded
 * bound is always the SAME local the size check used would miss this: the
 * field a control record has to overwrite here is `limit`'s slot, which sits
 * at a different offset than `count`'s.
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
    unsigned char limit;
    int i;

    printf("records (0-8, 8 bytes each): ");
    fflush(stdout);
    count = read_count();

    unsigned char total = (unsigned char)(count * 8);
    if (total > sizeof(buf)) {
        puts("too many records");
        return;
    }

    limit = count;
    printf("loading %u records...\n", (unsigned)limit);
    fflush(stdout);
    for (i = 0; i < (int)limit; i++) {
        read(0, buf + i * 8, 8);
    }
    puts("loaded");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== g23-14 second-narrow ===");
    vuln();
    puts("done");
    return 0;
}
