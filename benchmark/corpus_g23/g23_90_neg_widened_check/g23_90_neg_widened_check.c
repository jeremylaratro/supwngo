/*
 * G-23 loop_counter_overflow, NEGATIVE CONTROL.
 *
 * Statically the same shape as g23_10 in every respect this family's gate
 * inspects: a `read()` inside a backward-branching loop, a destination
 * computed as `buf + i*8` from a `lea` plus a scaled load of an `int` stack
 * local, and a loop condition that reloads its bound from memory every
 * iteration via `movzx eax, BYTE PTR [rbp-L]; cmp DWORD PTR [rbp-I],eax` --
 * with `I` and `L` still sitting closer to `rbp` than `buf`'s own base. A
 * gate keyed on any of those facts alone cannot tell this apart from g23_10,
 * and it is not supposed to (see typeconfusion_techniques.py's own control
 * for the same design choice in this codebase: the refusal belongs at the
 * live-measurement layer, not the static gate).
 *
 * What is DIFFERENT, and is a runtime fact rather than a static one: the size
 * check is computed in `unsigned int` -- wide enough that `count * 8` for any
 * `unsigned char count` (0-255) never wraps. `total > sizeof(buf)` therefore
 * genuinely rejects every count whose real byte count would exceed the
 * buffer, and the loop can never run more than 8 iterations (64/8). There is
 * no count that both passes the check and reaches record 9, so the derived
 * exploit -- and every other technique in the ladder -- has nothing to work
 * with here.
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

    /* FIX relative to g23_10: computed and compared in `unsigned int`, so
     * `count * 8` (max 255*8 == 2040) never wraps. The check is honest. */
    unsigned int total = (unsigned int)count * 8u;
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
    puts("=== g23-90 negative: widened check ===");
    vuln();
    puts("done");
    return 0;
}
