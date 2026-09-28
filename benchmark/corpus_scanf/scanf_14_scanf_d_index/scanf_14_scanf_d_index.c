/*
 * Unbounded scanf/strtoull scalar-and-buffer overwrite on PIE + canary +
 * Full RELRO -- VARIANT.
 *
 * VARIES, versus scanf_10_fnptr_struct: HOW THE SCALAR ARRIVES AND WHAT IT
 * DRIVES. There is no overflowed buffer in the vulnerable handler at all. The
 * index comes from `scanf("%d", &n)` -- the `%d`-driven half of the category --
 * and it is used as a subscript into a fixed stack array with no range check, so
 * `slots[n] = v` is a single, precisely aimed 8-byte stack write.
 *
 * WHY THAT IS A DIFFERENT CAPABILITY
 * Nothing linear happens here: there is no pad to compute, no canary in the way
 * (the write skips over it entirely, so the canary is never disturbed and its
 * value is never needed), and the value written arrives as a DECIMAL STRING
 * through `strtoull()` -- so the byte restrictions that dominate every `%s` row
 * in this family (no NUL, no whitespace) simply do not apply, and a full 64-bit
 * address is expressible. An implementation that has only learned "fill a buffer
 * until you reach the return address" has nothing to do here; the capability
 * required is to notice the subscript is unchecked and to compute which
 * subscript IS the saved return address.
 *
 * `slots[]` is the same array the leak reads out of range, which is the honest
 * shape of this bug in the wild: one unchecked subscript, used for both a read
 * and a write.
 *
 * FLAG{supwngo_bench_scanf_14_scanf_d_index}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NSLOT 8

void spawn_admin_shell(void)
{
    system("/bin/sh");
}

static unsigned long long get_number(void)
{
    char line[32];

    memset(line, 0, sizeof(line));
    if (scanf("%s", line) != 1)
        exit(0);
    return strtoull(line, NULL, 10);
}

static void dump_slot(void)
{
    unsigned long long slots[NSLOT];
    unsigned long long idx;

    memset(slots, 0, sizeof(slots));
    printf("slot: ");
    idx = get_number();
    printf("slot[%llu] = %llu\n", idx, slots[idx]);
}

/* The overwrite: `n` comes from scanf("%d") and is used as a subscript with
 * nothing comparing it to NSLOT. */
static void set_slot(void)
{
    unsigned long long slots[NSLOT];
    unsigned long long v;
    int n;

    memset(slots, 0, sizeof(slots));
    printf("index: ");
    if (scanf("%d", &n) != 1)
        exit(0);
    printf("value: ");
    v = get_number();
    slots[n] = v;
    printf("slot[%d] set\n", n);
}

int main(void)
{
    unsigned long long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("*** slot editor ***");
    for (;;) {
        puts("1 - set slot");
        puts("2 - dump slot");
        puts("3 - exit");
        printf("choice: ");
        choice = get_number();
        if (choice == 1)
            set_slot();
        else if (choice == 2)
            dump_slot();
        else if (choice == 3)
            break;
        else
            puts("?");
    }
    puts("bye");
    return 0;
}
