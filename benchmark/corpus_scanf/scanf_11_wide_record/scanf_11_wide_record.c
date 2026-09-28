/*
 * Unbounded scanf/strtoull scalar-and-buffer overwrite on PIE + canary +
 * Full RELRO -- VARIANT.
 *
 * VARIES, versus scanf_10_fnptr_struct: THE BUFFER SIZE, and nothing else.
 * `name[]` is 160 bytes instead of 32 and the leak array holds 24 qwords
 * instead of 8. Every other thing is byte-for-byte the anchor: the same
 * `get_number()`, the same struct-with-a-trailing-function-pointer, the same
 * out-of-range index read, the same menu, the same protections.
 *
 * WHY THIS IS A REAL VARIATION AND NOT A COSMETIC ONE
 * An implementation shaped around one measured target bakes in two numbers: the
 * distance from the overflowed buffer to the thing worth overwriting, and the
 * index at which the leak array runs into the canary. Both move here, in
 * opposite directions, and neither is recoverable from a "try 32, then 40, then
 * 64" table. They ARE recoverable from the frame: the scanf destination and the
 * indirect-call slot are both rbp-relative in the disassembly, and so is the
 * leak array's base. Deriving beats guessing, which is the point of the row.
 *
 * FLAG{supwngo_bench_scanf_11_wide_record}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_LEN 160
#define NSLOT 24

struct record {
    char name[NAME_LEN];
    void (*show)(const char *);
};

void spawn_admin_shell(void)
{
    system("/bin/sh");
}

static void show_plain(const char *name)
{
    printf("record: %s\n", name);
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

static void edit_record(void)
{
    struct record r;

    memset(&r, 0, sizeof(r));
    r.show = show_plain;
    printf("name: ");
    if (scanf("%s", r.name) != 1)
        exit(0);
    r.show(r.name);
}

int main(void)
{
    unsigned long long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("*** record editor ***");
    for (;;) {
        puts("1 - edit record");
        puts("2 - dump slot");
        puts("3 - exit");
        printf("choice: ");
        choice = get_number();
        if (choice == 1)
            edit_record();
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
