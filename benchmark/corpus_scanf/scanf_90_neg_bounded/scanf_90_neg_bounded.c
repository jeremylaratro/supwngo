/*
 * Unbounded scanf/strtoull scalar-and-buffer overwrite on PIE + canary +
 * Full RELRO -- NEGATIVE CONTROL. MUST NOT SOLVE.
 *
 * Byte-for-byte scanf_10_fnptr_struct except for two added bounds:
 *
 *   1. the record name is read with `scanf("%31s", r.name)` instead of
 *      `scanf("%s", r.name)`, so the write can no longer reach `show`; and
 *   2. the leak subscript is compared to NSLOT before use, so the out-of-range
 *      read that disclosed the canary and a PIE code address is gone.
 *
 * Either bound alone would be enough to make the target unexploitable. Both are
 * present because the control's job is to be unsolvable for a reason that is
 * about the CATEGORY, not about how much of it a particular implementation
 * happened to need: with (1) there is no unbounded write to a reachable slot,
 * and with (2) there is no address to aim one at even if there were.
 *
 * WHAT IS DELIBERATELY *NOT* REMOVED
 * `get_number()` still does `scanf("%s", line)` with no field width -- the
 * category's own signature, unchanged, in the same helper every positive in this
 * family shares. It is left in because it is structurally unexploitable in EVERY
 * target here, positive or control: -fstack-protector hoists `line[]` to the top
 * of get_number's frame, so the only thing above it is the canary, and `%s`
 * cannot write the canary's 0x00 low byte -- a long enough token reaches
 * __stack_chk_fail and nothing else. Keeping it means this control still presents
 * every surface feature an implementation keys on (an unbounded `__isoc99_scanf`,
 * a `strtoull` result used raw, a struct with a trailing function pointer that is
 * called, a `spawn_admin_shell` in the image, a menu, PIE + canary + Full RELRO),
 * and differs from the anchor only in whether the bug is exploitable. A success
 * here therefore means the corpus is reporting that RECOGNISING the pattern
 * counts as exploiting it, and invalidates every positive result beside it.
 *
 * FLAG{supwngo_bench_scanf_90_neg_bounded}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_LEN 32
#define NSLOT 8

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
    char line[NAME_LEN];

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
    /* THE BOUND (2): the subscript is checked, so there is no leak. */
    if (idx >= NSLOT) {
        puts("index out of range");
        return;
    }
    printf("slot[%llu] = %llu\n", idx, slots[idx]);
}

static void edit_record(void)
{
    struct record r;

    memset(&r, 0, sizeof(r));
    r.show = show_plain;
    printf("name: ");
    /* THE BOUND (1): a field width, so `show` is out of reach. */
    if (scanf("%31s", r.name) != 1)
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
