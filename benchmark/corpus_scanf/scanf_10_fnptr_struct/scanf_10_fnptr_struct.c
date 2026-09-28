/*
 * Unbounded scanf/strtoull scalar-and-buffer overwrite on PIE + canary +
 * Full RELRO -- ANCHOR.
 *
 * The category: a fixed-size stack buffer (or a scalar that guards a bound)
 * written through an input function with NO length limit --
 * `__isoc99_scanf("%s", buf)`, or a `strtoull()`/`scanf("%d")` result used as a
 * length or an index with no range check -- in an image that is PIE + canary +
 * Full RELRO + NX, so nothing is exploitable until something is leaked.
 *
 * This target is the fixed point of the family: it reproduces the shape of the
 * measured HTB target (auth-or-out) as closely as a standalone file can -- a
 * numeric menu, a `get_number()` helper that does `scanf("%s", line)` into a
 * 32-byte stack buffer and hands the text to `strtoull()`, a record struct whose
 * last member is a live function pointer, and an index taken straight from
 * `get_number()` with nothing comparing it to the array's bound.
 *
 * It exists so that a variant failure can be told apart from a corpus-wide
 * mistake. It is NOT a capability claim.
 *
 * WHY THE LEAK IS PART OF THE TARGET
 * With PIE + Full RELRO a fixed address is worth nothing: the GOT is read-only
 * and every code address moves per run. So each positive in this family
 * discloses something usable. Here it is an out-of-range index READ: `slots`
 * holds NSLOT qwords and ends exactly where the canary begins, so
 *
 *     slots[NSLOT]      is this frame's canary
 *     slots[NSLOT + 1]  is this frame's saved rbp
 *     slots[NSLOT + 2]  is this frame's saved return address -> PIE base
 *
 * and one out-of-range read discloses either.
 *
 * WHY THE OVERWRITE STOPS BELOW THE CANARY
 * `scanf("%s")` cannot emit a NUL byte, and the canary's low byte IS 0x00, so a
 * %s overflow can never cross a canary and keep it intact. That is not a
 * weakness of the fixture, it is the defining constraint of this half of the
 * category: the reachable target has to be something that lives BELOW the
 * canary. Here it is `struct record`'s trailing `show` pointer -- members of a
 * struct are not reordered by -fstack-protector, so the overflow of `name[]`
 * lands on `show` while the canary above is never touched. `show` already holds
 * a 6-byte PIE code address, so its two high bytes are already 0x00 and writing
 * 6 bytes plus scanf's own NUL terminator reconstitutes a whole, valid pointer.
 *
 * Variants that DO reach a saved return address exist in this family
 * (scanf_12, scanf_13, scanf_14); they get there through an unbounded `read()`
 * or an unchecked index store, neither of which is restricted to non-NUL bytes.
 *
 * FLAG{supwngo_bench_scanf_10_fnptr_struct}
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

/* The privileged path. No menu command calls it; reaching it means the caller
 * redirected control flow, which is the whole exercise. External linkage so the
 * compiler cannot discard it as unused. */
void spawn_admin_shell(void)
{
    system("/bin/sh");
}

static void show_plain(const char *name)
{
    printf("record: %s\n", name);
}

/* Half one of the category: an unbounded %s into a fixed 32-byte stack buffer,
 * whose text is then handed to strtoull() with no range check on the result.
 *
 * The overflow of `line` itself is NOT the exploitable one: -fstack-protector
 * hoists arrays to the top of the frame, so above `line` there is only the
 * canary, and %s cannot write the canary's NUL low byte. It is the value
 * get_number() RETURNS that is dangerous, because every caller uses it raw. */
static unsigned long long get_number(void)
{
    char line[NAME_LEN];

    memset(line, 0, sizeof(line));
    if (scanf("%s", line) != 1)
        exit(0);
    return strtoull(line, NULL, 10);
}

/* The leak: an index straight out of get_number() into a fixed stack array,
 * with nothing comparing it to NSLOT. */
static void dump_slot(void)
{
    unsigned long long slots[NSLOT];
    unsigned long long idx;

    memset(slots, 0, sizeof(slots));
    printf("slot: ");
    idx = get_number();
    printf("slot[%llu] = %llu\n", idx, slots[idx]);
}

/* The overwrite: `name` is filled by an unbounded %s and `show` is the very
 * next member of the same struct. */
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
    /* Unbuffered stdin, as the measured target does: it keeps stdio from
     * swallowing bytes that belong to whatever the exploit spawns. */
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
