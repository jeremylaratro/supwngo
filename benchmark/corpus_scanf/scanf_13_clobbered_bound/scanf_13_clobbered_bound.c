/*
 * Unbounded scanf/strtoull scalar-and-buffer overwrite on PIE + canary +
 * Full RELRO -- VARIANT.
 *
 * VARIES, versus scanf_10_fnptr_struct: WHICH SCALAR THE %s CLOBBERS. The
 * anchor's struct member is a function pointer, called immediately; here the
 * member is `cap`, the LOOP BOUND that governs the copy that follows. So the
 * unbounded `%s` does not hijack anything by itself -- it reprograms the bound,
 * and the now-unbounded copy does the hijacking.
 *
 * WHY THAT IS A DIFFERENT CAPABILITY
 * The anchor's solve is one write to one slot with one value. This one is a
 * two-step: the first write must clobber a *bound* (any large value will do, and
 * the shortest way to a large value is one non-NUL byte plus scanf's own NUL
 * terminator), and only then is there a write primitive big enough to reach the
 * saved return address -- through the canary, so the canary's leaked value has to
 * be replaced correctly on the way past. An implementation that treats "the
 * slot above the buffer" as always being the thing to point at code will write a
 * code address into `cap`, get a copy bound of some huge number, and then have no
 * second payload to put there.
 *
 * `flush_line()` exists because a raw `read()` follows a `scanf()` on the same
 * descriptor; see scanf_12's header. It is not a category particular.
 *
 * FLAG{supwngo_bench_scanf_13_clobbered_bound}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOT 8
#define TAG_LEN 32

struct blob {
    char tag[TAG_LEN];
    unsigned long long cap;
};

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

static void flush_line(void)
{
    int c;

    while ((c = getchar()) != '\n' && c != EOF)
        ;
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

/* The overwrite: `tag` is filled by an unbounded %s, and `cap` -- the bound the
 * body copy trusts -- is the very next member of the same struct. */
static void load_blob(void)
{
    struct blob b;

    memset(&b, 0, sizeof(b));
    b.cap = TAG_LEN;
    printf("tag: ");
    if (scanf("%s", b.tag) != 1)
        exit(0);
    flush_line();
    printf("body: ");
    if (read(0, b.tag, b.cap) < 0)
        exit(0);
    printf("cap was %llu\n", b.cap);
}

int main(void)
{
    unsigned long long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("*** blob editor ***");
    for (;;) {
        puts("1 - load blob");
        puts("2 - dump slot");
        puts("3 - exit");
        printf("choice: ");
        choice = get_number();
        if (choice == 1)
            load_blob();
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
