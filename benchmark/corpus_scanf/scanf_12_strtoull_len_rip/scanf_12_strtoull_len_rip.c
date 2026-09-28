/*
 * Unbounded scanf/strtoull scalar-and-buffer overwrite on PIE + canary +
 * Full RELRO -- VARIANT.
 *
 * VARIES, versus scanf_10_fnptr_struct: WHERE THE OVERWRITE LANDS, and the
 * input function that delivers it. The overwrite reaches the SAVED RETURN
 * ADDRESS rather than a local function pointer, because the write is no longer a
 * `%s` -- it is a `read(0, note, len)` whose `len` is the raw `strtoull()`
 * result with no range check at all.
 *
 * WHY THAT CHANGES THE SOLVE RATHER THAN JUST THE SOURCE
 * `%s` cannot emit a NUL byte and a canary's low byte IS 0x00, so the anchor's
 * overflow structurally could not cross the canary -- it had to stop at a slot
 * below it. `read()` has no such restriction, so this row's write goes straight
 * through the canary to the saved return address. That makes the canary LEAK
 * load-bearing for the first time in the family: the anchor never needed the
 * canary's value, and an implementation that only ever learned to leak a code
 * address will corrupt the canary here and be killed by __stack_chk_fail before
 * the function can return. The leak oracle is unchanged and already discloses
 * it -- `slots[]` ends exactly where the canary begins -- so the capability
 * required is to notice that it must be used, not to find a new oracle.
 *
 * `flush_line()` exists because a raw `read()` follows a `scanf()` on the same
 * descriptor: scanf pushes the delimiter back into the FILE, which a subsequent
 * read(2) would never see, and the fixture must not leave that ambiguity for an
 * exploit to trip over. It is not a category particular.
 *
 * FLAG{supwngo_bench_scanf_12_strtoull_len_rip}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOT 8
#define NOTE_LEN 64

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

/* The overwrite: `len` is the strtoull() result, used as the read() length with
 * nothing comparing it to sizeof(note). */
static void load_note(void)
{
    char note[NOTE_LEN];
    unsigned long long len;

    memset(note, 0, sizeof(note));
    printf("size: ");
    len = get_number();
    flush_line();
    printf("note: ");
    if (read(0, note, len) < 0)
        exit(0);
    printf("stored %llu bytes\n", len);
}

int main(void)
{
    unsigned long long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("*** note editor ***");
    for (;;) {
        puts("1 - load note");
        puts("2 - dump slot");
        puts("3 - exit");
        printf("choice: ");
        choice = get_number();
        if (choice == 1)
            load_note();
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
