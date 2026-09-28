/*
 * Indirect-call-hijack corpus, group (a) -- how the pointer is reached.
 *
 * The category: a function pointer that the program later CALLS is reachable
 * from attacker-controlled bytes. The hijack lands on a live call site, not on a
 * saved return address, so it fires in the middle of a function and a stack
 * canary never gets a chance to notice.
 *
 * VARIES FROM THE ANCHOR: nothing overflows. The program dispatches through a TABLE of
 * function pointers using an index it only bounds-checks UPWARDS, and the
 * index is signed -- so a negative index reads a "pointer" out of the
 * note buffer the operator filled in a moment earlier. A solver that looks
 * for an overflow finds nothing here.
 *
 * FLAG{supwngo_bench_fnptr_13_unchecked_table_index}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


void spawn_shell(void)
{
    system("/bin/sh");
}

/* One struct, so the note buffer is guaranteed to sit immediately below the
 * table rather than wherever the linker felt like putting it. */
struct dispatch {
    char note[64];
    void (*handlers[4])(void);
};

static struct dispatch T;

static void h_status(void) { puts("status: ok"); }
static void h_version(void) { puts("version: 1.0"); }
static void h_uptime(void) { puts("uptime: unknown"); }
static void h_help(void) { puts("handlers: 0..3"); }

int main(void)
{
    int idx;

    setvbuf(stdout, NULL, _IONBF, 0);
    T.handlers[0] = h_status;
    T.handlers[1] = h_version;
    T.handlers[2] = h_uptime;
    T.handlers[3] = h_help;

    fputs("note: ", stdout);
    read(0, T.note, sizeof(T.note));

    fputs("handler index: ", stdout);
    if (scanf("%d", &idx) != 1)
        return 1;

    /* THE DEFECT: `idx` is signed and only the upper bound is checked, so a
     * negative index reads a function pointer from before the table -- which is
     * where `note` lives. */
    if (idx > 3) {
        puts("bad index");
        return 1;
    }

    T.handlers[idx]();
    return 0;
}
