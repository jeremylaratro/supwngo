/*
 * Indirect-call-hijack corpus, group (b) -- what must be known before the pointer can be written.
 *
 * The category: an unsigned size computation decouples the ALLOCATION size
 * from the COPY length over a bump allocator, so a copy runs off the end of a
 * too-small region and overwrites a live object's function pointer, which the
 * program then calls indirectly.
 *
 * THE ARITHMETIC HERE: the anchor's `bump(sz + 1)` wrap, unchanged. What varies is that
 * the image is PIE and the arena is a stack local, so NO address in the
 * final payload is known statically. A SECOND defect supplies the first
 * leak: `rename` fills name[16] to its full width with no room for a
 * NUL, and `show` prints it with %s, which then runs into the adjacent
 * `note` pointer. The hijacked (note, print) pair is then used as an
 * ARBITRARY READ -- write note, leave print intact, print the object --
 * to recover a live code pointer and with it the image base.
 *
 * WRAPPING INPUT: sz == 18446744073709551615 (2**64-1), as the anchor.
 *
 * FLAG{supwngo_bench_objptr_25_pie_leak_first}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Held fixed across group (b). */
#define ARENA   0xC0
#define NOBJ    4
#define COPYCAP 0x100

typedef struct {
    char  name[16];      /* +0  */
    char *note;          /* +16 */
    void (*print)(char *); /* +24 -- the hijack target */
} Obj;                   /* sizeof == 32 */

/* The arena and the object table are members of ONE struct, in this order, so
 * that "the copy runs forward out of the arena into the object table" is a
 * language guarantee rather than a layout accident. */
struct pool {
    char arena[ARENA];   /* +0x00 */
    Obj  objs[NOBJ];     /* +0xC0 .. +0x140 */
};

static void pr(char *s)
{
    printf("note: [%s]\n", s);
}

/* The payoff. Takes (and ignores) a char* so that it matches the `print`
 * member's type exactly -- the hijack needs no argument control at all. */
void spawn_shell(char *ignored)
{
    (void)ignored;
    system("/bin/sh");
}

static struct pool *P;
static size_t top;
static int nobj;

/* Bump allocator over the pool's arena. Deliberately does NO rounding, so this
 * variant's only size defect is the one marked at the call site. */
static char *bump(size_t n)
{
    char *p;

    if (top + n > ARENA)
        return NULL;
    p = P->arena + top;
    top += n;
    return p;
}

int main(void)
{
    struct pool pool;   /* THE ARENA IS A LOCAL ARRAY IN main() */
    unsigned long choice, idx, sz;

    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&pool, 0, sizeof pool);
    P = &pool;

    for (;;) {
        fputs("> Choice: ", stdout);
        if (scanf("%lu", &choice) != 1)
            return 0;
        if (choice == 1) {
            if (nobj == NOBJ) {
                puts("pool full");
                continue;
            }
            strcpy(P->objs[nobj].name, "obj");
            P->objs[nobj].note = bump(16);
            P->objs[nobj].print = pr;
            printf("Object ID: %d\n", nobj);
            nobj++;
        } else if (choice == 2) {
            fputs("Object ID: ", stdout);
            if (scanf("%lu", &idx) != 1)
                return 0;
            if (idx >= (unsigned long)nobj) {
                puts("bad id");
                continue;
            }
            fputs("Note size: ", stdout);
            if (scanf("%lu", &sz) != 1)
                return 0;
            /* THE DEFECT: as the anchor. */
            P->objs[idx].note = bump(sz + 1);
            if (P->objs[idx].note == NULL) {
                puts("no space");
                continue;
            }
            fputs("Note: ", stdout);
            read(0, P->objs[idx].note, sz > COPYCAP ? COPYCAP : sz + 1);
        } else if (choice == 3) {
            fputs("Object ID: ", stdout);
            if (scanf("%lu", &idx) != 1)
                return 0;
            if (idx >= (unsigned long)nobj) {
                puts("bad id");
                continue;
            }
            /* THE LEAK: name[] is printed with %s. `rename` below fills all 16
             * bytes, so there is no terminator and this runs straight into the
             * `note` pointer that follows it. */
            printf("name: %s\n", P->objs[idx].name);
            /* The indirect call. `print` is reloaded from the object every
             * time, so whatever the copy above left there is what runs. */
            P->objs[idx].print(P->objs[idx].note);
        } else if (choice == 4) {
            return 0;
        } else if (choice == 5) {
            fputs("Object ID: ", stdout);
            if (scanf("%lu", &idx) != 1)
                return 0;
            if (idx >= (unsigned long)nobj) {
                puts("bad id");
                continue;
            }
            fputs("New name: ", stdout);
            /* THE SECOND DEFECT: 16 bytes into a 16-byte array. Every other
             * site writes a terminated string; this one leaves none. */
            read(0, P->objs[idx].name, sizeof(P->objs[idx].name));
        } else {
            puts("1 New / 2 Note / 3 Show / 4 Exit");
        }
    }
}
