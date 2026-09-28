/*
 * Indirect-call-hijack corpus, group (b) -- ANCHOR (matches the measured auth-or-out arithmetic).
 *
 * The category: an unsigned size computation decouples the ALLOCATION size
 * from the COPY length over a bump allocator, so a copy runs off the end of a
 * too-small region and overwrites a live object's function pointer, which the
 * program then calls indirectly.
 *
 * THE ARITHMETIC HERE: `bump(sz + 1)`. The +1 is computed in size_t, so a request of
 * 2**64-1 wraps to an allocation of 0 while the copy length is clamped
 * separately to COPYCAP. Arena: a LOCAL array in main().
 *
 * WRAPPING INPUT: sz == 18446744073709551615 (2**64-1) -- exactly one value, because
 * this allocator does no rounding.
 *
 * FLAG{supwngo_bench_objptr_20_add_wrap_local_arena}
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
            P->objs[nobj].note = NULL;
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
            /* THE DEFECT: sz + 1 wraps to 0, so a zero-byte region is handed
             * back for a copy of up to COPYCAP bytes. */
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
            /* The indirect call. `print` is reloaded from the object every
             * time, so whatever the copy above left there is what runs. */
            P->objs[idx].print(P->objs[idx].note);
        } else if (choice == 4) {
            return 0;
        } else {
            puts("1 New / 2 Note / 3 Show / 4 Exit");
        }
    }
}
