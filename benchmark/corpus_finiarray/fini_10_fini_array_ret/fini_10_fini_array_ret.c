/*
 * Hijacking a writable initialiser/finaliser table (CWE-787) -- ANCHOR.
 *
 * THE CATEGORY IS A DESTINATION, NOT A PRIMITIVE.
 * Every target in this family hands the operator the SAME write primitive -- a
 * bounded index write whose bound is wrong by three orders of magnitude -- and
 * varies only WHICH TABLE OF FUNCTION POINTERS that write is aimed at and HOW
 * THAT TABLE IS REACHED. The framework already knows two destinations for a
 * single arbitrary write (the GOT, via `tcache_poison_got`; a function pointer
 * inside a heap record, via `heap_record_hijack`). The one it does not know is
 * the loader's own exit machinery: `.fini_array`, `.init_array`, and a
 * program's own `atexit`-style handler table.
 *
 * WHAT THIS TARGET IS
 * The fixed point of the family. `.fini_array` holds exactly ONE entry
 * (`__do_global_dtors_aux`, which the compiler puts there unconditionally), the
 * image is linked `-z norelro` so that entry is writable, and `main`'s quit
 * command calls `exit(0)`. So:
 *
 *     registry[(fini_array - registry) / 8] = &spawn_admin_shell
 *     3                                        <- quit
 *     -> exit(0) -> __run_exit_handlers -> _dl_fini -> call_fini
 *     -> the single .fini_array entry is now spawn_admin_shell
 *
 * No ROP, no stack pivot, no leak, and nothing on the stack is touched. The
 * program's own termination path is the trigger.
 *
 * WHY `-z norelro` AND NOT `-z relro`
 * MEASURED on this host (gcc 13 / GNU ld, 2026-09-28), not assumed: with
 * PARTIAL RELRO -- which is gcc's DEFAULT -- `PT_GNU_RELRO` already covers
 * `.init_array`, `.fini_array`, `.data.rel.ro`, `.dynamic` and `.got`; only
 * `.got.plt`, `.data` and `.bss` stay writable. A write to `.fini_array[0]` in
 * a partial-RELRO image takes SIGSEGV. The often-repeated claim that "Partial
 * RELRO leaves .fini_array writable" is false on a modern toolchain: the
 * loader-table route needs NO RELRO at all. That measurement is why the RELRO
 * setting is pinned per target in this family's `cflags` files rather than
 * shared, and it is the fact the family exists to make un-guessable.
 *
 * THE DEFECT ITSELF (held identical across all six targets)
 * `do_patch()` reads a signed slot index and an unsigned 64-bit value, checks
 * the index against +-4096, and then stores. The check is real -- which is what
 * makes it a BOUNDED index write rather than an unbounded one -- and it is
 * useless: +-4096 slots is +-32 KiB, which spans the whole of the image's
 * writable data including every loader table. It deliberately does NOT reach
 * the stack (0x7ff...) or libc, so this primitive cannot be turned into a
 * return-address overwrite; the only thing it can reach is a table.
 *
 * FLAG{supwngo_bench_fini_10_fini_array_ret}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REG_SLOTS 8
/* The bound that exists and is wrong. 4096 slots x 8 bytes = 32 KiB either
 * way. Every loader table in this image is within 1 KiB of `registry`. */
#define PATCH_SPAN 4096L

/* The write primitive's base. In .bss, at a fixed address because the image is
 * -no-pie -- which is the whole reason a single write is enough here: the
 * destination address is a link-time constant, so nothing has to be leaked. */
static unsigned long registry[REG_SLOTS];

/* The command `spawn_admin_shell` runs. A writable global rather than a string
 * literal so that this function is BYTE-IDENTICAL across the family -- one
 * variant (fini_11) keeps this buffer masked until a destructor unmasks it, and
 * holding the win function constant is what makes that variant's axis point
 * visible instead of confounded. */
static char sh_cmd[16] = "/bin/sh";

/* The privileged path. No menu command calls it; reaching it means something
 * redirected a call through a table. External linkage so the compiler cannot
 * discard it as unreachable. */
void spawn_admin_shell(void)
{
    system(sh_cmd);
}

/* THE DEFECT (CWE-787: out-of-bounds write). */
static void do_patch(void)
{
    long slot;
    unsigned long value;

    printf("slot: ");
    if (scanf("%ld", &slot) != 1)
        _exit(1);
    printf("value: ");
    if (scanf("%lu", &value) != 1)
        _exit(1);
    if (slot < -PATCH_SPAN || slot > PATCH_SPAN) {
        puts("slot out of range");
        return;
    }
    registry[slot] = value;
    puts("patched");
}

static void do_show(void)
{
    printf("registry[0] = %lu\n", registry[0]);
}

/* The trigger. `exit(0)` rather than `_exit(0)`: that is the difference between
 * an image whose .fini_array is REACHABLE and one whose .fini_array is merely
 * writable. fini_13 is the same program with `_exit`, and its .fini_array never
 * runs. */
static void do_quit(void)
{
    puts("bye");
    exit(0);
}

int main(void)
{
    long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    /* Unbuffered stdin: stdio would otherwise pull the operator's follow-on
     * bytes into its own buffer, and the shell this target is made to spawn
     * would then see EOF instead of them. */
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("*** slot registry ***");
    for (;;) {
        puts("1 - patch slot");
        puts("2 - show slot 0");
        puts("3 - quit");
        printf("choice: ");
        if (scanf("%ld", &choice) != 1)
            _exit(1);
        if (choice == 1)
            do_patch();
        else if (choice == 2)
            do_show();
        else if (choice == 3)
            do_quit();
        else
            puts("unknown option");
    }
}
