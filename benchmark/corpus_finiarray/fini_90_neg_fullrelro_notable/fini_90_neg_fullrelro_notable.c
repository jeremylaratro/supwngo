/*
 * NEGATIVE CONTROL: fini_10 with the destination removed and nothing else
 * changed.
 *
 * ONE VARIABLE. The write primitive is byte-identical to fini_10's -- same
 * `do_patch()`, same +-4096-slot bound, same `registry` base in `.bss`. The win
 * function is still present and still spawns a shell if anything calls it. The
 * menu, the prompts, the `exit(0)` quit path and the unbuffered stdio are all
 * the same. The ONLY differences are:
 *
 *   * `-z relro -z now` (FULL RELRO), so `.init_array`, `.fini_array`,
 *     `.data.rel.ro`, `.dynamic` and the entire GOT are inside `PT_GNU_RELRO`
 *     and read-only before `main` runs; and
 *   * no program-owned handler table, no `atexit()` registration, and no
 *     function-pointer array of any kind in `.data`/`.bss`.
 *
 * So there is no writable finaliser, no writable initialiser, no writable GOT
 * entry, and no program-owned dispatch table. The primitive is fully intact and
 * there is nothing in its reach to point at code with.
 *
 * WHY THE PRIMITIVE IS LEFT IN PLACE
 * Because removing it would test the wrong thing. A control that also lost the
 * write would be declined for the obvious reason, and the family would prove
 * only that the executor notices a missing primitive. Holding the primitive
 * constant and removing the DESTINATION is what makes a decline here evidence
 * about the destination class -- which is the whole subject of this category.
 *
 * WHAT IS STILL REACHABLE, STATED HONESTLY
 * `registry[-4096 .. 4096]` covers +-32 KiB around a `.bss` address, so the
 * primitive still reaches `.data`, `.bss`, `.got.plt`'s page (read-only here),
 * and the libc FILE pointers glibc keeps in `.bss`. It does NOT reach the stack
 * (0x7ff...) or libc's own writable data, so it cannot be turned into a
 * saved-return-address overwrite, and there is no `__free_hook`-style pointer to
 * find. A file-structure-oriented attack on the `stdout` FILE object is the one
 * route this control does not architecturally forbid; no executor in this
 * framework implements one, and if a future one does, this control will start
 * solving and will need a further cut. Recorded now rather than discovered
 * later.
 *
 * FLAG{supwngo_bench_fini_90_neg_fullrelro_notable}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REG_SLOTS 8
#define PATCH_SPAN 4096L

static unsigned long registry[REG_SLOTS];
static char sh_cmd[16] = "/bin/sh";

void spawn_admin_shell(void)
{
    system(sh_cmd);
}

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

static void do_quit(void)
{
    puts("bye");
    exit(0);
}

int main(void)
{
    long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
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
