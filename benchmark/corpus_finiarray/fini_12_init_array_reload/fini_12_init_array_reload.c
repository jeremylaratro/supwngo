/*
 * Hijacking a writable INITIALISER table -- `.init_array`, re-walked mid-run.
 *
 * Same write primitive as fini_10, same `-z norelro`. The axis point is WHICH
 * TABLE and WHEN IT FIRES.
 *
 * THE ASSUMPTION THIS BREAKS: "a loader table fires at process termination, and
 * a write that arrives after the loader has already walked it is too late".
 *
 * `.init_array` is walked once, by the loader, before `main` -- long before any
 * operator input exists, so the classic `.init_array` overwrite needs a second
 * process invocation or a persisted image. This target reaches the same table
 * without either, because the PROGRAM WALKS IT AGAIN ITSELF: `do_reload()` is a
 * plugin-reload command that re-runs every module initialiser by iterating
 * `__init_array_start .. __init_array_end`. Those are linker-provided symbols
 * and, in a `-no-pie` image, link-time constants -- so the table the loop walks
 * is literally `.init_array`, at a fixed address, still writable because the
 * image has no RELRO.
 *
 * Two things change for whatever drives the exploit:
 *
 *   * THE TRIGGER IS A COMMAND, NOT TERMINATION. Sending the quit command here
 *     does nothing useful; the write only fires on menu option 4. An executor
 *     that assumes "write the table, then let the program end" never sees it.
 *   * THE WALK IS FORWARD. `call_fini()` walks `.fini_array` backwards; this
 *     loop walks `.init_array` from index 0 upwards, because it is ordinary
 *     program code and not the loader. Slot ordering logic derived from the
 *     `.fini_array` case is therefore wrong here, and any slot in range works.
 *
 * `.init_array` holds three entries: the compiler's own `frame_dummy` at index
 * 0 plus the two constructors below. Re-running them is exactly what a reload
 * command is for; they are written to be idempotent so that the reload is a
 * legitimate feature rather than a bug of its own.
 *
 * FLAG{supwngo_bench_fini_12_init_array_reload}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REG_SLOTS 8
#define PATCH_SPAN 4096L

static unsigned long registry[REG_SLOTS];
static char sh_cmd[16] = "/bin/sh";
static int module_generation;

/* Linker-provided bounds of this image's own `.init_array`. Absolute addresses
 * in a -no-pie link, so the loop below is a walk over a fixed table. */
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

void spawn_admin_shell(void)
{
    system(sh_cmd);
}

/* .init_array index 1. Idempotent on purpose -- a reload must be safe. */
__attribute__((constructor)) static void init_counters(void)
{
    module_generation += 1;
}

/* .init_array index 2. */
__attribute__((constructor)) static void init_banner(void)
{
    /* Nothing observable at startup; the reload path prints the generation. */
    module_generation += 0;
}

/* The later phase. The write into `.init_array` has already happened by the
 * time this runs, which is the whole point: the loader's walk is over, and the
 * program is about to walk the same table a second time. */
static void do_reload(void)
{
    long n = __init_array_end - __init_array_start;
    long i;

    printf("reloading %ld module initialiser(s)\n", n);
    for (i = 0; i < n; ++i)
        __init_array_start[i]();
    printf("generation %d\n", module_generation);
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

/* `_exit(0)`, deliberately, and this is a MEASUREMENT decision rather than a
 * stylistic one. With `exit(0)` here, this image's own one-entry `.fini_array`
 * -- writable, because the link has no RELRO -- would ALSO be a live
 * destination, and an executor would solve this target by the ordinary
 * fini-array route without ever exercising the `.init_array` re-walk that the
 * target exists to test. Verified before the change: writing `.fini_array[0]`
 * and sending quit did produce a shell. `_exit` goes straight to the kernel, so
 * `.fini_array` here is writable and DEAD and menu option 4 is the only way in. */
static void do_quit(void)
{
    puts("bye");
    _exit(0);
}

int main(void)
{
    long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("*** module host ***");
    for (;;) {
        puts("1 - patch slot");
        puts("2 - show slot 0");
        puts("3 - quit");
        puts("4 - reload modules");
        printf("choice: ");
        if (scanf("%ld", &choice) != 1)
            _exit(1);
        if (choice == 1)
            do_patch();
        else if (choice == 2)
            do_show();
        else if (choice == 3)
            do_quit();
        else if (choice == 4)
            do_reload();
        else
            puts("unknown option");
    }
}
