/*
 * Hijacking a PROGRAM-OWNED `atexit`-style handler table -- and the reason the
 * loader's own table is useless here even though it is writable.
 *
 * Same write primitive as fini_10, same `-z norelro`, so `.fini_array` in this
 * image IS WRITABLE. It is also DEAD: nothing in this program ever calls
 * `exit()` or `atexit()`, and `main` never returns. The quit command runs the
 * program's own shutdown-hook table and then calls `_exit(0)`, which goes
 * straight to the kernel -- no `__run_exit_handlers`, no `_dl_fini`, no
 * `.fini_array` walk, ever.
 *
 * THE ASSUMPTION THIS BREAKS: "a writable finaliser table is a reachable
 * finaliser table". Writability is a section-permission fact and is cheap to
 * check; reachability is a control-flow fact about the program's termination
 * path. An executor that gates on the first and skips the second writes
 * `.fini_array[0]`, watches the process exit cleanly, and reports a failed
 * attempt with no idea why.
 *
 * WHAT IS REACHABLE
 * `shutdown_hooks[]` -- eight qwords of `.bss`, filled by `register_hook()` at
 * startup and walked FORWARD by `run_shutdown_hooks()` on the quit path. It is
 * the same shape as an `atexit` list and it is the destination this target's
 * solve has to use. Two further differences from a loader table, both of which
 * matter to whatever has to find it:
 *
 *   * IT HAS NO ELF TAG. `.fini_array` announces itself in the dynamic section
 *     (`DT_FINI_ARRAY` / `DT_FINI_ARRAYSZ`); `shutdown_hooks` is an anonymous
 *     `.bss` object. The only way to know it is a dispatch table is to read the
 *     loop that indirect-calls through it.
 *   * ITS LENGTH IS A RUNTIME VARIABLE. The walk is bounded by `hook_count`, not
 *     by the array's size, so slots past the registered count are writable, in
 *     range, and never called. Slot 0 is the only index that is walked whenever
 *     the loop runs at all.
 *
 * FLAG{supwngo_bench_fini_13_hook_table_exit}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REG_SLOTS 8
#define PATCH_SPAN 4096L
#define MAX_HOOKS 8

static unsigned long registry[REG_SLOTS];
static char sh_cmd[16] = "/bin/sh";

/* The program's own handler table. Same job as glibc's atexit list, kept in the
 * program's own .bss where no RELRO setting can protect it. */
static void (*shutdown_hooks[MAX_HOOKS])(void);
static int hook_count;

void spawn_admin_shell(void)
{
    system(sh_cmd);
}

static void hook_flush(void)
{
    fflush(stdout);
}

static void hook_report(void)
{
    puts("[shutdown] registry released");
}

static void register_hook(void (*fn)(void))
{
    if (hook_count < MAX_HOOKS)
        shutdown_hooks[hook_count++] = fn;
}

/* The walker. Forward, and bounded by the registered count rather than by
 * MAX_HOOKS -- so only slots 0 .. hook_count-1 are ever called. */
static void run_shutdown_hooks(void)
{
    int i;

    for (i = 0; i < hook_count; ++i)
        shutdown_hooks[i]();
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

/* The trigger, and the reason .fini_array is dead in this image: the program
 * runs its OWN table and then leaves through `_exit`, which performs no
 * at-exit processing of any kind. */
static void do_quit(void)
{
    puts("bye");
    run_shutdown_hooks();
    _exit(0);
}

int main(void)
{
    long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    register_hook(hook_flush);
    register_hook(hook_report);

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
