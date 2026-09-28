/*
 * FULL RELRO plus a VALIDATED handler table -- two assumptions broken at once.
 *
 * Same write primitive as fini_10. Two things are different, and each one alone
 * defeats the solve that works on fini_10.
 *
 * (1) FULL RELRO. `-z relro -z now` puts `.init_array`, `.fini_array`,
 *     `.data.rel.ro`, `.dynamic` and the whole GOT inside `PT_GNU_RELRO`, which
 *     the loader turns read-only before `main` runs. Every loader table is
 *     closed. Note the measured qualifier recorded in fini_10's header: PARTIAL
 *     RELRO would have closed `.init_array`/`.fini_array` too -- Full RELRO is
 *     used here because it additionally closes the GOT, so the ONE writable
 *     destination left in this image is the program's own table, and a solve
 *     cannot have quietly gone through `tcache_poison_got`'s destination
 *     instead.
 *
 *     ASSUMPTION BROKEN: "the destination is `.fini_array`". Here it must be the
 *     program-owned table or nothing.
 *
 * (2) THE TABLE IS VALIDATED. `plugin_hooks[]` is mirrored by
 *     `expected_hooks[]`, a shadow copy written at registration time, and
 *     `run_plugin_hooks()` refuses any entry that no longer matches its shadow.
 *     A single write into `plugin_hooks[0]` therefore produces "hook table
 *     tampered -- refusing" and nothing else.
 *
 *     ASSUMPTION BROKEN: "one write is one hijack". This destination costs TWO
 *     writes with the same primitive -- `plugin_hooks[k]` and
 *     `expected_hooks[k]` -- and the second one is not optional. A shadow-copy
 *     check like this is the cheapest real mitigation a program can apply to its
 *     own dispatch table, and it is defeated by the same primitive precisely
 *     because the shadow lives in the same writable region as the table it
 *     guards. That is the finding, not a fixture quirk.
 *
 * THE TRIGGER
 * `run_plugin_hooks` is registered with `atexit()` at startup, so the walk
 * happens on the quit command's `exit(0)` -- the same termination path fini_10
 * uses, reached through glibc's exit-handler list rather than through
 * `.fini_array`. `atexit`'s own list is in libc's private data and is not what
 * is being written here; the hijacked table is the program's.
 *
 * FLAG{supwngo_bench_fini_14_fullrelro_whitelist}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REG_SLOTS 8
#define PATCH_SPAN 4096L
#define MAX_HOOKS 4

static unsigned long registry[REG_SLOTS];
static char sh_cmd[16] = "/bin/sh";

/* The dispatch table and its shadow. Both in the program's own writable data,
 * which is why a mitigation that compares one against the other cannot survive
 * a primitive that reaches both. */
static void (*plugin_hooks[MAX_HOOKS])(void);
static void (*expected_hooks[MAX_HOOKS])(void);
static int plugin_count;

void spawn_admin_shell(void)
{
    system(sh_cmd);
}

static void plugin_flush(void)
{
    fflush(stdout);
}

static void plugin_report(void)
{
    puts("[plugin] state written back");
}

static void register_plugin(void (*fn)(void))
{
    if (plugin_count < MAX_HOOKS) {
        plugin_hooks[plugin_count] = fn;
        expected_hooks[plugin_count] = fn;
        plugin_count += 1;
    }
}

/* The validated walk. */
static void run_plugin_hooks(void)
{
    int i;

    for (i = 0; i < plugin_count; ++i) {
        if (plugin_hooks[i] != expected_hooks[i]) {
            puts("hook table tampered -- refusing");
            continue;
        }
        plugin_hooks[i]();
    }
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

    register_plugin(plugin_flush);
    register_plugin(plugin_report);
    atexit(run_plugin_hooks);

    puts("*** plugin host ***");
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
