/*
 * Hijacking a writable finaliser table -- MANY ENTRIES, ONE REACHABLE SLOT.
 *
 * Same write primitive as fini_10, same `-z norelro`, same `exit(0)` trigger.
 * The axis point is the SHAPE OF THE ARRAY: `.fini_array` here holds FOUR real
 * entries, and exactly one of the four slots produces a shell.
 *
 * THE ASSUMPTION THIS BREAKS: "any slot inside the array will do".
 *
 * `call_fini()` walks `.fini_array` BACKWARDS -- highest index first, index 0
 * last. That is an ABI fact, not a heuristic, and it is what makes slot choice
 * load-bearing. Laid out by source order, the array is
 *
 *     index 0   __do_global_dtors_aux   (the compiler's own entry)
 *     index 1   fini_audit              harmless
 *     index 2   fini_halt               calls _exit(0)
 *     index 3   fini_unmask             un-XORs sh_cmd
 *
 * and the walk therefore runs 3, 2, 1, 0. Two consequences:
 *
 *   * `fini_halt` at index 2 terminates the process with `_exit`, so indices 1
 *     and 0 are NEVER REACHED even though they are inside the array and inside
 *     the write primitive's range. IN-RANGE IS NOT THE SAME AS WALKED.
 *   * `fini_unmask` at index 3 is walked FIRST and is the destructor the solve
 *     NEEDS: `sh_cmd` ships XOR-0x5a masked ("u834u)2"), and `spawn_admin_shell`
 *     runs whatever `sh_cmd` holds. Overwriting index 3 destroys the unmasking,
 *     so the hijacked call reaches `system("u834u)2")` -- which runs, returns
 *     "not found", and yields no shell at all.
 *
 * So index 3 fires but cannot win, indices 1 and 0 could win but never fire,
 * anything at index 4 or beyond is not in the array (it is `.data.rel.ro`) and
 * is not walked. Slot 2 -- the terminator's own slot -- is the only answer: the
 * unmasker has already run, and the terminator it replaces is the only thing the
 * program loses.
 *
 * WHY A MASKED COMMAND IS NOT A CONTRIVANCE
 * Deferring a string's deobfuscation to a shutdown handler is what real
 * packed/obfuscated binaries do, and it is the cheapest honest way to make ONE
 * destructor's execution a precondition of the win. The alternative -- asserting
 * "a destructor the program needs" without making the solve depend on it --
 * would leave slot choice untested, which is the one thing this target exists
 * to test.
 *
 * FLAG{supwngo_bench_fini_11_fini_array_multi}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REG_SLOTS 8
#define PATCH_SPAN 4096L
#define SH_MASK 0x5a

static unsigned long registry[REG_SLOTS];

/* "/bin/sh" XOR 0x5a. Masked at rest; `fini_unmask` restores it during
 * shutdown, which is why the walk order decides whether a hijacked slot can
 * actually reach a shell. */
static char sh_cmd[16] = "u834u)2";

void spawn_admin_shell(void)
{
    system(sh_cmd);
}

/* .fini_array index 1 -- walked THIRD, and therefore never reached, because
 * index 2 has already terminated the process by then. */
__attribute__((destructor)) static void fini_audit(void)
{
    puts("[audit] session closed");
}

/* .fini_array index 2 -- walked SECOND. A shutdown handler that hard-exits
 * rather than letting the rest of teardown run. Common in real programs that
 * want to skip slow atexit work, and here it is what truncates the walk. */
__attribute__((destructor)) static void fini_halt(void)
{
    puts("[halt] skipping remaining teardown");
    _exit(0);
}

/* .fini_array index 3 -- walked FIRST. The destructor the solve depends on. */
__attribute__((destructor)) static void fini_unmask(void)
{
    size_t i;

    for (i = 0; i < sizeof(sh_cmd); ++i)
        if (sh_cmd[i])
            sh_cmd[i] ^= SH_MASK;
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
