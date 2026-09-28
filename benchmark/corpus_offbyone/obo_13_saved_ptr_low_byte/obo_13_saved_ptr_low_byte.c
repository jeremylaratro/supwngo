/* obo_13_saved_ptr_low_byte -- FLAG{supwngo_bench_obo_13_saved_ptr_low_byte}
 *
 * Category: CWE-193 / CWE-787, off-by-one single-byte write. Family header in
 * obo_10_loop_le_saved_rbp.c.
 *
 * THIS TARGET'S AXIS POINT: the one extra byte lands on the LOW BYTE OF A SAVED
 * POINTER that the program then uses as a WRITE DESTINATION:
 *
 *     struct rec { char name[0x20]; char *dst; };
 *
 * `r.dst` is set to `g_state.notes` before the copy; `r.name[0x20]` IS
 * `((unsigned char *)&r.dst)[0]`. Zeroing that byte moves the pointer to the
 * bottom of its own 256-byte block, and `g_state` is declared
 * `__attribute__((aligned(256)))` with the function pointer FIRST, so the
 * bottom of that block is `&g_state.action`. The next statement writes 8 bytes
 * through the moved pointer, and the statement after it CALLS what it wrote.
 *
 *     r.dst  = &g_state.notes   ==  base + 8        (base % 256 == 0)
 *     r.name[0x20] = '\0'       ->  r.dst == base   ==  &g_state.action
 *     read(0, r.dst, 8)         ->  g_state.action := p64(win)
 *     g_state.action()          ->  win()
 *
 * DETERMINISTIC, and for a different reason than obo_12: the destination is not
 * a stack address, so nothing about it is randomised. `&g_state` is a link-time
 * constant under -no-pie, `aligned(256)` fixes the low byte of the block, and
 * the distance from `notes` back to `action` is a struct offset. The byte to
 * write (0x00) and the address it redirects to are both readable out of the
 * image before the target is ever run.
 *
 * WHY THE 256-BYTE ALIGNMENT IS PART OF THE FIXTURE AND NOT A CHEAT
 * ----------------------------------------------------------------
 * A one-byte pointer overwrite can only move a pointer WITHIN its own aligned
 * 256-byte block -- that is the primitive, not a simplification. In the wild the
 * attacker wins when something interesting happens to share that block, and
 * whether it does is a fact about the target's data layout. Pinning the block
 * with `aligned(256)` makes that fact HOLD CONSTANT instead of depending on
 * whatever address the linker happened to hand `g_state` in this build, which
 * would otherwise turn a layout coin-flip into an apparent executor
 * regression. The byte written is still one byte, the pointer still moves only
 * inside its block, and nothing about the exploit is short-circuited.
 *
 * `g_state` is in .data rather than .data.rel.ro precisely because this family
 * is -no-pie: the initialiser `hello` is a link-time constant needing no
 * relocation, so Full RELRO (which IS on -- see cflags) does not write-protect
 * it. That is worth stating because it is the one place in this family where the
 * RELRO flag could have mattered and does not.
 *
 * Note the canary asymmetry from `cflags`: like obo_12 this route is untouched
 * by -fstack-protector, since `name` and `dst` are members of one struct.
 *
 * Lab fixture. Deliberately vulnerable. Not for use outside this benchmark.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NAME_SZ 0x20

static void say(const char *s)
{
    write(1, s, strlen(s));
}

/* The single shell site. */
void win(void)
{
    say("[+] pointer redirected\n");
    system("/bin/sh");
}

/* The benign action the service was built to run. */
static void hello(void)
{
    say("[*] nothing to see here\n");
}

/* The write destination and the indirect-call target, in ONE 256-byte-aligned
 * block with the function pointer at the bottom of it. */
static struct {
    void (*action)(void);
    char notes[0x40];
} g_state __attribute__((aligned(256))) = { hello, { 0 } };

struct rec {
    char name[NAME_SZ];
    char *dst;                 /* the saved pointer, flush against `name` */
};

static void do_info(void)
{
    say("[*] label service, build 13\n");
}

/* ---------------- THE VARIED AXIS: the mechanism ------------------------- */

static void do_edit(void)
{
    struct rec r;
    ssize_t n;

    r.dst = g_state.notes;
    say("[*] name: ");
    n = read(0, r.name, NAME_SZ);
    if (n < 0)
        n = 0;
    if (n > NAME_SZ)           /* BUG: `>` admits n == NAME_SZ, so the
                                * terminator below can be written at index
                                * NAME_SZ -- one past the end */
        n = NAME_SZ;
    r.name[n] = '\0';          /* n == NAME_SZ -> r.dst's low byte */
    say("[*] note: ");
    read(0, r.dst, 8);         /* 8 bytes through the moved pointer */
    g_state.action();          /* ...and then call what was written */
    say("[+] stored\n");
}

static void handle(char c)
{
    switch (c) {
    case '1': do_info(); break;
    case '2': do_edit(); break;
    default:  say("[-] ?\n"); break;
    }
}

int main(void)
{
    char cmd[16];
    ssize_t n;

    say("== label service ==\n"
        "1) info  2) edit  0) quit\n");
    for (;;) {
        say("> ");
        n = read(0, cmd, sizeof cmd);
        if (n <= 0 || cmd[0] == '0')
            return 0;
        handle(cmd[0]);
    }
}
