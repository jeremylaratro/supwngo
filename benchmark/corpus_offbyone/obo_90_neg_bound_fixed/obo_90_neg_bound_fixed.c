/* obo_90_neg_bound_fixed -- FLAG{supwngo_bench_obo_90_neg_bound_fixed}
 *
 * NEGATIVE CONTROL for benchmark/corpus_offbyone.
 *
 * This is obo_10_loop_le_saved_rbp.c with ONE character changed:
 *
 *     -    for (i = 0; i <= n; i++)
 *     +    for (i = 0; i < n; i++)
 *
 * Everything else is byte-identical to the positive -- the same `win()` calling
 * `system("/bin/sh")`, the same `main -> handle -> do_edit` call depth, the same
 * 0x400-byte single local ending flush at (%rbp), the same menu, the same
 * prompts, and the same `cflags` (canary off, -no-pie, Full RELRO, -O0). The
 * ONLY thing absent is the off-by-one.
 *
 * WHAT MAKES IT A USABLE CONTROL
 * ------------------------------
 * The fill now stops at index n - 1, so the highest byte written is `buf[0x3ff]`
 * and the saved RBP at `(%rbp)` is never touched. There is no frame pivot to
 * fire, and -- because a correct exact-length fill is the ONLY write in the
 * program -- there is no other route either: no second read whose bound could be
 * widened, no pointer to redirect, no return address reachable from any input.
 * `win()` is present and completely unreachable.
 *
 * This means the control is refused by the STATIC half of the gate, on the
 * single fact the whole category turns on -- the fill's terminating comparison
 * is exclusive -- rather than by running out of budget. That is the strongest
 * kind of refusal available, and it is the reason this file exists in this exact
 * form: if `win()` and the geometry were also removed, a decline would be
 * attributable to any of four differences instead of to the missing byte.
 *
 * A client that sends 0x400 bytes plus one more gets the extra byte back in
 * `main`'s next `read(0, cmd, 16)`, where it is read as an unknown command. That
 * is the whole observable difference, and it is why "the exploit for obo_10 run
 * unchanged against this binary" is a meaningful RED test rather than a crash
 * with a different cause.
 *
 * Lab fixture. Not for use outside this benchmark.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_SZ 0x400

static void say(const char *s)
{
    write(1, s, strlen(s));
}

/* The single shell site. Present, and unreachable. */
void win(void)
{
    say("[+] frame pivoted\n");
    system("/bin/sh");
}

static void do_info(void)
{
    say("[*] label service, build 90\n");
}

/* ---------------- THE CORRECTED BOUND: `<` rather than `<=` --------------- */

static void read_line(char *dst, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (read(0, &dst[i], 1) != 1)
            return;
    }
}

/* ---------------- otherwise identical to obo_10 --------------------------- */

static void do_edit(void)
{
    char buf[BUF_SZ];                 /* the ONLY local: ends flush at (%rbp) */

    say("[*] line: ");
    read_line(buf, sizeof buf);       /* writes buf[0 .. BUF_SZ - 1] only */
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
