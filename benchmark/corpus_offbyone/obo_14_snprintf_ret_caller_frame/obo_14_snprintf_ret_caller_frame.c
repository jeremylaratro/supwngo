/* obo_14_snprintf_ret_caller_frame -- FLAG{supwngo_bench_obo_14_snprintf_ret_caller_frame}
 *
 * Category: CWE-193 / CWE-787, off-by-one single-byte write. Family header in
 * obo_10_loop_le_saved_rbp.c.
 *
 * THIS TARGET'S AXIS POINT: two assumptions, broken together on purpose. It is
 * the "break my own first implementation" member of the family.
 *
 * (1) THE MECHANISM IS snprintf's RETURN VALUE, NOT A LOOP AND NOT A strlen.
 *
 *         int n = snprintf(dst, cap, "%s", src);
 *         if (n > (int)cap)      <-- clamps to cap; correct is cap - 1
 *             n = (int)cap;
 *         dst[n] = '\0';         <-- n == cap  =>  one past the end
 *
 *     snprintf returns the length it WOULD have written, not the length it did,
 *     so `n` is attacker-sized without any byte of `src` reaching `dst[cap]`.
 *     There is no inclusive comparison against the buffer's bound anywhere: the
 *     clamp ceiling IS the bound, and it is compared with a SIGNED `jle`/`jg`
 *     against an `int` that came out of a return register. An off-by-one gate
 *     that looks only for `jbe` on a size_t cursor misses this entirely.
 *
 * (2) THE PIVOT LANDS IN THE CALLER'S FRAME, NOT IN THE OVERFLOWED ONE.
 *
 *     `do_tag()` holds a 0x20-byte `name` and nothing else, so `name[0x20]` is
 *     the saved RBP -- same primitive as obo_10. But 0x20 bytes cannot hold a
 *     landing zone: the pivot lands `(H & ~0xff) + 8` which is up to 232 bytes
 *     below H, and `name` only covers the top 32 of those. The sled has to be in
 *     `handle()`'s own 0x400-byte `board`, which is filled by a DIFFERENT read,
 *     in a DIFFERENT function, BEFORE the overflow happens.
 *
 *     An executor that sprays "the buffer the off-by-one overflowed" fills 32 of
 *     the 232 bytes it needs and fails ~87% of the time. One that sprays every
 *     attacker-writable region reachable on the way to the defect succeeds.
 *     This is the target that tells those two apart.
 *
 * GEOMETRY, READ OUT OF THE BUILT IMAGE:
 *   `handle` does `sub $0x410,%rsp` and puts `board` at -0x400(%rbp), spilling
 *   its `c` argument BELOW the array at -0x404(%rbp). So the landing zone ends
 *   FLUSH against H -- there is no gap at all, unlike obo_10 where the sled's
 *   top is 0x20 bytes short of H. The only losing low byte is 0x00 (where the
 *   write is a no-op), so the per-attempt ceiling is 15/16 == 93.75%: the
 *   HIGHEST in the family, even though the overflowed buffer is the smallest.
 *   That is the opposite of what "the 0x20-byte buffer must be the hard one"
 *   would suggest, and it is why the figure is read off the disassembly instead
 *   of reasoned about.
 *
 *   MEASURED, 32 independent attempts with the family's reference exploit
 *   (`benchmark/reference_exploits/offbyone_variants_reference.py --rate`):
 *   28/32 == 87.5%.
 *
 *   ERRATUM: an earlier revision of this comment asserted `board` was at
 *   -0x410(%rbp) with `c` spilled above it, a 0x10-byte gap, and a 14/16
 *   ceiling. That was PREDICTED, not measured, and it was wrong. It is recorded
 *   here rather than silently replaced because it is the only number in this
 *   family that was written down before it was checked, and the check is the
 *   whole point of the fixture.
 *
 * Lab fixture. Deliberately vulnerable. Not for use outside this benchmark.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BOARD_SZ 0x400
#define TAG_SZ   0x20

static char g_in[0x80];
static ssize_t g_len;

static void say(const char *s)
{
    write(1, s, strlen(s));
}

/* The single shell site. */
void win(void)
{
    say("[+] frame pivoted\n");
    system("/bin/sh");
}

static void do_info(void)
{
    say("[*] label service, build 14\n");
}

/* A CORRECT exact-count fill (exclusive bound). This is what lays down the
 * landing zone, and it is not the buggy call. */
static void read_all(char *dst, size_t n)
{
    size_t got = 0;
    ssize_t k;

    while (got < n) {
        k = read(0, dst + got, n - got);
        if (k <= 0)
            break;
        got += (size_t)k;
    }
}

/* ---------------- THE VARIED AXIS: the mechanism ------------------------- */

static void set_tag(char *dst, size_t cap, const char *src)
{
    int n = snprintf(dst, cap, "%s", src);   /* the UNTRUNCATED length */

    if (n < 0)
        n = 0;
    if (n > (int)cap)          /* BUG: clamps to cap, not cap - 1 */
        n = (int)cap;
    dst[n] = '\0';             /* n == cap -> dst[cap] */
}

/* ---------------- the overflowed frame: 0x20 bytes and no landing zone ---- */

static void do_tag(const char *src)
{
    char name[TAG_SZ];               /* the ONLY local: ends flush at (%rbp) */

    set_tag(name, sizeof name, src); /* -> saved RBP's low byte (handle's H) */
    say("[+] tagged\n");
}

/* ---------------- the frame the pivot actually lands in -------------------- */

static void handle(char c)
{
    char board[BOARD_SZ];            /* the landing zone lives HERE */

    switch (c) {
    case '1':
        do_info();
        break;
    case '2':
        say("[*] board: ");
        read_all(board, sizeof board);        /* NUL-tolerant: the sled */
        say("[*] tag: ");
        g_len = read(0, g_in, sizeof g_in - 1);
        if (g_len < 0)
            g_len = 0;
        g_in[g_len] = '\0';
        do_tag(g_in);                         /* fires the pivot on return */
        break;
    default:
        say("[-] ?\n");
        break;
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
