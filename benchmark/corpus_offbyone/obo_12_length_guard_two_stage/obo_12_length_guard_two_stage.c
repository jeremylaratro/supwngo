/* obo_12_length_guard_two_stage -- FLAG{supwngo_bench_obo_12_length_guard_two_stage}
 *
 * Category: CWE-193 / CWE-787, off-by-one single-byte write. Family header in
 * obo_10_loop_le_saved_rbp.c.
 *
 * THIS TARGET'S AXIS POINT: the one extra byte does NOT land on a saved frame
 * pointer. It lands on the LOW BYTE OF A LENGTH GUARD that lives immediately
 * after the overflowed array in the same record:
 *
 *     struct rec { char name[0x20]; unsigned int cap; char body[0x40]; };
 *
 * `copy_name()` is bounded by `sizeof r.name` and writes `r.name[0x20]`, which
 * IS `((unsigned char *)&r.cap)[0]`. The program set `r.cap = 0x10`, so the
 * single byte turns 0x00000010 into 0x000000ff -- and the very next statement
 * is `read(0, r.body, r.cap)`. One byte bought a 255-byte write into a 0x40-byte
 * array, and THAT write reaches the saved RBP and the return address the honest
 * way.
 *
 * WHY THIS IS THE MOST IMPORTANT MEMBER OF THE FAMILY
 * --------------------------------------------------
 * It is the only positive here that is DETERMINISTIC. The pivot shapes
 * (obo_10/11/14) inherit a 15/16 ceiling from the fact that a saved RBP's low
 * byte is not knowable from outside the process; this one needs no stack
 * address at all. The exploit is:
 *
 *     stage 1   0x20 bytes of anything, then one 0xff   -> cap := 255
 *     stage 2   84 bytes of filler, then a bare `ret` for alignment, then
 *               `win`                                    -> shell
 *
 * and it works on the first attempt, every time (MEASURED 32/32). A family whose
 * every member was probabilistic would leave "did the technique work?" and "did
 * the dice land?" entangled; this target separates them.
 *
 * THE 84 IS READ OFF THE BUILD, NOT COMPUTED FROM THE STRUCT. Reasoning from
 * `sizeof r.body` gives 0x40 + 8 = 72, and 72 is WRONG: gcc allocates
 * `sub $0x70,%rsp` for this 0x64-byte record and addresses `r.body` as
 * `lea -0x70(%rbp),%rax; add $0x24,%rax`, i.e. at -0x4c(%rbp) -- so the distance
 * to the return address is 0x4c + 8 = 84. An earlier revision of this comment
 * said 72; the erratum is left in place rather than silently replaced because
 * the lesson is the point. `cap` reaches 255 after the widening, so there is
 * ample room for the 100-byte chain either way, which is exactly why a wrong
 * constant here would have been easy to ship unnoticed if the executor had
 * hardcoded it instead of deriving it.
 *
 * WHAT IT BREAKS IN AN EXECUTOR WRITTEN AGAINST obo_10/obo_11
 * ----------------------------------------------------------
 * Everything downstream of the byte. There is no frame pivot, no sled, no
 * retry, and no `[win, ret]` pattern -- and the byte itself must be 0xff rather
 * than 0x00, because a NUL here would make `cap` SMALLER (0x10 -> 0x00) and the
 * defect would be harmless. So an executor that hardcodes "write a NUL onto the
 * byte past the buffer" gets a clean, silent no-op, and one that reads the
 * DESTINATION of the extra byte out of the frame gets a deterministic shell.
 * That is the whole reason the destination class, not the mechanism, is what
 * this family's executor routes on.
 *
 * Note the canary asymmetry called out in `cflags`: this route would survive
 * -fstack-protector untouched, because `name` and `cap` are members of ONE
 * struct and no frame reordering can be placed between them.
 *
 * Lab fixture. Deliberately vulnerable. Not for use outside this benchmark.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NAME_SZ 0x20
#define BODY_SZ 0x40

/* Staging for the name. The off-by-one copies from here, so the extra byte is
 * a byte the client chose. */
static char g_in[0x40];

struct rec {
    char name[NAME_SZ];
    unsigned int cap;          /* the length guard, flush against `name` */
    char body[BODY_SZ];
};

static void say(const char *s)
{
    write(1, s, strlen(s));
}

/* The single shell site. */
void win(void)
{
    say("[+] guard widened\n");
    system("/bin/sh");
}

static void do_info(void)
{
    say("[*] label service, build 12\n");
}

/* A CORRECT exact-count fill (exclusive bound), for contrast. */
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

static void copy_name(char *dst, const char *src, size_t n)
{
    size_t i;

    for (i = 0; i <= n; i++)   /* BUG: `<=` copies n + 1 bytes */
        dst[i] = src[i];
}

/* ---------------- the record, the guard, and the second write ------------- */

static void do_edit(void)
{
    struct rec r;

    r.cap = 0x10;                       /* the guard, before it is widened */
    say("[*] name: ");
    read_all(g_in, NAME_SZ + 1);        /* n bytes of name + the extra byte */
    copy_name(r.name, g_in, NAME_SZ);   /* writes r.name[NAME_SZ] == cap's LSB */
    say("[*] body: ");
    read(0, r.body, r.cap);             /* bounded by the guard we just moved */
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
