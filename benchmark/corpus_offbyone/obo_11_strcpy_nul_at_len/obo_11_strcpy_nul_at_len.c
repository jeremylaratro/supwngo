/* obo_11_strcpy_nul_at_len -- FLAG{supwngo_bench_obo_11_strcpy_nul_at_len}
 *
 * Category: CWE-193 / CWE-787, off-by-one single-byte write. See
 * obo_10_loop_le_saved_rbp.c for the family header -- the primitive, the
 * `leave; ret` pivot, the 15/16 ceiling and the held-constant list all live
 * there and are not repeated here.
 *
 * THIS TARGET'S AXIS POINT: a strcpy-shaped TERMINATOR.
 *
 *     size_t len = strlen(src);
 *     if (len > cap)      <-- admits len == cap; correct is `>=` or `cap - 1`
 *         len = cap;
 *     memcpy(dst, src, len);
 *     dst[len] = '\0';    <-- len == cap  =>  dst[cap], one past the end
 *
 * WHAT THIS BREAKS THAT obo_10 DOES NOT
 * -------------------------------------
 * In obo_10 the extra iteration is fed by the client, so the extra byte is
 * whatever the client chooses. Here the extra byte is a NUL emitted by the
 * PROGRAM; the client chooses only its POSITION (by making the source exactly
 * `cap` bytes long, which the clamp then permits). An executor that "sends one
 * more byte and picks its value" has nothing to pick, and one that looks for an
 * inclusive loop bound finds none -- the defect is in a COMPARISON OPERATOR on
 * a length, several instructions away from the store.
 *
 * AND THE SECOND THING IT BREAKS: THE SPRAY CANNOT GO WHERE THE OVERFLOW IS
 * -------------------------------------------------------------------------
 * The pivot lands on a word that must be a CODE ADDRESS, and on a -no-pie
 * x86-64 image every code address has five 0x00 bytes in it. The overflowing
 * write here is a `strlen`-bounded `memcpy`, so its source cannot contain a NUL
 * at all -- the label can never carry a p64(). The landing zone therefore has
 * to be filled by a DIFFERENT, NUL-tolerant write, which is why the record is
 *
 *     struct rec { char body[0x3f0]; char label[0x10]; };
 *
 * one 0x400-byte local ending flush at (%rbp), exactly like obo_10's `buf`: the
 * raw `read_all()` into `body` lays down the `[win, ret]` sled, and the
 * off-by-one on `label` only fires the pivot. The 0x10 bytes of `label` are the
 * one slice of the landing zone that cannot hold a sled word, and they sit at
 * the very top of it, so they cost exactly one of the sixteen landing slots:
 * the per-attempt ceiling here is 12/16 == 75% rather than obo_10's 13/16 --
 * the LOWEST in the family.
 *
 * MEASURED with the family's reference exploit
 * (`benchmark/reference_exploits/offbyone_variants_reference.py --rate`):
 * 19/32 == 59.4% at n=32, and 64/96 == 66.7% at n=96. Both are UNDER the 75%
 * derivation, and so are obo_10's and obo_14's by almost exactly the same
 * margin (~6 points) despite three different geometries -- which is why that
 * deficit is attributed to per-attempt probe flake rather than to this frame
 * layout. See corpus_offbyone.yaml, RE-MEASURED AT n=96, for the reasoning and
 * for what is NOT claimed about it.
 *
 * Lab fixture. Deliberately vulnerable. Not for use outside this benchmark.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_SZ   0x400
#define LABEL_SZ 0x10

/* Staging for the label. A global on purpose: `do_edit()` has to keep exactly
 * ONE local so that the record ends flush at (%rbp), which is what makes
 * `label[LABEL_SZ]` the saved RBP's low byte. */
static char g_in[0x40];
static ssize_t g_len;

struct rec {
    char body[BUF_SZ - LABEL_SZ];
    char label[LABEL_SZ];
};

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
    say("[*] label service, build 11\n");
}

/* A CORRECT exact-count fill, present so the family does not read as "every
 * loop in here is wrong": the bound is exclusive and the cursor never reaches
 * `n`. */
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

static void set_label(char *dst, size_t cap, const char *src)
{
    size_t len = strlen(src);

    if (len > cap)             /* BUG: `>` lets len == cap through */
        len = cap;
    memcpy(dst, src, len);
    dst[len] = '\0';           /* len == cap -> dst[cap] */
}

/* ---------------- HELD CONSTANT: the frame that gets pivoted -------------- */

static void do_edit(void)
{
    struct rec r;                     /* the ONLY local: ends flush at (%rbp) */

    say("[*] body: ");
    read_all(r.body, sizeof r.body);  /* NUL-tolerant: lays down the sled */
    say("[*] label: ");
    g_len = read(0, g_in, sizeof g_in - 1);
    if (g_len < 0)
        g_len = 0;
    g_in[g_len] = '\0';
    set_label(r.label, sizeof r.label, g_in);   /* -> saved RBP's low byte */
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
