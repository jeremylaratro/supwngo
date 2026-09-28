/* uninit_14_struct_padding -- FLAG{supwngo_bench_uninit_14_struct_padding}
 *
 * Category (HELD CONSTANT across benchmark/corpus_uninit):
 *   CWE-457 / CWE-908 -- uninitialised memory DISCLOSURE. A fixed-size record
 *   is allocated, only its first NAME_SZ bytes are written from user input, and
 *   then the WHOLE record is handed back with one `write(1, r, REC_SZ)`. The
 *   REC_SZ - NAME_SZ bytes nobody wrote are whatever the previous user of that
 *   memory left there. Nothing is overflowed and no pointer is corrupted, which
 *   is why this category is orthogonal to NX, to the canary, to RELRO and to
 *   PIE: there is nothing for them to check.
 *
 * THE VARIED AXIS (the ONLY thing that differs between the positives in this
 * corpus): WHICH PRIOR USE OF THE RECORD'S BYTES SURVIVES INTO THE DISCLOSED
 * TAIL -- and therefore what leaks and which of the target's own two win paths
 * becomes reachable. The axis knob is literally one function, `do_prepare()`.
 *
 *   uninit_10   a freed HEAP CHUNK handed straight back out of the tcache
 *   uninit_11   A RETURNED STACK FRAME at the same call depth
 *   uninit_12   the same freed chunk, surviving a memset given the WRONG length
 *   uninit_13   a returned DEEPER frame's stack CANARY -> the other win path
 *   uninit_14 (THIS FILE)
 *       A COMPILER PADDING HOLE. The chunk provenance is the anchor's, but
 *       here the record is a struct whose every NAMED field is explicitly
 *       assigned -- `name` from input, `id` and `note` by the program. What is
 *       never assigned is the 16-byte hole the compiler inserts to align `id`,
 *       because a hole is not a field. It sits exactly on TOKEN_OFF.
 *       MEASURED: sizeof(struct prec) == 64 == REC_SZ, hole at 16..31, and tail
 *       offset 16..31 == the live token, byte for byte.
 *   uninit_90   NEGATIVE CONTROL: uninit_12 with the memset length corrected
 *
 * HELD CONSTANT in every file:
 *   * `REC_SZ` 64, `NAME_SZ` 16, `TOKEN_SZ` 16, `TOKEN_OFF` 16;
 *   * the disclosure statement pair -- `read(0, <rec>, NAME_SZ)` followed by
 *     `write(1, <rec>, REC_SZ)`;
 *   * the privileged path: command '3' reads TOKEN_SZ bytes and calls `win()`
 *     on an exact `memcmp` against the runtime token;
 *   * `win()` -> `system("/bin/sh")`, the single shell site;
 *   * the bounded-overflow path: command '4', `char note[40]` with
 *     `read(0, note, 200)`. Canary-protected, so it is a win only for whoever
 *     already knows the canary -- which is exactly one target in this family;
 *   * the runtime token: 8 bytes of /dev/urandom hex-encoded to 16 characters,
 *     generated per process and NEVER printed, so it is not in the image and
 *     `strings` cannot substitute for the leak;
 *   * the menu, the prompts, the command letters, and cflags.
 *
 * WHAT IS NOT CONSTANT, STATED SO IT CANNOT BE MISTAKEN FOR A HIDDEN SECOND
 * BUG: the record's STORAGE CLASS follows from the axis point. You cannot
 * recycle a freed heap chunk into a stack local, so the heap points (10, 12,
 * 14) allocate the record and the stack points (11, 13) declare it. The
 * read/write statement pair either side of it is unchanged.
 *
 * WHY `handle()` HOLDS A 256-BYTE `arg` IT BARELY USES -- this is load-bearing
 * family geometry, MEASURED, not decoration. The stack points need the record
 * to live BELOW anything `main`'s own `say()`/`read()` calls reach between two
 * commands; glibc's `write` stub alone reaches ~0x50 past main's rsp and would
 * shred a depth-1 record. Putting every command handler at depth 2 under a
 * frame this size moves the record out of that region. It is present in all six
 * targets so the geometry cannot differ between them.
 *
 * Lab fixture. Deliberately vulnerable. Not for use outside this benchmark.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REC_SZ    64
#define NAME_SZ   16
#define TOKEN_SZ  16
#define TOKEN_OFF 16
#define NOTE_SZ   40
#define NOTE_READ 200

static char g_token[TOKEN_SZ + 1];

/* The disclosed record. Only `name` is ever written from input. */
struct rec {
    char name[NAME_SZ];
    char tail[REC_SZ - NAME_SZ];
};

/* The session record -- same size, so it lands in the same tcache bin.
 * `pad` exists because a freed tcache chunk's first two words hold `next`
 * and `key`; the token has to live past them to survive the free. */
struct sess {
    char pad[TOKEN_OFF];
    char token[TOKEN_SZ];
    char rest[REC_SZ - TOKEN_OFF - TOKEN_SZ];
};

static void say(const char *s)
{
    write(1, s, strlen(s));
}

static void gen_token(void)
{
    unsigned char raw[TOKEN_SZ / 2];
    static const char hex[] = "0123456789abcdef";
    int fd, i;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        _exit(1);
    if (read(fd, raw, sizeof raw) != (ssize_t)sizeof raw)
        _exit(1);
    close(fd);
    for (i = 0; i < (int)sizeof raw; i++) {
        g_token[2 * i]     = hex[raw[i] >> 4];
        g_token[2 * i + 1] = hex[raw[i] & 0x0f];
    }
}

/* The single shell site, and the ret2win target. */
static void win(void)
{
    say("[+] admin granted\n");
    system("/bin/sh");
}

/* ---------------- THE VARIED AXIS: the prior use of the record's bytes ----- */

static void do_prepare(void)
{
    struct sess *s = malloc(sizeof *s);

    if (!s)
        return;
    memset(s->pad, 0, sizeof s->pad);
    memcpy(s->token, g_token, TOKEN_SZ);
    memset(s->rest, '.', sizeof s->rest);
    say("[+] session opened\n");
    free(s);                    /* nothing clears it on the way out */
    say("[+] session closed\n");
}

/* ---------------- HELD CONSTANT: the disclosure --------------------------- */

/* Every NAMED field of this record is assigned below. The 16-byte hole the
 * compiler must insert to give `id` its requested 32-byte alignment is not a
 * field, so no assignment reaches it -- and it lands exactly on TOKEN_OFF. */
struct prec {
    char name[NAME_SZ];                             /*  0..15  assigned */
    /*                                                 16..31  PADDING  */
    unsigned long id __attribute__((aligned(32)));  /* 32..39  assigned */
    char note[REC_SZ - 40];                         /* 40..63  assigned */
};

static void do_record(void)
{
    struct prec *r = malloc(sizeof *r);    /* recycles do_prepare()'s chunk */

    if (!r)
        return;
    say("[*] name: ");
    read(0, r->name, sizeof r->name);      /* only NAME_SZ of REC_SZ written */
    r->id = 1;                             /* ...and every other field is too */
    memset(r->note, '.', sizeof r->note);
    write(1, r, sizeof *r);                /* ...and all REC_SZ handed back */
    say("\n[+] stored\n");
}

/* ---------------- HELD CONSTANT: the privileged path ---------------------- */

static void do_admin(char *arg)
{
    say("[*] token: ");
    if (read(0, arg, TOKEN_SZ) != TOKEN_SZ)
        return;
    if (memcmp(arg, g_token, TOKEN_SZ) == 0)
        win();
    else
        say("[-] denied\n");
}

/* ---------------- HELD CONSTANT: the bounded overflow --------------------- */

static void do_note(void)
{
    char note[NOTE_SZ];

    say("[*] note: ");
    read(0, note, NOTE_READ);              /* 200 into 40, canary-protected */
    say("[+] noted\n");
}

static void handle(char c)
{
    char arg[256];                         /* family geometry -- see header */

    arg[0] = 0;
    switch (c) {
    case '1': do_prepare(); break;
    case '2': do_record();  break;
    case '3': do_admin(arg); break;
    case '4': do_note();    break;
    default:  say("[-] ?\n"); break;
    }
}

int main(void)
{
    char cmd[16];
    ssize_t n;

    gen_token();
    say("== record service ==\n"
        "1) prepare session  2) new record  3) admin  4) note  0) quit\n");
    for (;;) {
        say("> ");
        n = read(0, cmd, sizeof cmd);
        if (n <= 0 || cmd[0] == '0')
            return 0;
        handle(cmd[0]);
    }
}
