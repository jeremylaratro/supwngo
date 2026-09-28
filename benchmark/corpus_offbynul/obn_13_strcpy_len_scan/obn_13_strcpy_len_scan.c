/*
 * obn_13_strcpy_len_scan
 *
 * FAMILY
 * ------
 * benchmark/corpus_offbynul/ -- heap off-by-NUL -> overlapping program-owned
 * records (CWE-193 -> CWE-122). See obn_10_len_scan_handler.c for the
 * family's shared skeleton (menu, prompts, pool layout, scan()'s walk, the
 * leak channel); only this target's delta is documented here.
 *
 * SOURCE DELTA vs the anchor (obn_10_len_scan_handler) -- A REAL strcpy(),
 * NOT A MANUAL memcpy()+STORE
 * ---------------------------------------------------------------------------
 * Every other target in this family writes its terminating NUL with an
 * explicit `data_at(idx)[n] = 0` store. This one is the textbook version of
 * the bug instead: the classic "inclusive strlen/strcpy bound", the literal
 * shape the category is named for.
 *
 *     if (strlen(buf) <= CAP) strcpy(data_at(idx), buf);
 *
 * `strlen(buf) == CAP` survives this check -- the check rejects only STRICTLY
 * LONGER strings -- and `strcpy()` then copies `CAP` data bytes plus its OWN
 * terminating NUL, `CAP + 1` bytes total, into a `CAP`-byte field. The
 * corrupted byte and its consequence (record `idx+1`'s `len` field is
 * collapsed to exactly 0, since it starts at CAP < 256) are identical to
 * obn_10; only the INSTRUCTION SHAPE that produces the corruption differs --
 * a library call reached past an inclusive bound, rather than a manual
 * clamp-then-store. `trigger` is the same multi-hop `scan()` as the anchor.
 *
 * Solve shape: create 0 ; create 1 ; show 0 (PIE leak) ; set(0, a 24-byte
 * string with no embedded NUL -- the off-by-one) ; set(1, fake header:
 * len=0, handler=&win, as a string with no embedded NUL of its own) ;
 * trigger(0).
 *
 * ONE CONSEQUENCE OF USING A REAL strcpy(): the payload set() carries must
 * itself contain no NUL byte before its intended end, or strcpy's OWN scan
 * stops early. This is a fact about how THIS record's data must be shaped,
 * not a new bug -- the fake header's low bytes (a zero length) cannot be
 * carried as a literal embedded NUL, so the exploit scatters them as the
 * LAST bytes of the payload instead of the first (see the reference exploit
 * and executor for how this is handled generically, by measuring the target's
 * own copy semantics rather than assuming this file's).
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON (see ./cflags).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_RECS 8
#define CAP      24
#define HDR_SZ   16                    /* len(4) + pad(4) + handler(8) */
#define SLOT_SZ  (HDR_SZ + CAP)
#define POOL_SZ  (SLOT_SZ * MAX_RECS)

struct hdr {
    unsigned int len;                  /* THE FIELD scan() TRUSTS TO HOP */
    unsigned int _pad;
    void (*handler)(void);
};

static unsigned char *pool;
static int nrecs;

static void default_handler(void) { puts("[handler] default"); }

void win(void) {
    puts("[win] shell");
    fflush(stdout);
    system("/bin/sh");
}

static const struct hdr HDR_TEMPLATE = {
    .len = CAP, ._pad = 0, .handler = default_handler,
};

static struct hdr *hdr_at(int i) {
    return (struct hdr *)(pool + (size_t)i * SLOT_SZ);
}

static unsigned char *data_at(int i) {
    return pool + (size_t)i * SLOT_SZ + HDR_SZ;
}

static int read_int(void) {
    int v = -1;
    if (scanf("%d", &v) != 1) exit(0);
    return v;
}

static int ask_index(void) {
    printf("index: ");
    fflush(stdout);
    int idx = read_int();
    if (idx < 0 || idx >= nrecs) return -1;
    return idx;
}

static void create_rec(void) {
    if (nrecs >= MAX_RECS) { puts("bad"); return; }
    memcpy(hdr_at(nrecs), &HDR_TEMPLATE, sizeof(HDR_TEMPLATE));
    memset(data_at(nrecs), 0, CAP);
    nrecs++;
    puts("ok");
}

static void set_rec(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    printf("data: ");
    fflush(stdout);
    char buf[CAP + 8];
    ssize_t r = read(0, buf, sizeof(buf) - 1);
    if (r < 0) r = 0;
    buf[r] = '\0';
    /* THE BUG: an inclusive bound. strlen(buf) == CAP survives this check,
     * and strcpy() then writes CAP bytes plus its own terminator -- CAP + 1
     * bytes -- into a CAP-byte field. */
    if (strlen(buf) <= CAP) {
        strcpy((char *)data_at(idx), buf);
    }
    puts("ok");
}

static void show_rec(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    ssize_t w = write(1, hdr_at(idx), SLOT_SZ);
    (void)w;
    putchar('\n');
    fflush(stdout);
}

static void trigger(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    unsigned char *cur = (unsigned char *)hdr_at(idx);
    unsigned char *end = pool + POOL_SZ;
    int hops = 0;
    while (cur + HDR_SZ <= end && hops < MAX_RECS * 2) {
        struct hdr *h = (struct hdr *)cur;
        h->handler();
        cur = cur + HDR_SZ + h->len;
        hops++;
    }
    puts("ok");
}

static void delete_rec(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    memset(hdr_at(idx), 0, SLOT_SZ);
    puts("ok");
}

static void menu(void) {
    puts("1) create   2) set   3) show   4) trigger   5) delete   6) exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    pool = malloc(POOL_SZ);
    if (!pool) return 1;
    puts("=== off-by-NUL variant: strcpy() inclusive bound -> scan() overlap ===");

    while (1) {
        menu();
        switch (read_int()) {
            case 1: create_rec(); break;
            case 2: set_rec(); break;
            case 3: show_rec(); break;
            case 4: trigger(); break;
            case 5: delete_rec(); break;
            case 6: puts("bye"); return 0;
            default: puts("bad"); break;
        }
    }
}
