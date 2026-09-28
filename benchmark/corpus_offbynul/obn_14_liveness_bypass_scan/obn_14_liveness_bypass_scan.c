/*
 * obn_14_liveness_bypass_scan
 *
 * FAMILY
 * ------
 * benchmark/corpus_offbynul/ -- heap off-by-NUL -> overlapping program-owned
 * records (CWE-193 -> CWE-122). See obn_10_len_scan_handler.c for the
 * family's shared skeleton (menu, prompts, pool layout, the leak channel);
 * only this target's delta is documented here.
 *
 * SOURCE DELTA vs the anchor (obn_10_len_scan_handler) -- A GUARD THAT LOOKS
 * LIKE IT VALIDATES THE WALK, BUT DOES NOT GATE ON ANYTHING
 * ---------------------------------------------------------------------------
 * The corrupted field is renamed `count` (still the header's first field, so
 * the off-by-one still lands on its low byte exactly as in the anchor), and
 * `trigger` is the same multi-hop walk as `scan()` -- but this program has
 * ALSO grown what reads like a defence: before invoking each hop's handler,
 * it computes a checksum of that hop's own header and only proceeds past a
 * log line when the checksum looks "off". The checksum is logged, never
 * enforced -- the handler is invoked either way. This is the shape a real
 * codebase produces more often than a clean absence of any check at all: a
 * validation that was added, observed to fire on legitimate data too (a
 * freshly created record's checksum is unremarkable), and never wired to an
 * actual `return`.
 *
 * The corruption and its consequence are otherwise identical to the anchor:
 * `count` starts at CAP (24, so its NUL-corrupted value is exactly 0) and a
 * fake header planted by an ordinary set() call at the corrupted record's
 * own data offset 0 is what the next hop finds and invokes.
 *
 * Solve shape: create 0 ; create 1 ; show 0 (PIE leak) ; set(0, 24 bytes --
 * the off-by-one) ; set(1, fake header: count=0, handler=&win) ;
 * trigger(0).
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON (see ./cflags).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_RECS 8
#define CAP      24
#define HDR_SZ   16                    /* count(4) + pad(4) + handler(8) */
#define SLOT_SZ  (HDR_SZ + CAP)
#define POOL_SZ  (SLOT_SZ * MAX_RECS)

struct hdr {
    unsigned int count;                /* THE FIELD scan() TRUSTS TO HOP */
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
    .count = CAP, ._pad = 0, .handler = default_handler,
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
    printf("len: ");
    fflush(stdout);
    unsigned int n = (unsigned int)read_int();
    printf("data: ");
    fflush(stdout);
    unsigned char buf[CAP + 8];
    ssize_t r = read(0, buf, sizeof(buf));
    if (r < 0) r = 0;
    if (n > (unsigned int)r) n = (unsigned int)r;
    /* THE BUG: an inclusive bound. n == CAP survives this clamp, and the
     * terminator below then writes at data_at(idx)[CAP] -- one past the
     * field's last valid index. */
    if (n > CAP) n = CAP;
    memcpy(data_at(idx), buf, n);
    data_at(idx)[n] = 0;
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
        /* Looks like a defence: a checksum of this hop's own header,
         * logged when it looks unusual. It is never used to refuse the
         * call below -- observing it costs nothing and this program
         * never wired it to a `return`. */
        unsigned int sum = h->count ^ (unsigned int)(size_t)h->handler;
        if (sum == 0) puts("[trigger] note: checksum is zero");
        h->handler();
        cur = cur + HDR_SZ + h->count;
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
    puts("=== off-by-NUL variant: count field -> scan() overlap (logged, not gated) ===");

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
