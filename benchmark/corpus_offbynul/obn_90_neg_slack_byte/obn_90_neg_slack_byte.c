/*
 * obn_90_neg_slack_byte -- NEGATIVE CONTROL
 *
 * FAMILY
 * ------
 * benchmark/corpus_offbynul/ -- heap off-by-NUL -> overlapping program-owned
 * records (CWE-193 -> CWE-122). See obn_10_len_scan_handler.c for the
 * family's shared skeleton.
 *
 * WHY THIS IS THE CONTROL, NOT JUST ANOTHER VARIANT
 * ---------------------------------------------------------------------------
 * `set()` keeps the EXACT SAME bug as every positive in this family:
 *
 *     if (n > CAP) n = CAP;                 -- inclusive: n == CAP survives
 *     memcpy(data_at(idx), buf, n);
 *     data_at(idx)[n] = 0;                  -- OOB by exactly one when n==CAP
 *
 * identical clamp, identical constant, identical explicit NUL store -- this
 * target is STATICALLY INDISTINGUISHABLE from obn_10/obn_11/obn_14 by the
 * pattern the executor's gate looks for (an inclusive-bound length check
 * immediately followed by a single-byte NUL store at the tainted offset), and
 * it is meant to be: the gate is a fact about the CODE SHAPE, and this file
 * has that shape. What makes it a control is what the overflowing byte lands
 * ON, which no static pattern over `set()` alone can see.
 *
 * Every positive's record layout puts a header directly against the data
 * field's far edge, so the off-by-one's single NUL byte lands on the first
 * byte of something a LATER operation reads back as meaningful (a length, a
 * capacity, a handler). This record adds ONE BYTE OF SLACK between the data
 * field and the next record's header:
 *
 *     struct hdr { unsigned int len; unsigned int _pad; void (*handler)(); };
 *     [ hdr (16) ][ data (24) ][ slack (1) ][ next record's hdr ... ]
 *
 * The overflowing NUL from `set(idx)` lands on `slack[0]` -- still inside
 * record `idx`'s own slot, past its data field but short of record `idx+1`'s
 * header by exactly the one byte this control exists to add. Nothing ever
 * reads `slack[0]`: it is not `len`, not `_pad`, not `handler`, not part of
 * any subsequent record's header, and `trigger()`'s walk (identical scan()
 * logic to the anchor) computes every hop from `len` and `handler`, which
 * this corruption never touches. show() still dumps it as part of the raw
 * SLOT_SZ bytes it always dumps -- there being a byte on the wire is not the
 * same as there being a byte anything downstream TRUSTS.
 *
 * MEASURED CONSEQUENCE, the discriminator this whole corpus exists to prove:
 * the identical live-discovery/escalation sequence this family's executor
 * runs against every positive (corrupt the neighbour, plant a fake header at
 * the measured hop offset, invoke `trigger`) finds nothing here to invoke,
 * because the byte it corrupts was never wired to anything -- not because the
 * bug is absent, but because this ONE byte of program-owned padding makes the
 * bug's landing spot inert.
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON (see ./cflags, byte-identical
 * to the rest of the family).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_RECS 8
#define CAP      24
#define SLACK    1                     /* the byte that absorbs the NUL */
#define HDR_SZ   16                    /* len(4) + pad(4) + handler(8) */
#define SLOT_SZ  (HDR_SZ + CAP + SLACK)
#define POOL_SZ  (SLOT_SZ * MAX_RECS)

struct hdr {
    unsigned int len;                  /* THE FIELD scan() TRUSTS TO HOP --
                                         * NEVER touched by this control's bug */
    unsigned int _pad;
    void (*handler)(void);
};

static unsigned char *pool;
static int nrecs;

static void default_handler(void) { puts("[handler] default"); }

/* win() exists in every corpus binary, positive or negative, so a would-be
 * detector cannot use ITS presence/absence as a shortcut. Whether it is
 * REACHABLE is the only thing that differs. */
void win(void) {
    puts("[win] shell");
    fflush(stdout);
    system("/bin/sh");
}

/* `len` is CAP + SLACK (25): with the slack byte present, a legitimate hop
 * has to skip it too, or ordinary (non-exploited) multi-record walking would
 * itself be broken. This is what a correct version of the family's records
 * looks like. */
static const struct hdr HDR_TEMPLATE = {
    .len = CAP + SLACK, ._pad = 0, .handler = default_handler,
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
    memset(data_at(nrecs), 0, CAP + SLACK);
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
    /* THE SAME BUG AS EVERY POSITIVE: an inclusive bound. n == CAP survives
     * this clamp, and the terminator below then writes at
     * data_at(idx)[CAP] -- one past the data field's last valid index, and
     * (unlike every positive) still short of anything meaningful: that byte
     * is this record's OWN slack, not the next record's header. */
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
    puts("=== off-by-NUL control: one slack byte absorbs the terminator ===");

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
