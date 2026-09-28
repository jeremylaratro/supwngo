/*
 * obn_11_cap_resize_handler
 *
 * FAMILY
 * ------
 * benchmark/corpus_offbynul/ -- heap off-by-NUL -> overlapping program-owned
 * records (CWE-193 -> CWE-122). See obn_10_len_scan_handler.c for the family's
 * shared skeleton and the full explanation of the off-by-one bug in set();
 * that explanation is not repeated here.
 *
 * SOURCE DELTA vs the anchor (obn_10_len_scan_handler)
 * ------------------------------------------------------
 * The corrupted field is renamed `cap` (still the first header field, so the
 * off-by-one lands on its low byte exactly as before) and `trigger` is no
 * longer a multi-hop walk: it is `resize(idx)`, a SINGLE explicit hop that
 * simulates a realloc-style "grow into the next region" operation -- the kind
 * of code a program-owned allocator would run when it believes `cap` bytes of
 * contiguous room follow a record and reaches for whatever sits at
 * `data_at(idx) + cap` to keep operating on. Real `realloc()` never runs
 * here; this is what a HOMEGROWN "resize this record in place" routine looks
 * like, and it is exactly why the task's steer calls this shape "an in-band
 * size/capacity field that a later realloc-style copy trusts": `cap` is read
 * once, trusted once, and the trust is single-hop rather than iterated.
 *
 * `cap` is <256 by construction (CAP is 24), so the off-by-one's NUL write
 * always collapses it to exactly 0 -- resize(idx) then reaches
 * `data_at(idx) + 0`, i.e. the record's OWN data field, at offset 0. Anything
 * placed there by an ordinary set() call is read back as the "resized"
 * record's header and its handler is invoked.
 *
 * Solve shape: create 0 ; create 1 ; show 0 (PIE leak) ; set(0, 24 bytes --
 * the off-by-one) ; set(1, fake header: cap=0, handler=&win) ; resize(1).
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON (see ./cflags).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_RECS 8
#define CAP      24
#define HDR_SZ   16                    /* cap(4) + pad(4) + handler(8) */
#define SLOT_SZ  (HDR_SZ + CAP)
#define POOL_SZ  (SLOT_SZ * MAX_RECS)

struct hdr {
    unsigned int cap;                  /* THE FIELD resize() TRUSTS TO HOP */
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
    .cap = CAP, ._pad = 0, .handler = default_handler,
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
    /* A single-hop "resize": trust `cap` to know where CONTIGUOUS room
     * following this record begins, and act on whatever a program-owned
     * grow-in-place routine finds there. */
    struct hdr *h = hdr_at(idx);
    unsigned char *next = (unsigned char *)h + HDR_SZ + h->cap;
    if (next + HDR_SZ > pool + POOL_SZ) { puts("bad"); return; }
    struct hdr *nh = (struct hdr *)next;
    nh->handler();
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
    puts("=== off-by-NUL variant: cap field -> resize() handler overlap ===");

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
