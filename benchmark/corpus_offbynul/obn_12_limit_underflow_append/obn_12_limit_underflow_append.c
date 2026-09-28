/*
 * obn_12_limit_underflow_append
 *
 * FAMILY
 * ------
 * benchmark/corpus_offbynul/ -- heap off-by-NUL -> overlapping program-owned
 * records (CWE-193 -> CWE-122). See obn_10_len_scan_handler.c for the
 * family's shared skeleton; only this target's delta is documented here.
 *
 * SOURCE DELTA vs the anchor (obn_10_len_scan_handler) -- A DIFFERENT
 * DOWNSTREAM PRIMITIVE ENTIRELY
 * ---------------------------------------------------------------------------
 * Every other target in this family escalates the corruption into a
 * fabricated header that a READ-ORIENTED walk discovers. This one is a
 * genuine WRITE overflow instead, and it needs two header fields rather than
 * one:
 *
 *     struct hdr { unsigned int limit;    THE FIELD THE OFF-BY-ONE CORRUPTS
 *                  unsigned int filled;   bytes already appended -- untouched
 *                  void (*handler)(void); };
 *
 * `trigger` here IS `append(idx, data)`: it computes `room = limit - filled`
 * and copies up to `room` bytes to `data_at(idx) + filled`, then notifies
 * whatever record immediately follows by calling ITS handler -- an ordinary
 * "let the next record know we grew" step, unrelated to the bug on its own.
 *
 * The off-by-one in set() corrupts `limit`'s low byte exactly as in every
 * other target. `limit` starts at CAP (24, so its NUL-corrupted value is
 * exactly 0, same reasoning as the rest of the family). The exploitable
 * moment is arithmetic, not positional: once a record has legitimately been
 * appended to UP TO its declared capacity (`filled == CAP`) and its `limit`
 * is then corrupted DOWN to 0, `room = limit - filled` is `0 - 24` in
 * unsigned 32-bit arithmetic -- an UNDERFLOW to 0xFFFFFFE8, not a small
 * number. The next append is bounded by nothing meaningful: it writes
 * starting at `data_at(idx) + filled` (== `data_at(idx) + CAP`, i.e. exactly
 * the header of the record that follows) for as many bytes as the operator
 * sends, which is a direct overwrite of that record's `handler` field with
 * attacker-chosen bytes. The "notify the next record" step that already
 * existed for entirely legitimate reasons then calls it in the very same
 * operation.
 *
 * Solve shape: create 0 ; create 1 ; create 2 ; show 0 (PIE leak) ;
 * trigger(1, 24, "A"*24)        -- fills record 1 to its declared capacity,
 *                                   ordinary use, nothing wrong yet
 * set(0, 24 bytes)              -- the off-by-one: record 1's limit -> 0
 * trigger(1, 16, fake header: limit=0, filled=0, handler=&win)
 *                                -- room underflows; the write lands exactly
 *                                   on record 2's header; the same call's
 *                                   "notify" step invokes it
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON (see ./cflags).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_RECS 8
#define CAP      24
#define HDR_SZ   16                    /* limit(4) + filled(4) + handler(8) */
#define SLOT_SZ  (HDR_SZ + CAP)
#define POOL_SZ  (SLOT_SZ * MAX_RECS)

struct hdr {
    unsigned int limit;                /* THE FIELD THE OFF-BY-ONE CORRUPTS */
    unsigned int filled;               /* bytes already appended */
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
    .limit = CAP, .filled = 0, .handler = default_handler,
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
    printf("len: ");
    fflush(stdout);
    unsigned int n = (unsigned int)read_int();
    printf("data: ");
    fflush(stdout);
    unsigned char buf[CAP * 4];
    ssize_t r = read(0, buf, sizeof(buf));
    if (r < 0) r = 0;
    if (n > (unsigned int)r) n = (unsigned int)r;

    struct hdr *h = hdr_at(idx);
    /* THE ESCALATION: room is meant to be "how much space is left before
     * this record's declared limit". If limit has been corrupted below an
     * already-legitimate filled count, this subtracts a smaller unsigned
     * value's smaller-still complement -- it UNDERFLOWS. */
    unsigned int room = h->limit - h->filled;
    unsigned int w = (n < room) ? n : room;
    if (data_at(idx) + h->filled + w > pool + POOL_SZ ||
        data_at(idx) + h->filled + w < data_at(idx)) {
        puts("bad");
        return;
    }
    memcpy(data_at(idx) + h->filled, buf, w);
    h->filled += w;

    /* Notify whichever record immediately follows -- ordinary bookkeeping,
     * not part of the bug by itself. */
    unsigned char *succ = data_at(idx) + CAP;
    if (succ + HDR_SZ <= pool + POOL_SZ) {
        ((struct hdr *)succ)->handler();
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
    puts("=== off-by-NUL variant: limit underflow -> append overwrite ===");

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
