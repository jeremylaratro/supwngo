/*
 * obn_10_len_scan_handler
 *
 * FAMILY
 * ------
 * benchmark/corpus_offbynul/ -- heap off-by-NUL -> overlapping program-owned
 * records (CWE-193 -> CWE-122). Gap item 7 of
 * docs/reference/2026-09-28-vulnerability-category-coverage.md's stage-4 queue.
 *
 * This is deliberately NOT the classic "poison the glibc chunk size" shape
 * (that fight is against ptmalloc2's own metadata hardening on glibc 2.35 and
 * is a research project, not a category). Every record here owns ITS OWN
 * header, allocated in one contiguous pool -- the off-by-one is a program bug,
 * not an allocator bug, and it is fully solvable without touching a single
 * byte of real chunk metadata.
 *
 * THE SHARED SKELETON (identical menu/prompts/I-O idiom across all six targets
 * in this family, including the negative control)
 * ---------------------------------------------------------------------------
 *   - one pool: `pool = malloc(POOL_SZ)`, records placed back-to-back at a
 *     FIXED stride (`SLOT_SZ`) -- the allocator itself never consults a
 *     record's own bookkeeping, so corrupting that bookkeeping cannot move
 *     where a record's true bytes live, only what a LATER reader believes
 *     about them.
 *   - each record: a small program-owned header immediately followed by a
 *     CAP-byte data field. The header's first field, whatever it is called in
 *     a given variant, is what the off-by-one corrupts.
 *   - menu: 1) create  2) set  3) show  4) trigger  5) delete  6) exit.
 *     "trigger" is the one command whose BEHAVIOUR is the family's variable --
 *     see THE ONE PARTICULAR below -- but its MENU LABEL and PROMPT-PROBING
 *     contract are identical, so the executor never needs to know its verb in
 *     advance.
 *   - show() dumps a record's RAW header+data, exactly like
 *     corpus_heap_variants' show_obj(): this is both the family's leak channel
 *     (a fresh record's handler field is `default_handler`, a PIE address) and
 *     the channel the exploit uses to read back the CORRUPTED header after
 *     triggering the bug, rather than assuming its post-corruption value.
 *   - win() spawns a shell and reads no flag itself: the only success signal
 *     is a real shell, which can then `cat flag.txt` beside the binary. No
 *     flag literal is ever compiled into this image.
 *
 * THE BUG (set(), identical in every positive, identical CODE SHAPE in the
 * negative control too)
 * ---------------------------------------------------------------------------
 *     if (n > CAP) n = CAP;                 -- inclusive: n == CAP survives
 *     memcpy(data_at(idx), buf, n);
 *     data_at(idx)[n] = 0;                  -- OOB by exactly one when n==CAP
 *
 * The clamp looks correct at a glance -- it rejects anything OVER CAP -- but
 * CAP itself is one past the last valid index of a CAP-byte array, so the
 * terminating NUL write at `data_at(idx)[CAP]` lands one byte past the
 * record's own data field: byte 0 of the header immediately following it.
 * That header belongs to record `idx+1` (or, in the negative control, to a
 * byte nothing downstream ever reads -- see the control's own header
 * comment).
 *
 * THE ONE PARTICULAR THIS TARGET VARIES
 * --------------------------------------
 * ANCHOR of the family. The corrupted field is `len`, a plain declared
 * capacity, the FIRST field of the header (so the off-by-one lands on its low
 * byte directly, byte-for-byte). `trigger` here is `scan()`: it walks the pool
 * starting at record 0, and for every hop it (a) CALLS that hop's `handler`
 * and (b) advances `cur += HDR_SZ + cur->len` -- i.e. it uses the record's own
 * declared length to find the next record, exactly the way a compacting
 * allocator would.
 *
 * `len` is always < 256 for a legitimately created record (CAP is 24), so its
 * upper three bytes are already zero and the off-by-one's NUL write collapses
 * the whole 32-bit field to exactly 0 -- not "some now-wrong value", a
 * PARTICULAR one, and the exploit reads it back off the target's own show()
 * rather than assuming that. When scan() reaches the corrupted record, its hop
 * formula becomes `cur + HDR_SZ + 0`, i.e. it lands INSIDE that very record's
 * own data field, at the exact byte offset it read back. Nothing has to leave
 * the corrupted record's own storage: everything scan() then reads there is
 * bytes the operator placed with a perfectly ordinary set() call. Craft those
 * bytes as a fake header -- a small length and `win`'s address, leaked earlier
 * off a legitimate record's own handler field -- and scan()'s next hop calls
 * it.
 *
 * Solve shape: create 0 ; create 1 ; show 0 (PIE leak) ; set(0, 24 bytes of
 * filler -- the off-by-one) ; set(1, fake header: len=0, handler=&win) ;
 * trigger(0).
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON (see ./cflags; glibc version
 * this was built and tested against is recorded there too).
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

/* A static const template, copied by memcpy rather than assigned field by
 * field. On a PIE image `default_handler`'s address here is filled in by the
 * dynamic linker's own relocations before main() ever runs -- there is no
 * `lea <fn>; mov [obj+N],<fn>` INSTRUCTION PAIR anywhere in this image
 * publishing a handler into a record, which is a different fact than
 * `heap_record_hijack`'s gate looks for (see the executor's module docstring
 * for the measured consequence). */
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
    puts("=== off-by-NUL variant: len field -> scan() handler overlap ===");

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
