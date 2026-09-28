/*
 * alloc_11_add_wrap_sizemax
 *
 * FAMILY
 * ------
 * benchmark/corpus_allocsize/ -- an integer overflow in an ALLOCATION SIZE
 * (CWE-190 -> CWE-122/787) on a PIE + canary + Full-RELRO + NX binary. Every
 * target in the family is the SAME menu-driven vector/job manager with the SAME
 * protections; what varies from target to target is THE ARITHMETIC THAT
 * COMPUTES THE ALLOCATION SIZE, and nothing else.
 *
 * Shared skeleton (byte-identical in all six targets):
 *   - `struct job`: 16 bytes of label, then a HANDLER POINTER at offset 16,
 *     allocated with a CONSTANT request size (sizeof(struct job) == 0x58).
 *   - `new_vec`: reads a count and computes an allocation size from it. THIS is
 *     the function each target varies.
 *   - `fill_vec`: writes vbytes[idx] bytes (capped at COPYCAP == 0x100) into the
 *     vector. vbytes[] is the HONEST length, derived from the same count but by
 *     an expression that does not wrap -- so when new_vec's arithmetic wraps,
 *     the allocation is tiny and the transfer is not.
 *   - menu: 1) new job  2) new vec  3) fill vec  4) delete  5) show  6) run
 *           7) exit
 *   - the family's MANDATORY LEAK: show() dumps a record raw, so a job record
 *     discloses its handler -- a PIE code address. Without it win() cannot be
 *     addressed at all. Identical in every target, including the negative
 *     control, so it is never what distinguishes them.
 *   - delete() NULLs the handle, so there is NO use-after-free and NO
 *     double-free primitive here; and fill_vec()'s length is the vector's own
 *     recorded length, so there is no "clamp to a fixed scratch size" overflow
 *     either. Those are benchmark/corpus_heap_variants/'s primitives, and their
 *     deliberate ABSENCE is what makes this family's solve attributable to the
 *     size arithmetic alone.
 *   - win() spawns a shell and deliberately does NOT print the flag, so the only
 *     success signal is a real shell reading flag.txt.
 *
 * THE SOLVE, IN ONE SENTENCE
 * -------------------------
 * Make new_vec's arithmetic wrap so malloc hands out the minimum chunk (0x20),
 * allocate a job record immediately above it, leak the job's default handler for
 * the PIE base, then let fill_vec's untruncated length run out of the tiny chunk
 * and across the job's `run` pointer, and select "run".
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON dynamic (see ./cflags, which
 * also records the glibc version this was built and tested against: 2.35).
 *
 * THE ONE PARTICULAR THIS TARGET VARIES
 * -------------------------------------
 * ARITHMETIC: `size_t nbytes = len + 1;` -- the "+1 for the terminator" idiom,
 * which wraps to 0 at the very top of the size_t range.
 *
 * WRAPPING INPUT: len == 18446744073709551615 (SIZE_MAX). SIZE_MAX + 1 == 0, so
 * malloc(0) hands back the minimum 0x20 chunk. There is EXACTLY ONE value that
 * triggers this, which is the point.
 *
 * THE ASSUMPTION IT BREAKS: "a +1 is too small to overflow anything" -- and,
 * more usefully for a detector, "the wrapping input is a quotient of 2**32 or
 * 2**64 by the element size". This target has no multiply at all: its only
 * wrapping input is SIZE_MAX itself, so a candidate sweep built purely out of
 * products misses it. It is also the one variant whose count is a BYTE length
 * rather than an element count.
 *
 * FLAG{supwngo_bench_alloc_11_add_wrap_sizemax}
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_alloc_11_add_wrap_sizemax}"
#endif

#define MAX_OBJS 20
#define OBJ_SZ   0x58            /* sizeof(struct job); a fixed malloc immediate */
#define ELEM_SZ  16u             /* bytes per vector element */
#define VHDR     16u             /* a vector's fixed header, used by alloc_13 */
#define COPYCAP  0x100           /* the transfer cap, identical in every target */
#define MAXREC   16              /* the legitimate element-count ceiling */

/* A record with a HANDLER POINTER at offset 16 -- the family's hijack target.
 * The offset is the same one benchmark/corpus_heap_variants/ uses, and for the
 * same reason: it is the first byte a free() does not clobber, so the field is
 * both leakable and overwritable without fighting the allocator. */
struct job {
    char label[16];
    void (*run)(void);
    char body[OBJ_SZ - 24];
};

static void  *objs[MAX_OBJS];
static char   kinds[MAX_OBJS];

/* The HONEST byte length of each vector, recorded by new_vec() and used by
 * fill_vec(). This is the second half of the defect: the allocation size is
 * computed by the wrapping expression, this one is not, and nothing ever
 * reconciles them. */
static size_t vbytes[MAX_OBJS];

static void default_run(void) { puts("[job] ran (default handler)"); }

/* The target. Deliberately prints NO flag: the only success signal this family
 * admits is a real shell (which can then read flag.txt beside the binary). */
void win(void) {
    puts("[win] shell");
    fflush(stdout);
    system("/bin/sh");
}

static long read_long(void) {
    long v = -1;
    if (scanf("%ld", &v) != 1) exit(0);
    return v;
}

static int ask_index(void) {
    printf("index: ");
    fflush(stdout);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_OBJS) return -1;
    return (int)idx;
}

static void new_job(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    struct job *j = malloc(sizeof(struct job));   /* a CONSTANT request size */
    if (!j) { puts("bad"); return; }
    memset(j, 0, sizeof(*j));
    j->run = default_run;
    objs[idx] = j;
    kinds[idx] = 'j';
    printf("label: ");
    fflush(stdout);
    ssize_t n = read(0, j->label, sizeof(j->label));
    (void)n;
    puts("ok");
}

/* ------------------------------------------------------------------------
 * THE ONE FUNCTION THIS TARGET VARIES.
 * ------------------------------------------------------------------------ */
static void new_vec(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    size_t len;
    printf("count: ");
    fflush(stdout);
    if (scanf("%zu", &len) != 1) exit(0);
    /* THE DEFECT: room for a terminator, added without checking the top of the
     * range. SIZE_MAX + 1 == 0. */
    size_t nbytes = len + 1;
    void *p = malloc(nbytes);
    if (!p) { puts("no space"); return; }
    objs[idx] = p;
    kinds[idx] = 'v';
    /* The honest length: `len` bytes, exactly as asked for. */
    vbytes[idx] = len;
    puts("ok");
}

/* Identical in every target: the transfer length comes from vbytes[], which the
 * wrapping arithmetic above never constrained. */
static void fill_vec(void) {
    int idx = ask_index();
    if (idx < 0 || !objs[idx] || kinds[idx] != 'v') { puts("bad"); return; }
    size_t want = vbytes[idx];
    if (want > COPYCAP) want = COPYCAP;
    printf("data: ");
    fflush(stdout);
    ssize_t r = read(0, objs[idx], want);
    (void)r;
    puts("ok");
}

static void delete_obj(void) {
    int idx = ask_index();
    if (idx < 0 || !objs[idx]) { puts("bad"); return; }
    free(objs[idx]);
    objs[idx] = NULL;           /* NO dangling pointer: the handle goes with the
                                 * chunk, so no use-after-free primitive exists
                                 * here -- this family's primitive is the size
                                 * arithmetic and nothing else. */
    kinds[idx] = 0;
    vbytes[idx] = 0;
    puts("ok");
}

static void show_obj(void) {
    int idx = ask_index();
    if (idx < 0 || !objs[idx]) { puts("bad"); return; }
    /* Raw record dump. For a job this discloses run() -- a PIE code address --
     * which is the family's mandatory leak channel, identical in every target
     * including the negative control. */
    ssize_t w = write(1, objs[idx], OBJ_SZ);
    (void)w;
    putchar('\n');
    fflush(stdout);
}

static void run_obj(void) {
    int idx = ask_index();
    if (idx < 0 || !objs[idx] || kinds[idx] != 'j') { puts("bad"); return; }
    struct job *j = objs[idx];
    j->run();                   /* the indirect call, reloaded from the record */
}

static void menu(void) {
    puts("1) new job    2) new vec    3) fill vec");
    puts("4) delete     5) show       6) run        7) exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== allocsize: size_t add wrap at SIZE_MAX ===");

    while (1) {
        menu();
        switch (read_long()) {
            case 1: new_job(); break;
            case 2: new_vec(); break;
            case 3: fill_vec(); break;
            case 4: delete_obj(); break;
            case 5: show_obj(); break;
            case 6: run_obj(); break;
            case 7: puts("bye"); return 0;
            default: puts("bad"); break;
        }
    }
}
