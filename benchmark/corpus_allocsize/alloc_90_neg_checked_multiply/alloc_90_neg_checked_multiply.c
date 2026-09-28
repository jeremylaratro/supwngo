/*
 * alloc_90_neg_checked_multiply
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
 * NEGATIVE CONTROL. The same program with the arithmetic MADE SAFE, and
 * nothing else changed.
 *
 * ARITHMETIC: `if (count != 0 && count > SIZE_MAX / ELEM_SZ) reject;` before
 * `size_t nbytes = count * ELEM_SZ;` -- the checked multiply CWE-190 asks for,
 * done in the widest type, so the product cannot wrap. vbytes[] is then set from
 * the SAME expression, so the honest transfer length is identically equal to the
 * allocation and fill_vec() can never run off the end.
 *
 * WRAPPING INPUT: none exists. Every candidate the executor tries is either
 * rejected by the guard (2**60, SIZE_MAX, and every negative spelling, which
 * scanf("%lu") reads back as a value near 2**64) or honoured honestly with an
 * allocation at least as large as the transfer (2**28 -> a real 4 GiB request).
 *
 * WHY THE STATIC SHAPE IS UNCHANGED, DELIBERATELY. This control still calls
 * malloc with a size computed at run time from a scanf-read value; it still
 * publishes a handler into an allocated record; it still calls through that
 * handler indirectly; its show() is byte-identical to the positives'. So the
 * family's STATIC gate opens here, exactly as it does on the five positives, and
 * the control is declined by MEASUREMENT: no candidate makes the allocation
 * smaller than the transfer, which the executor proves by writing a marker
 * ladder and finding that it never reaches the neighbour's handler. Closing this
 * target statically would make the corpus discriminate on an artifact of the
 * guard's text instead of on the defect.
 *
 * FALSIFIABILITY: the control must still LEAK. show() on a job record discloses
 * default_run() here just as it does everywhere else, so a failure to exploit
 * this target cannot be blamed on a broken target or a broken harness -- the
 * reference exploit asserts the leak before asserting the refusal.
 *
 * FLAG{supwngo_bench_alloc_90_neg_checked_multiply}
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_alloc_90_neg_checked_multiply}"
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
    unsigned long count;
    printf("count: ");
    fflush(stdout);
    if (scanf("%lu", &count) != 1) exit(0);
    /* THE CONTROL: the multiply is checked before it is performed, in the
     * widest type, so the product cannot wrap. */
    if (count != 0 && count > (size_t)-1 / ELEM_SZ) { puts("too many"); return; }
    size_t nbytes = count * ELEM_SZ;
    void *p = malloc(nbytes);
    if (!p) { puts("no space"); return; }
    objs[idx] = p;
    kinds[idx] = 'v';
    /* Identically equal to the allocation, always. */
    vbytes[idx] = count * ELEM_SZ;
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
    puts("=== allocsize: checked multiply (negative control) ===");

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
