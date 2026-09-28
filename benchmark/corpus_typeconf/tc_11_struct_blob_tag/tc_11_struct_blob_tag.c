/*
 * tc_11_struct_blob_tag
 *
 * FAMILY
 * ------
 * benchmark/corpus_typeconf/ -- TYPE CONFUSION THROUGH AN ATTACKER-CONTROLLED
 * UNION TAG (CWE-843) on a PIE + canary + Full-RELRO + NX binary. Every target
 * in the family is the SAME menu-driven cell manager with the SAME record
 * layout, the SAME leak channel, the SAME tag-guarded indirect call and the SAME
 * protections; what varies from target to target is HOW THE TAG COMES TO
 * DISAGREE WITH THE DATA, and nothing else.
 *
 * THE CATEGORY, PRECISELY
 * -----------------------
 * A record holds a union plus a separate `tag` field naming which arm is live.
 * The program writes the union through one arm (an integer, or inline bytes) and
 * later READS it through another (a function pointer) because the tag said so.
 * The attacker controls the tag independently of the data that was written, so
 * the confusion is in the GATE -- the `if (tag == TAG_FN)` that decides how the
 * bytes are interpreted -- and not in the payload. The bytes at the union offset
 * are exactly the bytes the program's own numeric writer put there; nothing
 * overflows, nothing is freed twice, no length is wrong, no index is out of
 * range.
 *
 * WHAT THIS IS NOT
 * ----------------
 * benchmark/corpus_objptr/ shares this family's DESTINATION -- an indirect call
 * through a pointer loaded out of a record -- and that reuse is deliberate,
 * because on a PIE + Full-RELRO image the program's own stored code pointer is
 * the cheapest reliable place to land. It does NOT share the cause: every
 * objptr_* target reaches its pointer by an out-of-bounds WRITE (a size
 * computation wraps, a bump allocator hands out a region smaller than the copy
 * that fills it) and every fnptr_* target by an unbounded read or an unchecked
 * table index. Here every write is in bounds, correctly sized, and lands exactly
 * where the program intended; what is wrong is which TYPE the program then
 * believes those in-bounds bytes have.
 *
 * SHARED SKELETON (byte-identical in all six targets)
 * ---------------------------------------------------
 *   - `struct cell` (32 bytes): `int tag` at +0, `int seq` at +4, the UNION at
 *     +8 (an `unsigned long num`, a `void (*fn)(void)`, and a `char str[8]` --
 *     three arms over the same eight bytes), `char label[16]` at +16.
 *   - `new cell`: mallocs a cell with a CONSTANT request size, installs
 *     `default_cell` into the pointer arm and sets `tag = TAG_FN`. That pairing
 *     is the program's own HONEST use of the pointer arm, and it is what makes
 *     the family's leak work.
 *   - `set num`: writes an operator-supplied integer into `u.num` AND sets
 *     `tag = TAG_NUM`. Correct, and identical in every target -- the writer
 *     always retags honestly, so a mismatch never originates here.
 *   - `set tag` / `reset`: the two functions a target may vary. In each target
 *     exactly ONE of them admits a mismatch; the other is written correctly.
 *   - `show`: dumps a record raw. For a freshly created cell that discloses
 *     `default_cell` -- a PIE code address -- which is the family's MANDATORY
 *     leak channel. Identical in every target, including the negative control,
 *     so it is never what distinguishes them.
 *   - `invoke`: `if (c->tag == TAG_FN) c->u.fn();` -- the indirect call, reloaded
 *     from the record, guarded by the tag. The only consumer of the pointer arm.
 *   - win() spawns a shell and deliberately does NOT print the flag, so the only
 *     success signal this family admits is a real shell reading flag.txt.
 *   - NO other primitive: `label` is read with its exact size, indices are
 *     bounds-checked on both sides, every allocation is
 *     `malloc(sizeof(struct cell))` (a compile-time immediate), and nothing is
 *     ever freed while a handle to it survives. Those absences are what make a
 *     solve here attributable to the tag and nothing else.
 *
 * THE SOLVE, IN ONE SENTENCE
 * --------------------------
 * Create a cell and `show` it to leak `default_cell` and recover the PIE base,
 * get win()'s address into the union as an INTEGER, make the tag say TAG_FN
 * while those bytes stand, and `invoke`.
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON dynamic (see ./cflags, which
 * also records the host toolchain this was built and tested against).
 *
 * THE ONE PARTICULAR THIS TARGET VARIES
 * -------------------------------------
 * MECHANISM: `reset` deserialises a 16-byte RECORD IMAGE straight over the head
 * of the cell with a single `read(0, c, 16)` -- `{int tag; int seq; union u;}`.
 * The tag and the payload therefore arrive TOGETHER, as ONE input, and the
 * program contains NO STORE TO THE TAG FIELD on this path at all: no `mov
 * DWORD PTR [rax+0x0], ...`, no assignment, nothing an author or a checker
 * could point at. `set tag` in this target is written correctly and refuses the
 * pointer arm outright, so the only route is the blob.
 *
 * THE ASSUMPTION IT BREAKS: "a mis-tag needs two operations -- write the data,
 * then re-tag it -- so guarding the tag-write operation closes the hole", and
 * its static cousin, "the defect will show up as a store into the tag field."
 * Here the mismatch is a single `read` of a struct-shaped buffer, the kind of
 * code every binary-format parser contains, and the tag is never assigned.
 *
 * FLAG{supwngo_bench_tc_11_struct_blob_tag}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_tc_11_struct_blob_tag}"
#endif

#define MAX_CELLS 16

/* The union's arms. TAG_FN is the POINTER arm and is program-only by intent:
 * `new cell` is the one place the program itself installs a code pointer. The
 * two data arms exist in every target so that the tag's domain is larger than a
 * boolean and a bound check on it is a plausible thing for an author to write.
 *
 * NUSER is the number of arms the operator is meant to be able to select. It is
 * 2 (num and str) in every target, and it is deliberately EQUAL TO TAG_FN --
 * which is what makes tc_12's off-by-one a single character rather than a
 * contrivance. */
#define TAG_NUM 0                /* u.num  -- an integer */
#define TAG_STR 1                /* u.str  -- eight inline bytes */
#define TAG_FN  2                /* u.fn   -- a code pointer */
#define NTAGS   3
#define NUSER   2                /* arms the operator may select */

struct cell {
    int  tag;                    /* +0  WHICH ARM IS LIVE */
    int  seq;                    /* +4  a serial number, so a record is never
                                  *     all zeroes and `show` always has content */
    union {
        unsigned long num;       /* +8  written as an INTEGER ... */
        void (*fn)(void);        /* +8  ... read as a CODE POINTER */
        char str[8];             /* +8  ... or written as inline BYTES */
    } u;
    char label[16];              /* +16 */
};

static struct cell *cells[MAX_CELLS];
static int next_seq = 1;

/* The program's own legitimate use of the pointer arm, and the family's leak. */
static void default_cell(void) { puts("[cell] default handler"); }

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

static unsigned long read_ulong(void) {
    unsigned long v = 0;
    if (scanf("%lu", &v) != 1) exit(0);
    return v;
}

static int ask_index(void) {
    printf("index: ");
    fflush(stdout);
    long idx = read_long();
    if (idx < 0 || idx >= MAX_CELLS) return -1;
    return (int)idx;
}

static void new_cell(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    struct cell *c = malloc(sizeof(struct cell));   /* a CONSTANT request size */
    if (!c) { puts("bad"); return; }
    memset(c, 0, sizeof(*c));
    c->seq = next_seq++;
    /* The program installs a code pointer and tags the cell accordingly. This
     * pairing is HONEST -- arm and data agree -- and it is the only place in the
     * program where the pointer arm is written. */
    c->u.fn = default_cell;
    c->tag = TAG_FN;
    cells[idx] = c;
    printf("label: ");
    fflush(stdout);
    ssize_t n = read(0, c->label, sizeof(c->label));   /* exact size: no overflow */
    (void)n;
    puts("ok");
}

/* Identical in every target, and CORRECT: the writer always retags. */
static void set_num(void) {
    int idx = ask_index();
    if (idx < 0 || !cells[idx]) { puts("bad"); return; }
    printf("num: ");
    fflush(stdout);
    unsigned long v = read_ulong();
    cells[idx]->u.num = v;
    cells[idx]->tag = TAG_NUM;    /* arm and data agree when leaving here */
    puts("ok");
}

/* ------------------------------------------------------------------------
 * THE TWO FUNCTIONS THIS FAMILY VARIES. In this target the defect is in
 * reset_cell(); the other one is written correctly.
 * ------------------------------------------------------------------------ */

/* CORRECT in this target, and correct in the same way the negative control is:
 * a tag change is not a field write, it is a RE-INITIALISATION of the arm it
 * names, and the pointer arm is not selectable at all. */
static void set_tag(void) {
    int idx = ask_index();
    if (idx < 0 || !cells[idx]) { puts("bad"); return; }
    printf("tag: ");
    fflush(stdout);
    long t = read_long();
    if (t != TAG_NUM && t != TAG_STR) { puts("bad tag"); return; }
    cells[idx]->tag = (int)t;
    if (t == TAG_NUM) cells[idx]->u.num = 0;
    else memset(cells[idx]->u.str, 0, sizeof(cells[idx]->u.str));
    puts("ok");
}

static void reset_cell(void) {
    int idx = ask_index();
    if (idx < 0 || !cells[idx]) { puts("bad"); return; }
    struct cell *c = cells[idx];
    printf("record: ");
    fflush(stdout);
    /* THE DEFECT: a 16-byte record image -- {tag, seq, union} -- is read
     * straight over the head of the cell. The tag and the bytes it describes
     * arrive in the SAME input, so there is no second operation to guard and no
     * assignment to the tag field anywhere on this path. The only validation
     * that could have helped ("does the arm this tag names match the bytes that
     * came with it?") is not expressible without knowing the answer. */
    ssize_t r = read(0, c, 16);
    (void)r;
    puts("ok");
}

static void show_cell(void) {
    int idx = ask_index();
    if (idx < 0 || !cells[idx]) { puts("bad"); return; }
    /* Raw record dump. For a freshly created cell this discloses default_cell --
     * a PIE code address -- which is the family's mandatory leak channel,
     * identical in every target including the negative control. */
    ssize_t w = write(1, cells[idx], sizeof(struct cell));
    (void)w;
    putchar('\n');
    fflush(stdout);
}

static void invoke_cell(void) {
    int idx = ask_index();
    if (idx < 0 || !cells[idx]) { puts("bad"); return; }
    struct cell *c = cells[idx];
    /* THE GATE. The tag alone decides how the eight bytes at +8 are interpreted,
     * and one of the three interpretations is "a function to call". */
    if (c->tag == TAG_FN) {
        c->u.fn();                /* the indirect call, reloaded from the record */
    } else if (c->tag == TAG_STR) {
        printf("str = %.8s\n", c->u.str);
    } else {
        printf("num = %lu\n", c->u.num);
    }
    fflush(stdout);
}

static void menu(void) {
    puts("1) new cell   2) set num    3) set tag");
    puts("4) show       5) invoke     6) reset      7) exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== typeconf: tag and payload arrive in one struct-shaped read ===");

    while (1) {
        menu();
        switch (read_long()) {
            case 1: new_cell(); break;
            case 2: set_num(); break;
            case 3: set_tag(); break;
            case 4: show_cell(); break;
            case 5: invoke_cell(); break;
            case 6: reset_cell(); break;
            case 7: puts("bye"); return 0;
            default: puts("bad"); break;
        }
    }
}
