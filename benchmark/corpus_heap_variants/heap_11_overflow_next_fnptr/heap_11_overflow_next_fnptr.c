/*
 * heap_11_overflow_next_fnptr
 *
 * FAMILY
 * ------
 * benchmark/corpus_heap_variants/ -- glibc heap corruption (the tcache/fastbin
 * family) on a PIE + canary + Full-RELRO + NX binary. Every target in the family
 * is the SAME menu-driven record manager with the SAME protections; what varies
 * from target to target is WHICH HEAP PRIMITIVE the source exposes, and each
 * target exposes exactly one (see "THE ONE PARTICULAR" below).
 *
 * Shared skeleton (identical in all six targets):
 *   - two record kinds in the SAME size class, so one can be allocated over the
 *     other: a `job` (16 bytes of label, then a HANDLER POINTER at offset 16,
 *     then a body) and a `note` (a plain, fully attacker-controlled buffer).
 *   - menu: 1) new job  2) new note  3) delete  4) show  5) edit  6) run
 *           7) hooks  8) exit
 *   - the family's MANDATORY LEAK: show() dumps a record raw, so a job record
 *     discloses its handler -- a PIE code address. Without it win() cannot be
 *     addressed at all. It is identical in every target, including the negative
 *     control, so it is never what distinguishes them.
 *   - hooks[]: a 16-byte-aligned table of function pointers in .bss, called by
 *     option 7. Full RELRO makes the GOT read-only, so the writable code
 *     pointers a heap primitive can aim at are the program's own: a job's
 *     handler (on the heap) and this table.
 *   - win() spawns a shell and deliberately does NOT print the flag, so the only
 *     success signal is a real shell reading flag.txt.
 *
 * THE ONE PARTICULAR THIS TARGET VARIES
 * -------------------------------------
 * PRIMITIVE PRESENT: a FORWARD LINEAR HEAP OVERFLOW out of one chunk into the
 * ADJACENT chunk's handler pointer. Nothing is ever freed: edit() clamps its
 * length to a fixed 0x200 scratch size instead of the record's size, so writing
 * into a note runs off the end of its chunk, across the next chunk's size field,
 * and into the next record's handler at +16 of ITS user data.
 *
 * The anchor's primitive is REMOVED here (delete() drops the handle), so the
 * overflow is the only primitive present -- which is the point of the variant.
 *
 * Solve shape: new note 0 ; new job 1 (job sits ABOVE note 0, allocations come
 * off the top in order) ; show 1 (PIE leak) ;
 * edit 0 len=0x68 with 0x40 filler + p64(0x61) [the job chunk's size field,
 * preserved] + 16 filler + &win ; run 1.
 * Distances, for glibc 2.35 and malloc(0x58) -> chunk 0x60: user data at p+0x10,
 * edit writes from p+0x28, the next chunk's size field is at p+0x68 and its
 * handler at p+0x80.
 *
 * SOURCE DELTA vs the anchor (heap_10_uaf_reclaim_fnptr)
 * ------------------------------------------------------
 * two lines, one primitive:
 *   - delete() now NULLs objs[idx]      (the anchor's primitive removed)
 *   - edit()'s clamp is 0x200, not the record size   (this primitive added)
 *
 * Protections: PIE=ON canary=ON RELRO=FULL NX=ON dynamic (see ./cflags, which
 * also records the glibc version this was built and tested against: 2.35).
 *
 * FLAG{supwngo_bench_heap_11_overflow_next_fnptr}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_heap_11_overflow_next_fnptr}"
#endif

#define MAX_OBJS 20
#define OBJ_SZ   0x58            /* both kinds -> the same size class */
#define EDIT_OFF 24

/* A record with a HANDLER POINTER at offset 16. Offset 16 is load-bearing: both
 * a tcache free (next at +0, key at +8) and an unsorted-bin free (fd at +0, bk
 * at +8) clobber only the first 16 bytes of user data, so a handler at +16
 * SURVIVES the free and is still there to be leaked and to be overwritten. */
struct job {
    char label[16];
    void (*run)(void);
    char body[OBJ_SZ - 24];
};

/* Same size class, no structure: whatever the attacker sends lands verbatim. */
struct note {
    char data[OBJ_SZ];
};

static void *objs[MAX_OBJS];
static char  kinds[MAX_OBJS];
static int   live[MAX_OBJS];

/* Writable function-pointer table in .bss, forced 16-byte aligned so that a
 * tcache pop landing on it passes glibc's aligned_OK() check. Option 7 calls
 * hooks[0]. Under Full RELRO this and a heap-resident handler are the only
 * writable code pointers in the process image. */
static void (*hooks[4])(void) __attribute__((aligned(16)));

static void banner(void) { puts("[hook] nothing to see here"); }

/* Every job is created pointing here. show() dumps the record raw, so this
 * address is the family's PIE leak. */
static void default_run(void) { puts("[job] ran (default handler)"); }

/* The target. Deliberately prints NO flag: the only success signal this family
 * admits is a real shell (which can then read flag.txt beside the binary). */
void win(void) {
    puts("[win] shell");
    fflush(stdout);
    system("/bin/sh");
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
    if (idx < 0 || idx >= MAX_OBJS) return -1;
    return idx;
}

static void new_job(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    struct job *j = malloc(sizeof(struct job));
    if (!j) { puts("bad"); return; }
    memset(j, 0, sizeof(*j));
    j->run = default_run;
    objs[idx] = j;
    kinds[idx] = 'j';
    live[idx] = 1;
    printf("label: ");
    fflush(stdout);
    ssize_t n = read(0, j->label, sizeof(j->label));
    (void)n;
    puts("ok");
}

static void new_note(void) {
    int idx = ask_index();
    if (idx < 0) { puts("bad"); return; }
    struct note *n = malloc(sizeof(struct note));
    if (!n) { puts("bad"); return; }
    objs[idx] = n;
    kinds[idx] = 'n';
    live[idx] = 1;
    printf("data: ");
    fflush(stdout);
    /* Exactly as many bytes as arrive: read() returns short, so a caller can
     * write only the first few bytes of the record and leave the rest. */
    ssize_t r = read(0, n->data, sizeof(n->data));
    (void)r;
    puts("ok");
}

static void delete_obj(void) {
    int idx = ask_index();
    if (idx < 0 || !objs[idx]) { puts("bad"); return; }
    free(objs[idx]);
    objs[idx] = NULL;           /* NO dangling pointer: the handle is
                                 * dropped together with the chunk */
    kinds[idx] = 0;
    live[idx] = 0;
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

static void edit_obj(void) {
    int idx = ask_index();
    if (idx < 0 || !objs[idx]) { puts("bad"); return; }
    if (!live[idx]) {           /* edit refuses a dead record */
        puts("bad");
        return;
    }
    printf("len: ");
    fflush(stdout);
    long len = read_int();
    if (len <= 0) { puts("bad"); return; }
    /* BUG: clamped to a fixed 0x200 scratch size rather than to this
     * record's own size -> a forward overflow into the next chunk. */
    if (len > 0x200) len = 0x200;
    printf("data: ");
    fflush(stdout);
    ssize_t r = read(0, (char *)objs[idx] + EDIT_OFF, (size_t)len);
    (void)r;
    puts("ok");
}

static void run_obj(void) {
    int idx = ask_index();
    if (idx < 0 || !objs[idx] || kinds[idx] != 'j') { puts("bad"); return; }
    /* BUG: no liveness check -> a freed job can still be invoked
     * through its dangling pointer. */
    struct job *j = objs[idx];
    j->run();
}

static void call_hook(void) {
    hooks[0]();
}

static void menu(void) {
    puts("1) new job    2) new note   3) delete   4) show");
    puts("5) edit       6) run        7) hooks    8) exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    hooks[0] = banner;
    hooks[1] = banner;
    hooks[2] = banner;
    hooks[3] = banner;
    puts("=== heap variant: overflow into next chunk ===");

    while (1) {
        menu();
        switch (read_int()) {
            case 1: new_job(); break;
            case 2: new_note(); break;
            case 3: delete_obj(); break;
            case 4: show_obj(); break;
            case 5: edit_obj(); break;
            case 6: run_obj(); break;
            case 7: call_hook(); break;
            case 8: puts("bye"); return 0;
            default: puts("bad"); break;
        }
    }
}
