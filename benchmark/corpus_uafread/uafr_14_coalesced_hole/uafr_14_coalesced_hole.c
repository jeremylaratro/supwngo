/*
 * uafr_14_coalesced_hole
 *
 * ASSUMPTION THIS VARIANT BREAKS: "a use-after-free read needs a pointer that
 * outlives the free." There is none. delete() here clears the slot pointer, the
 * length, the state, every alias, the creation registry AND the high-water
 * mark; after it returns, no pointer to the released body exists anywhere in
 * the program. The bug is a use-after-free of the REGION.
 *
 * MECHANISM: a note's 0x420 chunk borders the top chunk, so free() consolidates
 * it into top without writing anything into the body. report() then malloc()s a
 * workspace of 2*sizeof(struct note) -- LARGER than the note -- which is carved
 * from top at exactly the released body's address, writes a 13-byte banner into
 * it and hands the whole 2080 bytes to write(). The released note's text, and
 * with it the flag at offset 32, is inside that dump.
 *
 * SOLVE: delete(0); report().
 *
 * CATEGORY, HELD CONSTANT ACROSS benchmark/corpus_uafread/
 *   CWE-416 (use after free) used for CWE-200 (information disclosure). The
 *   secret is never printed by a win() function and no control flow is ever
 *   redirected; the program simply READS BYTES IT HAS ALREADY FREED and writes
 *   them to stdout. The success signal for this whole family is therefore
 *   FLAG_CAPTURED, not SHELL_ACCESS.
 *
 * HELD CONSTANT IN ALL SIX TARGETS
 *   * the menu (create / delete / show / list / bookmark / recall / retype /
 *     report / exit), the prompt words, and the banner;
 *   * `struct note` and the secret's placement: text at body+16, 16 bytes of
 *     'A' padding, FLAG at body+32;
 *   * sizeof(struct note) == 1040 -> a 0x420 chunk, above glibc's tcache
 *     ceiling, so every free() goes to the unsorted bin or straight into top;
 *   * the system note at slot 0, marked SLOT_SYSTEM, which every SAFE reader
 *     refuses -- so no target in this family has a benign path to the secret;
 *   * that free() does not wipe the released body. That is the PRECONDITION of
 *     the category, not the variable;
 *   * cflags (byte-identical across the family: canary, PIE, Full RELRO, NX,
 *     -O0).
 *
 * THE ONE VARIABLE
 *   WHICH READ PATH REACHES THE FREED BODY, chosen so that each positive
 *   defeats a DIFFERENT plausible assumption a detector might make. Exactly one
 *   command in each positive is the unsafe one; every other command is
 *   byte-identical to the negative control's safe version.
 *
 *     uafr_10  show() reads a slot the release path deliberately left pointing
 *              at the freed body, because its refusal set forgot SLOT_RETIRED.
 *     uafr_11  the release path DOES clear the slot pointer; a bulk list()
 *              reads a creation registry bounded by a never-lowered high-water
 *              mark.
 *     uafr_12  the index is LIVE and its pointer freshly allocated; only the
 *              stored LENGTH is stale, so the read runs off the new content
 *              into the previous occupant's tail.
 *     uafr_13  a second table aliases the pointer; authorisation is re-checked
 *              against the table that WAS updated, the read goes through the
 *              one that was not.
 *     uafr_14  no surviving pointer at all; the freed region is consolidated
 *              and handed out again inside a LARGER, uninitialised allocation.
 *     uafr_90  NEGATIVE CONTROL: every path safe. free() wipes the body first,
 *              clears the slot, invalidates aliases, lowers the high-water
 *              mark; every reader admits SLOT_USER only; retype() zeroes its
 *              replacement and updates the length; report() uses calloc().
 *              There is NO path that reads freed memory.
 *
 * GROUND TRUTH (version-sensitive; re-check before comparing results)
 *   glibc  2.35   (Ubuntu GLIBC 2.35-0ubuntu3.15)   -- `ldd --version`
 *   gcc    11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04.3)  -- `gcc --version`
 *   x86-64, Ubuntu 22.04, kernel 6.8.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_uafr_14_coalesced_hole}"
#endif

#define MAX_NOTES  8
#define MAX_MARKS  8
#define TEXT_SZ    1024
#define PAD_SZ     16

/* Slot lifecycle. RETIRED exists because a real note manager distinguishes
 * "never used" from "the operator released it": the audit trail wants to know
 * a slot HELD something. Whether every reader remembers to refuse it is the
 * kind of thing that varies between programs -- see uafr_10. */
enum slot_state { SLOT_EMPTY = 0, SLOT_USER = 1, SLOT_SYSTEM = 2, SLOT_RETIRED = 3 };

/* HELD CONSTANT ACROSS THE FAMILY -- the record, and where the secret sits in
 * it. sizeof(struct note) == 1040, so malloc() asks the allocator for a
 * 1040+8 -> 0x420 chunk. 0x420 is ABOVE glibc's largest tcache bin (0x410 on
 * x86-64, MINSIZE + 63*16), so on this libc every free() of a note bypasses
 * tcache entirely and goes to the unsorted bin -- or, when the chunk borders
 * the top chunk, is consolidated straight into top. Both paths are what make
 * the reuse geometry in uafr_12 and uafr_14 deterministic instead of
 * tcache-fill-order dependent, and the unsorted path writes exactly two
 * qwords (fd, bk) into the released body: `id` and `created`, and nothing
 * else. That is why those two fields are first and why the text starts at
 * +16.
 *
 * The flag is at text[PAD_SZ] == body offset 32, behind 16 bytes of 'A'
 * padding. Two reasons, both measured: the allocator's own bookkeeping can
 * only reach body[0..16), and a short reuse write of up to PAD_SZ bytes into
 * text[] (uafr_12) cannot reach it either. */
struct note {
    unsigned long id;        /* +0  clobbered by the unsorted-bin `fd` on free */
    unsigned long created;   /* +8  clobbered by the unsorted-bin `bk` on free */
    char          text[TEXT_SZ];   /* +16 ; FLAG at text[PAD_SZ] == body+32 */
};

#define WS_SZ (2 * sizeof(struct note))

static struct note *notes[MAX_NOTES];
static size_t       lens[MAX_NOTES];
static int          state[MAX_NOTES];
static int          high;                /* high-water slot count for list() */

/* A second registry of the same bodies, written by create() so that list()
 * can walk creation order without re-scanning notes[]. */
static struct note *shadow[MAX_NOTES];
static size_t       shadow_len[MAX_NOTES];

/* The bookmark table: a named alias for a note, so an operator can come back
 * to it without remembering the slot number. */
static struct note *marks[MAX_MARKS];
static size_t       mark_len[MAX_MARKS];
static int          mark_slot[MAX_MARKS];
static int          nmarks;

static int read_int(void) {
    int v = -1;
    if (scanf("%d", &v) != 1) exit(0);
    return v;
}

/* The one liveness predicate the safe readers share: only a slot the OPERATOR
 * created, still holding a pointer, may be read. A SYSTEM slot is sealed and a
 * released slot is gone. */
static int readable(int idx) {
    return idx >= 0 && idx < MAX_NOTES && state[idx] == SLOT_USER
           && notes[idx] != NULL;
}

static void forget_alias(int idx) {
    int i;
    for (i = 0; i < nmarks; i++) {
        if (mark_slot[i] == idx) {
            marks[i] = NULL;
            mark_len[i] = 0;
            mark_slot[i] = -1;
        }
    }
}

/* The system note. Pre-populated at startup with the deployment secret and
 * marked SLOT_SYSTEM, which every safe reader in this family refuses. There is
 * no command that unseals it, so in the negative control the bytes below are
 * unreachable for the whole life of the process. */
static void seed_vault(void) {
    struct note *n = malloc(sizeof *n);
    if (!n) exit(1);
    memset(n, 0, sizeof *n);
    n->id = 0;
    n->created = 1;
    memset(n->text, 'A', PAD_SZ);
    memcpy(n->text + PAD_SZ, FLAG, strlen(FLAG) + 1);
    notes[0] = n;
    lens[0] = TEXT_SZ;
    state[0] = SLOT_SYSTEM;
    shadow[0] = n;
    shadow_len[0] = TEXT_SZ;
    high = 1;
}

static void cmd_create(void) {
    int idx;
    long sz;
    struct note *n;
    ssize_t got;

    printf("index: ");
    idx = read_int();
    printf("size: ");
    sz = read_int();
    if (idx < 0 || idx >= MAX_NOTES || state[idx] != SLOT_EMPTY) {
        puts("bad");
        return;
    }
    if (sz <= 0 || sz > TEXT_SZ) {
        puts("bad");
        return;
    }
    n = malloc(sizeof *n);
    if (!n) {
        puts("bad");
        return;
    }
    memset(n, 0, sizeof *n);
    n->id = (unsigned long)idx;
    notes[idx] = n;
    printf("data: ");
    got = read(0, n->text, (size_t)sz);
    if (got < 0) got = 0;
    lens[idx] = (size_t)sz;
    state[idx] = SLOT_USER;
    shadow[idx] = n;
    shadow_len[idx] = (size_t)sz;
    if (idx + 1 > high) high = idx + 1;
    puts("ok");
}

/* Release, this variant. Everything is cleared: the slot pointer, the length,
 * the state, every alias, the creation registry and the high-water mark. After
 * this call NO pointer to the released body exists anywhere in the program, so
 * there is no dangling handle to find. The single omission is that the body is
 * not wiped -- and on this allocator a note's 0x420 chunk borders the top
 * chunk, so the release consolidates it into top without writing a single byte
 * into the body. */
static void cmd_delete(void) {
    int idx;

    printf("index: ");
    idx = read_int();
    if (idx < 0 || idx >= MAX_NOTES || state[idx] == SLOT_EMPTY
        || notes[idx] == NULL) {
        puts("bad");
        return;
    }
    free(notes[idx]);
    notes[idx] = NULL;
    lens[idx] = 0;
    state[idx] = SLOT_EMPTY;
    forget_alias(idx);
    shadow[idx] = NULL;
    shadow_len[idx] = 0;
    if (idx + 1 == high) high = idx;
    puts("ok");
}

/* SAFE. One predicate, and it admits SLOT_USER only. */
static void cmd_show(void) {
    int idx;

    printf("index: ");
    idx = read_int();
    if (!readable(idx)) {
        puts("sealed");
        return;
    }
    write(1, notes[idx]->text, lens[idx]);
    putchar('\n');
}

/* SAFE. Bounded by the live high-water mark and filtered through the same
 * predicate show() uses, reading notes[] rather than the creation registry. */
static void cmd_list(void) {
    int i;

    for (i = 0; i < high; i++) {
        if (!readable(i)) continue;
        printf("[%d] ", i);
        write(1, notes[i]->text, lens[i]);
        putchar('\n');
    }
    puts("ok");
}

/* SAFE. Only a readable note may be aliased, so a sealed system note can
 * never get a second handle. */
static void cmd_bookmark(void) {
    int idx;

    printf("index: ");
    idx = read_int();
    if (!readable(idx)) {
        puts("sealed");
        return;
    }
    if (nmarks >= MAX_MARKS) {
        puts("bad");
        return;
    }
    marks[nmarks] = notes[idx];
    mark_len[nmarks] = lens[idx];
    mark_slot[nmarks] = idx;
    printf("bookmark %d\n", nmarks);
    nmarks++;
}

/* SAFE. The alias is only honoured while it still AGREES with notes[]: same
 * slot, still SLOT_USER, same pointer. A released body fails all three. */
static void cmd_recall(void) {
    int id, slot;

    printf("id: ");
    id = read_int();
    if (id < 0 || id >= nmarks || marks[id] == NULL) {
        puts("bad");
        return;
    }
    slot = mark_slot[id];
    if (slot < 0 || slot >= MAX_NOTES) {
        puts("stale");
        return;
    }
    if (state[slot] != SLOT_USER || notes[slot] != marks[id]) {
        puts("stale");
        return;
    }
    write(1, marks[id]->text, mark_len[id]);
    putchar('\n');
}

/* SAFE. Refuses a sealed note, wipes the old body before releasing it, hands
 * out a ZEROED replacement, and updates the length to the new one. */
static void cmd_retype(void) {
    int idx;
    long sz;
    struct note *n;
    ssize_t got;

    printf("index: ");
    idx = read_int();
    printf("size: ");
    sz = read_int();
    if (!readable(idx)) {
        puts("sealed");
        return;
    }
    if (sz <= 0 || sz > TEXT_SZ) {
        puts("bad");
        return;
    }
    memset(notes[idx], 0, sizeof *notes[idx]);
    free(notes[idx]);
    notes[idx] = NULL;
    forget_alias(idx);
    n = calloc(1, sizeof *n);
    if (!n) {
        state[idx] = SLOT_EMPTY;
        puts("bad");
        return;
    }
    n->id = (unsigned long)idx;
    notes[idx] = n;
    printf("data: ");
    got = read(0, n->text, (size_t)sz);
    if (got < 0) got = 0;
    lens[idx] = (size_t)sz;
    shadow[idx] = n;
    shadow_len[idx] = (size_t)sz;
    puts("ok");
}

/* THE DEFECT OF THIS VARIANT. The report workspace is TWICE the size of a
 * note (0x830 chunk) -- larger than anything this program ever released -- and
 * it is malloc()ed rather than calloc()ed, with only the 13-byte banner
 * written into it before the whole 2080 bytes are handed to write().
 *
 * That matters because of where the memory comes from. A released note is
 * consolidated into the top chunk, so the top chunk's base moves back to the
 * released body's address; the next allocation -- of ANY size, including one
 * far larger than the note -- is carved from exactly there. So ws[0..1040)
 * IS the released note's body, ws + 32 is where its text's flag sat, and the
 * banner only covers ws[0..13).
 *
 * There is no use-after-free of a POINTER here. It is a use-after-free of the
 * REGION: the program discloses bytes it freed, through an allocation it made
 * afterwards and never initialised past the banner. */
static void cmd_report(void) {
    char *ws;

    ws = malloc(WS_SZ);
    if (!ws) {
        puts("bad");
        return;
    }
    memcpy(ws, "== report ==\n", 13);
    write(1, ws, WS_SZ);
    free(ws);
    puts("ok");
}

static void menu(void) {
    puts("1) create  2) delete  3) show  4) list");
    puts("5) bookmark  6) recall  7) retype  8) report  9) exit");
    printf("> ");
}

int main(void) {
    /* Both streams unbuffered BEFORE the first allocation, and that ordering is
     * load-bearing family geometry rather than tidiness:
     *   * it keeps glibc from mallocing a 0x1000 stdio buffer on the first
     *     scanf(), which would sit between the system note and the top chunk
     *     and make the consolidation in uafr_14 impossible;
     *   * an unbuffered stdin makes scanf() consume exactly one byte at a time,
     *     so a raw read(0, ...) that follows a scanf() cannot lose its bytes to
     *     the FILE buffer. The mixing of scanf() and read() is then
     *     timing-independent for every driver, not just for one that happens to
     *     wait for each prompt. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("=== uaf notes ===");
    seed_vault();

    while (1) {
        menu();
        switch (read_int()) {
            case 1: cmd_create(); break;
            case 2: cmd_delete(); break;
            case 3: cmd_show(); break;
            case 4: cmd_list(); break;
            case 5: cmd_bookmark(); break;
            case 6: cmd_recall(); break;
            case 7: cmd_retype(); break;
            case 8: cmd_report(); break;
            case 9: puts("bye"); return 0;
            default: puts("bad"); break;
        }
    }
}
