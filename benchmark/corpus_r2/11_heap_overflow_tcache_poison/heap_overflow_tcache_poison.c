/*
 * Round-2 Target 11: heap-overflow-driven tcache poisoning -> a global
 * function-pointer table entry overwrite, escalated to win().
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * Deliberately a DIFFERENT bug class from round-1's 12_heap_tcache_poison
 * (which corrupted a freed chunk's tcache `next` field via a UAF *write*
 * primitive on an already-freed chunk, with no allocation-size overflow
 * involved at all). Here there is no UAF write and delete_note() clears
 * its slot correctly (no dangling pointer bug exists in this target); the
 * bug is a genuine heap buffer overflow (CWE-122): fill_note() checks the
 * attacker-supplied length only against a fixed upper bound (0x400), never
 * against the note's own allocated size, so a fill() call can write past
 * one chunk into an adjacent, already-freed chunk's tcache metadata (its
 * mangled `next` pointer) and redirect it. `dispatch_table` is declared
 * 16-byte aligned so the corrupted pointer lands cleanly on
 * tcache_get()'s alignment check without needing a byte-offset workaround.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The flag is intentionally NOT compiled into this binary (no literal in
 * .rodata that `strings`/ELF.search() could find with zero exploitation).
 * It is generated fresh per build by build_all_r2.sh and written to
 * flag.txt alongside the binary; win() reads it at runtime only after the
 * real bug has actually been exploited. */
static void print_flag(void) {
    FILE *f = fopen("flag.txt", "r");
    if (!f) {
        puts("flag.txt missing");
        return;
    }
    char flag[256];
    if (fgets(flag, sizeof(flag), f)) {
        fputs(flag, stdout);
    }
    fclose(f);
}

#define MAX_NOTES 8

typedef void (*handler_t)(void);

static char *chunks[MAX_NOTES];
static size_t alloc_sizes[MAX_NOTES];

static void noop(void) {
    puts("(noop)");
}

/* 16-byte aligned so a tcache-poisoned pointer landing here passes
 * glibc's tcache_get() aligned_OK() check with no offset adjustment. */
handler_t dispatch_table[4] __attribute__((aligned(16))) = {noop, noop, noop, noop};

void win(void) {
    print_flag();
}

static int read_int(void) {
    int v = -1;
    if (scanf("%d", &v) != 1) exit(0);
    return v;
}

static void create_note(void) {
    printf("index: ");
    fflush(stdout);
    int idx = read_int();
    printf("size: ");
    fflush(stdout);
    long sz = read_int();
    if (idx < 0 || idx >= MAX_NOTES || sz <= 0 || sz > 0x400) {
        puts("bad");
        return;
    }
    chunks[idx] = malloc((size_t)sz);
    alloc_sizes[idx] = (size_t)sz;
    printf("chunk[%d] @ %p\n", idx, (void *)chunks[idx]);
    puts("ok");
}

static void fill_note(void) {
    printf("index: ");
    fflush(stdout);
    int idx = read_int();
    if (idx < 0 || idx >= MAX_NOTES || !chunks[idx]) {
        puts("bad");
        return;
    }
    printf("len: ");
    fflush(stdout);
    long len = read_int();
    /* BUG: only an absolute upper bound is enforced -- never checked
     * against this note's own allocated size, so len can overflow into
     * the next chunk on the heap. */
    if (len < 0 || len > 0x400) {
        puts("bad");
        return;
    }
    printf("data: ");
    fflush(stdout);
    read(0, chunks[idx], (size_t)len);
    puts("ok");
}

static void delete_note(void) {
    printf("index: ");
    fflush(stdout);
    int idx = read_int();
    if (idx < 0 || idx >= MAX_NOTES || !chunks[idx]) {
        puts("bad");
        return;
    }
    free(chunks[idx]);
    chunks[idx] = NULL; /* correctly cleared: no dangling pointer here */
    puts("ok");
}

static void call_handler(void) {
    printf("index: ");
    fflush(stdout);
    int idx = read_int();
    if (idx < 0 || idx >= 4) {
        puts("bad");
        return;
    }
    dispatch_table[idx]();
}

static void menu(void) {
    puts("1) create  2) fill  3) delete  4) call  5) exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-11 heap-overflow -> tcache-poison -> dispatch-table hijack ===");

    while (1) {
        menu();
        int choice = read_int();
        switch (choice) {
            case 1: create_note(); break;
            case 2: fill_note(); break;
            case 3: delete_note(); break;
            case 4: call_handler(); break;
            case 5: puts("bye"); return 0;
            default: puts("bad"); break;
        }
    }
}
