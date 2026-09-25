/*
 * Target 12: menu-driven heap UAF *write* primitive escalated to a
 * tcache-poisoning arbitrary write, used to overwrite free@got with
 * win()'s address.
 *
 * Same create/delete bug as target 11 (delete() never clears the stored
 * pointer), plus edit(), which writes into a chunk with no check that it
 * hasn't already been freed -- a UAF *write*. That lets an attacker
 * corrupt a freed chunk's tcache `fd` pointer (glibc >= 2.32 safe-linking:
 * mangled = (chunk_addr >> 12) ^ target_addr) to redirect the next two
 * same-size allocations, landing one of them directly on free@got.
 * create() prints the allocated address as a convenience so the exploit
 * doesn't need a separate heap-address leak stage -- this target is about
 * the corruption primitive, not defeating heap ASLR (target 11 covers
 * leaks).
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial (GOT must stay
 * writable -- built without -z now), dynamic.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_12_heap_tcache_poison}"
#endif

#define MAX_NOTES 16

static char *chunks[MAX_NOTES];
static size_t sizes[MAX_NOTES];

void win(void) {
    puts(FLAG);
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
    sizes[idx] = (size_t)sz;
    printf("chunk[%d] @ %p\n", idx, (void *)chunks[idx]);
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
    /* BUG: chunks[idx] is never cleared -> dangling pointer (UAF). */
    puts("ok");
}

static void edit_note(void) {
    printf("index: ");
    fflush(stdout);
    int idx = read_int();
    if (idx < 0 || idx >= MAX_NOTES || !chunks[idx]) {
        puts("bad");
        return;
    }
    printf("data: ");
    fflush(stdout);
    /* BUG: no check that this chunk hasn't already been freed -> UAF
     * write, usable to corrupt tcache metadata of a freed chunk. */
    ssize_t n = read(0, chunks[idx], sizes[idx]);
    (void)n;
    puts("ok");
}

static void menu(void) {
    puts("1) create  2) delete  3) edit  4) exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 12 heap UAF-write -> tcache poisoning -> GOT overwrite ===");

    while (1) {
        menu();
        int choice = read_int();
        switch (choice) {
            case 1: create_note(); break;
            case 2: delete_note(); break;
            case 3: edit_note(); break;
            case 4: puts("bye"); return 0;
            default: puts("bad"); break;
        }
    }
}
