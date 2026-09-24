/*
 * Target 11: classic menu-driven heap use-after-free, used for a READ
 * leak. delete() frees a chunk but never NULLs the stored pointer, and
 * show() prints a chunk's contents with no check that it hasn't already
 * been freed -- a textbook dangling-pointer UAF read.
 *
 * At startup, note index 0 is pre-populated with a sensitive value (the
 * flag) and freed *by the program itself is not required* -- the attacker
 * reaches it themselves via the ordinary delete/show primitives: delete
 * index 0 (frees a chunk they never allocated) then show index 0 (reads
 * the still-resident bytes of the freed chunk). The first 16 bytes of the
 * freed chunk get clobbered by glibc's own tcache bookkeeping (the `key`
 * and safe-linking `next` fields), so the flag is placed starting at
 * offset 16 to survive that untouched.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_11_heap_uaf_leak}"
#endif

#define MAX_NOTES 16

static char *chunks[MAX_NOTES];
static size_t sizes[MAX_NOTES];

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
    printf("data: ");
    fflush(stdout);
    ssize_t n = read(0, chunks[idx], sizes[idx]);
    (void)n;
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

static void show_note(void) {
    printf("index: ");
    fflush(stdout);
    int idx = read_int();
    if (idx < 0 || idx >= MAX_NOTES || !chunks[idx]) {
        puts("bad");
        return;
    }
    /* BUG: no check that this chunk hasn't already been freed. */
    write(1, chunks[idx], sizes[idx]);
    putchar('\n');
}

static void menu(void) {
    puts("1) create  2) delete  3) show  4) exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 11 heap UAF (read leak) ===");

    /* Pre-populated "system note" at index 0, holding the flag. The
     * first 16 bytes are padding that tcache bookkeeping will clobber
     * once this chunk is freed; the flag text starts after that. */
    chunks[0] = malloc(80);
    sizes[0] = 80;
    memset(chunks[0], 'A', 16);
    memcpy(chunks[0] + 16, FLAG, strlen(FLAG) + 1);

    while (1) {
        menu();
        int choice = read_int();
        switch (choice) {
            case 1: create_note(); break;
            case 2: delete_note(); break;
            case 3: show_note(); break;
            case 4: puts("bye"); return 0;
            default: puts("bad"); break;
        }
    }
}
