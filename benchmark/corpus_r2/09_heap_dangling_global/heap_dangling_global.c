/*
 * Round-2 Target 09: use-after-free READ via a single dangling GLOBAL
 * pointer, distinct in shape from round-1's 11_heap_uaf_leak (which used
 * a multi-slot notes array with an index-driven delete()/show()).
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * There is no note index at all here: `note_ptr` is a single global heap
 * pointer, populated once at startup by alloc_note() with an inert
 * placeholder (NOT the flag). free_note() frees it but never clears the
 * global -- a dangling pointer. show_note() then reads through it with no
 * already-freed check.
 *
 * IMPORTANT (anti-gaming: the flag must not be recoverable from benign
 * use): the flag is NOT stored in note_ptr's memory at any point under
 * normal operation. It only ever gets written by check_license(), an
 * ordinary, unrelated internal routine that allocates its own same-size
 * buffer to hold an auth token -- if that allocation happens to be called
 * after free_note() and reuses the just-freed chunk (glibc tcache is
 * LIFO, so a same-size malloc() immediately after a matching free()
 * deterministically returns that exact chunk), check_license()'s own
 * legitimate write ends up landing on the memory note_ptr still
 * (incorrectly) references. Calling show_note() at any point BEFORE that
 * sequence (e.g. immediately after alloc_note(), or even right after
 * free_note() but before check_license()) prints only the placeholder or
 * corrupted tcache-metadata bytes -- never the flag. The flag is only
 * exposed by the genuine three-step UAF chain: free, reuse-for-something-
 * else, read-through-the-stale-pointer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NOTE_SIZE 80

/* The flag is intentionally NOT compiled into this binary (no literal in
 * .rodata that `strings`/ELF.search() could find with zero exploitation).
 * It is generated fresh per build by build_all_r2.sh and written to
 * flag.txt alongside the binary; check_license() reads it at runtime, the
 * same way a real auth-token loader would read a secret from disk. */
static void read_flag_into(char *dst, size_t cap) {
    memset(dst, 0, cap);
    FILE *f = fopen("flag.txt", "r");
    if (!f) return;
    fgets(dst, (int)cap, f);
    dst[strcspn(dst, "\n")] = '\0';
    fclose(f);
}

static char *note_ptr;

static void alloc_note(void) {
    note_ptr = malloc(NOTE_SIZE);
    memset(note_ptr, 'A', NOTE_SIZE); /* inert placeholder -- never the flag */
    puts("note allocated");
}

static void free_note(void) {
    if (!note_ptr) {
        puts("bad");
        return;
    }
    free(note_ptr);
    /* BUG: note_ptr is never cleared -> dangling global pointer (UAF). */
    puts("note freed");
}

static void show_note(void) {
    if (!note_ptr) {
        puts("bad");
        return;
    }
    puts(note_ptr + 16); /* no check that note_ptr was already freed */
}

/* Ordinary, unrelated internal routine (e.g. loading a session auth
 * token) -- has no bug of its own. It allocates a same-size buffer and
 * fills it with the real secret. It intentionally leaks its own local
 * `tok` handle (nothing else in the program keeps a reference to it);
 * the only remaining way to reach that memory afterward is through
 * whatever OTHER stale pointer happens to still reference it, exactly
 * like real-world allocator-reuse UAF impact. */
static void check_license(void) {
    char *tok = malloc(NOTE_SIZE);
    memset(tok, 0, NOTE_SIZE);
    read_flag_into(tok + 16, NOTE_SIZE - 17);
    puts("license ok");
}

static void menu(void) {
    puts("1) alloc  2) free  3) show  4) check-license  5) exit");
    printf("> ");
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-09 heap-dangling-global ===");

    while (1) {
        menu();
        int choice;
        if (scanf("%d", &choice) != 1) break;
        switch (choice) {
            case 1: alloc_note(); break;
            case 2: free_note(); break;
            case 3: show_note(); break;
            case 4: check_license(); break;
            default: puts("bye"); return 0;
        }
    }
    puts("done");
    return 0;
}
