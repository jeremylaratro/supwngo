/*
 * Round-2 Target 04: stack buffer overflow with the stack canary ON, no PIE.
 * Technique: leak the canary indirectly through a second, smaller relay
 * buffer, then bypass it and redirect control flow to win().
 *
 * Protections: canary=ON, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * Deliberately different shape from round-1's 04_canary_leak_bypass:
 *  - `buf` is 64 bytes here (not 72). Unlike round 1, the canary is NOT
 *    immediately adjacent to buf on this build: objdump confirms an
 *    8-byte compiler-inserted alignment gap between buf's end (rbp-0x10)
 *    and the canary (rbp-0x8), so the leak reads buf+72, not buf+64 --
 *    a genuinely different (and non-obvious) offset an automated tool
 *    has to get right, not just assume.
 *  - Those 8 canary bytes are copied into a separate 16-byte `relay_buf`
 *    via memcpy() before being echoed with write(), instead of writing
 *    straight out of `buf` itself.
 *  - The real overflow read is a distinct third read() call, after an
 *    intermediate "menu" prompt, rather than immediately following the
 *    leak.
 */
#include <stdio.h>
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
        fputs(flag, stdout); /* flag.txt already ends in '\n' */
    }
    fclose(f);
}

void win(void) {
    print_flag();
}

void vuln(void) {
    char buf[64];
    char relay_buf[16];
    memset(buf, 0, sizeof(buf));
    memset(relay_buf, 0, sizeof(relay_buf));

    printf("Name: ");
    fflush(stdout);
    read(0, buf, 64); /* fills buf right up to the canary boundary */

    /* The 8 bytes right after buf's declared 64 are compiler-inserted
     * stack-alignment padding (verified via objdump: buf sits at rbp-0x50,
     * the canary at rbp-0x8 -- an 8-byte gap, not immediate adjacency),
     * so the canary itself is 72 bytes past buf's start on this build. */
    memcpy(relay_buf, buf + 72, 8);

    printf("Relay: ");
    fflush(stdout);
    write(1, relay_buf, 8); /* indirect echo, not a direct buf write */
    putchar('\n');
    fflush(stdout);

    printf("Message: ");
    fflush(stdout);
    read(0, buf, 200); /* real overflow; needs the leaked canary to pass */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-04 canary-relay-bypass ===");
    vuln();
    puts("done");
    return 0;
}
