/*
 * Round-2 Target 05: format-string arbitrary read used to defeat PIE (not
 * the canary), followed by a plain second-stage overflow straight to
 * win() once its real address is known.
 *
 * Protections: canary=OFF, NX=ON, PIE=ON, RELRO=partial, dynamic.
 *
 * Deliberately different shape and objective from round-1's
 * 05_fmtstr_arbread (which had canary=ON / PIE=OFF and leaked the
 * canary): here the canary is off entirely and PIE is on, so the
 * format-string leak's job is to recover a code pointer (a local copy of
 * `&vuln`, which the exploit is expected to discover empirically via
 * %N$p scanning, exactly as round 1's canary-index discovery was framed)
 * and use it to compute the binary's PIE base. Once the base is known,
 * win()'s real address (a fixed, statically-knowable offset from vuln())
 * is reachable directly -- no canary bypass needed since canary=OFF here.
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
    void (*self)(void) = vuln; /* spilled to the stack; discoverable via %N$p */
    char name[128];
    char buf[64];

    printf("name: ");
    fflush(stdout);
    ssize_t n = read(0, name, sizeof(name) - 1);
    if (n < 0) n = 0;
    name[n] = '\0';
    size_t len = strcspn(name, "\n");
    name[len] = '\0';

    printf(name); /* direct format-string vulnerability */
    putchar('\n');
    fflush(stdout);

    (void)self;
    printf("buf: ");
    fflush(stdout);
    /* buf sits at the very bottom of a large (0x60+128+64-ish) stack
     * frame; the saved return address is 232 bytes past buf's start on
     * this build (verified via objdump), so the read count must clear
     * that -- 200 was not enough and left the bug unreachable. */
    read(0, buf, 300); /* second-stage overflow, redirect to win() */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-05 fmtstr-pie-leak ===");
    vuln();
    puts("done");
    return 0;
}
