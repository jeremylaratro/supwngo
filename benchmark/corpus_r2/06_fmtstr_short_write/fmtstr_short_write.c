/*
 * Round-2 Target 06: format-string arbitrary write, %hn (2-byte write)
 * variant targeting an exact 16-bit magic value gate.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * Deliberately different shape and mechanic from round-1's
 * 06_fmtstr_arbwrite (which used a full 8-byte %n write to make a bool
 * nonzero):
 *  - The gate here is a 16-bit `auth_level` that must equal an EXACT
 *    magic value (0x1337), not just be nonzero -- the exploit must use
 *    printf's printed-character-count mechanism (padding width specifiers)
 *    to land the precise low-16-bit value, then a %N$hn directive (a
 *    2-byte write, not the full pointer-width %n).
 *  - The %hn directive still needs to come FIRST in the payload (same
 *    embedded-NUL-in-address ordering constraint as round 1's target 06:
 *    a raw address value placed before any directive can contain a 0x00
 *    byte that truncates printf's C-string parsing before a later
 *    directive is ever reached), but the write itself is a different
 *    primitive.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define AUTH_MAGIC 0x1337

static unsigned short auth_level = 0;

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
    char buf[128];

    printf("msg: ");
    fflush(stdout);
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n < 0) n = 0;
    buf[n] = '\0';

    printf(buf); /* direct format-string vulnerability */
    putchar('\n');
    fflush(stdout);

    if (auth_level == AUTH_MAGIC) {
        win();
    } else {
        puts("access denied");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-06 fmtstr-short-write ===");
    vuln();
    puts("done");
    return 0;
}
