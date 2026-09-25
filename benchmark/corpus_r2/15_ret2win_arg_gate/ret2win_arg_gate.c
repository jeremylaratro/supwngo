/*
 * Round-2 Target 15: sanity baseline #2 -- plain stack overflow redirecting
 * to a win() that requires a specific integer ARGUMENT, not just a bare
 * call. Needs a one-gadget `pop rdi; ret` (explicitly embedded below so
 * the target is deterministic regardless of toolchain-incidental gadget
 * availability) plus the redirected return address.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=full, dynamic.
 *
 * Deliberately different from round-1's 15_win_function (a bare,
 * argument-free ret2win): this requires a minimal ROP chain (one
 * register-load gadget) rather than a single return-address overwrite,
 * while remaining a "should be trivially solvable by any working
 * automated pipeline" sanity check for the corpus's easy tier.
 */
#include <stdio.h>
#include <unistd.h>

#define WIN_MAGIC 0x1337L

/* The flag is intentionally NOT compiled into this binary (no literal in
 * .rodata that `strings`/ELF.search() could find with zero exploitation).
 * It is generated fresh per build by build_all_r2.sh and written to
 * flag.txt alongside the binary; win() reads it at runtime only after the
 * real bug has actually been exploited AND the correct argument was
 * supplied (the gate this target's ROP chain has to satisfy). */
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

void win(long magic) {
    if (magic == WIN_MAGIC) {
        print_flag();
    } else {
        puts("wrong magic");
    }
}

/* Explicit, always-present one-gadget: pop rdi; ret. Embedded deliberately
 * so this target's solvability does not depend on whatever incidental
 * gadgets a given toolchain version happens to emit elsewhere. */
__attribute__((naked, used)) void pop_rdi_gadget(void) {
    __asm__("pop %rdi\n\t"
             "ret\n\t");
}

void vuln(void) {
    char buf[48];

    printf("data> ");
    fflush(stdout);
    read(0, buf, 200); /* buf is 48 bytes: classic unbounded overflow */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-15 ret2win-arg-gate (sanity baseline, needs pop-rdi) ===");
    vuln();
    puts("done");
    return 0;
}
