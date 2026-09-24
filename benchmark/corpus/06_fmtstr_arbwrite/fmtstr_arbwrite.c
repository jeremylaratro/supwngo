/*
 * Target 06: format-string vulnerability used for an arbitrary WRITE.
 * Technique: use a %n write to flip the `unlocked` global from 0 to
 * non-zero, which unlocks a call to win().
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial (GOT stays
 * writable -- overwriting free@got or another GOT entry instead of the
 * `unlocked` global is an equally valid alternate solve path), dynamic.
 */
#include <stdio.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_06_fmtstr_arbwrite}"
#endif

int unlocked = 0; /* %n write target */

void win(void) {
    puts(FLAG);
}

void vuln(void) {
    char buf[128];

    printf("unlocked @ %p\n", (void *)&unlocked);
    fflush(stdout);

    printf("Message: ");
    fflush(stdout);
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n < 0) n = 0;
    buf[n] = 0;

    printf(buf); /* FORMAT STRING VULN: arbitrary write via %n */
    fflush(stdout);

    if (unlocked) {
        win();
    } else {
        puts("locked.");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 06 format-string arbitrary-write ===");
    vuln();
    puts("done");
    return 0;
}
