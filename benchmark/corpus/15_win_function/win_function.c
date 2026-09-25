/*
 * Target 15: sanity baseline. Plain stack buffer overflow, no
 * protections beyond NX (irrelevant here since no shellcode is needed),
 * redirecting the return address straight to a hidden win() function.
 * This is the simplest possible target in the corpus and should be
 * trivially solvable by any working automated pipeline.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=FULL (does not affect
 * solvability -- included here purely for RELRO-level variety, since
 * ret2win never touches the GOT), dynamic.
 */
#include <stdio.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_15_win_function}"
#endif

void win(void) {
    puts(FLAG);
}

void vuln(void) {
    char buf[32];

    printf("Say something: ");
    fflush(stdout);
    read(0, buf, 200); /* buf is 32 bytes: no canary to stop the overflow */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 15 win-function baseline ===");
    vuln();
    puts("done");
    return 0;
}
