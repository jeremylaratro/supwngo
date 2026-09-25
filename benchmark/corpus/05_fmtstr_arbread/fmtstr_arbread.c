/*
 * Target 05: format-string vulnerability used for an arbitrary READ.
 * Technique: leak the stack canary through a directly user-controlled
 * format string (printf(name)), then perform an ordinary stack overflow
 * that needs the leaked canary to succeed and redirects to win().
 *
 * Protections: canary=ON, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * `name` is read into a local buffer and handed to printf() *as the
 * format string itself* -- the classic, plainly-visible format-string
 * bug. The exact %N$p offset that lines up with the canary depends on
 * the compiled stack layout and is meant to be discovered dynamically
 * (e.g. by probing %1$p.. %12$p), not hardcoded by the challenge author.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_05_fmtstr_arbread}"
#endif

void win(void) {
    puts(FLAG);
}

void vuln(void) {
    char name[64];
    char buf[64];

    printf("Name: ");
    fflush(stdout);
    ssize_t n = read(0, name, sizeof(name) - 1);
    if (n < 0) n = 0;
    name[n] = 0;

    printf(name); /* FORMAT STRING VULN: user input used as the format */
    fflush(stdout);

    printf("\nMessage: ");
    fflush(stdout);
    read(0, buf, 200); /* real overflow; needs the leaked canary to pass */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 05 format-string arbitrary-read (canary leak) ===");
    vuln();
    puts("done");
    return 0;
}
