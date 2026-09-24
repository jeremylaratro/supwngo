/*
 * Target 04: stack buffer overflow with the stack canary ON, no PIE.
 * Technique: leak the canary by echoing raw stack bytes back to the
 * caller, then bypass it and redirect control flow to win().
 *
 * Protections: canary=ON, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * The first read() fills `buf` completely, then the program echoes back
 * `buf` plus the 8 bytes immediately after it -- the canary itself, in
 * full. This is a raw write(), not a printf("%s", ...) echo: %s would
 * stop at the very first NUL byte it encounters, which is exactly the
 * canary's own leading (lowest-address) byte (always 0x00 by design on
 * x86-64), leaking nothing at all. A second read() then performs the
 * real overflow using the canary value recovered from the echo.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_04_canary_leak_bypass}"
#endif

void win(void) {
    puts(FLAG);
}

void vuln(void) {
    char buf[72];
    memset(buf, 0, sizeof(buf));

    printf("Name: ");
    fflush(stdout);
    read(0, buf, 72); /* fills buf right up to the canary boundary */

    printf("Hello: ");
    fflush(stdout);
    write(1, buf, 72 + 8); /* raw echo: buf + all 8 canary bytes */
    putchar('\n');
    fflush(stdout);

    printf("Message: ");
    fflush(stdout);
    read(0, buf, 200); /* real overflow; needs the leaked canary to pass */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 04 canary-leak-then-bypass ===");
    vuln();
    puts("done");
    return 0;
}
