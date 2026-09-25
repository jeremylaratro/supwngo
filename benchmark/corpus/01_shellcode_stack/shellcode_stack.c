/*
 * Target 01: classic stack buffer overflow, NO protections.
 * Technique: shellcode-on-stack.
 *
 * Protections: canary=OFF, NX=OFF, PIE=OFF, RELRO=partial, dynamic.
 *
 * `buf` is 64 bytes but the second read() accepts up to 300 bytes with no
 * bounds check, so the saved return address can be overwritten directly.
 * Since NX is off, the stack is executable, so shellcode can be placed in
 * `buf` and the return address can be pointed straight back at it.
 *
 * The program prints the address of `buf` before the overflow. This is a
 * deliberate, common convenience in this category of challenge: the
 * interesting property under test here is NX being off, not defeating
 * ASLR (that is exercised by target 03). Without this print, a stack
 * address would need to be guessed or leaked through some other channel
 * every run, which is a different (and already-covered) problem.
 */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[64];

    printf("buf @ %p\n", (void *)buf);
    fflush(stdout);

    printf("shellcode> ");
    fflush(stdout);
    read(0, buf, 300); /* buf is 64 bytes: classic unbounded overflow */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 01 shellcode-stack (no canary / no NX / no PIE) ===");
    vuln();
    puts("done");
    return 0;
}
