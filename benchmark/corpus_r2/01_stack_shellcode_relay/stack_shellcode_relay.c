/*
 * Round-2 Target 01: classic stack buffer overflow, NO protections.
 * Technique: shellcode-on-stack.
 *
 * Protections: canary=OFF, NX=OFF, PIE=OFF, RELRO=partial, dynamic.
 *
 * Deliberately different shape from round-1's 01_shellcode_stack: the
 * overflow is not a direct read() into the vulnerable buffer. Untrusted
 * bytes are first read into a larger "network" staging buffer in relay(),
 * then memcpy()'d into the real 96-byte destination with no bound check
 * against the destination's size -- a classic "trusted the wrong length"
 * overflow shape, one call frame removed from vuln() itself.
 *
 * The program prints the destination buffer's address before the copy, the
 * same deliberate convenience as round 1 (NX-off is the property under
 * test here, not ASLR -- that's covered by target 03).
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void relay(char *dst) {
    char net[300];
    ssize_t n = read(0, net, sizeof(net));
    if (n <= 0) return;
    memcpy(dst, net, (size_t)n); /* no check that n fits dst's real size */
}

static void vuln(void) {
    char buf[96];

    printf("buf @ %p\n", (void *)buf);
    fflush(stdout);

    printf("shellcode> ");
    fflush(stdout);
    relay(buf); /* buf is 96 bytes; relay() can copy up to 300 */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-01 stack-shellcode-relay (no canary / no NX / no PIE) ===");
    vuln();
    puts("done");
    return 0;
}
