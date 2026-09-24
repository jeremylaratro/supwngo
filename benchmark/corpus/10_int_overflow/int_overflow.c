/*
 * Target 10: signed-to-narrow-unsigned truncation bypassing a length
 * check, leading to a buffer overflow (CWE-190/CWE-197).
 *
 * Technique: `len_in` is a signed 32-bit int compared against an upper
 * bound only (`len_in > 64`); a negative `len_in` passes that check.
 * The value actually used for the read, though, is
 * `(unsigned char)len_in` -- an 8-bit truncation, not a 64-bit
 * sign-extension. Any negative `len_in` whose low byte exceeds 64 (e.g.
 * -1 truncates to 0xFF = 255) yields a small, safely-mappable byte count
 * that is still well past the end of the 64-byte buffer, so the overflow
 * is directly reachable via glibc's own read().
 *
 * (An earlier version of this target reinterpreted the raw 64-bit
 * sign-extension of a negative int as the read() count. That is a dead
 * end on real Linux: any negative 32-bit int sign-extends to a size_t
 * near 2**64, and the kernel's access_ok() check rejects a destination
 * range that large with EFAULT before ever touching the buffer --
 * regardless of whether the call goes through glibc's read() wrapper
 * (SSIZE_MAX guard) or a raw syscall(SYS_read, ...) [no such guard, but
 * the kernel's own range check still fires]. The byte-truncation variant
 * above is what real-world CWE-190/197 bugs of this shape actually look
 * like, and is genuinely exploitable.)
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 */
#include <stdio.h>
#include <unistd.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_bench_10_int_overflow}"
#endif

void win(void) {
    puts(FLAG);
}

void vuln(void) {
    char buf[64];
    int len_in;

    printf("Length: ");
    fflush(stdout);
    if (scanf("%d", &len_in) != 1) return;
    getchar(); /* consume the trailing newline */

    if (len_in > 64) { /* signed check only -- a negative len_in bypasses it */
        puts("too long");
        return;
    }

    /* BUG: the value actually used for the read is truncated to a single
     * unsigned byte, discarding the sign entirely -- a negative len_in
     * that satisfies the check above can still truncate to a byte count
     * greater than 64. */
    unsigned char len = (unsigned char)len_in;

    printf("Data: ");
    fflush(stdout);
    read(0, buf, len);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 10 integer-truncation size-check bypass ===");
    vuln();
    puts("done");
    return 0;
}
