/*
 * Target 07: ret2libc via an info leak. No static system()/"/bin/sh" is
 * present anywhere in this binary -- the only way to get a shell is to
 * leak puts()'s real address via puts(puts@got), compute the libc base
 * from it, and then call system("/bin/sh") out of libc itself.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * vuln() is called three times from main(): round 1 leaks puts@got via a
 * ROP chain that returns back into vuln(), round 2 performs the final
 * ret2libc call using the now-known libc base. `gadget_pop_rdi_ret`
 * guarantees a usable argument-loading gadget exists.
 */
#include <stdio.h>
#include <unistd.h>

__attribute__((naked, used))
void gadget_pop_rdi_ret(void) {
    asm volatile ("pop %rdi; ret");
}

void vuln(void) {
    char buf[64];

    printf("Input: ");
    fflush(stdout);
    read(0, buf, 200); /* buf is 64 bytes: no canary to stop the overflow */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 07 ret2libc-via-leak (no static system/binsh) ===");
    for (int i = 0; i < 3; i++) {
        vuln();
    }
    puts("done");
    return 0;
}
