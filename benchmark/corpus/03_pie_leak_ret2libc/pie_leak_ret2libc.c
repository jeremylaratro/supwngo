/*
 * Target 03: stack buffer overflow, NX+PIE on, no canary.
 * Technique: PIE-defeating leak (puts() of a text pointer), then a second
 * stage that leaks a libc address via GOT, then ret2libc.
 *
 * Protections: canary=OFF, NX=ON, PIE=ON, RELRO=partial, dynamic.
 *
 * vuln() is called three times from main() so a real exploit can use
 * separate rounds for: (1) receive the free PIE-base leak, (2) leak
 * puts()'s real libc address via puts(puts@got) and return back into
 * vuln(), (3) call system("/bin/sh") from libc using the now-known base.
 * `gadget_pop_rdi_ret` guarantees a usable argument-loading gadget exists
 * at a PIE-relative, discoverable offset.
 */
#include <stdio.h>
#include <unistd.h>

__attribute__((naked, used))
void gadget_pop_rdi_ret(void) {
    asm volatile ("pop %rdi; ret");
}

void vuln(void) {
    char buf[64];

    /* "a puts() of a stack/text pointer" -- leaks this function's own
     * (PIE-relative) address, from which the PIE base is computable. */
    printf("Leak: %p\n", (void *)vuln);
    fflush(stdout);

    printf("Input: ");
    fflush(stdout);
    read(0, buf, 200); /* buf is 64 bytes: no canary to stop the overflow */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 03 pie-nx-leak-ret2libc ===");
    for (int i = 0; i < 3; i++) {
        vuln();
    }
    puts("done");
    return 0;
}
