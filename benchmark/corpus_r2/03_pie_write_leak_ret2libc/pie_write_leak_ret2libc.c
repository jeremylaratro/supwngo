/*
 * Round-2 Target 03: PIE self-leak -> GOT leak -> ret2libc.
 *
 * Protections: canary=OFF, NX=ON, PIE=ON, RELRO=full (this toolchain
 * defaults PIE links to full RELRO -- see benchmark/README.md note in the
 * round-1 corpus for the same discrepancy), dynamic.
 *
 * Deliberately different shape from round-1's 03_pie_leak_ret2libc:
 *  - The self-leak is a raw 8-byte binary write() of a function pointer
 *    (`&vuln`), not a textual printf("%p", ...) leak. The exploit must
 *    unpack raw bytes (pwntools u64()) rather than parse hex text.
 *  - The second-stage GOT leak uses write@plt(1, &target_got, 8) for a
 *    clean, full 8-byte raw leak with no NUL-terminated-string truncation
 *    -- unlike a puts()-based leak, nothing here depends on where the
 *    leaked bytes' first zero byte falls.
 *  - vuln() is called only ONCE from main(); every subsequent overflow
 *    "round" is reached by the ROP chain returning to `&vuln` itself
 *    (self-referential looping), not by multiple source-level call sites.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Explicit, always-present gadgets (this small binary's own compiled code
 * has no incidental pop-rdi/pop-rsi-rdx sequences at -O0, same rationale
 * as targets 02 and 15): pop rdi; ret -- and pop rsi; pop rdx; ret -- so
 * the exploit can drive write@plt(1, addr, 8) and, later, a ret2libc
 * system@libc call, deterministically. */
__attribute__((naked, used)) void pop_rdi_gadget(void) {
    __asm__("pop %rdi\n\t"
             "ret\n\t");
}

__attribute__((naked, used)) void pop_rsi_rdx_gadget(void) {
    __asm__("pop %rsi\n\t"
             "pop %rdx\n\t"
             "ret\n\t");
}

__attribute__((naked, used)) void bare_ret_gadget(void) {
    __asm__("ret\n\t");
}

void vuln(void) {
    char buf[72];
    void (*self)(void) = vuln; /* raw pointer leak: exact PIE base of vuln */

    write(1, &self, sizeof(self));
    write(1, "\n", 1);

    read(0, buf, 500); /* buf is 72 bytes; room for a multi-round ROP chain */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-03 pie-write-leak-ret2libc ===");
    vuln();
    puts("done");
    return 0;
}
