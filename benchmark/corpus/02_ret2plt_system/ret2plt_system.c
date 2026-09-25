/*
 * Target 02: stack buffer overflow, NX on, no PIE, no canary.
 * Technique: ret2plt / ret2system -- system() is already reachable via the
 * binary's own PLT and a "/bin/sh" string already lives in the binary, so
 * no libc leak is required at all.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * `gadget_pop_rdi_ret` is deliberately compiled in (and kept via the `used`
 * attribute so the compiler can't discard it) to guarantee a `pop rdi; ret`
 * gadget exists at a fixed, discoverable address -- x86-64 calling
 * convention needs the argument to system() in RDI, so the classic 32-bit
 * "stack arg" ret2plt trick does not translate directly to 64-bit without
 * a register-loading gadget.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *g_shell_cmd = "/bin/sh";

__attribute__((naked, used))
void gadget_pop_rdi_ret(void) {
    asm volatile ("pop %rdi; ret");
}

/* Ensures system() is imported (present in the PLT) and the "/bin/sh"
 * string is embedded in the binary, without ever actually running it
 * during normal execution. */
__attribute__((noinline, used))
void unreachable_shell(void) {
    if (getenv("SUPWNGO_NEVER_SET_THIS")) {
        system(g_shell_cmd);
    }
}

void vuln(void) {
    char buf[64];

    printf("Input: ");
    fflush(stdout);
    read(0, buf, 300); /* buf is 64 bytes: no canary to stop the overflow */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 02 ret2plt-ret2system (NX on, no canary/PIE) ===");
    vuln();
    puts("done");
    return 0;
}
