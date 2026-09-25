/*
 * Target 09: SROP (sigreturn-oriented programming). Minimal gadgets --
 * only a `pop rax; ret` and a `syscall; ret` are guaranteed present
 * (deliberately compiled in below), which is not enough register control
 * to build a classic execve() ROP chain by hand, but is exactly what
 * SROP needs: set rax=15 (rt_sigreturn), hit the syscall gadget, and let
 * the kernel restore a fully attacker-controlled register state (a
 * pwntools SigreturnFrame) from the stack, including rax=59 (execve),
 * rdi -> "/bin/sh", rsi=0, rdx=0.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * `binsh` is a static "/bin/sh" string living at a fixed (PIE is off)
 * .rodata address -- the frame's rdi points here for the execve() call, so
 * no separate stack/libc leak is needed to find a usable path string.
 *
 * The overflow read is 400 bytes: a full x86-64 rt_sigreturn frame (as
 * pwntools' SigreturnFrame produces, including the FP/xsave area) is 248
 * bytes on its own, which combined with the offset-to-return-address
 * padding and the small ROP prefix that reaches the syscall gadget does
 * not fit in a plain 64/72-byte-scale read; a real SROP payload needs the
 * extra room.
 */
#include <stdio.h>
#include <unistd.h>

const char binsh[] = "/bin/sh";

__attribute__((naked, used))
void gadget_pop_rax_ret(void) {
    asm volatile ("pop %rax; ret");
}

__attribute__((naked, used))
void gadget_syscall_ret(void) {
    asm volatile ("syscall; ret");
}

void vuln(void) {
    char buf[64];

    printf("Input: ");
    fflush(stdout);
    read(0, buf, 400); /* buf is 64 bytes: no canary to stop the overflow;
                         * 400 bytes leaves enough room for a full SROP
                         * frame past the return address. */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== 09 srop (minimal gadgets) ===");
    vuln();
    puts("done");
    return 0;
}
