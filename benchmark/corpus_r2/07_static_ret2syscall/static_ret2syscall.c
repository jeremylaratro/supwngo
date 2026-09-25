/*
 * Round-2 Target 07: ret2libc's "no leak needed" sibling -- a statically
 * linked binary has NO ASLR on its code/libc at all (there is no separate
 * libc.so to be randomized), so no info leak is required; the exploit
 * just needs to build a ROP chain directly from gadgets and data already
 * present at fixed addresses in the binary and drive a raw execve()
 * syscall.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, STATIC linking.
 *
 * Deliberately different technique shape from round-1's leak-free target
 * (02_ret2plt_system, which calls system@plt): there is no system()/PLT
 * call here at all -- the chain must set rax=59 (execve), rdi -> the
 * fixed-address `shell_path` string, rsi=0, rdx=0, then hit a bare
 * `syscall` gadget, entirely via ROP over the large static-binary gadget
 * set (pop-register + syscall gadgets are abundant in a full statically
 * linked glibc image). This is the corpus's "ret2libc without a leak
 * requirement" entry, structurally distinct from the ret2plt/system entry
 * (target 02).
 */
#include <stdio.h>
#include <unistd.h>

static char shell_path[8] = "/bin/sh";

void vuln(void) {
    char buf[80];

    printf("input> ");
    fflush(stdout);
    read(0, buf, 400); /* buf is 80 bytes; ample room for a syscall ROP chain */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-07 static-ret2syscall (no ASLR: static linking) ===");
    vuln();
    puts("done");
    return 0;
}
