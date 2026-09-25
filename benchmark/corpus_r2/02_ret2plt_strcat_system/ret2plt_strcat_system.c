/*
 * Round-2 Target 02: ret2plt system("/bin/sh"), no leak needed.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * Deliberately different shape from round-1's 02_ret2plt_system:
 *  - "/bin/sh" is not a single pre-existing string literal; it is built at
 *    runtime by concatenating two smaller literals ("/bin" + "/sh") into a
 *    fixed-address global buffer via build_string(). The exploit needs a
 *    fixed data address (sh_buf), not a literal string search.
 *  - There is a harmless, correctly-bounded decoy read (greet()) before the
 *    real vulnerable one, so the tool must find the actual bug rather than
 *    the first read() it sees.
 *  - The vulnerable buffer/offsets and call depth (main -> build_string,
 *    greet, vuln) differ from round 1.
 *
 * system@plt is still linked in (called nowhere in this source on a normal
 * path, but referenced so the PLT stub is emitted) and reachable directly;
 * no libc base leak is required.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char sh_buf[16];

/* Explicit, always-present one-gadget: pop rdi; ret. This small binary's
 * own compiled code has no incidental "pop rdi; ret" sequence at -O0, so
 * (as with target 15) the gadget is embedded deliberately for a
 * deterministic build, rather than relying on toolchain-incidental
 * gadgets that could vary across gcc/binutils versions. */
__attribute__((naked, used)) void pop_rdi_gadget(void) {
    __asm__("pop %rdi\n\t"
             "ret\n\t");
}

/* Referenced so system@plt is emitted, exactly as a ret2plt target needs --
 * never actually called on any normal execution path. */
static void __attribute__((used)) unused_system_ref(void) {
    if (getenv("SUPWNGO_NEVER_SET_R2_02")) {
        system(sh_buf);
    }
}

static void build_string(void) {
    strcpy(sh_buf, "/bin");
    strcat(sh_buf, "/sh");
}

static void greet(void) {
    char name[32];
    printf("name: ");
    fflush(stdout);
    ssize_t n = read(0, name, 31); /* bounded: not the bug */
    if (n < 0) n = 0;
    name[n] = '\0';
    printf("hello %s\n", name);
    fflush(stdout);
}

static void vuln(void) {
    char cmd[64];

    printf("cmd> ");
    fflush(stdout);
    read(0, cmd, 200); /* cmd is 64 bytes: classic unbounded overflow */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-02 ret2plt-strcat-system (no leak needed) ===");
    build_string();
    greet();
    vuln();
    puts("done");
    return 0;
}
