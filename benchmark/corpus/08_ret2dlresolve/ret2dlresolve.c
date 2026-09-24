/*
 * Target 08: ret2dlresolve. No libc leak primitive exists in this binary
 * at all -- the only imported/PLT-resolved libc function is read(), and
 * every other user-visible message is emitted via a raw inline `syscall`
 * instruction rather than a libc call, so there is no puts()/write()-like
 * primitive an attacker could point at an arbitrary address to exfiltrate
 * memory. The intended solve path is to abuse the binary's own dynamic
 * linker machinery (PLT0 + a forged Elf64_Rela + a forged symbol name in
 * writable memory) to resolve and call system("/bin/sh") by name, without
 * ever knowing libc's base address.
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial (lazy binding is
 * required for dl-resolve -- must not be built with -z now), dynamic.
 *
 * `gadget_pop_rdi_ret` and the fixed `binsh` string are what let the
 * exploit actually set system()'s argument once dl-resolve has patched
 * the forged GOT slot with system()'s real address -- ret2dlresolve
 * finds the *function*, it does not by itself get an argument into rdi.
 *
 * `gadget_pop_rdi_rsi_rdx_ret` is needed for an earlier step: the forged
 * Elf64_Rela + fake symbol + symbol-name bytes that ret2dlresolve reads
 * from have to actually be *written* into memory at a known, writable
 * address (.bss) before the resolve trampoline runs -- read() is the
 * only libc call this binary ever imports, so the exploit ROP-calls
 * read() a second time (read(0, bss_addr, len)) to place them there,
 * which needs all three of rdi/rsi/rdx under ROP control.
 */
#include <unistd.h>

const char binsh[] = "/bin/sh";

__attribute__((naked, used))
void gadget_pop_rdi_ret(void) {
    asm volatile ("pop %rdi; ret");
}

__attribute__((naked, used))
void gadget_pop_rdi_rsi_rdx_ret(void) {
    asm volatile ("pop %rdi; pop %rsi; pop %rdx; ret");
}

static void raw_write(const char *s, unsigned long n) {
    long ret;
    asm volatile (
        "mov $1, %%rax\n\t" /* SYS_write */
        "mov $1, %%rdi\n\t" /* fd = 1 (stdout) */
        "syscall\n\t"
        : "=a"(ret)
        : "S"(s), "d"(n)
        : "rcx", "r11", "memory"
    );
    (void)ret;
}

void vuln(void) {
    char buf[64];
    raw_write("input> ", 7);
    read(0, buf, 300); /* buf is 64 bytes: no canary to stop the overflow */
}

int main(void) {
    raw_write("=== 08 ret2dlresolve (no leak primitive) ===\n", 46);
    vuln();
    raw_write("done\n", 5);
    return 0;
}
