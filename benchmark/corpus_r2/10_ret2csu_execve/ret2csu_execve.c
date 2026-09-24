/*
 * Round-2 Target 10: advanced ROP variant -- the classic ret2csu gadget
 * pair, used to control the rdi/rsi/rdx argument registers and make an
 * indirect call through a fixed-address function-pointer slot, entirely
 * without a leak and without needing simple standalone `pop rdi; ret` /
 * `pop rsi; ret` / `pop rdx; ret` gadgets. This technique does not appear
 * anywhere in round 1's corpus at all (round 1's hard tier used
 * ret2dlresolve and SROP).
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial, dynamic.
 *
 * IMPORTANT BUILD-TIME NOTE: glibc >= 2.34 (this box ships 2.35) removed
 * __libc_csu_init/__libc_csu_fini entirely (libpthread was folded into
 * libc and __libc_start_main now drives .init_array directly), so the
 * gadget pair classic ret2csu tutorials point at no longer exists in any
 * binary built on this toolchain -- verified empirically: neither
 * `nm`/`objdump` nor ROPgadget find a __libc_csu_init symbol or a
 * matching 6-register pop sequence anywhere in a plain gcc -no-pie
 * binary here. csu_gadget() below reproduces the exact classic
 * __libc_csu_init epilogue instruction-for-instruction via inline asm so
 * the *technique* (register control + indirect call through csu's own
 * shuffle, not independent single-purpose pop gadgets) remains
 * genuinely exercisable on this glibc version -- this is standard
 * practice for ret2csu challenges built on glibc 2.34+.
 *
 * `win_ptr` is a global function pointer initialized to `&win` -- a
 * fixed-address, no-PIE, no-leak-needed memory location holding win()'s
 * real address as literal data. csu_gadget's second half:
 *   mov rdx, r13 ; mov rsi, r12 ; mov edi, r14d ; call [r15 + rbx*8]
 * lets an attacker load r15 = &win_ptr, rbx = 0, r14 = WIN_MAGIC (the
 * 32-bit `mov edi, r14d` zero-extends into rdi) via the gadget pair's
 * first half (a single `pop rbx,rbp,r12,r13,r14,r15; ret`), then falls
 * into the second half, which calls *win_ptr(WIN_MAGIC) -- i.e. win() --
 * with the argument register set entirely through csu's own register
 * shuffle.
 */
#include <stdio.h>
#include <unistd.h>

#define WIN_MAGIC 0xCAFEBABEUL

/* The flag is intentionally NOT compiled into this binary (no literal in
 * .rodata that `strings`/ELF.search() could find with zero exploitation).
 * It is generated fresh per build by build_all_r2.sh and written to
 * flag.txt alongside the binary; win() reads it at runtime only after the
 * real bug has actually been exploited (and only when the magic gate
 * passes). */
static void print_flag(void) {
    FILE *f = fopen("flag.txt", "r");
    if (!f) {
        puts("flag.txt missing");
        return;
    }
    char flag[256];
    if (fgets(flag, sizeof(flag), f)) {
        fputs(flag, stdout); /* flag.txt already ends in '\n' */
    }
    fclose(f);
}

void win(unsigned long magic) {
    if (magic == WIN_MAGIC) {
        print_flag();
    } else {
        puts("wrong magic");
    }
}

/* Fixed-address data slot holding win()'s real address -- the target for
 * ret2csu's indirect call, no leak required. */
void (*win_ptr)(unsigned long) = win;

/* Classic __libc_csu_init epilogue, reproduced instruction-for-instruction
 * (glibc >= 2.34 no longer emits it -- see note above). Two entry points:
 * csu_gadget (the 6-register pop) and csu_gadget_call (the register
 * shuffle + indirect call), exactly like the original two ret2csu
 * gadget addresses. */
__attribute__((naked, used)) void csu_gadget(void) {
    __asm__(
        "pop %rbx\n\t"
        "pop %rbp\n\t"
        "pop %r12\n\t"
        "pop %r13\n\t"
        "pop %r14\n\t"
        "pop %r15\n\t"
        "ret\n\t"
        ".globl csu_gadget_call\n\t"
        "csu_gadget_call:\n\t"
        "mov %r13, %rdx\n\t"
        "mov %r12, %rsi\n\t"
        "mov %r14d, %edi\n\t"
        "call *(%r15,%rbx,8)\n\t"
        "add $8, %rsp\n\t"
        "pop %rbx\n\t"
        "pop %rbp\n\t"
        "pop %r12\n\t"
        "pop %r13\n\t"
        "pop %r14\n\t"
        "pop %r15\n\t"
        "ret\n\t"
    );
}

void vuln(void) {
    char buf[72];

    printf("input> ");
    fflush(stdout);
    read(0, buf, 400); /* buf is 72 bytes; ample room for a ret2csu chain */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-10 ret2csu-execve (advanced ROP, no simple 3-arg gadgets assumed) ===");
    vuln();
    puts("done");
    return 0;
}
