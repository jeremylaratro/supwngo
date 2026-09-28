/*
 * SROP-against-no-writable-segment variant corpus -- ANCHOR.
 *
 * The category (constant across the family): a static, no-PIE image with only
 * two PT_LOAD segments -- R and R E -- and NO writable segment, no imports, no
 * leak. The hard part of sigreturn-oriented programming here is not building the
 * frame, it is supplying a controlled [rsp] to the `syscall; ret` that runs
 * after the sigreturn: with nothing writable and no leak there is no staging
 * area and no stack address. Two facts make it solvable anyway, and both are
 * reproduced faithfully below:
 *
 *   1. rax = 15 (rt_sigreturn) comes for free from a COUNT-RETURNING syscall
 *      wrapper: write(1, x, 15) returns 15, and the wrapper's own `ret` is the
 *      jump onto the bare `syscall`. The frame's first two qwords (uc_flags and
 *      &uc) are ignored by the kernel, so they double as the wrapper's
 *      stack-passed rsi/rdx.
 *
 *   2. A PT_LOAD is mapped a page at a time, so every file byte in the last page
 *      is mapped even past p_filesz. In an image this small that tail is the
 *      SYMBOL TABLE, whose st_value fields are qwords holding the binary's own
 *      function addresses, at fixed known vaddrs. Pointing the frame's rsp at
 *      one means the post-sigreturn `ret` reads a function address out of the
 *      symtab and re-enters it -- with rsp now inside the page the frame just
 *      mprotect()'d RWX.
 *
 * This target is the fixed point of the family: it reproduces sick_rop's shape
 * as closely as a standalone file can -- read/write syscall wrappers that take
 * rsi/rdx from [rsp+8]/[rsp+0x10], a `vuln` that read()s far past a fixed stack
 * buffer, and _start looping on vuln. It exists so that a variant failure can be
 * told apart from a corpus-wide mistake. It already solves; it is not a
 * capability claim.
 *
 * Shape: buffer 0x20, overflow offset 0x20+8 = 40, standard write wrapper.
 *
 * FLAG{supwngo_bench_srop_10_baseline}
 */
__asm__(
".intel_syntax noprefix\n"
".global _start\n"
".text\n"

/* read(0, [rsp+8], [rsp+0x10]); returns byte count in rax, `ret` is a bare
 * `syscall; ret` gadget too. */
"my_read:\n"
"    mov  eax, 0\n"
"    mov  edi, 0\n"
"    mov  rsi, QWORD PTR [rsp+0x8]\n"
"    mov  rdx, QWORD PTR [rsp+0x10]\n"
"    syscall\n"
"    ret\n"

/* write(1, [rsp+8], [rsp+0x10]); the COUNT-RETURNING wrapper: write(1, x, 15)
 * leaves rax = 15, and this `ret` jumps to the bare syscall. */
"my_write:\n"
"    mov  eax, 1\n"
"    mov  edi, 1\n"
"    mov  rsi, QWORD PTR [rsp+0x8]\n"
"    mov  rdx, QWORD PTR [rsp+0x10]\n"
"    syscall\n"
"    ret\n"

/* The overflow. read()s 0x300 bytes into a 0x20 stack buffer, then echoes what
 * it read (write(1, buf, rax)) before returning -- the echo is how a driver
 * knows a stage completed. */
"vuln:\n"
"    push rbp\n"
"    mov  rbp, rsp\n"
"    sub  rsp, 0x20\n"
"    mov  r10, rsp\n"
"    push 0x300\n"
"    push r10\n"
"    call my_read\n"
"    push rax\n"
"    push r10\n"
"    call my_write\n"
"    leave\n"
"    ret\n"

"_start:\n"
"    call vuln\n"
"    jmp  _start\n"
".att_syntax prefix\n"
);
