/*
 * SROP-against-no-writable-segment variant corpus -- VARY THE FRAME SIZE.
 *
 * Category held constant (see srop_10_baseline for the full description): static
 * no-PIE image, two PT_LOAD (R and R E), no writable segment, count-returning
 * write wrapper, bare `syscall; ret`, symbol-table-tail pivot.
 *
 * The ONE thing that changes here: the overflowing function's stack buffer is
 * 0x40 instead of 0x20, so the overflow offset is 0x40 + 8 = 72, not 40. This
 * "moves the search": a solver that assumed a single fixed offset, or that
 * hard-coded the re-entered function's buffer at pivot-0x20, lands the second
 * stage's shellcode-return at the wrong address. The re-entered buffer is at
 * pivot-(offset-8) = pivot-0x40, which a generalizing solver must track from the
 * offset it is actually using rather than from a constant.
 *
 * Shape: buffer 0x40, overflow offset 0x40+8 = 72, standard write wrapper.
 *
 * FLAG{supwngo_bench_srop_20_wide_frame}
 */
__asm__(
".intel_syntax noprefix\n"
".global _start\n"
".text\n"

"my_read:\n"
"    mov  eax, 0\n"
"    mov  edi, 0\n"
"    mov  rsi, QWORD PTR [rsp+0x8]\n"
"    mov  rdx, QWORD PTR [rsp+0x10]\n"
"    syscall\n"
"    ret\n"

"my_write:\n"
"    mov  eax, 1\n"
"    mov  edi, 1\n"
"    mov  rsi, QWORD PTR [rsp+0x8]\n"
"    mov  rdx, QWORD PTR [rsp+0x10]\n"
"    syscall\n"
"    ret\n"

"vuln:\n"
"    push rbp\n"
"    mov  rbp, rsp\n"
"    sub  rsp, 0x40\n"          /* wider frame -> offset 0x40+8 = 72 */
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
