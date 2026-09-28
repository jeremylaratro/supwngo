/*
 * SROP-against-no-writable-segment variant corpus -- VARY THE FRAME (DEEP).
 *
 * Category held constant (see srop_10_baseline): static no-PIE image, two
 * PT_LOAD (R and R E), no writable segment, count-returning write wrapper, bare
 * `syscall; ret`, symbol-table-tail pivot.
 *
 * The ONE thing that changes here: a deep 0x80 stack buffer, so the overflow
 * offset is 0x80 + 8 = 136. This pushes past the offset band a solver tuned to
 * the anchor would sweep -- it moves the search meaningfully wider than
 * srop_20's 72. It also stresses the pivot's clearance: the re-entered
 * function's buffer now lands at pivot-0x80, so a pivot too close above the code
 * would have its second-stage read overwrite the executing bytes. `vuln`'s
 * symtab slot sits far enough above the code that its clearance is ample; a
 * generalizing solver simply must not attempt (pivot, offset) pairs whose
 * pivot-(offset-8) would fall back into the code.
 *
 * Shape: buffer 0x80, overflow offset 0x80+8 = 136, standard write wrapper.
 *
 * FLAG{supwngo_bench_srop_50_deep_frame}
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
"    sub  rsp, 0x80\n"          /* deep frame -> offset 0x80+8 = 136 */
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
