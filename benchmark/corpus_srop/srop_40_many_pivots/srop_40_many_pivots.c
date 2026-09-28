/*
 * SROP-against-no-writable-segment variant corpus -- VARY THE SYMBOL TABLE.
 *
 * Category held constant (see srop_10_baseline): static no-PIE image, two
 * PT_LOAD (R and R E), no writable segment, count-returning write wrapper, bare
 * `syscall; ret`, symbol-table-tail pivot.
 *
 * The ONE thing that changes here: the symbol table is padded with many small
 * functions defined BEFORE `vuln`. Every one of them has an executable st_value,
 * so every one is a candidate pivot -- and because they precede `vuln` in the
 * table, the qword that actually re-enters the overflowing function sits well
 * past the first dozen candidates. A solver that only tries a fixed prefix of
 * the pivot list (say the first twelve) never reaches the working pivot and
 * fails, even though the target is squarely in-category. Generalising means
 * searching the pivots the image really exposes, not an arbitrary truncation.
 *
 * The dummies are bare `ret`s: re-entering one just pops whatever qword the
 * mapped tail holds next and wanders off -- a fast miss, never a false success.
 * Only `vuln`'s st_value re-enters a function that read()s into a stack buffer
 * and then returns through it.
 *
 * Shape: buffer 0x20, offset 40, standard write wrapper, 14 decoy pivots ahead
 * of the working one.
 *
 * FLAG{supwngo_bench_srop_40_many_pivots}
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

/* 14 decoy functions: each contributes an executable st_value ahead of vuln. */
"dummy00:\n    ret\n"
"dummy01:\n    ret\n"
"dummy02:\n    ret\n"
"dummy03:\n    ret\n"
"dummy04:\n    ret\n"
"dummy05:\n    ret\n"
"dummy06:\n    ret\n"
"dummy07:\n    ret\n"
"dummy08:\n    ret\n"
"dummy09:\n    ret\n"
"dummy10:\n    ret\n"
"dummy11:\n    ret\n"
"dummy12:\n    ret\n"
"dummy13:\n    ret\n"

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
