/*
 * SROP-against-no-writable-segment variant corpus -- NEGATIVE CONTROL.
 *
 * This target is deliberately OUT of category and MUST NOT be solved by
 * `srop_symtab_pivot`. Everything else about it is identical to the anchor
 * (srop_10_baseline): same syscall wrappers, same 0x20 buffer, same overflow,
 * same bare `syscall; ret`, same symbol table in the mapped tail.
 *
 * The ONE thing that changes: a `.data` section with a four-qword staging area,
 * which gives the image a WRITABLE PT_LOAD. That single fact dissolves the whole
 * premise of the technique. The technique exists only because there is nowhere to
 * stage a sigreturn frame and no known writable address; with a writable segment
 * present, an exploit should write its frame to `staging_area` (or use any of the
 * ordinary write-what-where techniques) instead of hunting qwords in the symbol
 * table's mapped tail. The symtab-pivot executor's gate therefore has to DECLINE
 * here -- not merely fail to find a chain, but recognise the target as belonging
 * to some other technique.
 *
 * That makes this control a test of the GATE, which is the part of an executor
 * most likely to rot into "always applicable" as the search around it is
 * loosened. If a generalisation ever makes this target report a shell via
 * `srop_symtab_pivot`, the loosening went too far and the measurement on the five
 * positives stops meaning anything.
 *
 * Note on the shell oracle: like every target in this corpus, `vuln` echoes what
 * it read (write(1, buf, rax)) and _start loops. An oracle that only checks
 * whether a token it sent appears on stdout will pass HERE, on an unexploited
 * process, because the target reflects its own input. Proof of a shell has to be
 * something /bin/echo cannot produce -- this corpus uses `echo SH$((6*7))OK`,
 * whose SH42OK only appears if a real shell evaluated the arithmetic.
 *
 * FLAG{supwngo_bench_srop_90_writable}
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

/* The out-of-category bit: a writable PT_LOAD with room to stage a frame. */
".section .data\n"
".global staging_area\n"
"staging_area:\n"
"    .quad 0\n"
"    .quad 0\n"
"    .quad 0\n"
"    .quad 0\n"
".att_syntax prefix\n"
);
