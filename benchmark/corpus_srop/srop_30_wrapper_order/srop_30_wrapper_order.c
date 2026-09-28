/*
 * SROP-against-no-writable-segment variant corpus -- VARY THE COUNT WRAPPER.
 *
 * Category held constant (see srop_10_baseline): static no-PIE image, two
 * PT_LOAD (R and R E), no writable segment, bare `syscall; ret`, symbol-table-
 * tail pivot. The count-returning wrapper is STILL a write -- and it must be.
 *
 * A note on the obvious alternative "read-returns-count": it is NOT a member of
 * this category. read(fd, buf, n) returns a count too, but to return 15 it must
 * successfully write 15 bytes to `buf`, and the wrapper takes buf from a frame
 * qword we control only as a VALUE. Before the frame's own mprotect() runs there
 * is no writable address we know (no writable segment, no stack leak), so read
 * would fault (EFAULT) instead of returning 15. The count therefore has to come
 * from a write, whose source only needs to be readable (the image always is).
 *
 * The ONE thing that changes here: the wrapper loads its stack arguments in the
 * opposite order -- rdx (from [rsp+0x10]) before rsi (from [rsp+0x8]). The
 * write it performs is byte-for-byte identical (write(1, rsi, rdx)); only the
 * instruction order differs. A solver that recognises the wrapper with a rigid
 * "eax=1, then rsi, then rdx, then syscall" template fails to find any count
 * wrapper and declines the whole target. Recognition has to be tolerant of the
 * two argument-load orders.
 *
 * Shape: buffer 0x20, overflow offset 40, REORDERED write wrapper (rdx, rsi).
 *
 * FLAG{supwngo_bench_srop_30_wrapper_order}
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

/* Same write, arguments loaded rdx-then-rsi. Still write(1, [rsp+8], [rsp+0x10]). */
"my_write:\n"
"    mov  eax, 1\n"
"    mov  edi, 1\n"
"    mov  rdx, QWORD PTR [rsp+0x10]\n"
"    mov  rsi, QWORD PTR [rsp+0x8]\n"
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
".att_syntax prefix\n"
);
