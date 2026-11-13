# Freestanding program with no `main`: `_start` is the only entry.
#
# Built with `gcc -nostdlib -static -o nomain nomain.S`. There is no libc start
# call, so a default-function search must fall back to the entry function
# itself (selected_by == "entry"), not to `helper`, which `_start` calls.
        .text
        .globl  helper
        .type   helper, @function
helper:
        mov     $39, %eax               # getpid
        syscall
        ret

        .globl  _start
        .type   _start, @function
_start:
        call    helper
        xor     %edi, %edi
        mov     $60, %eax               # exit
        syscall
        hlt
