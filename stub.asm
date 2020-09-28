[bits 64]

push rax
push rdi
push rsi
push rdx

mov rax, 0xa
mov rdi, 0x400450 ;start
mov rsi, 0x182 ;len
mov rdx, 7 ;prot
syscall

mov rdi, 0x400450
mov rsi, rdi
mov rcx, 0x182

cld
my_loop:
    lodsb
    xor al, 0xaa
    stosb
loop my_loop


pop rdx
pop rsi
pop rdi
pop rax

push 0x400450
ret
