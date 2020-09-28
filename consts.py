import struct

ELF_HEADER_FORMAT = '16sHHIQQQIHHHHHH'
ELF_HEADER_LEN = struct.calcsize(ELF_HEADER_FORMAT)
PHDR_FORMAT = 'IIQQQQQQ'
SHDR_FORMAT = 'IIQQQQIIQQ'
PAGE_SIZE = 0x20000

READ_PERM = 0b100
WRITE_PERM = 0b010
EXEC_PERM = 0b001

PT_NULL = 0x00000000
PT_LOAD = 0x00000001
PT_DYNAMIC = 0x00000002
PT_INTERP = 0x00000003
PT_NOTE = 0x00000004
PT_SHLIB = 0x00000005
PT_PHDR = 0x00000006
PT_TLS = 0x00000007
PT_LOOS = 0x60000000
PT_HIOS = 0x6FFFFFFF
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7FFFFFFF

SHT_NULL = 0x0
SHT_PROGBITS = 0x1
SHT_SYMTAB = 0x2
SHT_STRTAB = 0x3
SHT_RELA = 0x4
SHT_HASH = 0x5
SHT_DYNAMIC = 0x6
SHT_NOTE = 0x7
SHT_NOBITS = 0x8
SHT_REL = 0x9
SHT_SHLIB = 0x0A
SHT_DYNSYM = 0x0B
SHT_INIT_ARRAY = 0x0E
SHT_FINI_ARRAY = 0x0F
SHT_PREINIT_ARRAY = 0x10
SHT_GROUP = 0x11
SHT_SYMTAB_SHNDX = 0x12
SHT_NUM = 0x13
SHT_LOOS = 0x60000000

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_MERGE = 0x10
SHF_STRINGS = 0x20
SHF_INFO_LINK = 0x40
SHF_LINK_ORDER = 0x80
SHF_OS_NONCONFORMING = 0x100
SHF_GROUP = 0x200
SHF_TLS = 0x400
SHF_MASKOS = 0x0ff00000
SHF_MASKPROC = 0xf0000000
SHF_ORDERED = 0x4000000
SHF_EXCLUDE = 0x8000000

KEY_VALUE = 0xaa
STUB_FORMAT = """
[bits 64]

push rax
push rdi
push rsi
push rdx

mov rax, 0xa
mov rdi, {text_segment_start} ;start
mov rsi, {text_segment_len} ;len
mov rdx, 7 ;prot
syscall

mov rdi, {text_section_start}
mov rsi, rdi
mov rcx, {text_section_size}

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

push {original_entry}
ret
"""
STUB_ASM_FILE = 'stub.asm'
STUB_FILE = 'stub'
