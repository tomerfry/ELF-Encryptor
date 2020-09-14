import sys
import os
import struct
import subprocess

from consts import *


def main():
    if len(sys.argv) != 2:
        print('Usage: main.py <binary>')
        return 1

    binary = sys.argv[1]
    binary_file = open(binary, 'rb')
    packed_file = open(binary + '.packed', 'wb')

    elf_header = binary_file.read(struct.calcsize(ELF_FILE_HEADER_FORMAT))
    e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, \
    e_shentsize, e_shnum, e_shstrndx = struct.unpack(ELF_FILE_HEADER_FORMAT, elf_header)

    packed_file.write(struct.pack(ELF_FILE_HEADER_FORMAT, e_ident, e_type, e_machine, e_version, e_entry, e_phoff,
                                  0, e_flags, e_ehsize, e_phentsize, 3, e_shentsize, 0, 0))

    phdrs = []

    # Parse the program-headers and add them to the packed binary.
    for i in range(e_phnum):
        phdr_chunk = binary_file.read(e_phentsize)
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(PHDR_STRUCT_FORMAT,
                                                                                                phdr_chunk)
        if p_type == PT_PHDR or (p_type == PT_LOAD and p_flags == READ_PERM | EXEC_PERM):
            phdrs.append(struct.pack(PHDR_STRUCT_FORMAT, p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz,
                                          p_memsz, p_align))
            packed_file.write(phdrs[-1])
        elif p_type == PT_LOAD and p_flags == READ_PERM | WRITE_PERM:
            phdrs.append(struct.pack(PHDR_STRUCT_FORMAT, p_type, p_flags, p_offset, p_vaddr, p_paddr,
                                          os.path.getsize(binary), os.path.getsize(binary), p_align))
            packed_file.write(phdrs[-1])

    # Write the program segment to the packed file.
    for packed_phdr in phdrs:
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(PHDR_STRUCT_FORMAT,
                                                                                                packed_phdr)
        if p_type == PT_LOAD and p_flags == READ_PERM | EXEC_PERM:
            new_entry = p_vaddr
            binary_file.seek(p_offset)
            packed_file.write(b'\xcc' * p_filesz)

            with open('stub.nasm', 'w') as f:
                f.write(STUB_PROGRAM.format(entry=hex(p_vaddr)))

            os.system('nasm ./stub.nasm')
            with open('stub', 'rb') as f:
                packed_file.write(f.read().ljust(p_filesz, b'\xcc'))

        elif p_type == PT_LOAD and p_flags == READ_PERM | WRITE_PERM:
            packed_file.seek(p_offset)
            binary_file.seek(0)
            packed_file.write(binary_file.read())


    packed_file.seek(0)
    packed_file.write(struct.pack(ELF_FILE_HEADER_FORMAT, e_ident, e_type, e_machine, e_version, new_entry, e_phoff,
                                  e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx))

    packed_file.close()
    binary_file.close()


if __name__ == '__main__':
    main()
