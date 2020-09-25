import sys
import os

from elf.elf import ELF
from elf.consts import *
from elf.utils import *


def main():
    if len(sys.argv) != 2:
        print('Usage: main.py <binary>')
        return 1

    binary = sys.argv[1]
    binary_obj = ELF(binary)
    new_file = open('clone', 'wb')

    for phdr in binary_obj.phdrs:
        if phdr['p_type'] == PT_LOAD and phdr['p_flags'] == READ_PERM | WRITE_PERM:
            end_data_segment = phdr['p_vaddr'] + phdr['p_memsz']

    for index, phdr in enumerate(binary_obj.phdrs):

        if phdr['p_type'] == PT_NOTE:
            phdr['p_type'] = PT_LOAD
            phdr['p_align'] = 0x200000
            phdr['p_offset'] = os.path.getsize(binary)
            phdr['p_vaddr'] = end_data_segment
            phdr['p_paddr'] = end_data_segment
            phdr['p_filesz'] = 1
            phdr['p_memsz'] = 1

    new_file.write(pack_elf_header(binary_obj.elf_header))
    new_file.write(pack_phdrs(binary_obj.phdrs))
    new_file.write(binary_obj.filler)
    new_file.write(pack_shdrs(binary_obj.shdrs))
    new_file.write(b'\xcc')

    new_file.close()


if __name__ == '__main__':
    main()
