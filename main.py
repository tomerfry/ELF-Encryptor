import sys
import os

from elf.elf import ELF
from elf.consts import *

def main():
    if len(sys.argv) != 2:
        print('Usage: main.py <binary>')
        return 1

    binary = sys.argv[1]
    binary_obj = ELF(binary)

    # Find data segment
    for phdr in binary_obj.phdrs:
        if phdr['p_type'] == PT_LOAD and phdr['p_flags'] == READ_PERM | WRITE_PERM:
            ds_end_addr = phdr['p_vaddr'] + phdr['p_memsz']
            ds_end_off = phdr['p_offset'] + phdr['p_filesz']
            align_size = phdr['p_align']

    for index, phdr in enumerate(binary_obj.phdrs):
        if phdr['p_type'] == PT_NOTE:
            phdr['p_type'] = PT_LOAD
            phdr['p_align'] = 0x200000
            phdr['p_vaddr'] = 0xc000000
            phdr['p_paddr'] = 0xc000000
            phdr['p_flags'] = READ_PERM | EXEC_PERM
            phdr['p_offset'] = os.path.getsize(binary)
            payload = b'\xcc'
            phdr['p_filesz'] += len(payload)
            phdr['p_memsz'] += len(payload)
            binary_obj.segments[index] = payload

    binary_obj.construct_binary('clone')


if __name__ == '__main__':
    main()
