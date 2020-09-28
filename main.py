import sys
import os

from binary import Binary
from consts import *

STUB = b'\xcc'
STUB_SIZE = 1


def inject_stub(binary_obj, stub, stub_size):
    for phdr in binary_obj.phdrs:
        if phdr.p_type == PT_LOAD and phdr.p_flags == READ_PERM | EXEC_PERM:
            binary_obj.ehdr.e_entry = phdr.p_vaddr + phdr.p_memsz
            text_segment_end_off = phdr.p_offset + phdr.p_filesz
            phdr.p_filesz += stub_size
            phdr.p_memsz += stub_size

    for shdr, section in zip(binary_obj.shdrs, binary_obj.sections):
        if shdr.sh_offset + shdr.sh_size == text_segment_end_off:
            section.section_chunk += stub


def load_stub(text_segment_start, text_segment_len, text_section_start, text_section_size, original_entry):
    with open(STUB_ASM_FILE, 'wb') as stub_asm_file:
        stub_asm_file.write(STUB_FORMAT.format(text_segment_start=text_segment_start,
                                               text_segment_len=text_segment_len,
                                               text_section_start=text_section_start,
                                               text_section_size=text_section_size,
                                               original_entry=original_entry))
        os.system('nasm {}'.format(STUB_ASM_FILE))

    with open(STUB_FILE, 'rb') as stub_file:
        stub = stub_file.read()

    os.remove(STUB_ASM_FILE)
    os.remove(STUB_FILE)
    return stub


def is_injectable(binary_obj, stub_size):
    for phdr in binary_obj.phdrs:
        if phdr.p_type == PT_LOAD and phdr.p_flags == READ_PERM | EXEC_PERM:
            text_segment_end_off = phdr.p_offset + phdr.p_filesz
        if phdr.p_type == PT_LOAD and phdr.p_flags == READ_PERM | WRITE_PERM:
            data_segment_start_off = phdr.p_offset

    return stub_size > data_segment_start_off - text_segment_end_off


def encrypt_text_section(binary_obj):
    for shdr, section in zip(binary_obj.shdrs, binary_obj.sections):
        if section.section_name == b'.text':
            section.section_chunk = bytearray([b ^ KEY_VALUE for b in section.section_chunk])


def main():
    if len(sys.argv) != 2:
        print('Usage: main.py <binary>')
        return 1

    binary = sys.argv[1]
    binary_file = open(binary, 'rb')
    binary_obj = Binary(binary_file)

    for phdr in binary_obj.phdrs:
        if phdr.p_type == PT_LOAD and phdr.p_flags == READ_PERM | EXEC_PERM:
            text_segment_start = phdr.p_vaddr
            text_segment_len = phdr.p_memsz

    for shdr, section in zip(binary_obj.shdrs, binary_obj.sections):
        if section.section_name == b'.text':
            text_section_start = shdr.sh_addr
            text_section_size = shdr.sh_size

    original_entry = binary_obj.ehdr.e_entry

    stub = load_stub(text_segment_start, text_segment_len, text_section_start, text_section_size, original_entry)

    if is_injectable(binary_obj, len(stub)):
        print('[+] Cannot inject stub')
        return -1

    inject_stub(binary_obj, stub, stub_size)
    encrypt_text_section(binary_obj)

    binary_obj.construct_binary('clone')
    binary_file.close()


if __name__ == '__main__':
    main()
