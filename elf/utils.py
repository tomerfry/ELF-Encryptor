import struct

from elf.consts import *


def parse_elf_header(elf_header_chunk):
    e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, \
    e_shentsize, e_shnum, e_shstrndx = struct.unpack(ELF_FILE_HEADER_FORMAT, elf_header_chunk)
    return {
        'e_ident': e_ident,
        'e_type': e_type,
        'e_machine': e_machine,
        'e_version': e_version,
        'e_entry': e_entry,
        'e_phoff': e_phoff,
        'e_shoff': e_shoff,
        'e_flags': e_flags,
        'e_ehsize': e_ehsize,
        'e_phentsize': e_phentsize,
        'e_phnum': e_phnum,
        'e_shentsize': e_shentsize,
        'e_shnum': e_shnum,
        'e_shstrndx': e_shstrndx
    }


def parse_phdrs_table(elf_phdrs_chunk, phdr_chunk_len):
    phdrs = []

    for off in range(0, len(elf_phdrs_chunk), phdr_chunk_len):
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, \
            p_align = struct.unpack(PHDR_STRUCT_FORMAT, elf_phdrs_chunk[off:off + phdr_chunk_len])
        phdrs.append({
            'p_type': p_type,
            'p_flags': p_flags,
            'p_offset': p_offset,
            'p_vaddr': p_vaddr,
            'p_paddr': p_paddr,
            'p_filesz': p_filesz,
            'p_memsz': p_memsz,
            'p_align': p_align
        })

    return phdrs


def parse_shdrs_table(elf_shdrs_chunk, shdr_chunk_len):
    shdrs = []

    for off in range(0, len(elf_shdrs_chunk), shdr_chunk_len):
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, \
            sh_entsize = struct.unpack(SHDR_STRUCT_FORMAT, elf_shdrs_chunk[off:off + shdr_chunk_len])
        shdrs.append({
            'sh_name': sh_name,
            'sh_type': sh_type,
            'sh_flags': sh_flags,
            'sh_addr': sh_addr,
            'sh_offset': sh_offset,
            'sh_size': sh_size,
            'sh_link': sh_link,
            'sh_info': sh_info,
            'sh_addralign': sh_addralign,
            'sh_entsize': sh_entsize
        })
    return shdrs


def pack_elf_header(elf_header):
    return struct.pack(
        ELF_FILE_HEADER_FORMAT,
        elf_header['e_ident'],
        elf_header['e_type'],
        elf_header['e_machine'],
        elf_header['e_version'],
        elf_header['e_entry'],
        elf_header['e_phoff'],
        elf_header['e_shoff'],
        elf_header['e_flags'],
        elf_header['e_ehsize'],
        elf_header['e_phentsize'],
        elf_header['e_phnum'],
        elf_header['e_shentsize'],
        elf_header['e_shnum'],
        elf_header['e_shstrndx']
    )


def pack_phdrs(elf_phdrs):
    phdrs_chunk = b''
    for phdr in elf_phdrs:
        phdrs_chunk += struct.pack(
            PHDR_STRUCT_FORMAT,
            phdr['p_type'],
            phdr['p_flags'],
            phdr['p_offset'],
            phdr['p_vaddr'],
            phdr['p_paddr'],
            phdr['p_filesz'],
            phdr['p_memsz'],
            phdr['p_align']
        )
    return phdrs_chunk


def pack_shdrs(elf_shdrs):
    shdrs_chunk = b''
    for shdr in elf_shdrs:
        shdrs_chunk += struct.pack(
            SHDR_STRUCT_FORMAT,
            shdr['sh_name'],
            shdr['sh_type'],
            shdr['sh_flags'],
            shdr['sh_addr'],
            shdr['sh_offset'],
            shdr['sh_size'],
            shdr['sh_link'],
            shdr['sh_info'],
            shdr['sh_addralign'],
            shdr['sh_entsize'],
        )
    return shdrs_chunk