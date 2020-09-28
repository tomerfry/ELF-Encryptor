import struct

from consts import *


class ElfHeader(object):
    def __init__(self, buffer):
        self.e_ident, self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff, self.e_shoff, \
            self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, \
            self.e_shstrndx = struct.unpack(ELF_HEADER_FORMAT, buffer)

    def get_packed(self):
        return struct.pack(ELF_HEADER_FORMAT, self.e_ident, self.e_type, self.e_machine, self.e_version, self.e_entry,
                           self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
                           self.e_shentsize, self.e_shnum, self.e_shstrndx)


class Phdr(object):
    def __init__(self, buffer):
        self.p_type, self.p_flags, self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz, self.p_memsz, \
            self.p_align = struct.unpack(PHDR_FORMAT, buffer)

    def get_packed(self):
        return struct.pack(PHDR_FORMAT, self.p_type, self.p_flags, self.p_offset, self.p_vaddr, self.p_paddr,
                           self.p_filesz, self.p_memsz, self.p_align)


class Shdr(object):
    def __init__(self, buffer):
        self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset, self.sh_size, self.sh_link, \
            self.sh_info, self.sh_addralign, self.sh_entsize = struct.unpack(SHDR_FORMAT, buffer)

    def get_packed(self):
        return struct.pack(SHDR_FORMAT, self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset,
                           self.sh_size, self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize)


class Section(object):
    def __init__(self, buffer, section_name):
        self.section_chunk = buffer
        self.section_name = section_name

    def get_packed(self):
        return self.section_chunk


class Binary(object):
    def __init__(self, binary_file):
        self.ehdr = ElfHeader(binary_file.read(ELF_HEADER_LEN))

        self.phdrs = []
        for phdr_num in range(self.ehdr.e_phnum):
            phdr_chunk = binary_file.read(self.ehdr.e_phentsize)
            self.phdrs.append(Phdr(phdr_chunk))

        binary_file.seek(self.ehdr.e_shoff)
        self.shdrs = []
        for shdr_num in range(self.ehdr.e_shnum):
            shdr_chunk = binary_file.read(self.ehdr.e_shentsize)
            self.shdrs.append(Shdr(shdr_chunk))

        self.sections = []
        for shdr in self.shdrs:
            section_name = self.get_section_name(shdr, binary_file)
            binary_file.seek(shdr.sh_offset)
            self.sections.append(Section(binary_file.read(shdr.sh_size), section_name))

    def get_section_name(self, shdr, binary_file):
        # Section-Header of strings section.
        shstr = self.shdrs[self.ehdr.e_shstrndx]

        section_name = b''
        binary_file.seek(shstr.sh_offset + shdr.sh_name)
        c = binary_file.read(1)
        while c != b'\x00':
            section_name += c
            c = binary_file.read(1)

        return section_name

    def write_headers(self, f):
        f.write(self.ehdr.get_packed())

        f.seek(self.ehdr.e_phoff)
        for phdr in self.phdrs:
            f.write(phdr.get_packed())

        f.seek(self.ehdr.e_shoff)
        for shdr in self.shdrs:
            f.write(shdr.get_packed())

    def construct_binary(self, new_name):
        new_binary = open(new_name, 'wb')
        self.write_headers(new_binary)

        for shdr, section in zip(self.shdrs, self.sections):
            if shdr.sh_type != SHT_NULL:
                new_binary.seek(shdr.sh_offset)
                new_binary.write(section.get_packed())




