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



