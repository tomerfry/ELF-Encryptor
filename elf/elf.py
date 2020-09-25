from elf.utils import *


class ELF(object):

    def __init__(self, binary):
        binary_file = open(binary, 'rb')
        elf_header_chunk = binary_file.read(struct.calcsize(ELF_FILE_HEADER_FORMAT))
        self.elf_header = parse_elf_header(elf_header_chunk)

        elf_phdrs_chunk = binary_file.read(self.elf_header['e_phentsize'] * self.elf_header['e_phnum'])
        self.phdrs = parse_phdrs_table(elf_phdrs_chunk, self.elf_header['e_phentsize'])

        filler_size = self.elf_header['e_shoff'] - self.elf_header['e_phoff'] - \
                      (self.elf_header['e_phnum'] * self.elf_header['e_phentsize'])

        self.filler = binary_file.read(filler_size)

        elf_shdrs_chunk = binary_file.read(self.elf_header['e_shentsize'] * self.elf_header['e_shnum'])
        self.shdrs = parse_shdrs_table(elf_shdrs_chunk, self.elf_header['e_shentsize'])

        binary_file.close()


