from elf.utils import *


class ELF(object):

    def __init__(self, binary):
        binary_file = open(binary, 'rb')
        elf_header_chunk = binary_file.read(struct.calcsize(ELF_FILE_HEADER_FORMAT))
        self.elf_header = parse_elf_header(elf_header_chunk)

        elf_phdrs_chunk = binary_file.read(self.elf_header['e_phentsize'] * self.elf_header['e_phnum'])
        self.phdrs = parse_phdrs_table(elf_phdrs_chunk, self.elf_header['e_phentsize'])

        binary_file.seek(self.elf_header['e_shoff'])
        elf_shdrs_chunk = binary_file.read(self.elf_header['e_shentsize'] * self.elf_header['e_shnum'])
        self.shdrs = parse_shdrs_table(elf_shdrs_chunk, self.elf_header['e_shentsize'])

        self.segments = []
        for phdr in self.phdrs:
            binary_file.seek(phdr['p_offset'])
            self.segments.append(binary_file.read(phdr['p_filesz']))

        self.sections = []
        for shdr in self.shdrs:
            binary_file.seek(shdr['sh_offset'])
            self.sections.append(binary_file.read(shdr['sh_size']))

        binary_file.close()

    def construct_binary(self, name):
        elf_header_chunk = pack_elf_header(self.elf_header)
        elf_phdrs = pack_phdrs(self.phdrs)
        elf_shdrs = pack_shdrs(self.shdrs)

        with open(name, 'wb') as f:
            f.write(elf_header_chunk)
            f.write(elf_phdrs)
            f.seek(self.elf_header['e_shoff'])
            f.write(elf_shdrs)
            for phdr, segment in zip(self.phdrs, self.segments):
                if phdr['p_offset'] > self.elf_header['e_phoff']:
                    f.seek(phdr['p_offset'])
                    f.write(segment)
            for shdr, section in zip(self.shdrs, self.sections):
                if shdr['sh_offset'] > self.elf_header['e_phoff']:
                    f.seek(shdr['sh_offset'])
                    f.write(section)


