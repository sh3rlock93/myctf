from section import *
from disasm import *
from error import *

from collections import OrderedDict

class Backend(object):
    def __init__(self, input_file):
        self.input_file = input_file
        self.binary = open(self.input_file, 'rb').read()

        self._clearing()

    def _clearing(self):
        self.binary = self.patched_binary
        self._initialize()
        self._parsing()

    def _initialize(self):
        self.parser = SectionParser()
        self.insn_address = OrderedDict()
        self.new_insn_address = OrderedDict()
        self.patches = OrderedDict()

        self.section = []
        self.directories = []

        self.text = None
        self.offset = None
        self.base = None
        self.entrypoint = None
        self.asm = None
        self.size = 0
        self.added_inst_size = 0

    def _insert(self, offset, data):
        self.patched_binary = self.patched_binary[:offset] + data + self.patched_binary[offset + len(data):]

    def _parsing(self):
        if self.binary[:2] == 'MZ':
            self.offset = u32(self.binary[0x3c:][:4])
            if self.binary[self.offset:self.offset + 2] == 'PE':
                self.base = u32(self.binary[self.offset + 0x34:][:4])
                self.section = self.parser.get_section(self.base, self.binary, self.offset)
                self.entrypoint = u32(self.binary[self.offset + 0x28:][:4])
            else:
                raise FileError(self.input_file)
        else:
            raise FileError(self.input_file)

    def _get_reloc(self):
        reloc = self.parser.find_section('reloc')
        reloc_size = 0
        reloc_table = OrderedDict()
        while True:
            rva = u32(self.patched_binary[reloc.ptrd + reloc_size:][:4])
            t_size = u32(self.patched_binary[reloc.ptrd + reloc_size + 4:][:4])

            if rva == 0:
                break

            reloc_table[rva] = []
            for offset in range(8, t_size, 2):
                reloc_rva = u16(self.patched_binary[reloc.ptrd + reloc_size + offset:][:2])
                reloc_table[rva].append(reloc_rva)
            reloc_size += t_size
        return reloc_table

    def _set_reloc(self, reloc_table):
        reloc = self.parser.find_section('reloc')
        reloc_size = 0

        for rva in reloc_table:
            t_size = len(reloc_table[rva])*2 + 8

            self._insert(reloc.ptrd + reloc_size, p32(rva))
            self._insert(reloc.ptrd + reloc_size + 4, p32(t_size))

            for idx, offset in enumerate(range(8, t_size, 2)):
                self._insert(reloc.ptrd + reloc_size + offset, p16(reloc_table[rva][idx]))
            reloc_size += t_size

        self._insert(self.offset + 0x78 + 5*8 + 4, p32(reloc_size))
        return True

    def add_reloc(self, addr):
        self.parser.get_section(self.base, self.patched_binary, self.offset)
        reloc_table = self._get_reloc()

        vaddr = addr - self.base
        rva = int(map32(vaddr))
        offset = vaddr - rva + 0x3000
        isinserted = False
        new_offset_list = []

        if rva in reloc_table:
            for old_offset in reloc_table[rva]:
                if offset < old_offset and not isinserted:
                    new_offset_list.append(offset)
                    isinserted = True
                elif old_offset == 0:
                    new_offset_list.append(offset)
                    isinserted = True
                new_offset_list.append(old_offset)
            reloc_table[rva] = new_offset_list
        else:
            new_reloc_table = OrderedDict()
            new_offset_list.append(offset)
            new_offset_list.append(0)

            for old_rva in reloc_table:
                if rva < old_rva and not isinserted:
                    new_reloc_table[rva] = new_offset_list
                    isinserted = True
                new_reloc_table[old_rva] = reloc_table[old_rva]
            reloc_table = new_reloc_table

        assert isinserted
        self._set_reloc(reloc_table)

    def add_section(self, size, mode, name):
        last_section = self.parser.section[-1]
        nSection = len(self.parser.section)
        if last_section.vsize % 0x1000:
            vaddr = last_section.vaddr + ((last_section.vsize & 0xfffff000) + 0x1000)
        else:
            vaddr = last_section.vaddr + last_section.vsize
        ptrd = last_section.ptrd + ((last_section.sord & 0xffffff00) + 0x200)

        self._insert(self.offset + 6, p16(nSection + 1))
        self._insert(last_section._name.offset + 0x28, name)
        self._insert(last_section._vsize.offset + 0x28, p32(size))
        self._insert(last_section._vaddr.offset + 0x28, p32(vaddr))
        self._insert(last_section._sord.offset + 0x28, p32(size))
        self._insert(last_section._ptrd.offset + 0x28, p32(ptrd))
        self._insert(last_section._ptrc.offset + 0x28, p32(0))
        self._insert(last_section._ptln.offset + 0x28, p32(0))
        self._insert(last_section._norc.offset + 0x28, p16(0))
        self._insert(last_section._noln.offset + 0x28, p16(0))

        self._insert(last_section._character.offset + 0x28, p32(mode))

        self.patched_binary = self.patched_binary.ljust(ptrd, '\x00') + '\x00' * size
        self._insert(self.offset + 0x50, p32(size))

        self._clearing()

        return self.base + vaddr

    def pop_section(self):
        pass

    def save(self, output_file=None):
        if output_file is None:
            output_file = '%s_patched' % self.input_file
        open(output_file, 'wb').write(self.patched_binary)

    def apply_patches(self, patches):
        raise Exception("not Implement yet")
