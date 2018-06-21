from section import *
from patch import *
from disasm import *
from error import *

from collections import OrderedDict
from collections import defaultdict
import re

regexp = re.compile(r'{[0-9|a-z|A-Z|_|+]}')

class PatchPEx86:
    def __init__(self, input_file):
        self.input_file = input_file
        self.binary = open(self.input_file, 'rb').read()
        self.patched_binary = self.binary

        self._initialize()

        self._parsing()
        self._preprocessing()
        self._patch_section(isPreprocessing=True)
        self.remain_size = self.size - self.added_inst_size

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
                self.text = self.parser.find_section('text')
                if self.text is None:
                    raise SectionError('text')
                self.asm = disassembler.disasm(self.binary[self.text.ptrd:self.text.ptrd + \
                    self.text.sord], self.base + self.text.vaddr)
            else:
                raise FileError(self.input_file)
        else:
            raise FileError(self.input_file)

    def _patch_section(self, isPreprocessing=False, size=0):
        if size:
            self.size = size

        size_of_code = u32(self.binary[self.offset + 0x1c:][:4])
        size_of_image = u32(self.binary[self.offset + 0x50:][:4])

        self._insert(self.offset + 0x1c, p32(size_of_code + self.size))
        self._insert(self.offset + 0x50, p32(size_of_image + self.size))

        for section in self.section:
            if self.text.idx < section.idx:
                self._insert(section._vaddr.offset, p32(section.vaddr + self.size))
                self._insert(section._ptrd.offset, p32(section.ptrd + self.size))

        self._patch_directory()
        self._patch_rdata()
        self._patch_idata()
        self._patch_rsrc()

        self._patch_text(isPreprocessing)
        if isPreprocessing:
            self._patch_reloc()

        entrypoint = u32(self.binary[self.offset + 0x28:][:4])
        self._insert(self.offset + 0x28, p32(self.insn_address[self.base + entrypoint] - self.base))

    def _patch_directory(self):
        # modify data_directories
        nDirectories = u32(self.binary[self.offset + 0x74:][:4])
        for i in range(nDirectories):
            rva = u32(self.binary[self.offset + 0x78 + i*8:][:4])
            t_size = u32(self.binary[self.offset + 0x78 + i*8 + 4:][:4])
            self.directories.append([rva, t_size])
            if t_size != 0:
                self._insert(self.offset + 0x78 + i*8, p32(rva + self.size))

    def _patch_rdata(self):
        # modify .rdata section
        rdata = self.parser.find_section('rdata')
        if rdata is None:
            return False

        for offset in range(rdata.sord - 4):
            if self.binary[rdata.ptrd + offset:][:12] == 'penValidate5':
                idd = rdata.ptrd + offset + 0x20
                ilcd = idd + 0x38

                idtc_vaddr = u32(self.binary[idd + 0x14:idd + 0x18])
                idtc_ptrd = u32(self.binary[idd + 0x18:idd + 0x1c])
                idt_vaddr = u32(self.binary[idd + 0x30:idd + 0x34])
                idt_ptrd = u32(self.binary[idd + 0x34:idd + 0x38])

                self._insert(idd + 0x14, p32(idtc_vaddr + self.size))
                self._insert(idd + 0x18, p32(idtc_ptrd + self.size))
                self._insert(idd + 0x30, p32(idt_vaddr + self.size))
                self._insert(idd + 0x34, p32(idt_ptrd + self.size))
                return True

        return False

    def _patch_idata(self):
        # modify .idata section
        if self.directories[12][0]:
            idata = Section()
            idata._vaddr = Value(self.directories[12][0], 0, 4)
            idata._ptrd = Value(self._rva2raw(idata.vaddr), 0, 4)
            idata_size = self.directories[12][1]

            idx = 0
            while idx < idata_size:
                addr = u32(self.binary[idata.ptrd + idx:][:4])
                if addr != 0:
                    self._insert(idata.ptrd + idx, p32(addr + self.size))
                idx += 4

            import_offset = self._rva2raw(self.directories[1][0])
            import_size = self.directories[1][1]

            for offset in range(0, import_size, 0x14):
                intrva = u32(self.binary[import_offset + offset:][:4])
                namerva = u32(self.binary[import_offset + offset + 0xc:][:4])
                iatrva = u32(self.binary[import_offset + offset + 0x10:][:4])

                if intrva == 0 and namerva == 0 and iatrva == 0:
                    break

                self._insert(import_offset + offset, p32(intrva + self.size))
                self._insert(import_offset + offset + 0xc, p32(namerva + self.size))
                self._insert(import_offset + offset + 0x10, p32(iatrva + self.size))

                intrd = idata.ptrd + intrva - idata.vaddr
                iatrd = idata.ptrd + iatrva - idata.vaddr

                _offset = 0
                while True:
                    rva = u32(self.binary[intrd + _offset:][:4])
                    if rva == 0:
                        break
                    self._insert(intrd + _offset, p32(rva + self.size))
                    _offset += 4

                _offset = 0
                while True:
                    rva = u32(self.binary[iatrd + _offset:][:4])
                    if rva == 0:
                        break
                    self._insert(iatrd + _offset, p32(rva + self.size))
                    _offset += 4
            return True

        return False

    def _patch_rsrc(self):
        # modify .rsrc section
        rsrc = self.parser.find_section('rsrc')
        if rsrc is None:
            return False

        rva = u32(self.binary[rsrc.ptrd + 0x48:][:4])
        self._insert(rsrc.ptrd + 0x48, p32(rva + self.size))
        return True

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
        text = self.parser.find_section('text')
        reloc_size = 0

        for rva in reloc_table:
            if rva != text.vaddr and reloc_table[rva][-1] != 0:
                reloc_table[rva].append(0)
            t_size = len(reloc_table[rva])*2 + 8

            self._insert(reloc.ptrd + reloc_size, p32(rva))
            self._insert(reloc.ptrd + reloc_size + 4, p32(t_size))

            for idx, offset in enumerate(range(8, t_size, 2)):
                self._insert(reloc.ptrd + reloc_size + offset, p16(reloc_table[rva][idx]))
            reloc_size += t_size

        self._insert(self.offset + 0x78 + 5*8 + 4, p32(reloc_size))
        return True

    def _patch_reloc(self):
        # modify .reloc section
        self.parser.get_section(self.base, self.patched_binary, self.offset)
        reloc_table = self._get_reloc()
        new_reloc_table = OrderedDict()

        for rva in reloc_table:
            for offset in reloc_table[rva]:
                if self.text.vaddr <= rva <= self.text.vaddr + self.text.vsize:
                    new_offset = self._get_reloc_offset(rva + (offset & 0xfff))
                    new_rva = map32(new_offset + self.text.vaddr)
                    if offset == 0:
                        if new_rva in new_reloc_table:
                            new_reloc_table[new_rva].append(0)
                        else:
                            new_reloc_table[new_rva] = []
                            new_reloc_table[new_rva].append(0)
                        continue
                    if new_rva in new_reloc_table:
                        new_reloc_table[new_rva].append((new_offset & 0xfff) + 0x3000)
                    else:
                        new_reloc_table[new_rva] = []
                        new_reloc_table[new_rva].append((new_offset & 0xfff) + 0x3000)
                    reloc_addr = u32(self.patched_binary[self.text.ptrd + new_offset:][:4])
                    if reloc_addr in self.insn_address:
                        self._insert(self.text.ptrd + new_offset, p32(self.insn_address[reloc_addr]))
                    else:
                        self._insert(self.text.ptrd + new_offset, p32(reloc_addr + self.size))
                else:
                    new_rva = rva + self.size
                    new_offset = offset & 0xfff
                    if offset == 0:
                        if new_rva in new_reloc_table:
                            new_reloc_table[new_rva].append(0)
                        else:
                            new_reloc_table[new_rva] = []
                            new_reloc_table[new_rva].append(0)
                        continue
                    if new_rva in new_reloc_table:
                        new_reloc_table[new_rva].append(new_offset + 0x3000)
                    else:
                        new_reloc_table[new_rva] = []
                        new_reloc_table[new_rva].append(new_offset + 0x3000)
                    section = self.parser.find_section(self.base + new_rva)
                    if section and section.name != '.text':
                        reloc_addr = u32(self.patched_binary[section.ptrd + new_rva + new_offset - section.vaddr:][:4])
                        if reloc_addr in self.insn_address:
                            self._insert(section.ptrd + new_rva + new_offset - section.vaddr, p32(self.insn_address[reloc_addr]))
                        else:
                            self._insert(section.ptrd + new_rva + new_offset - section.vaddr, p32(reloc_addr + self.size))
        self._set_reloc(new_reloc_table)
        return True

    def _patch_text(self, isPreprocessing=False):
        if isPreprocessing:
            self._patch_jmp()
        else:
            self.added_inst_size = 0

        self._insert(self.text._vsize.offset, p32(self.text.vsize + self.size))
        self._insert(self.text._sord.offset, p32(self.text.sord + self.size))

        self.patched_binary = self.patched_binary[:self.text.ptrd + self.text.sord + self.added_inst_size] + \
            '\x00' * (self.size - self.added_inst_size) + \
            self.patched_binary[self.text.ptrd + self.text.sord + self.added_inst_size:]

    def _preprocessing(self):
        for asm in self.asm:
            self.insn_address[asm.address] = asm.address + self.added_inst_size
            if asm.mnemonic in jmp_list and self.base + self.text.vaddr <= asm.operands[0].value.imm <= self.base + self.text.vaddr + self.text.vsize:
                opcode = asm.bytes[:1]
                if opcode != '\xf2':
                    if asm.mnemonic == 'call' or asm.mnemonic == 'jmp':
                        self.added_inst_size += 5 - asm.size
                    else:
                        self.added_inst_size += 6 - asm.size
                else:
                    if asm.mnemonic == 'call' or asm.mnemonic == 'jmp':
                        self.added_inst_size += 6 - asm.size
                    else:
                        self.added_inst_size += 7 - asm.size
        self.size = map32(self.added_inst_size) + 0x1000

    #TODO implementing relocation in user patches
    def _patch_preprocessing(self, patches):
        for asm in self.asm:
            if asm.address in self.patches:
                for patch in self.patches[asm.address]:
                    if patch.pos == 'forward':
                        patch.addr = asm.address + self.added_inst_size
                        self.added_inst_size += len(patch.code)
                        self.insn_address[asm.address] = asm.address + self.added_inst_size
                    elif patch.pos == 'backward':
                        self.insn_address[asm.address] = asm.address + self.added_inst_size
                        patch.addr = asm.address + self.added_inst_size
                        self.added_inst_size += len(patch.code)
                    patch.base = patch.addr
                    added_code = ''
                    for code in re.split(r'\n|;', patch.asm_code):
                        if re.search(regexp, c):
                            symbol = re.findall(regexp,c)[0]
                            for p in patches:
                                if p.name == symbol[1:-1]:
                                    c = c.replace(symbol, '0x%x' % p.addr)
                                    break
                        added_code += asm(c, arch='x86', vma=(patch.base + len(added_code)))
            else:
                self.insn_address[asm.address] = asm.address + self.added_inst_size

    def _patch_jmp(self):
        self.added_inst_size = 0
        raw_offset = self.base + self.text.vaddr - self.text.ptrd
        for asm in self.asm:
            inst_offset = asm.address - raw_offset + self.added_inst_size
            opcode = self.patched_binary[inst_offset:][:1]
            if asm.mnemonic in jmp_list and self.base + self.text.vaddr <= asm.operands[0].value.imm <= self.base + self.text.vaddr + self.text.vsize:
                offset = self.insn_address[asm.operands[0].value.imm] - self.insn_address[asm.address]
                if opcode != '\xf2':
                    if asm.mnemonic == 'call':
                        offset -= 5
                        self.patched_binary = self.patched_binary[:inst_offset] + '\xe8' + p32(offset) + \
                            self.patched_binary[inst_offset + asm.size:]
                        self.added_inst_size += 5 - asm.size
                    elif asm.mnemonic == 'jmp':
                        offset -= 5
                        self.patched_binary = self.patched_binary[:inst_offset] + '\xe9' + p32(offset) + \
                            self.patched_binary[inst_offset + asm.size:]
                        self.added_inst_size += 5 - asm.size
                    else:
                        offset -= 6
                        self.patched_binary = self.patched_binary[:inst_offset] + '\x0f' + p8((u8(opcode) | 0x80) & 0x8f) + p32(offset) + \
                            self.patched_binary[inst_offset + asm.size:]
                        self.added_inst_size += 6 - asm.size
                else:
                    if asm.mnemonic == 'call':
                        offset -= 6
                        self.patched_binary = self.patched_binary[:inst_offset + 1] + '\xe8' + p32(offset) + \
                            self.patched_binary[inst_offset + asm.size:]
                        self.added_inst_size += 6 - asm.size
                    elif asm.mnemonic == 'jmp':
                        offset -= 6
                        self.patched_binary = self.patched_binary[:inst_offset + 1] + '\xe9' + p32(offset) + \
                            self.patched_binary[inst_offset + asm.size:]
                        self.added_inst_size += 6 - asm.size
                    else:
                        offset -= 7
                        self.patched_binary = self.patched_binary[:inst_offset + 1] + '\x0f' + p8((u8(opcode) | 0x80) & 0x8f) + p32(offset) + \
                            self.patched_binary[inst_offset + asm.size:]
                        self.added_inst_size += 7 - asm.size

    def _patch_code(self):
        self.added_inst_size = 0
        raw_offset = self.base + self.text.vaddr - self.text.ptrd
        for asm in self.asm:
            inst_offset = asm.address - raw_offset + self.added_inst_size
            opcode = self.patched_binary[inst_offset:][:1]
            if asm.mnemonic in jmp_list and self.base + self.text.vaddr <= asm.operands[0].value.imm <= self.base + self.text.vaddr + self.text.vsize:
                offset = self.insn_address[asm.operands[0].value.imm] - self.insn_address[asm.address] - asm.size
                if opcode != '\xf2':
                    if asm.mnemonic == 'call' or asm.mnemonic == 'jmp':
                        self.patched_binary = self.patched_binary[:inst_offset + 1] + p32(offset) + self.patched_binary[inst_offset + asm.size:]
                    else:
                        self.patched_binary = self.patched_binary[:inst_offset + 2] + p32(offset) + self.patched_binary[inst_offset + asm.size:]
                else:
                    if asm.mnemonic == 'call' or asm.mnemonic == 'jmp':
                        self.patched_binary = self.patched_binary[:inst_offset + 2] + p32(offset) + self.patched_binary[inst_offset + asm.size:]
                    else:
                        self.patched_binary = self.patched_binary[:inst_offset + 3] + p32(offset) + self.patched_binary[inst_offset + asm.size:]

            if asm.address in self.patches:
                for patch in self.patches[asm.address]:
                    code = patch.code
                    self.added_inst_size += len(code)
                    if patch.pos == 'forward':
                        self.patched_binary = self.patched_binary[:inst_offset] + code + self.patched_binary[inst_offset:]
                    elif patch.pos == 'backward':
                        self.patched_binary = self.patched_binary[:inst_offset + asm.size] + code + self.patched_binary[inst_offset + asm.size:]

        self.patched_binary = self.patched_binary[:self.text.ptrd + self.text.sord + self.size - self.added_inst_size] + self.patched_binary[self.text.ptrd + self.text.sord + self.size:]
        self._patch_reloc()

    def _get_reloc_offset(self, offset):
        offset = self.base + offset
        for i in range(10):
            # reloc offset doesn't be aligned because of opcode
            if offset - i in self.insn_address:
                return self.insn_address[offset - i] + i - self.base - self.text.vaddr

    def _rva2raw(self, rva):
        section = self.parser.find_section(self.base + rva)
        if section:
            offset = rva - section.vaddr
            return section.ptrd + offset
        raise SectionError(hex(self.base + rva))

    def _add_section(self, patch):
        last_section = self.parser.section[-1]
        nSection = len(self.parser.section)
        if last_section.vsize % 0x1000:
            vaddr = last_section.vaddr + ((last_section.vsize & 0xfffff000) + 0x1000)
        else:
            vaddr = last_section.vaddr + last_section.vsize
        ptrd = last_section.ptrd + ((last_section.sord & 0xffffff00) + 0x200)

        self._insert(self.offset + 6, p16(nSection + 1))
        self._insert(last_section._name.offset + 0x28, patch.section_name)
        self._insert(last_section._vsize.offset + 0x28, p32(patch.len))
        self._insert(last_section._vaddr.offset + 0x28, p32(vaddr))
        self._insert(last_section._sord.offset + 0x28, p32(patch.len))
        self._insert(last_section._ptrd.offset + 0x28, p32(ptrd))
        self._insert(last_section._ptrc.offset + 0x28, p32(0))
        self._insert(last_section._ptln.offset + 0x28, p32(0))
        self._insert(last_section._norc.offset + 0x28, p16(0))
        self._insert(last_section._noln.offset + 0x28, p16(0))

        self._insert(last_section._character.offset + 0x28, p32(eval(patch.mode) | 0x40))

        self.patched_binary = self.patched_binary.ljust(ptrd, '\x00') + '\x00' * patch.len
        self._insert(self.offset + 0x50, p32(vaddr + patch.len))
        self.parser.get_section(self.base, self.patched_binary, self.offset)

        return self.base + vaddr

    def save(self, output_file=None):
        if output_file is None:
            output_file = '%s_patched' % self.input_file
        open(output_file, 'wb').write(self.patched_binary)

    def apply_patches(self, patches):
        self._initialize()
        self.binary = self.patched_binary
        self._parsing()

        for patch in patches:
            if isinstance(patch, AddSectionPatch):
                patch.addr = self._add_section(patch)

        insert_code_patches = [p for p in patches if isinstance(p, InsertCodePatch)]
        insert_code_patches_dict = defaultdict(list)
        for p in insert_code_patches:
            insert_code_patches_dict[p.addr].append(p)
        insert_code_patches_dict_sorted = defaultdict(list)
        for k, v in insert_code_patches_dict.iteritems():
            insert_code_patches_dict_sorted[k] = sorted(v, key=lambda x: 1*x.priority) # TODO

        for addr, patch in insert_code_patches_dict_sorted.iteritems():
            self.patches[addr] = patch

        self._patch_preprocessing(patches)

        if self.added_inst_size > self.remain_size:
            self.size = map32(self.added_inst_size) + 0x1000
            self.remain_size += self.size - self.added_inst_size
            self._patch_section()

        self._patch_code()
