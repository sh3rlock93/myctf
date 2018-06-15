from utils import *

class Section:
    def __init__(self):
        pass

    def dump(self):
        print 'Idx:', self.idx
        print 'Name:', self.name
        print 'VirtualSize:', hex(self.vsize)
        print 'VirtualAddress:', hex(self.vaddr)
        print 'SizeofRawData:', hex(self.sord)
        print 'PointerToRawData', hex(self.ptrd)
        print 'PointerToRelocations:', hex(self.ptrc)
        print 'PointerToLineNumbers:', hex(self.ptln)
        print 'NumberofRelocations:', hex(self.norc)
        print 'NumberofLineNumbers:', hex(self.noln)
        print 'Characteristics:', hex(self.character).strip('L')
        print '\r\n'

class SectionParser:
    def __init__(self):
        self.section = None
        self.nSection = None
        self.base = None

    def get_section(self, base, data, offset):
        self.section = []
        self.base = base
        self.nSection = u16(data[offset + 6:offset + 8])
        section = data[offset + 0xf8:]

        for n in range(self.nSection):
            sec = Section()
            idx = 0x28 * n
            sec._name = Value(section[idx:idx + 8], offset + 0xf8 + idx, 8)
            sec._vsize = Value(u32(section[idx + 8:idx + 12]), offset + 0xf8, + idx + 8, 4)
            sec._vaddr = Value(u32(section[idx + 12:idx + 16]), offset + 0xf8 + idx + 12, 4)
            sec._sord = Value(u32(section[idx + 16:idx + 20]), offset + 0xf8 + idx + 16, 4)
            sec._ptrd = Value(u32(section[idx + 20:idx + 24]), offset + 0xf8 + idx + 20, 4)
            sec._ptrc = Value(u32(section[idx + 24:idx + 28]), offset + 0xf8 + idx + 24, 4)
            sec._ptln = Value(u32(section[idx + 28:idx + 32]), offset + 0xf8 + idx + 28, 4)
            sec._norc = Value(u32(section[idx + 32:idx + 34]), offset + 0xf8 + idx + 32, 2)
            sec._noln = Value(u32(section[idx + 34:idx + 36]), offset + 0xf8 + idx + 34, 2)
            sec._character = Value(u32(section[idx + 36:idx + 40]), offset + 0xf8 + idx + 36, 4)
            sec.idx = n
            self.section.append(sec)
        return self.section

    def find_section(self, *args):
        signature = tuple(arg.__class__ for arg in args)
        typemap = {(int, ): self.find_section_int, (long, ): self.find_section_int, (str,): self.find_section_str}

        if signature in typemap:
            return typemap[signature](*args)
        else:
            raise TypeError("Invalid type signature: {0}".format(signature))

    def find_section_int(self, addr):
        for section in self.section:
            border = self.base + section.vaddr
            if border <= addr < border + section.vsize:
                return section
        return None

    def find_section_str(self, name):
        for section in self.section:
            section_name = section.name.replace('\x00', '')
            if section.name[0] == '.':
                section_name = section_name[1:]
            if name == section_name:
                return s
        return None

class Value(object):
    def __init__(self, value, offset, size):
        self.value = value
        self.offset = offset
        self.size = size
