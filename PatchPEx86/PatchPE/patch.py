from pwn import asm

class Patch(object):
    def __init__(self, name):
        self.name = name

class CodePatch(Patch):
    def __init__(self, name, code):
        super(CodePatch, self).__init__(name)

        self.base = 0
        self.asm_code = code

    @property
    def code(self):
        return asm(self.asm_code, arch='x86', vma=self.base)

class InsertCodePatch(CodePatch):
    def __init__(self, addr, code, pos='backward', name=None, priority=1):
        super(InsertCodePatch, self).__init__(name, code)

        self.addr = addr
        self.pos = pos
        self.priority = priority

class AddSectionPatch(Patch):
    def __init__(self, section_name, tlen, mode, name=None):
        super(AddSectionPatch, self).__init__(name)
        assert type(tlen) == int

        self.len = tlen
        self.mode = mode.upper()
        self.section_name = section_name
        self.addr = 0
