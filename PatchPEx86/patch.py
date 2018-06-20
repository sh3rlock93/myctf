from pwn import asm

class Patch(object):
    def __init__(self, name):
        self.name = name

class CodePatch(Patch):
    def __init__(self, name, code):
        super(CodePatch, self).__init__(name)

        self.code = code
        self.asm_code = asm(code, arch='x86')

class InsertCodePatch(CodePatch):
    def __init__(self, name, addr, code, pos='backward'):
        super(InsertCodePatch, self).__init__(name, code)

        self.addr = addr
        self.pos = pos
