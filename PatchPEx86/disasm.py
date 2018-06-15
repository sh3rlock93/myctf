from capstone import *

class Disassembler:
    def __init__(self):
        pass

    @staticmethod
    def disasm(code, size):
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        dis = disassembler.disasm(code, size)
        result = []

        for asm in dis:
            result.append(asm)
        return result

disassembler = Disassembler()

jmp_list = ['call', 'jmp', 'jne', 'je', 'ja', 'jb', 'jae', 'jbe', 'jg']
jmp_list += ['jge', 'jl', 'jle', 'jns', 'js', 'jo', 'jno', 'jnz', 'jz']
