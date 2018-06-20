from backend import *

if __name__ == '__main__':
    source_file = './test.exe'
    result_file = './result.exe'

    patcher = PatchPEx86(source_file, result_file)
    patches = []

    patches.append(InsertCode('test', 0x41181e, 'nop'))

    patcher.apply_patch(patches)
