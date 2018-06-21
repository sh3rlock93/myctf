from backend import *

if __name__ == '__main__':
    source_file = './test.exe'
    result_file = './result.exe'

    patcher = PatchPEx86(source_file)
    patches = []

    patches.append(AddSectionPatch('.test', 0x1000, 'R|W'))
    patches.append(InsertCodePatch(0x41181e, 'nop', name='test'))

    patcher.apply_patches(patches)
    patcher.save(result_file)
