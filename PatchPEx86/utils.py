import struct

def p8(x):
    return struct.pack('B', x & 0xff)

def u8(x):
    return struct.unpack('B', x)[0]

def p16(x):
    return struct.pack('H', x & 0xffff)

def u16(x):
    return struct.unpack('H', x)[0]

def p32(x):
    return struct.pack('I', x & 0xffffffff)

def u32(x):
    return struct.unpack('I', x)[0]

def p64(x):
    return struct.pack('Q', x & 0xffffffffffffffff)

def u64(x):
    return struct.unpack('Q', x)[0]

def map32(x):
    return x & 0xfffff000
