#include <stdint.h>

int32_t _start(){
    asm(".intel_syntax noprefix");
    asm("call go");
    asm(".ascii \"/bin/sh\\0\"");

    asm("go:");
    asm("pop esi");
    asm("mov ebx, 0");
    asm("mov eax, 0xa");
    asm("int 0x80");
        
    asm("xchg eax, ebx");
    asm("mov eax, 0xd");
    asm("int 0x80");

    asm("xor edx, edx");
    asm("xor ecx, ecx");
    asm("mov ebx, esi");
    asm("mov eax, 0xb");
    asm("int 0x80");
    
    asm(".att_syntax prefix");

}
